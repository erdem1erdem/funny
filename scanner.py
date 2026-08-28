import concurrent.futures
import os
import re
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field

from netaddr import EUI, NotRegisteredError
from scapy.all import DNS, DNSQR, IP, Raw, UDP, conf, send, sniff

from dhcp_fingerprint import DhcpListener, enrich_device_with_dhcp

PORT_SERVICES = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    631: "IPP-Yazici",
    515: "LPD-Yazici",
    3389: "RDP",
    5000: "NAS",
    5001: "NAS",
    5555: "ADB",
    8001: "Samsung-TV",
    8002: "Samsung-TV",
    8008: "Chromecast",
    8009: "Chromecast",
    8080: "HTTP-Alt",
    9100: "Raw-Yazici",
    62078: "Apple-Sync",
}

PHONE_VENDORS = (
    "xiaomi", "huawei", "honor", "oppo", "vivo", "realme", "oneplus",
    "google, inc.", "motorola", "zte", "tcl", "hmd global", "nokia",
)

IOT_VENDORS = (
    "espressif", "tuya", "shenzhen", "hangzhou", "broadlink", "sonoff",
    "esp", "realtek semiconductor", "actions semiconductor",
)


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    alive: bool = False
    ttl: int = None
    vendor: str = ""
    dev_type: str = "?"
    os_guess: str = ""
    probe_os: str = ""
    open_ports: list = field(default_factory=list)

    @property
    def mac_display(self) -> str:
        if self.mac:
            return self.mac.replace("-", ":").lower()
        return "-"


def get_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


def get_prefix_length(ip: str) -> int:
    """Ag on sureci (prefix) uzunlugunu platforma gore bulur."""
    try:
        if os.name == "nt":
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-NetIPAddress -IPAddress %s -ErrorAction Stop).PrefixLength" % ip,
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return int(result.stdout.strip())
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        m = re.search(r"dev\s+(\S+)", out)
        iface = m.group(1)
        addrs = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        for line in addrs.splitlines():
            m2 = re.search(r"inet\s+\S+/(\d+)", line)
            if m2:
                return int(m2.group(1))
    except Exception:
        pass
    return 24


def network_hosts(ip: str, prefix: int) -> list:
    addr = struct.unpack("!I", socket.inet_aton(ip))[0]
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = addr & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    return [socket.inet_ntoa(struct.pack("!I", n)) for n in range(network + 1, broadcast)]


def _ping(host: str, timeout_ms: int) -> Device:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
    result = subprocess.run(cmd, capture_output=True)
    ttl = None
    match = re.search(rb"TTL[=:](\d+)", result.stdout, re.IGNORECASE)
    if match:
        ttl = int(match.group(1))
    return Device(ip=host, alive=result.returncode == 0, ttl=ttl)


def is_randomized_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.split("-")[0] if "-" in mac else mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def get_vendor(mac: str) -> str:
    if not mac or is_randomized_mac(mac):
        return ""
    try:
        registration = EUI(mac).oui.registration()
        return (registration.org or "").strip().rstrip(",")
    except (NotRegisteredError, Exception):
        return ""


def _tcp_probe(ip: str, port: int, timeout: float = 0.4):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return port
    except OSError:
        return None


def quick_port_scan(ip: str, max_workers: int = 32) -> list:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(lambda p: _tcp_probe(ip, p), PORT_SERVICES.keys()))
    return sorted(port for port in results if port)


def guess_os(ttl) -> str:
    if ttl is None:
        return ""
    if ttl >= 129:
        return "Windows"
    if ttl == 255:
        return "Ag ekipmani"
    if ttl == 64:
        return "Linux / Android / macOS"
    if ttl < 64:
        return f"Bilinmiyor (TTL {ttl})"
    return ""


ANDROID_HINTS = (
    "android", "pixel", "galaxy", "redmi", "poco", "mi 8", "mi 9", "mi 10",
    "mi 11", "mi 12", "note ", "huawei", "honor", "oppo", "vivo", "realme",
    "oneplus", "motorola", "nokia",
)


def classify_device(d: Device, gateway_ip: str = "") -> Device:
    host = (d.hostname or "").lower()
    vendor = (d.vendor or "").lower()
    probe = (d.probe_os or "").lower()
    ports = set(d.open_ports)
    d.os_guess = guess_os(d.ttl)

    def has(*ps):
        return bool(ports.intersection(ps))

    if d.ip == gateway_ip or host and any(
        k in host for k in ("router", "gateway", "adsl", "modem")
    ):
        d.dev_type = "Modem/Router"
    elif has(9100, 631, 515):
        d.dev_type = "Yazici"
    elif has(8008, 8009):
        d.dev_type = "TV/Medya (Chromecast)"
    elif has(8001, 8002) and "samsung" in vendor:
        d.dev_type = "Akilli TV"
    elif (
        "android" in probe
        or host.startswith("android")
        or any(k in host for k in ANDROID_HINTS)
        or has(5555)
        or (d.ttl == 64 and any(v in vendor for v in PHONE_VENDORS))
    ):
        d.dev_type = "Telefon (Android)"
        d.os_guess = "Android" + (f" ({d.probe_os})" if d.probe_os and "android" not in probe else "")
    elif has(62078) or host.startswith(("iphone", "ipad")):
        d.dev_type = "iPhone/iPad"
    elif "apple" in vendor:
        d.dev_type = "Mac"
    elif has(3389, 139) or host.startswith(("desktop-", "lapto")) or "windows" in probe:
        d.dev_type = "Windows PC"
    elif has(22, 5000, 5001):
        d.dev_type = "Sunucu/NAS"
    elif any(v in vendor for v in IOT_VENDORS):
        d.dev_type = "IoT cihaz"
    elif d.ttl == 128:
        d.dev_type = "PC (Windows?)"
    elif d.ttl == 64:
        d.dev_type = "Linux tabanli cihaz"
    else:
        d.dev_type = "Bilinmiyor"

    return d


def get_arp_table() -> dict:
    entries = {}
    if os.name == "nt":
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})"
        )
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match:
                entries[match.group(1)] = match.group(2)
    else:
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
            )
        except Exception:
            return entries
        text = result.stdout.decode(errors="ignore")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].lower() != "fail":
                entries[parts[0]] = parts[1].replace("-", ":")
    return entries


def _resolve_hostname(device: Device) -> None:
    try:
        device.hostname = socket.gethostbyaddr(device.ip)[0]
    except Exception:
        pass


MDNS_SERVICES = (
    "_googlecast._tcp.local",
    "_ipp._tcp.local",
    "_spotify-connect._tcp.local",
    "_companion-link._tcp.local",
    "_androidtvremote2._tcp.local",
)


def probe_mdns(ip: str, wait: float = 2.5) -> dict:
    """mDNS ters-sorgu + servis listesi: cihaz .local ismini dondururse yakalar."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    questions = [DNSQR(qname=rev, qtype="PTR"), DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR")]
    questions += [DNSQR(qname=svc, qtype="PTR") for svc in MDNS_SERVICES]
    pkt = IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(rd=0, qd=questions)

    found = {"hostname": "", "os": ""}
    stop_flag = {"hit": False}

    def grab(p):
        if IP not in p or p[IP].src != ip or DNS not in p:
            return
        dns_layer = p[DNS]
        if int(dns_layer.qr) != 1:
            return
        for section in (dns_layer.an, dns_layer.ns):
            if not section:
                continue
            for rr in section:
                candidates = []
                try:
                    name = bytes(rr.rrname).decode(errors="ignore").rstrip(".")
                    candidates.append(name)
                    if int(rr.type) == 12:
                        candidates.append(
                            bytes(rr.rdata).decode(errors="ignore").rstrip(".")
                        )
                except Exception:
                    continue
                for cand in candidates:
                    low = cand.lower()
                    if not low.endswith(".local"):
                        continue
                    if low.endswith("in-addr.arpa") or low.startswith("_services"):
                        continue
                    if found["hostname"] == "" or not found["hostname"].startswith("_"):
                        if cand and (not cand.startswith("_") or not found["hostname"]):
                            found["hostname"] = cand
                            stop_flag["hit"] = True

    try:
        send(pkt, verbose=False)
        send(pkt, verbose=False)
        sniff(
            iface=conf.iface,
            filter="udp port 5353",
            prn=grab,
            store=False,
            timeout=wait,
            stop_filter=lambda _p: stop_flag["hit"],
        )
    except Exception:
        pass
    return found


def probe_ssdp(ip: str, wait: float = 2.5, sport: int = 50190) -> dict:
    """SSDP M-SEARCH gonderir; SERVER basligindan OS/ipucu toplar."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n\r\n"
    )
    found = {"os": ""}

    def grab(p):
        if IP not in p or UDP not in p or p[IP].src != ip:
            return
        raw = bytes(p[UDP].payload)
        text = raw.decode(errors="ignore")
        match = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
        if match:
            found["os"] = match.group(1).strip()

    try:
        send(IP(dst="239.255.255.250") / UDP(sport=sport, dport=1900) / Raw(load=msg.encode()), verbose=False)
    except Exception:
        pass
    try:
        sniff(
            iface=conf.iface,
            filter=f"src host {ip} and udp and dst port {sport}",
            prn=grab,
            store=False,
            timeout=wait,
        )
    except Exception:
        pass
    return found


def probe_netbios(ip: str) -> str:
    """nbtstat ile Windows makine adini sorar; Windows olmayan cihaz sessiz kalir."""
    try:
        cmd = ["nbtstat", "-A", ip] if os.name == "nt" else ["nmblookup", "-A", ip]
        result = subprocess.run(cmd, capture_output=True, timeout=8)
        output = (result.stdout or b"").decode(errors="ignore")
        if os.name == "nt":
            match = re.search(r"(\S+)\s+<00>\s+UNIQUE", output)
            if match:
                return match.group(1).strip()
        else:
            match = re.search(r"looking up", output)
            if match:
                return ip
    except Exception:
        pass
    return ""


def probe_identity(device: Device) -> dict:
    """Cihaza dogrudan sorarak isim/OS bilgisi toplar (mDNS + SSDP + NetBIOS)."""
    netbios = probe_netbios(device.ip)
    if netbios:
        return {"hostname": netbios, "os": "windows"}

    results = {"hostname": "", "os": ""}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_mdns = ex.submit(probe_mdns, device.ip)
        f_ssdp = ex.submit(probe_ssdp, device.ip)
        try:
            results.update(f_mdns.result())
        except Exception:
            pass
        try:
            ssdp = f_ssdp.result()
            if ssdp.get("os") and not results["os"]:
                results["os"] = ssdp["os"]
        except Exception:
            pass
    return results


def _is_multicast_or_broadcast(ip: str, network: int, broadcast: int) -> bool:
    addr = struct.unpack("!I", socket.inet_aton(ip))[0]
    if addr <= network or addr >= broadcast:
        return True
    return addr >> 24 >= 224


def scan_network(timeout_ms: int = 1000, max_workers: int = 128, deep: bool = True, dhcp_listen_time: int = 5):
    local_ip = get_local_ip()
    prefix = get_prefix_length(local_ip)

    addr = struct.unpack("!I", socket.inet_aton(local_ip))[0]
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = addr & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    gateway_hint = socket.inet_ntoa(struct.pack("!I", network + 1))

    dhcp_listener = DhcpListener()
    dhcp_listener.start()
    print(f"    [*] DHCP dinleyici baslatildi ({dhcp_listen_time} sn)...")
    time.sleep(dhcp_listen_time)

    hosts = network_hosts(local_ip, prefix)
    devices = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_ping, host, timeout_ms) for host in hosts]
        for future in concurrent.futures.as_completed(futures):
            device = future.result()
            devices[device.ip] = device

    for ip, mac in get_arp_table().items():
        if _is_multicast_or_broadcast(ip, network, broadcast):
            continue
        if ip in devices:
            devices[ip].mac = mac
        else:
            devices[ip] = Device(ip=ip, mac=mac)

    targets = [d for d in devices.values() if d.alive or d.mac]

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures = [pool.submit(_resolve_hostname, device) for device in targets]
        for future in concurrent.futures.as_completed(futures):
            future.result()

    vendor_cache = {}
    for device in targets:
        if device.mac not in vendor_cache:
            vendor_cache[device.mac] = get_vendor(device.mac)
        device.vendor = vendor_cache[device.mac]

    if deep:
        alive = [d for d in targets if d.alive and d.ip != local_ip]
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = {pool.submit(quick_port_scan, d.ip): d for d in alive}
            for future in concurrent.futures.as_completed(futures):
                futures[future].open_ports = future.result()

        probe_pool = [d for d in alive if not d.hostname or not d.vendor]
        if probe_pool:
            print(f"    [*] {len(probe_pool)} cihaza kimlik sorgusu yapiliyor (mDNS/SSDP)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                futures = {pool.submit(probe_identity, d): d for d in probe_pool}
                for future in concurrent.futures.as_completed(futures):
                    device = futures[future]
                    try:
                        info = future.result()
                    except Exception:
                        continue
                    if not device.hostname and info.get("hostname"):
                        device.hostname = info["hostname"]
                    device.probe_os = info.get("os", "")

    for device in targets:
        enrich_device_with_dhcp(device, dhcp_listener)

    dhcp_listener.stop()

    for device in targets:
        classify_device(device, gateway_ip=gateway_hint)

    info = {"local_ip": local_ip, "prefix": prefix, "gateway_hint": gateway_hint}
    return info, sorted(targets, key=lambda d: struct.unpack("!I", socket.inet_aton(d.ip))[0])
