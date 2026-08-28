import threading
import time
from collections import Counter, defaultdict, deque

from scapy.all import DNS, DNSQR, IP, TCP, UDP, conf, sniff


def extract_sni(payload: bytes):
    """TLS Client Hello paketinden SNI (ziyaret edilen domain) bilgisini cikarir."""
    try:
        if len(payload) < 44 or payload[0] != 0x16:
            return None
        pos = 5
        if payload[pos] != 0x01:
            return None
        pos += 4
        pos += 2
        pos += 32
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos >= len(payload):
            return None
        cm_len = payload[pos]
        pos += 1 + cm_len
        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_len, len(payload))
        while pos + 4 <= end:
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            body = payload[pos + 4:pos + 4 + elen]
            if etype == 0 and len(body) >= 5:
                name_len = int.from_bytes(body[3:5], "big")
                name = body[5:5 + name_len].decode(errors="ignore")
                return name or None
            pos += 4 + elen
    except Exception:
        return None
    return None


def extract_http_host(payload: bytes):
    """Duz HTTP istegindeki Host basligini cikarir."""
    try:
        head = payload[:2048]
        if not head.startswith(
            (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")
        ):
            return None
        idx = head.find(b"\r\nHost:")
        if idx == -1:
            idx = head.lower().find(b"\r\nhost:")
        if idx == -1:
            return None
        line = head[idx + 7:].split(b"\r\n")[0].strip()
        host = line.decode(errors="ignore").split(":")[0]
        return host or None
    except Exception:
        return None


def sniff_device_domains(iface: str, target_ip: str, seconds: float = 15.0):
    """Tek cihazin DNS/SNI/HTTP izlerini belirtilen sure boyunca toplar."""
    counts = Counter()
    stop_flag = {"hit": False}

    def grab(pkt):
        if IP not in pkt or pkt[IP].src != target_ip:
            return
        domain, kind = _domain_from_packet(pkt)
        if domain:
            counts[domain] += 1

    try:
        sniff(
            iface=iface,
            filter=f"src host {target_ip}",
            prn=grab,
            store=False,
            timeout=seconds,
            stop_filter=lambda _p: stop_flag["hit"],
        )
    except Exception:
        pass
    return counts


def sniff_stop_after(seconds):
    """stop_filter icin zaman asidi yardimcisi."""
    start = time.time()
    return lambda _p: time.time() - start > seconds


def _domain_from_packet(pkt):
    if UDP in pkt and pkt[UDP].dport == 53 and pkt.haslayer(DNSQR):
        try:
            dns_layer = pkt[DNS]
            if int(dns_layer.qr) == 0:
                return pkt[DNSQR].qname.decode(errors="ignore").rstrip("."), "DNS"
        except Exception:
            return None, ""
    if TCP in pkt:
        payload = bytes(pkt[TCP].payload)
        if not payload:
            return None, ""
        if pkt[TCP].dport == 443:
            sni = extract_sni(payload)
            if sni:
                return sni, "HTTPS"
        elif pkt[TCP].dport == 80:
            host = extract_http_host(payload)
            if host:
                return host, "HTTP"
    return None, ""


IDENTITY_HINTS = {
    "android-xiaomi": ("miui", "xiaomi", "duokan", "mi.com", "redmi", "poco"),
    "android-muhtemel": (
        "firebaseremoteconfig",
        "graph.facebook",
        "app-measurement",
        "crashlytics",
        "mtalk.google",
        "android.clients.google",
        "firebaseinstallations",
    ),
    "apple": ("icloud", "apple.com", "mzstatic", "cdn-apple"),
    "tv": ("samsung", "smart-tv", "smarttv", "/tv", "netflix.tv"),
}


def guess_identity_from_domains(domains) -> str:
    """Yakalanan domain listesinden cihaz turu ipucu uretir."""
    text = " ".join(domains).lower()
    for label, keywords in IDENTITY_HINTS.items():
        if any(k in text for k in keywords):
            return label
    return ""


class TrafficMonitor:
    """
    MITM uzerinden gecen trafikten cihaz basina web aktivitesi cikarir.
    Kaynaklar: DNS sorgulari (udp/53), TLS SNI (tcp/443), HTTP Host (tcp/80).
    """

    def __init__(self, iface: str, my_ip: str):
        self.iface = iface
        self.my_ip = my_ip
        self.scope = set()
        self.events = []
        self.domain_counts = defaultdict(lambda: defaultdict(int))
        self.bytes_by_ip = defaultdict(int)
        self.packet_count = 0
        self.seq = 0
        self.running = False
        self.started_at = None
        self.dedup_window = 10.0
        self._last_seen = {}
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def set_scope(self, ips):
        with self.lock:
            self.scope = set(ips)

    def start(self):
        self._stop_event.clear()
        self.running = True
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=6)
        self.running = False

    def reset_stats(self):
        with self.lock:
            self.events.clear()
            self.domain_counts.clear()
            self.bytes_by_ip.clear()
            self.packet_count = 0
            self.seq = 0
            self._last_seen.clear()

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter="ip",
                    prn=self._classify,
                    store=False,
                    timeout=15,
                    stop_filter=lambda _pkt: self._stop_event.is_set(),
                )
            except Exception as exc:
                print(f"[!] Trafik izleyici hatasi: {exc}")
                self._stop_event.wait(2)

    def _classify(self, pkt) -> None:
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        src = ip_layer.src
        first_octet = int(src.split(".")[0]) if src.count(".") == 3 else 0
        if src == self.my_ip or first_octet >= 224:
            return

        domain, kind = _domain_from_packet(pkt)

        with self.lock:
            self.packet_count += 1
            self.bytes_by_ip[src] += len(pkt)
            if domain:
                now = time.time()
                key = (src, domain, kind)
                last = self._last_seen.get(key)
                if last is None or now - last > self.dedup_window:
                    self._last_seen[key] = now
                    self.seq += 1
                    entry = (self.seq, now, src, domain, kind)
                    self.events.append(entry)
                    self.domain_counts[src][domain] += 1
                if len(self._last_seen) > 4000:
                    cutoff = now - self.dedup_window * 2
                    expired = [k for k, t in self._last_seen.items() if t < cutoff]
                    for k in expired:
                        del self._last_seen[k]

    def events_after(self, last_seq: int):
        with self.lock:
            out = [e for e in self.events if e[0] > last_seq][-100:]
            new_seq = self.seq
        return out, new_seq

    def summary(self, scope=None, top=12):
        with self.lock:
            counts_snapshot = {
                ip: dict(domains)
                for ip, domains in self.domain_counts.items()
            }
            bytes_snapshot = dict(self.bytes_by_ip)
            packet_total = self.packet_count

        lines = []
        targets = scope or list(counts_snapshot.keys())
        for ip in sorted(targets, key=lambda x: [int(p) for p in x.split(".")]):
            mb = bytes_snapshot.get(ip, 0) / (1024 * 1024)
            domains = counts_snapshot.get(ip, {})
            total_hits = sum(domains.values())
            lines.append(f"{ip:<16} {mb:>8.2f} MB   {total_hits} site erisimi")
            for domain, count in sorted(domains.items(), key=lambda kv: -kv[1])[:top]:
                lines.append(f"    {count:>3}x  {domain}")
            if not domains:
                lines.append("    (domain yakalanmadi)")
        lines.append(f"\nToplam islenen paket: {packet_total}")
        return "\n".join(lines)
