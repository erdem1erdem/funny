import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import DHCP, BOOTP, IP, UDP, conf, sniff


@dataclass
class DhcpFingerprint:
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor_class: str = ""
    param_req_list: list = field(default_factory=list)
    client_id: bytes = b""
    dhcp_options: dict = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    msg_types: list = field(default_factory=list)

    def fingerprint_string(self) -> str:
        parts = []
        if self.vendor_class:
            parts.append(f"v={self.vendor_class}")
        if self.param_req_list:
            parts.append(f"p={','.join(str(x) for x in self.param_req_list)}")
        if self.client_id:
            parts.append(f"c={self.client_id.hex()}")
        for k in sorted(self.dhcp_options.keys()):
            if k not in (53, 50, 54, 51, 58, 59, 12, 60, 61, 55):
                v = self.dhcp_options[k]
                if isinstance(v, bytes):
                    v = v.hex()
                parts.append(f"{k}={v}")
        return "|".join(parts)

    def guess_os(self) -> str:
        fp = self.fingerprint_string().lower()
        if "android" in fp or "dhcpcd" in fp:
            return "Android/Linux"
        if "msft" in fp or "microsoft" in fp:
            return "Windows"
        if "apple" in fp or "ipad" in fp or "iphone" in fp:
            return "iOS/macOS"
        if "linux" in fp or "udhcpc" in fp:
            return "Linux"
        if "cisco" in fp:
            return "Cisco"
        if "hp" in fp:
            return "HP"
        return "Unknown"


DHCP_OPTION_NAMES = {
    1: "subnet_mask",
    3: "router",
    6: "dns_server",
    12: "hostname",
    15: "domain_name",
    26: "interface_mtu",
    28: "broadcast_addr",
    33: "static_routes",
    40: "nis_domain",
    41: "nis_servers",
    42: "ntp_servers",
    43: "vendor_specific",
    50: "requested_ip",
    51: "lease_time",
    53: "msg_type",
    54: "server_id",
    55: "param_req_list",
    58: "renewal_time",
    59: "rebinding_time",
    60: "vendor_class",
    61: "client_id",
    66: "tftp_server",
    67: "bootfile",
    97: "uuid_guid",
    119: "domain_search",
    121: "classless_static_routes",
    160: "captive_portal",
    175: "etherboot",
    252: "proxy_autodiscovery",
}


def parse_dhcp_options(dhcp_layer) -> dict:
    opts = {}
    if not dhcp_layer.options:
        return opts
    for opt in dhcp_layer.options:
        if isinstance(opt, tuple):
            k, v = opt
            if k == "end":
                break
            opts[k] = v
    return opts


def mac_from_chaddr(chaddr: bytes) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[:6])


class DhcpListener:
    def __init__(self, iface: str = None):
        self.iface = iface or conf.iface
        self.fingerprints: dict[str, DhcpFingerprint] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter="udp and (port 67 or port 68)",
                    prn=self._handle_packet,
                    store=False,
                    timeout=15,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            except Exception as e:
                print(f"[!] DHCP listener error: {e}")
                time.sleep(2)

    def _handle_packet(self, pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return

        bootp = pkt[BOOTP]
        dhcp = pkt[DHCP]
        mac = mac_from_chaddr(bootp.chaddr).lower()
        ciaddr = bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else ""
        yiaddr = bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else ""

        opts = parse_dhcp_options(dhcp)
        msg_type = opts.get(53)

        with self.lock:
            fp = self.fingerprints.get(mac)
            if not fp:
                fp = DhcpFingerprint(mac=mac, first_seen=time.time())
                self.fingerprints[mac] = fp

            fp.last_seen = time.time()
            if yiaddr:
                fp.ip = yiaddr
            elif ciaddr:
                fp.ip = ciaddr

            if msg_type:
                fp.msg_types.append(int(msg_type))

            if 12 in opts:
                fp.hostname = opts[12].decode(errors="ignore") if isinstance(opts[12], bytes) else str(opts[12])
            if 60 in opts:
                fp.vendor_class = opts[60].decode(errors="ignore") if isinstance(opts[60], bytes) else str(opts[60])
            if 55 in opts:
                prl = opts[55]
                if isinstance(prl, bytes):
                    fp.param_req_list = list(prl)
                elif isinstance(prl, list):
                    fp.param_req_list = prl
            if 61 in opts:
                fp.client_id = opts[61] if isinstance(opts[61], bytes) else bytes(opts[61])
            for k, v in opts.items():
                if k not in (53, 50, 54, 51, 58, 59):
                    fp.dhcp_options[k] = v

    def get_fingerprint(self, mac: str) -> Optional[DhcpFingerprint]:
        with self.lock:
            return self.fingerprints.get(mac.lower())

    def all_fingerprints(self) -> list[DhcpFingerprint]:
        with self.lock:
            return list(self.fingerprints.values())

    def clear(self):
        with self.lock:
            self.fingerprints.clear()


def enrich_device_with_dhcp(device, listener: DhcpListener) -> None:
    fp = listener.get_fingerprint(device.mac.replace("-", ":").lower())
    if not fp:
        return
    if not device.hostname and fp.hostname:
        device.hostname = fp.hostname
    if not device.vendor and fp.vendor_class:
        device.vendor = fp.vendor_class
    if fp.guess_os() != "Unknown":
        device.os_guess = fp.guess_os()
    device.dhcp_fingerprint = fp.fingerprint_string()


if __name__ == "__main__":
    print("Starting DHCP listener... (Ctrl+C to stop)")
    listener = DhcpListener()
    listener.start()
    try:
        while True:
            time.sleep(10)
            fps = listener.all_fingerprints()
            if fps:
                print(f"\n--- {len(fps)} DHCP fingerprints ---")
                for fp in fps:
                    print(f"  {fp.mac}  IP:{fp.ip or '-'}  Host:{fp.hostname or '-'}")
                    print(f"    Vendor: {fp.vendor_class or '-'}")
                    print(f"    ParamReq: {fp.param_req_list or '-'}")
                    print(f"    OS Guess: {fp.guess_os()}")
                    print(f"    FP: {fp.fingerprint_string()}")
    except KeyboardInterrupt:
        listener.stop()
        print("\nStopped.")