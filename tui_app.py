import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, DataTable, Static, Button, Input, Select,
    TabbedContent, TabPane, Label, RichLog, ProgressBar, Sparkline
)
from textual.screen import Screen
from textual.message import Message
from textual.reactive import reactive
from textual.timer import Timer

from scanner import scan_network, Device, classify_device, get_local_ip
from spoofer import ArpKiller, gateway_route, test_kill, check_environment, is_admin
from monitor import TrafficMonitor, sniff_device_domains, guess_identity_from_domains
from redirector import DnsRedirector, PageServer, set_forwarding, force_forwarding_off
from main import cleanup_redirect_state
from dhcp_fingerprint import DhcpListener, enrich_device_with_dhcp


class DeviceRow:
    def __init__(self, device: Device, dhcp_fp: str = ""):
        self.device = device
        self.dhcp_fp = dhcp_fp

    def to_row(self, index: int) -> tuple:
        d = self.device
        status_icons = []
        if d.ip in getattr(self, '_killed', {}):
            status_icons.append("🔴")
        if d.ip in getattr(self, '_redirected', {}):
            status_icons.append("🔀")
        status = " ".join(status_icons) if status_icons else "🟢"
        
        return (
            str(index),
            d.ip,
            d.dev_type or "?",
            d.os_guess or "-",
            d.mac_display,
            (d.vendor[:20] + "..") if d.vendor and len(d.vendor) > 20 else (d.vendor or "-"),
            d.hostname or "-",
            status
        )


class ScanWorker:
    def __init__(self, app_ref):
        self.app = app_ref
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.dhcp_listener: Optional[DhcpListener] = None

    def start(self, dhcp_time: int = 5):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, args=(dhcp_time,), daemon=True)
        self.thread.start()

    def _run(self, dhcp_time: int):
        try:
            self.dhcp_listener = DhcpListener()
            self.dhcp_listener.start()
            time.sleep(dhcp_time)

            info, devices = scan_network(deep=True, dhcp_listen_time=0)
            
            for d in devices:
                enrich_device_with_dhcp(d, self.dhcp_listener)

            self.dhcp_listener.stop()

            self.app.call_from_thread(self.app.on_scan_complete, info, devices)
        except Exception as e:
            self.app.call_from_thread(self.app.on_scan_error, str(e))
        finally:
            self.running = False


class TrafficMonitorWorker:
    def __init__(self, app_ref):
        self.app = app_ref
        self.monitor: Optional[TrafficMonitor] = None
        self.running = False
        self.scope_ips = set()
        self.iface = ""
        self.my_ip = ""
        self._last_seq = 0

    def start(self, scope_ips: list, observe: bool = True):
        if self.running:
            return
        self.scope_ips = set(scope_ips)
        self.iface, self.my_ip, _ = gateway_route()
        self.monitor = TrafficMonitor(self.iface, self.my_ip)
        self.monitor.set_scope(self.scope_ips)
        self.monitor.start()
        set_forwarding(observe)
        self.running = True
        self._last_seq = 0
        asyncio.create_task(self._poll())

    async def _poll(self):
        while self.running and self.monitor:
            await asyncio.sleep(0.5)
            try:
                events, self._last_seq = self.monitor.events_after(self._last_seq)
                for seq, ts, ip, domain, kind in events:
                    self.app.call_from_thread(self.app.on_traffic_event, ip, domain, kind, ts)
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.monitor:
            self.monitor.stop()
        set_forwarding(False)


class KickWorker:
    def __init__(self, app_ref):
        self.app = app_ref
        self.killed: dict[str, ArpKiller] = {}

    def kick(self, device: Device) -> bool:
        if device.ip in self.killed:
            return False
        killer = ArpKiller(device.ip, device.mac)
        if not killer.ready:
            return False
        try:
            killer.start()
            self.killed[device.ip] = killer
            self.app.call_from_thread(self.app.on_kick_started, device.ip)
            return True
        except Exception as e:
            self.app.call_from_thread(self.app.on_kick_error, device.ip, str(e))
            return False

    def kick_all(self, devices: list[Device], gateway_ip: str, my_ip: str) -> int:
        count = 0
        for d in devices:
            if d.ip in (gateway_ip, my_ip) or d.ip in self.killed:
                continue
            killer = ArpKiller(d.ip, d.mac)
            if killer.ready:
                try:
                    killer.start()
                    self.killed[d.ip] = killer
                    count += 1
                except Exception:
                    pass
        if count:
            self.app.call_from_thread(self.app.on_kick_all_started, count)
        return count

    def restore(self, ip: str) -> bool:
        if ip not in self.kicked:
            return False
        killer = self.killed.pop(ip)
        killer.stop(restore=True)
        self.app.call_from_thread(self.app.on_restore, ip)
        return True

    def restore_all(self):
        for ip in list(self.killed.keys()):
            self.restore(ip)

    def get_killed(self) -> dict[str, ArpKiller]:
        return self.killed.copy()


class RedirectWorker:
    def __init__(self, app_ref):
        self.app = app_ref
        self.redirected: dict[str, DnsRedirector] = {}
        self.page_server: Optional[PageServer] = None

    def redirect(self, device: Device, target_url: str = "", message: str = "", domains: list = None) -> bool:
        if device.ip not in self.kick_worker.killed:
            return False
        
        my_ip = get_local_ip()
        redirect_url = target_url or None
        msg = message or None
        
        if redirect_url and not set_forwarding(True):
            return False

        if self.page_server is None or self.page_server.redirect_url != redirect_url or self.page_server.message != msg:
            if self.page_server:
                self.page_server.stop()
            self.page_server = PageServer(message=msg, redirect_url=redirect_url, host_ip=my_ip)
            PageServer.open_firewall()
            self.page_server.start()

        passthrough = None
        if redirect_url:
            from urllib.parse import urlparse
            host = urlparse(redirect_url).netloc.split(":")[0].lower()
            passthrough = [host]
            if "x.com" in host or "twitter.com" in host:
                passthrough += ["twimg.com", "t.co"]

        dns_redir = DnsRedirector(
            device.ip,
            redirect_ip=my_ip,
            domains=domains,
            passthrough_domains=passthrough
        )
        dns_redir.start()
        self.redirected[device.ip] = dns_redir
        self.app.call_from_thread(self.app.on_redirect_started, device.ip, redirect_url or "local")
        return True

    def stop_redirect(self, ip: str = None):
        if ip:
            if ip in self.redirected:
                self.redirected.pop(ip).stop()
                self.app.call_from_thread(self.app.on_redirect_stopped, ip)
        else:
            for ip in list(self.redirected.keys()):
                self.redirected.pop(ip).stop()
            if self.page_server:
                self.page_server.stop()
                self.page_server = None
            set_forwarding(False)
            self.app.call_from_thread(self.app.on_all_redirects_stopped)


class WiFiKillerApp(App):
    CSS = """
    Screen {
        background: #0d1117;
    }
    
    Header {
        background: #161b22;
        border-bottom: solid #30363d;
        height: 3;
    }
    
    Footer {
        background: #161b22;
        border-top: solid #30363d;
    }
    
    #main-container {
        layout: horizontal;
    }
    
    #sidebar {
        width: 28;
        background: #161b22;
        border-right: solid #30363d;
        padding: 1;
    }
    
    #sidebar-title {
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
    }
    
    #sidebar .button {
        width: 100%;
        margin-bottom: 1;
        background: #21262d;
        border: solid #30363d;
    }
    
    #sidebar .button:hover {
        background: #30363d;
        border: solid #58a6ff;
    }
    
    #content {
        width: 1fr;
        padding: 1;
    }
    
    #device-table {
        height: 1fr;
    }
    
    #device-table > .datatable--header {
        background: #161b22;
        color: #58a6ff;
        text-style: bold;
    }
    
    #device-table > .datatable--cursor {
        background: #388bfd;
        color: #ffffff;
    }
    
    #detail-panel {
        height: 40%;
        background: #161b22;
        border: solid #30363d;
        padding: 1;
        margin-top: 1;
    }
    
    #log-panel {
        height: 30%;
        background: #161b22;
        border: solid #30363d;
        margin-top: 1;
    }
    
    .stat-card {
        width: 1fr;
        height: 8;
        background: #161b22;
        border: solid #30363d;
        padding: 1;
        margin: 0 1 1 0;
    }
    
    .stat-value {
        text-style: bold;
        font-size: 2;
        color: #58a6ff;
        text-align: center;
    }
    
    .stat-label {
        text-align: center;
        color: #8b949e;
        margin-top: -1;
    }
    
    #stats-row {
        layout: horizontal;
        height: 10;
        margin-bottom: 1;
    }
    
    .highlight {
        color: #f78166;
    }
    
    .success {
        color: #3fb950;
    }
    
    .warning {
        color: #d29922;
    }
    
    Input, Select {
        background: #21262d;
        border: solid #30363d;
        color: #e6edf3;
    }
    
    Input:focus, Select:focus {
        border: solid #58a6ff;
    }
    
    TabbedContent {
        background: #161b22;
        border: solid #30363d;
    }
    
    TabPane {
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Rescan"),
        Binding("k", "kick_selected", "Kick"),
        Binding("u", "restore_selected", "Restore"),
        Binding("m", "monitor_selected", "Monitor"),
        Binding("d", "detail_selected", "Detail"),
        Binding("ctrl+c", "quit", "Quit"),
    ]
    
    devices: list[Device] = []
    selected_device: Optional[Device] = None
    scan_worker: Optional[ScanWorker] = None
    traffic_worker: Optional[TrafficMonitorWorker] = None
    kick_worker: KickWorker = None
    redirect_worker: RedirectWorker = None
    local_ip: str = ""
    gateway_ip: str = ""
    iface: str = ""
    scan_timer: Optional[Timer] = None
    
    def __init__(self):
        super().__init__()
        self.kick_worker = KickWorker(self)
        self.redirect_worker = RedirectWorker(self)
        self.redirect_worker.kick_worker = self.kick_worker
        
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            with Vertical(id="sidebar"):
                yield Static("🛡️  WiFi KILLER", id="sidebar-title")
                yield Button("🔍  Scan Network", id="btn-scan", variant="primary")
                yield Button("👢  Kick Selected", id="btn-kick", variant="error")
                yield Button("🔀  Redirect Selected", id="btn-redirect", variant="warning")
                yield Button("📡  Monitor Traffic", id="btn-monitor", variant="default")
                yield Button("🔧  Restore Selected", id="btn-restore", variant="success")
                yield Button("🔄  Restore All", id="btn-restore-all", variant="success")
                yield Button("📋  Device Detail", id="btn-detail", variant="default")
                yield Button("🧪  Test Kick", id="btn-test", variant="default")
                yield Static("", classes="stat-card")
                yield Static("", classes="stat-card")
                yield Static("", classes="stat-card")
                yield Static("", classes="stat-card")
            
            with Vertical(id="content"):
                with Horizontal(id="stats-row"):
                    yield Static(
                        "[bold]Devices[/bold]\n[stat-value]0[/stat-value]\n[stat-label]Total[/stat-label]",
                        classes="stat-card", id="stat-total"
                    )
                    yield Static(
                        "[bold]Kicked[/bold]\n[stat-value]0[/stat-value]\n[stat-label]Active[/stat-label]",
                        classes="stat-card", id="stat-kicked"
                    )
                    yield Static(
                        "[bold]Redirected[/bold]\n[stat-value]0[/stat-value]\n[stat-label]Active[/stat-label]",
                        classes="stat-card", id="stat-redirected"
                    )
                    yield Static(
                        "[bold]Monitoring[/bold]\n[stat-value]0[/stat-value]\n[stat-label]Devices[/stat-label]",
                        classes="stat-card", id="stat-monitoring"
                    )
                
                yield DataTable(id="device-table", cursor_type="row", zebra_stripes=True)
                
                with TabbedContent(id="detail-panel"):
                    with TabPane("📋 Details", id="tab-detail"):
                        yield RichLog(id="detail-log", markup=True, highlight=True)
                    with TabPane("🌐 Traffic", id="tab-traffic"):
                        yield RichLog(id="traffic-log", markup=True, highlight=True)
                    with TabPane("📊 Ports", id="tab-ports"):
                        yield RichLog(id="ports-log", markup=True, highlight=True)
                    with TabPane("🔐 DHCP", id="tab-dhcp"):
                        yield RichLog(id="dhcp-log", markup=True, highlight=True)
                
                yield RichLog(id="log-panel", markup=True, highlight=True, wrap=True)
        
        yield Footer()
    
    def on_mount(self):
        self.setup_table()
        self.log("🚀 WiFi Killer TUI started")
        self.log("Press [bold]R[/bold] to scan network, [bold]Q[/bold] to quit")
        self.check_admin()
        self.action_refresh()
    
    def setup_table(self):
        table = self.query_one("#device-table", DataTable)
        table.add_columns("#", "IP", "Type", "OS", "MAC", "Vendor", "Hostname", "Status")
        table.cursor_type = "row"
        table.zebra_stripes = True
    
    def check_admin(self):
        if not is_admin():
            self.log("[warning]⚠️  Not running as Admin - ARP spoofing will fail[/warning]")
            self.notify("Not running as Administrator!", severity="warning")
    
    def log(self, msg: str):
        log_widget = self.query_one("#log-panel", RichLog)
        timestamp = time.strftime("%H:%M:%S")
        log_widget.write(f"[dim]{timestamp}[/dim] {msg}")
    
    def update_stats(self):
        total = len(self.devices)
        kicked = len(self.kick_worker.get_killed())
        redirected = len(self.redirect_worker.redirected)
        monitoring = len(self.traffic_worker.scope_ips) if self.traffic_worker and self.traffic_worker.running else 0
        
        self.query_one("#stat-total", Static).update(
            f"[bold]Devices[/bold]\n[stat-value]{total}[/stat-value]\n[stat-label]Total[/stat-label]"
        )
        self.query_one("#stat-kicked", Static).update(
            f"[bold]Kicked[/bold]\n[stat-value]{kicked}[/stat-value]\n[stat-label]Active[/stat-label]"
        )
        self.query_one("#stat-redirected", Static).update(
            f"[bold]Redirected[/bold]\n[stat-value]{redirected}[/stat-value]\n[stat-label]Active[/stat-label]"
        )
        self.query_one("#stat-monitoring", Static).update(
            f"[bold]Monitoring[/bold]\n[stat-value]{monitoring}[/stat-value]\n[stat-label]Devices[/stat-label]"
        )
    
    def refresh_table(self):
        table = self.query_one("#device-table", DataTable)
        table.clear()
        
        killed = self.kick_worker.get_killed()
        redirected = self.redirect_worker.redirected
        
        for i, device in enumerate(self.devices, 1):
            row = DeviceRow(device)
            row._killed = killed
            row._redirected = redirected
            table.add_row(*row.to_row(i), key=device.ip)
        
        self.update_stats()
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.row_key.value:
            ip = event.row_key.value
            self.selected_device = next((d for d in self.devices if d.ip == ip), None)
            if self.selected_device:
                self.show_device_detail()
    
    def show_device_detail(self):
        if not self.selected_device:
            return
        d = self.selected_device
        
        detail_log = self.query_one("#detail-log", RichLog)
        detail_log.clear()
        detail_log.write(f"[bold cyan]Device Details: {d.ip}[/bold cyan]")
        detail_log.write(f"  MAC: {d.mac_display}")
        detail_log.write(f"  Type: {d.dev_type}")
        detail_log.write(f"  OS: {d.os_guess or 'Unknown'}")
        detail_log.write(f"  Vendor: {d.vendor or 'Unknown'}")
        detail_log.write(f"  Hostname: {d.hostname or 'Unknown'}")
        detail_log.write(f"  TTL: {d.ttl if d.ttl else 'N/A'}")
        detail_log.write(f"  Alive: {'Yes' if d.alive else 'No'}")
        
        ports_log = self.query_one("#ports-log", RichLog)
        ports_log.clear()
        if d.open_ports:
            ports_log.write("[bold cyan]Open Ports:[/bold cyan]")
            for port in d.open_ports:
                from scanner import PORT_SERVICES
                ports_log.write(f"  {port}/tcp - {PORT_SERVICES.get(port, 'Unknown')}")
        else:
            ports_log.write("No open ports found")
        
        dhcp_log = self.query_one("#dhcp-log", RichLog)
        dhcp_log.clear()
        if hasattr(d, 'dhcp_fingerprint') and d.dhcp_fingerprint:
            dhcp_log.write("[bold cyan]DHCP Fingerprint:[/bold cyan]")
            dhcp_log.write(f"  {d.dhcp_fingerprint}")
            dhcp_log.write(f"  OS Guess: {getattr(d, 'os_guess', 'Unknown')}")
        else:
            dhcp_log.write("No DHCP data captured")
            dhcp_log.write("Tip: Rescan with longer DHCP listen time")
    
    def action_refresh(self):
        self.log("[cyan]🔍 Starting network scan...[/cyan]")
        self.scan_worker = ScanWorker(self)
        self.scan_worker.start(dhcp_time=5)
    
    def on_scan_complete(self, info, devices):
        self.devices = devices
        self.local_ip = info["local_ip"]
        self.gateway_ip = info["gateway_hint"]
        self.iface, _, _ = gateway_route()
        self.refresh_table()
        self.log(f"[success]✅ Scan complete: {len(devices)} devices found[/success]")
        self.notify(f"Found {len(devices)} devices")
    
    def on_scan_error(self, error: str):
        self.log(f"[highlight]❌ Scan error: {error}[/highlight]")
        self.notify(f"Scan failed: {error}", severity="error")
    
    def action_kick_selected(self):
        if not self.selected_device:
            self.notify("No device selected", severity="warning")
            return
        if self.selected_device.ip == self.local_ip:
            self.notify("Cannot kick yourself!", severity="error")
            return
        self.log(f"[warning]👢 Kicking {self.selected_device.ip}...[/warning]")
        self.kick_worker.kick(self.selected_device)
    
    def on_kick_started(self, ip: str):
        self.log(f"[success]✅ Kicked {ip}[/success]")
        self.refresh_table()
    
    def on_kick_error(self, ip: str, error: str):
        self.log(f"[highlight]❌ Kick failed for {ip}: {error}[/highlight]")
        self.notify(f"Kick failed: {error}", severity="error")
    
    def action_kick_all(self):
        self.log("[warning]👢 Kicking all devices...[/warning]")
        count = self.kick_worker.kick_all(self.devices, self.gateway_ip, self.local_ip)
        if count:
            self.log(f"[success]✅ Kicked {count} devices[/success]")
        else:
            self.log("[warning]No devices to kick[/warning]")
    
    def action_restore_selected(self):
        if not self.selected_device:
            self.notify("No device selected", severity="warning")
            return
        if self.kick_worker.restore(self.selected_device.ip):
            self.log(f"[success]✅ Restored {self.selected_device.ip}[/success]")
            self.refresh_table()
        else:
            self.notify("Device not kicked", severity="warning")
    
    def on_restore(self, ip: str):
        self.refresh_table()
    
    def action_restore_all(self):
        self.kick_worker.restore_all()
        self.redirect_worker.stop_redirect()
        if self.traffic_worker and self.traffic_worker.running:
            self.traffic_worker.stop()
        self.log("[success]✅ All restored[/success]")
        self.refresh_table()
    
    def on_all_redirects_stopped(self):
        self.refresh_table()
    
    def action_monitor_selected(self):
        if not self.selected_device:
            self.notify("No device selected", severity="warning")
            return
        
        if self.selected_device.ip not in self.kick_worker.get_killed():
            self.log(f"[warning]Starting MITM for {self.selected_device.ip} first...[/warning]")
            self.kick_worker.kick(self.selected_device)
            time.sleep(1)
        
        if self.selected_device.ip in self.kick_worker.get_killed():
            self.traffic_worker = TrafficMonitorWorker(self)
            self.traffic_worker.start([self.selected_device.ip], observe=True)
            self.log(f"[cyan]📡 Monitoring {self.selected_device.ip} (internet ON)[/cyan]")
            self.query_one("#detail-panel", TabbedContent).active = "tab-traffic"
        else:
            self.notify("Failed to start MITM", severity="error")
    
    def on_traffic_event(self, ip: str, domain: str, kind: str, ts: float):
        traffic_log = self.query_one("#traffic-log", RichLog)
        clock = time.strftime("%H:%M:%S", time.localtime(ts))
        color = {"DNS": "cyan", "HTTPS": "green", "HTTP": "yellow"}.get(kind, "white")
        traffic_log.write(f"[dim]{clock}[/dim] [{color}]{kind}[/{color}] {ip} → {domain}")
    
    def action_detail_selected(self):
        if self.selected_device:
            self.show_device_detail()
            self.query_one("#detail-panel", TabbedContent).active = "tab-detail"
    
    def on_redirect_started(self, ip: str, target: str):
        self.log(f"[success]🔀 Redirecting {ip} → {target}[/success]")
        self.refresh_table()
    
    def on_redirect_stopped(self, ip: str):
        self.log(f"[success]✅ Redirect stopped for {ip}[/success]")
        self.refresh_table()
    
    def on_button_pressed(self, event: Button.Pressed):
        actions = {
            "btn-scan": self.action_refresh,
            "btn-kick": self.action_kick_selected,
            "btn-redirect": self.show_redirect_dialog,
            "btn-monitor": self.action_monitor_selected,
            "btn-restore": self.action_restore_selected,
            "btn-restore-all": self.action_restore_all,
            "btn-detail": self.action_detail_selected,
            "btn-test": self.run_test_kick,
        }
        if event.button.id in actions:
            actions[event.button.id]()
    
    def show_redirect_dialog(self):
        if not self.selected_device:
            self.notify("Select a device first", severity="warning")
            return
        if self.selected_device.ip not in self.kick_worker.get_killed():
            self.notify("Device must be kicked first", severity="warning")
            return
        
        self.push_screen(RedirectScreen(self.selected_device.ip, self.redirect_worker))
    
    def run_test_kick(self):
        if not self.selected_device:
            self.notify("Select a device first", severity="warning")
            return
        if self.selected_device.ip not in self.kick_worker.get_killed():
            self.notify("Device must be kicked first", severity="warning")
            return
        
        self.log(f"[cyan]🧪 Testing kick on {self.selected_device.ip}...[/cyan]")
        result = test_kill(self.selected_device.ip, duration=8)
        
        if not result["lan_alive"]:
            self.log("[highlight]Device not reachable on LAN[/highlight]")
        elif result["intercepted"]:
            self.log(f"[success]✅ KICK CONFIRMED - {result['packet_count']} packets intercepted[/success]")
        else:
            self.log("[warning]Uncertain - no packets intercepted[/warning]")


class RedirectScreen(Screen):
    def __init__(self, target_ip: str, redirect_worker: RedirectWorker):
        super().__init__()
        self.target_ip = target_ip
        self.redirect_worker = redirect_worker
    
    def compose(self) -> ComposeResult:
        yield Container(
            Static(f"🔀 Redirect [bold]{self.target_ip}[/bold]", id="redirect-title"),
            Input(placeholder="Target URL (https://...) or empty for local page", id="redirect-url"),
            Input(placeholder="Custom message (optional)", id="redirect-msg"),
            Input(placeholder="Domain filter (comma separated, optional)", id="redirect-domains"),
            Horizontal(
                Button("Start Redirect", id="redirect-start", variant="warning"),
                Button("Cancel", id="redirect-cancel", variant="default"),
            ),
            id="redirect-dialog"
        )
    
    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "redirect-start":
            url = self.query_one("#redirect-url", Input).value.strip()
            msg = self.query_one("#redirect-msg", Input).value.strip()
            domains_raw = self.query_one("#redirect-domains", Input).value.strip()
            domains = [d.strip() for d in domains_raw.split(",") if d.strip()] or None
            
            device = next((d for d in self.app.devices if d.ip == self.target_ip), None)
            if device:
                self.redirect_worker.redirect(device, url, msg, domains)
            self.app.pop_screen()
        elif event.button.id == "redirect-cancel":
            self.app.pop_screen()


def main():
    app = WiFiKillerApp()
    app.run()


if __name__ == "__main__":
    main()