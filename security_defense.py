#!/usr/bin/env python3
"""
🚨 SECURITY DEFENSE SYSTEM 🚨
- Auto-detectie van aanvallen
- Automatische IP blokkering
- Rode alarm scherm
- Port scanning met uitleg
"""

import gi, subprocess, time, threading, re, collections
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib
from datetime import datetime

# Bekende poorten en hun gebruik
PORT_DATABASE = {
    20: "FTP Data - Bestandsoverdracht",
    21: "FTP Control - Bestandsoverdracht beheer",
    22: "SSH - Veilige remote toegang",
    23: "Telnet - Onveilige remote toegang (vermijd!)",
    25: "SMTP - Email versturen",
    53: "DNS - Domein naam resolutie",
    80: "HTTP - Normale websites",
    110: "POP3 - Email ophalen",
    143: "IMAP - Email synchronisatie",
    443: "HTTPS - Beveiligde websites",
    445: "SMB - Windows bestandsdeling",
    3306: "MySQL - Database",
    3389: "RDP - Windows remote desktop",
    5432: "PostgreSQL - Database",
    5900: "VNC - Remote desktop",
    6379: "Redis - Cache database",
    8080: "HTTP Alt - Alternatieve webserver",
    8443: "HTTPS Alt - Alternatieve beveiligde webserver",
    27017: "MongoDB - NoSQL database"
}

# Verdachte activiteit detectie
SUSPICIOUS_THRESHOLD = 20  # Verbindingen per seconde
BLOCK_DURATION = 300  # 5 minuten

class SecurityDefense(Gtk.Window):
    def __init__(self):
        super().__init__(title="🛡️ SECURITY DEFENSE")
        
        self.set_default_size(800, 600)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_keep_above(True)
        
        # Tracking
        self.connection_tracker = collections.defaultdict(list)  # IP -> [timestamps]
        self.blocked_ips = set()
        self.alarm_active = False
        self.alarm_overlay = None
        
        # Dark security theme
        css = Gtk.CssProvider()
        css.load_from_data(b"""
        window {
            background-color: #0a0a0a;
            color: #00FF00;
        }
        .alarm-red {
            background-color: #FF0000;
            color: #FFFFFF;
            font-size: 32px;
            font-weight: bold;
            text-shadow: 2px 2px 4px #000000, -2px -2px 4px #000000, 2px -2px 4px #000000, -2px 2px 4px #000000;
        }
        .alarm-black {
            background-color: #000000;
            color: #FFFFFF;
            font-size: 32px;
            font-weight: bold;
            text-shadow: 2px 2px 4px #FF0000, -2px -2px 4px #FF0000, 2px -2px 4px #FF0000, -2px 2px 4px #FF0000;
        }
        """)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            css,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        
        self.setup_ui()
        
        # Start monitoring
        threading.Thread(target=self._monitor_threats, daemon=True).start()
        
    def setup_ui(self):
        """Setup de UI"""
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        vbox.set_margin_start(15)
        vbox.set_margin_end(15)
        vbox.set_margin_top(15)
        vbox.set_margin_bottom(15)
        self.add(vbox)
        
        # Header
        header = Gtk.Label()
        header.set_markup("<span foreground='#FF0000' size='xx-large'><b>🛡️ SECURITY DEFENSE SYSTEM</b></span>")
        vbox.pack_start(header, False, False, 10)
        
        # Status indicator
        self.status_label = Gtk.Label()
        self.status_label.set_markup("<span foreground='#00FF00' size='large'>✅ SYSTEEM VEILIG</span>")
        vbox.pack_start(self.status_label, False, False, 5)
        
        # Buttons
        hbox_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        vbox.pack_start(hbox_buttons, False, False, 10)
        
        btn_scan = Gtk.Button(label="🔍 Scan Open Poorten")
        btn_scan.connect("clicked", self.on_scan_ports)
        hbox_buttons.pack_start(btn_scan, True, True, 0)
        
        btn_test_alarm = Gtk.Button(label="🚨 Test Alarm")
        btn_test_alarm.connect("clicked", self.on_test_alarm)
        hbox_buttons.pack_start(btn_test_alarm, True, True, 0)
        
        btn_clear = Gtk.Button(label="🧹 Clear Blocks")
        btn_clear.connect("clicked", self.on_clear_blocks)
        hbox_buttons.pack_start(btn_clear, True, True, 0)
        
        # Threats log
        lbl_threats = Gtk.Label()
        lbl_threats.set_markup("<span foreground='#FFA500' size='large'><b>⚠️ DETECTED THREATS:</b></span>")
        lbl_threats.set_xalign(0)
        vbox.pack_start(lbl_threats, False, False, 5)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_size_request(-1, 300)
        vbox.pack_start(scrolled, True, True, 0)
        
        self.threats_store = Gtk.ListStore(str, str)  # [message, color]
        self.threats_tree = Gtk.TreeView(model=self.threats_store)
        self.threats_tree.set_headers_visible(False)
        
        renderer = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn("Threat", renderer, text=0, foreground=1)
        col.set_expand(True)
        self.threats_tree.append_column(col)
        scrolled.add(self.threats_tree)
        
        # Blocked IPs
        lbl_blocked = Gtk.Label()
        lbl_blocked.set_markup("<span foreground='#FF0000' size='large'><b>🚫 BLOCKED IPs:</b></span>")
        lbl_blocked.set_xalign(0)
        vbox.pack_start(lbl_blocked, False, False, 5)
        
        scrolled2 = Gtk.ScrolledWindow()
        scrolled2.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled2.set_size_request(-1, 150)
        vbox.pack_start(scrolled2, True, True, 0)
        
        self.blocked_store = Gtk.ListStore(str, str)  # [IP, color]
        self.blocked_tree = Gtk.TreeView(model=self.blocked_store)
        self.blocked_tree.set_headers_visible(False)
        
        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Blocked", renderer2, text=0, foreground=1)
        col2.set_expand(True)
        self.blocked_tree.append_column(col2)
        scrolled2.add(self.blocked_tree)
        
    def on_scan_ports(self, button):
        """Scan open poorten en toon popup"""
        threading.Thread(target=self._do_port_scan, daemon=True).start()
        
    def _do_port_scan(self):
        """Voer port scan uit"""
        try:
            # Scan luisterende poorten
            result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
            lines = result.stdout.strip().splitlines()[1:]
            
            open_ports = {}
            for line in lines:
                parts = line.split()
                if len(parts) < 5:
                    continue
                    
                proto = parts[0]
                local = parts[4]
                
                # Extract port
                match = re.search(r':(\d+)$', local)
                if match:
                    port = int(match.group(1))
                    
                    # Get process name
                    process = "?"
                    if len(parts) >= 7:
                        pid_match = re.search(r'pid=(\d+)', parts[6])
                        if pid_match:
                            try:
                                pname = subprocess.run(
                                    ["ps", "-p", pid_match.group(1), "-o", "comm="],
                                    capture_output=True, text=True
                                ).stdout.strip()
                                process = pname if pname else "?"
                            except:
                                pass
                    
                    open_ports[port] = {
                        'proto': proto,
                        'process': process,
                        'description': PORT_DATABASE.get(port, "Unknown service")
                    }
            
            # Toon popup
            GLib.idle_add(self._show_port_popup, open_ports)
            
        except Exception as e:
            GLib.idle_add(self.log_threat, f"❌ Scan error: {e}", "#FF0000")
    
    def _show_port_popup(self, open_ports):
        """Toon popup met open poorten"""
        dialog = Gtk.Dialog(
            title="🔍 OPEN POORTEN SCAN RESULTAAT",
            parent=self,
            flags=Gtk.DialogFlags.MODAL
        )
        dialog.set_default_size(700, 500)
        
        content = dialog.get_content_area()
        content.set_margin_start(20)
        content.set_margin_end(20)
        content.set_margin_top(20)
        content.set_margin_bottom(20)
        
        # Header
        header = Gtk.Label()
        header.set_markup(f"<span size='x-large'><b>Gevonden: {len(open_ports)} open poorten</b></span>")
        content.pack_start(header, False, False, 10)
        
        # Scrolled window
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        content.pack_start(scrolled, True, True, 0)
        
        # TreeView
        store = Gtk.ListStore(str, str, str, str, str)  # Port, Proto, Process, Description, Color
        tree = Gtk.TreeView(model=store)
        
        # Columns
        cols = ["Poort", "Protocol", "Process", "Gebruik"]
        for i, title in enumerate(cols):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(title, renderer, text=i, foreground=4)
            col.set_resizable(True)
            col.set_sort_column_id(i)
            tree.append_column(col)
        
        scrolled.add(tree)
        
        # Vul data
        for port in sorted(open_ports.keys()):
            info = open_ports[port]
            
            # Kleur op basis van gevaar
            if port in [21, 23, 3389, 5900]:  # Gevaarlijke poorten
                color = "#FF0000"
            elif port in [22, 80, 443]:  # Normale poorten
                color = "#00FF00"
            else:
                color = "#FFA500"
            
            store.append([
                str(port),
                info['proto'],
                info['process'],
                info['description'],
                color
            ])
        
        # Close button
        dialog.add_button("Sluiten", Gtk.ResponseType.CLOSE)
        
        dialog.show_all()
        dialog.run()
        dialog.destroy()
    
    def _monitor_threats(self):
        """Monitor voor aanvallen"""
        while True:
            try:
                # Haal actieve verbindingen op
                result = subprocess.run(["ss", "-tn"], capture_output=True, text=True)
                lines = result.stdout.strip().splitlines()[1:]
                
                current_time = time.time()
                
                for line in lines:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    
                    remote = parts[5]
                    
                    # Extract IP
                    match = re.search(r'([0-9.]+):\d+', remote)
                    if not match:
                        continue
                    
                    ip = match.group(1)
                    
                    # Skip lokaal
                    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
                        continue
                    
                    # Track verbindingen
                    self.connection_tracker[ip].append(current_time)
                    
                    # Verwijder oude timestamps (ouder dan 10 sec)
                    self.connection_tracker[ip] = [
                        ts for ts in self.connection_tracker[ip]
                        if current_time - ts < 10
                    ]
                    
                    # Check voor aanval
                    conn_count = len(self.connection_tracker[ip])
                    if conn_count > SUSPICIOUS_THRESHOLD and ip not in self.blocked_ips:
                        # AANVAL GEDETECTEERD!
                        GLib.idle_add(self._trigger_alarm, ip, conn_count)
                        self._block_ip_auto(ip)
                
                time.sleep(2)
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(5)
    
    def _trigger_alarm(self, ip, conn_count):
        """Activeer rode alarm scherm"""
        self.alarm_active = True
        
        # Update status
        self.status_label.set_markup(
            f"<span foreground='#FF0000' size='x-large'><b>🚨 AANVAL GEDETECTEERD! 🚨</b></span>"
        )
        
        # Log threat
        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = f"[{timestamp}] 🚨 ATTACK from {ip} - {conn_count} connections/sec - AUTO BLOCKED"
        self.log_threat(msg, "#FF0000")
        
        # Toon fullscreen alarm
        self._show_alarm_screen(ip)
    
    def _show_alarm_screen(self, ip):
        """Toon knipperend rood alarm scherm - tekst blijft leesbaar"""
        # Maak fullscreen overlay
        if self.alarm_overlay is None:
            self.alarm_overlay = Gtk.Window()
            self.alarm_overlay.set_decorated(False)
            self.alarm_overlay.set_keep_above(True)
            self.alarm_overlay.fullscreen()
            
            # Label met tekst
            self.alarm_label = Gtk.Label()
            self.alarm_label.get_style_context().add_class("alarm-red")
            self.alarm_overlay.add(self.alarm_label)
        
        self.alarm_label.set_markup(
            f"<span size='72000'><b>🚨 SECURITY ALERT 🚨</b></span>\n\n"
            f"<span size='48000'>AANVAL GEDETECTEERD!\n\n"
            f"Verdacht IP: {ip}\n\n"
            f"Automatisch GEBLOKKEERD</span>"
        )
        
        self.alarm_overlay.show_all()
        
        # Start knipperen (alleen achtergrond)
        self.blink_count = 0
        GLib.timeout_add(500, self._blink_alarm)
    
    def _blink_alarm(self):
        """Laat achtergrond knipperen (tekst blijft zichtbaar)"""
        if self.blink_count >= 10:  # 5 seconden knipperen
            self.alarm_overlay.hide()
            self.alarm_active = False
            
            # Reset status na 5 sec
            GLib.timeout_add(5000, self._reset_status)
            return False
        
        # Toggle achtergrondkleur tussen rood en zwart
        style_context = self.alarm_label.get_style_context()
        if self.blink_count % 2 == 0:
            # Verwijder rode class, voeg zwarte toe
            style_context.remove_class("alarm-red")
            style_context.add_class("alarm-black")
        else:
            # Verwijder zwarte class, voeg rode toe
            style_context.remove_class("alarm-black")
            style_context.add_class("alarm-red")
        
        self.blink_count += 1
        return True
    
    def _reset_status(self):
        """Reset status naar veilig"""
        self.status_label.set_markup(
            "<span foreground='#00FF00' size='large'>✅ SYSTEEM VEILIG - Threat geblokkeerd</span>"
        )
        return False
    
    def _block_ip_auto(self, ip):
        """Blokkeer IP automatisch"""
        try:
            # Blokkeer met iptables
            subprocess.run(
                ["pkexec", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            
            self.blocked_ips.add(ip)
            
            # Update UI
            timestamp = datetime.now().strftime("%H:%M:%S")
            GLib.idle_add(
                self.blocked_store.append,
                [f"[{timestamp}] {ip} - AUTO BLOCKED", "#FF0000"]
            )
            
        except Exception as e:
            print(f"Block error: {e}")
    
    def log_threat(self, msg, color):
        """Log een threat"""
        self.threats_store.prepend([msg, color])
        
        # Limit tot 100 entries
        if len(self.threats_store) > 100:
            iter = self.threats_store.get_iter(100)
            if iter:
                self.threats_store.remove(iter)
    
    def on_test_alarm(self, button):
        """Test het alarm systeem"""
        self._trigger_alarm("123.45.67.89", 999)
    
    def on_clear_blocks(self, button):
        """Clear alle geblokkeerde IPs"""
        try:
            # Flush iptables INPUT chain (alleen DROP rules)
            subprocess.run(
                ["pkexec", "iptables", "-F", "INPUT"],
                capture_output=True
            )
            
            self.blocked_ips.clear()
            self.blocked_store.clear()
            self.log_threat("✅ Alle blocks verwijderd", "#00FF00")
            
        except Exception as e:
            self.log_threat(f"❌ Clear error: {e}", "#FF0000")

if __name__ == "__main__":
    win = SecurityDefense()
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()
