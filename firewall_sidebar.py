#!/usr/bin/env python3
# Firewall & Security Sidebar - IP blokkeren en systeem activiteit
# Werkt samen met port_sidebar.py

import gi, subprocess, time, threading, re, os
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

INTERVAL = 3.0  # seconden tussen checks

class FirewallSidebar(Gtk.Window):
    def __init__(self):
        super().__init__(title="Firewall & Security")

        # 🔥 Rode/Oranje thema voor security
        css = Gtk.CssProvider()
        css.load_from_data(b"""
        window {
            background-color: #0a0a0a;
            color: #FF6B35;
        }
        treeview {
            background-color: #0a0a0a;
            color: #FF6B35;
        }
        button {
            background-color: #1a1a1a;
            color: #FF6B35;
            border: 1px solid #FF6B35;
            padding: 5px;
        }
        button:hover {
            background-color: #2a2a2a;
        }
        """)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        self.set_decorated(False)
        self.set_keep_above(True)
        self.set_resizable(True)
        self.set_default_size(550, 700)

        # Positie links op scherm (nieuwe GTK3 methode)
        display = Gdk.Display.get_default()
        monitor = display.get_primary_monitor()
        if monitor:
            geom = monitor.get_geometry()
            self.move(geom.x + 30, geom.y + 30)
        else:
            self.move(30, 30)  # Fallback positie

        self.connect("delete-event", Gtk.main_quit)

        # State
        self.blocked_ips = set()
        self.lock = threading.Lock()

        # Main container
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        # Header met drag functie
        self.header_box = Gtk.EventBox()
        header = Gtk.Label()
        header.set_markup("<span foreground='#FF6B35' size='large'><b>🔥 Firewall Control</b></span>")
        header.set_xalign(0)
        header.set_margin_start(6)
        header.set_margin_end(6)
        header.set_margin_top(6)
        header.set_margin_bottom(6)
        self.header_box.add(header)
        
        # Mouse events voor dragging
        self.header_box.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK |
            Gdk.EventMask.ENTER_NOTIFY_MASK |
            Gdk.EventMask.LEAVE_NOTIFY_MASK
        )
        
        self.header_box.connect("button-press-event", self.on_header_click)
        self.header_box.connect("enter-notify-event", self.on_header_enter)
        self.header_box.connect("leave-notify-event", self.on_header_leave)
        
        vbox.pack_start(self.header_box, False, False, 0)

        # IP Block sectie
        block_frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        vbox.pack_start(block_frame, False, False, 5)

        lbl_block = Gtk.Label()
        lbl_block.set_markup("<span foreground='#FF4444'><b>🚫 Blokkeer IP Adres:</b></span>")
        lbl_block.set_xalign(0)
        lbl_block.set_margin_start(6)
        block_frame.pack_start(lbl_block, False, False, 0)

        ip_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        ip_box.set_margin_start(6)
        ip_box.set_margin_end(6)
        block_frame.pack_start(ip_box, False, False, 0)

        self.entry_ip = Gtk.Entry()
        self.entry_ip.set_placeholder_text("IP adres (bijv. 192.168.1.100)")
        ip_box.pack_start(self.entry_ip, True, True, 0)

        btn_block = Gtk.Button(label="🚫 Block")
        btn_block.connect("clicked", self.on_block_ip)
        ip_box.pack_start(btn_block, False, False, 0)

        btn_unblock = Gtk.Button(label="✅ Unblock")
        btn_unblock.connect("clicked", self.on_unblock_ip)
        ip_box.pack_start(btn_unblock, False, False, 0)

        # Quick actions
        quick_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        quick_box.set_margin_start(6)
        quick_box.set_margin_end(6)
        block_frame.pack_start(quick_box, False, False, 3)

        btn_show_rules = Gtk.Button(label="📋 Toon Rules")
        btn_show_rules.connect("clicked", self.on_show_rules)
        quick_box.pack_start(btn_show_rules, True, True, 0)

        btn_flush = Gtk.Button(label="💧 Flush All")
        btn_flush.connect("clicked", self.on_flush_rules)
        quick_box.pack_start(btn_flush, True, True, 0)

        btn_status = Gtk.Button(label="⚡ UFW Status")
        btn_status.connect("clicked", self.on_ufw_status)
        quick_box.pack_start(btn_status, True, True, 0)

        # Backup/Restore en Security Scan
        backup_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        backup_box.set_margin_start(6)
        backup_box.set_margin_end(6)
        block_frame.pack_start(backup_box, False, False, 3)

        btn_save = Gtk.Button(label="💾 Save Rules")
        btn_save.connect("clicked", self.on_save_rules)
        backup_box.pack_start(btn_save, True, True, 0)

        btn_restore = Gtk.Button(label="♻️ Restore")
        btn_restore.connect("clicked", self.on_restore_rules)
        backup_box.pack_start(btn_restore, True, True, 0)

        btn_scan = Gtk.Button(label="🔍 Security Scan")
        btn_scan.connect("clicked", self.on_security_scan)
        backup_box.pack_start(btn_scan, True, True, 0)

        # Dangerous actions
        danger_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        danger_box.set_margin_start(6)
        danger_box.set_margin_end(6)
        block_frame.pack_start(danger_box, False, False, 3)

        btn_close_all = Gtk.Button(label="🔒 Close All Ports")
        btn_close_all.connect("clicked", self.on_close_all_ports)
        danger_box.pack_start(btn_close_all, True, True, 0)

        btn_lockdown = Gtk.Button(label="🛡️ Lockdown Mode")
        btn_lockdown.connect("clicked", self.on_lockdown_mode)
        danger_box.pack_start(btn_lockdown, True, True, 0)

        # Geblokkeerde IPs lijst
        lbl_blocked = Gtk.Label()
        lbl_blocked.set_markup("<span foreground='#FF4444'><b>🔒 Geblokkeerde IP's:</b></span>")
        lbl_blocked.set_xalign(0)
        lbl_blocked.set_margin_start(6)
        vbox.pack_start(lbl_blocked, False, False, 3)

        scrolled1 = Gtk.ScrolledWindow()
        scrolled1.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled1.set_size_request(-1, 150)
        vbox.pack_start(scrolled1, False, False, 0)

        self.blocked_store = Gtk.ListStore(str, str)  # [IP, timestamp]
        self.blocked_tree = Gtk.TreeView(model=self.blocked_store)
        self.blocked_tree.set_headers_visible(True)
        self.blocked_tree.connect("button-press-event", self.on_blocked_tree_click)

        renderer = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn("Geblokkeerde IP's", renderer, text=0, foreground=1)
        col.set_expand(True)
        self.blocked_tree.append_column(col)
        scrolled1.add(self.blocked_tree)

        # Open Poorten Lijst - GROOT EN ZICHTBAAR
        lbl_open_ports = Gtk.Label()
        lbl_open_ports.set_markup("<span foreground='#FFD700' size='x-large'><b>🔓 OPEN POORTEN:</b></span>")
        lbl_open_ports.set_xalign(0)
        lbl_open_ports.set_margin_start(6)
        lbl_open_ports.set_margin_top(10)
        vbox.pack_start(lbl_open_ports, False, False, 5)

        scrolled_ports = Gtk.ScrolledWindow()
        scrolled_ports.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled_ports.set_size_request(-1, 180)
        vbox.pack_start(scrolled_ports, False, False, 0)

        self.ports_store = Gtk.ListStore(str, str)  # [port info, color]
        self.ports_tree = Gtk.TreeView(model=self.ports_store)
        self.ports_tree.set_headers_visible(True)

        renderer_port = Gtk.CellRendererText()
        col_port = Gtk.TreeViewColumn("🔌 Protocol | Poort | Process", renderer_port, text=0, foreground=1)
        col_port.set_expand(True)
        self.ports_tree.append_column(col_port)
        scrolled_ports.add(self.ports_tree)

        # Systeem Activiteit (kleiner)
        lbl_activity = Gtk.Label()
        lbl_activity.set_markup("<span foreground='#00BFFF'><b>📊 Systeem Info:</b></span>")
        lbl_activity.set_xalign(0)
        lbl_activity.set_margin_start(6)
        vbox.pack_start(lbl_activity, False, False, 3)

        scrolled2 = Gtk.ScrolledWindow()
        scrolled2.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled2.set_size_request(-1, 100)
        vbox.pack_start(scrolled2, False, False, 0)

        self.activity_store = Gtk.ListStore(str, str)  # [activity, color]
        self.activity_tree = Gtk.TreeView(model=self.activity_store)
        self.activity_tree.set_headers_visible(False)

        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Activiteit", renderer2, text=0, foreground=1)
        col2.set_expand(True)
        self.activity_tree.append_column(col2)
        scrolled2.add(self.activity_tree)

        # Live IP Verbindingen (vervangen van login pogingen)
        lbl_ips = Gtk.Label()
        lbl_ips.set_markup("<span foreground='#FF6B35'><b>🌐 Live IP Verbindingen (wie praat met mijn PC):</b></span>")
        lbl_ips.set_xalign(0)
        lbl_ips.set_margin_start(6)
        vbox.pack_start(lbl_ips, False, False, 3)

        scrolled3 = Gtk.ScrolledWindow()
        scrolled3.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled3.set_size_request(-1, 150)
        vbox.pack_start(scrolled3, True, True, 0)

        self.ip_store = Gtk.ListStore(str, str, str)  # [IP, richting, color]
        self.ip_tree = Gtk.TreeView(model=self.ip_store)
        self.ip_tree.set_headers_visible(False)
        self.ip_tree.connect("button-press-event", self.on_ip_tree_click)

        renderer3 = Gtk.CellRendererText()
        col3 = Gtk.TreeViewColumn("IP", renderer3, text=0, foreground=2)
        col3.set_expand(True)
        self.ip_tree.append_column(col3)
        scrolled3.add(self.ip_tree)

        # Start monitoring threads
        threading.Thread(target=self._monitor_activity, daemon=True).start()
        threading.Thread(target=self._monitor_live_ips, daemon=True).start()
        threading.Thread(target=self._monitor_open_ports, daemon=True).start()
        GLib.timeout_add(5000, self.refresh_blocked_list)

    def on_header_click(self, widget, event):
        """Start window drag"""
        if event.button == 1:
            self.begin_move_drag(event.button, int(event.x_root), int(event.y_root), event.time)
        return True

    def on_header_enter(self, widget, event):
        """Cursor naar handje"""
        window = widget.get_window()
        if window:
            window.set_cursor(Gdk.Cursor.new_from_name(Gdk.Display.get_default(), "grab"))
        return False

    def on_header_leave(self, widget, event):
        """Reset cursor"""
        window = widget.get_window()
        if window:
            window.set_cursor(None)
        return False

    def on_block_ip(self, button):
        """Blokkeer een IP adres met iptables"""
        ip = self.entry_ip.get_text().strip()
        if not self.validate_ip(ip):
            self.show_notification("⚠️ Ongeldig IP adres", "#FFA500")
            return

        try:
            # Gebruik pkexec voor grafische sudo prompt (of NOPASSWD sudoers)
            # Probeer eerst zonder sudo (als NOPASSWD is ingesteld)
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            
            # Als dat niet werkt, probeer met pkexec (grafische prompt)
            if result.returncode != 0:
                result = subprocess.run(
                    ["pkexec", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True
                )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                timestamp = time.strftime("%H:%M:%S")
                GLib.idle_add(self.blocked_store.prepend, [f"{ip} (geblokkeerd om {timestamp})", "#FF0000"])
                self.show_notification(f"✅ IP {ip} geblokkeerd!", "#00FF00")
                self.entry_ip.set_text("")
            else:
                # Probeer met hosts.deny als alternatief (geen sudo nodig)
                self.block_via_hosts_deny(ip)
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def block_via_hosts_deny(self, ip):
        """Alternatieve methode: blokkeer via /etc/hosts.deny (TCP wrappers)"""
        try:
            result = subprocess.run(
                ["pkexec", "sh", "-c", f"echo 'ALL: {ip}' >> /etc/hosts.deny"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                timestamp = time.strftime("%H:%M:%S")
                GLib.idle_add(self.blocked_store.prepend, [f"{ip} (hosts.deny {timestamp})", "#FF0000"])
                self.show_notification(f"✅ IP {ip} geblokkeerd via hosts.deny!", "#00FF00")
                self.entry_ip.set_text("")
            else:
                self.show_notification(f"❌ Geen permissie. Setup required.", "#FF0000")
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_unblock_ip(self, button):
        """Deblokkeer een IP adres"""
        ip = self.entry_ip.get_text().strip()
        if not self.validate_ip(ip):
            self.show_notification("⚠️ Ongeldig IP adres", "#FFA500")
            return

        try:
            # Probeer met iptables (zonder sudo eerst, dan met pkexec)
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                result = subprocess.run(
                    ["pkexec", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True
                )
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.show_notification(f"✅ IP {ip} gedeblokkeerd!", "#00FF00")
                self.entry_ip.set_text("")
                GLib.idle_add(self.refresh_blocked_list)
            else:
                # Probeer hosts.deny te cleanen
                self.unblock_via_hosts_deny(ip)
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def unblock_via_hosts_deny(self, ip):
        """Verwijder IP uit hosts.deny"""
        try:
            result = subprocess.run(
                ["pkexec", "sed", "-i", f"/ALL: {ip}/d", "/etc/hosts.deny"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.show_notification(f"✅ IP {ip} verwijderd uit hosts.deny!", "#00FF00")
                self.entry_ip.set_text("")
                GLib.idle_add(self.refresh_blocked_list)
            else:
                self.show_notification(f"⚠️ IP niet gevonden", "#FFA500")
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def validate_ip(self, ip):
        """Valideer IP adres format"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if pattern.match(ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False

    def on_show_rules(self, button):
        """Toon firewall rules"""
        try:
            # Probeer eerst zonder sudo
            result = subprocess.run(["iptables", "-L", "-n", "-v"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                result = subprocess.run(["pkexec", "iptables", "-L", "-n", "-v"], 
                                      capture_output=True, text=True)
            
            lines = result.stdout.split('\n')[:20]  # Eerste 20 regels
            GLib.idle_add(self.activity_store.clear)
            for line in lines:
                if line.strip():
                    GLib.idle_add(self.activity_store.append, [line, "#00BFFF"])
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_flush_rules(self, button):
        """Flush alle iptables rules (GEVAARLIJK!)"""
        dialog = Gtk.MessageDialog(
            parent=self,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text="⚠️ Alle firewall rules verwijderen?"
        )
        dialog.format_secondary_text("Dit verwijdert ALLE iptables rules. Weet je het zeker?")
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            try:
                result = subprocess.run(["iptables", "-F"], capture_output=True, text=True)
                if result.returncode != 0:
                    result = subprocess.run(["pkexec", "iptables", "-F"], check=True)
                self.blocked_ips.clear()
                GLib.idle_add(self.blocked_store.clear)
                self.show_notification("✅ Alle rules verwijderd!", "#00FF00")
            except Exception as e:
                self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_ufw_status(self, button):
        """Toon UFW status"""
        try:
            result = subprocess.run(["ufw", "status", "verbose"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                result = subprocess.run(["pkexec", "ufw", "status", "verbose"], 
                                      capture_output=True, text=True)
            
            GLib.idle_add(self.activity_store.clear)
            for line in result.stdout.split('\n'):
                if line.strip():
                    GLib.idle_add(self.activity_store.append, [line, "#FFD700"])
        except Exception as e:
            self.show_notification(f"❌ UFW niet beschikbaar: {e}", "#FF0000")

    def on_save_rules(self, button):
        """Sla huidige firewall rules op naar backup bestand"""
        try:
            backup_file = os.path.expanduser("~/firewall_rules_backup.txt")
            
            # Sla iptables rules op
            result = subprocess.run(["iptables-save"], capture_output=True, text=True)
            if result.returncode != 0:
                result = subprocess.run(["pkexec", "iptables-save"], capture_output=True, text=True)
            
            if result.returncode == 0:
                with open(backup_file, 'w') as f:
                    f.write(f"# Firewall Rules Backup - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(result.stdout)
                
                self.show_notification(f"✅ Rules opgeslagen in {backup_file}", "#00FF00")
            else:
                self.show_notification("❌ Kon rules niet opslaan", "#FF0000")
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_restore_rules(self, button):
        """Herstel firewall rules van backup"""
        backup_file = os.path.expanduser("~/firewall_rules_backup.txt")
        
        if not os.path.exists(backup_file):
            self.show_notification("⚠️ Geen backup gevonden!", "#FFA500")
            return
        
        dialog = Gtk.MessageDialog(
            parent=self,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="♻️ Firewall rules herstellen?"
        )
        dialog.format_secondary_text(f"Dit zal de huidige rules vervangen met backup.\n\nBackup: {backup_file}")
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            try:
                # Lees backup
                with open(backup_file, 'r') as f:
                    rules = f.read()
                
                # Herstel rules
                result = subprocess.run(
                    ["pkexec", "sh", "-c", f"echo '{rules}' | iptables-restore"],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    self.show_notification("✅ Rules hersteld!", "#00FF00")
                else:
                    self.show_notification("❌ Kon rules niet herstellen", "#FF0000")
            except Exception as e:
                self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_security_scan(self, button):
        """Voer complete security scan uit"""
        self.show_notification("🔍 Security scan gestart...", "#00BFFF")
        GLib.idle_add(self.activity_store.clear)
        
        # Start scan in background thread
        threading.Thread(target=self._run_security_scan, daemon=True).start()

    def _run_security_scan(self):
        """Voer security checks uit"""
        findings = []
        score = 100
        
        # 1. Check UFW status
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "Status: active" in result.stdout:
                findings.append(("✅ UFW Firewall: ACTIEF", "#00FF00"))
            else:
                findings.append(("❌ UFW Firewall: INACTIEF (GEVAAR!)", "#FF0000"))
                score -= 30
        except:
            findings.append(("⚠️ UFW niet geïnstalleerd", "#FFA500"))
            score -= 20
        
        # 2. Check open poorten
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            open_ports = len([l for l in result.stdout.split('\n') if ':' in l]) - 1
            if open_ports < 10:
                findings.append((f"✅ Open poorten: {open_ports} (goed)", "#00FF00"))
            elif open_ports < 20:
                findings.append((f"⚠️ Open poorten: {open_ports} (veel)", "#FFA500"))
                score -= 10
            else:
                findings.append((f"❌ Open poorten: {open_ports} (TE VEEL!)", "#FF0000"))
                score -= 20
        except:
            pass
        
        # 3. Check SSH configuratie
        if os.path.exists("/etc/ssh/sshd_config"):
            try:
                with open("/etc/ssh/sshd_config", 'r') as f:
                    ssh_config = f.read()
                    
                if "PermitRootLogin no" in ssh_config or "PermitRootLogin prohibit-password" in ssh_config:
                    findings.append(("✅ SSH: Root login uitgeschakeld", "#00FF00"))
                else:
                    findings.append(("⚠️ SSH: Root login mogelijk (risico)", "#FFA500"))
                    score -= 15
                    
                if "PasswordAuthentication no" in ssh_config:
                    findings.append(("✅ SSH: Alleen key-based auth", "#00FF00"))
                else:
                    findings.append(("⚠️ SSH: Password auth ingeschakeld", "#FFA500"))
                    score -= 10
            except:
                findings.append(("⚠️ SSH config niet leesbaar", "#FFA500"))
        else:
            findings.append(("✅ SSH niet geïnstalleerd", "#00FF00"))
        
        # 4. Check voor gevaarlijke open poorten
        dangerous_ports = [23, 21, 445, 139, 3389]  # telnet, ftp, smb, rdp
        try:
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            for port in dangerous_ports:
                if f":{port}" in result.stdout:
                    findings.append((f"❌ GEVAAR: Poort {port} is open!", "#FF0000"))
                    score -= 25
        except:
            pass
        
        # 5. Check iptables rules
        try:
            result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
            if result.returncode != 0:
                result = subprocess.run(["pkexec", "iptables", "-L", "-n"], capture_output=True, text=True)
            
            rules_count = len([l for l in result.stdout.split('\n') if 'DROP' in l or 'REJECT' in l])
            if rules_count > 0:
                findings.append((f"✅ iptables: {rules_count} blokkeer regels actief", "#00FF00"))
            else:
                findings.append(("⚠️ iptables: Geen blokkeer regels", "#FFA500"))
                score -= 15
        except:
            pass
        
        # 6. Check failed login attempts
        try:
            if os.path.exists("/var/log/auth.log") and os.access("/var/log/auth.log", os.R_OK):
                result = subprocess.run(
                    ["grep", "-c", "Failed password", "/var/log/auth.log"],
                    capture_output=True, text=True
                )
                failed_count = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                if failed_count > 50:
                    findings.append((f"❌ {failed_count} mislukte logins! (aanval?)", "#FF0000"))
                    score -= 20
                elif failed_count > 10:
                    findings.append((f"⚠️ {failed_count} mislukte logins", "#FFA500"))
                    score -= 10
                else:
                    findings.append((f"✅ {failed_count} mislukte logins (normaal)", "#00FF00"))
        except:
            pass
        
        # Bepaal overall status
        if score >= 80:
            status_color = "#00FF00"
            status = "GOED BEVEILIGD"
        elif score >= 60:
            status_color = "#FFD700"
            status = "MATIG BEVEILIGD"
        elif score >= 40:
            status_color = "#FFA500"
            status = "ZWAK BEVEILIGD"
        else:
            status_color = "#FF0000"
            status = "ONVEILIG!"
        
        # Toon resultaten
        GLib.idle_add(self.activity_store.append, [f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "#FFFFFF"])
        GLib.idle_add(self.activity_store.append, [f"🛡️  SECURITY SCAN RESULTATEN", "#FFFFFF"])
        GLib.idle_add(self.activity_store.append, [f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "#FFFFFF"])
        GLib.idle_add(self.activity_store.append, [f"", "#FFFFFF"])
        GLib.idle_add(self.activity_store.append, [f"📊 Security Score: {score}/100", status_color])
        GLib.idle_add(self.activity_store.append, [f"🔒 Status: {status}", status_color])
        GLib.idle_add(self.activity_store.append, [f"", "#FFFFFF"])
        
        for finding, color in findings:
            GLib.idle_add(self.activity_store.append, [finding, color])
        
        GLib.idle_add(self.activity_store.append, [f"", "#FFFFFF"])
        GLib.idle_add(self.activity_store.append, [f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "#FFFFFF"])
        
        if score < 80:
            GLib.idle_add(self.activity_store.append, [f"💡 TIP: Verbeter je score door:", "#00BFFF"])
            if score < 70:
                GLib.idle_add(self.activity_store.append, [f"   1. UFW activeren: sudo ufw enable", "#00BFFF"])
            if score < 80:
                GLib.idle_add(self.activity_store.append, [f"   2. Onnodige poorten sluiten", "#00BFFF"])
                GLib.idle_add(self.activity_store.append, [f"   3. SSH root login uitschakelen", "#00BFFF"])
        
        GLib.idle_add(self.show_notification, f"✅ Scan compleet! Score: {score}/100", status_color)

    def on_close_all_ports(self, button):
        """Sluit alle niet-essentiële open poorten (GEVAARLIJK!)"""
        dialog = Gtk.MessageDialog(
            parent=self,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text="🔒 ALLE open poorten sluiten?"
        )
        dialog.format_secondary_text(
            "Dit zal ALLE luisterende processen stoppen behalve:\n"
            "- SSH (22) - om locked out te voorkomen\n"
            "- Dit script zelf\n\n"
            "⚠️ Dit stopt webservers, databases, etc!\n"
            "Weet je het ZEKER?"
        )
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            threading.Thread(target=self._close_all_ports_thread, daemon=True).start()

    def _close_all_ports_thread(self):
        """Background thread om alle poorten te sluiten"""
        GLib.idle_add(self.show_notification, "🔒 Bezig met sluiten van poorten...", "#FFA500")
        
        closed_count = 0
        skipped = []
        essential_ports = [22]  # SSH - niet sluiten!
        
        try:
            # Get alle luisterende processen
            result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
            
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) < 7:
                    continue
                
                local = parts[4]
                
                # Extract poort
                try:
                    port = int(local.split(':')[-1])
                except:
                    continue
                
                # Skip essentiële poorten
                if port in essential_ports:
                    skipped.append(f"Port {port} (SSH)")
                    continue
                
                # Skip localhost only
                if "127.0.0.1" in local or "::1" in local:
                    continue
                
                # Extract PID
                pid_match = re.search(r'pid=(\d+)', parts[6] if len(parts) > 6 else "")
                if pid_match:
                    pid = pid_match.group(1)
                    
                    # Get process naam
                    try:
                        pname = subprocess.run(
                            ["ps", "-p", pid, "-o", "comm="],
                            capture_output=True, text=True
                        ).stdout.strip()
                        
                        # Skip eigen proces
                        if "python" in pname.lower() and "sidebar" in pname.lower():
                            continue
                        
                        # Kill proces
                        os.kill(int(pid), signal.SIGTERM)
                        closed_count += 1
                        GLib.idle_add(
                            self.show_notification,
                            f"✅ Gesloten: {pname} op poort {port}",
                            "#00FF00"
                        )
                        time.sleep(0.1)  # Kleine pauze
                        
                    except Exception as e:
                        print(f"Kon proces {pid} niet stoppen: {e}")
        
        except Exception as e:
            GLib.idle_add(self.show_notification, f"❌ Error: {e}", "#FF0000")
        
        # Samenvatting
        summary = f"🔒 {closed_count} poorten gesloten"
        if skipped:
            summary += f"\n⚠️ {len(skipped)} overgeslagen (essentieel)"
        
        GLib.idle_add(self.show_notification, summary, "#FFD700")

    def on_lockdown_mode(self, button):
        """Volledige lockdown: sluit poorten + blokkeer alle inkomend verkeer"""
        dialog = Gtk.MessageDialog(
            parent=self,
            flags=0,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.YES_NO,
            text="🛡️ LOCKDOWN MODE?"
        )
        dialog.format_secondary_text(
            "⚠️ EXTREME MAATREGEL ⚠️\n\n"
            "Dit zal:\n"
            "1. ALLE open poorten sluiten\n"
            "2. ALLE inkomend verkeer blokkeren\n"
            "3. UFW op 'deny incoming' zetten\n\n"
            "Gebruik dit ALLEEN bij:\n"
            "- Actieve aanval gedetecteerd\n"
            "- Verdacht gedrag\n"
            "- Emergency situatie\n\n"
            "Je kunt hierna niet meer bereikbaar zijn!\n"
            "Doorgaan?"
        )
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            threading.Thread(target=self._lockdown_mode_thread, daemon=True).start()

    def _lockdown_mode_thread(self):
        """Volledige lockdown uitvoeren"""
        GLib.idle_add(self.show_notification, "🛡️ LOCKDOWN MODE GEACTIVEERD!", "#FF0000")
        
        try:
            # 1. Sluit alle poorten
            GLib.idle_add(self.show_notification, "🔒 Stap 1: Sluiten alle poorten...", "#FFA500")
            self._close_all_ports_thread()
            
            time.sleep(1)
            
            # 2. Blokkeer alle inkomend verkeer
            GLib.idle_add(self.show_notification, "🚫 Stap 2: Blokkeren inkomend verkeer...", "#FFA500")
            
            # iptables: drop alles behalve established
            commands = [
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        subprocess.run(["pkexec"] + cmd, capture_output=True, text=True)
                except:
                    pass
            
            # UFW lockdown
            try:
                subprocess.run(["pkexec", "ufw", "default", "deny", "incoming"], 
                             capture_output=True, text=True)
                subprocess.run(["pkexec", "ufw", "enable"], 
                             capture_output=True, text=True)
            except:
                pass
            
            time.sleep(1)
            
            # 3. Klaar
            GLib.idle_add(self.show_notification, "✅ LOCKDOWN ACTIEF - Machine beveiligd!", "#FF0000")
            GLib.idle_add(self.show_notification, "⚠️ Restart nodig om normale mode te herstellen", "#FFA500")
            
        except Exception as e:
            GLib.idle_add(self.show_notification, f"❌ Lockdown error: {e}", "#FF0000")

    def refresh_blocked_list(self):
        """Refresh lijst van geblokkeerde IPs"""
        return True

    def on_blocked_tree_click(self, treeview, event):
        """Rechtermuisklik op geblokkeerd IP voor quick unblock"""
        if event.button == 3:
            path = treeview.get_path_at_pos(int(event.x), int(event.y))
            if path:
                model, tree_iter = treeview.get_selection().get_selected()
                if tree_iter:
                    text = model[tree_iter][0]
                    ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', text)
                    if ip_match:
                        self.entry_ip.set_text(ip_match.group(1))
        return True

    def on_login_tree_click(self, treeview, event):
        """Rechtermuisklik op IP voor extractie"""
        if event.button == 3:
            path = treeview.get_path_at_pos(int(event.x), int(event.y))
            if path:
                model, tree_iter = treeview.get_selection().get_selected()
                if tree_iter:
                    text = model[tree_iter][0]
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
                    if ip_match:
                        self.entry_ip.set_text(ip_match.group(1))
        return True

    def on_ip_tree_click(self, treeview, event):
        """Rechtermuisklik op IP verbinding voor blokkeren"""
        if event.button == 3:
            path = treeview.get_path_at_pos(int(event.x), int(event.y))
            if path:
                model, tree_iter = treeview.get_selection().get_selected()
                if tree_iter:
                    text = model[tree_iter][0]
                    # Extract IP (eerste IP in de regel)
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
                    if ip_match:
                        ip = ip_match.group(1)
                        # Skip eigen IP's
                        if not ip.startswith("127.") and not ip.startswith("0."):
                            self.entry_ip.set_text(ip)
                            
                            # Toon quick menu
                            menu = Gtk.Menu()
                            
                            item_block = Gtk.MenuItem(label=f"🚫 Block {ip}")
                            item_block.connect("activate", lambda x: self.on_block_ip(None))
                            menu.append(item_block)
                            
                            menu.show_all()
                            menu.popup(None, None, None, None, event.button, event.time)
        return True

    def _monitor_activity(self):
        """Monitor systeem activiteit"""
        while True:
            try:
                # CPU en Memory gebruik
                cpu = subprocess.run(["top", "-bn1"], capture_output=True, text=True)
                cpu_line = [l for l in cpu.stdout.split('\n') if 'Cpu(s)' in l]
                if cpu_line:
                    GLib.idle_add(self.activity_store.prepend, 
                                [f"🖥️ {cpu_line[0].strip()}", "#00FF00"])
                
                # Netwerk activiteit
                net = subprocess.run(["ss", "-s"], capture_output=True, text=True)
                net_lines = net.stdout.split('\n')[:3]
                for line in net_lines:
                    if line.strip():
                        GLib.idle_add(self.activity_store.prepend, 
                                    [f"🌐 {line.strip()}", "#00BFFF"])
                
                # Limiteer lijst tot 50 items
                if len(self.activity_store) > 50:
                    GLib.idle_add(lambda: self.activity_store.remove(
                        self.activity_store.get_iter(len(self.activity_store)-1)))
                
            except Exception as e:
                print(f"Activity monitor error: {e}")
            
            time.sleep(INTERVAL)

    def _monitor_open_ports(self):
        """Monitor alle open/luisterende poorten"""
        while True:
            try:
                # Get alle luisterende poorten
                result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
                
                ports_list = []
                
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    proto = parts[0]
                    local = parts[4]
                    
                    # Extract poort
                    try:
                        if ':' in local:
                            port = local.split(':')[-1]
                        else:
                            continue
                        
                        # Skip als geen getal
                        if not port.isdigit():
                            continue
                        
                        port_num = int(port)
                        
                        # Get process info
                        process = "?"
                        if len(parts) >= 7:
                            pid_match = re.search(r'pid=(\d+)', parts[6])
                            if pid_match:
                                pid = pid_match.group(1)
                                try:
                                    pname = subprocess.run(
                                        ["ps", "-p", pid, "-o", "comm="],
                                        capture_output=True, text=True
                                    ).stdout.strip()
                                    process = pname if pname else "?"
                                except:
                                    pass
                        
                        # Bepaal kleur op basis van poort
                        if port_num in [22, 80, 443]:  # Standaard poorten
                            color = "#00FF00"  # Groen - normaal
                        elif port_num < 1024:  # Privileged ports
                            color = "#FFD700"  # Goud - belangrijk
                        elif port_num in [23, 21, 445, 139, 3389]:  # Gevaarlijk
                            color = "#FF0000"  # Rood - gevaar!
                        else:
                            color = "#00BFFF"  # Blauw - custom
                        
                        # Check if localhost only
                        if "127.0.0.1" in local or "::1" in local:
                            scope = "localhost"
                            color = "#808080"  # Grijs - alleen local
                        else:
                            scope = "EXTERN"
                        
                        ports_list.append({
                            'proto': proto,
                            'port': port_num,
                            'process': process,
                            'scope': scope,
                            'color': color,
                            'local': local
                        })
                    
                    except Exception as e:
                        continue
                
                # Update UI
                GLib.idle_add(self.ports_store.clear)
                
                # Sorteer op poortnummer
                ports_list.sort(key=lambda x: x['port'])
                
                # Groepeer per type
                extern_ports = [p for p in ports_list if p['scope'] == 'EXTERN']
                local_ports = [p for p in ports_list if p['scope'] == 'localhost']
                
                # Toon externe poorten eerst (belangrijker!)
                if extern_ports:
                    GLib.idle_add(self.ports_store.append, ["═══ EXTERNE POORTEN (bereikbaar van buitenaf) ═══", "#FFFFFF"])
                    for port in extern_ports:
                        display = f"{port['proto']:4} | {port['port']:5} | {port['process'][:20]:20} | {port['local']}"
                        GLib.idle_add(self.ports_store.append, [display, port['color']])
                
                # Dan localhost poorten
                if local_ports:
                    GLib.idle_add(self.ports_store.append, ["", "#000000"])
                    GLib.idle_add(self.ports_store.append, ["═══ LOCALHOST POORTEN (alleen intern) ═══", "#808080"])
                    for port in local_ports[:10]:  # Max 10 localhost
                        display = f"{port['proto']:4} | {port['port']:5} | {port['process'][:20]:20}"
                        GLib.idle_add(self.ports_store.append, [display, port['color']])
                
                # Totalen
                GLib.idle_add(self.ports_store.append, ["", "#000000"])
                summary = f"📊 Totaal: {len(extern_ports)} extern, {len(local_ports)} localhost"
                GLib.idle_add(self.ports_store.append, [summary, "#FFFFFF"])
                
                # Waarschuwing bij gevaarlijke poorten
                dangerous = [p for p in extern_ports if p['port'] in [23, 21, 445, 139, 3389]]
                if dangerous:
                    GLib.idle_add(self.ports_store.append, [f"⚠️ GEVAAR: {len(dangerous)} onveilige poorten open!", "#FF0000"])
                
            except Exception as e:
                print(f"Port monitor error: {e}")
            
            time.sleep(INTERVAL)  # Update elke 3 seconden

    def _monitor_live_ips(self):
        """Monitor live IP verbindingen - wie praat met je PC"""
        seen_ips = {}
        
        while True:
            try:
                # Get alle actieve verbindingen
                result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
                
                current_ips = {}
                
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    
                    proto = parts[0]
                    state = parts[1] if len(parts) > 1 else ""
                    local = parts[4] if len(parts) > 4 else ""
                    remote = parts[5] if len(parts) > 5 else ""
                    
                    # Skip als geen remote IP
                    if not remote or remote == "*" or ":" not in remote:
                        continue
                    
                    # Extract remote IP
                    try:
                        remote_ip = remote.rsplit(':', 1)[0]
                        remote_port = remote.rsplit(':', 1)[1]
                        local_port = local.rsplit(':', 1)[1] if ':' in local else "?"
                        
                        # Skip localhost
                        if remote_ip.startswith("127.") or remote_ip.startswith("::1") or remote_ip == "0.0.0.0":
                            continue
                        
                        # Bepaal richting
                        if state in ["ESTAB", "ESTABLISHED"]:
                            direction = "↔"
                        elif state == "LISTEN":
                            continue  # Skip listeners
                        else:
                            direction = "→"
                        
                        # Count verbindingen per IP
                        if remote_ip not in current_ips:
                            current_ips[remote_ip] = {
                                'count': 0,
                                'ports': set(),
                                'proto': proto,
                                'direction': direction
                            }
                        
                        current_ips[remote_ip]['count'] += 1
                        current_ips[remote_ip]['ports'].add(remote_port)
                        
                    except:
                        continue
                
                # Lookup hostnames voor nieuwe IPs (in background)
                for ip in current_ips:
                    if ip not in seen_ips:
                        try:
                            # Quick reverse DNS lookup (timeout 1 sec)
                            import socket
                            socket.setdefaulttimeout(1)
                            hostname = socket.gethostbyaddr(ip)[0]
                            seen_ips[ip] = hostname[:30]  # Limiteer lengte
                        except:
                            seen_ips[ip] = "unknown"
                
                # Update UI
                GLib.idle_add(self.ip_store.clear)
                
                # Sorteer op aantal verbindingen (meeste eerst)
                sorted_ips = sorted(current_ips.items(), key=lambda x: x[1]['count'], reverse=True)
                
                for ip, data in sorted_ips[:30]:  # Top 30
                    proto = data['proto']
                    count = data['count']
                    ports = ', '.join(sorted(data['ports'])[:3])  # Max 3 poorten
                    if len(data['ports']) > 3:
                        ports += "..."
                    hostname = seen_ips.get(ip, "?")
                    
                    # Bepaal kleur gebaseerd op aantal verbindingen
                    if count > 10:
                        color = "#FF0000"  # Veel verbindingen = rood (verdacht?)
                    elif count > 5:
                        color = "#FFA500"  # Gemiddeld = oranje
                    else:
                        color = "#00FF00"  # Weinig = groen (normaal)
                    
                    # Format display
                    display = f"{ip:15} {data['direction']} :{ports:10} ({count}x) {hostname}"
                    
                    GLib.idle_add(self.ip_store.append, [display, data['direction'], color])
                
                # Als geen verbindingen
                if not current_ips:
                    GLib.idle_add(self.ip_store.append, ["⚪ Geen externe verbindingen", "", "#808080"])
                        
            except Exception as e:
                print(f"IP monitor error: {e}")
            
            time.sleep(INTERVAL)  # Update elke 3 seconden

    def show_notification(self, msg, color):
        """Toon notificatie"""
        GLib.idle_add(self.activity_store.prepend, [f"📢 {msg}", color])

if __name__ == "__main__":
    win = FirewallSidebar()
    win.show_all()
    Gtk.main()
