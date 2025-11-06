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

        # Positie links op scherm
        screen = Gdk.Screen.get_default()
        monitor = screen.get_primary_monitor()
        geom = screen.get_monitor_geometry(monitor)
        self.move(geom.x + 30, geom.y + 30)

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

        # Systeem Activiteit
        lbl_activity = Gtk.Label()
        lbl_activity.set_markup("<span foreground='#FFD700'><b>📊 Systeem Activiteit:</b></span>")
        lbl_activity.set_xalign(0)
        lbl_activity.set_margin_start(6)
        vbox.pack_start(lbl_activity, False, False, 3)

        scrolled2 = Gtk.ScrolledWindow()
        scrolled2.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled2.set_size_request(-1, 200)
        vbox.pack_start(scrolled2, True, True, 0)

        self.activity_store = Gtk.ListStore(str, str)  # [activity, color]
        self.activity_tree = Gtk.TreeView(model=self.activity_store)
        self.activity_tree.set_headers_visible(False)

        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Activiteit", renderer2, text=0, foreground=1)
        col2.set_expand(True)
        self.activity_tree.append_column(col2)
        scrolled2.add(self.activity_tree)

        # Login pogingen
        lbl_logins = Gtk.Label()
        lbl_logins.set_markup("<span foreground='#FF6B35'><b>🔑 Recente Login Pogingen:</b></span>")
        lbl_logins.set_xalign(0)
        lbl_logins.set_margin_start(6)
        vbox.pack_start(lbl_logins, False, False, 3)

        scrolled3 = Gtk.ScrolledWindow()
        scrolled3.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled3.set_size_request(-1, 150)
        vbox.pack_start(scrolled3, True, True, 0)

        self.login_store = Gtk.ListStore(str, str)  # [login info, color]
        self.login_tree = Gtk.TreeView(model=self.login_store)
        self.login_tree.set_headers_visible(False)
        self.login_tree.connect("button-press-event", self.on_login_tree_click)

        renderer3 = Gtk.CellRendererText()
        col3 = Gtk.TreeViewColumn("Login", renderer3, text=0, foreground=1)
        col3.set_expand(True)
        self.login_tree.append_column(col3)
        scrolled3.add(self.login_tree)

        # Start monitoring threads
        threading.Thread(target=self._monitor_activity, daemon=True).start()
        threading.Thread(target=self._monitor_logins, daemon=True).start()
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
            # Probeer met iptables
            result = subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                timestamp = time.strftime("%H:%M:%S")
                GLib.idle_add(self.blocked_store.prepend, [f"{ip} (geblokkeerd om {timestamp})", "#FF0000"])
                self.show_notification(f"✅ IP {ip} geblokkeerd!", "#00FF00")
                self.entry_ip.set_text("")
            else:
                # Probeer met ufw
                result = subprocess.run(
                    ["sudo", "ufw", "deny", "from", ip],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.blocked_ips.add(ip)
                    timestamp = time.strftime("%H:%M:%S")
                    GLib.idle_add(self.blocked_store.prepend, [f"{ip} (UFW blocked {timestamp})", "#FF0000"])
                    self.show_notification(f"✅ IP {ip} geblokkeerd via UFW!", "#00FF00")
                    self.entry_ip.set_text("")
                else:
                    self.show_notification(f"❌ Firewall error (probeer sudo)", "#FF0000")
        except Exception as e:
            self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_unblock_ip(self, button):
        """Deblokkeer een IP adres"""
        ip = self.entry_ip.get_text().strip()
        if not self.validate_ip(ip):
            self.show_notification("⚠️ Ongeldig IP adres", "#FFA500")
            return

        try:
            # Probeer met iptables
            result = subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.show_notification(f"✅ IP {ip} gedeblokkeerd!", "#00FF00")
                self.entry_ip.set_text("")
                GLib.idle_add(self.refresh_blocked_list)
            else:
                # Probeer met ufw
                result = subprocess.run(
                    ["sudo", "ufw", "delete", "deny", "from", ip],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.blocked_ips.discard(ip)
                    self.show_notification(f"✅ IP {ip} gedeblokkeerd via UFW!", "#00FF00")
                    self.entry_ip.set_text("")
                    GLib.idle_add(self.refresh_blocked_list)
                else:
                    self.show_notification(f"⚠️ IP niet gevonden in firewall", "#FFA500")
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
            result = subprocess.run(["sudo", "iptables", "-L", "-n", "-v"], 
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
                subprocess.run(["sudo", "iptables", "-F"], check=True)
                self.blocked_ips.clear()
                GLib.idle_add(self.blocked_store.clear)
                self.show_notification("✅ Alle rules verwijderd!", "#00FF00")
            except Exception as e:
                self.show_notification(f"❌ Error: {e}", "#FF0000")

    def on_ufw_status(self, button):
        """Toon UFW status"""
        try:
            result = subprocess.run(["sudo", "ufw", "status", "verbose"], 
                                  capture_output=True, text=True)
            GLib.idle_add(self.activity_store.clear)
            for line in result.stdout.split('\n'):
                if line.strip():
                    GLib.idle_add(self.activity_store.append, [line, "#FFD700"])
        except Exception as e:
            self.show_notification(f"❌ UFW niet beschikbaar: {e}", "#FF0000")

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
        """Rechtermuisklik op login voor IP extractie"""
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

    def _monitor_logins(self):
        """Monitor login pogingen"""
        while True:
            try:
                # Laatste logins
                result = subprocess.run(["last", "-n", "10"], 
                                      capture_output=True, text=True)
                GLib.idle_add(self.login_store.clear)
                for line in result.stdout.split('\n')[:10]:
                    if line.strip() and 'reboot' not in line.lower():
                        color = "#00FF00" if "still logged in" in line else "#FFA500"
                        GLib.idle_add(self.login_store.append, [line.strip(), color])
                
                # Failed logins (indien beschikbaar)
                if os.path.exists("/var/log/auth.log"):
                    try:
                        result = subprocess.run(
                            ["sudo", "grep", "Failed password", "/var/log/auth.log"],
                            capture_output=True, text=True
                        )
                        failed = result.stdout.split('\n')[-5:]  # Laatste 5
                        for line in failed:
                            if line.strip():
                                GLib.idle_add(self.login_store.prepend, 
                                            [f"❌ {line.strip()}", "#FF0000"])
                    except:
                        pass
                        
            except Exception as e:
                print(f"Login monitor error: {e}")
            
            time.sleep(INTERVAL * 2)  # Minder frequent

    def show_notification(self, msg, color):
        """Toon notificatie"""
        GLib.idle_add(self.activity_store.prepend, [f"📢 {msg}", color])

if __name__ == "__main__":
    win = FirewallSidebar()
    win.show_all()
    Gtk.main()
