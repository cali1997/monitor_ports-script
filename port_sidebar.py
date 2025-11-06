#!/usr/bin/env python3
# Port Sidebar Monitor - Uitgebreide versie met kill functie en verkeer monitoring
# Start automatisch bij login (zie uitleg onderaan)

import gi, subprocess, time, threading, re, signal, os
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

INTERVAL = 2.0   # seconden tussen checks
HIGHLIGHT_MS = 1500  # hoe lang highlight blijft

def read_listeners(show_localhost=False):
    """Lees alle luisterende poorten"""
    out = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
    lines = out.stdout.strip().splitlines()[1:]
    items = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        
        # Filter localhost indien nodig
        if not show_localhost and ("127.0.0.1" in local or "::1" in local):
            continue
        
        # Probeer PID te vinden
        pid = ""
        process_name = ""
        if len(parts) >= 7:
            match = re.search(r'pid=(\d+)', parts[6])
            if match:
                pid = match.group(1)
                # Krijg process naam
                try:
                    pname = subprocess.run(["ps", "-p", pid, "-o", "comm="], 
                                         capture_output=True, text=True).stdout.strip()
                    process_name = pname if pname else "?"
                except:
                    process_name = "?"
        
        items.append({
            'proto': proto,
            'local': local,
            'pid': pid,
            'process': process_name,
            'key': f"{proto} {local}"
        })
    return items

def read_connections():
    """Lees actieve verbindingen (inkomend/uitgaand)"""
    out = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
    lines = out.stdout.strip().splitlines()[1:]
    connections = []
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0]
        state = parts[1] if len(parts) > 1 else ""
        local = parts[4] if len(parts) > 4 else ""
        remote = parts[5] if len(parts) > 5 else ""
        
        direction = "↓ IN" if state in ["ESTAB", "ESTABLISHED"] else "↑ OUT"
        
        connections.append({
            'proto': proto,
            'direction': direction,
            'local': local,
            'remote': remote,
            'state': state,
            'key': f"{proto} {local} ↔ {remote}"
        })
    return connections

class PortSidebar(Gtk.Window):
    def __init__(self):
        super().__init__(title="Port Monitor Pro")

        # 🖤 Zwarte achtergrond met betere kleuren
        css = Gtk.CssProvider()
        css.load_from_data(b"""
        window {
            background-color: #000000;
            color: #00FF00;
        }
        treeview {
            background-color: #000000;
            color: #00FF00;
        }
        button {
            background-color: #1a1a1a;
            color: #00FF00;
            border: 1px solid #00FF00;
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

        # Positie rechts op scherm (nieuwe GTK3 methode)
        display = Gdk.Display.get_default()
        monitor = display.get_primary_monitor()
        if monitor:
            geom = monitor.get_geometry()
            self.move(geom.x + geom.width - 550, geom.y + 30)
        else:
            self.move(1370, 30)  # Fallback positie

        self.connect("delete-event", Gtk.main_quit)

        # State
        self.show_localhost = False
        self.show_connections = False
        self.prev_listeners = {}
        self.lock = threading.Lock()

        # Main container
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        # Header met drag functie - EventBox voor mouse events
        self.header_box = Gtk.EventBox()
        header = Gtk.Label()
        header.set_markup("<span foreground='#00FF00' size='large'><b>🧠 Port Monitor </b></span>")
        header.set_xalign(0)
        header.set_margin_start(6)
        header.set_margin_end(6)
        header.set_margin_top(6)
        header.set_margin_bottom(6)
        self.header_box.add(header)
        
        # Voeg mouse events toe aan header_box
        self.header_box.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK |
            Gdk.EventMask.BUTTON_RELEASE_MASK |
            Gdk.EventMask.POINTER_MOTION_MASK |
            Gdk.EventMask.ENTER_NOTIFY_MASK |
            Gdk.EventMask.LEAVE_NOTIFY_MASK
        )
        
        self.header_box.connect("button-press-event", self.on_header_click)
        self.header_box.connect("enter-notify-event", self.on_header_enter)
        self.header_box.connect("leave-notify-event", self.on_header_leave)
        
        vbox.pack_start(self.header_box, False, False, 0)

        # Control buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        vbox.pack_start(btn_box, False, False, 3)

        # Toggle localhost button
        self.btn_localhost = Gtk.Button(label="🏠 Toon Localhost")
        self.btn_localhost.connect("clicked", self.on_toggle_localhost)
        btn_box.pack_start(self.btn_localhost, True, True, 0)

        # Toggle connections button
        self.btn_connections = Gtk.Button(label="📡 Toon Verkeer")
        self.btn_connections.connect("clicked", self.on_toggle_connections)
        btn_box.pack_start(self.btn_connections, True, True, 0)

        # Sort/organize button
        btn_organize = Gtk.Button(label="📋 Sorteer")
        btn_organize.connect("clicked", self.on_organize)
        btn_box.pack_start(btn_organize, True, True, 0)

        # Clear button
        btn_clear = Gtk.Button(label="🗑️ Clear")
        btn_clear.connect("clicked", self.on_clear)
        btn_box.pack_start(btn_clear, True, True, 0)

        # Manual kill section
        kill_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        vbox.pack_start(kill_box, False, False, 3)

        lbl_kill = Gtk.Label()
        lbl_kill.set_markup("<span foreground='#FF6B6B'><b>🔪 Kill poort:</b></span>")
        kill_box.pack_start(lbl_kill, False, False, 5)

        self.entry_port = Gtk.Entry()
        self.entry_port.set_placeholder_text("Poort nummer (bijv. 8080)")
        self.entry_port.set_max_length(5)
        kill_box.pack_start(self.entry_port, True, True, 0)

        btn_kill_port = Gtk.Button(label="💀 Kill")
        btn_kill_port.connect("clicked", self.on_manual_kill)
        kill_box.pack_start(btn_kill_port, False, False, 0)

        btn_kill_all_port = Gtk.Button(label="⚡ Kill All")
        btn_kill_all_port.connect("clicked", self.on_kill_all_on_port)
        kill_box.pack_start(btn_kill_all_port, False, False, 0)

        # Scrolled window for listeners
        self.lbl_listeners = Gtk.Label()
        self.lbl_listeners.set_markup("<span foreground='#FFD700'><b>📍 Luisterende Poorten:</b></span>")
        self.lbl_listeners.set_xalign(0)
        vbox.pack_start(self.lbl_listeners, False, False, 3)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_size_request(-1, 250)
        vbox.pack_start(scrolled, True, True, 0)

        # Store: [display_text, timestamp, color, pid, full_info]
        self.store = Gtk.ListStore(str, float, str, str, str)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(True)
        self.tree.connect("button-press-event", self.on_tree_button_press)

        renderer = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn("Info", renderer, text=0, foreground=2)
        col.set_expand(True)
        self.tree.append_column(col)
        scrolled.add(self.tree)

        # Scrolled window for connections
        self.lbl_connections = Gtk.Label()
        self.lbl_connections.set_markup("<span foreground='#00BFFF'><b>🌐 Actieve Verbindingen:</b></span>")
        self.lbl_connections.set_xalign(0)
        vbox.pack_start(self.lbl_connections, False, False, 3)

        scrolled2 = Gtk.ScrolledWindow()
        scrolled2.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scrolled2.set_size_request(-1, 200)
        vbox.pack_start(scrolled2, True, True, 0)

        self.conn_store = Gtk.ListStore(str, str)  # [display_text, color]
        self.conn_tree = Gtk.TreeView(model=self.conn_store)
        self.conn_tree.set_headers_visible(False)

        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn("Verbinding", renderer2, text=0, foreground=1)
        col2.set_expand(True)
        self.conn_tree.append_column(col2)
        scrolled2.add(self.conn_tree)

        # Keyboard controls info
        info_label = Gtk.Label()
        info_label.set_markup("<span size='small' foreground='#808080'>⌨️ Pijltjestoetsen: Beweeg window | Ctrl+Pijltjes: Sneller</span>")
        info_label.set_margin_top(6)
        info_label.set_margin_bottom(4)
        vbox.pack_start(info_label, False, False, 0)

        # Connect keyboard events
        self.connect("key-press-event", self.on_key_press)

        # Start threads
        threading.Thread(target=self._poll_loop, daemon=True).start()
        GLib.timeout_add(300, self._refresh_highlights)

    def on_header_click(self, widget, event):
        """Start window drag met GTK's ingebouwde functie"""
        if event.button == 1:  # Linkermuisknop
            self.begin_move_drag(
                event.button,
                int(event.x_root),
                int(event.y_root),
                event.time
            )
        return True

    def on_header_enter(self, widget, event):
        """Verander cursor naar handje"""
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

    def on_drag_start(self, widget, event):
        """Start het slepen van het venster"""
        if event.button == 1:  # Linkermuisknop
            self.is_dragging = True
            self.drag_start_x = event.x_root - self.get_position()[0]
            self.drag_start_y = event.y_root - self.get_position()[1]
            return True

    def on_drag_end(self, widget, event):
        """Stop het slepen"""
        if event.button == 1:
            self.is_dragging = False
            return True

    def on_drag_motion(self, widget, event):
        """Verplaats het venster tijdens slepen"""
        if self.is_dragging:
            new_x = int(event.x_root - self.drag_start_x)
            new_y = int(event.y_root - self.drag_start_y)
            self.move(new_x, new_y)
            return True

    def on_key_press(self, widget, event):
        """Handle keyboard shortcuts voor window movement"""
        keyval = event.keyval
        state = event.state
        
        # Haal huidige positie op
        x, y = self.get_position()
        
        # Bepaal stap grootte (Ctrl = sneller)
        step = 50 if state & Gdk.ModifierType.CONTROL_MASK else 10
        
        # Pijltjestoetsen
        if keyval == Gdk.KEY_Left:
            self.move(x - step, y)
            return True
        elif keyval == Gdk.KEY_Right:
            self.move(x + step, y)
            return True
        elif keyval == Gdk.KEY_Up:
            self.move(x, y - step)
            return True
        elif keyval == Gdk.KEY_Down:
            self.move(x, y + step)
            return True
        
        return False

    def on_toggle_localhost(self, button):
        """Toggle localhost weergave"""
        self.show_localhost = not self.show_localhost
        if self.show_localhost:
            self.btn_localhost.set_label("🏠 Verberg Localhost")
        else:
            self.btn_localhost.set_label("🏠 Toon Localhost")

    def on_toggle_connections(self, button):
        """Toggle verbindingen weergave"""
        self.show_connections = not self.show_connections
        if self.show_connections:
            self.btn_connections.set_label("📡 Verberg Verkeer")
        else:
            self.btn_connections.set_label("📡 Toon Verkeer")

    def on_organize(self, button):
        """Sorteer items alfabetisch"""
        with self.lock:
            self.store.set_sort_column_id(0, Gtk.SortType.ASCENDING)

    def on_clear(self, button):
        """Clear alle items"""
        with self.lock:
            self.store.clear()
            self.conn_store.clear()

    def on_manual_kill(self, button):
        """Kill eerste proces op opgegeven poort"""
        port_text = self.entry_port.get_text().strip()
        if not port_text.isdigit():
            self.show_notification("⚠️ Voer een geldig poortnummer in", "#FFA500")
            return
        
        port = int(port_text)
        pids = self.find_pids_on_port(port)
        
        if not pids:
            self.show_notification(f"❌ Geen proces gevonden op poort {port}", "#FF0000")
            return
        
        # Kill eerste proces
        pid = pids[0]
        self.kill_process(pid, signal.SIGTERM)
        self.entry_port.set_text("")

    def on_kill_all_on_port(self, button):
        """Kill alle processen op opgegeven poort"""
        port_text = self.entry_port.get_text().strip()
        if not port_text.isdigit():
            self.show_notification("⚠️ Voer een geldig poortnummer in", "#FFA500")
            return
        
        port = int(port_text)
        pids = self.find_pids_on_port(port)
        
        if not pids:
            self.show_notification(f"❌ Geen proces gevonden op poort {port}", "#FF0000")
            return
        
        # Kill alle processen
        killed_count = 0
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGTERM)
                killed_count += 1
            except:
                pass
        
        self.show_notification(f"✅ {killed_count} proces(sen) gestopt op poort {port}", "#00FF00")
        self.entry_port.set_text("")

    def find_pids_on_port(self, port):
        """Vind alle PIDs die op een bepaalde poort luisteren"""
        pids = []
        try:
            # Probeer met ss
            out = subprocess.run(
                ["ss", "-tulnp", f"sport = :{port}"],
                capture_output=True, text=True
            )
            for line in out.stdout.splitlines()[1:]:
                match = re.search(r'pid=(\d+)', line)
                if match:
                    pids.append(match.group(1))
            
            # Als ss niks vindt, probeer lsof
            if not pids:
                out = subprocess.run(
                    ["lsof", "-ti", f":{port}"],
                    capture_output=True, text=True
                )
                pids = [p.strip() for p in out.stdout.strip().split('\n') if p.strip()]
        except Exception as e:
            print(f"Error finding PIDs: {e}")
        
        return pids

    def on_tree_button_press(self, treeview, event):
        """Rechtermuisklik menu voor kill functie"""
        if event.button == 3:  # Rechtermuisklik
            path = treeview.get_path_at_pos(int(event.x), int(event.y))
            if path:
                treeview.set_cursor(path[0])
                model, tree_iter = treeview.get_selection().get_selected()
                if tree_iter:
                    pid = model[tree_iter][3]  # PID kolom
                    if pid and pid.isdigit():
                        self.show_kill_menu(event, pid, model[tree_iter][0])
            return True

    def show_kill_menu(self, event, pid, info):
        """Toon context menu om proces te killen"""
        menu = Gtk.Menu()
        
        item_info = Gtk.MenuItem(label=f"PID: {pid}")
        item_info.set_sensitive(False)
        menu.append(item_info)
        
        menu.append(Gtk.SeparatorMenuItem())
        
        item_kill = Gtk.MenuItem(label=f"🔪 Kill proces (SIGTERM)")
        item_kill.connect("activate", lambda x: self.kill_process(pid, signal.SIGTERM))
        menu.append(item_kill)
        
        item_kill9 = Gtk.MenuItem(label=f"💀 Force kill (SIGKILL)")
        item_kill9.connect("activate", lambda x: self.kill_process(pid, signal.SIGKILL))
        menu.append(item_kill9)
        
        menu.show_all()
        menu.popup(None, None, None, None, event.button, event.time)

    def kill_process(self, pid, sig):
        """Kill een proces met opgegeven signal"""
        try:
            os.kill(int(pid), sig)
            GLib.idle_add(self.show_notification, f"✅ Proces {pid} gestopt", "#00FF00")
        except PermissionError:
            GLib.idle_add(self.show_notification, f"❌ Geen permissie voor PID {pid} (probeer sudo)", "#FF0000")
        except ProcessLookupError:
            GLib.idle_add(self.show_notification, f"⚠️ Proces {pid} bestaat niet meer", "#FFA500")
        except Exception as e:
            GLib.idle_add(self.show_notification, f"❌ Error: {e}", "#FF0000")

    def show_notification(self, msg, color):
        """Toon notificatie bovenaan"""
        with self.lock:
            self.store.prepend([msg, time.time(), color, "", msg])

    def _poll_loop(self):
        """Hoofd polling loop"""
        while True:
            try:
                # Update listeners
                listeners = read_listeners(self.show_localhost)
                current_keys = {item['key']: item for item in listeners}
                
                # Detecteer veranderingen
                added = set(current_keys.keys()) - set(self.prev_listeners.keys())
                removed = set(self.prev_listeners.keys()) - set(current_keys.keys())
                
                with self.lock:
                    now = time.time()
                    
                    # Nieuwe poorten
                    for key in sorted(added):
                        item = current_keys[key]
                        display = f"🆕 {item['proto']} {item['local']}"
                        if item['process']:
                            display += f" ({item['process']})"
                        self.store.prepend([display, now, "#00FF00", item['pid'], key])
                    
                    # Gesloten poorten
                    for key in sorted(removed):
                        item = self.prev_listeners[key]
                        display = f"❌ CLOSED: {item['proto']} {item['local']}"
                        if item['process']:
                            display += f" ({item['process']})"
                        self.store.prepend([display, now, "#FF0000", "", key])
                
                self.prev_listeners = current_keys
                
                # Update connections indien ingeschakeld
                if self.show_connections:
                    connections = read_connections()
                    GLib.idle_add(self.update_connections, connections)
                else:
                    GLib.idle_add(self.conn_store.clear)
                    
            except Exception as e:
                print(f"Error in poll loop: {e}")
            
            time.sleep(INTERVAL)

    def update_connections(self, connections):
        """Update de connecties lijst"""
        self.conn_store.clear()
        for conn in connections[:50]:  # Limiteer tot 50 voor performance
            direction_color = "#00BFFF" if "IN" in conn['direction'] else "#FFA500"
            display = f"{conn['direction']} {conn['proto']} {conn['local']} ↔ {conn['remote']}"
            self.conn_store.append([display, direction_color])

    def _refresh_highlights(self):
        """Refresh highlights (fade uit na tijd)"""
        now = time.time()
        with self.lock:
            for row in self.store:
                ts = row[1]
                if (now - ts) * 1000.0 > HIGHLIGHT_MS and "CLOSED:" not in row[0] and "🆕" not in row[0]:
                    row[2] = "#00FF00"
                # Verwijder oude 🆕 emoji's
                if "🆕" in row[0] and (now - ts) > 5:
                    row[0] = row[0].replace("🆕 ", "")
        return True

if __name__ == "__main__":
    win = PortSidebar()
    win.show_all()
    Gtk.main()
