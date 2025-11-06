#!/usr/bin/env python3
# Port Sidebar Monitor - aangepaste versie met zwart thema en kleurige tekst
# Start automatisch bij login (zie uitleg onderaan)

import gi, subprocess, time, threading
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

INTERVAL = 2.0   # seconden tussen checks
HIGHLIGHT_MS = 1500  # hoe lang highlight blijft

def read_listeners():
    out = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
    lines = out.stdout.strip().splitlines()[1:]
    items = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        # Alleen externe poorten tonen (geen localhost)
        if "127.0.0.1" in local or "::1" in local:
            continue
        items.add(f"{proto} {local}")
    return items

class PortSidebar(Gtk.Window):
    def __init__(self):
        super().__init__(title="Port Monitor")

        # 🖤 Zwarte achtergrond
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
        """)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        self.set_decorated(False)
        self.set_keep_above(True)
        self.set_resizable(True)
        self.set_default_size(400, 600)

        screen = Gdk.Screen.get_default()
        monitor = screen.get_primary_monitor()
        geom = screen.get_monitor_geometry(monitor)
        self.move(geom.x + geom.width - 400, geom.y + 30)

        self.connect("delete-event", Gtk.main_quit)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        header = Gtk.Label()
        header.set_markup("<span foreground='#00FF00' size='large'><b>🧠 Open poorten (live)</b></span>")
        header.set_xalign(0)
        vbox.pack_start(header, False, False, 6)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        vbox.pack_start(scrolled, True, True, 6)

        self.store = Gtk.ListStore(str, float, str)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(False)

        renderer = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn("Listener", renderer, text=0, foreground=2)
        self.tree.append_column(col)
        scrolled.add(self.tree)

        self.prev = set()
        self.lock = threading.Lock()

        threading.Thread(target=self._poll_loop, daemon=True).start()
        GLib.timeout_add(300, self._refresh_highlights)

    def _poll_loop(self):
        while True:
            try:
                cur = read_listeners()
            except Exception:
                cur = set()

            added = cur - self.prev
            removed = self.prev - cur
            with self.lock:
                now = time.time()
                for a in sorted(added):
                    self.store.prepend([a, now, "#00FF00"])  # groen
                for r in sorted(removed):
                    self.store.prepend([f"CLOSED: {r}", now, "#FF0000"])  # rood
            self.prev = cur
            time.sleep(INTERVAL)

    def _refresh_highlights(self):
        now = time.time()
        with self.lock:
            # na verloop tijd terug naar groen
            for row in self.store:
                ts = row[1]
                if (now - ts) * 1000.0 > HIGHLIGHT_MS and "CLOSED:" not in row[0]:
                    row[2] = "#00FF00"
        return True

if __name__ == "__main__":
    win = PortSidebar()
    win.show_all()
    Gtk.main()
