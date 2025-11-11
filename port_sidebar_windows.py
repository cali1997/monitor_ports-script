#!/usr/bin/env python3
# Windows Port Sidebar Monitor - Versie voor Windows 11
# Gebruikt netstat en taskkill in plaats van ss en kill

import subprocess, time, threading, re, signal, os, sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# Windows specifieke imports
if sys.platform == "win32":
    import psutil

INTERVAL = 2.0   # seconden tussen checks
HIGHLIGHT_MS = 1500  # hoe lang highlight blijft

def read_listeners_windows(show_localhost=False):
    """Lees alle luisterende poorten op Windows met netstat"""
    try:
        # Gebruik netstat met -ano voor PID informatie
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, shell=True)
        lines = result.stdout.strip().splitlines()
        
        items = []
        for line in lines:
            # Parse netstat output: Proto Local-Address Foreign-Address State PID
            if "LISTENING" in line or ("UDP" in line and "*:*" in line):
                parts = line.split()
                if len(parts) >= 4:
                    proto = parts[0]
                    local = parts[1]
                    pid = parts[-1] if parts[-1].isdigit() else ""
                    
                    # Filter localhost indien nodig
                    if not show_localhost and ("127.0.0.1" in local or "[::1]" in local):
                        continue
                    
                    # Krijg process naam via PID
                    process_name = ""
                    if pid and pid.isdigit():
                        try:
                            process = psutil.Process(int(pid))
                            process_name = process.name()
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
    except Exception as e:
        print(f"Error reading ports: {e}")
        return []

def get_connections_windows():
    """Krijg actieve verbindingen op Windows"""
    try:
        result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, shell=True)
        lines = result.stdout.strip().splitlines()
        
        connections = []
        for line in lines:
            if "ESTABLISHED" in line or "TIME_WAIT" in line:
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        'proto': parts[0],
                        'local': parts[1],
                        'foreign': parts[2],
                        'state': parts[3]
                    })
        return connections
    except Exception as e:
        print(f"Error reading connections: {e}")
        return []

def kill_process_windows(pid):
    """Kill proces op Windows met taskkill"""
    if not pid or not pid.isdigit():
        return False, "Geen geldig PID"
    
    try:
        result = subprocess.run(["taskkill", "/F", "/PID", pid], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            return True, f"Proces {pid} gestopt"
        else:
            return False, f"Fout bij stoppen: {result.stderr}"
    except Exception as e:
        return False, f"Fout: {str(e)}"

class WindowsPortMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🖥️ Windows Port Monitor Pro")
        self.root.geometry("600x800")
        
        # Zet venster rechts op scherm
        self.root.geometry("+1300+50")
        
        # Altijd bovenop
        self.root.attributes('-topmost', True)
        
        # Dark theme
        self.root.configure(bg='#0a0a0a')
        
        self.setup_ui()
        self.setup_variables()
        self.start_monitoring()
        
    def setup_variables(self):
        self.show_localhost = tk.BooleanVar(value=False)
        self.last_ports = set()
        self.highlighted_items = {}
        self.monitoring = True
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#0a0a0a')
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = tk.Label(header_frame, text="🖥️ WINDOWS PORT MONITOR", 
                             bg='#0a0a0a', fg='#00ff41', font=('Consolas', 14, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        # Controls
        controls_frame = tk.Frame(self.root, bg='#0a0a0a')
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Checkbutton(controls_frame, text="Toon localhost", 
                      variable=self.show_localhost, bg='#0a0a0a', fg='#00ff41',
                      selectcolor='#1a1a1a').pack(side=tk.LEFT)
        
        tk.Button(controls_frame, text="🔄 Refresh", command=self.force_refresh,
                 bg='#1a1a1a', fg='#00ff41', relief=tk.FLAT).pack(side=tk.RIGHT)
        
        # Port lijst
        self.setup_port_tree()
        
        # Connection lijst
        self.setup_connection_tree()
        
        # Status
        self.status_var = tk.StringVar(value="Monitoring...")
        status_label = tk.Label(self.root, textvariable=self.status_var,
                               bg='#0a0a0a', fg='#00ff41', font=('Consolas', 10))
        status_label.pack(pady=5)
        
    def setup_port_tree(self):
        # Ports frame
        ports_frame = tk.LabelFrame(self.root, text="🔌 Listening Ports", 
                                   bg='#0a0a0a', fg='#00ff41')
        ports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview voor ports
        columns = ("Proto", "Address", "PID", "Process")
        self.port_tree = ttk.Treeview(ports_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=120)
        
        # Scrollbar
        port_scrollbar = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=port_scrollbar.set)
        
        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right-click menu
        self.port_menu = tk.Menu(self.root, tearoff=0, bg='#1a1a1a', fg='#00ff41')
        self.port_menu.add_command(label="🔪 Kill Process", command=self.kill_selected_process)
        self.port_tree.bind("<Button-3>", self.show_port_menu)
        
    def setup_connection_tree(self):
        # Connections frame  
        conn_frame = tk.LabelFrame(self.root, text="🌐 Active Connections", 
                                  bg='#0a0a0a', fg='#00ff41')
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Proto", "Local", "Foreign", "State")
        self.conn_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=120)
            
        conn_scrollbar = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def show_port_menu(self, event):
        item = self.port_tree.identify_row(event.y)
        if item:
            self.port_tree.selection_set(item)
            self.port_menu.post(event.x_root, event.y_root)
            
    def kill_selected_process(self):
        selection = self.port_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.port_tree.item(item, 'values')
        pid = values[2] if len(values) > 2 else ""
        process = values[3] if len(values) > 3 else ""
        
        if not pid:
            messagebox.showwarning("Geen PID", "Geen proces ID gevonden")
            return
            
        if messagebox.askyesno("Kill Process", 
                              f"Weet je zeker dat je proces {process} (PID {pid}) wilt stoppen?"):
            success, msg = kill_process_windows(pid)
            if success:
                messagebox.showinfo("Success", msg)
                self.force_refresh()
            else:
                messagebox.showerror("Error", msg)
    
    def force_refresh(self):
        self.update_displays()
        
    def start_monitoring(self):
        def monitor_loop():
            while self.monitoring:
                try:
                    self.root.after(0, self.update_displays)
                    time.sleep(INTERVAL)
                except:
                    break
                    
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def update_displays(self):
        # Update port lijst
        ports = read_listeners_windows(self.show_localhost.get())
        
        # Clear en populate ports
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
            
        current_ports = set()
        for port in ports:
            self.port_tree.insert('', 'end', values=(
                port['proto'], port['local'], port['pid'], port['process']
            ))
            current_ports.add(port['key'])
            
        # Check voor nieuwe ports
        new_ports = current_ports - self.last_ports
        if new_ports and self.last_ports:  # Niet bij eerste run
            self.root.bell()  # Windows beep
            
        self.last_ports = current_ports
        
        # Update connections
        connections = get_connections_windows()
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
            
        for conn in connections:
            self.conn_tree.insert('', 'end', values=(
                conn['proto'], conn['local'], conn['foreign'], conn['state']
            ))
            
        # Update status
        self.status_var.set(f"Monitoring - {len(ports)} ports, {len(connections)} connections - {datetime.now().strftime('%H:%M:%S')}")
        
    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.monitoring = False

if __name__ == "__main__":
    if sys.platform != "win32":
        print("⚠️  Deze versie is specifiek voor Windows!")
        print("Gebruik port_sidebar.py voor Linux systemen.")
        sys.exit(1)
        
    try:
        import psutil
    except ImportError:
        print("❌ psutil niet gevonden. Installeer met: pip install psutil")
        sys.exit(1)
        
    print("🖥️ Starting Windows Port Monitor...")
    monitor = WindowsPortMonitor()
    monitor.run()