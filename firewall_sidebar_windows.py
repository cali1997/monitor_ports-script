#!/usr/bin/env python3
# Windows Firewall & Security Sidebar - Versie voor Windows 11
# Gebruikt Windows Firewall en netsh commando's

import subprocess, time, threading, re, os, sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

if sys.platform == "win32":
    import psutil

INTERVAL = 3.0  # seconden tussen checks

def run_powershell(command):
    """Voer PowerShell commando uit"""
    try:
        result = subprocess.run(["powershell", "-Command", command], 
                              capture_output=True, text=True, shell=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def block_ip_windows(ip_address):
    """Blokkeer IP adres via Windows Firewall"""
    rule_name = f"BlockIP_{ip_address}_{int(time.time())}"
    
    # PowerShell commando om IP te blokkeren
    ps_command = f"""
    New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -RemoteAddress {ip_address} -Action Block
    New-NetFirewallRule -DisplayName '{rule_name}_Out' -Direction Outbound -RemoteAddress {ip_address} -Action Block
    """
    
    success, stdout, stderr = run_powershell(ps_command)
    return success, rule_name if success else stderr

def unblock_ip_windows(ip_address):
    """Deblokkeer IP adres via Windows Firewall"""
    # Zoek alle regels die dit IP blokkeren
    ps_command = f"Get-NetFirewallRule | Where-Object {{$_.DisplayName -like '*BlockIP_{ip_address}*'}} | Remove-NetFirewallRule"
    
    success, stdout, stderr = run_powershell(ps_command)
    return success, "IP gedeblokkeerd" if success else stderr

def get_firewall_rules():
    """Krijg Windows Firewall regels"""
    ps_command = "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Action -eq 'Block'} | Select-Object DisplayName, Direction | ConvertTo-Json"
    
    success, stdout, stderr = run_powershell(ps_command)
    if success and stdout.strip():
        try:
            import json
            rules = json.loads(stdout)
            if isinstance(rules, dict):
                rules = [rules]
            return rules
        except:
            return []
    return []

def get_network_connections():
    """Krijg actieve netwerk verbindingen met IP info"""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    # Krijg proces info
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except:
                            pass
                    
                    connections.append({
                        'local_ip': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else '',
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'pid': conn.pid or '',
                        'process': process_name
                    })
                except:
                    continue
        return connections
    except Exception as e:
        print(f"Error getting connections: {e}")
        return []

def get_system_info():
    """Krijg systeem informatie"""
    try:
        # CPU en Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Disk
        disk = psutil.disk_usage('C:')
        
        # Network stats
        net_io = psutil.net_io_counters()
        
        return {
            'cpu': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': memory.used // (1024**3),  # GB
            'memory_total': memory.total // (1024**3),  # GB
            'disk_percent': (disk.used / disk.total) * 100,
            'disk_used': disk.used // (1024**3),  # GB
            'disk_total': disk.total // (1024**3),  # GB
            'net_sent': net_io.bytes_sent // (1024**2),  # MB
            'net_recv': net_io.bytes_recv // (1024**2)  # MB
        }
    except Exception as e:
        print(f"Error getting system info: {e}")
        return {}

class WindowsFirewallSidebar:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ Windows Firewall & Security")
        self.root.geometry("600x900")
        
        # Zet venster links op scherm
        self.root.geometry("+50+50")
        
        # Altijd bovenop
        self.root.attributes('-topmost', True)
        
        # Dark theme
        self.root.configure(bg='#0a0a0a')
        
        self.setup_ui()
        self.setup_variables()
        self.start_monitoring()
        
    def setup_variables(self):
        self.monitoring = True
        self.blocked_ips = set()
        
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#0a0a0a')
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = tk.Label(header_frame, text="🛡️ WINDOWS FIREWALL & SECURITY", 
                             bg='#0a0a0a', fg='#FF6B35', font=('Consolas', 12, 'bold'))
        title_label.pack()
        
        # IP Blocking section
        self.setup_ip_blocking()
        
        # System info
        self.setup_system_info()
        
        # Firewall rules
        self.setup_firewall_rules()
        
        # Network connections
        self.setup_network_connections()
        
        # Log
        self.setup_log()
        
    def setup_ip_blocking(self):
        block_frame = tk.LabelFrame(self.root, text="🚫 IP Blocking", 
                                   bg='#0a0a0a', fg='#FF6B35')
        block_frame.pack(fill=tk.X, padx=10, pady=5)
        
        input_frame = tk.Frame(block_frame, bg='#0a0a0a')
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(input_frame, text="IP Address:", bg='#0a0a0a', fg='#FF6B35').pack(side=tk.LEFT)
        
        self.ip_entry = tk.Entry(input_frame, bg='#1a1a1a', fg='#FF6B35', insertbackground='#FF6B35')
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        tk.Button(input_frame, text="🚫 Block", command=self.block_ip,
                 bg='#cc2936', fg='white', relief=tk.FLAT).pack(side=tk.RIGHT, padx=2)
        
        tk.Button(input_frame, text="✅ Unblock", command=self.unblock_ip,
                 bg='#2d5016', fg='white', relief=tk.FLAT).pack(side=tk.RIGHT, padx=2)
        
    def setup_system_info(self):
        sys_frame = tk.LabelFrame(self.root, text="📊 System Monitor", 
                                 bg='#0a0a0a', fg='#FF6B35')
        sys_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.sys_text = tk.Text(sys_frame, height=4, bg='#1a1a1a', fg='#FF6B35',
                               font=('Consolas', 9))
        self.sys_text.pack(fill=tk.X, padx=5, pady=5)
        
    def setup_firewall_rules(self):
        rules_frame = tk.LabelFrame(self.root, text="🔥 Firewall Rules (Blocked)", 
                                   bg='#0a0a0a', fg='#FF6B35')
        rules_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Rule Name", "Direction")
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show='headings', height=6)
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=200)
        
        rules_scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_network_connections(self):
        conn_frame = tk.LabelFrame(self.root, text="🌐 Active Connections", 
                                  bg='#0a0a0a', fg='#FF6B35')
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Remote IP", "Port", "Process", "PID")
        self.conn_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=6)
        
        for col in columns:
            self.conn_tree.heading(col, text=col)
            self.conn_tree.column(col, width=100)
        
        conn_scrollbar = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right-click menu voor blokkeren
        self.conn_menu = tk.Menu(self.root, tearoff=0, bg='#1a1a1a', fg='#FF6B35')
        self.conn_menu.add_command(label="🚫 Block this IP", command=self.block_selected_ip)
        self.conn_tree.bind("<Button-3>", self.show_conn_menu)
        
    def setup_log(self):
        log_frame = tk.LabelFrame(self.root, text="📋 Security Log", 
                                 bg='#0a0a0a', fg='#FF6B35')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, bg='#1a1a1a', 
                                                 fg='#FF6B35', font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def show_conn_menu(self, event):
        item = self.conn_tree.identify_row(event.y)
        if item:
            self.conn_tree.selection_set(item)
            self.conn_menu.post(event.x_root, event.y_root)
            
    def block_selected_ip(self):
        selection = self.conn_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.conn_tree.item(item, 'values')
        ip = values[0] if len(values) > 0 else ""
        
        if ip and ip not in ['127.0.0.1', '::1']:
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip)
            self.block_ip()
        
    def block_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            return
            
        # Valideer IP (basic)
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            messagebox.showerror("Error", "Ongeldig IP adres format")
            return
            
        success, result = block_ip_windows(ip)
        if success:
            self.blocked_ips.add(ip)
            self.log(f"✅ IP {ip} geblokkeerd via Windows Firewall")
            self.ip_entry.delete(0, tk.END)
        else:
            self.log(f"❌ Fout bij blokkeren {ip}: {result}")
            
    def unblock_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            return
            
        success, result = unblock_ip_windows(ip)
        if success:
            self.blocked_ips.discard(ip)
            self.log(f"🔓 IP {ip} gedeblokkeerd")
            self.ip_entry.delete(0, tk.END)
        else:
            self.log(f"❌ Fout bij deblokkeren {ip}: {result}")
            
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
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
        # Update system info
        sys_info = get_system_info()
        if sys_info:
            self.sys_text.delete(1.0, tk.END)
            info_text = f"""CPU: {sys_info.get('cpu', 0):.1f}%
Memory: {sys_info.get('memory_percent', 0):.1f}% ({sys_info.get('memory_used', 0)}/{sys_info.get('memory_total', 0)} GB)
Disk C: {sys_info.get('disk_percent', 0):.1f}% ({sys_info.get('disk_used', 0)}/{sys_info.get('disk_total', 0)} GB)
Network: ↑{sys_info.get('net_sent', 0)} MB ↓{sys_info.get('net_recv', 0)} MB"""
            self.sys_text.insert(1.0, info_text)
        
        # Update firewall rules
        rules = get_firewall_rules()
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        for rule in rules:
            self.rules_tree.insert('', 'end', values=(
                rule.get('DisplayName', ''), rule.get('Direction', '')
            ))
        
        # Update network connections
        connections = get_network_connections()
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
            
        for conn in connections:
            self.conn_tree.insert('', 'end', values=(
                conn['remote_ip'], conn['remote_port'], 
                conn['process'], conn['pid']
            ))
        
    def run(self):
        try:
            self.log("🛡️ Windows Firewall & Security gestart")
            self.log("💡 Rechtermuisklik op verbindingen om IPs te blokkeren")
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.monitoring = False

if __name__ == "__main__":
    if sys.platform != "win32":
        print("⚠️  Deze versie is specifiek voor Windows!")
        print("Gebruik firewall_sidebar.py voor Linux systemen.")
        sys.exit(1)
        
    # Check of we admin rechten hebben (nodig voor firewall)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  Waarschuwing: Administrator rechten aanbevolen voor firewall functies")
            print("   Start als administrator voor volledige functionaliteit")
    except:
        pass
        
    try:
        import psutil
    except ImportError:
        print("❌ psutil niet gevonden. Installeer met: pip install psutil")
        sys.exit(1)
        
    print("🛡️ Starting Windows Firewall & Security...")
    firewall = WindowsFirewallSidebar()
    firewall.run()