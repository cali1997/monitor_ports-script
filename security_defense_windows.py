#!/usr/bin/env python3
"""
🚨 WINDOWS SECURITY DEFENSE SYSTEM 🚨
- Auto-detectie van aanvallen
- Automatische IP blokkering via Windows Firewall
- Rode alarm scherm
- Port scanning met uitleg (Windows specifiek)
"""

import subprocess, time, threading, re, collections, sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

if sys.platform == "win32":
    import psutil

# Bekende poorten en hun gebruik (Windows focus)
PORT_DATABASE = {
    20: "FTP Data - Bestandsoverdracht",
    21: "FTP Control - Bestandsoverdracht beheer",
    22: "SSH - Veilige remote toegang (rare op Windows)",
    23: "Telnet - Onveilige remote toegang (vermijd!)",
    25: "SMTP - Email versturen",
    53: "DNS - Domein naam resolutie",
    80: "HTTP - Normale websites/IIS",
    88: "Kerberos - Windows authenticatie",
    110: "POP3 - Email ophalen",
    135: "RPC Endpoint Mapper - Windows services",
    139: "NetBIOS Session - Windows netwerkdeling",
    143: "IMAP - Email synchronisatie",
    389: "LDAP - Active Directory",
    443: "HTTPS - Beveiligde websites",
    445: "SMB - Windows bestandsdeling (kritiek!)",
    636: "LDAPS - Beveiligde Active Directory",
    993: "IMAPS - Beveiligde email",
    995: "POP3S - Beveiligde email",
    1433: "SQL Server - Microsoft database",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP - Windows Remote Desktop (vaak aangevallen!)",
    5432: "PostgreSQL Database",
    5985: "WinRM HTTP - Windows Remote Management",
    5986: "WinRM HTTPS - Beveiligde Windows Remote Management",
    8080: "HTTP Alt - Alternatieve webserver",
    8443: "HTTPS Alt - Alternatieve beveiligde webserver"
}

# Windows specifieke verdachte activiteit
SUSPICIOUS_THRESHOLD = 15  # Verbindingen per seconde (lager voor Windows)
BLOCK_DURATION = 600  # 10 minuten
HIGH_RISK_PORTS = [3389, 445, 135, 139, 22, 23]  # Extra gevaarlijk op Windows

def run_powershell(command):
    """Voer PowerShell commando uit"""
    try:
        result = subprocess.run(["powershell", "-Command", command], 
                              capture_output=True, text=True, shell=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def scan_port_windows(target_ip, port, timeout=1):
    """Scan poort op Windows met PowerShell"""
    ps_command = f"""
    $timeout = {timeout * 1000}
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connect = $tcpClient.BeginConnect('{target_ip}', {port}, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne($timeout, $false)
    if ($wait) {{
        try {{
            $tcpClient.EndConnect($connect)
            Write-Output 'OPEN'
        }} catch {{
            Write-Output 'CLOSED'
        }}
    }} else {{
        Write-Output 'FILTERED'
    }}
    $tcpClient.Close()
    """
    
    success, stdout, stderr = run_powershell(ps_command)
    return stdout.strip() if success else "ERROR"

def block_ip_windows_defense(ip_address):
    """Blokkeer IP via Windows Firewall (defense versie)"""
    rule_name = f"SecurityDefense_Block_{ip_address}_{int(time.time())}"
    
    ps_command = f"""
    New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -RemoteAddress {ip_address} -Action Block -Enabled True
    New-NetFirewallRule -DisplayName '{rule_name}_Out' -Direction Outbound -RemoteAddress {ip_address} -Action Block -Enabled True
    """
    
    success, stdout, stderr = run_powershell(ps_command)
    return success, rule_name if success else stderr

def get_suspicious_connections():
    """Zoek verdachte verbindingen op Windows"""
    try:
        suspicious = []
        connections = psutil.net_connections(kind='inet')
        
        # Groepeer per remote IP
        ip_counts = collections.defaultdict(int)
        ip_connections = collections.defaultdict(list)
        
        for conn in connections:
            if conn.raddr and conn.status == 'ESTABLISHED':
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Skip lokale IPs
                if remote_ip.startswith(('127.', '192.168.', '10.', '172.')):
                    continue
                
                ip_counts[remote_ip] += 1
                ip_connections[remote_ip].append({
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_port': remote_port,
                    'pid': conn.pid
                })
        
        # Detecteer verdachte activiteit
        for ip, count in ip_counts.items():
            risk_level = "LOW"
            reasons = []
            
            if count >= SUSPICIOUS_THRESHOLD:
                risk_level = "HIGH"
                reasons.append(f"Te veel verbindingen ({count})")
            
            # Check hoge risico poorten
            for conn in ip_connections[ip]:
                if conn['local_port'] in HIGH_RISK_PORTS:
                    if risk_level == "LOW":
                        risk_level = "MEDIUM"
                    reasons.append(f"Hoog risico poort {conn['local_port']}")
            
            if count >= 5 or risk_level != "LOW":  # Toon alles wat interessant is
                suspicious.append({
                    'ip': ip,
                    'count': count,
                    'risk': risk_level,
                    'reasons': reasons,
                    'connections': ip_connections[ip]
                })
        
        return suspicious
    except Exception as e:
        print(f"Error detecting suspicious connections: {e}")
        return []

class WindowsSecurityDefense:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ WINDOWS SECURITY DEFENSE")
        self.root.geometry("900x700")
        self.root.configure(bg='#000000')
        
        # Center op scherm
        self.center_window()
        
        # Altijd bovenop
        self.root.attributes('-topmost', True)
        
        # Tracking
        self.blocked_ips = set()
        self.monitoring = True
        self.alarm_active = False
        self.connection_history = collections.defaultdict(list)
        
        self.setup_ui()
        self.start_monitoring()
        
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"+{x}+{y}")
        
    def setup_ui(self):
        # Header met alarm status
        self.header_frame = tk.Frame(self.root, bg='#000000')
        self.header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.title_label = tk.Label(self.header_frame, 
                                   text="🛡️ WINDOWS SECURITY DEFENSE SYSTEM", 
                                   bg='#000000', fg='#00ff00', 
                                   font=('Consolas', 14, 'bold'))
        self.title_label.pack()
        
        self.status_label = tk.Label(self.header_frame, 
                                    text="System Active - Monitoring...", 
                                    bg='#000000', fg='#00ff00',
                                    font=('Consolas', 10))
        self.status_label.pack()
        
        # Notebook voor tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Port Scanner
        self.setup_port_scanner_tab()
        
        # Tab 2: Threat Monitor
        self.setup_threat_monitor_tab()
        
        # Tab 3: Auto Defense
        self.setup_auto_defense_tab()
        
        # Tab 4: Security Log
        self.setup_security_log_tab()
        
    def setup_port_scanner_tab(self):
        scanner_frame = tk.Frame(self.notebook, bg='#000000')
        self.notebook.add(scanner_frame, text="🔍 Port Scanner")
        
        # Input
        input_frame = tk.Frame(scanner_frame, bg='#000000')
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(input_frame, text="Target IP:", bg='#000000', fg='#00ff00').pack(side=tk.LEFT)
        
        self.target_entry = tk.Entry(input_frame, bg='#1a1a1a', fg='#00ff00', insertbackground='#00ff00')
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.target_entry.insert(0, "127.0.0.1")
        
        tk.Button(input_frame, text="🔍 Scan Common Ports", command=self.scan_common_ports,
                 bg='#0066cc', fg='white', relief=tk.FLAT).pack(side=tk.RIGHT, padx=2)
        
        tk.Button(input_frame, text="🔍 Quick Scan", command=self.quick_scan,
                 bg='#009900', fg='white', relief=tk.FLAT).pack(side=tk.RIGHT, padx=2)
        
        # Results
        results_frame = tk.LabelFrame(scanner_frame, text="Scan Results", 
                                     bg='#000000', fg='#00ff00')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Port", "Status", "Service", "Risk", "Description")
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.scan_tree.column("Port", width=60)
        self.scan_tree.column("Status", width=80)
        self.scan_tree.column("Service", width=100)
        self.scan_tree.column("Risk", width=80)
        self.scan_tree.column("Description", width=300)
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
        
        scan_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scan_scrollbar.set)
        
        self.scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scan_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_threat_monitor_tab(self):
        threat_frame = tk.Frame(self.notebook, bg='#000000')
        self.notebook.add(threat_frame, text="🚨 Threat Monitor")
        
        # Controls
        controls_frame = tk.Frame(threat_frame, bg='#000000')
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(controls_frame, text="🔄 Refresh Threats", command=self.refresh_threats,
                 bg='#cc6600', fg='white', relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        tk.Button(controls_frame, text="🚨 Test Alarm", command=self.test_alarm,
                 bg='#cc0000', fg='white', relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        # Threat List
        threat_list_frame = tk.LabelFrame(threat_frame, text="Detected Threats", 
                                        bg='#000000', fg='#ff6b35')
        threat_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("IP Address", "Connections", "Risk Level", "Reasons", "Action")
        self.threat_tree = ttk.Treeview(threat_list_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=120)
        
        threat_scrollbar = ttk.Scrollbar(threat_list_frame, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=threat_scrollbar.set)
        
        self.threat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        threat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right-click menu
        self.threat_menu = tk.Menu(self.root, tearoff=0, bg='#1a1a1a', fg='#ff6b35')
        self.threat_menu.add_command(label="🚫 Block IP", command=self.block_selected_threat)
        self.threat_tree.bind("<Button-3>", self.show_threat_menu)
        
    def setup_auto_defense_tab(self):
        defense_frame = tk.Frame(self.notebook, bg='#000000')
        self.notebook.add(defense_frame, text="🤖 Auto Defense")
        
        # Settings
        settings_frame = tk.LabelFrame(defense_frame, text="Defense Settings", 
                                     bg='#000000', fg='#00ff00')
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.auto_block_var = tk.BooleanVar(value=True)
        tk.Checkbutton(settings_frame, text="Auto-block suspicious IPs", 
                      variable=self.auto_block_var, bg='#000000', fg='#00ff00',
                      selectcolor='#1a1a1a').pack(anchor=tk.W, padx=5, pady=2)
        
        self.alarm_var = tk.BooleanVar(value=True)
        tk.Checkbutton(settings_frame, text="Enable visual alarms", 
                      variable=self.alarm_var, bg='#000000', fg='#00ff00',
                      selectcolor='#1a1a1a').pack(anchor=tk.W, padx=5, pady=2)
        
        # Statistics
        stats_frame = tk.LabelFrame(defense_frame, text="Defense Statistics", 
                                   bg='#000000', fg='#00ff00')
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=15, bg='#1a1a1a', fg='#00ff00',
                                 font=('Consolas', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_security_log_tab(self):
        log_frame = tk.Frame(self.notebook, bg='#000000')
        self.notebook.add(log_frame, text="📋 Security Log")
        
        # Log controls
        log_controls = tk.Frame(log_frame, bg='#000000')
        log_controls.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(log_controls, text="🗑️ Clear Log", command=self.clear_log,
                 bg='#660000', fg='white', relief=tk.FLAT).pack(side=tk.LEFT)
        
        # Log text
        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#1a1a1a', fg='#00ff00',
                                                 font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def show_threat_menu(self, event):
        item = self.threat_tree.identify_row(event.y)
        if item:
            self.threat_tree.selection_set(item)
            self.threat_menu.post(event.x_root, event.y_root)
            
    def block_selected_threat(self):
        selection = self.threat_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        values = self.threat_tree.item(item, 'values')
        ip = values[0] if len(values) > 0 else ""
        
        if ip:
            self.block_ip_auto(ip, "Manual block from threat list")
    
    def quick_scan(self):
        """Snelle scan van meest voorkomende poorten"""
        common_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 5985]
        self.scan_ports(common_ports)
        
    def scan_common_ports(self):
        """Uitgebreide scan van bekende poorten"""
        ports_to_scan = list(PORT_DATABASE.keys())
        self.scan_ports(ports_to_scan)
        
    def scan_ports(self, ports):
        """Scan specifieke poorten"""
        target = self.target_entry.get().strip()
        if not target:
            return
            
        # Clear previous results
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
            
        self.log(f"🔍 Starting port scan on {target}")
        
        # Scan in thread om UI niet te blokkeren
        def scan_thread():
            for port in sorted(ports):
                if not self.monitoring:
                    break
                    
                status = scan_port_windows(target, port, timeout=2)
                
                if status == "OPEN":
                    service = PORT_DATABASE.get(port, "Unknown")
                    
                    # Bepaal risico niveau
                    if port in HIGH_RISK_PORTS:
                        risk = "HIGH"
                        risk_color = "#ff0000"
                    elif port in [80, 443, 53]:
                        risk = "LOW"
                        risk_color = "#00ff00"
                    else:
                        risk = "MEDIUM"
                        risk_color = "#ffaa00"
                    
                    # Update UI in main thread
                    self.root.after(0, lambda p=port, s=status, srv=service, r=risk: 
                                   self.add_scan_result(p, s, srv, r))
                
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def add_scan_result(self, port, status, service, risk):
        """Voeg scan resultaat toe aan tree"""
        description = PORT_DATABASE.get(port, "Unknown service")
        
        # Kleur op basis van risico
        if risk == "HIGH":
            tags = ("high_risk",)
        elif risk == "MEDIUM":
            tags = ("medium_risk",)
        else:
            tags = ("low_risk",)
            
        self.scan_tree.insert('', 'end', values=(port, status, service.split(' - ')[0], risk, description), tags=tags)
        
        # Configure tag colors
        self.scan_tree.tag_configure("high_risk", foreground="#ff0000")
        self.scan_tree.tag_configure("medium_risk", foreground="#ffaa00")
        self.scan_tree.tag_configure("low_risk", foreground="#00ff00")
        
    def refresh_threats(self):
        """Ververs threat detection"""
        threats = get_suspicious_connections()
        
        # Clear previous
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
            
        for threat in threats:
            reasons_text = ", ".join(threat['reasons'][:2])  # Eerste 2 redenen
            action = "BLOCKED" if threat['ip'] in self.blocked_ips else "MONITORING"
            
            self.threat_tree.insert('', 'end', values=(
                threat['ip'], threat['count'], threat['risk'], 
                reasons_text, action
            ))
            
            # Auto-block bij hoog risico
            if (threat['risk'] == "HIGH" and 
                self.auto_block_var.get() and 
                threat['ip'] not in self.blocked_ips):
                self.block_ip_auto(threat['ip'], f"Auto-block: {reasons_text}")
                
    def block_ip_auto(self, ip, reason):
        """Blokkeer IP automatisch"""
        if ip in ['127.0.0.1', '::1'] or ip.startswith(('192.168.', '10.')):
            self.log(f"⚠️  Skipping local IP {ip}")
            return
            
        success, result = block_ip_windows_defense(ip)
        if success:
            self.blocked_ips.add(ip)
            self.log(f"🚫 AUTO-BLOCKED {ip}: {reason}")
            
            if self.alarm_var.get():
                self.trigger_alarm(f"IP {ip} BLOCKED!")
        else:
            self.log(f"❌ Failed to block {ip}: {result}")
            
    def trigger_alarm(self, message):
        """Trigger visueel alarm"""
        if self.alarm_active:
            return
            
        self.alarm_active = True
        original_bg = self.root.cget('bg')
        
        def flash_alarm():
            for i in range(6):  # 3 seconden knipperen
                self.root.configure(bg='#ff0000' if i % 2 == 0 else '#000000')
                self.status_label.configure(text=f"🚨 ALARM: {message}")
                self.root.update()
                time.sleep(0.5)
                
            self.root.configure(bg=original_bg)
            self.status_label.configure(text="System Active - Monitoring...")
            self.alarm_active = False
            
        threading.Thread(target=flash_alarm, daemon=True).start()
        
    def test_alarm(self):
        """Test alarm functie"""
        self.trigger_alarm("TEST ALARM - System OK")
        
    def clear_log(self):
        """Wis security log"""
        self.log_text.delete(1.0, tk.END)
        
    def log(self, message):
        """Log bericht naar security log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
    def start_monitoring(self):
        """Start continuous monitoring"""
        def monitor_loop():
            while self.monitoring:
                try:
                    # Update threat detection elke 5 seconden
                    self.root.after(0, self.refresh_threats)
                    
                    # Update statistics
                    self.root.after(0, self.update_statistics)
                    
                    time.sleep(5)
                except:
                    break
                    
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def update_statistics(self):
        """Update defense statistics"""
        try:
            connections = psutil.net_connections(kind='inet')
            established = len([c for c in connections if c.status == 'ESTABLISHED'])
            listening = len([c for c in connections if c.status == 'LISTEN'])
            
            stats_text = f"""🛡️ WINDOWS SECURITY DEFENSE STATS

🔌 Network Status:
   • Established connections: {established}
   • Listening ports: {listening}
   • Blocked IPs: {len(self.blocked_ips)}

🚫 Blocked IPs:
"""
            for ip in sorted(self.blocked_ips):
                stats_text += f"   • {ip}\n"
                
            if not self.blocked_ips:
                stats_text += "   • None\n"
                
            stats_text += f"""
⚡ System Status:
   • Auto-blocking: {'ENABLED' if self.auto_block_var.get() else 'DISABLED'}
   • Visual alarms: {'ENABLED' if self.alarm_var.get() else 'DISABLED'}
   • Monitoring: ACTIVE
   • Last update: {datetime.now().strftime('%H:%M:%S')}
"""
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            
        except Exception as e:
            self.log(f"Error updating statistics: {e}")
    
    def run(self):
        try:
            self.log("🛡️ Windows Security Defense System gestart")
            self.log("💡 Gebruik de tabs om verschillende functies te bekijken")
            self.log("🚨 Auto-defense is actief voor hoog-risico verbindingen")
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.monitoring = False

if __name__ == "__main__":
    if sys.platform != "win32":
        print("⚠️  Deze versie is specifiek voor Windows!")
        print("Gebruik security_defense.py voor Linux systemen.")
        sys.exit(1)
        
    # Check dependencies
    try:
        import psutil
    except ImportError:
        print("❌ psutil niet gevonden. Installeer met: pip install psutil")
        sys.exit(1)
        
    # Check admin rights
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  Administrator rechten aanbevolen voor firewall functies")
            print("   Start als administrator voor automatische IP blokkering")
    except:
        pass
        
    print("🛡️ Starting Windows Security Defense System...")
    defense = WindowsSecurityDefense()
    defense.run()