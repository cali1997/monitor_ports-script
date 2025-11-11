# Windows Security Monitoring Suite 🛡️

**Complete beveiligings- en monitoring suite voor Windows 11** met automatische threat detection & response!

## 🚀 Windows Componenten

### 1. port_sidebar_windows.py (RECHTS)
**Windows Port Monitor Pro** - Real-time poort monitoring
- 🔍 Monitor open TCP/UDP poorten met `netstat`
- 🔪 Kill processen met `taskkill` (rechtermuisklik)
- 📡 Bekijk actieve verbindingen
- 🏠 Toggle localhost weergave
- 🖥️ Windows-native GUI met Tkinter

### 2. firewall_sidebar_windows.py (LINKS)
**Windows Firewall & Security Control** - Beveiligingsbeheer
- 🚫 Blokkeer/deblokkeer IP adressen via Windows Firewall
- 🛡️ `New-NetFirewallRule` PowerShell integration
- 📊 Live systeem monitoring met `psutil`
- 🌐 Live IP verbindingen tracker
- ⚡ Automatische PowerShell commando uitvoering

### 3. security_defense_windows.py (CENTER) ⭐ WINDOWS SPECIAL!
**Auto-Defense System** - Intelligente Windows beveiliging
- 🔍 **Port Scanner** met Windows socket testing
- 🚨 **Auto-detect aanvallen** (>15 conn/sec - Windows optimized)
- 🚫 **Auto-block via Windows Firewall**
- 🔴 **Fullscreen alarm** (knipperend rood)
- 📊 **Windows-specific threat detection**
- 🖥️ **Multi-tab interface** (Port Scanner, Threat Monitor, Auto Defense, Security Log)
- ⚡ **PowerShell integration** voor port scanning

### 4. monitor_ports_windows.ps1
**PowerShell Port Monitor** - Command-line monitoring
- 📊 Gebruikt `netstat` voor port detection
- 🔔 Audio alerts met `[Console]::Beep()`
- 📝 Optionele logging
- ⚙️ Configureerbare settings

### 5. launch_windows_suite.bat / .ps1
**Complete Suite Launcher** - Start alles tegelijk!
- 🔍 **Dependency checking** (Python, psutil, tkinter)
- 👑 **Administrator rechten detectie**
- 🚀 Start alle componenten automatisch
- 🎛️ **PowerShell versie** met geavanceerde opties
- 🛑 Netjes stoppen van alle processen

## 📦 Windows Installatie

### Vereisten
**Basis systeem:**
- Windows 10/11
- PowerShell 5.1+ (standaard op Windows 10/11)
- Administrator rechten (aanbevolen voor firewall functies)

**Python Setup:**
```cmd
# Download Python van https://python.org (3.7+ aanbevolen)
# Zorg dat "Add Python to PATH" aangevinkt is tijdens installatie

# Controleer installatie
python --version
pip --version
```

**Installeer Python dependencies:**
```cmd
pip install psutil
```

*Opmerking: `tkinter` is standaard meegeleverd met Python op Windows*

### 🚀 Snelle Start

**Optie 1: Batch Launcher (Simpel)**
```cmd
# Dubbelklik op launch_windows_suite.bat
# OF via command prompt:
cd path\to\monitor_ports-script
launch_windows_suite.bat
```

**Optie 2: PowerShell Launcher (Geavanceerd)**
```powershell
# Start PowerShell als Administrator voor beste ervaring
# Navigeer naar script directory
cd "C:\path\to\monitor_ports-script"

# Start complete suite
.\launch_windows_suite.ps1

# OF start individuele componenten
.\launch_windows_suite.ps1 -Component ports
.\launch_windows_suite.ps1 -Component firewall  
.\launch_windows_suite.ps1 -Component defense

# Skip dependency checks (sneller)
.\launch_windows_suite.ps1 -SkipDependencyCheck

# Start zonder wachten op gebruiker input
.\launch_windows_suite.ps1 -NoWait
```

**Optie 3: Individueel starten**
```cmd
# Port Monitor
python port_sidebar_windows.py

# Firewall Control  
python firewall_sidebar_windows.py

# Security Defense
python security_defense_windows.py

# PowerShell Port Monitor
powershell -ExecutionPolicy Bypass -File monitor_ports_windows.ps1
```

## 🛡️ Windows-Specifieke Features

### Windows Firewall Integration
```powershell
# Automatische firewall rules via PowerShell:
New-NetFirewallRule -DisplayName "BlockIP_1.2.3.4" -Direction Inbound -RemoteAddress "1.2.3.4" -Action Block
```

### Process Management
```cmd
# Process killing via taskkill:
taskkill /F /PID 1234
```

### Network Monitoring
```cmd
# Port scanning met netstat:
netstat -ano | findstr LISTENING
```

## ⚙️ Windows Configuratie

### PowerShell Execution Policy
Als je problemen hebt met .ps1 scripts:
```powershell
# Als Administrator:
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# OF tijdelijk:
powershell -ExecutionPolicy Bypass -File script.ps1
```

### Windows Firewall
Voor automatische IP blokkering:
```cmd
# Start Command Prompt of PowerShell als Administrator
# Anders kunnen firewall rules niet worden aangemaakt
```

### Windows Defender
Windows Defender kan Python scripts als verdacht markeren:
```
1. Ga naar Windows Security
2. Virus & threat protection
3. Manage settings onder Virus & threat protection settings
4. Add exclusion
5. Voeg je script directory toe
```

## 🎯 Windows-Optimized Security Features

### High-Risk Port Detection (Windows Focus)
- **RDP (3389)** - Vaak aangevallen op Windows
- **SMB (445)** - Kritiek voor Windows netwerken  
- **RPC (135)** - Windows service communication
- **NetBIOS (139)** - Legacy Windows networking
- **WinRM (5985/5986)** - Windows Remote Management

### Threat Detection Thresholds
- **Aangepast voor Windows**: 15 conn/sec (vs 20 op Linux)
- **Focus op Windows-attacks**: RDP brute force, SMB scanning
- **PowerShell-native blocking**: Direct Windows Firewall integration

## 🔧 Troubleshooting Windows

### Veel Voorkomende Problemen

**"Python niet gevonden"**
```cmd
# Voeg Python toe aan PATH:
# Zoek Python installatie (meestal C:\Python3X\ of C:\Users\%username%\AppData\Local\Programs\Python\)
# Voeg toe aan System PATH via System Properties
```

**"psutil import error"**
```cmd
pip install --upgrade psutil
# Of als dat niet werkt:
python -m pip install psutil
```

**"PowerShell execution policy error"**
```powershell
# Als Administrator:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Firewall rules niet werken"**
- Start als Administrator
- Check Windows Firewall service status
- Controleer Group Policy settings

**"GUI niet verschijnt"**
```cmd
# Check tkinter:
python -c "import tkinter; print('OK')"

# Als niet beschikbaar, herinstalleer Python met tkinter
```

### Performance Optimizations

**Voor betere performance op Windows:**
- Start als Administrator voor snellere netwerk toegang
- Disable Windows Defender real-time protection voor script directory (tijdelijk)
- Gebruik SSD voor log files indien veel logging
- Sluit andere resource-intensive programma's

## 📋 Windows Keyboard Shortcuts

**In alle GUI vensters:**
- `F5` - Refresh
- `Ctrl+C` - Copy selectie  
- `Right-click` - Context menu
- `Esc` - Cancel operatie

## 🔒 Windows Security Considerations

### Permissions
- **Administrator rechten** voor firewall modificaties
- **Standard user** kan port monitoring en threat detection
- **Network permissions** voor externe port scanning

### Windows Firewall
- Scripts maken automatisch firewall rules
- Rules zijn persistent (blijven na reboot)
- Handmatige cleanup mogelijk via Windows Firewall console

### Privacy
- Alle network monitoring blijft lokaal
- Geen data verzonden naar externe servers
- Logs blijven lokaal op systeem

## 📚 Windows Command Reference

### Nuttige Windows commando's voor network monitoring:

```cmd
# Port informatie
netstat -ano | findstr :80
netstat -an | findstr LISTENING

# Process informatie  
tasklist | findstr python.exe
wmic process where "name='python.exe'" get processid,commandline

# Firewall rules
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall delete rule name="BlockIP_1.2.3.4"

# Network connecties
netsh int ipv4 show tcpconnections
```

## 🎉 Windows Tips & Tricks

1. **Pin to Taskbar**: Pin launcher scripts voor snelle toegang
2. **Startup Integration**: Plaats in Windows Startup folder voor auto-start
3. **Multiple Monitors**: Vensters positioneren automatisch op multi-monitor setups
4. **Dark Mode**: GUI past zich aan aan Windows dark/light theme
5. **Notifications**: Gebruik Windows toast notifications voor alerts

---

**🏠 Originele Linux versie**: Gebruik `README.md` voor Linux installatie-instructies.

**⭐ Windows 11 optimized** - Gemaakt specifiek voor moderne Windows systemen!