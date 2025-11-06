# monitor_ports-script

Complete security & monitoring suite voor Linux met dual-sidebar interface.

## 🚀 Scripts

### 1. port_sidebar.py (RECHTS)
**Port Monitor Pro** - Real-time poort monitoring
- 🔍 Monitor open TCP/UDP poorten
- 🔪 Kill processen (rechtermuisklik of handmatig)
- 📡 Bekijk actieve verbindingen (in/uitgaand)
- 🏠 Toggle localhost weergave
- 🖱️ Versleepbaar venster

### 2. firewall_sidebar.py (LINKS) ⭐ NIEUW!
**Firewall & Security Control** - Beveiligingsbeheer
- 🚫 Blokkeer/deblokkeer IP adressen
- 🛡️ iptables & UFW controle
- 📊 Systeem activiteit monitoring
- 🔑 Login pogingen tracker
- ⚡ Quick firewall actions

### 3. launch_both.sh ⭐ NIEUW!
**Dual Sidebar Launcher** - Start beide tegelijk
- Start port monitor (rechts)
- Start firewall control (links)
- Beide vensters tegelijk beheren

### 4. monitor_ports.sh
**Terminal Monitor** - Bash monitoring script
- Eenvoudige terminal interface
- Logging opties
- Configureerbare filters

## 📦 Installatie

### Vereisten
**Basis:**
- Python 3
- GTK 3
- PyGObject
- sudo rechten (voor firewall functies)

**Installeer dependencies:**
```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 iptables ufw
```

## 🎮 Gebruik

### Beide sidebars starten (AANBEVOLEN):
```bash
./launch_both.sh
```

### Of apart:

**Port Monitor:**
```bash
./port_sidebar.py
```

**Firewall Control:**
```bash
./firewall_sidebar.py
```

**Terminal Monitor:**
```bash
./monitor_ports.sh
```

## ✨ Features

### Port Monitor Pro (port_sidebar.py)
✅ Real-time poort detectie  
✅ Proces informatie (naam + PID)  
✅ Kill functie (rechtermuisklik)  
✅ Handmatige poort kill (type poortnummer)  
✅ Actieve verbindingen (↓IN / ↑OUT)  
✅ Localhost filter toggle  
✅ Sorteer & clear functies  
✅ Versleepbaar venster  
✅ Groen/rood kleurcodering  

### Firewall Control (firewall_sidebar.py)
✅ IP blokkeren/deblokkeren  
✅ iptables & UFW support  
✅ Firewall rules viewer  
✅ Flush all rules (met bevestiging)  
✅ Systeem activiteit (CPU, netwerk)  
✅ Login pogingen monitoring  
✅ Failed login detectie  
✅ Rechtermuisklik → auto-fill IP  
✅ Versleepbaar venster  
✅ Oranje/rood security thema  

## 🔥 Firewall Functies

### IP Blokkeren:
```
1. Type IP adres: 192.168.1.100
2. Klik "🚫 Block"
3. IP is direct geblokkeerd via iptables/UFW
```

### IP Deblokkeren:
```
1. Type IP adres of klik op geblokkeerd IP
2. Klik "✅ Unblock"
```

### Firewall Rules Bekijken:
```
Klik "📋 Toon Rules" → Zie alle iptables rules
Klik "⚡ UFW Status" → Zie UFW configuratie
```

### ⚠️ GEVAARLIJK:
```
"💧 Flush All" → Verwijdert ALLE firewall rules!
(Vraagt bevestiging)
```

## 🎯 Handige Tips

### Port Monitor:
- **Rechtermuisklik** op poort → Kill menu
- **Type poortnummer** → Kill handmatig
- **"Kill All"** → Stop alle processen op die poort
- **Drag header** → Verplaats venster

### Firewall Control:
- **Rechtermuisklik** op geblokkeerd IP → Auto-fill voor unblock
- **Rechtermuisklik** op login → Extract IP voor block
- **Monitor failed logins** → Block verdachte IPs
- **Drag header** → Verplaats venster

## 🚨 Security Waarschuwingen

1. **Firewall wijzigingen vereisen sudo** - Je krijgt mogelijk een wachtwoord prompt
2. **Test firewall rules zorgvuldig** - Blokkeer niet je eigen IP!
3. **Flush All is permanent** - Alleen gebruiken als je weet wat je doet
4. **SSH blokkeren** kan je buitensluiten op remote servers
5. **Backup firewall config** voordat je grote wijzigingen maakt

## 📋 Voorbeelden

### Scenario 1: Verdacht IP detecteren en blokkeren
```
1. Open beide sidebars: ./launch_both.sh
2. Zie verdachte connectie in Port Monitor
3. Kopieer IP adres
4. Ga naar Firewall Control
5. Plak IP en klik Block
```

### Scenario 2: Poort 8080 vrijmaken
```
1. Type "8080" in Port Monitor
2. Klik "Kill All"
3. Alle processen op poort 8080 gestopt
```

### Scenario 3: Failed logins blokkeren
```
1. Bekijk "Login Pogingen" in Firewall Control
2. Rechtermuisklik op failed login
3. IP wordt auto-gevuld
4. Klik Block
```

### Scenario 3: Failed logins blokkeren
```
1. Bekijk "Login Pogingen" in Firewall Control
2. Rechtermuisklik op failed login
3. IP wordt auto-gevuld
4. Klik Block
```

## 🖥️ Screenshots Layout

```
┌─────────────────────┐         ┌─────────────────────┐
│ 🔥 Firewall Control │         │ 🧠 Port Monitor Pro │
│ (LINKS)             │         │ (RECHTS)            │
├─────────────────────┤         ├─────────────────────┤
│ 🚫 Block IP         │         │ 🏠 Toggle Localhost │
│ 📋 Rules            │         │ 📡 Toggle Verkeer   │
│ 🔒 Blocked IPs      │         │ 🔪 Kill Poort       │
│ 📊 Activity         │         │ 📍 Luisterende      │
│ 🔑 Logins           │         │ 🌐 Verbindingen     │
└─────────────────────┘         └─────────────────────┘
```

## 🔧 Troubleshooting

**"Permission denied" bij firewall:**
```bash
# Run met sudo of voeg user toe aan sudoers
sudo usermod -aG sudo $USER
```

**"iptables command not found":**
```bash
sudo apt install iptables
```

**"UFW not available":**
```bash
sudo apt install ufw
sudo ufw enable
```

**Sidebar verdwijnt:**
- Klik op de header en sleep terug
- Of herstart met ./launch_both.sh

## 🎨 Kleurenschema

### Port Monitor (Groen thema):
- 🟢 Groen: Actieve poorten / Succes
- 🔴 Rood: Gesloten poorten / Error
- 🔵 Blauw: Inkomend verkeer
- 🟠 Oranje: Uitgaand verkeer

### Firewall Control (Oranje thema):
- 🔴 Rood: Geblokkeerde IPs / Failed logins
- 🟢 Groen: Succes / Active logins
- 🟠 Oranje: Waarschuwingen
- 🔵 Blauw: Netwerk info
- 🟡 Goud: Systeem info

## 📝 Licentie
MIT

## 👨‍💻 Auteur
cali1997

## 🌟 Credits
- GTK3 voor UI framework
- iptables/UFW voor firewall
- ss/lsof voor netwerk monitoring
