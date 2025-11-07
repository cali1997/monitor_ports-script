# monitor_ports-script

Complete security & monitoring suite voor Linux met **automatische threat detection & response**! 🛡️

## 🚀 Scripts

### 1. port_sidebar.py (RECHTS)
**Port Monitor Pro** - Real-time poort monitoring
- 🔍 Monitor open TCP/UDP poorten
- 🔪 Kill processen (rechtermuisklik of handmatig)
- 📡 Bekijk actieve verbindingen (in/uitgaand)
- 🏠 Toggle localhost weergave
- ⌨️ Keyboard controls (pijltjestoetsen)

### 2. firewall_sidebar.py (LINKS)
**Firewall & Security Control** - Beveiligingsbeheer
- 🚫 Blokkeer/deblokkeer IP adressen
- 🛡️ iptables & UFW controle
- 📊 Live systeem monitoring
- 🌐 Live IP verbindingen tracker
- ⌨️ Keyboard controls (pijltjestoetsen)

### 3. security_defense.py (CENTER) ⭐ NIEUW!
**Auto-Defense System** - Intelligente beveiliging
- � **Port Scanner** met volledige uitleg
- 🚨 **Auto-detect aanvallen** (>20 conn/sec)
- 🚫 **Auto-block verdachte IPs**
- 🔴 **Fullscreen alarm** (knipperend rood)
- 📊 **Real-time threat log**
- ✅ **Test mode** voor alarm

### 4. launch_both.sh
**Complete Suite Launcher** - Start alles tegelijk!
- Start port monitor (rechts)
- Start firewall control (links)
- Start security defense (center)
- Alle systemen tegelijk beheren

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

### Complete suite starten (AANBEVOLEN):
```bash
./launch_both.sh
```

Dit start ALLE 3 systemen:
1. 🛡️ Security Defense (center) - Auto-defense
2. 🧠 Port Monitor (rechts) - Poort monitoring  
3. 🔥 Firewall Control (links) - Firewall beheer

### Of individueel:
```bash
./security_defense.py   # Auto-defense system
./port_sidebar.py       # Port monitor
./firewall_sidebar.py   # Firewall control
```

## ✨ Features

### 🛡️ Security Defense System (NIEUW!)

#### Port Scanner:
✅ Scan alle open poorten  
✅ Detecteer welke processen draaien  
✅ **Kleurgecodeerde risico's** (rood = gevaarlijk)  
✅ **Volledige uitleg** per poort:
   - Poort 22 = SSH (veilige remote toegang)
   - Poort 80 = HTTP (websites)
   - Poort 443 = HTTPS (beveiligde websites)
   - Poort 3389 = RDP (gevaarlijk!)
   - +20 andere bekende services

#### Auto-Defense:
✅ **Real-time monitoring** van alle verbindingen  
✅ **Detecteert aanvallen** (>20 verbindingen/sec)  
✅ **Automatisch blokkeren** via iptables  
✅ **Threat logging** met timestamps  
✅ **Geblokkeerde IPs lijst**  

#### Alarm Systeem:
✅ **Fullscreen rood scherm** bij aanval  
✅ **Knippert 5 seconden** (10x flashing)  
✅ **Toont IP van aanvaller**  
✅ **Audio/visuele waarschuwing**  
✅ **Test mode** om te testen  

### Port Monitor Pro:
✅ Real-time poort detectie  
✅ Kill functie (rechtermuisklik)  
✅ Actieve verbindingen (↓IN / ↑OUT)  
✅ Keyboard movement (pijltjes)  
✅ Groen/rood kleurcodering  

### Firewall Control:
✅ IP blokkeren/deblokkeren  
✅ Live IP verbindingen  
✅ Open poorten display  
✅ Systeem info (CPU/RAM/Network)  
✅ Keyboard movement (pijltjes)  
✅ Horizontale layout (3 kolommen)  

## 🔥 Security Defense Gebruik

### Port Scan Uitvoeren:
```
1. Open Security Defense
2. Klik "� Scan Open Poorten"
3. Zie popup met:
   - Alle open poorten
   - Protocol (TCP/UDP)
   - Proces naam
   - Wat de poort doet
   - Risico kleur (rood/oranje/groen)
```

### Auto-Defense Activeren:
```
✅ Is ALTIJD actief in de achtergrond!

Bij aanval:
1. Detecteert >20 verbindingen/sec van 1 IP
2. Blokkeert IP AUTOMATISCH
3. Toont ROOD ALARM scherm (knipperend)
4. Logt in threat lijst
5. Voegt toe aan blocked IPs
```

### Alarm Testen:
```
1. Klik "� Test Alarm"
2. Zie volledig alarm systeem
3. Rood knipperend scherm
4. Simulated attack info
```

### Geblokkeerde IPs Verwijderen:
```
1. Klik "🧹 Clear Blocks"
2. Alle IP blocks worden verwijderd
3. Iptables wordt geflusht
```

## ⌨️ Keyboard Controls

**Beide sidebars (port + firewall):**
- ⬅️ = Window naar links (10px)
- ➡️ = Window naar rechts (10px)
- ⬆️ = Window naar boven (10px)
- ⬇️ = Window naar onder (10px)
- **Ctrl + pijltjes** = Sneller (50px)

**Positioneer perfect waar JE wilt!**

## 🚨 Security Features

### Threat Detection:
- ⚡ **Real-time monitoring** elke 2 seconden
- 🎯 **Detecteert DDoS aanvallen** 
- 🔍 **Port scan detectie**
- 🌐 **Verdachte IP tracking**
- 📊 **Verbindingen per seconde tellen**

### Auto-Response:
- 🚫 **Instant IP blocking** bij detectie
- ⏰ **5 minuten cooldown** per geblokkeerd IP
- 🔒 **iptables DROP rules**
- 📝 **Volledige logging**
- 🔴 **Visual alerts** (fullscreen)

### Thresholds:
- **Normaal**: 1-10 verbindingen/sec → Groen
- **Verdacht**: 10-20 verbindingen/sec → Oranje  
- **AANVAL**: >20 verbindingen/sec → **ROOD + AUTO-BLOCK**

## 📋 Voorbeelden

### Scenario 1: Systeem scannen op open poorten
```
1. Start: ./security_defense.py
2. Klik "🔍 Scan Open Poorten"  
3. Zie popup met alle info
4. Rood = gevaarlijk (bijv. Telnet poort 23)
5. Groen = normaal (bijv. HTTPS poort 443)
```

### Scenario 2: Aanval wordt automatisch geblokkeerd
```
1. Security Defense draait in achtergrond
2. Hacker probeert 100 verbindingen/sec
3. 🚨 ALARM! Rood scherm verschijnt
4. IP wordt automatisch geblokkeerd
5. Zie in "Blocked IPs" lijst
6. Check "Threats" log voor details
```

### Scenario 3: Complete security suite
```
1. Start: ./launch_both.sh
2. LINKS: Firewall Control → monitor live IPs
3. CENTER: Security Defense → auto-blocks
4. RECHTS: Port Monitor → zie actieve poorten
5. Positioneer met keyboard (pijltjes)
6. Volledige security overview!
```

## 🖥️ Screenshots Layout

```
┌───────────────┐  ┌─────────────────┐  ┌────────────────┐
│ 🔥 Firewall   │  │ 🛡️ Security     │  │ 🧠 Port        │
│    Control    │  │    Defense      │  │    Monitor     │
│   (LINKS)     │  │   (CENTER)      │  │   (RECHTS)     │
├───────────────┤  ├─────────────────┤  ├────────────────┤
│� Poorten     │  │🔍 Port Scanner  │  │🏠 Localhost    │
│🌐 Live IPs    │  │� Auto-Defense  │  │🔪 Kill Poort   │
│📊 Systeem     │  │⚠️ Threats Log   │  │📍 Luisterende  │
│⌨️ Keyboard    │  │🚫 Blocked IPs   │  │🌐 Verbindingen │
└───────────────┘  └─────────────────┘  └────────────────┘
```

## 🎨 Kleurenschema

### Security Defense:
- 🔴 **Rood**: Aanvallen / Geblokkeerd / ALARM
- 🟢 **Groen**: Veilig / Normale poorten
- 🟠 **Oranje**: Waarschuwing / Risico poorten
- ⚪ **Wit**: Info tekst op alarm

### Port Database Kleuren:
- 🟢 **Groen**: SSH (22), HTTP (80), HTTPS (443) - Normaal
- 🟠 **Oranje**: Databases, custom services - Check
- 🔴 **Rood**: Telnet (23), RDP (3389), VNC (5900) - GEVAARLIJK!

## 🔧 Troubleshooting

**"Permission denied" bij auto-block:**
```bash
# Use pkexec (graphical sudo) of setup NOPASSWD:
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /usr/sbin/iptables
```

**Alarm scherm blijft hangen:**
```bash
# Kill proces en herstart:
pkill -f security_defense
./security_defense.py
```

**Te veel false positives:**
```python
# Edit security_defense.py regel 28:
SUSPICIOUS_THRESHOLD = 50  # Verhoog threshold
```

## 📊 Port Database

Ingebouwde database met **20+ services**:
- 🌐 Web: 80 (HTTP), 443 (HTTPS), 8080, 8443
- � Remote: 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC)
- � Mail: 25 (SMTP), 110 (POP3), 143 (IMAP)
- � Databases: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
- � Other: 21 (FTP), 53 (DNS), 445 (SMB), 6379 (Redis)

## 📝 Licentie
MIT

## 👨‍💻 Auteur
cali1997

## 🌟 Credits
- GTK3 voor UI framework
- iptables voor auto-blocking
- ss voor network monitoring
- Python threading voor real-time detection
