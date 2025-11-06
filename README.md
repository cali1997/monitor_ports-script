# monitor_ports-script

Dit project bevat twee scripts voor het monitoren van open poorten op je Linux systeem.

## Scripts

### 1. monitor_ports.sh
Een bash script dat continu in de terminal de open TCP/UDP poorten monitort en wijzigingen toont.

### 2. port_sidebar.py
Een GTK3 Python applicatie die een sidebar venster toont met real-time port monitoring.

## Installatie

### Vereisten
Voor `monitor_ports.sh`:
- bash
- ss (meestal al geïnstalleerd)

Voor `port_sidebar.py`:
- Python 3
- GTK 3
- PyGObject

Installeer de vereisten voor Python script:
```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0
```

## Gebruik

### monitor_ports.sh starten

1. Maak het script uitvoerbaar:
```bash
chmod +x monitor_ports.sh
```

2. Start het script:
```bash
./monitor_ports.sh
```

3. Stop met Ctrl+C

**Instellingen aanpassen:**
Open het script en pas de variabelen aan het begin aan:
- `INTERVAL`: tijd tussen checks (seconden)
- `ONLY_TCP`: true voor alleen TCP, false voor TCP+UDP
- `FILTER_LOCAL`: true om localhost te verbergen
- `LOGFILE`: pad voor logbestand (optioneel)

### port_sidebar.py starten

1. Maak het script uitvoerbaar:
```bash
chmod +x port_sidebar.py
```

2. Start het script:
```bash
./port_sidebar.py
```

**Automatisch starten bij login:**
Voeg toe aan je startup applicaties of gebruik:
```bash
cp port_sidebar.py ~/.local/bin/
echo "python3 ~/.local/bin/port_sidebar.py &" >> ~/.bashrc
```

## Kenmerken

### monitor_ports.sh
- Real-time monitoring van open poorten
- Toont nieuwe en gesloten poorten
- Optionele logging
- Aanpasbare filters

### port_sidebar.py
- GTK sidebar interface
- Real-time updates
- Kleurrijke weergave
- Highlight voor nieuwe poorten
- Donker thema

## Licentie
MIT
