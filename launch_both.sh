#!/usr/bin/env bash
# Start beide sidebars tegelijk

echo "🚀 Starting Port Monitor Pro & Firewall Control..."

# Start port monitor (rechts)
python3 "$(dirname "$0")/port_sidebar.py" &
PORT_PID=$!

# Wacht even
sleep 0.5

# Start firewall sidebar (links)
python3 "$(dirname "$0")/firewall_sidebar.py" &
FIREWALL_PID=$!

echo "✅ Port Monitor PID: $PORT_PID"
echo "✅ Firewall Control PID: $FIREWALL_PID"
echo ""
echo "Druk op Ctrl+C om beide te stoppen..."

# Wacht op user interrupt
trap "kill $PORT_PID $FIREWALL_PID 2>/dev/null; echo '👋 Gestopt!'; exit" INT TERM

wait
