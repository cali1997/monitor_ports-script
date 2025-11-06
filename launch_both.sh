#!/usr/bin/env bash
# Start beide sidebars tegelijk

echo "🚀 Starting Port Monitor Pro & Firewall Control..."
echo ""
echo "ℹ️  Firewall functies vereisen sudo rechten."
echo "   Je wordt om wachtwoord gevraagd wanneer je een IP blokkeert."
echo ""

# Start port monitor (rechts)
python3 "$(dirname "$0")/port_sidebar.py" &
PORT_PID=$!

# Wacht even
sleep 0.5

# Start firewall sidebar (links)
python3 "$(dirname "$0")/firewall_sidebar.py" &
FIREWALL_PID=$!

echo "✅ Port Monitor PID: $PORT_PID (rechts)"
echo "✅ Firewall Control PID: $FIREWALL_PID (links)"
echo ""
echo "💡 TIP: Sleep de headers om vensters te verplaatsen!"
echo "📌 Druk op Ctrl+C om beide te stoppen..."
echo ""

# Wacht op user interrupt
trap "kill $PORT_PID $FIREWALL_PID 2>/dev/null; echo ''; echo '👋 Beide sidebars gestopt!'; exit" INT TERM

wait
