#!/usr/bin/env bash
# Start complete security monitoring suite

echo "🚀 Starting Security Monitoring Suite..."

# Start port monitor (rechts)
python3 "$(dirname "$0")/port_sidebar.py" &
PORT_PID=$!

# Wacht even
sleep 0.5

# Start firewall sidebar (links)
python3 "$(dirname "$0")/firewall_sidebar.py" &
FIREWALL_PID=$!

# Wacht even
sleep 0.5

# Start security defense (center)
python3 "$(dirname "$0")/security_defense.py" &
SECURITY_PID=$!

echo "✅ Port Monitor PID: $PORT_PID"
echo "✅ Firewall Control PID: $FIREWALL_PID"
echo "✅ Security Defense PID: $SECURITY_PID"
echo ""
echo "🛡️  SECURITY SUITE ACTIVE:"
echo "   - Port Monitor (rechts)"
echo "   - Firewall Control (links)"
echo "   - Security Defense (center - auto-blocks attacks)"
echo ""
echo "Druk op Ctrl+C om alle systemen te stoppen..."

# Wacht op user interrupt
trap "kill $PORT_PID $FIREWALL_PID $SECURITY_PID 2>/dev/null; echo '👋 Alle systemen gestopt!'; exit" INT TERM

wait
