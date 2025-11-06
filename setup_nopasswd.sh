#!/usr/bin/env bash
# Setup script voor passwordless firewall commands
# Run dit EENMALIG met: sudo ./setup_nopasswd.sh

echo "🔧 Setup: Passwordless firewall commands..."
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Dit script moet met sudo worden uitgevoerd:"
    echo "   sudo ./setup_nopasswd.sh"
    exit 1
fi

USER=$(logname)
SUDOERS_FILE="/etc/sudoers.d/monitor-port-nopasswd"

echo "📝 Maak sudoers regel voor user: $USER"

# Maak sudoers bestand
cat > "$SUDOERS_FILE" << EOF
# Allow $USER to run firewall commands without password
# Created by monitor-port setup script

$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
$USER ALL=(ALL) NOPASSWD: /usr/bin/iptables
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw
$USER ALL=(ALL) NOPASSWD: /usr/bin/ufw
$USER ALL=(ALL) NOPASSWD: /bin/grep * /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/auth.log
EOF

# Set correcte permissies
chmod 0440 "$SUDOERS_FILE"

# Valideer sudoers file
if visudo -c -f "$SUDOERS_FILE" >/dev/null 2>&1; then
    echo "✅ Sudoers bestand aangemaakt: $SUDOERS_FILE"
    echo ""
    echo "📋 Toegevoegde commando's (zonder wachtwoord):"
    echo "   - iptables (add/remove rules)"
    echo "   - ufw (firewall status/rules)"
    echo "   - grep auth.log (login monitoring)"
    echo ""
    echo "🎉 Setup compleet!"
    echo ""
    echo "Je kunt nu de sidebars starten zonder wachtwoord prompts:"
    echo "   ./launch_both.sh"
else
    echo "❌ Error: Sudoers validatie mislukt!"
    rm -f "$SUDOERS_FILE"
    exit 1
fi

echo ""
echo "⚠️  BELANGRIJK:"
echo "   - Dit geeft je account rechten om firewall te beheren"
echo "   - Gebruik verantwoordelijk!"
echo "   - Om te verwijderen: sudo rm $SUDOERS_FILE"
