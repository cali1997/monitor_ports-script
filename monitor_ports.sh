#!/usr/bin/env bash

# ==== instellingen ====
INTERVAL=3          # aantal seconden tussen checks
ONLY_TCP=true       # true = alleen tcp luisteren, false = tcp+udp
FILTER_LOCAL=true   # true = 127.0.0.1 / ::1 niet tonen
LOGFILE=""          # bv. /var/log/port_monitor.log of leeg laten
# ======================

prev=""

echo "[*] Port monitor gestart (elke $INTERVAL s). Ctrl+C om te stoppen."

get_current() {
    if [ "$ONLY_TCP" = true ]; then
        # alleen tcp
        out=$(ss -tln | awk 'NR>1 {print $1,$5}')
    else
        # tcp + udp
        out=$(ss -tuln | awk 'NR>1 {print $1,$5}')
    fi

    if [ "$FILTER_LOCAL" = true ]; then
        # filter alles wat alleen op localhost luistert
        out=$(echo "$out" | grep -Ev '127\.0\.0\.1:|::1:')
    fi

    # sorteren voor comm
    echo "$out" | sed '/^$/d' | sort
}

while true; do
    current=$(get_current)

    if [ -n "$prev" ]; then
        # nieuw: in current maar niet in prev
        added=$(comm -13 <(echo "$prev") <(echo "$current"))
        # gesloten: in prev maar niet in current
        removed=$(comm -23 <(echo "$prev") <(echo "$current"))

        if [ -n "$added" ]; then
            echo
            echo -e "🔔 \e[32mNIEUWE LISTENING SOCKET(s) GEDTECTEERD:\e[0m"
            echo "$added"
            echo -ne "\a"
            [ -n "$LOGFILE" ] && echo "$(date) ADDED: $added" >> "$LOGFILE"
        fi

        if [ -n "$removed" ]; then
            echo
            echo -e "❌ \e[31mSOCKET(s) GESLOTEN:\e[0m"
            echo "$removed"
            [ -n "$LOGFILE" ] && echo "$(date) REMOVED: $removed" >> "$LOGFILE"
        fi
    fi

    prev="$current"
    sleep "$INTERVAL"
done
