#!/bin/bash

# SSH Login Analyzer
# Analyzes failed SSH login attempts and identifies suspicious IPs.

THRESHOLD=5
OUTPUT="ssh_report_$(date +%Y%m%d_%H%M%S).csv"

# Detect authentication log
if [[ -f /var/log/auth.log ]]; then
    LOG="/var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
    LOG="/var/log/secure"
else
    echo "[!] Authentication log not found."
    exit 1
fi

echo "SSH Login Security Report"
echo "========================="
echo "Log file : $LOG"
echo "Threshold: $THRESHOLD failed attempts"
echo

# CSV
echo "IP,Failed_Attempts,Status" > "$OUTPUT"
echo "[+] Failed SSH login attempts:"
echo

# Extract failed SSH login IPs
grep -E "sshd.*(Failed password|Invalid user)" "$LOG" 2>/dev/null |
awk '
{
    for (i=1; i<=NF; i++) {
        if ($i == "from") {
            print $(i+1)
        }
    }
}' |
sort |
uniq -c |
sort -nr |
while read -r COUNT IP; do

    if [[ "$COUNT" -ge "$THRESHOLD" ]]; then
        STATUS="SUSPICIOUS"
    else
        STATUS="NORMAL"
    fi

    printf "%-18s %-10s %s\n" "$IP" "$COUNT" "$STATUS"
    echo "$IP,$COUNT,$STATUS" >> "$OUTPUT"
done
echo
echo "[+] Report saved to: $OUTPUT"
