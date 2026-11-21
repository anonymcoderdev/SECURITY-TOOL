#!/bin/bash

set -u

TARGET="$1"

if [[ -z "${TARGET:-}" ]]; then
    echo "Usage: $0 <IP|CIDR|hostname>"
    echo
    echo "Examples:"
    echo "  $0 192.168.1.10"
    echo "  $0 192.168.1.0/24"
    echo "  $0 example.com"
    exit 1
fi

# ==============================
# Configuration
# ==============================

PORTS=(22 53 80 443 445 3306 3389 5432 8080 8443)

TIMEOUT=1
OUTPUT="scan_$(date +%Y%m%d_%H%M%S).csv"

echo "Target : $TARGET"
echo "Output : $OUTPUT"
echo

# ==============================
# Dependencies
# ==============================

for CMD in ping curl; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[!] Missing dependency: $CMD"
        exit 1
    fi
done

# ==============================
# CSV header
# ==============================

echo "IP,Status,ReverseDNS,OpenPorts,HTTP" > "$OUTPUT"

# ==============================
# Single host check
# ==============================

check_host() {

    local IP="$1"

    echo
    echo "--------------------------------"
    echo "[*] Checking $IP"

    # Ping
    if ping -c 1 -W 1 "$IP" >/dev/null 2>&1; then
        STATUS="UP"
        echo "[+] Host: UP"
    else
        STATUS="DOWN"
        echo "[-] Host: DOWN"
        echo "$IP,$STATUS,,, " >> "$OUTPUT"
        return
    fi

    # Reverse DNS
    REVERSE=$(getent hosts "$IP" 2>/dev/null | awk '{print $2}')

    if [[ -n "$REVERSE" ]]; then
        echo "[+] Reverse DNS: $REVERSE"
    else
        REVERSE="-"
        echo "[+] Reverse DNS: -"
    fi

    # Port scan
    OPEN_PORTS=""
    echo "[+] Ports:"
    for PORT in "${PORTS[@]}"; do
        if timeout "$TIMEOUT" \
            bash -c "</dev/tcp/$IP/$PORT" \
            >/dev/null 2>&1; then
            echo "    $PORT/tcp OPEN"
            if [[ -n "$OPEN_PORTS" ]]; then
                OPEN_PORTS="$OPEN_PORTS;$PORT"
            else
                OPEN_PORTS="$PORT"
            fi
        fi
    done
    [[ -z "$OPEN_PORTS" ]] && OPEN_PORTS="-"

    # HTTP
    HTTP_INFO="-"
    for SCHEME in http https; do
        RESULT=$(curl -k -s \
            --connect-timeout 2 \
            --max-time 4 \
            -o /dev/null \
            -w "%{http_code}|%{url_effective}" \
            "$SCHEME://$IP" 2>/dev/null)
        CODE="${RESULT%%|*}"
        URL="${RESULT#*|}"

        if [[ "$CODE" != "000" ]]; then
            HTTP_INFO="$CODE $URL"
            echo "[+] HTTP: $CODE $URL"
            break
        fi
    done

    # CSV
    echo "$IP,$STATUS,$REVERSE,$OPEN_PORTS,\"$HTTP_INFO\"" >> "$OUTPUT"
}


# CIDR handling

if [[ "$TARGET" == */* ]]; then
    if ! command -v nmap >/dev/null 2>&1; then
        echo "[!] CIDR scanning requires nmap."
        echo "    Install it first."
        exit 1
    fi
    echo "[*] CIDR detected"
    echo "[*] Discovering live hosts..."
    echo

    HOSTS=$(nmap -sn "$TARGET" -oG - 2>/dev/null |
        awk '/Up$/{print $2}')

    if [[ -z "$HOSTS" ]]; then
        echo "[-] No live hosts found."
        exit 0
    fi

    echo "[+] Live hosts:"
    echo "$HOSTS"

    while read -r IP; do
        check_host "$IP"
    done <<< "$HOSTS"

else
    check_host "$TARGET"
fi

echo
echo "================================"
echo "[+] Scan completed"
echo "[+] Results: $OUTPUT"
echo "================================"