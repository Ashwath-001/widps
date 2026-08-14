#!/bin/bash
# WIDPS Honeypot Shutdown Script
# Kill all honeypot processes and clean up firewall rules.

echo "[WIDPS] Stopping honeypot deception network..."

# Kill processes by PID file
for pidfile in /tmp/widps_honeypot_hostapd.pid /tmp/widps_honeypot_dnsmasq.pid /tmp/widps_honeypot_portal.pid; do
    if [ -f "$pidfile" ]; then
        kill $(cat "$pidfile") 2>/dev/null
        rm -f "$pidfile"
    fi
done

# Kill by name (fallback)
killall hostapd 2>/dev/null || true
killall dnsmasq 2>/dev/null || true
pkill -f "captive_portal.py" 2>/dev/null || true

HONEYPOT_IFACE="${WIDPS_HONEYPOT_IFACE:-wlan2}"

# Remove virtual BSS IPs
for i in 1 2 3; do
    VBSS="${HONEYPOT_IFACE}_${i}"
    ip addr flush dev "$VBSS" 2>/dev/null || true
done

# Remove primary interface IP
ip addr flush dev "$HONEYPOT_IFACE" 2>/dev/null || true

# Remove firewall chain
iptables -D FORWARD -j WIDPS_HONEYPOT 2>/dev/null || true
iptables -F WIDPS_HONEYPOT 2>/dev/null || true
iptables -X WIDPS_HONEYPOT 2>/dev/null || true

# Remove individual rules
iptables -D INPUT -i "$HONEYPOT_IFACE" -p udp --dport 67 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$HONEYPOT_IFACE" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$HONEYPOT_IFACE" -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$HONEYPOT_IFACE" -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true

echo "[WIDPS] Honeypot stopped. All processes killed, firewall rules removed."
echo "[WIDPS] Forensic reports preserved in: data/honeypot_forensics/"
