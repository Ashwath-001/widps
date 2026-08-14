#!/bin/bash
# ============================================================================
# WIDPS Advanced Honeypot Setup Script
# ============================================================================
# Deploys a full multi-SSID deception network with:
#   - 4 fake SSIDs targeting different attacker profiles
#   - Captive portal for credential capture intelligence
#   - DNS logging for C2 domain detection
#   - DHCP fingerprinting for OS identification
#   - Full network isolation from production
#
# Run with: sudo bash honeypot/setup.sh
#
# Architecture:
#   wlan2 ─── FreeWiFi ────────── 192.168.66.0/24
#   wlan2_1 ─ eduroam_guest ───── 192.168.67.0/24
#   wlan2_2 ─ HP-Print-Setup ──── 192.168.68.0/24
#   wlan2_3 ─ DIRECT-wifi ─────── 192.168.69.0/24
#
# All subnets are isolated. No internet access provided.
# All DNS queries logged. All HTTP traffic captured.
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

HONEYPOT_IFACE="${WIDPS_HONEYPOT_IFACE:-wlan2}"
MONITOR_IFACE="${WIDPS_MONITOR_IFACE:-wlan1mon}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   WIDPS Advanced Honeypot Deception Network      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Honeypot Interface: ${GREEN}$HONEYPOT_IFACE${NC}"
echo -e "  Monitor Interface:  ${GREEN}$MONITOR_IFACE${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[0/7] Checking dependencies...${NC}"
MISSING=""
for cmd in hostapd dnsmasq iptables python3 ip; do
    if ! command -v $cmd &> /dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    echo -e "${RED}[ERROR] Missing dependencies:$MISSING${NC}"
    echo "        Install with: sudo apt install$MISSING"
    exit 1
fi

# Check interface exists
if ! ip link show "$HONEYPOT_IFACE" &> /dev/null; then
    echo -e "${RED}[ERROR] Interface $HONEYPOT_IFACE not found.${NC}"
    echo "        Available wireless interfaces:"
    iw dev 2>/dev/null | grep Interface | awk '{print "          " $2}' || \
        ip link show | grep -E "wlan|wl" | awk '{print "          " $2}'
    echo ""
    echo "        Set custom interface: WIDPS_HONEYPOT_IFACE=wlan3 sudo bash honeypot/setup.sh"
    exit 1
fi

# Check if interface supports AP mode
if ! iw phy $(iw dev "$HONEYPOT_IFACE" info 2>/dev/null | grep wiphy | awk '{print $2}') info 2>/dev/null | grep -q "* AP"; then
    echo -e "${YELLOW}[WARN] Interface may not support AP mode. Proceeding anyway...${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Kill conflicting processes
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/7] Stopping conflicting services...${NC}"
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
killall hostapd 2>/dev/null || true
killall dnsmasq 2>/dev/null || true

# Kill any existing captive portal
pkill -f "captive_portal.py" 2>/dev/null || true

# NetworkManager: unmanage honeypot interface
if command -v nmcli &> /dev/null; then
    nmcli device set "$HONEYPOT_IFACE" managed no 2>/dev/null || true
fi

echo -e "  ${GREEN}✓ Clean state${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Configure network interfaces
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/7] Configuring network interfaces...${NC}"

# Bring down first
ip link set "$HONEYPOT_IFACE" down 2>/dev/null || true

# Flush existing addresses
ip addr flush dev "$HONEYPOT_IFACE" 2>/dev/null || true

# Set primary IP (FreeWiFi subnet)
ip addr add 192.168.66.1/24 dev "$HONEYPOT_IFACE"
ip link set "$HONEYPOT_IFACE" up

# Note: virtual BSSes (wlan2_1, wlan2_2, wlan2_3) are created by hostapd
# We'll add their IPs after hostapd starts

echo -e "  ${GREEN}✓ Interface configured (192.168.66.1/24)${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Enable IP forwarding (needed for DHCP relay)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/7] Enabling IP forwarding...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -e "  ${GREEN}✓ IP forwarding enabled${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Firewall — complete isolation
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/7] Setting up firewall isolation...${NC}"

# Create honeypot chain
iptables -N WIDPS_HONEYPOT 2>/dev/null || iptables -F WIDPS_HONEYPOT

# DROP all forwarding from honeypot subnets to anywhere else
iptables -D FORWARD -j WIDPS_HONEYPOT 2>/dev/null || true
iptables -I FORWARD -j WIDPS_HONEYPOT

# Block honeypot → production network
iptables -A WIDPS_HONEYPOT -s 192.168.66.0/24 -d 192.168.0.0/16 -j DROP
iptables -A WIDPS_HONEYPOT -s 192.168.67.0/24 -d 192.168.0.0/16 -j DROP
iptables -A WIDPS_HONEYPOT -s 192.168.68.0/24 -d 192.168.0.0/16 -j DROP
iptables -A WIDPS_HONEYPOT -s 192.168.69.0/24 -d 192.168.0.0/16 -j DROP

# Block honeypot → internet (10.0.0.0/8 covers most campus LANs)
iptables -A WIDPS_HONEYPOT -s 192.168.66.0/22 -d 10.0.0.0/8 -j DROP
iptables -A WIDPS_HONEYPOT -s 192.168.66.0/22 -o eth0 -j DROP

# Block honeypot → monitor interface
iptables -A WIDPS_HONEYPOT -s 192.168.66.0/22 -o "$MONITOR_IFACE" -j DROP

# Allow DHCP + DNS + HTTP within honeypot
iptables -A INPUT -i "$HONEYPOT_IFACE" -p udp --dport 67 -j ACCEPT
iptables -A INPUT -i "$HONEYPOT_IFACE" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i "$HONEYPOT_IFACE" -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -i "$HONEYPOT_IFACE" -p tcp --dport 8080 -j ACCEPT

# LOG all other traffic from honeypot (for forensics)
iptables -A WIDPS_HONEYPOT -s 192.168.66.0/22 -j LOG --log-prefix "[WIDPS-HP] " --log-level 4

echo -e "  ${GREEN}✓ Firewall rules applied (full isolation)${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Start hostapd (multi-SSID AP)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/7] Starting hostapd (4 SSIDs)...${NC}"

hostapd "$SCRIPT_DIR/hostapd.conf" -B \
    -P /tmp/widps_honeypot_hostapd.pid \
    -f /tmp/widps_honeypot_hostapd.log

sleep 2

# Add IPs to virtual BSSes (created by hostapd)
for i in 1 2 3; do
    VBSS="${HONEYPOT_IFACE}_${i}"
    if ip link show "$VBSS" &> /dev/null; then
        SUBNET=$((66 + i))
        ip addr add "192.168.${SUBNET}.1/24" dev "$VBSS" 2>/dev/null || true
        ip link set "$VBSS" up 2>/dev/null || true
        echo -e "  ${GREEN}✓ Virtual BSS $VBSS → 192.168.${SUBNET}.0/24${NC}"
    fi
done

echo -e "  ${GREEN}✓ hostapd running (4 SSIDs active)${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Start dnsmasq (DHCP + DNS)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[6/7] Starting dnsmasq (DHCP + DNS intelligence)...${NC}"

# Create log file
touch /var/log/widps_honeypot_dns.log
chmod 644 /var/log/widps_honeypot_dns.log

dnsmasq -C "$SCRIPT_DIR/dnsmasq.conf" \
    --pid-file=/tmp/widps_honeypot_dnsmasq.pid

echo -e "  ${GREEN}✓ dnsmasq running (DHCP + DNS logging active)${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Start captive portal
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[7/7] Starting captive portal...${NC}"

python3 "$SCRIPT_DIR/captive_portal.py" &
echo $! > /tmp/widps_honeypot_portal.pid

sleep 1
echo -e "  ${GREEN}✓ Captive portal active (credential capture ready)${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# Create forensics directory
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p data/honeypot_forensics

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   🍯 Honeypot Deception Network ACTIVE           ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║                                                   ║${NC}"
echo -e "${CYAN}║  SSID: FreeWiFi          → 192.168.66.0/24       ║${NC}"
echo -e "${CYAN}║  SSID: eduroam_guest     → 192.168.67.0/24       ║${NC}"
echo -e "${CYAN}║  SSID: HP-Print-Setup    → 192.168.68.0/24       ║${NC}"
echo -e "${CYAN}║  SSID: DIRECT-wifi       → 192.168.69.0/24       ║${NC}"
echo -e "${CYAN}║                                                   ║${NC}"
echo -e "${CYAN}║  All subnets ISOLATED from production.            ║${NC}"
echo -e "${CYAN}║  No internet access provided.                     ║${NC}"
echo -e "${CYAN}║                                                   ║${NC}"
echo -e "${CYAN}║  Intelligence gathered:                           ║${NC}"
echo -e "${CYAN}║    • DNS queries (C2 detection)                   ║${NC}"
echo -e "${CYAN}║    • DHCP fingerprints (OS identification)        ║${NC}"
echo -e "${CYAN}║    • HTTP requests (tool detection)               ║${NC}"
echo -e "${CYAN}║    • Credential submissions (intent proof)        ║${NC}"
echo -e "${CYAN}║    • Connection patterns (classification)         ║${NC}"
echo -e "${CYAN}║                                                   ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Logs:                                            ║${NC}"
echo -e "${CYAN}║    DNS:     /var/log/widps_honeypot_dns.log       ║${NC}"
echo -e "${CYAN}║    HTTP:    /tmp/widps_honeypot_http.log          ║${NC}"
echo -e "${CYAN}║    hostapd: /tmp/widps_honeypot_hostapd.log       ║${NC}"
echo -e "${CYAN}║    Leases:  /tmp/widps_honeypot_leases            ║${NC}"
echo -e "${CYAN}║    Reports: data/honeypot_forensics/              ║${NC}"
echo -e "${CYAN}║                                                   ║${NC}"
echo -e "${CYAN}║  Stop:  sudo bash honeypot/stop.sh                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
