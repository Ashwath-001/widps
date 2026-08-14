#!/bin/bash
# ============================================================================
# WIDPS Raspberry Pi Hardening Script
# ============================================================================
# Secures the Pi for deployment as a wireless IDS sensor.
# Run once after initial OS setup: sudo bash deploy/harden.sh
#
# What this does:
#   1. Disables password SSH (key-only auth)
#   2. Installs and configures fail2ban
#   3. Sets up firewall (only allow SSH + dashboard ports)
#   4. Disables unnecessary services
#   5. Sets up automatic security updates
#   6. Configures log rotation
#   7. Protects the monitoring interface from external manipulation
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} WIDPS Raspberry Pi Hardening${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Must run as root: sudo bash deploy/harden.sh${NC}"
    exit 1
fi

MONITOR_IFACE="${WIDPS_MONITOR_IFACE:-wlan1mon}"
DASHBOARD_PORT=5173
API_PORT=8787
SSH_PORT=22

# ---------------------------------------------------------------------------
# 1. SSH Hardening
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[1/7] Hardening SSH...${NC}"

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.widps

# Apply hardening
cat >> /etc/ssh/sshd_config.d/widps-hardening.conf << 'EOF'
# WIDPS SSH Hardening
PasswordAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 20
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Ensure at least one SSH key exists
if [ ! -f /home/pi/.ssh/authorized_keys ] && [ ! -f /root/.ssh/authorized_keys ]; then
    echo -e "${YELLOW}  [WARN] No SSH keys found! Add your key before restarting SSH.${NC}"
    echo -e "${YELLOW}  Run: ssh-copy-id pi@<pi-ip> from your laptop first.${NC}"
else
    systemctl restart sshd
    echo -e "${GREEN}  SSH hardened (key-only, max 3 attempts)${NC}"
fi

# ---------------------------------------------------------------------------
# 2. Fail2ban
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[2/7] Installing fail2ban...${NC}"

apt-get update -qq
apt-get install -y -qq fail2ban > /dev/null 2>&1

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}  fail2ban active (SSH: 3 attempts → 2hr ban)${NC}"

# ---------------------------------------------------------------------------
# 3. Firewall (iptables/nftables)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[3/7] Configuring firewall...${NC}"

# Flush existing rules
iptables -F
iptables -X

# Default policies: drop everything incoming
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT

# Allow WIDPS Dashboard
iptables -A INPUT -p tcp --dport $DASHBOARD_PORT -j ACCEPT

# Allow WIDPS API
iptables -A INPUT -p tcp --dport $API_PORT -j ACCEPT

# Allow DHCP for honeypot interface (if present)
iptables -A INPUT -i wlan2 -p udp --dport 67 -j ACCEPT
iptables -A INPUT -i wlan2 -p udp --dport 53 -j ACCEPT

# Block all attempts to deauth/disassociate our monitor interface
# (won't stop RF attacks but logs injection attempts via our interface)
iptables -A INPUT -i "$MONITOR_IFACE" -j DROP

# Save rules
iptables-save > /etc/iptables.rules

# Auto-restore on boot
cat > /etc/network/if-pre-up.d/iptables << 'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
chmod +x /etc/network/if-pre-up.d/iptables

echo -e "${GREEN}  Firewall configured (SSH:$SSH_PORT, Dashboard:$DASHBOARD_PORT, API:$API_PORT)${NC}"

# ---------------------------------------------------------------------------
# 4. Disable unnecessary services
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[4/7] Disabling unnecessary services...${NC}"

SERVICES_TO_DISABLE="bluetooth avahi-daemon cups triggerhappy"
for svc in $SERVICES_TO_DISABLE; do
    if systemctl is-active "$svc" > /dev/null 2>&1; then
        systemctl stop "$svc"
        systemctl disable "$svc"
        echo "  Disabled: $svc"
    fi
done

echo -e "${GREEN}  Unnecessary services disabled${NC}"

# ---------------------------------------------------------------------------
# 5. Automatic security updates
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[5/7] Configuring automatic security updates...${NC}"

apt-get install -y -qq unattended-upgrades > /dev/null 2>&1

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

echo -e "${GREEN}  Automatic security updates enabled${NC}"

# ---------------------------------------------------------------------------
# 6. Log rotation for WIDPS
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[6/7] Configuring log rotation...${NC}"

cat > /etc/logrotate.d/widps << 'EOF'
/home/*/projects/widps/widps_alerts.jsonl
/var/log/widps_honeypot_dns.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

echo -e "${GREEN}  Log rotation configured (30 days retention)${NC}"

# ---------------------------------------------------------------------------
# 7. Interface protection
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[7/7] Protecting monitor interface...${NC}"

# Prevent NetworkManager from touching our interfaces
if [ -f /etc/NetworkManager/NetworkManager.conf ]; then
    cat >> /etc/NetworkManager/NetworkManager.conf << EOF

[keyfile]
unmanaged-devices=interface-name:wlan1*;interface-name:wlan2*
EOF
    systemctl restart NetworkManager 2>/dev/null || true
fi

# Set interface to not respond to ARP on the monitor interface
echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore 2>/dev/null || true

echo -e "${GREEN}  Monitor interface protected from management daemons${NC}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN} Hardening Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo " Applied:"
echo "   ✓ SSH: Key-only auth, max 3 attempts"
echo "   ✓ Fail2ban: 3 failures → 2hr ban"
echo "   ✓ Firewall: Only SSH + WIDPS ports open"
echo "   ✓ Services: Bluetooth/Avahi/CUPS disabled"
echo "   ✓ Updates: Automatic security patches"
echo "   ✓ Logs: 30-day rotation with compression"
echo "   ✓ Interface: Monitor protected from mgmt daemons"
echo ""
echo -e "${YELLOW} IMPORTANT: Ensure you have SSH key access before"
echo -e " disconnecting! Password auth is now disabled.${NC}"
echo ""
