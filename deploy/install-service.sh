#!/bin/bash
# ============================================================================
# WIDPS Systemd Service Installer
# ============================================================================
# Installs WIDPS as a system daemon that starts on boot.
#
# Usage: sudo bash deploy/install-service.sh
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_FILE="$SCRIPT_DIR/widps.service"
USER=$(logname 2>/dev/null || echo "pi")

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run with sudo: sudo bash deploy/install-service.sh"
    exit 1
fi

# Update paths in service file to match current user/location
echo "[1/4] Configuring service for user '$USER' at '$PROJECT_DIR'..."
sed -i "s|/home/ashh/widps|$PROJECT_DIR|g" "$SERVICE_FILE"

# Copy service file
echo "[2/4] Installing systemd service..."
cp "$SERVICE_FILE" /etc/systemd/system/widps.service

# Create data directory
echo "[3/4] Creating data directories..."
mkdir -p "$PROJECT_DIR/data/logs"
mkdir -p "$PROJECT_DIR/data/honeypot_forensics"

# Enable and start
echo "[4/4] Enabling service..."
systemctl daemon-reload
systemctl enable widps.service

echo ""
echo "============================================"
echo " WIDPS Service Installed!"
echo "============================================"
echo ""
echo " Commands:"
echo "   sudo systemctl start widps     # Start now"
echo "   sudo systemctl stop widps      # Stop"
echo "   sudo systemctl restart widps   # Restart"
echo "   sudo systemctl status widps    # Check status"
echo "   journalctl -u widps -f         # View live logs"
echo ""
echo " The service will auto-start on every boot."
echo ""
