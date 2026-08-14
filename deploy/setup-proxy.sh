set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "║  WIDPS Reverse Proxy Setup               ║"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run with sudo: sudo bash deploy/setup-proxy.sh"
    exit 1
fi

# Install nginx if missing
if ! command -v nginx &> /dev/null; then
    echo "[1/5] Installing nginx..."
    apt-get update -qq
    apt-get install -y -qq nginx > /dev/null 2>&1
else
    echo "[1/5] nginx already installed"
fi

# Build frontend for production
echo "[2/5] Building frontend..."
if [ -d "$PROJECT_DIR/widps-dashboard" ]; then
    (cd "$PROJECT_DIR/widps-dashboard" && npm run build 2>/dev/null)
fi

# Deploy frontend static files
echo "[3/5] Deploying frontend to /opt/widps/dashboard..."
mkdir -p /opt/widps/dashboard
if [ -d "$PROJECT_DIR/widps-dashboard/dist" ]; then
    rm -rf /opt/widps/dashboard/*
    cp -r "$PROJECT_DIR/widps-dashboard/dist/"* /opt/widps/dashboard/
else
    echo "  [WARN] No dist/ found. Run 'npm run build' in widps-dashboard first."
fi

# Deploy nginx config
echo "[4/5] Configuring nginx..."
cp "$SCRIPT_DIR/nginx.conf" /etc/nginx/sites-available/widps
ln -sf /etc/nginx/sites-available/widps /etc/nginx/sites-enabled/widps
rm -f /etc/nginx/sites-enabled/default

# Lock backend port to localhost only (iptables)
echo "[5/5] Restricting backend port 8787 to localhost..."
iptables -D INPUT -p tcp --dport 8787 -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport 8787 -j DROP 2>/dev/null || true
iptables -A INPUT -p tcp --dport 8787 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8787 -j DROP

# Test and reload
nginx -t
systemctl enable nginx
systemctl reload nginx

echo "Done!"