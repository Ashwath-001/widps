# WIDPS Deployment — Production Setup Guide

## Overview

This folder contains everything needed to deploy WIDPS on a Raspberry Pi 5 in production:

| File | Purpose |
|------|---------|
| `nginx.conf` | Reverse proxy (frontend + API + SSE streaming) |
| `setup-proxy.sh` | Automated deployment script (installs nginx, builds frontend, locks ports) |
| `harden.sh` | OS-level security hardening (SSH, firewall, fail2ban, auto-updates) |

---

## Architecture (Production)

```
Internet / LAN
      │
      ▼ :80
┌─────────────────────────────────────┐
│          Nginx Reverse Proxy        │
│                                     │
│  /            → static SPA files    │
│  /assets/*    → cached (365d)       │
│  /api/*       → proxy → :8787      │
│  /api/stream  → SSE (no buffering)  │
└──────────────────┬──────────────────┘
                   │ 127.0.0.1:8787 only
                   ▼
┌─────────────────────────────────────┐
│         Rust Backend (WIDPS)        │
│  Not externally accessible          │
└─────────────────────────────────────┘
```

---

## Quick Deploy (All-in-One)

```bash
# Run from project root
sudo bash deploy/setup-proxy.sh
```

This script does:
1. Installs nginx (if not present)
2. Builds the React frontend (`npm run build`)
3. Copies dist files to `/opt/widps/dashboard/`
4. Installs and enables the nginx config
5. Locks port 8787 to localhost only (iptables)
6. Tests and reloads nginx

After running, the dashboard is at `http://<pi-ip>/` and the API is proxied through nginx.

---

## Security Hardening

```bash
sudo bash deploy/harden.sh
```

**What it does (7 steps):**

| Step | Action | Detail |
|------|--------|--------|
| 1 | SSH hardening | Key-only auth, max 3 attempts, disable forwarding |
| 2 | fail2ban | 3 failed SSH logins → 2-hour IP ban |
| 3 | Firewall | Default DROP, only allow SSH + WIDPS ports |
| 4 | Disable services | Bluetooth, Avahi, CUPS, triggerhappy |
| 5 | Auto-updates | Unattended security patches |
| 6 | Log rotation | 30-day retention with compression |
| 7 | Interface protection | Monitor interface hidden from NetworkManager |

**Important:** Make sure you have SSH key access before running — password auth gets disabled.

```bash
# Copy your SSH key first
ssh-copy-id pi@<pi-ip>

# Then harden
sudo bash deploy/harden.sh
```

---

## nginx.conf Details

### Rate Limiting

| Zone | Rate | Purpose |
|------|------|---------|
| `api_general` | 30 req/s per IP | GET endpoints |
| `api_write` | 5 req/s per IP | POST endpoints (config, whitelist, confirm) |
| `sse_conn` | 5 connections per IP | SSE streaming |

### SSE Streaming

The `/api/stream` endpoint has special handling:
- No proxy buffering (`proxy_buffering off`)
- 24-hour timeout (`proxy_read_timeout 86400s`)
- No chunked encoding (`chunked_transfer_encoding off`)
- `X-Accel-Buffering: no` header

### Security Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; ...`
- `Permissions-Policy: camera=(self), microphone=(), ...`

### Static Asset Caching

Vite-hashed files (`/assets/*.js`, `*.css`) get `Cache-Control: public, immutable` with 365-day expiry. This is safe because filenames change on rebuild.

---

## Firewall Rules (After Hardening)

```
Default policy: DROP (incoming), ACCEPT (outgoing)

Allowed inbound:
  - TCP :22   (SSH)
  - TCP :80   (nginx dashboard)
  - TCP :8787 (only from 127.0.0.1 — nginx proxy)
  - UDP :67   (DHCP on wlan2 for honeypot)
  - UDP :53   (DNS on wlan2 for honeypot)

Blocked:
  - All other incoming traffic
  - Direct access to :8787 from external IPs
  - Monitor interface (wlan1mon) input traffic
```

---

## Docker Deployment (Alternative)

Instead of bare-metal, use the root `docker-compose.yml`:

```bash
# Build frontend first
cd widps-dashboard && npm run build && cd ..

# Start full stack
docker compose up -d

# With SIEM
docker compose --profile siem up -d
```

See the root README for details.

---

## Systemd Service (Auto-Start on Boot)

Create `/etc/systemd/system/widps.service`:

```ini
[Unit]
Description=WIDPS Wireless Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/pi/widps
ExecStart=/home/pi/widps/widps-backend/target/release/widps
Restart=always
RestartSec=5
Environment=WIDPS_SIEM_ENABLED=0

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable widps
sudo systemctl start widps
```

---

## Checklist for Deployment

- [ ] Build backend: `cd widps-backend && cargo build --release`
- [ ] Train ML model: `cd ml && python train_model.py`
- [ ] Build frontend: `cd widps-dashboard && npm run build`
- [ ] Run setup-proxy: `sudo bash deploy/setup-proxy.sh`
- [ ] Run hardening: `sudo bash deploy/harden.sh`
- [ ] Create systemd service (above)
- [ ] Edit whitelist: `config/whitelist.toml` (add your known APs)
- [ ] Enable monitor mode: `sudo airmon-ng start wlan1`
- [ ] Start WIDPS: `sudo systemctl start widps`
- [ ] Verify dashboard: `http://<pi-ip>/`
- [ ] (Optional) Start honeypot: `sudo bash honeypot/setup.sh`
- [ ] (Optional) Start SIEM: `cd siem && docker compose up -d`
