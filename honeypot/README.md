# WIDPS Honeypot — Dynamic Deception & Attacker Confirmation

## Purpose

The honeypot **confirms** that devices flagged by the IDS are actually malicious, eliminating false positives. A device operating a suspected Evil Twin that also connects to our honeypot = **confirmed attacker** (legitimate infrastructure never seeks open WiFi).

See [DESIGN.md](DESIGN.md) for the academic rationale.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    CORRELATION FLOW                                 │
│                                                                    │
│  wlan1mon (passive scan)        wlan2 (honeypot AP)                │
│  ┌──────────────────┐          ┌─────────────────────┐            │
│  │ Detect rogue AP  │──mark───►│ FreeWiFi (open)     │            │
│  │ MAC: XX:XX       │          │ eduroam_guest (open) │            │
│  │                  │          │ HP-Print-Setup       │            │
│  │ Detect deauth    │──mark───►│ DIRECT-wifi          │            │
│  │ MAC: YY:YY       │          │                     │            │
│  └──────────────────┘          └──────────┬──────────┘            │
│                                           │                        │
│                                   XX:XX connects!                  │
│                                           │                        │
│                                           ▼                        │
│                    ┌──────────────────────────────────┐            │
│                    │     CORRELATION ENGINE            │            │
│                    │  XX:XX was rogue AP suspect       │            │
│                    │  XX:XX connected to honeypot      │            │
│                    │  → CONFIRMED ATTACKER (+25 score) │            │
│                    └──────────────────────────────────┘            │
└────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Deploy the honeypot network (requires 2nd WiFi adapter in AP mode)
sudo bash honeypot/setup.sh

# 2. Start WIDPS backend (correlator auto-reads honeypot connections)
sudo ./widps-backend/target/release/widps

# 3. Stop honeypot
sudo bash honeypot/stop.sh
```

---

## What Gets Deployed

### 4 Fake SSIDs (Multi-BSS via hostapd)

| SSID | Subnet | Target Profile |
|------|--------|----------------|
| `FreeWiFi` | 192.168.66.0/24 | Opportunistic attackers seeking open networks |
| `eduroam_guest` | 192.168.67.0/24 | Credential-stealing attackers targeting academia |
| `HP-Print-Setup` | 192.168.68.0/24 | IoT exploiters looking for vulnerable devices |
| `DIRECT-wifi` | 192.168.69.0/24 | Automated scanners probing P2P networks |

All subnets are **completely isolated** — no internet, no production LAN access.

### Intelligence Gathering Layers

| Layer | What's Captured | File |
|-------|----------------|------|
| DNS | All queries (C2 domain detection) | `/var/log/widps_honeypot_dns.log` |
| DHCP | MAC, hostname, OS fingerprint | `/tmp/widps_honeypot_leases` |
| HTTP | Paths, user-agents, tool signatures | `/tmp/widps_honeypot_http.log` |
| Credentials | Form submissions to captive portal | `/tmp/widps_honeypot_http.log` |
| Connection | STA events (join/leave timestamps) | `/tmp/widps_honeypot_hostapd.log` |
| Forensics | Per-attacker reports | `data/honeypot_forensics/` |

---

## Files

| File | Purpose |
|------|---------|
| `hostapd.conf` | Multi-SSID AP config (4 virtual BSSes on wlan2) |
| `dnsmasq.conf` | DHCP + DNS intelligence (all queries logged, no real resolution) |
| `captive_portal.py` | HTTP server mimicking WiFi login pages (credential capture) |
| `setup.sh` | Full deployment (interfaces, firewall, hostapd, dnsmasq, portal) |
| `stop.sh` | Clean teardown (kill processes, flush IPs, remove firewall rules) |
| `DESIGN.md` | Academic rationale and positioning |
| `README.md` | This file |

---

## Captive Portal (`captive_portal.py`)

A lightweight Python HTTP server that mimics real WiFi login pages:

- **FreeWiFi** → generic email/password form (looks like airport WiFi)
- **eduroam_guest** → institutional login page (user@university.edu)
- **Success page** → shows "Connected!" to keep attacker engaged

### What It Detects

| Detection | Trigger | Evidence |
|-----------|---------|----------|
| Scanner tools | User-Agent contains nmap/nikto/burp/etc. | Logged with tool name |
| Path enumeration | Requests to /.env, /wp-admin, /.git, /api | Logged as suspicious |
| Credential theft | Password submitted to login form | HIGH confidence malicious |
| Captive portal checks | OS connectivity check requests | Identifies device OS |
| Automated crawling | robots.txt, sitemap requests | Bot classification |

### Running Standalone

```bash
sudo python3 honeypot/captive_portal.py
```

Serves on ports 80 (all subnets) and 8080 (testing without root).

---

## Confirmation Types & Scoring

| Confirmation | Trigger | Threat Score Impact |
|-------------|---------|---------------------|
| Rogue AP Operator | MAC flagged by IDS + connected to honeypot | +25 (× 2.5 multiplier) |
| Deauth Attacker | MAC sent deauths + connected to honeypot | +25 |
| Active Recon | Connected to dynamically-created SSID | +15 |
| Network Mapper | Connected to multiple honeypot SSIDs | +20 |
| Credential Theft | Submitted credentials to portal | +30 |

The threat scorer (`threat_scorer.rs`) applies a 2.5× weight multiplier to honeypot evidence — the highest of any source — because connecting to a honeypot is definitive proof of malicious intent.

---

## Dynamic SSID Deployment

The Rust backend's `honeypot.rs` module can **dynamically create new SSIDs** based on probe requests:

1. Monitor mode captures probe requests for SSIDs that don't exist
2. When 3+ distinct devices probe for the same ghost SSID → deploy it as a trap
3. If a device connects to a SSID that didn't exist until we created it → confirmed recon

This is handled programmatically and shown in the dashboard's Honeypot page.

---

## Hardware Requirements

| Option | Adapter | Multi-BSS | Price |
|--------|---------|-----------|-------|
| Budget | Ralink RT5370 | No (1 SSID only) | ~$8 |
| Recommended | MediaTek MT7612U | Yes (4+ SSIDs) | ~$25 |
| Best | Alfa AWUS036ACH | Yes (4+ SSIDs, 5GHz) | ~$60 |

The honeypot adapter must be **separate** from the monitor-mode adapter (wlan1mon).

---

## Firewall Isolation

The setup script creates a dedicated iptables chain `WIDPS_HONEYPOT`:

```
WIDPS_HONEYPOT chain:
  192.168.66.0/22 → 192.168.0.0/16  DROP   (block LAN)
  192.168.66.0/22 → 10.0.0.0/8      DROP   (block campus)
  192.168.66.0/22 → eth0             DROP   (block internet)
  192.168.66.0/22 → wlan1mon         DROP   (block monitor)
  192.168.66.0/22 → *                LOG    (log everything else)

INPUT chain additions:
  wlan2 UDP:67  ACCEPT  (DHCP)
  wlan2 UDP:53  ACCEPT  (DNS)
  wlan2 TCP:80  ACCEPT  (Captive portal)
  wlan2 TCP:8080 ACCEPT (Backup portal port)
```

---

## What It Does NOT Do

- ❌ Does not entrap innocent users (devices connect voluntarily to open networks)
- ❌ Does not intercept real traffic (subnets are fully isolated)
- ❌ Does not provide internet access (all DNS resolves to honeypot IP)
- ❌ Does not inject packets (purely passive on the confirmation side)
- ❌ Does not store real passwords (only logs that a submission occurred + length)

---

## Integration with WIDPS Backend

The Rust module `honeypot.rs` runs a background thread that:
1. Monitors hostapd control interface for STA-CONNECTED events
2. Parses DHCP leases for MAC→IP mapping
3. Cross-references connecting MACs against the threat scorer's suspect list
4. If match found → fires alert + adds +25 evidence to threat profile
5. Generates per-attacker forensic report in `data/honeypot_forensics/`

### API Endpoint

```
GET /api/honeypot/status
```

Returns:
```json
{
  "stats": { "total_connections": 3, "confirmed_threats": 1, "ssids_active": 4 },
  "connections": [
    { "mac": "99:88:77:66:55:44", "ip": "192.168.66.12", "ssid": "FreeWiFi", "timestamp": "..." }
  ],
  "pending_dynamic_ssids": ["MyHomeWiFi", "NETGEAR-5G"]
}
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Interface not found" | Check `ip link show wlan2` or set `WIDPS_HONEYPOT_IFACE=wlanX` |
| "AP mode not supported" | Need different adapter (must support `nl80211` AP mode) |
| hostapd fails | Check `/tmp/widps_honeypot_hostapd.log` for driver errors |
| No DHCP leases | Verify dnsmasq is running: `ps aux | grep dnsmasq` |
| Captive portal unreachable | Check IPs: `ip addr show wlan2` should show 192.168.66.1 |
| Firewall issues | Review: `iptables -L WIDPS_HONEYPOT -v` |
