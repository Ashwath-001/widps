# WIDPS SIEM Integration — Wazuh

## Overview

Integrates WIDPS alerts into Wazuh (open-source SIEM) for centralized security monitoring, correlation with other data sources, compliance reporting, and long-term alert archival.

---

## Architecture

```
┌─────────────────┐  UDP/TCP:1514    ┌────────────────────┐
│  WIDPS Backend  │─────────────────►│  Wazuh Manager     │
│  (siem_forwarder│  JSON/Syslog/CEF │  (rule matching)   │
│   .rs module)   │                  │  (alert generation)│
└─────────────────┘                  └─────────┬──────────┘
                                               │
                                               ▼
                                     ┌────────────────────┐
                                     │  Wazuh Indexer      │
                                     │  (OpenSearch)       │
                                     │  :9200              │
                                     └─────────┬──────────┘
                                               │
                                               ▼
                                     ┌────────────────────┐
                                     │  Wazuh Dashboard    │
                                     │  (Kibana-based)     │
                                     │  :5601              │
                                     └────────────────────┘
```

---

## Quick Start

```bash
# Start Wazuh stack
cd siem/
docker compose up -d

# Wait ~2 minutes for services to initialize
# Check status:
docker compose ps

# Access dashboard:
#   URL:  http://localhost:5601
#   User: admin
#   Pass: SecretPassword
```

---

## Enable WIDPS → Wazuh Forwarding

Set environment variables before starting the Rust backend:

```bash
export WIDPS_SIEM_ENABLED=1
export WIDPS_SIEM_HOST=127.0.0.1
export WIDPS_SIEM_PORT=1514
export WIDPS_SIEM_FORMAT=json       # Options: json, syslog, cef
export WIDPS_SIEM_TCP=0             # 0=UDP (default), 1=TCP

sudo ./widps-backend/target/release/widps
```

Or all on one line:
```bash
WIDPS_SIEM_ENABLED=1 WIDPS_SIEM_HOST=127.0.0.1 WIDPS_SIEM_PORT=1514 sudo ./target/release/widps
```

---

## Alert Format (JSON)

When `WIDPS_SIEM_FORMAT=json`, alerts are sent as:

```json
{
  "timestamp": "2025-07-15T14:23:45+05:30",
  "source": "WIDPS",
  "severity": "Critical",
  "title": "Deauthentication Flood Detected",
  "detail": "47 deauth/disassoc frames from BSSID 99:88:77:66:55:44 within 5s",
  "category": "wireless_intrusion",
  "sensor_type": "802.11_monitor",
  "sensor_id": "widps-pi5-01",
  "bssid": "99:88:77:66:55:44",
  "threat_score": 85
}
```

---

## Custom Decoder (`rules/widps_decoder.xml`)

Parses incoming WIDPS JSON alerts:

```xml
<decoder name="widps-json">
  <prematch>"source":"WIDPS"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="widps-alert">
  <parent>widps-json</parent>
  <regex>"severity":"(\S+)","title":"(\.+)","detail":"(\.+)"</regex>
  <order>severity, title, detail</order>
</decoder>
```

Wazuh's JSON decoder automatically extracts all fields from the alert payload.

---

## Custom Rules (`rules/widps_rules.xml`)

Rule IDs 100100–100199 are reserved for WIDPS:

| Rule ID | Level | Match | Description |
|---------|-------|-------|-------------|
| 100100 | 3 | Any WIDPS alert | Base rule (all alerts) |
| 100101 | 6 | severity=Medium | Reconnaissance, probing |
| 100102 | 10 | severity=High | Active attack detected |
| 100103 | 14 | severity=Critical | Confirmed active threat (triggers email) |
| 100110 | 12 | "Deauth" | Deauthentication flood |
| 100111 | 13 | "Evil Twin\|Rogue AP" | Rogue AP / Evil Twin |
| 100112 | 11 | "Karma" | Karma/MANA attack |
| 100113 | 10 | "Sequence Anomaly\|MAC Spoof" | MAC spoofing |
| 100114 | 8 | "Probe.*Flood\|Reconnaissance" | Network recon |
| 100115 | 14 | "Composite Threat Score" | Multi-factor score threshold |
| 100120 | 10 | "AI classified" | ML classification triggered |
| 100130 | 12 | "Honeypot" | Honeypot connection (confirmed attacker) |

### Wazuh Level Mapping

| WIDPS Severity | Wazuh Level | Action |
|---------------|-------------|--------|
| Low | 3 | Log only |
| Medium | 6 | Dashboard alert |
| High | 10 | Active response eligible |
| Critical | 14 | Email alert + active response |

---

## Transport Formats

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `WIDPS_SIEM_FORMAT=json` | Wazuh (default), ELK, Splunk HEC |
| Syslog (RFC 5424) | `WIDPS_SIEM_FORMAT=syslog` | Traditional SIEM, rsyslog |
| CEF | `WIDPS_SIEM_FORMAT=cef` | ArcSight, QRadar, Splunk |

### CEF Example

```
CEF:0|WIDPS|WirelessIDS|1.0|deauth_flood|Deauthentication Flood Detected|9|src=99:88:77:66:55:44 msg=47 deauth frames in 5s
```

---

## Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Wazuh single-node stack (indexer + manager + dashboard) |
| `rules/widps_decoder.xml` | Custom decoder for WIDPS JSON alerts |
| `rules/widps_rules.xml` | Custom rules mapping WIDPS severities to Wazuh levels |
| `README.md` | This file |

---

## Services (docker-compose)

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `wazuh-indexer` | wazuh/wazuh-indexer:4.9.0 | 9200 | OpenSearch data store |
| `wazuh-manager` | wazuh/wazuh-manager:4.9.0 | 1514/udp, 55000 | Alert processing + rules |
| `wazuh-dashboard` | wazuh/wazuh-dashboard:4.9.0 | 5601 | Web UI (Kibana-based) |

---

## Testing the Integration

### 1. Send a Test Alert

```bash
# Raw JSON via netcat (UDP)
echo '{"timestamp":"2025-01-01T00:00:00+05:30","source":"WIDPS","severity":"Critical","title":"Test Alert","detail":"SIEM integration test","category":"wireless_intrusion","sensor_type":"802.11_monitor"}' | nc -u 127.0.0.1 1514
```

### 2. Verify in Wazuh Dashboard

1. Open http://localhost:5601
2. Login: admin / SecretPassword
3. Go to: Security Events → search for "WIDPS"
4. Should see rule 100103 (Critical) triggered

### 3. Check Manager Logs

```bash
docker exec widps-wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json | grep WIDPS
```

### 4. Check Decoder Works

```bash
docker exec widps-wazuh-manager /var/ossec/bin/wazuh-logtest
# Paste your JSON alert, should show "widps-json" decoder match
```

---

## Configuring Email Alerts

Critical alerts (rule 100103) have `alert_by_email` enabled. Configure Wazuh email:

```bash
docker exec -it widps-wazuh-manager bash
vi /var/ossec/etc/ossec.conf
```

Add under `<global>`:
```xml
<email_notification>yes</email_notification>
<smtp_server>smtp.gmail.com</smtp_server>
<email_from>widps-alerts@gmail.com</email_from>
<email_to>admin@university.edu</email_to>
```

---

## Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 4 GB | 8 GB |
| Disk | 2 GB (containers) | 10 GB (with logs) |
| CPU | 2 cores | 4 cores |
| Network | Port 1514 (UDP) open from WIDPS host | |

---

## Backend Module (`siem_forwarder.rs`)

The Rust backend has a dedicated SIEM module that:
1. Subscribes to the SSE broadcaster (same as dashboard)
2. Filters for alert events
3. Formats per configured format (JSON/Syslog/CEF)
4. Sends via UDP or TCP socket to configured host:port
5. Handles connection failures gracefully (logs and retries)

### API Endpoint

```
GET /api/siem/status
```

Returns:
```json
{
  "enabled": true,
  "target_host": "127.0.0.1",
  "target_port": "1514",
  "format": "json",
  "protocol": "UDP"
}
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Dashboard won't load | Wait 2–3 minutes after `docker compose up`, indexer needs time |
| "No alerts showing" | Verify `WIDPS_SIEM_ENABLED=1` and check `nc -ul 1514` receives data |
| Decoder not matching | Run `wazuh-logtest` inside manager container to debug |
| High memory usage | Reduce indexer JVM: change `-Xms512m -Xmx512m` to `-Xms256m -Xmx256m` |
| Container restart loop | Check: `docker logs widps-wazuh-manager` — likely port conflict |
| Rules not loaded | Verify mount: `docker exec widps-wazuh-manager ls /var/ossec/etc/rules/widps_rules.xml` |

---

## Stopping / Cleanup

```bash
# Stop all containers
cd siem/
docker compose down

# Stop and remove data volumes (DESTRUCTIVE)
docker compose down -v
```
