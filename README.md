# WIDPS — Wireless Intrusion Detection & Prevention System

> Real-time 802.11 wireless threat detection on Raspberry Pi 5 with a 16-page animated React dashboard, 3-tier AI/ML detection, SIEM integration, and honeypot deception.

---

## Project Overview

WIDPS captures raw IEEE 802.11 frames in monitor mode, runs deterministic threat detection heuristics combined with ML classification and composite scoring, and presents findings through a modern 16-page React/TypeScript dashboard with real-time SSE streaming.

**Domain:** Wireless Network Security, Intrusion Detection, 802.11 Anomaly Analysis  
**Platform:** Raspberry Pi 5 (8GB) with external WiFi adapter in monitor mode  
**Architecture:** Modular monolith (Rust) + React SPA + Python ML pipeline

---

## Architecture

```
┌──────────────┐     pcap      ┌──────────────────┐     HTTP/SSE     ┌──────────────────┐
│  wlan1mon    │──────────────►│  Rust Backend     │◄────────────────►│  React Dashboard │
│  (Monitor)   │  raw frames   │  (22 modules)     │   port 8787      │  (16 pages)      │
└──────────────┘               └──────────────────┘                   └──────────────────┘
                                        │                                       ▲
                                        │ stdin/stdout JSON                     │
                                        ▼                                       │
                               ┌──────────────────┐                   ┌─────────────────┐
                               │  Python ML Engine │                   │  Nginx Reverse   │
                               │  (RF + ONNX +     │                   │  Proxy (port 80) │
                               │   SHAP + IF)      │                   └─────────────────┘
                               └──────────────────┘
                                        │
                                        ▼
                               ┌──────────────────┐
                               │  Wazuh SIEM       │
                               │  (Syslog/CEF/JSON)│
                               └──────────────────┘
```

See [`architecture/`](architecture/) for detailed SVG diagrams of each subsystem.

---

## Dashboard Pages (16)

| # | Page | Route | Description |
|---|------|-------|-------------|
| 1 | Overview | `#overview` | System health, live KPIs, threat summary cards |
| 2 | Live Network | `#network` | Scanned APs table with RSSI sparklines, search, CSV export |
| 3 | Live Traffic | `#traffic` | Real-time frame type breakdown (area chart) |
| 4 | AI Detection | `#ai` | ML predictions, confusion matrix, threat profiles |
| 5 | SHAP Explainability | `#shap` | Feature importance waterfall charts per prediction |
| 6 | Threat Scoring | `#scoring` | Per-BSSID composite scores with evidence timeline |
| 7 | Threat Map | `#threats` | Active attacks with severity + mitigation status |
| 8 | Threat Intelligence | `#intel` | MAC blacklist/whitelist, SSID similarity detection |
| 9 | Honeypot | `#honeypot` | Deception AP status, attacker connections, forensics |
| 10 | Event Log | `#log` | Filterable alert history with acknowledge/confirm |
| 11 | Statistics | `#stats` | Attack distribution, channel utilization, signal histogram |
| 12 | Device Topology | `#topology` | Force-directed graph of AP↔client relationships |
| 13 | System Logs | `#logs` | Structured JSON log viewer (ECS format) |
| 14 | Security Audit | `#audit` | HMAC integrity verification of alert records |
| 15 | Reports | `#reports` | Server-generated HTML incident reports |
| 16 | Settings | `#settings` | Runtime config (hopping, retention, blocking, notifications) |

---

## Backend Modules (22)

| Module | File | Purpose |
|--------|------|---------|
| Orchestrator | `main.rs` | Spawns all threads, wires services, main capture loop |
| Capture | `capture.rs` | Opens pcap on monitor interface |
| Channel Hopper | `channel_hopper.rs` | Cycles channels 1–11 every 300ms |
| Frame Parser | `frame.rs` | 802.11 FC parsing → type, MACs, seq, SSID |
| Radiotap Parser | `radiotap.rs` | Radiotap header → RSSI (dBm), rate |
| IE Parser | `ie_parser.rs` | RSN/WPA cipher + AKM extraction |
| OUI Lookup | `oui.rs` | MAC → vendor resolution |
| Whitelist | `whitelist.rs` | TOML-based trusted SSID→BSSID mapping |
| Client Tracker | `client_tracker.rs` | Per-MAC behavioral state |
| Behavioral Profiler | `behavioral_profiler.rs` | Long-term per-device pattern analysis |
| Threat Scorer | `threat_scorer.rs` | CVSS-style composite scoring with time-decay |
| Fingerprint | `fingerprint.rs` | Device capability hashing (Evil Twin detection) |
| Alert System | `alert.rs` | HMAC-signed alerts to DB + SSE + JSONL |
| API Server | `api_server.rs` | 20 REST endpoints + SSE streaming |
| SSE Broadcaster | `sse.rs` | Pub/sub with 200-event catch-up buffer |
| Database | `db.rs` | SQLite WAL with 5 tables + migrations |
| ML Bridge | `ml_bridge.rs` | Python subprocess IPC (stdin/stdout JSON) |
| Honeypot | `honeypot.rs` | Dynamic deception AP + correlation engine |
| Report Generator | `report_generator.rs` | Server-side HTML incident reports |
| SIEM Forwarder | `siem_forwarder.rs` | Syslog/CEF/JSON forwarding to Wazuh |
| Threat Intelligence | `threat_intel.rs` | MAC reputation, SSID similarity, blacklists |
| Logger | `logger.rs` | Structured JSON logging (ECS, daily rotation) |
| Config | `config.rs` | Runtime atomic flags (live-updatable) |

---

## Detection Engines

### Layer 1: Rule-Based Heuristics (7 Detectors)

| Detector | Trigger | Severity |
|----------|---------|----------|
| Deauth Flood | 10+ deauth/disassoc from one BSSID / 5s | Critical |
| Rogue AP | Same SSID, different BSSID or cipher mismatch | High/Critical |
| Karma/MANA | AP responds to 5+ unknown SSIDs | Medium/High |
| Sequence Anomaly | 3+ backward/large seq jumps in 5s | High |
| Probe Flood | 30+ probes from one MAC / 5s | Medium |
| Beacon Flood | 50+ beacons/s from randomized BSSIDs | High |
| Auth Flood | 20+ auth frames / 5s from random MACs | High |

### Layer 2: ML Classification (Random Forest + Isolation Forest)

- **Model:** Random Forest (30 trees, depth 10) → ONNX export
- **Features:** 20 statistical + 100 TF-IDF n-gram tokens = 120 dimensions
- **Classes:** Normal, Deauth_Flood, Auth_Flood, Evil_Twin, Krack, Kr00k
- **Accuracy:** 99.55% on test set (confusion matrix available via `/api/ai/accuracy`)
- **Inference:** ~0.001ms per window (ONNX), 1-second sliding windows
- **Zero-Day:** Isolation Forest unsupervised anomaly detection
- **Explainability:** SHAP TreeExplainer for feature attribution

### Layer 3: Composite Threat Scoring

- Per-BSSID evidence accumulation with source-weighted multipliers
- Time-decay (0.5 pts/sec) prevents stale scores
- Correlation bonus (1.5×) when 2+ sources hit same device in 10s
- CVSS-style severity mapping (0–100 → None/Low/Medium/High/Critical)
- Alert thresholds: 60 = High alert, 85 = Critical alert

---

## ML Pipeline (`ml/`)

| Script | Purpose |
|--------|---------|
| `feature_extraction.py` | NLP tokenization + TF-IDF vectorization of frame sequences |
| `train_model.py` | Random Forest training, cross-validation, export |
| `inference.py` | Live inference + SHAP + Isolation Forest + evaluation |
| `isolation_forest.py` | Zero-day anomaly detector (unsupervised) |
| `online_trainer.py` | Incremental retraining from admin-confirmed samples |
| `shap_explainer.py` | SHAP TreeExplainer wrapper |

### inference.py Modes

```bash
python ml/inference.py --stdin          # Pipe mode (Rust backend integration)
python ml/inference.py --simulate       # Replay test set
python ml/inference.py --live           # Watch alert/network files
python ml/inference.py --evaluate-json  # Output confusion matrix as JSON
python ml/inference.py --export-onnx    # Convert to ONNX format
python ml/inference.py --benchmark      # Throughput benchmark
```

---

## SIEM Integration (Wazuh)

- Custom decoder: `siem/rules/widps_decoder.xml`
- Custom rules: `siem/rules/widps_rules.xml` (rule IDs 100001–100010)
- Transport: UDP/TCP syslog or JSON-over-TCP to port 1514
- Dashboard: Wazuh OpenSearch Dashboards on port 5601

Enable: `WIDPS_SIEM_ENABLED=1 WIDPS_SIEM_HOST=127.0.0.1 WIDPS_SIEM_PORT=1514`

---

## Honeypot Deception

- Dynamic SSID creation based on attacker probe requests
- Captive portal for credential capture (`honeypot/captive_portal.py`)
- Automatic threat score escalation (+25 per honeypot engagement)
- Forensic logging of all DNS queries and HTTP requests
- Configuration: `honeypot/hostapd.conf`, `honeypot/dnsmasq.conf`

---

## Quick Start

### Prerequisites

```bash
# Raspberry Pi 5 (Debian Bookworm)
sudo apt install build-essential libpcap-dev aircrack-ng python3-venv
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Enable monitor mode
sudo airmon-ng start wlan1
sudo ip link set wlan1mon up
```

### Build & Run (Development)

```bash
# Backend
cd widps-backend
cargo build --release
sudo ../target/release/widps

# ML (separate terminal)
cd ml
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python train_model.py    # Train model first
.venv/bin/python inference.py --stdin  # (auto-started by backend)

# Dashboard (separate terminal)
cd widps-dashboard
npm install
npm run dev     # http://localhost:5173
```

### Docker Deployment (Production)

```bash
# Build frontend
cd widps-dashboard && npm run build && cd ..

# Full stack
docker compose up -d

# With SIEM (Wazuh)
docker compose --profile siem up -d

# Dashboard: http://localhost
# Wazuh:     http://localhost:5601
```

### Demo / Presentation Mode

```bash
# Generate realistic alerts without hardware
python demo/simulate_attack.py --demo-presentation

# Simulate specific attack (pipe to ML)
python demo/simulate_attack.py --attack all --duration 60 --pipe-to-ml
```

---

## API Endpoints (20)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/networks` | GET | All scanned APs with RSSI history |
| `/api/alerts` | GET | Alert history (latest 200) |
| `/api/status` | GET | System telemetry (CPU, mem, temp, PPS) |
| `/api/traffic` | GET | Frame type traffic history |
| `/api/clients` | GET | Tracked client devices |
| `/api/ai/predict` | GET | Current ML prediction |
| `/api/ai/shap` | GET | Recent SHAP explanations |
| `/api/ai/history` | GET | ML prediction history |
| `/api/ai/accuracy` | GET | Confusion matrix (6×6) + accuracy |
| `/api/threats` | GET | Active threat profiles with scores |
| `/api/events` | GET | SSE event polling (with last_id) |
| `/api/stream` | GET | SSE persistent connection |
| `/api/profiles` | GET | Behavioral profiler summaries |
| `/api/honeypot/status` | GET | Honeypot stats + connections |
| `/api/siem/status` | GET | SIEM forwarder configuration |
| `/api/audit/integrity` | GET | HMAC verification results |
| `/api/report` | GET | Generated HTML incident report |
| `/api/logs` | GET | Structured log query |
| `/api/config` | POST | Update runtime configuration |
| `/api/whitelist` | POST | Add trusted AP |

---

## Configuration

| File | Purpose |
|------|---------|
| `config/whitelist.toml` | Trusted SSID→BSSID mappings |
| `config/oui.csv` | MAC vendor prefix database |
| `deploy/nginx.conf` | Production reverse proxy |
| `deploy/harden.sh` | OS-level hardening script |
| `honeypot/hostapd.conf` | Honeypot AP configuration |
| `honeypot/dnsmasq.conf` | Honeypot DHCP/DNS |

---

## Project Structure

```
widps/
├── widps-backend/           # Rust detection engine (22 modules)
├── widps-dashboard/         # React/TypeScript SPA (16 pages)
├── ml/                      # Python ML pipeline (6 scripts)
├── siem/                    # Wazuh integration (docker-compose + rules)
├── honeypot/                # Deception AP config + scripts
├── deploy/                  # nginx.conf, harden.sh, setup-proxy.sh
├── demo/                    # simulate_attack.py
├── architecture/            # SVG architecture diagrams
├── dataset/                 # AWID3 training data (CSV)
├── docker-compose.yml       # Full-stack deployment
└── README.md                # This file
```

---

## Security Features

- HMAC-SHA256 signed alerts (tamper detection via `/api/audit/integrity`)
- Rate limiting (Nginx: 30r/s general, 5r/s write endpoints)
- CSP, X-Frame-Options, HSTS security headers
- Parameterized SQL queries (no injection vectors)
- Input validation on all POST endpoints (10KB body limit)
- Structured logging in ECS format with daily rotation
- Runtime config via atomic flags (no restart required)
- Privilege separation: capture thread → worker threads → API thread

---

## Dataset

Training uses the AWID3 dataset (Attacks in WiFi Dataset, 3rd generation):
- 6 classes: Normal, Deauth_Flood, Auth_Flood, Evil_Twin, Krack, Kr00k
- NLP-inspired frame tokenization (type/subtype/flags → n-grams)
- 80/20 train/test split with stratification
- Located in `dataset/archive/CSV/`

---

## References

- Base papers in `Base-paper/`
- AWID3 Dataset: Kolias et al., "Empirical Evaluation of Attacks Against IEEE 802.11 Enterprise Networks"
- Detection methodology: Machine Learning Based Intrusion Detection for Wireless Sensor Networks

---

## License

Academic project — Batch 160 Final Year Project.
