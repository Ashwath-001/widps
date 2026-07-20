# WIDPS - Wireless Intrusion Detection & Prevention System

> Real-time 802.11 wireless threat detection on Raspberry Pi with a modern React dashboard.

---

## Project Overview

WIDPS captures raw IEEE 802.11 frames in monitor mode, runs deterministic threat detection heuristics (with planned AI/ML classification), and presents findings through an animated React/TypeScript dashboard. Designed as a full-scale final year project targeting campus wireless security.

**Domain:** Wireless Network Security, Intrusion Detection, 802.11 Anomaly Analysis

---

## Architecture

```
┌──────────────┐     pcap      ┌──────────────────┐     HTTP/SSE     ┌──────────────────┐
│  wlan1mon    │──────────────►│  Rust Backend     │◄────────────────►│  React Dashboard │
│  (Monitor)   │  raw frames   │  (Detection Core) │   port 8787      │  (Visualization) │
└──────────────┘               └──────────────────┘                   └──────────────────┘
```

---

## Backend (Rust) - `widps-backend/`

### Modules

| Module | File | Purpose |
|--------|------|---------|
| Entry Point | `main.rs` | Spawns all threads, runs capture loop, feeds detectors |
| Capture | `capture.rs` | Opens pcap on monitor interface with immediate mode |
| Channel Hopper | `channel_hopper.rs` | Cycles channels 1–11 every 300ms via `iw` |
| Frame Parser | `frame.rs` | Parses 802.11 FC byte → type, extracts MACs, SSID, seq number |
| Radiotap Parser | `radiotap.rs` | Walks radiotap fields, extracts RSSI (dBm) |
| IE Parser | `ie_parser.rs` | Extracts RSN/WPA cipher + AKM for Evil Twin detection |
| OUI Lookup | `oui.rs` | CSV-based MAC vendor resolution |
| Whitelist | `whitelist.rs` | TOML-based trusted SSID→BSSID mapping |
| Client Tracker | `client_tracker.rs` | Per-MAC probe history, association, deauth victim count |
| Alert System | `alert.rs` | Fires alerts to stdout + `widps_alerts.jsonl` |
| API Server | `api_server.rs` | HTTP server on port 8787 with CORS |

### Detectors (`src/detectors/`)

| Detector | Trigger Condition | Severity |
|----------|-------------------|----------|
| `deauth_flood.rs` | 10+ deauth/disassoc from one BSSID within 5s | Critical |
| `rogue_ap.rs` | Same SSID, different BSSID or mismatched cipher | High/Critical |
| `karma.rs` | AP responds to unknown SSID or 5+ distinct SSIDs | Medium/High |
| `sequence_anomaly.rs` | Backwards/large seq jumps (3+ in 5s window) | High |
| `probe_flood.rs` | 30+ probe requests from one MAC within 5s | Medium |

### API Endpoints

| Endpoint | Method | Response |
|----------|--------|----------|
| `/api/networks` | GET | JSON array of all scanned APs |
| `/api/alerts` | GET | JSON array of alerts from JSONL file |
| `/api/status` | GET | System telemetry (channel, PPS, CPU, temp) |

### Build & Run

```bash
# Prerequisites
sudo airmon-ng start wlan1
sudo ip link set wlan1mon up

# Build
cd widps-backend
cargo build --release

# Run (from project root so config/ paths resolve)
sudo ./target/release/widps
```

### Configuration

- `config/whitelist.toml` - Known-good APs (edit before deployment)
- `config/oui.csv` - MAC vendor prefixes (replace with full IEEE list for production)

### Simulation Mode

If `wlan1mon` is unavailable, the backend automatically starts a simulated scanner with 6 seed APs and generates timed alerts for development/demo purposes.

---

## Frontend (React/TypeScript) - `widps-dashboard/`

### Tech Stack

- React 19 + TypeScript 6
- Vite 8 (build)
- Tailwind CSS 4 (dark theme via CSS variables)
- Recharts (data visualization)
- Framer Motion (animations)
- Lucide React (icons)

### Pages

| Page | Route Key | Purpose |
|------|-----------|---------|
| Overview | `overview` | Summary dashboard + live scanned networks table |
| Live Network | `network` | Searchable AP table with RSSI bars + detail panel |
| Live Traffic | `traffic` | Channel density & signal distribution charts |
| AI Detection | `ai` | ML engine status (Phase 2 placeholder) |
| Threat Map | `threats` | Threat event cards with triage actions |
| Event Log | `log` | Searchable/sortable alert table + CSV export |
| Statistics | `stats` | Attack distribution pie + channel bar chart |
| Device Topology | `topology` | SVG radial graph of APs |
| Reports | `reports` | Export UI (JSON/CSV/PDF) |
| Settings | `settings` | Monitoring + UI toggles (localStorage) |

### Data Hooks (`src/hooks/useMockLiveData.ts`)

| Hook | Interval | Source |
|------|----------|--------|
| `useScannedNetworks` | 1s | `/api/networks` + MAC extraction from `/api/alerts` |
| `useLiveAlerts` | 1.5s | `/api/alerts` |
| `useSystemStatus` | 2s | `/api/status` |
| `useLiveFeed` | 8s | Mock generator (Phase 2: wire to SSE) |
| `useTrafficHistory` | 2s | Mock generator (Phase 2: wire to `/api/traffic`) |

### Run

```bash
cd widps-dashboard
npm install
npm run dev
```

Dashboard auto-discovers the backend at `http://<hostname>:8787`, falls back to `localhost:8787` and `127.0.0.1:8787`.

---

## Output

- **Console:** Live alerts with timestamps and severity
- **File:** `widps_alerts.jsonl` - structured JSON-lines log
- **File:** `widps_networks.json` - current AP state snapshot
- **Dashboard:** Full visualization at `http://localhost:5173`

---

## Demo (own test AP only)

```bash
# Trigger a deauth flood alert
sudo aireplay-ng --deauth 20 -a <test_AP_BSSID> wlan1mon
```

---

## Project Structure

```
widps/
├── widps-backend/
│   ├── Cargo.toml
│   ├── config/
│   │   ├── oui.csv
│   │   └── whitelist.toml
│   └── src/
│       ├── main.rs
│       ├── alert.rs
│       ├── api_server.rs
│       ├── capture.rs
│       ├── channel_hopper.rs
│       ├── client_tracker.rs
│       ├── frame.rs
│       ├── ie_parser.rs
│       ├── oui.rs
│       ├── radiotap.rs
│       ├── whitelist.rs
│       └── detectors/
│           ├── mod.rs
│           ├── deauth_flood.rs
│           ├── karma.rs
│           ├── probe_flood.rs
│           ├── rogue_ap.rs
│           └── sequence_anomaly.rs
├── widps-dashboard/
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── App.tsx
│       ├── main.tsx
│       ├── index.css
│       ├── types/index.ts
│       ├── data/mockData.ts
│       ├── hooks/useMockLiveData.ts
│       ├── components/
│       │   ├── common/
│       │   └── layout/
│       └── pages/
│           ├── Overview.tsx
│           ├── LiveNetwork.tsx
│           ├── LiveTraffic.tsx
│           ├── AIDetection.tsx
│           ├── ThreatMap.tsx
│           ├── EventLog.tsx
│           ├── Statistics.tsx
│           ├── DeviceTopology.tsx
│           ├── Reports.tsx
│           └── SettingsPage.tsx
└── README.md
```

---

## Dependencies

### Backend (Rust)

```toml
pcap = "1.3"
chrono = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
tiny_http = "0.12.0"
```

### Frontend (Node)

```json
"react": "^19.2.7",
"framer-motion": "^12.42.2",
"lucide-react": "^1.25.0",
"recharts": "^3.9.2",
"tailwindcss": "^4.3.3",
"vite": "^8.1.1",
"typescript": "~6.0.2"
```

---
