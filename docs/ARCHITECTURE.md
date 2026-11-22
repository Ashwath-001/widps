# WIDPS — Microservices Architecture

## Design Philosophy: Modular Monolith

WIDPS uses a **modular monolith** pattern — microservice-style boundaries
(single responsibility, clear interfaces, independent testability) deployed
as a single binary for edge performance. This is the industry-standard
approach for embedded/IoT security systems where:

- Inter-process communication latency is unacceptable (frame processing at 5000+ fps)
- Resource constraints prohibit container orchestration (8GB Pi 5)
- All services share the same data plane (captured frames)

Each "service" is a Rust module with strict interface boundaries.
They communicate via typed shared-memory channels (Arc<Mutex<T>>),
not HTTP/gRPC, eliminating serialization overhead.

---

## Project Structure

```
widps/
│
├── widps-backend/                 # Rust binary — all services compiled together
│   ├── Cargo.toml
│   ├── config/
│   │   ├── whitelist.toml         # Trusted AP definitions
│   │   └── oui.csv               # MAC vendor database
│   ├── data/                      # Runtime data (gitignored)
│   │   ├── widps.db              # SQLite (WAL mode)
│   │   ├── logs/                 # Structured JSON logs (daily rotation)
│   │   └── honeypot_forensics/   # Per-attacker forensic reports
│   └── src/
│       ├── main.rs               # Orchestrator: wires services, capture thread, processing thread
│       ├── capture/              # Capture
│       │   ├── mod.rs            # pcap source (BPF "type mgt"), bounded frame queue, adapter reopen
│       │   ├── radiotap.rs       # Radiotap header parsing (RSSI, rate)
│       │   ├── frame.rs          # 802.11 frame control (type/subtype), MACs, seq, reason code
│       │   ├── ie_parser.rs      # Information elements (RSN, WPA)
│       │   ├── channel_hopper.rs # Cycles channels 1-11
│       │   ├── packet_stats.rs   # Per-type frame counters
│       │   └── replay.rs         # Offline pcap helpers (not wired yet)
│       ├── detect/               # Detection
│       │   ├── detectors/        # deauth_flood, rogue_ap, karma, sequence_anomaly, probe_flood, beacon_flood, auth_flood
│       │   ├── threat_scorer.rs  # Composite scoring (CVSS, correlation, decay)
│       │   ├── fingerprint.rs    # Device capability hashing
│       │   ├── client_tracker.rs # Per-client state
│       │   ├── behavioral_profiler.rs # Long-term per-device patterns
│       │   ├── threat_intel.rs   # MAC reputation, blacklist/whitelist, STIX export
│       │   ├── passive_block.rs  # Alert when a blacklisted MAC transmits
│       │   ├── honeypot.rs       # Honeypot connection correlation
│       │   ├── whitelist.rs      # Trusted SSID/BSSID list
│       │   └── oui.rs            # MAC vendor lookup
│       ├── ml/bridge.rs          # Supervised Python inference process (stdin/stdout JSON)
│       ├── store/                # Storage
│       │   ├── db.rs             # SQLite schema, queries, migrations
│       │   ├── audit.rs          # HMAC key + hash-chain helpers
│       │   ├── alert.rs          # Alert creation (DB + JSONL + SSE)
│       │   ├── snapshot.rs       # Periodic atomic AP snapshot
│       │   └── logger.rs         # Structured JSON logging
│       ├── api/                  # HTTP API
│       │   ├── web.rs            # axum server: sessions, CSRF, roles, /api/v1, SSE
│       │   ├── legacy.rs         # Pre-v1 /api route handlers
│       │   ├── auth.rs           # Users, Argon2id, sessions, login throttling
│       │   ├── sse.rs            # Event broadcaster
│       │   ├── report_generator.rs # HTML incident report
│       │   └── siem_forwarder.rs # Syslog/CEF/JSON forwarding
│       └── app/                  # Setup
│           ├── config.rs         # Runtime settings (partial updates)
│           ├── dotenv.rs         # .env loader
│           └── admin_cli.rs      # `widps admin ...` user management
│
├── widps-dashboard/               # React SPA — API Gateway client
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/           # Reusable: Card, Select, Badge, StatusBadge
│   │   │   └── layout/           # Shell: Sidebar, TopBar, AlertCenter, LiveFeed
│   │   ├── hooks/                # Data layer: SSE, polling, routing, toast
│   │   ├── pages/                # 15 route pages (one per feature)
│   │   ├── types/                # TypeScript DTOs (mirrors Rust serde structs)
│   │   └── data/                 # Mock data for offline dev
│   └── vite.config.ts            # Dev proxy → localhost:8787
│
├── ml/                            # ML Service — Python
│   ├── legacy/feature_extraction.py # NLP tokenization + TF-IDF
│   ├── legacy/train_model.py     # Random Forest training
│   ├── inference.py              # Live inference + SHAP + Isolation Forest
│   ├── isolation_forest.py       # Zero-day anomaly detector (unsupervised)
│   ├── online_trainer.py         # Incremental retraining from admin feedback
│   ├── shap_explainer.py         # SHAP TreeExplainer wrapper
│   ├── requirements.txt
│   ├── README.md                 # Full training pipeline documentation
│   └── output/                   # Trained artifacts (model, vectorizer, encoder)
│
├── honeypot/                      # Honeypot Service — config + scripts
│   ├── hostapd.conf              # Multi-SSID AP config
│   ├── dnsmasq.conf              # DHCP + DNS intelligence
│   ├── captive_portal.py         # HTTP credential trap
│   ├── setup.sh                  # Deploy honeypot network
│   ├── stop.sh                   # Tear down
│   ├── DESIGN.md                 # Architectural rationale
│   └── README.md
│
├── siem/                          # SIEM Service — Docker + rules
│   ├── docker-compose.yml        # Wazuh (manager + indexer + dashboard)
│   ├── rules/
│   │   ├── widps_decoder.xml     # JSON alert parser
│   │   └── widps_rules.xml       # 13 custom detection rules
│   └── README.md
│
├── deploy/                        # Deployment & Operations
│   ├── nginx.conf                # Reverse proxy (hides backend)
│   ├── setup-proxy.sh            # One-command proxy deploy
│   └── harden.sh                 # Pi security hardening
│
├── architecture/                  # System diagrams (SVG, patent-format)
│   └── *.svg
│
├── dataset/                       # AWID3 training data (CSV)
│
├── widps-docs/                    # Project documentation
│
├── docs/ARCHITECTURE.md          # This file
└── README.md                     # Project overview
```

---

## Service Communication Matrix

| From → To | Mechanism | Data Format |
|-----------|-----------|-------------|
| Capture → Detection | Direct function call (same thread) | `ParsedFrame` struct |
| Capture → ML | Subprocess stdin pipe | JSON line per frame |
| Detection → API Gateway | Shared Arc<Mutex<T>> | Rust structs |
| Detection → Honeypot | Shared Arc<Mutex<T>> | MAC + reason strings |
| Detection → Alert | Static global (Mutex) | Severity + title + detail |
| Alert → SSE | Shared broadcaster | JSON event |
| Alert → DB | Shared Arc<Mutex<DB>> | Parameterized SQL |
| Alert → SIEM | Channel subscription | Syslog/CEF/JSON |
| ML → Detection | Subprocess stdout pipe | JSON prediction |
| Honeypot → Detection | Shared Arc<Mutex<T>> | Correlation result |
| API Gateway → Dashboard | HTTP/SSE over nginx | JSON/HTML |

---

## Deployment Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    Raspberry Pi 5                             │
│                                                              │
│  ┌──────────┐    ┌──────────────────────────────────────┐   │
│  │  nginx   │────│          widps (Rust binary)          │   │
│  │  :80     │    │  ┌────────┐ ┌─────────┐ ┌────────┐  │   │
│  └────┬─────┘    │  │Capture │→│Detection│→│  API   │  │   │
│       │          │  └────────┘ └────┬────┘ └────────┘  │   │
│       │          │       ┌──────────┼──────────┐        │   │
│       │          │  ┌────▼───┐ ┌────▼───┐ ┌───▼────┐   │   │
│  ┌────▼─────┐    │  │Honeypot│ │  SIEM  │ │   ML   │   │   │
│  │Dashboard │    │  │Service │ │Forward │ │Service │   │   │
│  │(static)  │    │  └────────┘ └────────┘ └────────┘   │   │
│  └──────────┘    └──────────────────────────────────────┘   │
│                                                              │
│  ┌──────────┐    ┌──────────┐                               │
│  │ wlan1mon │    │  wlan2   │                               │
│  │(monitor) │    │(honeypot)│                               │
│  └──────────┘    └──────────┘                               │
└─────────────────────────────────────────────────────────────┘
         │                              │
     passive RF                    deception AP
      capture                    (4 fake SSIDs)
```

---

## API Endpoints (Gateway Service)

| Method | Path | Service Owner | Returns |
|--------|------|--------------|---------|
| GET | `/api/networks` | Detection | Scanned AP list |
| GET | `/api/alerts` | Gateway (DB) | Alert history |
| GET | `/api/status` | Capture + Detection | System telemetry |
| GET | `/api/traffic` | Capture | Frame rate time series |
| GET | `/api/clients` | Detection | Client tracking state |
| GET | `/api/threats` | Detection | Composite threat profiles |
| GET | `/api/ai/predict` | ML | Latest prediction |
| GET | `/api/ai/shap` | ML (DB) | SHAP explanations |
| GET | `/api/honeypot/status` | Honeypot | Connections + correlations |
| GET | `/api/events` | Gateway (SSE) | Event buffer (polling) |
| GET | `/api/stream` | Gateway (SSE) | Persistent event stream |
| GET | `/api/report` | Gateway | HTML incident report |
| GET | `/api/logs` | Gateway (files) | Structured log query |
| GET | `/api/logs/services` | Gateway (files) | Service name list |
| GET | `/api/audit/integrity` | Gateway (DB) | HMAC verification |
| GET | `/api/siem/status` | SIEM | Forwarding config |
| GET | `/api/config` | Shared | Runtime flags |
| POST | `/api/config` | Shared | Update runtime flags |
| POST | `/api/alerts/:id/ack` | Gateway (DB) | Acknowledge alert |
| POST | `/api/alerts/:id/confirm` | ML (DB) | Confirm attack for retraining |
| GET | `/api/online-learning/status` | ML (DB) | Pending samples + retrain status |
| GET | `/api/profiles` | Detection | Behavioral profiler device summaries |

---

## Frontend Page → Service Mapping

| Page | Primary Service | Endpoints Used |
|------|----------------|----------------|
| Dashboard | Capture + Detection | `/api/status`, `/api/networks` |
| Network | Detection | `/api/networks`, `/api/alerts` |
| Traffic | Capture | `/api/traffic` |
| AI Detection | ML | `/api/ai/predict`, `/api/threats` |
| Explainability | ML | `/api/ai/shap` |
| Threat Scores | Detection | `/api/threats` |
| Threat Map | Detection | `/api/alerts` |
| Honeypot | Honeypot | `/api/honeypot/status` |
| Event Log | Gateway | `/api/alerts` |
| Statistics | Detection | `/api/alerts`, `/api/networks` |
| Topology | Detection | `/api/networks`, `/api/clients` |
| System Logs | Gateway | `/api/logs`, `/api/logs/services` |
| Security | Gateway | `/api/audit/integrity`, `/api/siem/status` |
| Reports | Gateway | `/api/report` |
| Settings | Shared | `/api/config` |

