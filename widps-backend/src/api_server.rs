use crate::client_tracker::ClientTracker;
use crate::config::ConfigFlags;
use crate::db::Database;
use crate::ml_bridge::SharedPrediction;
use crate::packet_stats::SharedTrafficHistory;
use crate::sse::SharedBroadcaster;
use crate::threat_scorer::ThreatScorer;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};


pub type SharedConfigFlags = Arc<ConfigFlags>;
pub type SharedDatabase = Arc<Mutex<Database>>;

/// Read CPU usage from /proc/stat (Linux-specific)
fn read_cpu_usage() -> u32 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f32>().ok())
        .map(|load| (load * 25.0).min(100.0) as u32) // 4-core Pi: load 4.0 = 100%
        .unwrap_or(0)
}

/// Read memory usage from /proc/meminfo (Linux-specific)
fn read_memory_usage() -> u32 {
    let content = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total: u64 = 0;
    let mut available: u64 = 0;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        } else if line.starts_with("MemAvailable:") {
            available = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    if total == 0 { return 0; }
    ((total - available) * 100 / total) as u32
}

/// Read Pi temperature from thermal zone (Linux-specific)
fn read_pi_temperature() -> u32 {
    std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|millideg| millideg / 1000)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannedAp {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub rssi: i8,
    pub vendor: String,
    pub encryption: String,
    pub beacon_interval_ms: u16,
    pub client_count: u32,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    /// Last 20 RSSI readings for sparkline visualization
    pub rssi_history: Vec<i8>,
}

const RSSI_HISTORY_SIZE: usize = 20;

impl ScannedAp {
    /// Push a new RSSI value into the ring buffer (keeps last 20)
    pub fn push_rssi(&mut self, rssi: i8) {
        self.rssi_history.push(rssi);
        if self.rssi_history.len() > RSSI_HISTORY_SIZE {
            self.rssi_history.remove(0);
        }
    }
}

pub type SharedApStore = Arc<Mutex<HashMap<String, ScannedAp>>>;
pub type SharedClientTracker = Arc<Mutex<ClientTracker>>;
pub type SharedThreatScorer = Arc<Mutex<ThreatScorer>>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatusResponse {
    pub monitoring_active: bool,
    pub interface_name: String,
    pub current_channel: u8,
    pub nearby_ap_count: usize,
    pub connected_station_count: u32,
    pub packets_per_second: u32,
    pub ai_model_status: String,
    pub cpu_usage_pct: u32,
    pub memory_usage_pct: u32,
    pub pi_temperature_c: u32,
    pub detection_engine_status: String,
    pub sse_subscribers: usize,
}

/// Shared state the legacy JSON routes read.
#[derive(Clone)]
pub struct ApiCtx {
    pub ap_store: SharedApStore,
    pub current_channel: Arc<AtomicU8>,
    pub client_tracker: SharedClientTracker,
    pub packets_per_second: Arc<AtomicU32>,
    pub traffic_history: SharedTrafficHistory,
    pub ml_prediction: SharedPrediction,
    pub threat_scorer: SharedThreatScorer,
    pub sse_broadcaster: SharedBroadcaster,
    pub config_flags: SharedConfigFlags,
    pub database: SharedDatabase,
}

pub struct ApiResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl ApiResponse {
    pub fn json(status: u16, body: String) -> Self {
        Self { status, content_type: "application/json", body }
    }
    fn html(body: String) -> Self {
        Self { status: 200, content_type: "text/html; charset=utf-8", body }
    }
}

/// Every pre-existing /api route, unchanged; authentication and CSRF run before this in web.rs.
pub fn handle(ctx: &ApiCtx, method: &str, raw_url: &str, body: &str, actor: &str) -> ApiResponse {
    let ApiCtx {
        ap_store, current_channel, client_tracker, packets_per_second, traffic_history,
        ml_prediction, threat_scorer, sse_broadcaster, config_flags, database,
    } = ctx;
    let url_path = raw_url.split('?').next().unwrap_or(raw_url).trim_end_matches('/');
    let (status, body) = match url_path {
        "/api/alerts" => {
            if method == "POST" {
                // Check if this is a clear request
                let body_str = body.to_string();
                let payload = serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or_default();
                if payload["action"] == "clear" && payload["confirm"] == "CLEAR" {
                    match archive_alerts(database, actor) {
                        Ok((n, file)) => {
                            (200, serde_json::json!({"status": "archived", "archived": n, "archive_file": file}).to_string())
                        }
                        Err(e) => (500, serde_json::json!({"error": "archive failed", "detail": e}).to_string()),
                    }
                } else if payload["action"] == "clear" {
                    (400, "{\"error\":\"confirmation required: send {\\\"action\\\":\\\"clear\\\",\\\"confirm\\\":\\\"CLEAR\\\"}\"}".to_string())
                } else {
                    (400, "{\"error\":\"unknown action\"}".to_string())
                }
            } else {
                let db = database.lock().unwrap();
                let rows = db.get_recent_alerts(200);
                if rows.is_empty() {
                    (200, alerts_from_jsonl())
                } else {
                    (200, serde_json::to_string(&rows.iter().map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "time": r.timestamp,
                            "severity": r.severity,
                            "title": r.title,
                            "detail": r.detail,
                            "acknowledged": r.acknowledged,
                            "hmac_signature": r.hmac_signature,
                        })
                    }).collect::<Vec<_>>()).unwrap_or_else(|_| "[]".into()))
                }
            }
        }
        "/api/networks" | "/api/aps" => {
            let list: Vec<ScannedAp> = {
                let store = ap_store.lock().unwrap();
                store.values().cloned().collect()
            };
            if list.is_empty() {
                if let Ok(file_contents) = fs::read_to_string("widps_networks.json") {
                    (200, file_contents)
                } else {
                    (200, "[]".to_string())
                }
            } else {
                (200, serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()))
            }
        }
        "/api/status" => {
            let ap_count = ap_store.lock().unwrap().len();
            let ch = current_channel.load(Ordering::Acquire);
            let station_count = client_tracker.lock().unwrap().client_count() as u32;
            let pps = packets_per_second.load(Ordering::Acquire);
            let subs = sse_broadcaster.lock().unwrap().subscriber_count();

            let sys = SystemStatusResponse {
                monitoring_active: true,
                interface_name: "wlan1mon".into(),
                current_channel: ch,
                nearby_ap_count: ap_count,
                connected_station_count: station_count,
                packets_per_second: pps,
                ai_model_status: "Active (RF + ONNX)".into(),
                cpu_usage_pct: read_cpu_usage(),
                memory_usage_pct: read_memory_usage(),
                pi_temperature_c: read_pi_temperature(),
                detection_engine_status: "Running".into(),
                sse_subscribers: subs,
            };
            (200, serde_json::to_string(&sys).unwrap_or_else(|_| "{}".into()))
        }
        "/api/traffic" => {
            let history = traffic_history.lock().unwrap();
            let points: Vec<_> = history.iter().cloned().collect();
            (200, serde_json::to_string(&points).unwrap_or_else(|_| "[]".into()))
        }
        "/api/clients" => {
            let tracker = client_tracker.lock().unwrap();
            let clients = tracker.get_all_clients();
            (200, serde_json::to_string(&clients).unwrap_or_else(|_| "[]".into()))
        }
        "/api/ai/predict" => {
            let pred = ml_prediction.lock().unwrap();
            match &*pred {
                Some(p) => (200, serde_json::to_string(p).unwrap_or_else(|_| "{}".into())),
                None => (200, "{\"label\":\"Normal\",\"confidence\":1.0,\"threat_score\":0,\"inference_ms\":0,\"frame_count\":0}".to_string()),
            }
        }
        "/api/ai/shap" => {
            let db = database.lock().unwrap();
            let rows = db.get_recent_shap(20);
            (200, serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()))
        }
        "/api/ai/history" => {
            let db = database.lock().unwrap();
            let rows = db.get_ml_predictions(100);
            (200, serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()))
        }
        "/api/ai/accuracy" => {
            // Run inference.py --evaluate-json and return confusion matrix
            let python = if std::path::Path::new("ml/.venv/bin/python").exists() {
                "ml/.venv/bin/python"
            } else {
                "python3"
            };
            let output = std::process::Command::new(python)
                .args(&["ml/inference.py", "--evaluate-json"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    let json_str = String::from_utf8_lossy(&o.stdout).to_string();
                    (200, json_str)
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr).to_string();
                    (500, format!("{{\"error\":\"evaluation failed\",\"detail\":\"{}\"}}", err.replace('"', "\\\"").chars().take(200).collect::<String>()))
                }
                Err(e) => {
                    (500, format!("{{\"error\":\"failed to spawn python\",\"detail\":\"{}\"}}", e))
                }
            }
        }
        "/api/threats" => {
            let scorer = threat_scorer.lock().unwrap();
            let profiles = scorer.get_all_profiles();
            (200, serde_json::to_string(&profiles).unwrap_or_else(|_| "[]".into()))
        }
        "/api/events" => {
            let last_id_str = raw_url.split("last_id=").nth(1).unwrap_or("0");
            let last_id: u64 = last_id_str.parse().unwrap_or(0);
            let broadcaster = sse_broadcaster.lock().unwrap();
            let events = if last_id == 0 {
                broadcaster.latest_events(20)
            } else {
                broadcaster.events_since(last_id)
            };
            let payload: Vec<serde_json::Value> = events.iter().map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "type": e.event_type,
                    "data": e.data,
                })
            }).collect();
            (200, serde_json::to_string(&payload).unwrap_or_else(|_| "[]".into()))
        }
        "/api/audit/integrity" => {
            let db = database.lock().unwrap();
            let alerts = db.verify_alert_chain();
            let audit_log = db.verify_audit_chain();
            let clean = alerts.is_clean() && audit_log.is_clean();
            (200, serde_json::to_string(&serde_json::json!({
                "total_signed_alerts": alerts.chained,
                "valid": alerts.valid,
                "tampered": alerts.broken,
                "integrity_status": if clean { "CLEAN" } else { "TAMPERED" },
                "alert_chain": alerts,
                "audit_chain": audit_log,
                "limits": "Detects edits, reordering and deletions inside the chain by anyone without the key. Deleting the newest records (the tail) is only detectable against an exported head hash.",
            })).unwrap_or_else(|_| "{}".into()))
        }
        "/api/audit/log" => {
            let rows = database.lock().unwrap().recent_audit(200);
            (200, serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()))
        }
        "/api/profiles" => {
            // Behavioral profiler device summaries
            let guard = crate::behavioral_profiler::SHARED_PROFILER.lock();
            match guard {
                Ok(opt) => {
                    if let Some(ref profiler_arc) = *opt {
                        let p = profiler_arc.lock().unwrap();
                        let summaries = p.get_profiles_summary();
                        (200, serde_json::to_string(&serde_json::json!({
                            "device_count": p.device_count(),
                            "profiles": summaries,
                        })).unwrap_or_else(|_| "{}".into()))
                    } else {
                        (200, "{\"device_count\":0,\"profiles\":[]}".into())
                    }
                }
                Err(_) => (500, "{\"error\":\"lock\"}".into()),
            }
        }
        "/api/honeypot/status" => {
            // Honeypot stats + connections + pending deployments
            let hp = crate::honeypot::SHARED_MONITOR.lock();
            match hp {
                Ok(guard) => {
                    if let Some(ref monitor_arc) = *guard {
                        let m = monitor_arc.lock().unwrap();
                        let stats = m.get_stats();
                        let connections = m.get_all_connections();
                        let pending = m.get_pending_deployments();
                        (200, serde_json::to_string(&serde_json::json!({
                            "stats": stats,
                            "connections": connections,
                            "pending_dynamic_ssids": pending,
                        })).unwrap_or_else(|_| "{}".into()))
                    } else {
                        (200, "{\"stats\":null,\"connections\":[],\"pending_dynamic_ssids\":[]}".into())
                    }
                }
                Err(_) => (500, "{\"error\":\"lock poisoned\"}".into()),
            }
        }
        "/api/siem/status" => {
            let enabled = std::env::var("WIDPS_SIEM_ENABLED").unwrap_or_default() == "1";
            let host = std::env::var("WIDPS_SIEM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
            let port = std::env::var("WIDPS_SIEM_PORT").unwrap_or_else(|_| "514".to_string());
            let format = std::env::var("WIDPS_SIEM_FORMAT").unwrap_or_else(|_| "json".to_string());
            (200, serde_json::to_string(&serde_json::json!({
                "enabled": enabled,
                "target_host": host,
                "target_port": port,
                "format": format,
                "protocol": if std::env::var("WIDPS_SIEM_TCP").unwrap_or_default() == "1" { "TCP" } else { "UDP" },
            })).unwrap_or_else(|_| "{}".into()))
        }
        "/api/report" => {
            // Generate full HTML incident report server-side
            let ch = current_channel.load(Ordering::Acquire);
            let pps = packets_per_second.load(Ordering::Acquire);
            let station_count = client_tracker.lock().unwrap().client_count() as u32;
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "widps-sensor".to_string());

            let sys_info = crate::report_generator::SystemInfo {
                hostname,
                interface_name: "wlan1mon".to_string(),
                current_channel: ch,
                packets_per_second: pps,
                engine_status: "Active".to_string(),
                station_count,
            };

            let html = {
                let db = database.lock().unwrap();
                crate::report_generator::generate_incident_report(&db, &sys_info)
            };

            return ApiResponse::html(html);
        }
        "/api/logs" => {
            // Query structured logs from today's log file
            let query_str = raw_url.split('?').nth(1).unwrap_or("");
            let params: std::collections::HashMap<&str, &str> = query_str
                .split('&')
                .filter_map(|p| p.split_once('='))
                .collect();

            let limit: usize = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100);
            let level_filter = params.get("level").map(|s| s.to_uppercase());
            let service_filter = params.get("service").copied();

            let log_path = format!("data/logs/widps-{}.jsonl", chrono::Local::now().format("%Y-%m-%d"));
            let content = fs::read_to_string(&log_path).unwrap_or_default();

            let mut lines: Vec<&str> = content.lines().rev().collect();

            // Apply filters
            if level_filter.is_some() || service_filter.is_some() {
                lines.retain(|line| {
                    let level_ok = match &level_filter {
                        Some(lvl) => line.contains(&format!("\"level\":\"{}\"", lvl)),
                        None => true,
                    };
                    let service_ok = match service_filter {
                        Some(svc) => line.contains(&format!("\"service\":\"{}\"", svc)),
                        None => true,
                    };
                    level_ok && service_ok
                });
            }

            let limited: Vec<&str> = lines.into_iter().take(limit).collect();
            let body = format!("[{}]", limited.join(","));
            (200, body)
        }
        "/api/logs/services" => {
            // Return list of unique services found in today's logs
            let log_path = format!("data/logs/widps-{}.jsonl", chrono::Local::now().format("%Y-%m-%d"));
            let content = fs::read_to_string(&log_path).unwrap_or_default();

            let mut services: std::collections::HashSet<String> = std::collections::HashSet::new();
            for line in content.lines().take(1000) {
                if let Some(start) = line.find("\"service\":\"") {
                    let after = &line[start + 11..];
                    if let Some(end) = after.find('"') {
                        services.insert(after[..end].to_string());
                    }
                }
            }

            let list: Vec<&str> = services.iter().map(|s| s.as_str()).collect();
            (200, serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()))
        }
        "/api/config" => {
            if method == "POST" {
                let body = body.to_string();
                if let Ok(cfg) = serde_json::from_str::<crate::config::RuntimeConfig>(&body) {
                    config_flags.apply(&cfg);
                    database.lock().unwrap().record_audit(&actor, "config_change", "runtime_config",
                        &serde_json::to_string(&cfg).unwrap_or_default());
                    (200, "{\"status\":\"ok\"}".to_string())
                } else {
                    (400, "{\"error\":\"invalid config JSON\"}".to_string())
                }
            } else {
                let cfg = config_flags.to_runtime_config();
                (200, serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".into()))
            }
        }
        _ if url_path.starts_with("/api/alerts/") && url_path.ends_with("/ack") => {
            let id_str = url_path.trim_start_matches("/api/alerts/").trim_end_matches("/ack");
            if method != "POST" {
                (405, "{\"error\":\"POST required\"}".to_string())
            } else if let Ok(alert_id) = id_str.parse::<i64>() {
                let db = database.lock().unwrap();
                let success = db.ack_alert(alert_id, actor) != crate::db::AckResult::NotFound;
                if success {
                    db.record_audit(&actor, "alert_ack", &alert_id.to_string(), "");
                    (200, "{\"status\":\"acknowledged\"}".to_string())
                } else {
                    (404, "{\"error\":\"alert not found\"}".to_string())
                }
            } else {
                (400, "{\"error\":\"invalid alert id\"}".to_string())
            }
        }
        _ if url_path.starts_with("/api/alerts/") && url_path.ends_with("/confirm") => {
            // Online Learning: admin confirms an alert as a true attack
            if method == "POST" {
                let body_str = body.to_string();

                // Expect: {"label": "Deauth_Flood", "features": [...]}
                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    let label = payload["label"].as_str().unwrap_or("Unknown");
                    let features = payload.get("features")
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "[]".to_string());

                    let alert_id = url_path.trim_start_matches("/api/alerts/").trim_end_matches("/confirm");
                    let db = database.lock().unwrap();
                    db.insert_confirmed_sample(label, &features);
                    db.record_audit(&actor, "alert_confirm", alert_id, &format!("label={}", label));
                    (200, "{\"status\":\"confirmed\",\"message\":\"Sample saved for retraining\"}".to_string())
                } else {
                    (400, "{\"error\":\"invalid JSON body\"}".to_string())
                }
            } else {
                (405, "{\"error\":\"POST required\"}".to_string())
            }
        }
        "/api/online-learning/status" => {
            let db = database.lock().unwrap();
            let (total, pending) = db.get_confirmed_sample_count();
            (200, serde_json::to_string(&serde_json::json!({
                "total_confirmed_samples": total,
                "pending_retrain": pending,
                "retrain_threshold": 10,
                "status": if pending >= 10 { "ready_to_retrain" } else { "collecting" },
            })).unwrap_or_else(|_| "{}".into()))
        }
        "/api/intel" => {
            // Full threat intelligence — all devices with reputation
            let guard = crate::threat_intel::SHARED_INTEL.lock().unwrap();
            if let Some(ref intel) = *guard {
                let i = intel.lock().unwrap();
                let all = i.get_all_intel();
                let stats = i.stats();
                (200, serde_json::to_string(&serde_json::json!({
                    "stats": stats,
                    "devices": all,
                })).unwrap_or_else(|_| "{}".into()))
            } else {
                (200, "{\"stats\":{},\"devices\":[]}".into())
            }
        }
        "/api/intel/threats" => {
            let guard = crate::threat_intel::SHARED_INTEL.lock().unwrap();
            if let Some(ref intel) = *guard {
                let threats = intel.lock().unwrap().get_threats();
                (200, serde_json::to_string(&threats).unwrap_or_else(|_| "[]".into()))
            } else {
                (200, "[]".into())
            }
        }
        "/api/intel/feed" => {
            // STIX-compatible threat feed export
            let guard = crate::threat_intel::SHARED_INTEL.lock().unwrap();
            if let Some(ref intel) = *guard {
                let feed = intel.lock().unwrap().export_feed();
                (200, serde_json::to_string_pretty(&feed).unwrap_or_else(|_| "{}".into()))
            } else {
                (200, "{}".into())
            }
        }
        _ if url_path.starts_with("/api/intel/") && method == "POST" => {
            // Admin actions: /api/intel/<MAC>/whitelist, /api/intel/<MAC>/blacklist, /api/intel/<MAC>/reset
            let path_parts: Vec<&str> = url_path.trim_start_matches("/api/intel/").split('/').collect();
            if path_parts.len() == 2 {
                let Some(mac) = normalize_mac(&path_parts[0].replace('-', ":")) else {
                    return ApiResponse::json(400, r#"{"error":"invalid MAC address"}"#.to_string());
                };
                let action = path_parts[1];

                let body_str = body.to_string();
                let reason = serde_json::from_str::<serde_json::Value>(&body_str).ok()
                    .and_then(|v| v["reason"].as_str().map(|s| s.to_string()));

                let guard = crate::threat_intel::SHARED_INTEL.lock().unwrap();
                if matches!(action, "whitelist" | "blacklist" | "reset") {
                    database.lock().unwrap().record_audit(&actor, &format!("intel_{}", action), &mac,
                        reason.as_deref().unwrap_or(""));
                }
                if let Some(ref intel) = *guard {
                    let mut i = intel.lock().unwrap();
                    match action {
                        "whitelist" => {
                            i.admin_whitelist(&mac, reason.as_deref());
                            (200, serde_json::json!({"status": "whitelisted", "mac": mac}).to_string())
                        }
                        "blacklist" => {
                            i.admin_blacklist(&mac, reason.as_deref());
                            (200, serde_json::json!({"status": "blacklisted", "mac": mac}).to_string())
                        }
                        "reset" => {
                            i.admin_reset(&mac, reason.as_deref());
                            (200, serde_json::json!({"status": "reset", "mac": mac}).to_string())
                        }
                        _ => (400, "{\"error\":\"unknown action\"}".to_string()),
                    }
                } else {
                    (500, "{\"error\":\"intel not initialized\"}".to_string())
                }
            } else {
                (400, "{\"error\":\"invalid path format\"}".to_string())
            }
        }
        "/api/whitelist" => {
            if method == "POST" {
                // Add a new trusted AP
                let body_str = body.to_string();
                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    let ssid = payload["ssid"].as_str().unwrap_or("");
                    let bssid_norm = normalize_mac(payload["bssid"].as_str().unwrap_or(""));
                    let bssid = bssid_norm.as_deref().unwrap_or("");
                    if ssid.is_empty() || bssid.is_empty() {
                        (400, "{\"error\":\"ssid and a valid bssid (AA:BB:CC:DD:EE:FF) required\"}".to_string())
                    } else if ssid.len() > 32 || ssid.chars().any(|c| c.is_control()) {
                        (400, "{\"error\":\"ssid must be at most 32 bytes without control characters\"}".to_string())
                    } else {
                        let guard = crate::whitelist::SHARED_WHITELIST.lock().unwrap();
                        if let Some(ref wl) = *guard {
                            let added = wl.lock().unwrap().add_trusted(ssid, bssid);
                            if added {
                                database.lock().unwrap().record_audit(&actor, "whitelist_add", bssid, ssid);
                                // Update AP status to Normal immediately
                                {
                                    let mut store = ap_store.lock().unwrap();
                                    if let Some(ap) = store.get_mut(bssid) {
                                        ap.status = "Normal".to_string();
                                    }
                                }
                                // Clear threat score for this BSSID
                                {
                                    let mut scorer = threat_scorer.lock().unwrap();
                                    scorer.clear_device(bssid);
                                }
                                (200, serde_json::json!({"status": "added", "ssid": ssid, "bssid": bssid}).to_string())
                            } else {
                                (200, "{\"status\":\"already_trusted\"}".to_string())
                            }
                        } else {
                            (500, "{\"error\":\"whitelist not initialized\"}".to_string())
                        }
                    }
                } else {
                    (400, "{\"error\":\"invalid JSON\"}".to_string())
                }
            } else {
                // GET: list all trusted APs
                let guard = crate::whitelist::SHARED_WHITELIST.lock().unwrap();
                if let Some(ref wl) = *guard {
                    let entries = wl.lock().unwrap().get_all();
                    let list: Vec<serde_json::Value> = entries.into_iter()
                        .map(|(ssid, bssid)| serde_json::json!({"ssid": ssid, "bssid": bssid}))
                        .collect();
                    (200, serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()))
                } else {
                    (200, "[]".to_string())
                }
            }
        }
        _ => (404, "{\"error\":\"not found\"}".to_string()),
    };
    ApiResponse::json(status, body)
}

/// Exports visible alerts to data/archive and hides them (nothing is deleted); returns (count, file).
pub fn archive_alerts(database: &SharedDatabase, actor: &str) -> Result<(u32, String), String> {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f").to_string();
    let archive = std::path::PathBuf::from(format!("data/archive/alerts-{}.jsonl", stamp));
    let n = database.lock().unwrap_or_else(|e| e.into_inner()).archive_all_alerts(&archive, actor)?;
    let jsonl = std::path::Path::new(crate::alert::ALERTS_JSONL);
    if jsonl.exists() {
        let _ = std::fs::rename(jsonl, format!("data/archive/widps_alerts-{}.jsonl", stamp));
    }
    Ok((n, archive.display().to_string()))
}

/// Upper-case AA:BB:CC:DD:EE:FF, or None if `s` is not a MAC address.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    let ok = parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then(|| s.trim().to_ascii_uppercase())
}

fn alerts_from_jsonl() -> String {
    let contents = fs::read_to_string("widps_alerts.jsonl").unwrap_or_default();
    let lines: Vec<&str> = contents.lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let recent = if lines.len() > 200 { &lines[lines.len() - 200..] } else { &lines[..] };
    format!("[{}]", recent.join(","))
}

#[cfg(test)]
mod tests {
    use super::normalize_mac;

    #[test]
    fn mac_validation() {
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        for bad in ["", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:fg", "aa:bb:cc:dd:ee:ff:00", "\"},{\"x\":1", "aabbccddeeff"] {
            assert!(normalize_mac(bad).is_none(), "{}", bad);
        }
    }
}
