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
use std::io::Read;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server};

// ---------------------------------------------------------------------------
// ChannelReader: bridges mpsc channel to std::io::Read for SSE streaming
// ---------------------------------------------------------------------------
struct ChannelReader {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: std::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self { rx, buffer: Vec::new(), pos: 0 }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have leftover data in our buffer, serve from there
        if self.pos < self.buffer.len() {
            let available = &self.buffer[self.pos..];
            let to_copy = available.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.pos += to_copy;
            return Ok(to_copy);
        }

        // Wait for new data from the channel (blocking)
        match self.rx.recv() {
            Ok(data) => {
                if data.is_empty() {
                    return Ok(0); // EOF signal
                }
                let to_copy = data.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    // Store remainder
                    self.buffer = data;
                    self.pos = to_copy;
                } else {
                    self.buffer.clear();
                    self.pos = 0;
                }
                Ok(to_copy)
            }
            Err(_) => Ok(0), // Channel closed = EOF
        }
    }
}

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

pub fn spawn(
    port: u16,
    ap_store: SharedApStore,
    current_channel: Arc<AtomicU8>,
    client_tracker: SharedClientTracker,
    packets_per_second: Arc<AtomicU32>,
    traffic_history: SharedTrafficHistory,
    ml_prediction: SharedPrediction,
    threat_scorer: SharedThreatScorer,
    sse_broadcaster: SharedBroadcaster,
    config_flags: SharedConfigFlags,
    database: SharedDatabase,
) {
    thread::spawn(move || {
        let server = match Server::http(format!("0.0.0.0:{}", port)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("==================================================================");
                eprintln!("[API SERVER ERROR] COULD NOT BIND PORT {}: {}", port, e);
                eprintln!("[API SERVER ERROR] Please kill any existing process running on port {}!", port);
                eprintln!("==================================================================");
                return;
            }
        };
        println!("[api] HTTP API Server successfully listening on http://0.0.0.0:{}", port);

        for mut request in server.incoming_requests() {
            let origin = request.headers().iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("origin"))
                .map(|h| h.value.as_str().to_string());

            let allowed_origin = match &origin {
                Some(o) if o.starts_with("http://localhost") || o.starts_with("http://127.0.0.1") => o.as_str(),
                Some(o) if o.contains(":5173") || o.contains(":4173") => o.as_str(),
                _ => "http://localhost:5173",
            };

            let cors_origin = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], allowed_origin.as_bytes()).unwrap();
            let cors_methods = Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap();
            let cors_headers = Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type, X-API-Key, Last-Event-ID"[..]).unwrap();
            let cors_credentials = Header::from_bytes(&b"Vary"[..], &b"Origin"[..]).unwrap();

            if request.method() == &Method::Options {
                let response = Response::from_string("")
                    .with_status_code(204)
                    .with_header(cors_origin)
                    .with_header(cors_methods)
                    .with_header(cors_headers)
                    .with_header(cors_credentials);
                let _ = request.respond(response);
                continue;
            }

            let raw_url = request.url().to_string();
            let url_path = raw_url.split('?').next().unwrap_or(&raw_url).trim_end_matches('/');

            if request.body_length().unwrap_or(0) > 10240 {
                let response = Response::from_string("{\"error\":\"request body too large\"}")
                    .with_status_code(413)
                    .with_header(cors_origin)
                    .with_header(cors_credentials);
                let _ = request.respond(response);
                continue;
            }

   
            if url_path == "/api/stream" {
                let last_event_id: u64 = request.headers().iter()
                    .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("last-event-id"))
                    .and_then(|h| h.value.as_str().parse().ok())
                    .unwrap_or(0);

                let (catch_up, rx) = {
                    let mut b = sse_broadcaster.lock().unwrap();
                    let catch_up = b.catch_up_since(last_event_id);
                    let rx = b.subscribe();
                    (catch_up, rx)
                };

                let (writer_tx, reader_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(64);

                thread::spawn(move || {
                    if !catch_up.is_empty() {
                        if writer_tx.send(catch_up.into_bytes()).is_err() {
                            return;
                        }
                    }

                    let connected_msg = b"event: connected\ndata: {\"status\":\"ok\"}\n\n".to_vec();
                    if writer_tx.send(connected_msg).is_err() {
                        return;
                    }

                    loop {
                        match rx.recv_timeout(Duration::from_secs(15)) {
                            Ok(msg) => {
                                if writer_tx.send(msg.into_bytes()).is_err() {
                                    break; // Client disconnected
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                // Send keepalive
                                if writer_tx.send(b": keepalive\n\n".to_vec()).is_err() {
                                    break;
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                break;
                            }
                        }
                    }
                });

                // Create a streaming reader that reads from the channel
                let stream_reader = ChannelReader::new(reader_rx);

                let content_type = Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap();
                let cache = Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).unwrap();
                let connection_hdr = Header::from_bytes(&b"Connection"[..], &b"keep-alive"[..]).unwrap();
                let no_buffer = Header::from_bytes(&b"X-Accel-Buffering"[..], &b"no"[..]).unwrap();

                let response = Response::new(
                    tiny_http::StatusCode(200),
                    vec![content_type, cache, connection_hdr, no_buffer, cors_origin, cors_credentials],
                    stream_reader,
                    None, // No content-length (chunked)
                    None,
                );
                let _ = request.respond(response);
                continue;
            }

            // Standard REST endpoints
 
            let (status, body) = match url_path {
                "/api/alerts" => {
                    let db = database.lock().unwrap();
                    let rows = db.get_recent_alerts(200);
                    if rows.is_empty() {
                        (200, alerts_from_jsonl())
                    } else {
                        (200, serde_json::to_string(&rows.iter().map(|r| {
                            serde_json::json!({
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
                    // Try venv Python first (has sklearn), fall back to system python3
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
                    let (total, valid, tampered) = db.audit_alert_integrity();
                    (200, serde_json::to_string(&serde_json::json!({
                        "total_signed_alerts": total,
                        "valid": valid,
                        "tampered": tampered,
                        "integrity_status": if tampered == 0 { "CLEAN" } else { "TAMPERED" },
                    })).unwrap_or_else(|_| "{}".into()))
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

                    // Return HTML directly (not JSON)
                    let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                    let response = Response::from_string(html)
                        .with_status_code(200)
                        .with_header(ct)
                        .with_header(cors_origin)
                        .with_header(cors_credentials);
                    let _ = request.respond(response);
                    continue;
                }
                "/api/logs" => {
                    // Query structured logs from today's log file
                    // Supports ?level=INFO&service=honeypot&limit=100&offset=0
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
                    if request.method() == &Method::Post {
                        let mut body = String::new();
                        let _ = request.as_reader().read_to_string(&mut body);
                        if let Ok(cfg) = serde_json::from_str::<crate::config::RuntimeConfig>(&body) {
                            config_flags.apply(&cfg);
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
                    if let Ok(alert_id) = id_str.parse::<i64>() {
                        let success = database.lock().unwrap().acknowledge_alert(alert_id);
                        if success {
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
                    // This saves the detection context as a labeled training sample
                    if request.method() == &Method::Post {
                        let mut body_str = String::new();
                        let _ = request.as_reader().read_to_string(&mut body_str);

                        // Expect: {"label": "Deauth_Flood", "features": [...]}
                        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&body_str) {
                            let label = payload["label"].as_str().unwrap_or("Unknown");
                            let features = payload.get("features")
                                .map(|f| f.to_string())
                                .unwrap_or_else(|| "[]".to_string());

                            database.lock().unwrap().insert_confirmed_sample(label, &features);
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
                _ if url_path.starts_with("/api/intel/") && request.method() == &Method::Post => {
                    // Admin actions: /api/intel/<MAC>/whitelist, /api/intel/<MAC>/blacklist, /api/intel/<MAC>/reset
                    let path_parts: Vec<&str> = url_path.trim_start_matches("/api/intel/").split('/').collect();
                    if path_parts.len() == 2 {
                        let mac = path_parts[0].replace('-', ":");
                        let action = path_parts[1];

                        let mut body_str = String::new();
                        let _ = request.as_reader().read_to_string(&mut body_str);
                        let reason = serde_json::from_str::<serde_json::Value>(&body_str).ok()
                            .and_then(|v| v["reason"].as_str().map(|s| s.to_string()));

                        let guard = crate::threat_intel::SHARED_INTEL.lock().unwrap();
                        if let Some(ref intel) = *guard {
                            let mut i = intel.lock().unwrap();
                            match action {
                                "whitelist" => {
                                    i.admin_whitelist(&mac, reason.as_deref());
                                    (200, format!("{{\"status\":\"whitelisted\",\"mac\":\"{}\"}}", mac))
                                }
                                "blacklist" => {
                                    i.admin_blacklist(&mac, reason.as_deref());
                                    (200, format!("{{\"status\":\"blacklisted\",\"mac\":\"{}\"}}", mac))
                                }
                                "reset" => {
                                    i.admin_reset(&mac, reason.as_deref());
                                    (200, format!("{{\"status\":\"reset\",\"mac\":\"{}\"}}", mac))
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
                    if request.method() == &Method::Post {
                        // Add a new trusted AP
                        let mut body_str = String::new();
                        let _ = request.as_reader().read_to_string(&mut body_str);
                        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&body_str) {
                            let ssid = payload["ssid"].as_str().unwrap_or("");
                            let bssid = payload["bssid"].as_str().unwrap_or("");
                            if ssid.is_empty() || bssid.is_empty() {
                                (400, "{\"error\":\"ssid and bssid required\"}".to_string())
                            } else {
                                let guard = crate::whitelist::SHARED_WHITELIST.lock().unwrap();
                                if let Some(ref wl) = *guard {
                                    let added = wl.lock().unwrap().add_trusted(ssid, bssid);
                                    if added {
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
                                        (200, format!("{{\"status\":\"added\",\"ssid\":\"{}\",\"bssid\":\"{}\"}}", ssid, bssid))
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

            let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let response = Response::from_string(body)
                .with_status_code(status)
                .with_header(content_type)
                .with_header(cors_origin)
                .with_header(cors_methods)
                .with_header(cors_headers)
                .with_header(cors_credentials);

            let _ = request.respond(response);
        }
    });
}

fn alerts_from_jsonl() -> String {
    let contents = fs::read_to_string("widps_alerts.jsonl").unwrap_or_default();
    let lines: Vec<&str> = contents.lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let recent = if lines.len() > 200 { &lines[lines.len() - 200..] } else { &lines[..] };
    format!("[{}]", recent.join(","))
}
