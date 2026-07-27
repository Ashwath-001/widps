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
use tiny_http::{Header, Method, Response, Server};

pub type SharedConfigFlags = Arc<ConfigFlags>;
pub type SharedDatabase = Arc<Mutex<Database>>;

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
            let cors_headers = Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type, X-API-Key"[..]).unwrap();
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

            let raw_url = request.url();
            let url_path = raw_url.split('?').next().unwrap_or(raw_url).trim_end_matches('/');

            if request.body_length().unwrap_or(0) > 10240 {
                let response = Response::from_string("{\"error\":\"request body too large\"}")
                    .with_status_code(413)
                    .with_header(cors_origin)
                    .with_header(cors_credentials);
                let _ = request.respond(response);
                continue;
            }

            let (status, body) = match url_path {
                "/api/alerts" => (200, alerts_as_json_array()),
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

                    let sys = SystemStatusResponse {
                        monitoring_active: true,
                        interface_name: "wlan1mon".into(),
                        current_channel: ch,
                        nearby_ap_count: ap_count,
                        connected_station_count: station_count,
                        packets_per_second: pps,
                        ai_model_status: "Offline (MVP Roadmap)".into(),
                        cpu_usage_pct: 15,
                        memory_usage_pct: 32,
                        pi_temperature_c: 45,
                        detection_engine_status: "Running".into(),
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
                    let count = tracker.client_count();
                    (200, format!("{{\"count\":{}}}", count))
                }
                "/api/ai/predict" => {
                    let pred = ml_prediction.lock().unwrap();
                    match &*pred {
                        Some(p) => (200, serde_json::to_string(p).unwrap_or_else(|_| "{}".into())),
                        None => (200, "{\"label\":\"Normal\",\"confidence\":1.0,\"threat_score\":0,\"inference_ms\":0,\"frame_count\":0}".to_string()),
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

fn alerts_as_json_array() -> String {
    let contents = fs::read_to_string("widps_alerts.jsonl").unwrap_or_default();
    let lines: Vec<&str> = contents.lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let recent = if lines.len() > 200 { &lines[lines.len() - 200..] } else { &lines[..] };
    format!("[{}]", recent.join(","))
}
