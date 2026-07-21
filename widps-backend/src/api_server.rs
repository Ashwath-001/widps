#![allow(unused_imports)]

use crate::client_tracker::ClientTracker;
use crate::packet_stats::SharedTrafficHistory;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tiny_http::{Header, Method, Response, Server};

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

        for request in server.incoming_requests() {
            let cors_origin = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
            let cors_methods = Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap();
            let cors_headers = Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"*"[..]).unwrap();

            if request.method() == &Method::Options {
                let response = Response::from_string("")
                    .with_status_code(200)
                    .with_header(cors_origin)
                    .with_header(cors_methods)
                    .with_header(cors_headers);
                let _ = request.respond(response);
                continue;
            }

            let raw_url = request.url();
            let url_path = raw_url.split('?').next().unwrap_or(raw_url).trim_end_matches('/');

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
                _ => (404, "{\"error\":\"not found\"}".to_string()),
            };

            let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let response = Response::from_string(body)
                .with_status_code(status)
                .with_header(content_type)
                .with_header(cors_origin)
                .with_header(cors_methods)
                .with_header(cors_headers);

            let _ = request.respond(response);
        }
    });
}

fn alerts_as_json_array() -> String {
    let contents = fs::read_to_string("widps_alerts.jsonl").unwrap_or_default();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    format!("[{}]", lines.join(","))
}
