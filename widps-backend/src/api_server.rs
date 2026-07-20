#![allow(unused_imports)]

use crate::client_tracker::ClientTracker;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tiny_http::{Header, Method, Response, Server};

#[derive(Debug, Clone, Serialize)]
pub struct ScannedAp {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub rssi: i8,
    pub vendor: String,
    pub encryption: String,
    pub beaconIntervalMs: u16,
    pub clientCount: u32,
    pub status: String,
    pub firstSeen: String,
    pub lastSeen: String,
}

pub type SharedApStore = Arc<Mutex<HashMap<String, ScannedAp>>>;
pub type SharedClientTracker = Arc<Mutex<ClientTracker>>;

#[derive(Debug, Clone, Serialize)]
pub struct SystemStatusResponse {
    pub monitoringActive: bool,
    pub interfaceName: String,
    pub currentChannel: u8,
    pub nearbyApCount: usize,
    pub connectedStationCount: u32,
    pub packetsPerSecond: u32,
    pub aiModelStatus: String,
    pub cpuUsagePct: u32,
    pub memoryUsagePct: u32,
    pub piTemperatureC: u32,
    pub detectionEngineStatus: String,
}

/// Serves widps_alerts.jsonl, scanned networks (/api/networks), and system status (/api/status)
pub fn spawn(
    port: u16,
    ap_store: SharedApStore,
    current_channel: Arc<AtomicU8>,
    client_tracker: SharedClientTracker,
    packets_per_second: Arc<AtomicU32>,
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
                    let store = ap_store.lock().unwrap();
                    let list: Vec<ScannedAp> = store.values().cloned().collect();
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
                    let ch = current_channel.load(Ordering::Relaxed);
                    let station_count = client_tracker.lock().unwrap().client_count() as u32;
                    let pps = packets_per_second.load(Ordering::Relaxed);

                    let sys = SystemStatusResponse {
                        monitoringActive: true,
                        interfaceName: "wlan1mon".into(),
                        currentChannel: ch,
                        nearbyApCount: ap_count,
                        connectedStationCount: station_count,
                        packetsPerSecond: pps,
                        aiModelStatus: "Offline (MVP Roadmap)".into(),
                        cpuUsagePct: 15,
                        memoryUsagePct: 32,
                        piTemperatureC: 45,
                        detectionEngineStatus: "Running".into(),
                    };
                    (200, serde_json::to_string(&sys).unwrap_or_else(|_| "{}".into()))
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