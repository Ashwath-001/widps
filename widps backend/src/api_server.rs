use std::fs;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;
use tiny_http::{Header, Response, Server};

/// Serves widps_alerts.jsonl (converted to a JSON array) and system status
/// over plain HTTP so the dashboard can poll it with fetch().
/// CORS is wide open — fine for a local demo, tighten before anything real.
pub fn spawn(port: u16) {
    thread::spawn(move || {
        let server = Server::http(format!("0.0.0.0:{}", port)).expect("failed to bind API server");
        println!("[api] serving on http://0.0.0.0:{}", port);

        for request in server.incoming_requests() {
            let (status, body) = match request.url() {
                "/api/alerts" => (200, alerts_as_json_array()),
                _ => (404, "{\"error\":\"not found\"}".to_string()),
            };

            let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
            let response = Response::from_string(body)
                .with_status_code(status)
                .with_header(header)
                .with_header(cors);

            let _ = request.respond(response);
        }
    });
}

fn alerts_as_json_array() -> String {
    let contents = fs::read_to_string("widps_alerts.jsonl").unwrap_or_default();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    format!("[{}]", lines.join(","))
}