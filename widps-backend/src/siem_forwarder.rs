//! SIEM Integration Module — Syslog Forwarder
//!
//! Forwards WIDPS alerts to external SIEM systems (Wazuh, Splunk, ELK)
//! via syslog (RFC 5424) over UDP or TCP.
//!
//! Also supports CEF (Common Event Format) for enterprise SIEM compatibility.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::sse::SharedBroadcaster;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub enabled: bool,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: SiemProtocol,
    pub format: SiemFormat,
    pub facility: u8,      // syslog facility (default: 4 = auth)
    pub app_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SiemProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SiemFormat {
    Syslog,  // RFC 5424
    Cef,     // Common Event Format (ArcSight/Splunk)
    Json,    // Raw JSON (Elasticsearch/Wazuh)
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_host: "127.0.0.1".to_string(),
            target_port: 514,
            protocol: SiemProtocol::Udp,
            format: SiemFormat::Json,
            facility: 4,
            app_name: "WIDPS".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Syslog severity mapping
// ---------------------------------------------------------------------------
fn severity_to_syslog(severity: &str) -> u8 {
    match severity {
        "Critical" => 2, // syslog critical
        "High" => 3,     // syslog error
        "Medium" => 4,   // syslog warning
        "Low" => 5,      // syslog notice
        _ => 6,          // informational
    }
}

fn severity_to_cef(severity: &str) -> u8 {
    match severity {
        "Critical" => 10,
        "High" => 7,
        "Medium" => 4,
        "Low" => 2,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------
fn format_syslog_rfc5424(config: &SiemConfig, severity: &str, title: &str, detail: &str) -> String {
    let priority = (config.facility * 8) + severity_to_syslog(severity);
    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "widps-sensor".to_string());

    // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
    format!(
        "<{}>1 {} {} {} - - - [alert severity=\"{}\" title=\"{}\" detail=\"{}\"]",
        priority,
        timestamp,
        hostname,
        config.app_name,
        severity,
        title.replace('"', "'"),
        detail.replace('"', "'").replace('\n', " | "),
    )
}

fn format_cef(severity: &str, title: &str, detail: &str) -> String {
    let cef_severity = severity_to_cef(severity);
    let safe_detail = detail.replace('|', "\\|").replace('\n', " ");

    // CEF: Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
    format!(
        "CEF:0|WIDPS|WirelessIDS|1.0|ALERT|{}|{}|detail={} severity={}",
        title.replace('|', "\\|"),
        cef_severity,
        safe_detail,
        severity,
    )
}

fn format_json(severity: &str, title: &str, detail: &str) -> String {
    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z").to_string();
    serde_json::json!({
        "timestamp": timestamp,
        "source": "WIDPS",
        "severity": severity,
        "title": title,
        "detail": detail,
        "category": "wireless_intrusion",
        "sensor_type": "802.11_monitor",
    }).to_string()
}

// ---------------------------------------------------------------------------
// SiemForwarder
// ---------------------------------------------------------------------------
pub struct SiemForwarder {
    config: SiemConfig,
    socket: Option<UdpSocket>,
}

impl SiemForwarder {
    pub fn new(config: SiemConfig) -> Self {
        let socket = if config.enabled && config.protocol == SiemProtocol::Udp {
            UdpSocket::bind("0.0.0.0:0").ok()
        } else {
            None
        };

        if config.enabled {
            println!("[SIEM] Forwarder enabled: {}:{} ({:?} format)",
                config.target_host, config.target_port, config.format);
        }

        Self { config, socket }
    }

    pub fn forward_alert(&self, severity: &str, title: &str, detail: &str) {
        if !self.config.enabled {
            return;
        }

        let message = match self.config.format {
            SiemFormat::Syslog => format_syslog_rfc5424(&self.config, severity, title, detail),
            SiemFormat::Cef => format_cef(severity, title, detail),
            SiemFormat::Json => format_json(severity, title, detail),
        };

        self.send_message(&message);
    }

    fn send_message(&self, message: &str) {
        match self.config.protocol {
            SiemProtocol::Udp => {
                if let Some(ref socket) = self.socket {
                    let target = format!("{}:{}", self.config.target_host, self.config.target_port);
                    let _ = socket.send_to(message.as_bytes(), &target);
                }
            }
            SiemProtocol::Tcp => {
                // TCP syslog: message + newline delimiter
                if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                    &format!("{}:{}", self.config.target_host, self.config.target_port)
                        .parse()
                        .unwrap_or_else(|_| "127.0.0.1:514".parse().unwrap()),
                    Duration::from_secs(2),
                ) {
                    use std::io::Write;
                    let _ = write!(stream, "{}\n", message);
                }
            }
        }
    }
}

pub type SharedSiemForwarder = Arc<Mutex<SiemForwarder>>;

/// Spawn background thread that listens to SSE events and forwards to SIEM.
pub fn spawn_siem_listener(
    broadcaster: SharedBroadcaster,
    config: SiemConfig,
) -> SharedSiemForwarder {
    let forwarder = Arc::new(Mutex::new(SiemForwarder::new(config)));
    let forwarder_clone = Arc::clone(&forwarder);

    if !forwarder.lock().unwrap().config.enabled {
        return forwarder;
    }

    // Subscribe to the event broadcaster and forward alerts
    let rx = {
        let mut b = broadcaster.lock().unwrap();
        b.subscribe()
    };

    thread::spawn(move || {
        loop {
            match rx.recv() {
                Ok(msg) => {
                    // Parse the SSE message to extract alert data
                    if msg.contains("event: alert") {
                        // Extract data line from SSE format
                        for line in msg.lines() {
                            if let Some(data) = line.strip_prefix("data: ") {
                                if let Ok(alert) = serde_json::from_str::<serde_json::Value>(data) {
                                    let severity = alert["severity"].as_str().unwrap_or("Medium");
                                    let title = alert["title"].as_str().unwrap_or("");
                                    let detail = alert["detail"].as_str().unwrap_or("");

                                    forwarder_clone.lock().unwrap()
                                        .forward_alert(severity, title, detail);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Channel closed, exit thread
                    break;
                }
            }
        }
    });

    forwarder
}
