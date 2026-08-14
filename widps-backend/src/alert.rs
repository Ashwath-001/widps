use chrono::Local;
use hmac::{Hmac, Mac};
use hex;
use serde::Serialize;
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use crate::sse::SharedBroadcaster;

type HmacSha256 = Hmac<Sha256>;


const HMAC_KEY: &[u8] = b"widps-tamper-evident-audit-2025-secret";

#[derive(Debug, Clone)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Serialize)]
struct AlertLine<'a> {
    time: &'a str,
    severity: &'a str,
    title: &'a str,
    detail: &'a str,
    hmac_sha256: &'a str,
}

static ALERT_FILE_LOCK: Mutex<()> = Mutex::new(());
static SSE_BROADCASTER: Mutex<Option<SharedBroadcaster>> = Mutex::new(None);
static DB_HANDLE: Mutex<Option<crate::db::SharedDb>> = Mutex::new(None);

pub fn set_broadcaster(broadcaster: SharedBroadcaster) {
    *SSE_BROADCASTER.lock().unwrap() = Some(broadcaster);
}

pub fn set_database(db: crate::db::SharedDb) {
    *DB_HANDLE.lock().unwrap() = Some(db);
}

fn sign_alert(time: &str, severity: &str, title: &str, detail: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(HMAC_KEY)
        .expect("HMAC can take key of any size");
    mac.update(time.as_bytes());
    mac.update(b"|");
    mac.update(severity.as_bytes());
    mac.update(b"|");
    mac.update(title.as_bytes());
    mac.update(b"|");
    mac.update(detail.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

pub fn verify_alert_signature(time: &str, severity: &str, title: &str, detail: &str, signature: &str) -> bool {
    let expected = sign_alert(time, severity, title, detail);
    expected == signature
}

pub fn fire(sev: Severity, title: &str, detail: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let sev_str = match sev {
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    };

    println!("[{}] [{}] {}\n{}\n", ts, sev_str, title, detail);

    let safe_detail = detail.replace('\n', " | ");

    let signature = sign_alert(&ts, sev_str, title, &safe_detail);

    let alert = AlertLine {
        time: &ts,
        severity: sev_str,
        title,
        detail: &safe_detail,
        hmac_sha256: &signature,
    };

    let line = match serde_json::to_string(&alert) {
        Ok(json) => json,
        Err(_) => return,
    };

    let _lock = ALERT_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("widps_alerts.jsonl") {
        let _ = writeln!(f, "{}", line);
    }

    if let Ok(guard) = SSE_BROADCASTER.lock() {
        if let Some(ref broadcaster) = *guard {
            if let Ok(mut b) = broadcaster.lock() {
                b.push("alert", &line);
            }
        }
    }

    if let Ok(guard) = DB_HANDLE.lock() {
        if let Some(ref db) = *guard {
            if let Ok(db) = db.lock() {
                db.insert_alert(sev_str, title, &safe_detail, None, "rule", Some(&signature));
            }
        }
    }
}
