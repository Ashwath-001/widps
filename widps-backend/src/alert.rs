use chrono::Local;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use crate::sse::SharedBroadcaster;

/// JSONL mirror of alerts; tests use a per-process temp directory so they never touch the working copy.
pub fn alerts_jsonl_path() -> std::path::PathBuf {
    if cfg!(test) {
        return test_dir().join("widps_alerts.jsonl");
    }
    std::path::PathBuf::from(std::env::var("WIDPS_ALERTS_JSONL").unwrap_or_else(|_| "widps_alerts.jsonl".into()))
}

/// Where archived alerts are exported.
pub fn archive_dir() -> std::path::PathBuf {
    if cfg!(test) {
        return test_dir().join("archive");
    }
    std::path::PathBuf::from("data/archive")
}

fn test_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("widps-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    d
}



#[derive(Debug, Clone)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Serialize)]
struct AlertLine<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    detector: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bssid: Option<&'a str>,
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

#[allow(dead_code)]
pub fn fire(sev: Severity, title: &str, detail: &str) {
    fire_from("rule", None, sev, title, detail)
}

/// Raises an alert attributed to `detector`; `subject` is the BSSID or MAC it concerns.
pub fn fire_from(detector: &str, subject: Option<&str>, sev: Severity, title: &str, detail: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let sev_str = match sev {
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    };

    println!("[{}] [{}] {}\n{}\n", ts, sev_str, title, detail);

    let safe_detail = detail.replace('\n', " | ");
    let subject = subject.map(|s| s.trim().to_ascii_uppercase()).filter(|s| !s.is_empty());

    // The DB append computes the chained hash; the same timestamp is used for the row, JSONL and SSE.
    let chained = DB_HANDLE.lock().ok().and_then(|guard| {
        guard.as_ref().and_then(|db| {
            db.lock().ok().and_then(|db| db.insert_alert(&ts, sev_str, title, &safe_detail, subject.as_deref(), detector))
        })
    });
    let (id, record_hash) = match &chained {
        Some(r) => (Some(r.id), r.record_hash.as_str()),
        None => (None, ""),
    };

    let alert = AlertLine {
        id,
        detector,
        bssid: subject.as_deref(),
        time: &ts,
        severity: sev_str,
        title,
        detail: &safe_detail,
        hmac_sha256: record_hash,
    };

    let line = match serde_json::to_string(&alert) {
        Ok(json) => json,
        Err(_) => return,
    };

    let _lock = ALERT_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(alerts_jsonl_path()) {
        let _ = writeln!(f, "{}", line);
    }

    if let Ok(guard) = SSE_BROADCASTER.lock() {
        if let Some(ref broadcaster) = *guard {
            if let Ok(mut b) = broadcaster.lock() {
                b.push("alert", &line);
            }
        }
    }
}
