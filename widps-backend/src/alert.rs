use chrono::Local;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

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
}

static ALERT_FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn fire(sev: Severity, title: &str, detail: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let sev_str = match sev {
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    };

    println!("[{}] [{}] {}\n{}\n", ts, sev_str, title, detail);

    let safe_detail = detail.replace('\n', " | ");

    let alert = AlertLine {
        time: &ts,
        severity: sev_str,
        title,
        detail: &safe_detail,
    };

    let line = match serde_json::to_string(&alert) {
        Ok(json) => json,
        Err(_) => return,
    };

    let _lock = ALERT_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("widps_alerts.jsonl") {
        let _ = writeln!(f, "{}", line);
    }
}
