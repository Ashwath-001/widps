use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

static ALERT_FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn fire(sev: Severity, title: &str, detail: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("[{}] [{:?}] {}\n{}\n", ts, sev, title, detail);

    let safe_detail = detail.replace('"', "'").replace('\n', " | ");
    let line = format!(
        "{{\"time\":\"{}\",\"severity\":\"{:?}\",\"title\":\"{}\",\"detail\":\"{}\"}}",
        ts, sev, title, safe_detail
    );

    let _lock = ALERT_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("widps_alerts.jsonl") {
        let _ = writeln!(f, "{}", line);
    }
}
