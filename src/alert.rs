use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug, Clone)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

pub fn fire(sev: Severity, title: &str, detail: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("[{}] [{:?}] {}\n{}\n", ts, sev, title, detail);

    let safe_detail = detail.replace('"', "'").replace('\n', " | ");
    let line = format!(
        "{{\"time\":\"{}\",\"severity\":\"{:?}\",\"title\":\"{}\",\"detail\":\"{}\"}}",
        ts, sev, title, safe_detail
    );

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("widps_alerts.jsonl") {
        let _ = writeln!(f, "{}", line);
    }
}