//! ==========================================================================
//! WIDPS Structured Logging System (Enterprise/Microservice Style)
//! ==========================================================================
//!
//! Implements structured JSON logging following the ECS (Elastic Common Schema)
//! pattern used by enterprise microservices. Every log entry is a self-contained
//! JSON object with:
//!
//! - timestamp (ISO 8601)
//! - level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
//! - service (which module/component produced the log)
//! - message (human-readable text)
//! - fields (arbitrary key-value context)
//! - trace_id (optional, for request tracing)
//! - span_id (optional, for sub-operations)
//!
//! Output destinations:
//! - stdout (for container/systemd journal capture)
//! - File rotation (data/logs/widps-YYYY-MM-DD.jsonl)
//! - Optional syslog forwarding (for SIEM integration)
//!
//! This replaces scattered println! calls with a unified, queryable, parseable
//! log format that Wazuh/ELK/Splunk can ingest directly.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

const LOG_DIR: &str = "data/logs";
const MAX_LOG_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50 MB per file

// ---------------------------------------------------------------------------
// Log Levels
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
            Level::Fatal => "FATAL",
        }
    }
}

// ---------------------------------------------------------------------------
// Log Entry
// ---------------------------------------------------------------------------
#[derive(Debug, serde::Serialize)]
struct LogEntry<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    level: &'a str,
    service: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    fields: std::collections::HashMap<&'a str, serde_json::Value>,
    host: &'a str,
    pid: u32,
}

// ---------------------------------------------------------------------------
// Global Logger
// ---------------------------------------------------------------------------
static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub struct Logger {
    min_level: Level,
    hostname: String,
    pid: u32,
    current_file: Option<String>,
    stdout_enabled: bool,
    file_enabled: bool,
}

impl Logger {
    fn new(min_level: Level) -> Self {
        let _ = fs::create_dir_all(LOG_DIR);

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "widps-sensor".to_string());

        Self {
            min_level,
            hostname,
            pid: std::process::id(),
            current_file: None,
            stdout_enabled: true,
            file_enabled: true,
        }
    }

    fn log_file_path() -> String {
        let date = chrono::Local::now().format("%Y-%m-%d").to_string();
        format!("{}/widps-{}.jsonl", LOG_DIR, date)
    }

    fn write_entry(&mut self, entry: &str) {
        if self.stdout_enabled {
            println!("{}", entry);
        }

        if self.file_enabled {
            let path = Self::log_file_path();

            // Rotate if file too large
            if let Ok(meta) = fs::metadata(&path) {
                if meta.len() > MAX_LOG_SIZE_BYTES {
                    let rotated = format!("{}.1", path);
                    let _ = fs::rename(&path, &rotated);
                }
            }

            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
                let _ = writeln!(f, "{}", entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the global logger. Call once at startup.
pub fn init(min_level: Level) {
    let logger = Logger::new(min_level);
    *LOGGER.lock().unwrap() = Some(logger);
}

/// Core log function. Use the macros below for convenience.
pub fn log(level: Level, service: &str, message: &str, fields: &[(&str, serde_json::Value)]) {
    let mut guard = LOGGER.lock().unwrap();
    let logger = match guard.as_mut() {
        Some(l) => l,
        None => return, // Logger not initialized
    };

    if level < logger.min_level {
        return;
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();

    let fields_map: std::collections::HashMap<&str, serde_json::Value> =
        fields.iter().cloned().collect();

    let entry = LogEntry {
        timestamp,
        level: level.as_str(),
        service,
        message,
        trace_id: None,
        span_id: None,
        duration_ms: None,
        fields: fields_map,
        host: &logger.hostname,
        pid: logger.pid,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        logger.write_entry(&json);
    }
}

/// Log with a duration measurement (for timing operations)
pub fn log_timed(level: Level, service: &str, message: &str, started: Instant, fields: &[(&str, serde_json::Value)]) {
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut guard = LOGGER.lock().unwrap();
    let logger = match guard.as_mut() {
        Some(l) => l,
        None => return,
    };

    if level < logger.min_level {
        return;
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();

    let fields_map: std::collections::HashMap<&str, serde_json::Value> =
        fields.iter().cloned().collect();

    let entry = LogEntry {
        timestamp,
        level: level.as_str(),
        service,
        message,
        trace_id: None,
        span_id: None,
        duration_ms: Some(duration_ms),
        fields: fields_map,
        host: &logger.hostname,
        pid: logger.pid,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        logger.write_entry(&json);
    }
}

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------

#[macro_export]
macro_rules! log_info {
    ($service:expr, $msg:expr) => {
        $crate::logger::log($crate::logger::Level::Info, $service, $msg, &[])
    };
    ($service:expr, $msg:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::logger::log($crate::logger::Level::Info, $service, $msg, &[$(($key, serde_json::json!($val))),+])
    };
}

#[macro_export]
macro_rules! log_warn {
    ($service:expr, $msg:expr) => {
        $crate::logger::log($crate::logger::Level::Warn, $service, $msg, &[])
    };
    ($service:expr, $msg:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::logger::log($crate::logger::Level::Warn, $service, $msg, &[$(($key, serde_json::json!($val))),+])
    };
}

#[macro_export]
macro_rules! log_error {
    ($service:expr, $msg:expr) => {
        $crate::logger::log($crate::logger::Level::Error, $service, $msg, &[])
    };
    ($service:expr, $msg:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::logger::log($crate::logger::Level::Error, $service, $msg, &[$(($key, serde_json::json!($val))),+])
    };
}

#[macro_export]
macro_rules! log_debug {
    ($service:expr, $msg:expr) => {
        $crate::logger::log($crate::logger::Level::Debug, $service, $msg, &[])
    };
    ($service:expr, $msg:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::logger::log($crate::logger::Level::Debug, $service, $msg, &[$(($key, serde_json::json!($val))),+])
    };
}

#[macro_export]
macro_rules! log_trace {
    ($service:expr, $msg:expr) => {
        $crate::logger::log($crate::logger::Level::Trace, $service, $msg, &[])
    };
    ($service:expr, $msg:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::logger::log($crate::logger::Level::Trace, $service, $msg, &[$(($key, serde_json::json!($val))),+])
    };
}
