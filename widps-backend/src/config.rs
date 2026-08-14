use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub channel_hopping: bool,
    pub passive_scan: bool,
    pub client_tracking: bool,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,       // 0 = keep forever, 7 or 30
    #[serde(default)]
    pub auto_archive_hours: u32,   // 0 = disabled, 24 = auto-mark-read after 24h
    #[serde(default = "default_true")]
    pub passive_blocking: bool,    // Blacklisted MACs trigger instant Critical
    #[serde(default)]
    pub client_warnings: bool,     // Notify when tracked client connects to flagged AP
}

fn default_retention_days() -> u32 { 0 }
fn default_true() -> bool { true }

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            channel_hopping: true,
            passive_scan: true,
            client_tracking: true,
            retention_days: 0,
            auto_archive_hours: 0,
            passive_blocking: true,
            client_warnings: false,
        }
    }
}

pub struct ConfigFlags {
    pub hopping_enabled: Arc<AtomicBool>,
    pub client_tracking_enabled: Arc<AtomicBool>,
    pub passive_blocking_enabled: Arc<AtomicBool>,
    pub client_warnings_enabled: Arc<AtomicBool>,
    pub retention_days: Arc<AtomicU32>,
    pub auto_archive_hours: Arc<AtomicU32>,
}

impl ConfigFlags {
    pub fn new() -> Self {
        Self {
            hopping_enabled: Arc::new(AtomicBool::new(true)),
            client_tracking_enabled: Arc::new(AtomicBool::new(true)),
            passive_blocking_enabled: Arc::new(AtomicBool::new(true)),
            client_warnings_enabled: Arc::new(AtomicBool::new(false)),
            retention_days: Arc::new(AtomicU32::new(0)),
            auto_archive_hours: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            channel_hopping: self.hopping_enabled.load(Ordering::Acquire),
            passive_scan: true,
            client_tracking: self.client_tracking_enabled.load(Ordering::Acquire),
            retention_days: self.retention_days.load(Ordering::Acquire),
            auto_archive_hours: self.auto_archive_hours.load(Ordering::Acquire),
            passive_blocking: self.passive_blocking_enabled.load(Ordering::Acquire),
            client_warnings: self.client_warnings_enabled.load(Ordering::Acquire),
        }
    }

    pub fn apply(&self, config: &RuntimeConfig) {
        self.hopping_enabled.store(config.channel_hopping, Ordering::Release);
        self.client_tracking_enabled.store(config.client_tracking, Ordering::Release);
        self.passive_blocking_enabled.store(config.passive_blocking, Ordering::Release);
        self.client_warnings_enabled.store(config.client_warnings, Ordering::Release);
        self.retention_days.store(config.retention_days, Ordering::Release);
        self.auto_archive_hours.store(config.auto_archive_hours, Ordering::Release);
    }
}
