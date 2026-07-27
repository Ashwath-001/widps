use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub channel_hopping: bool,
    pub passive_scan: bool,
    pub client_tracking: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            channel_hopping: true,
            passive_scan: true,
            client_tracking: true,
        }
    }
}

pub struct ConfigFlags {
    pub hopping_enabled: Arc<AtomicBool>,
    pub client_tracking_enabled: Arc<AtomicBool>,
}

impl ConfigFlags {
    pub fn new() -> Self {
        Self {
            hopping_enabled: Arc::new(AtomicBool::new(true)),
            client_tracking_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            channel_hopping: self.hopping_enabled.load(Ordering::Acquire),
            passive_scan: true,
            client_tracking: self.client_tracking_enabled.load(Ordering::Acquire),
        }
    }

    pub fn apply(&self, config: &RuntimeConfig) {
        self.hopping_enabled.store(config.channel_hopping, Ordering::Release);
        self.client_tracking_enabled.store(config.client_tracking, Ordering::Release);
    }
}
