use crate::alert::{self, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const FLOOD_WINDOW: Duration = Duration::from_secs(5);
const FLOOD_THRESHOLD: u32 = 30;
const PROBE_ALERT_INTERVAL: Duration = Duration::from_secs(15);

struct DeviceProbeState {
    count: u32,
    window_start: Instant,
    last_alert: Option<Instant>,
}

pub struct ProbeFloodDetector {
    devices: HashMap<String, DeviceProbeState>,
}

impl ProbeFloodDetector {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    pub fn process(&mut self, mac: &str, ssid: &str) {
        let now = Instant::now();
        let entry = self.devices.entry(mac.to_string()).or_insert_with(|| DeviceProbeState {
            count: 0,
            window_start: now,
            last_alert: None,
        });

        if now.duration_since(entry.window_start) > FLOOD_WINDOW {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count >= FLOOD_THRESHOLD {
            let should_alert = match entry.last_alert {
                None => true,
                Some(last) => now.duration_since(last) > PROBE_ALERT_INTERVAL,
            };

            if should_alert {
                entry.last_alert = Some(now);
                alert::fire(
                    Severity::Medium,
                    "Probe Request Flood / Reconnaissance",
                    &format!(
                        "Device MAC {} sent {} Probe Requests within {:?} (latest requested SSID: '{}'). Possible network reconnaissance or scanner.",
                        mac, entry.count, FLOOD_WINDOW, ssid
                    ),
                );
            }
        }
    }
}
