use crate::alert::{self, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(1);
const THRESHOLD: u32 = 50;
const ALERT_COOLDOWN: Duration = Duration::from_secs(10);

pub struct BeaconFloodDetector {
    counts: HashMap<String, BssidState>,
}

struct BssidState {
    count: u32,
    window_start: Instant,
    last_alert: Option<Instant>,
}

impl BeaconFloodDetector {
    pub fn new() -> Self {
        Self { counts: HashMap::new() }
    }

    pub fn process(&mut self, bssid: &str, ssid: &str) {
        let now = Instant::now();
        let state = self.counts.entry(bssid.to_string()).or_insert_with(|| BssidState {
            count: 0,
            window_start: now,
            last_alert: None,
        });

        if now.duration_since(state.window_start) > WINDOW {
            state.count = 0;
            state.window_start = now;
        }

        state.count += 1;

        if state.count >= THRESHOLD {
            let should_alert = match state.last_alert {
                None => true,
                Some(last) => now.duration_since(last) > ALERT_COOLDOWN,
            };

            if should_alert {
                state.last_alert = Some(now);
                alert::fire(
                    Severity::High,
                    "Beacon Flood Detected",
                    &format!(
                        "BSSID {} is transmitting {} beacons/sec (SSID: '{}') - \
                         legitimate APs send ~10/sec. This jams client association tables.",
                        bssid, state.count, ssid
                    ),
                );
            }
        }
    }
}
