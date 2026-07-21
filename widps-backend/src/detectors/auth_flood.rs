use crate::alert::{self, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(5);
const THRESHOLD: u32 = 20;
const ALERT_COOLDOWN: Duration = Duration::from_secs(15);

pub struct AuthFloodDetector {
    targets: HashMap<String, TargetState>,
}

struct TargetState {
    count: u32,
    window_start: Instant,
    last_alert: Option<Instant>,
    unique_sources: Vec<String>,
}

impl AuthFloodDetector {
    pub fn new() -> Self {
        Self { targets: HashMap::new() }
    }

    pub fn process(&mut self, target_bssid: &str, source_mac: &str) {
        let now = Instant::now();
        let state = self.targets.entry(target_bssid.to_string()).or_insert_with(|| TargetState {
            count: 0,
            window_start: now,
            last_alert: None,
            unique_sources: Vec::new(),
        });

        if now.duration_since(state.window_start) > WINDOW {
            state.count = 0;
            state.window_start = now;
            state.unique_sources.clear();
        }

        state.count += 1;
        if !state.unique_sources.contains(&source_mac.to_string()) {
            state.unique_sources.push(source_mac.to_string());
        }

        if state.count >= THRESHOLD {
            let should_alert = match state.last_alert {
                None => true,
                Some(last) => now.duration_since(last) > ALERT_COOLDOWN,
            };

            if should_alert {
                state.last_alert = Some(now);
                alert::fire(
                    Severity::High,
                    "Authentication / Association Flood",
                    &format!(
                        "{} auth/assoc frames targeting BSSID {} within {:?} from {} unique sources. \
                         DoS attack against AP association table.",
                        state.count, target_bssid, WINDOW, state.unique_sources.len()
                    ),
                );
            }
        }
    }
}
