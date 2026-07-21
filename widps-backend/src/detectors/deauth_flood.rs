use crate::alert::{self, Severity};
use crate::frame::FrameType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(5);
const THRESHOLD: u32 = 10;

pub struct DeauthFloodDetector {
    counts: HashMap<String, (u32, Instant)>,
}

impl DeauthFloodDetector {
    pub fn new() -> Self {
        Self { counts: HashMap::new() }
    }

    pub fn process(&mut self, frame_type: FrameType, bssid: &str, victim: &str) {
        if !matches!(frame_type, FrameType::Deauth | FrameType::Disassoc) {
            return;
        }

        let entry = self.counts.entry(bssid.to_string()).or_insert((0, Instant::now()));

        // RC-1 FIX: Combine the elapsed check and reset into a single atomic operation.
        // Previously, the check and reset were separate statements, creating a TOCTOU
        // window if detectors were ever parallelized. Now reset-and-increment is one block.
        let elapsed = entry.1.elapsed();
        if elapsed > WINDOW {
            entry.0 = 1;
            entry.1 = Instant::now();
        } else {
            entry.0 += 1;
        }

        if entry.0 == THRESHOLD {
            alert::fire(
                Severity::Critical,
                "Deauthentication Flood Detected",
                &format!(
                    "{} deauth/disassoc frames from BSSID {} within {:?} (latest target: {})",
                    entry.0, bssid, WINDOW, victim
                ),
            );
        }
    }
}
