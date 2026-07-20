use crate::alert::{self, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MIN_ALERT_INTERVAL: Duration = Duration::from_secs(10);

struct DeviceSeqState {
    last_seq: u16,
    last_seen: Instant,
    anomaly_count: u32,
    last_alert: Option<Instant>,
}

pub struct SequenceAnomalyDetector {
    devices: HashMap<String, DeviceSeqState>,
}

impl SequenceAnomalyDetector {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    pub fn process(&mut self, mac: &str, seq: u16, frame_type_desc: &str, ssid_opt: Option<&str>) {
        let now = Instant::now();
        let entry = self.devices.entry(mac.to_string()).or_insert_with(|| DeviceSeqState {
            last_seq: seq,
            last_seen: now,
            anomaly_count: 0,
            last_alert: None,
        });

        let elapsed = now.duration_since(entry.last_seen);
        entry.last_seen = now;

        let prev = entry.last_seq;
        entry.last_seq = seq;

        if prev == seq {
            return;
        }

        let diff_forward = (seq as i32 - prev as i32 + 4096) % 4096;
        let diff_backward = (prev as i32 - seq as i32 + 4096) % 4096;

        let mut anomaly = false;
        let mut reason = String::new();

        if elapsed < Duration::from_secs(5) {
            if diff_backward > 0 && diff_backward < 200 {
                anomaly = true;
                reason = format!(
                    "Sequence number went backwards from {} to {} (diff: -{}) in {:?}",
                    prev, seq, diff_backward, elapsed
                );
            } else if diff_forward > 500 && diff_forward < 3500 {
                anomaly = true;
                reason = format!(
                    "Sequence number jumped forward from {} to {} (diff: +{}) in {:?}",
                    prev, seq, diff_forward, elapsed
                );
            }
        }

        if anomaly {
            entry.anomaly_count += 1;
            if entry.anomaly_count >= 3 {
                let should_alert = match entry.last_alert {
                    None => true,
                    Some(last) => now.duration_since(last) > MIN_ALERT_INTERVAL,
                };

                if should_alert {
                    entry.last_alert = Some(now);
                    let ssid_desc = ssid_opt.map(|s| format!(" (SSID: '{}')", s)).unwrap_or_default();
                    alert::fire(
                        Severity::High,
                        "MAC Spoofing / Sequence Anomaly Detected",
                        &format!(
                            "Device MAC {} {} exhibits severe sequence number anomalies ({}) during {}.
Reason: {}
Total anomalies tracked for this device: {}",
                            mac, ssid_desc, frame_type_desc, frame_type_desc, reason, entry.anomaly_count
                        ),
                    );
                }
            }
        } else {
            if entry.anomaly_count > 0 && diff_forward < 10 {
                entry.anomaly_count -= 1;
            }
        }
    }
}
