use crate::alert::{self, Severity};
use crate::frame::FrameType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const ALERT_COOLDOWN: Duration = Duration::from_secs(15);
const STALE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_DEVICES: usize = 512;
const SCORE_DECAY_INTERVAL: Duration = Duration::from_secs(20);
const MIN_FRAMES_BEFORE_DETECTION: u32 = 10;
const ALERT_SCORE_THRESHOLD: f32 = 15.0;
const REBOOT_GAP: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SeqStream {
    Management,
    Data,
}

struct StreamState {
    last_seq: u16,
    last_seen: Instant,
    frame_count: u32,
}

struct DeviceState {
    streams: HashMap<SeqStream, StreamState>,
    anomaly_score: f32,
    last_alert: Option<Instant>,
    last_decay: Instant,
    last_activity: Instant,
    duplicate_count: u32,
    total_frames: u32,
}

pub struct SequenceAnomalyDetector {
    devices: HashMap<String, DeviceState>,
    last_prune: Instant,
}

impl SequenceAnomalyDetector {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    pub fn process(
        &mut self,
        mac: &str,
        seq: u16,
        frame_type: FrameType,
        frame_type_desc: &str,
        ssid_opt: Option<&str>,
        is_retry: bool,
        is_qos: bool,
        rssi: Option<i8>,
    ) {
        let now = Instant::now();

        if now.duration_since(self.last_prune) > Duration::from_secs(60) {
            self.prune(now);
            self.last_prune = now;
        }

        if is_retry {
            let device = self.devices.entry(mac.to_string()).or_insert_with(|| new_device(now));
            device.duplicate_count += 1;
            device.last_activity = now;

            if device.duplicate_count > 50 && device.total_frames > 100 {
                let dup_ratio = device.duplicate_count as f32 / device.total_frames as f32;
                if dup_ratio > 0.4 {
                    device.anomaly_score += 0.5;
                }
            }
            return;
        }

        let stream_key = classify_stream(frame_type, is_qos);

        let device = self.devices.entry(mac.to_string()).or_insert_with(|| new_device(now));
        device.total_frames += 1;
        device.last_activity = now;

        if now.duration_since(device.last_decay) > SCORE_DECAY_INTERVAL {
            let decay_periods = now.duration_since(device.last_decay).as_secs() / SCORE_DECAY_INTERVAL.as_secs();
            device.anomaly_score = (device.anomaly_score - decay_periods as f32 * 2.0).max(0.0);
            device.last_decay = now;
        }

        let stream = device.streams.entry(stream_key).or_insert_with(|| StreamState {
            last_seq: seq,
            last_seen: now,
            frame_count: 0,
        });

        let prev_seq = stream.last_seq;
        let elapsed = now.duration_since(stream.last_seen);
        stream.last_seq = seq;
        stream.last_seen = now;
        stream.frame_count += 1;

        if prev_seq == seq {
            return;
        }

        if stream.frame_count < MIN_FRAMES_BEFORE_DETECTION {
            return;
        }

        if elapsed > REBOOT_GAP {
            return;
        }

        let (direction, distance) = seq_distance(prev_seq, seq);

        let score_delta = match direction {
            SeqDirection::Forward => {
                if distance <= 20 {
                    0.0
                } else if distance <= 100 && elapsed < Duration::from_millis(200) {
                    0.0
                } else if distance > 1000 && elapsed < Duration::from_millis(300) {
                    let weight = (distance as f32 / 2000.0).min(3.0);
                    weight
                } else if distance > 500 && elapsed < Duration::from_millis(100) {
                    2.0
                } else {
                    0.0
                }
            }
            SeqDirection::Backward => {
                if distance <= 2 {
                    0.0
                } else if distance <= 5 && elapsed < Duration::from_millis(50) {
                    0.3
                } else if distance > 5 && elapsed < Duration::from_secs(1) {
                    let weight = (distance as f32 / 100.0).min(4.0);
                    weight
                } else {
                    0.0
                }
            }
        };

        if score_delta > 0.0 {
            device.anomaly_score += score_delta;

            if device.anomaly_score >= ALERT_SCORE_THRESHOLD {
                let should_alert = match device.last_alert {
                    None => true,
                    Some(last) => now.duration_since(last) > ALERT_COOLDOWN,
                };

                if should_alert {
                    device.last_alert = Some(now);

                    let dir_str = match direction {
                        SeqDirection::Forward => format!("+{}", distance),
                        SeqDirection::Backward => format!("-{}", distance),
                    };

                    let ssid_part = ssid_opt.map(|s| format!(" SSID: '{}'", s)).unwrap_or_default();
                    let rssi_part = rssi.map(|r| format!(" RSSI: {}dBm", r)).unwrap_or_default();

                    alert::fire(
                        Severity::High,
                        "MAC Spoofing / Sequence Anomaly Detected",
                        &format!(
                            "Device {} ({} stream){}{} — score {:.1}/{:.1}\n\
                             Latest: seq {} -> {} ({}) within {:?}\n\
                             Frames tracked: {} | Duplicates: {} | Stream: {}",
                            mac,
                            stream_name(stream_key),
                            ssid_part,
                            rssi_part,
                            device.anomaly_score,
                            ALERT_SCORE_THRESHOLD,
                            prev_seq, seq, dir_str, elapsed,
                            device.total_frames,
                            device.duplicate_count,
                            frame_type_desc,
                        ),
                    );
                }
            }
        } else if device.anomaly_score > 0.0 && distance <= 5 && direction == SeqDirection::Forward {
            device.anomaly_score = (device.anomaly_score - 0.1).max(0.0);
        }
    }

    fn prune(&mut self, now: Instant) {
        self.devices.retain(|_, d| now.duration_since(d.last_activity) < STALE_TIMEOUT);

        if self.devices.len() > MAX_DEVICES {
            let mut entries: Vec<(String, Instant)> = self.devices
                .iter()
                .map(|(k, v)| (k.clone(), v.last_activity))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let remove_count = self.devices.len() - MAX_DEVICES;
            for (key, _) in entries.into_iter().take(remove_count) {
                self.devices.remove(&key);
            }
        }
    }
}

fn new_device(now: Instant) -> DeviceState {
    DeviceState {
        streams: HashMap::new(),
        anomaly_score: 0.0,
        last_alert: None,
        last_decay: now,
        last_activity: now,
        duplicate_count: 0,
        total_frames: 0,
    }
}

fn classify_stream(frame_type: FrameType, _is_qos: bool) -> SeqStream {
    match frame_type {
        FrameType::Beacon | FrameType::ProbeRequest | FrameType::ProbeResponse
        | FrameType::Auth | FrameType::AssocRequest | FrameType::Deauth | FrameType::Disassoc => {
            SeqStream::Management
        }
        _ => SeqStream::Data,
    }
}

fn stream_name(s: SeqStream) -> &'static str {
    match s {
        SeqStream::Management => "mgmt",
        SeqStream::Data => "data",
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SeqDirection {
    Forward,
    Backward,
}

fn seq_distance(prev: u16, curr: u16) -> (SeqDirection, u16) {
    let forward = (curr as i32 - prev as i32 + 4096) % 4096;
    let backward = (prev as i32 - curr as i32 + 4096) % 4096;

    if forward <= backward {
        (SeqDirection::Forward, forward as u16)
    } else {
        (SeqDirection::Backward, backward as u16)
    }
}
