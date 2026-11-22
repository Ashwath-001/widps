use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Serialize)]
pub struct FrameForMl {
    pub fc_type: u8,
    pub fc_subtype: u8,
    pub dst: String,
    pub src: String,
    pub rssi: i8,
    pub frame_length: u16,
    pub duration: u16,
    pub protected: u8,
    pub retry: u8,
    pub reason_code: u16,
    pub seq_num: u16,
    pub inter_frame_time: f64,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlPrediction {
    pub label: String,
    pub confidence: f64,
    pub threat_score: u32,
    pub inference_ms: f64,
    pub frame_count: u32,
    /// Monotonic id assigned by the reader thread when a prediction arrives.
    /// Lets consumers apply each prediction exactly once.
    #[serde(default)]
    pub seq: u64,
}

pub type SharedPrediction = Arc<Mutex<Option<MlPrediction>>>;

pub struct MlBridge {
    child_stdin: Option<std::process::ChildStdin>,
    pub latest_prediction: SharedPrediction,
}

impl MlBridge {
    pub fn spawn(python_path: &str, script_path: &str) -> Option<Self> {
        let mut child = match Command::new(python_path)
            .args([script_path, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ml_bridge] Failed to spawn ML process: {}", e);
                eprintln!("[ml_bridge] Ensure ml/.venv/bin/python exists and ml/inference.py is present");
                return None;
            }
        };

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let prediction: SharedPrediction = Arc::new(Mutex::new(None));
        let pred_clone = Arc::clone(&prediction);

        if let Some(stdout) = stdout {
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                let mut next_seq: u64 = 1;
                for line in reader.lines() {
                    if let Ok(line) = line {
                        if let Ok(mut pred) = serde_json::from_str::<MlPrediction>(&line) {
                            pred.seq = next_seq;
                            next_seq += 1;
                            if pred.label != "Normal" && pred.confidence > 0.7 {
                                println!(
                                    "[ML] {} (conf: {:.0}%, score: {}, frames: {})",
                                    pred.label, pred.confidence * 100.0, pred.threat_score, pred.frame_count
                                );
                            }
                            *pred_clone.lock().unwrap() = Some(pred);
                        }
                    }
                }
                eprintln!("[ml_bridge] ML process stdout closed");
            });
        }

        println!("[ml_bridge] ML inference process started successfully");

        Some(Self {
            child_stdin: stdin,
            latest_prediction: prediction,
        })
    }

    pub fn send_frame(&mut self, frame: &FrameForMl) {
        if let Some(ref mut stdin) = self.child_stdin {
            if let Ok(json) = serde_json::to_string(frame) {
                let _ = writeln!(stdin, "{}", json);
            }
        }
    }
}

/// Hands out each prediction at most once, however often it is polled.
pub struct PredictionGate {
    last_seq: u64,
}

impl PredictionGate {
    pub fn new() -> Self {
        Self { last_seq: 0 }
    }

    /// Returns the shared prediction only if it has not been returned before.
    pub fn take_new(&mut self, shared: &SharedPrediction) -> Option<MlPrediction> {
        let guard = shared.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(p) if p.seq > self.last_seq => {
                self.last_seq = p.seq;
                Some(p.clone())
            }
            _ => None,
        }
    }
}

/// Tracks which BSSID dominated the frames sent to the ML process since the
/// last prediction, so a prediction can be attributed to a device instead of
/// to whichever frame happens to be in hand when it arrives.
pub struct WindowAttribution {
    attack_frames: HashMap<String, u32>,
    all_frames: HashMap<String, u32>,
}

impl WindowAttribution {
    pub fn new() -> Self {
        Self { attack_frames: HashMap::new(), all_frames: HashMap::new() }
    }

    /// `is_attack_frame` marks frame types an attacker typically floods
    /// (deauth, disassoc, auth, association request).
    pub fn record(&mut self, bssid: &str, is_attack_frame: bool) {
        *self.all_frames.entry(bssid.to_string()).or_insert(0) += 1;
        if is_attack_frame {
            *self.attack_frames.entry(bssid.to_string()).or_insert(0) += 1;
        }
    }

    /// Returns the BSSID with the most attack frames (falling back to the most
    /// frames overall) and starts a new window. Ties break on the lowest BSSID
    /// string so results are deterministic.
    pub fn take_dominant(&mut self) -> Option<String> {
        let pick = |m: &HashMap<String, u32>| {
            m.iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                .map(|(k, _)| k.clone())
        };
        let result = pick(&self.attack_frames).or_else(|| pick(&self.all_frames));
        self.attack_frames.clear();
        self.all_frames.clear();
        result
    }
}

/// Seconds between consecutive frame timestamps (0.0 for the first frame).
pub struct InterFrameTimer {
    last_ts: Option<f64>,
}

impl InterFrameTimer {
    pub fn new() -> Self {
        Self { last_ts: None }
    }

    pub fn next(&mut self, ts: f64) -> f64 {
        let delta = match self.last_ts {
            Some(prev) if ts >= prev => ts - prev,
            _ => 0.0,
        };
        self.last_ts = Some(ts);
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(seq: u64, label: &str) -> MlPrediction {
        MlPrediction {
            label: label.to_string(),
            confidence: 0.9,
            threat_score: 80,
            inference_ms: 1.0,
            frame_count: 100,
            seq,
        }
    }

    #[test]
    fn gate_returns_each_prediction_once() {
        let shared: SharedPrediction = Arc::new(Mutex::new(None));
        let mut gate = PredictionGate::new();
        assert!(gate.take_new(&shared).is_none());

        *shared.lock().unwrap() = Some(pred(1, "Deauth_Flood"));
        assert_eq!(gate.take_new(&shared).unwrap().seq, 1);
        // Polled for the next 1,000 frames: must not be handed out again.
        for _ in 0..1000 {
            assert!(gate.take_new(&shared).is_none());
        }

        *shared.lock().unwrap() = Some(pred(2, "Evil_Twin"));
        let second = gate.take_new(&shared).unwrap();
        assert_eq!((second.seq, second.label.as_str()), (2, "Evil_Twin"));
        assert!(gate.take_new(&shared).is_none());
    }

    #[test]
    fn gate_ignores_stale_or_equal_seq() {
        let shared: SharedPrediction = Arc::new(Mutex::new(Some(pred(5, "Auth_Flood"))));
        let mut gate = PredictionGate::new();
        assert!(gate.take_new(&shared).is_some());
        *shared.lock().unwrap() = Some(pred(5, "Auth_Flood"));
        assert!(gate.take_new(&shared).is_none());
        *shared.lock().unwrap() = Some(pred(3, "Auth_Flood"));
        assert!(gate.take_new(&shared).is_none());
    }

    #[test]
    fn prediction_json_without_seq_defaults_to_zero() {
        let json = r#"{"label":"Normal","confidence":0.99,"threat_score":0,"inference_ms":1.2,"frame_count":10}"#;
        let p: MlPrediction = serde_json::from_str(json).unwrap();
        assert_eq!(p.seq, 0);
    }

    #[test]
    fn attribution_prefers_attack_frames_over_beacons() {
        let mut a = WindowAttribution::new();
        for _ in 0..500 {
            a.record("AA:AA:AA:AA:AA:AA", false); // busy legitimate AP beaconing
        }
        for _ in 0..40 {
            a.record("66:66:66:66:66:66", true); // deauth source
        }
        assert_eq!(a.take_dominant().as_deref(), Some("66:66:66:66:66:66"));
    }

    #[test]
    fn attribution_falls_back_to_busiest_bssid() {
        let mut a = WindowAttribution::new();
        for _ in 0..3 {
            a.record("11:11:11:11:11:11", false);
        }
        a.record("22:22:22:22:22:22", false);
        assert_eq!(a.take_dominant().as_deref(), Some("11:11:11:11:11:11"));
    }

    #[test]
    fn attribution_resets_after_take_and_handles_empty() {
        let mut a = WindowAttribution::new();
        assert_eq!(a.take_dominant(), None);
        a.record("11:11:11:11:11:11", true);
        assert!(a.take_dominant().is_some());
        assert_eq!(a.take_dominant(), None);
    }

    #[test]
    fn attribution_tie_break_is_deterministic() {
        for _ in 0..20 {
            let mut a = WindowAttribution::new();
            a.record("BB:BB:BB:BB:BB:BB", true);
            a.record("AA:AA:AA:AA:AA:AA", true);
            assert_eq!(a.take_dominant().as_deref(), Some("AA:AA:AA:AA:AA:AA"));
        }
    }

    #[test]
    fn inter_frame_timer_reports_deltas() {
        let mut t = InterFrameTimer::new();
        assert_eq!(t.next(100.0), 0.0);
        assert!((t.next(100.25) - 0.25).abs() < 1e-9);
        assert!((t.next(100.30) - 0.05).abs() < 1e-9);
        // Clock going backwards never yields a negative delta.
        assert_eq!(t.next(99.0), 0.0);
        assert!((t.next(99.5) - 0.5).abs() < 1e-9);
    }
}
