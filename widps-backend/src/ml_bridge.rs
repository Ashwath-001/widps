use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::api_server::RuntimeState;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
    #[serde(default)]
    pub seq: u64,
}

pub type SharedPrediction = Arc<Mutex<Option<MlPrediction>>>;

/// Frames waiting for the ML process; when full, frames are dropped (counted) instead of blocking capture.
pub const ML_QUEUE_CAPACITY: usize = 2048;
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const STARTUP_GRACE: Duration = Duration::from_secs(60);
const STALL_LIMIT: Duration = Duration::from_secs(30);

/// Runs the Python inference process under a supervisor: restarts with backoff, kills it if it stops answering.
pub struct MlBridge {
    tx: SyncSender<String>,
    runtime: Arc<RuntimeState>,
    pub latest_prediction: SharedPrediction,
}

enum Exit {
    Restart(&'static str),
    Shutdown,
}

impl MlBridge {
    pub fn start_python(python_path: &str, script_path: &str, runtime: Arc<RuntimeState>) -> Self {
        let (py, script) = (python_path.to_string(), script_path.to_string());
        Self::start(
            move || {
                let mut c = Command::new(&py);
                c.args([script.as_str(), "--stdin"]);
                c
            },
            runtime,
        )
    }

    /// `make_command` builds a fresh command for every (re)start.
    pub fn start<F: Fn() -> Command + Send + 'static>(make_command: F, runtime: Arc<RuntimeState>) -> Self {
        let (tx, rx) = sync_channel::<String>(ML_QUEUE_CAPACITY);
        let prediction: SharedPrediction = Arc::new(Mutex::new(None));
        let (pred, rt) = (Arc::clone(&prediction), Arc::clone(&runtime));
        let _ = thread::Builder::new()
            .name("widps-ml-supervisor".into())
            .spawn(move || supervise(make_command, rx, pred, rt));
        Self { tx, runtime, latest_prediction: prediction }
    }

    /// Never blocks: a full queue (slow or restarting ML process) drops the frame and counts it.
    pub fn send_frame(&self, frame: &FrameForMl) {
        if let Ok(json) = serde_json::to_string(frame) {
            if let Err(TrySendError::Full(_)) = self.tx.try_send(json) {
                self.runtime.note_ml_dropped();
            }
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Discards queued frames for `d` (they would be stale after a restart). False if the bridge was dropped.
fn drain_for(rx: &Receiver<String>, d: Duration) -> bool {
    let until = Instant::now() + d;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        match rx.recv_timeout(left) {
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn supervise<F: Fn() -> Command>(make_command: F, rx: Receiver<String>, pred: SharedPrediction, runtime: Arc<RuntimeState>) {
    let seq = Arc::new(AtomicU64::new(1));
    let mut backoff = Duration::from_secs(1);
    let mut first = true;
    loop {
        if !first {
            runtime.note_ml_restart();
        }
        first = false;
        let mut cmd = make_command();
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ml_bridge] cannot start ML process: {} (retrying in {:?})", e, backoff);
                runtime.set_ml_running(false);
                if !drain_for(&rx, backoff) {
                    return;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let started = Instant::now();
        runtime.set_ml_running(true);
        let last_in = Arc::new(AtomicU64::new(0));
        let last_out = Arc::new(AtomicU64::new(now_ms()));

        if let Some(stdout) = child.stdout.take() {
            let (pred, seq, last_out) = (Arc::clone(&pred), Arc::clone(&seq), Arc::clone(&last_out));
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    last_out.store(now_ms(), Ordering::Relaxed);
                    if let Ok(mut p) = serde_json::from_str::<MlPrediction>(&line) {
                        p.seq = seq.fetch_add(1, Ordering::Relaxed);
                        if p.label != "Normal" && p.confidence > 0.7 {
                            println!("[ML] {} (conf: {:.0}%, score: {}, frames: {})", p.label, p.confidence * 100.0, p.threat_score, p.frame_count);
                        }
                        *pred.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
                    }
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    eprintln!("[ml] {}", line);
                }
            });
        }

        let mut stdin = child.stdin.take();
        let child = Arc::new(Mutex::new(child));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        {
            // Watchdog: input keeps arriving but the process has produced nothing for STALL_LIMIT -> kill it.
            let (child, alive, last_in, last_out) = (Arc::clone(&child), Arc::clone(&alive), Arc::clone(&last_in), Arc::clone(&last_out));
            thread::spawn(move || {
                while alive.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(1));
                    let (i, o) = (last_in.load(Ordering::Relaxed), last_out.load(Ordering::Relaxed));
                    if started.elapsed() > STARTUP_GRACE && i > o && i - o > STALL_LIMIT.as_millis() as u64 {
                        eprintln!("[ml_bridge] ML process stalled for {:?}; killing it", STALL_LIMIT);
                        let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
                        return;
                    }
                }
            });
        }

        let exit = loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(line) => {
                    last_in.store(now_ms(), Ordering::Relaxed);
                    let w = stdin.as_mut().map(|s| writeln!(s, "{}", line));
                    if !matches!(w, Some(Ok(()))) {
                        break Exit::Restart("stdin closed");
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break Exit::Shutdown,
            }
            if let Ok(Some(status)) = child.lock().unwrap_or_else(|e| e.into_inner()).try_wait() {
                eprintln!("[ml_bridge] ML process exited ({})", status);
                break Exit::Restart("exited");
            }
        };
        alive.store(false, Ordering::Relaxed);
        drop(stdin.take());
        {
            let mut c = child.lock().unwrap_or_else(|e| e.into_inner());
            let _ = c.kill();
            let _ = c.wait();
        }
        runtime.set_ml_running(false);
        match exit {
            Exit::Shutdown => return,
            Exit::Restart(why) => {
                if started.elapsed() > STARTUP_GRACE {
                    backoff = Duration::from_secs(1);
                }
                eprintln!("[ml_bridge] restarting ML process ({}) in {:?}", why, backoff);
                if !drain_for(&rx, backoff) {
                    return;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
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

/// Tracks which BSSID dominated the frames sent to the ML process since the last prediction, so a...
pub struct WindowAttribution {
    attack_frames: HashMap<String, u32>,
    all_frames: HashMap<String, u32>,
}

impl WindowAttribution {
    pub fn new() -> Self {
        Self { attack_frames: HashMap::new(), all_frames: HashMap::new() }
    }

    /// `is_attack_frame` marks frame types an attacker typically floods (deauth, disassoc, auth...
    pub fn record(&mut self, bssid: &str, is_attack_frame: bool) {
        *self.all_frames.entry(bssid.to_string()).or_insert(0) += 1;
        if is_attack_frame {
            *self.attack_frames.entry(bssid.to_string()).or_insert(0) += 1;
        }
    }

    /// Returns the BSSID with the most attack frames (falling back to the most frames overall) and starts...
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

    fn frame() -> FrameForMl {
        FrameForMl {
            fc_type: 0, fc_subtype: 12, dst: "ff:ff:ff:ff:ff:ff".into(), src: "aa:bb:cc:dd:ee:ff".into(), rssi: -50,
            frame_length: 26, duration: 0, protected: 0, retry: 0, reason_code: 7, seq_num: 1, inter_frame_time: 0.01, timestamp: 1.0,
        }
    }

    fn sh(script: &'static str) -> impl Fn() -> Command + Send + 'static {
        move || {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        }
    }

    #[test]
    fn supervisor_restarts_a_process_that_exits() {
        let rt = Arc::new(RuntimeState::new("wlan1mon"));
        // Answers one frame with a prediction, then exits.
        let bridge = MlBridge::start(sh(r#"read l; echo '{"label":"Deauth_Flood","confidence":0.9,"threat_score":80,"inference_ms":1.0,"frame_count":5}'"#), Arc::clone(&rt));
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut max_seq = 0;
        while Instant::now() < deadline && max_seq < 2 {
            bridge.send_frame(&frame());
            thread::sleep(Duration::from_millis(100));
            max_seq = bridge.latest_prediction.lock().unwrap().as_ref().map(|p| p.seq).unwrap_or(0);
        }
        assert!(max_seq >= 2, "a second prediction must arrive from a restarted process (seq {})", max_seq);
        assert!(rt.pipeline_stats().ml_restarts >= 1);
    }

    #[test]
    fn slow_ml_process_never_blocks_the_sender() {
        let rt = Arc::new(RuntimeState::new("wlan1mon"));
        let bridge = MlBridge::start(sh("sleep 3"), Arc::clone(&rt));
        thread::sleep(Duration::from_millis(200));
        let start = Instant::now();
        for _ in 0..20_000 {
            bridge.send_frame(&frame());
        }
        assert!(start.elapsed() < Duration::from_secs(2), "send_frame blocked: {:?}", start.elapsed());
        assert!(rt.pipeline_stats().ml_dropped > 0);
    }

    #[test]
    fn missing_interpreter_reports_not_running() {
        let rt = Arc::new(RuntimeState::new("wlan1mon"));
        let bridge = MlBridge::start(|| Command::new("/nonexistent/widps-python"), Arc::clone(&rt));
        thread::sleep(Duration::from_millis(300));
        assert!(!rt.ml_running());
        let start = Instant::now();
        for _ in 0..5_000 {
            bridge.send_frame(&frame());
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

