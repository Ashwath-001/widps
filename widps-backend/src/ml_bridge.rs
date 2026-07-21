use serde::{Deserialize, Serialize};
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
    pub reason_code: u8,
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
                for line in reader.lines() {
                    if let Ok(line) = line {
                        if let Ok(pred) = serde_json::from_str::<MlPrediction>(&line) {
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
