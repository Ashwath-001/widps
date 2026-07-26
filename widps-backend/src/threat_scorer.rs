use crate::alert::{self, Severity};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const ALERT_THRESHOLD: f32 = 60.0;
const CRITICAL_THRESHOLD: f32 = 85.0;
const MAX_SCORE: f32 = 100.0;
const DECAY_RATE_PER_SEC: f32 = 0.5;
const PRUNE_BELOW: f32 = 2.0;
const PRUNE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceEntry {
    pub source: String,
    pub weight: f32,
    pub description: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatProfile {
    pub bssid: String,
    pub ssid: Option<String>,
    pub score: f32,
    pub evidence: Vec<EvidenceEntry>,
    pub first_seen: String,
    pub last_updated: String,
    pub alert_count: u32,
    pub verdict: String,
}

struct InternalProfile {
    bssid: String,
    ssid: Option<String>,
    score: f32,
    evidence: Vec<EvidenceEntry>,
    first_seen: Instant,
    last_update: Instant,
    last_decay: Instant,
    alert_count: u32,
    first_seen_str: String,
}

pub struct ThreatScorer {
    profiles: HashMap<String, InternalProfile>,
    last_prune: Instant,
}

impl ThreatScorer {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    pub fn add_evidence(
        &mut self,
        bssid: &str,
        ssid: Option<&str>,
        source: &str,
        weight: f32,
        description: &str,
    ) {
        let now = Instant::now();
        let now_str = chrono::Local::now().format("%H:%M:%S").to_string();

        let profile = self.profiles.entry(bssid.to_string()).or_insert_with(|| InternalProfile {
            bssid: bssid.to_string(),
            ssid: ssid.map(|s| s.to_string()),
            score: 0.0,
            evidence: Vec::new(),
            first_seen: now,
            last_update: now,
            last_decay: now,
            alert_count: 0,
            first_seen_str: now_str.clone(),
        });

        if ssid.is_some() && profile.ssid.is_none() {
            profile.ssid = ssid.map(|s| s.to_string());
        }

        let elapsed_since_decay = now.duration_since(profile.last_decay).as_secs_f32();
        if elapsed_since_decay > 1.0 {
            let decay = elapsed_since_decay * DECAY_RATE_PER_SEC;
            profile.score = (profile.score - decay).max(0.0);
            profile.last_decay = now;
        }

        profile.score = (profile.score + weight).min(MAX_SCORE);
        profile.last_update = now;

        profile.evidence.push(EvidenceEntry {
            source: source.to_string(),
            weight,
            description: description.to_string(),
            timestamp: now_str,
        });

        if profile.evidence.len() > 20 {
            profile.evidence.remove(0);
        }

        if profile.score >= ALERT_THRESHOLD {
            let severity = if profile.score >= CRITICAL_THRESHOLD {
                Severity::Critical
            } else {
                Severity::High
            };

            profile.alert_count += 1;

            if profile.alert_count <= 3 || profile.alert_count % 5 == 0 {
                let ssid_str = profile.ssid.as_deref().unwrap_or("<unknown>");
                let top_evidence: Vec<String> = profile.evidence
                    .iter()
                    .rev()
                    .take(3)
                    .map(|e| format!("[{}] {} (+{:.0})", e.source, e.description, e.weight))
                    .collect();

                alert::fire(
                    severity,
                    "Composite Threat Score Exceeded",
                    &format!(
                        "BSSID: {} | SSID: '{}' | Score: {:.0}/100 | Alerts: {}\nEvidence:\n{}",
                        bssid,
                        ssid_str,
                        profile.score,
                        profile.alert_count,
                        top_evidence.join("\n"),
                    ),
                );
            }
        }

        if now.duration_since(self.last_prune) > PRUNE_INTERVAL {
            self.prune(now);
            self.last_prune = now;
        }
    }

    pub fn add_ml_evidence(&mut self, bssid: &str, label: &str, confidence: f64, threat_score: u32) {
        if label == "Normal" || confidence < 0.5 {
            return;
        }

        let weight = match label {
            "Deauth_Flood" => 25.0 * confidence as f32,
            "Evil_Twin" => 30.0 * confidence as f32,
            "Auth_Flood" => 20.0 * confidence as f32,
            "Krack" => 35.0 * confidence as f32,
            "Kr00k" => 25.0 * confidence as f32,
            _ => 15.0 * confidence as f32,
        };

        self.add_evidence(
            bssid,
            None,
            "ML-ONNX",
            weight,
            &format!("AI classified as {} (conf: {:.0}%, score: {})", label, confidence * 100.0, threat_score),
        );
    }

    pub fn get_score(&self, bssid: &str) -> f32 {
        self.profiles.get(bssid).map(|p| p.score).unwrap_or(0.0)
    }

    pub fn get_all_profiles(&self) -> Vec<ThreatProfile> {
        self.profiles.values()
            .filter(|p| p.score > 5.0)
            .map(|p| {
                let verdict = if p.score >= CRITICAL_THRESHOLD {
                    "CRITICAL THREAT"
                } else if p.score >= ALERT_THRESHOLD {
                    "HIGH THREAT"
                } else if p.score >= 30.0 {
                    "SUSPICIOUS"
                } else {
                    "MONITORING"
                };

                ThreatProfile {
                    bssid: p.bssid.clone(),
                    ssid: p.ssid.clone(),
                    score: p.score,
                    evidence: p.evidence.clone(),
                    first_seen: p.first_seen_str.clone(),
                    last_updated: chrono::Local::now().format("%H:%M:%S").to_string(),
                    alert_count: p.alert_count,
                    verdict: verdict.to_string(),
                }
            })
            .collect()
    }

    fn prune(&mut self, now: Instant) {
        self.profiles.retain(|_, p| {
            let elapsed = now.duration_since(p.last_update).as_secs_f32();
            let decayed_score = p.score - (elapsed * DECAY_RATE_PER_SEC);
            decayed_score > PRUNE_BELOW
        });
    }
}
