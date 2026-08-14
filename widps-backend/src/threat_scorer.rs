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


const CORRELATION_WINDOW_SEC: f32 = 10.0;
const CORRELATION_MULTIPLIER: f32 = 1.5;
const CORRELATION_MIN_SOURCES: usize = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CvssSeverity {
    None,       // 0.0
    Low,        // 0.1 - 3.9
    Medium,     // 4.0 - 6.9
    High,       // 7.0 - 8.9
    Critical,   // 9.0 - 10.0
}

impl CvssSeverity {
    pub fn from_score(score: f32) -> Self {
        let normalized = score / 10.0; // our 0-100 → CVSS 0-10
        match normalized {
            s if s >= 9.0 => CvssSeverity::Critical,
            s if s >= 7.0 => CvssSeverity::High,
            s if s >= 4.0 => CvssSeverity::Medium,
            s if s >= 0.1 => CvssSeverity::Low,
            _ => CvssSeverity::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CvssSeverity::None => "NONE",
            CvssSeverity::Low => "LOW",
            CvssSeverity::Medium => "MEDIUM",
            CvssSeverity::High => "HIGH",
            CvssSeverity::Critical => "CRITICAL",
        }
    }
}


fn source_weight_multiplier(source: &str) -> f32 {
    match source {
        "ML-ONNX" => 1.8,               // ML has high confidence
        "deauth_detector" => 1.4,        // direct attack indicator
        "rogue_ap" => 1.6,               // dangerous
        "karma_detector" => 1.3,         // active attack
        "fingerprint" => 2.0,            // hardware-level evidence
        "auth_flood" => 1.2,             // DoS attempt
        "sequence_anomaly" => 1.5,       // MAC spoofing indicator
        "beacon_flood" => 1.1,           // noisy but less targeted
        "probe_flood" => 1.0,            // recon activity
        "isolation_forest" => 1.7,       // zero-day anomaly
        "behavioral_profiler" => 1.4,    // long-term deviation
        "honeypot" => 2.5,              // definitive attacker proof
        "cert_mismatch" => 2.2,          // evil twin confirmed
        _ => 1.0,
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------
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
    pub cvss_severity: CvssSeverity,
    pub cvss_score: f32,
    pub evidence: Vec<EvidenceEntry>,
    pub first_seen: String,
    pub last_updated: String,
    pub alert_count: u32,
    pub verdict: String,
    pub correlation_active: bool,
    pub distinct_sources: Vec<String>,
    pub attack_vector: String,
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
    // Correlation tracking
    recent_sources: Vec<(String, Instant)>,
}

impl InternalProfile {
    fn distinct_recent_sources(&self, now: Instant, window_sec: f32) -> Vec<String> {
        let mut sources: Vec<String> = self.recent_sources.iter()
            .filter(|(_, t)| now.duration_since(*t).as_secs_f32() < window_sec)
            .map(|(s, _)| s.clone())
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }

    fn is_correlated(&self, now: Instant) -> bool {
        self.distinct_recent_sources(now, CORRELATION_WINDOW_SEC).len() >= CORRELATION_MIN_SOURCES
    }

    fn primary_attack_vector(&self) -> String {
        let mut source_weights: HashMap<String, f32> = HashMap::new();
        for ev in &self.evidence {
            *source_weights.entry(ev.source.clone()).or_insert(0.0) += ev.weight;
        }
        source_weights.into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(s, _)| s)
            .unwrap_or_else(|| "unknown".to_string())
    }
}

// ---------------------------------------------------------------------------
// ThreatScorer
// ---------------------------------------------------------------------------
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
            recent_sources: Vec::new(),
        });

        if ssid.is_some() && profile.ssid.is_none() {
            profile.ssid = ssid.map(|s| s.to_string());
        }

        // Apply time-based decay
        let elapsed_since_decay = now.duration_since(profile.last_decay).as_secs_f32();
        if elapsed_since_decay > 1.0 {
            let decay = elapsed_since_decay * DECAY_RATE_PER_SEC;
            profile.score = (profile.score - decay).max(0.0);
            profile.last_decay = now;
        }

        // Apply source weight multiplier
        let multiplier = source_weight_multiplier(source);
        let effective_weight = weight * multiplier;

        // Track source for correlation
        profile.recent_sources.push((source.to_string(), now));
        // Prune old source entries
        profile.recent_sources.retain(|(_, t)| now.duration_since(*t).as_secs_f32() < CORRELATION_WINDOW_SEC * 2.0);

        // Apply correlation bonus if multiple attack types converge
        let correlation_bonus = if profile.is_correlated(now) {
            CORRELATION_MULTIPLIER
        } else {
            1.0
        };

        let final_weight = effective_weight * correlation_bonus;
        profile.score = (profile.score + final_weight).min(MAX_SCORE);
        profile.last_update = now;

        profile.evidence.push(EvidenceEntry {
            source: source.to_string(),
            weight: final_weight,
            description: description.to_string(),
            timestamp: now_str,
        });

        // Keep evidence buffer bounded
        if profile.evidence.len() > 30 {
            profile.evidence.remove(0);
        }

        // Fire alert if threshold crossed
        if profile.score >= ALERT_THRESHOLD {
            let severity = if profile.score >= CRITICAL_THRESHOLD {
                Severity::Critical
            } else {
                Severity::High
            };

            profile.alert_count += 1;

            // Rate-limit alert output: first 3, then every 5th
            if profile.alert_count <= 3 || profile.alert_count % 5 == 0 {
                let ssid_str = profile.ssid.as_deref().unwrap_or("<unknown>");
                let cvss = CvssSeverity::from_score(profile.score);
                let distinct = profile.distinct_recent_sources(now, CORRELATION_WINDOW_SEC);
                let correlated = distinct.len() >= CORRELATION_MIN_SOURCES;

                let top_evidence: Vec<String> = profile.evidence
                    .iter()
                    .rev()
                    .take(3)
                    .map(|e| format!("[{}] {} (+{:.0})", e.source, e.description, e.weight))
                    .collect();

                let correlation_note = if correlated {
                    format!("\n⚠ CORRELATED ATTACK: {} distinct sources ({}) within {}s window",
                        distinct.len(),
                        distinct.join(", "),
                        CORRELATION_WINDOW_SEC,
                    )
                } else {
                    String::new()
                };

                alert::fire(
                    severity,
                    "Composite Threat Score Exceeded",
                    &format!(
                        "BSSID: {} | SSID: '{}' | Score: {:.0}/100 | CVSS: {} ({:.1}) | Alerts: {}{}\nEvidence:\n{}",
                        bssid,
                        ssid_str,
                        profile.score,
                        cvss.as_str(),
                        profile.score / 10.0,
                        profile.alert_count,
                        correlation_note,
                        top_evidence.join("\n"),
                    ),
                );
            }
        }

        // Periodic pruning
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
        let now = Instant::now();
        self.profiles.values()
            .filter(|p| p.score > 5.0)
            .map(|p| {
                let cvss = CvssSeverity::from_score(p.score);
                let distinct = p.distinct_recent_sources(now, CORRELATION_WINDOW_SEC);
                let correlated = distinct.len() >= CORRELATION_MIN_SOURCES;

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
                    cvss_severity: cvss,
                    cvss_score: p.score / 10.0,
                    evidence: p.evidence.clone(),
                    first_seen: p.first_seen_str.clone(),
                    last_updated: chrono::Local::now().format("%H:%M:%S").to_string(),
                    alert_count: p.alert_count,
                    verdict: verdict.to_string(),
                    correlation_active: correlated,
                    distinct_sources: distinct,
                    attack_vector: p.primary_attack_vector(),
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
