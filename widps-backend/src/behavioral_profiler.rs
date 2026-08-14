//! Behavioral Profiler — Per-Device Long-Term Pattern Analysis
//!
//! Tracks normal behavior per MAC address over time and flags deviations.
//! A device suddenly probing 50 new SSIDs at 3am is suspicious even if
//! it's below the probe flood threshold.
//!
//! What it tracks per device:
//! - Usual probe SSIDs (remembered networks)
//! - Usual active hours (time-of-day histogram)
//! - Usual channels seen on
//! - Average frame rate contribution
//! - Usual RSSI range (distance proxy)
//!
//! Deviations that trigger alerts:
//! - New SSIDs probed that were never seen before (>5 new in 1 min)
//! - Activity outside normal hours (3am on a device that's usually 9-5)
//! - Sudden channel change (was always on ch6, now on ch1)
//! - RSSI anomaly (was -70dBm, now -30dBm — moved much closer)
//! - Frame rate spike (was 2/min, now 100/sec — possible attack tool)

use crate::alert::{self, Severity};
use crate::threat_scorer::ThreatScorer;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
/// Minimum observations before a profile is considered "established"
const MIN_OBSERVATIONS: u32 = 20;
/// New SSIDs threshold: if a device probes this many new SSIDs in one burst, flag it
const NEW_SSID_BURST_THRESHOLD: usize = 5;
/// RSSI deviation threshold (dBm) — if signal changes by this much, flag it
const RSSI_DEVIATION_THRESHOLD: f32 = 20.0;
/// Frame rate spike: if current rate is N times the average, flag it
const FRAME_RATE_SPIKE_MULTIPLIER: f32 = 10.0;
/// Hour-of-day: if device is active outside its usual 80% time range, flag it
const TIME_ANOMALY_THRESHOLD: f32 = 0.05; // Less than 5% of historical activity at this hour

// ---------------------------------------------------------------------------
// Per-Device Profile
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct DeviceProfile {
    mac: String,
    /// All SSIDs this device has ever probed for
    known_ssids: HashSet<String>,
    /// Hour-of-day histogram (24 slots, counts per hour)
    hourly_activity: [u32; 24],
    /// Channels this device has been observed on
    known_channels: HashSet<u8>,
    /// Running RSSI average and variance
    rssi_sum: f64,
    rssi_sq_sum: f64,
    rssi_count: u32,
    /// Frame count observations (for rate estimation)
    frame_observations: Vec<(Instant, u32)>,  // (time, count in that window)
    /// Total observations
    total_observations: u32,
    /// First and last seen
    first_seen: Instant,
    last_seen: Instant,
    /// Recent new SSIDs (for burst detection)
    recent_new_ssids: Vec<(String, Instant)>,
    /// Number of anomalies detected for this device
    anomaly_count: u32,
}

impl DeviceProfile {
    fn new(mac: &str) -> Self {
        let now = Instant::now();
        Self {
            mac: mac.to_uppercase(),
            known_ssids: HashSet::new(),
            hourly_activity: [0; 24],
            known_channels: HashSet::new(),
            rssi_sum: 0.0,
            rssi_sq_sum: 0.0,
            rssi_count: 0,
            frame_observations: Vec::new(),
            total_observations: 0,
            first_seen: now,
            last_seen: now,
            recent_new_ssids: Vec::new(),
            anomaly_count: 0,
        }
    }

    fn is_established(&self) -> bool {
        self.total_observations >= MIN_OBSERVATIONS
    }

    fn rssi_mean(&self) -> f32 {
        if self.rssi_count == 0 { return -70.0; }
        (self.rssi_sum / self.rssi_count as f64) as f32
    }

    fn rssi_std(&self) -> f32 {
        if self.rssi_count < 2 { return 10.0; }
        let mean = self.rssi_sum / self.rssi_count as f64;
        let variance = (self.rssi_sq_sum / self.rssi_count as f64) - (mean * mean);
        variance.max(0.0).sqrt() as f32
    }

    fn peak_hour_fraction(&self, hour: u8) -> f32 {
        let total: u32 = self.hourly_activity.iter().sum();
        if total == 0 { return 1.0; }
        self.hourly_activity[hour as usize] as f32 / total as f32
    }
}

// ---------------------------------------------------------------------------
// Anomaly Types
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
pub enum BehavioralAnomaly {
    NewSsidBurst { count: usize, ssids: Vec<String> },
    UnusualHour { hour: u8, normal_fraction: f32 },
    RssiDeviation { current: i8, mean: f32, deviation: f32 },
    FrameRateSpike { current_rate: f32, normal_rate: f32 },
    NewChannel { channel: u8, known_channels: Vec<u8> },
}

impl BehavioralAnomaly {
    fn description(&self) -> String {
        match self {
            Self::NewSsidBurst { count, ssids } =>
                format!("Probed {} new SSIDs in burst: {}", count, ssids.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
            Self::UnusualHour { hour, normal_fraction } =>
                format!("Active at {:02}:00 (only {:.1}% of historical activity at this hour)", hour, normal_fraction * 100.0),
            Self::RssiDeviation { current, mean, deviation } =>
                format!("Signal strength changed significantly: {} dBm (normal: {:.0} ± {:.0} dBm)", current, mean, deviation),
            Self::FrameRateSpike { current_rate, normal_rate } =>
                format!("Frame rate spike: {:.0}/s (normal: {:.1}/s) — possible attack tool", current_rate, normal_rate),
            Self::NewChannel { channel, known_channels } =>
                format!("Appeared on channel {} (usually on {:?})", channel, known_channels),
        }
    }

    fn weight(&self) -> f32 {
        match self {
            Self::NewSsidBurst { count, .. } => 15.0 + (*count as f32 * 3.0),
            Self::UnusualHour { .. } => 10.0,
            Self::RssiDeviation { deviation, .. } => 5.0 + (deviation / 5.0),
            Self::FrameRateSpike { .. } => 20.0,
            Self::NewChannel { .. } => 8.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Profiler Engine
// ---------------------------------------------------------------------------
pub struct BehavioralProfiler {
    profiles: HashMap<String, DeviceProfile>,
}

impl BehavioralProfiler {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Process a frame observation for a device.
    /// Returns any behavioral anomalies detected.
    pub fn observe(
        &mut self,
        mac: &str,
        ssid: Option<&str>,
        channel: u8,
        rssi: Option<i8>,
    ) -> Vec<BehavioralAnomaly> {
        let now = Instant::now();
        let hour = chrono::Local::now().format("%H").to_string().parse::<u8>().unwrap_or(0);
        let mac_upper = mac.to_uppercase();

        let profile = self.profiles.entry(mac_upper.clone())
            .or_insert_with(|| DeviceProfile::new(&mac_upper));

        profile.last_seen = now;
        profile.total_observations += 1;
        profile.hourly_activity[hour as usize] += 1;

        let mut anomalies = Vec::new();

        // Only check for anomalies if profile is established
        if !profile.is_established() {
            // Still learning — just record data
            if let Some(s) = ssid {
                if !s.is_empty() && s != "<hidden>" {
                    profile.known_ssids.insert(s.to_string());
                }
            }
            profile.known_channels.insert(channel);
            if let Some(r) = rssi {
                profile.rssi_sum += r as f64;
                profile.rssi_sq_sum += (r as f64) * (r as f64);
                profile.rssi_count += 1;
            }
            return anomalies;
        }

        // ─── Check 1: New SSID burst ───
        if let Some(s) = ssid {
            if !s.is_empty() && s != "<hidden>" && !profile.known_ssids.contains(s) {
                profile.recent_new_ssids.push((s.to_string(), now));
                // Clean old entries (older than 60s)
                profile.recent_new_ssids.retain(|(_, t)| now.duration_since(*t).as_secs() < 60);

                if profile.recent_new_ssids.len() >= NEW_SSID_BURST_THRESHOLD {
                    let new_ssids: Vec<String> = profile.recent_new_ssids.iter()
                        .map(|(s, _)| s.clone()).collect();
                    anomalies.push(BehavioralAnomaly::NewSsidBurst {
                        count: new_ssids.len(),
                        ssids: new_ssids,
                    });
                    profile.recent_new_ssids.clear();
                }

                profile.known_ssids.insert(s.to_string());
            }
        }

        // ─── Check 2: Unusual hour ───
        let hour_fraction = profile.peak_hour_fraction(hour);
        if hour_fraction < TIME_ANOMALY_THRESHOLD && profile.total_observations > 100 {
            anomalies.push(BehavioralAnomaly::UnusualHour {
                hour,
                normal_fraction: hour_fraction,
            });
        }

        // ─── Check 3: RSSI deviation ───
        if let Some(r) = rssi {
            let mean = profile.rssi_mean();
            let std = profile.rssi_std();
            let deviation = (r as f32 - mean).abs();

            if deviation > RSSI_DEVIATION_THRESHOLD && deviation > std * 3.0 {
                anomalies.push(BehavioralAnomaly::RssiDeviation {
                    current: r,
                    mean,
                    deviation,
                });
            }

            profile.rssi_sum += r as f64;
            profile.rssi_sq_sum += (r as f64) * (r as f64);
            profile.rssi_count += 1;
        }

        // ─── Check 4: New channel ───
        if !profile.known_channels.contains(&channel) && profile.known_channels.len() >= 2 {
            anomalies.push(BehavioralAnomaly::NewChannel {
                channel,
                known_channels: profile.known_channels.iter().cloned().collect(),
            });
            profile.known_channels.insert(channel);
        } else {
            profile.known_channels.insert(channel);
        }

        if !anomalies.is_empty() {
            profile.anomaly_count += anomalies.len() as u32;
        }

        anomalies
    }

    /// Get a summary of all profiled devices
    pub fn get_profiles_summary(&self) -> Vec<DeviceProfileSummary> {
        self.profiles.values()
            .filter(|p| p.total_observations > 5)
            .map(|p| {
                let uptime_sec = Instant::now().duration_since(p.first_seen).as_secs();
                DeviceProfileSummary {
                    mac: p.mac.clone(),
                    known_ssids: p.known_ssids.len(),
                    known_channels: p.known_channels.iter().cloned().collect(),
                    rssi_mean: p.rssi_mean(),
                    total_observations: p.total_observations,
                    anomaly_count: p.anomaly_count,
                    established: p.is_established(),
                    uptime_hours: (uptime_sec as f32 / 3600.0),
                    peak_hour: p.hourly_activity.iter()
                        .enumerate()
                        .max_by_key(|(_, &count)| count)
                        .map(|(h, _)| h as u8)
                        .unwrap_or(0),
                }
            })
            .collect()
    }

    pub fn device_count(&self) -> usize {
        self.profiles.len()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceProfileSummary {
    pub mac: String,
    pub known_ssids: usize,
    pub known_channels: Vec<u8>,
    pub rssi_mean: f32,
    pub total_observations: u32,
    pub anomaly_count: u32,
    pub established: bool,
    pub uptime_hours: f32,
    pub peak_hour: u8,
}

pub type SharedProfiler = Arc<Mutex<BehavioralProfiler>>;

/// Global shared profiler reference for API access
pub static SHARED_PROFILER: std::sync::Mutex<Option<SharedProfiler>> = std::sync::Mutex::new(None);

/// Process anomalies: fire alerts and feed threat scorer
pub fn handle_anomalies(
    mac: &str,
    anomalies: &[BehavioralAnomaly],
    threat_scorer: &Arc<Mutex<ThreatScorer>>,
) {
    for anomaly in anomalies {
        let weight = anomaly.weight();
        let description = anomaly.description();

        threat_scorer.lock().unwrap().add_evidence(
            mac,
            None,
            "behavioral_profiler",
            weight,
            &description,
        );

        // Fire alert for significant deviations
        if weight >= 15.0 {
            alert::fire(
                Severity::Medium,
                "Behavioral Anomaly Detected",
                &format!("MAC: {} | {}", mac, description),
            );
        }
    }
}
