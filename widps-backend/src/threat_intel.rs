//! Layer 1: IoC Database (indicators of compromise)
//! Layer 2: Reputation Scoring (-100 to +100)
//! Layer 3: Enrichment (vendor, hardware type, SSID analysis)
//! Layer 4: Policy Engine (automated response decisions)
//! Layer 5: Feed Export (STIX-compatible JSON output)

use crate::alert::{self, Severity};
use crate::oui::OuiDb;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ===========================================================================
// LAYER 1: Indicators of Compromise
// ===========================================================================

/// Known attack hardware OUI prefixes (first 3 octets of MAC)
const ATTACK_HARDWARE_OUIS: &[(&str, &str)] = &[
    ("00:C0:CA", "WiFi Pineapple (Hak5)"),
    ("00:13:37", "WiFi Pineapple (Hak5 Mark VII)"),
    ("DC:A6:32", "Raspberry Pi (common attack platform)"),
    ("B8:27:EB", "Raspberry Pi (older models)"),
    ("D8:3A:DD", "Raspberry Pi 5"),
    ("E4:5F:01", "Raspberry Pi (compute module)"),
    ("00:E0:4C", "Realtek (common in cheap attack adapters)"),
    ("00:0F:00", "Alfa Networks (penetration testing adapter)"),
    ("00:C0:01", "PCMCIA ethernet (old but flagged)"),
    ("02:00:00", "Locally administered (potential spoof)"),
    ("06:00:00", "Locally administered (potential spoof)"),
    ("0A:00:00", "Locally administered (potential spoof)"),
    ("0E:00:00", "Locally administered (potential spoof)"),
];

/// Suspicious SSID patterns (regex-like matching)
const SUSPICIOUS_SSID_PATTERNS: &[(&str, &str, i32)] = &[
    // (contains, reason, reputation_penalty)
    ("Free", "Common lure SSID pattern", -5),
    ("free", "Common lure SSID pattern", -5),
    ("FREE", "Common lure SSID pattern", -5),
    ("Open", "Open network indicator", -3),
    ("Guest", "Guest networks are common impersonation targets", -2),
    ("_5G", "Potential clone with 5G suffix added", -8),
    ("-5G", "Potential clone with 5G suffix added", -8),
    ("_test", "Test network (shouldn't be in production)", -4),
    ("setup", "Setup/config network (transient)", -3),
    ("DIRECT-", "WiFi Direct (P2P, unusual in enterprise)", -3),
];

/// Check if a MAC address is locally administered (bit 1 of first octet)
fn is_locally_administered_mac(mac: &str) -> bool {
    let first_octet = mac.split(':').next().unwrap_or("00");
    if let Ok(byte) = u8::from_str_radix(first_octet, 16) {
        (byte & 0x02) != 0 // Locally administered bit
    } else {
        false
    }
}

/// Check if MAC matches known attack hardware
fn check_attack_hardware(mac: &str) -> Option<&'static str> {
    let prefix = mac.to_uppercase();
    for (oui, description) in ATTACK_HARDWARE_OUIS {
        if prefix.starts_with(oui) {
            return Some(description);
        }
    }
    None
}

/// Check SSID against suspicious patterns
fn check_suspicious_ssid(ssid: &str) -> Vec<(&'static str, i32)> {
    let mut matches = Vec::new();
    for (pattern, reason, penalty) in SUSPICIOUS_SSID_PATTERNS {
        if ssid.contains(pattern) {
            matches.push((*reason, *penalty));
        }
    }
    matches
}

/// Compute Levenshtein distance between two strings (for SSID similarity)
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 { return b_len; }
    if b_len == 0 { return a_len; }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a.as_bytes()[i - 1] == b.as_bytes()[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

// ===========================================================================
// LAYER 2: Reputation Scoring
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReputationLevel {
    Trusted,     // > +50
    Known,       // +20 to +50
    Unknown,     // -20 to +20
    Watchlist,   // -50 to -20
    Threat,      // < -50
}

impl ReputationLevel {
    pub fn from_score(score: i32) -> Self {
        match score {
            s if s > 50 => Self::Trusted,
            s if s > 20 => Self::Known,
            s if s >= -20 => Self::Unknown,
            s if s >= -50 => Self::Watchlist,
            _ => Self::Threat,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Known => "KNOWN",
            Self::Unknown => "UNKNOWN",
            Self::Watchlist => "WATCHLIST",
            Self::Threat => "THREAT",
        }
    }
}

// ===========================================================================
// LAYER 3: Enrichment Data
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct DeviceEnrichment {
    pub vendor: String,
    pub is_attack_hardware: bool,
    pub attack_hardware_type: Option<String>,
    pub is_locally_administered: bool,
    pub ssid_suspicion_reasons: Vec<String>,
    pub similar_to_known_ssids: Vec<(String, usize)>, // (known SSID, distance)
    pub first_seen: String,
    pub days_on_network: f32,
    pub total_observations: u32,
    pub consistency_score: f32, // 0-1, how consistent its behavior is
}

// ===========================================================================
// LAYER 4: Policy Engine + Device Intel Record
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct DeviceIntel {
    pub mac: String,
    pub ssid: Option<String>,
    pub reputation_score: i32,
    pub reputation_level: ReputationLevel,
    pub enrichment: DeviceEnrichment,
    pub ioc_matches: Vec<String>,
    pub admin_action: Option<AdminAction>,
    pub last_updated: String,
    pub history: Vec<ReputationEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminAction {
    pub action: String,       // "whitelist", "blacklist", "override"
    pub timestamp: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReputationEvent {
    pub timestamp: String,
    pub delta: i32,
    pub reason: String,
    pub source: String,  // "system", "admin", "honeypot", "detector", "policy"
}

// Internal mutable state
struct IntelRecord {
    mac: String,
    ssid: Option<String>,
    reputation: i32,
    enrichment: DeviceEnrichment,
    ioc_matches: Vec<String>,
    admin_action: Option<AdminAction>,
    history: Vec<ReputationEvent>,
    first_seen: Instant,
    last_seen: Instant,
    observation_count: u32,
    // Consistency tracking
    seen_ssids: Vec<String>,
    seen_channels: Vec<u8>,
    seen_encryptions: Vec<String>,
}

impl IntelRecord {
    fn new(mac: &str) -> Self {
        Self {
            mac: mac.to_uppercase(),
            ssid: None,
            reputation: 0,
            enrichment: DeviceEnrichment {
                vendor: String::new(),
                is_attack_hardware: false,
                attack_hardware_type: None,
                is_locally_administered: false,
                ssid_suspicion_reasons: Vec::new(),
                similar_to_known_ssids: Vec::new(),
                first_seen: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                days_on_network: 0.0,
                total_observations: 0,
                consistency_score: 1.0,
            },
            ioc_matches: Vec::new(),
            admin_action: None,
            history: Vec::new(),
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            observation_count: 0,
            seen_ssids: Vec::new(),
            seen_channels: Vec::new(),
            seen_encryptions: Vec::new(),
        }
    }

    fn apply_delta(&mut self, delta: i32, reason: &str, source: &str) {
        let old = self.reputation;
        self.reputation = (self.reputation + delta).clamp(-100, 100);

        // Cannot go below -50 (THREAT) without admin action or honeypot correlation
        if source != "admin" && source != "honeypot" && self.reputation < -50 {
            self.reputation = -50;
        }

        if self.reputation != old {
            self.history.push(ReputationEvent {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                delta: self.reputation - old,
                reason: reason.to_string(),
                source: source.to_string(),
            });
            // Keep history bounded
            if self.history.len() > 50 {
                self.history.remove(0);
            }
        }
    }

    fn update_consistency(&mut self) {
        // Consistency = how stable is this device's behavior
        // Devices that change SSID/channel/encryption frequently are less trustworthy
        let ssid_variety = self.seen_ssids.len().min(5) as f32 / 5.0;
        let channel_variety = self.seen_channels.len().min(5) as f32 / 5.0;
        let enc_variety = self.seen_encryptions.len().min(3) as f32 / 3.0;

        // 1.0 = perfectly consistent, 0.0 = chaotic
        self.enrichment.consistency_score = 1.0 - ((ssid_variety + channel_variety + enc_variety) / 3.0);
    }

    fn days_active(&self) -> f32 {
        Instant::now().duration_since(self.first_seen).as_secs_f32() / 86400.0
    }

    fn to_device_intel(&self) -> DeviceIntel {
        DeviceIntel {
            mac: self.mac.clone(),
            ssid: self.ssid.clone(),
            reputation_score: self.reputation,
            reputation_level: ReputationLevel::from_score(self.reputation),
            enrichment: DeviceEnrichment {
                days_on_network: self.days_active(),
                total_observations: self.observation_count,
                ..self.enrichment.clone()
            },
            ioc_matches: self.ioc_matches.clone(),
            admin_action: self.admin_action.clone(),
            last_updated: chrono::Local::now().format("%H:%M:%S").to_string(),
            history: self.history.clone(),
        }
    }
}

// ===========================================================================
// MAIN ENGINE
// ===========================================================================

pub struct ThreatIntelPlatform {
    records: HashMap<String, IntelRecord>,
    /// Known-good SSIDs (from whitelist) for similarity comparison
    known_ssids: Vec<String>,
}

impl ThreatIntelPlatform {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            known_ssids: Vec::new(),
        }
    }

    /// Register known legitimate SSIDs (from whitelist) for similarity detection
    pub fn register_known_ssids(&mut self, ssids: &[String]) {
        self.known_ssids = ssids.clone().to_vec();
    }

    /// Process a device observation — the main entry point.
    /// Called for every beacon/probe/deauth frame from the capture loop.
    /// Returns the current reputation level for the device.
    pub fn observe(
        &mut self,
        mac: &str,
        ssid: Option<&str>,
        channel: u8,
        encryption: Option<&str>,
        oui_db: &OuiDb,
    ) -> ReputationLevel {
        let mac_upper = mac.to_uppercase();
        let now = Instant::now();

        let is_new = !self.records.contains_key(&mac_upper);

        // If new, insert a fresh record first
        if is_new {
            self.records.insert(mac_upper.clone(), IntelRecord::new(&mac_upper));
        }

        // Now do enrichment if new (needs self for known_ssids)
        if is_new {
            // Collect enrichment data without borrowing records mutably
            let vendor = oui_db.lookup(&mac_upper);
            let attack_hw = check_attack_hardware(&mac_upper);
            let is_local = is_locally_administered_mac(&mac_upper);
            let ssid_matches = ssid.map(|s| check_suspicious_ssid(s)).unwrap_or_default();
            let similar_ssids: Vec<(String, usize)> = if let Some(s) = ssid {
                self.known_ssids.iter()
                    .filter(|k| k.as_str() != s)
                    .filter_map(|k| {
                        let dist = levenshtein(s, k);
                        if dist > 0 && dist <= 2 { Some((k.clone(), dist)) } else { None }
                    })
                    .collect()
            } else {
                Vec::new()
            };

            // Apply to record
            let record = self.records.get_mut(&mac_upper).unwrap();
            record.enrichment.vendor = vendor;

            if let Some(hw_type) = attack_hw {
                record.enrichment.is_attack_hardware = true;
                record.enrichment.attack_hardware_type = Some(hw_type.to_string());
                record.ioc_matches.push(format!("Attack hardware: {}", hw_type));
                record.apply_delta(-15, &format!("Known attack hardware OUI: {}", hw_type), "system");
            }

            if is_local {
                record.enrichment.is_locally_administered = true;
                record.ioc_matches.push("Locally administered MAC address (randomized/spoofed)".to_string());
                record.apply_delta(-8, "Locally administered MAC (potential spoof)", "system");
            }

            for (reason, penalty) in &ssid_matches {
                record.enrichment.ssid_suspicion_reasons.push(reason.to_string());
                record.apply_delta(*penalty, reason, "system");
            }

            for (known_ssid, dist) in &similar_ssids {
                record.enrichment.similar_to_known_ssids.push((known_ssid.clone(), *dist));
                record.ioc_matches.push(format!("SSID similar to known '{}' (distance: {})", known_ssid, dist));
                record.apply_delta(-12, &format!("SSID similar to known '{}' (distance {})", known_ssid, dist), "system");
            }
        }

        // Update observation data
        let record = self.records.get_mut(&mac_upper).unwrap();
        record.last_seen = now;
        record.observation_count += 1;
        record.enrichment.total_observations = record.observation_count;

        if let Some(s) = ssid {
            record.ssid = Some(s.to_string());
            if !record.seen_ssids.contains(&s.to_string()) {
                record.seen_ssids.push(s.to_string());
            }
        }
        if !record.seen_channels.contains(&channel) {
            record.seen_channels.push(channel);
        }
        if let Some(enc) = encryption {
            if !record.seen_encryptions.contains(&enc.to_string()) {
                record.seen_encryptions.push(enc.to_string());
            }
        }

        // Policy: time-based reputation improvement
        if record.observation_count % 100 == 0 && record.reputation < 50 {
            let has_no_recent_alerts = record.history.iter()
                .rev()
                .take(10)
                .all(|h| h.delta >= 0);

            if has_no_recent_alerts {
                record.apply_delta(1, "Consistent clean behavior (100 frames without incident)", "policy");
            }
        }

        record.update_consistency();

        ReputationLevel::from_score(record.reputation)
    }

    /// Called by detection engine when a device triggers an alert
    pub fn report_detection(&mut self, mac: &str, detector: &str, severity: &str) {
        let mac_upper = mac.to_uppercase();
        if let Some(record) = self.records.get_mut(&mac_upper) {
            let penalty = match severity {
                "Critical" => -20,
                "High" => -12,
                "Medium" => -6,
                _ => -3,
            };
            record.apply_delta(penalty, &format!("Detection: {} ({})", detector, severity), "detector");
        }
    }

    /// Called by honeypot when a device is confirmed as attacker
    pub fn report_honeypot_confirmation(&mut self, mac: &str) {
        let mac_upper = mac.to_uppercase();
        if let Some(record) = self.records.get_mut(&mac_upper) {
            // Honeypot confirmation CAN push below -50
            record.reputation = (record.reputation - 40).clamp(-100, 100);
            record.history.push(ReputationEvent {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                delta: -40,
                reason: "Honeypot correlation confirmed — device is malicious".to_string(),
                source: "honeypot".to_string(),
            });
            record.ioc_matches.push("Honeypot-confirmed attacker".to_string());
        }
    }

    /// Admin action: whitelist a device
    pub fn admin_whitelist(&mut self, mac: &str, reason: Option<&str>) {
        let mac_upper = mac.to_uppercase();
        let record = self.records.entry(mac_upper.clone())
            .or_insert_with(|| IntelRecord::new(&mac_upper));

        record.reputation = 80;
        record.admin_action = Some(AdminAction {
            action: "whitelist".to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            reason: reason.map(|s| s.to_string()),
        });
        record.history.push(ReputationEvent {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            delta: 80 - record.reputation,
            reason: format!("Admin whitelisted: {}", reason.unwrap_or("no reason given")),
            source: "admin".to_string(),
        });
    }

    /// Admin action: blacklist a device
    pub fn admin_blacklist(&mut self, mac: &str, reason: Option<&str>) {
        let mac_upper = mac.to_uppercase();
        let record = self.records.entry(mac_upper.clone())
            .or_insert_with(|| IntelRecord::new(&mac_upper));

        record.reputation = -90;
        record.admin_action = Some(AdminAction {
            action: "blacklist".to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            reason: reason.map(|s| s.to_string()),
        });
        record.history.push(ReputationEvent {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            delta: -90 - record.reputation,
            reason: format!("Admin blacklisted: {}", reason.unwrap_or("confirmed threat")),
            source: "admin".to_string(),
        });
    }

    /// Admin action: reset device to neutral (override)
    pub fn admin_reset(&mut self, mac: &str, reason: Option<&str>) {
        let mac_upper = mac.to_uppercase();
        if let Some(record) = self.records.get_mut(&mac_upper) {
            let old = record.reputation;
            record.reputation = 0;
            record.admin_action = Some(AdminAction {
                action: "override".to_string(),
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                reason: reason.map(|s| s.to_string()),
            });
            record.history.push(ReputationEvent {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                delta: -old,
                reason: format!("Admin reset to neutral: {}", reason.unwrap_or("re-evaluation")),
                source: "admin".to_string(),
            });
        }
    }

    // ─── Query API ───

    pub fn get_device_intel(&self, mac: &str) -> Option<DeviceIntel> {
        self.records.get(&mac.to_uppercase()).map(|r| r.to_device_intel())
    }

    pub fn get_all_intel(&self) -> Vec<DeviceIntel> {
        self.records.values()
            .filter(|r| r.observation_count > 2) // skip transient single-frame devices
            .map(|r| r.to_device_intel())
            .collect()
    }

    pub fn get_threats(&self) -> Vec<DeviceIntel> {
        self.records.values()
            .filter(|r| r.reputation < -20)
            .map(|r| r.to_device_intel())
            .collect()
    }

    pub fn get_watchlist(&self) -> Vec<DeviceIntel> {
        self.records.values()
            .filter(|r| r.reputation >= -50 && r.reputation < -20)
            .map(|r| r.to_device_intel())
            .collect()
    }

    // ─── Layer 5: Export ───

    /// Export all threat intel as a STIX-like JSON feed
    pub fn export_feed(&self) -> serde_json::Value {
        let threats: Vec<serde_json::Value> = self.records.values()
            .filter(|r| r.reputation < -20)
            .map(|r| {
                serde_json::json!({
                    "type": "indicator",
                    "id": format!("widps:indicator-{}", r.mac.replace(':', "")),
                    "created": r.enrichment.first_seen,
                    "modified": chrono::Local::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    "name": format!("Malicious wireless device {}", r.mac),
                    "pattern": format!("[mac-addr:value = '{}']", r.mac),
                    "pattern_type": "stix",
                    "valid_from": r.enrichment.first_seen,
                    "labels": r.ioc_matches.clone(),
                    "confidence": ((-r.reputation) as f32 / 100.0 * 100.0) as u32,
                    "x_widps_reputation": r.reputation,
                    "x_widps_level": ReputationLevel::from_score(r.reputation).as_str(),
                    "x_widps_vendor": r.enrichment.vendor,
                })
            })
            .collect();

        serde_json::json!({
            "type": "bundle",
            "id": format!("widps:bundle-{}", chrono::Local::now().format("%Y%m%d%H%M%S")),
            "objects": threats,
        })
    }

    pub fn stats(&self) -> ThreatIntelStats {
        let total = self.records.len();
        let trusted = self.records.values().filter(|r| r.reputation > 50).count();
        let known = self.records.values().filter(|r| r.reputation > 20 && r.reputation <= 50).count();
        let unknown = self.records.values().filter(|r| r.reputation >= -20 && r.reputation <= 20).count();
        let watchlist = self.records.values().filter(|r| r.reputation >= -50 && r.reputation < -20).count();
        let threat = self.records.values().filter(|r| r.reputation < -50).count();
        let ioc_hits = self.records.values().filter(|r| !r.ioc_matches.is_empty()).count();

        ThreatIntelStats {
            total_devices: total,
            trusted,
            known,
            unknown,
            watchlist,
            threat,
            ioc_hits,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelStats {
    pub total_devices: usize,
    pub trusted: usize,
    pub known: usize,
    pub unknown: usize,
    pub watchlist: usize,
    pub threat: usize,
    pub ioc_hits: usize,
}

pub type SharedThreatIntel = Arc<Mutex<ThreatIntelPlatform>>;

/// Global reference for API access
pub static SHARED_INTEL: std::sync::Mutex<Option<SharedThreatIntel>> = std::sync::Mutex::new(None);
