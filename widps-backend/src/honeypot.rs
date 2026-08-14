//! ==========================================================================
//! WIDPS Dynamic Honeypot — Attacker Confirmation & False Positive Eliminator
//! ==========================================================================
//!
//! PURPOSE (why a honeypot in a rogue AP detector):
//! ────────────────────────────────────────────────────────────────────────────
//! The #1 problem in wireless IDS is FALSE POSITIVES. When we detect a new
//! BSSID broadcasting a known SSID, it could be:
//!   (a) An attacker's Evil Twin
//!   (b) A new legitimate AP deployed by IT
//!   (c) A student's mobile hotspot
//!
//! The honeypot CONFIRMS attacker identity by:
//!   1. If a device operating a suspected rogue AP ALSO probes/connects to
//!      our honeypot → it's definitively an attack device (legitimate APs
//!      don't actively seek open networks)
//!   2. If a device that was deauthing clients ALSO connects to our honeypot
//!      → confirmed attacker (not a misconfigured router)
//!   3. Devices probing for honeypot SSIDs reveal reconnaissance behavior
//!      that correlates with other IDS detections
//!
//! DYNAMIC HONEYPOT:
//! ────────────────────────────────────────────────────────────────────────────
//! Unlike static honeypots (fixed "FreeWiFi" SSID), our honeypot dynamically
//! adapts based on the environment:
//!
//!   • Watches probe requests in the environment
//!   • Identifies SSIDs that devices are looking for but nobody is serving
//!   • Dynamically creates honeypot APs for those unserved SSIDs
//!   • Any device that connects to an SSID that didn't exist before we
//!     created it → definitively an attacker or an exposed device
//!
//! This is the "Shadow Honeynet" concept (Springer 2015) adapted for modern
//! 802.11 with ML correlation.
//!
//! ARCHITECTURE:
//! ────────────────────────────────────────────────────────────────────────────
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                                                                         │
//! │  Main Monitor (wlan1mon)                     Honeypot AP (wlan2)        │
//! │  ┌───────────────────┐                      ┌──────────────────┐       │
//! │  │ Passive capture   │ ──── correlate ────► │ Dynamic SSIDs    │       │
//! │  │ • Detects rogue   │                      │ • Unserved probes│       │
//! │  │ • Sees probes     │                      │ • Attacker lures │       │
//! │  │ • Flags suspects  │                      │ • Confirmation   │       │
//! │  └────────┬──────────┘                      └────────┬─────────┘       │
//! │           │                                           │                 │
//! │           ▼                                           ▼                 │
//! │  ┌────────────────────────────────────────────────────────────┐        │
//! │  │              CORRELATION ENGINE                             │        │
//! │  │                                                            │        │
//! │  │  If (rogue_AP_detected.src_mac == honeypot_connection.mac) │        │
//! │  │     → CONFIRMED ATTACKER (eliminate false positive)        │        │
//! │  │                                                            │        │
//! │  │  If (deauth_source.mac == honeypot_probe.mac)              │        │
//! │  │     → CONFIRMED ATTACKER (correlated evidence)             │        │
//! │  │                                                            │        │
//! │  │  If (device probes for SSID we just created)               │        │
//! │  │     → ACTIVE RECONNAISSANCE (not innocent device)          │        │
//! │  │                                                            │        │
//! │  └────────────────────────────────────────────────────────────┘        │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! KEY INSIGHT: We're not trying to "catch hackers with fake WiFi."
//! We're using the honeypot as a HIGH-CONFIDENCE ORACLE to resolve
//! ambiguous detections from the main IDS into definitive verdicts.

use crate::alert::{self, Severity};
use crate::sse::SharedBroadcaster;
use crate::threat_scorer::ThreatScorer;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const LEASE_FILE: &str = "/tmp/widps_honeypot_leases";
const DNS_LOG: &str = "/var/log/widps_honeypot_dns.log";
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const FORENSIC_REPORT_DIR: &str = "data/honeypot_forensics";

/// Minimum probes for an unserved SSID before we consider deploying it as honeypot
const DYNAMIC_SSID_PROBE_THRESHOLD: usize = 3;
/// How long to track unserved SSIDs before they expire
const UNSERVED_SSID_EXPIRE_SEC: u64 = 300;

// ---------------------------------------------------------------------------
// Dynamic SSID Management
// ---------------------------------------------------------------------------
/// Tracks SSIDs that devices are probing for but no AP is serving.
/// These become candidates for dynamic honeypot deployment.
#[derive(Debug, Clone, Serialize)]
pub struct UnservedSsidTracker {
    /// SSID → (probe count, first seen, set of MACs that probed for it)
    ssid_probes: HashMap<String, SsidProbeRecord>,
    /// SSIDs currently deployed as dynamic honeypot APs
    active_dynamic_ssids: HashSet<String>,
    /// Static honeypot SSIDs (always running)
    static_ssids: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SsidProbeRecord {
    probe_count: usize,
    first_seen: String,
    probing_macs: HashSet<String>,
    #[serde(skip)]
    first_seen_instant: Option<Instant>,
}

impl UnservedSsidTracker {
    fn new() -> Self {
        let mut static_ssids = HashSet::new();
        // The one static honeypot SSID we always run
        static_ssids.insert("FreeWiFi".to_string());

        Self {
            ssid_probes: HashMap::new(),
            active_dynamic_ssids: HashSet::new(),
            static_ssids,
        }
    }

    /// Record a probe request for an SSID that has no serving AP.
    /// Called by the main capture loop when a probe is seen for an unknown SSID.
    fn record_unserved_probe(&mut self, ssid: &str, src_mac: &str) {
        // Don't track broadcast probes (empty SSID)
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }

        let entry = self.ssid_probes.entry(ssid.to_string()).or_insert_with(|| SsidProbeRecord {
            probe_count: 0,
            first_seen: chrono::Local::now().format("%H:%M:%S").to_string(),
            probing_macs: HashSet::new(),
            first_seen_instant: Some(Instant::now()),
        });

        entry.probe_count += 1;
        entry.probing_macs.insert(src_mac.to_uppercase());
    }

    /// Get SSIDs that should be deployed as dynamic honeypots.
    /// An SSID becomes a candidate when multiple devices probe for it
    /// but no legitimate AP is serving it.
    fn get_deployment_candidates(&self) -> Vec<(String, usize)> {
        self.ssid_probes.iter()
            .filter(|(ssid, record)| {
                record.probe_count >= DYNAMIC_SSID_PROBE_THRESHOLD
                    && !self.active_dynamic_ssids.contains(*ssid)
                    && !self.static_ssids.contains(*ssid)
            })
            .map(|(ssid, record)| (ssid.clone(), record.probing_macs.len()))
            .collect()
    }

    /// Mark an SSID as deployed (we started serving it as honeypot)
    fn mark_deployed(&mut self, ssid: &str) {
        self.active_dynamic_ssids.insert(ssid.to_string());
    }

    /// Check if an SSID is one of our honeypot SSIDs (static or dynamic)
    fn is_honeypot_ssid(&self, ssid: &str) -> bool {
        self.static_ssids.contains(ssid) || self.active_dynamic_ssids.contains(ssid)
    }

    /// Get MACs that probed for a specific honeypot SSID
    fn get_probing_macs(&self, ssid: &str) -> HashSet<String> {
        self.ssid_probes.get(ssid)
            .map(|r| r.probing_macs.clone())
            .unwrap_or_default()
    }

    /// Expire old unserved SSID tracking
    fn expire_old(&mut self) {
        let now = Instant::now();
        self.ssid_probes.retain(|_, record| {
            if let Some(first) = record.first_seen_instant {
                now.duration_since(first).as_secs() < UNSERVED_SSID_EXPIRE_SEC
            } else {
                true
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Correlation Evidence — the core value of the honeypot
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
pub enum ConfirmationType {
    /// Device operating a suspected rogue AP connected to our honeypot
    RogueApOperatorConfirmed,
    /// Device that was sending deauths also probed/connected to honeypot
    DeauthAttackerConfirmed,
    /// Device probed for dynamically-deployed SSID (proves active recon)
    ActiveReconnaissance,
    /// Device connected to honeypot and exhibits attack tool signatures
    AttackToolDetected,
    /// Device connected to multiple honeypot SSIDs (network mapping)
    NetworkMapper,
}

impl ConfirmationType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::RogueApOperatorConfirmed => "Rogue AP Operator Confirmed",
            Self::DeauthAttackerConfirmed => "Deauth Attacker Confirmed",
            Self::ActiveReconnaissance => "Active Reconnaissance",
            Self::AttackToolDetected => "Attack Tool Detected",
            Self::NetworkMapper => "Network Mapper",
        }
    }

    fn confidence_weight(&self) -> f32 {
        match self {
            Self::RogueApOperatorConfirmed => 80.0,  // Highest: definitive proof
            Self::DeauthAttackerConfirmed => 75.0,   // Very high: correlated evidence
            Self::AttackToolDetected => 60.0,        // High: strong indicator
            Self::ActiveReconnaissance => 50.0,      // Medium-high
            Self::NetworkMapper => 45.0,             // Medium
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationResult {
    pub mac_address: String,
    pub confirmation_type: String,
    pub confidence_weight: f32,
    pub evidence_chain: Vec<String>,
    pub timestamp: String,
    pub related_bssid: Option<String>,
}

// ---------------------------------------------------------------------------
// Connection record
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize)]
pub struct HoneypotConnection {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub connected_ssid: String,
    pub timestamp: String,
    pub is_dynamic_ssid: bool,
    pub correlation: Option<CorrelationResult>,
    pub dns_queries: Vec<String>,
}

// ---------------------------------------------------------------------------
// Main Honeypot Engine
// ---------------------------------------------------------------------------
pub struct HoneypotMonitor {
    /// Tracks unserved SSIDs in the environment (for dynamic deployment)
    ssid_tracker: UnservedSsidTracker,
    /// Known connected MACs
    known_macs: HashSet<String>,
    /// Active connections
    connections: Vec<HoneypotConnection>,
    /// MACs that the main IDS suspects of operating rogue APs
    suspected_rogue_operators: HashMap<String, Vec<String>>, // MAC → [reasons]
    /// MACs that the main IDS detected sending deauths
    known_deauth_sources: HashSet<String>,
    /// DNS log position for tailing
    dns_log_pos: u64,
}

impl HoneypotMonitor {
    pub fn new() -> Self {
        let _ = fs::create_dir_all(FORENSIC_REPORT_DIR);

        Self {
            ssid_tracker: UnservedSsidTracker::new(),
            known_macs: HashSet::new(),
            connections: Vec::new(),
            suspected_rogue_operators: HashMap::new(),
            known_deauth_sources: HashSet::new(),
            dns_log_pos: 0,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // API: Called by the main capture loop
    // ─────────────────────────────────────────────────────────────────────

    /// Called when a probe request is seen for an SSID that no known AP serves.
    /// This feeds the dynamic honeypot SSID selection.
    pub fn record_unserved_probe(&mut self, ssid: &str, src_mac: &str) {
        self.ssid_tracker.record_unserved_probe(ssid, src_mac);
    }

    /// Called when the IDS suspects a MAC of operating a rogue AP.
    /// If this MAC later connects to our honeypot → confirmed attacker.
    pub fn mark_suspected_rogue_operator(&mut self, mac: &str, reason: &str) {
        let entry = self.suspected_rogue_operators
            .entry(mac.to_uppercase())
            .or_insert_with(Vec::new);
        if !entry.contains(&reason.to_string()) {
            entry.push(reason.to_string());
        }
    }

    /// Called when the IDS detects a MAC sending deauth frames.
    /// If this MAC later connects to our honeypot → confirmed attacker.
    pub fn mark_deauth_source(&mut self, mac: &str) {
        self.known_deauth_sources.insert(mac.to_uppercase());
    }

    /// Check if a given SSID is one of our honeypot SSIDs
    pub fn is_honeypot_ssid(&self, ssid: &str) -> bool {
        self.ssid_tracker.is_honeypot_ssid(ssid)
    }

    /// Get dynamic SSIDs that should be deployed right now.
    /// The external setup script reads this and creates the APs.
    pub fn get_pending_deployments(&self) -> Vec<(String, usize)> {
        self.ssid_tracker.get_deployment_candidates()
    }

    /// Mark a dynamic SSID as deployed (called after hostapd is reconfigured)
    pub fn mark_ssid_deployed(&mut self, ssid: &str) {
        self.ssid_tracker.mark_deployed(ssid);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Core: Correlation logic
    // ─────────────────────────────────────────────────────────────────────

    /// Attempt to correlate a new honeypot connection with existing IDS data.
    /// This is the KEY function — it turns the honeypot from "just a trap"
    /// into a false-positive-eliminating oracle.
    fn correlate_connection(&self, mac: &str, ssid: &str) -> Option<CorrelationResult> {
        let mac_upper = mac.to_uppercase();
        let mut evidence_chain = Vec::new();

        // Check 1: Is this MAC suspected of operating a rogue AP?
        if let Some(reasons) = self.suspected_rogue_operators.get(&mac_upper) {
            evidence_chain.push(format!("Previously flagged as rogue AP operator: {}", reasons.join("; ")));
            evidence_chain.push(format!("Now connected to honeypot SSID '{}'", ssid));
            evidence_chain.push("Legitimate APs do not connect to random open networks".to_string());

            return Some(CorrelationResult {
                mac_address: mac_upper,
                confirmation_type: ConfirmationType::RogueApOperatorConfirmed.as_str().to_string(),
                confidence_weight: ConfirmationType::RogueApOperatorConfirmed.confidence_weight(),
                evidence_chain,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                related_bssid: None,
            });
        }

        // Check 2: Is this MAC a known deauth source?
        if self.known_deauth_sources.contains(&mac_upper) {
            evidence_chain.push(format!("Previously detected sending deauthentication frames"));
            evidence_chain.push(format!("Now connected to honeypot SSID '{}'", ssid));
            evidence_chain.push("Correlates deauth attack with active network probing".to_string());

            return Some(CorrelationResult {
                mac_address: mac_upper,
                confirmation_type: ConfirmationType::DeauthAttackerConfirmed.as_str().to_string(),
                confidence_weight: ConfirmationType::DeauthAttackerConfirmed.confidence_weight(),
                evidence_chain,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                related_bssid: None,
            });
        }

        // Check 3: Did this device connect to a dynamically-deployed SSID?
        // (An SSID that didn't exist until we created it as a trap)
        if self.ssid_tracker.active_dynamic_ssids.contains(ssid) {
            evidence_chain.push(format!("Connected to dynamically-deployed honeypot SSID '{}'", ssid));
            evidence_chain.push("This SSID was created specifically as a trap based on probe analysis".to_string());
            evidence_chain.push("Connection proves device is actively seeking networks to exploit".to_string());

            return Some(CorrelationResult {
                mac_address: mac_upper,
                confirmation_type: ConfirmationType::ActiveReconnaissance.as_str().to_string(),
                confidence_weight: ConfirmationType::ActiveReconnaissance.confidence_weight(),
                evidence_chain,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                related_bssid: None,
            });
        }

        // Check 4: Has this MAC connected to multiple honeypot SSIDs?
        let prev_connections: Vec<&str> = self.connections.iter()
            .filter(|c| c.mac_address == mac_upper && c.connected_ssid != ssid)
            .map(|c| c.connected_ssid.as_str())
            .collect();

        if !prev_connections.is_empty() {
            evidence_chain.push(format!("Connected to honeypot SSID '{}'", ssid));
            evidence_chain.push(format!("Previously connected to: {}", prev_connections.join(", ")));
            evidence_chain.push("Multiple honeypot connections indicate systematic network mapping".to_string());

            return Some(CorrelationResult {
                mac_address: mac_upper,
                confirmation_type: ConfirmationType::NetworkMapper.as_str().to_string(),
                confidence_weight: ConfirmationType::NetworkMapper.confidence_weight(),
                evidence_chain,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                related_bssid: None,
            });
        }

        None
    }

    // ─────────────────────────────────────────────────────────────────────
    // Monitoring: Parse lease file for new connections
    // ─────────────────────────────────────────────────────────────────────

    fn check_for_new_connections(&mut self) -> Vec<HoneypotConnection> {
        let content = match fs::read_to_string(LEASE_FILE) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut new_connections = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let mac = parts[1].to_uppercase();
            let ip = parts[2].to_string();
            let hostname = if parts[3] != "*" {
                Some(parts[3].to_string())
            } else {
                None
            };

            if self.known_macs.contains(&mac) {
                continue;
            }
            self.known_macs.insert(mac.clone());

            // Determine which SSID this connection belongs to (based on IP subnet)
            let connected_ssid = match ip.as_str() {
                s if s.starts_with("192.168.66.") => "FreeWiFi".to_string(),
                s if s.starts_with("192.168.67.") => "eduroam_guest".to_string(),
                s if s.starts_with("192.168.68.") => "HP-Print-Setup".to_string(),
                s if s.starts_with("192.168.69.") => "DIRECT-wifi".to_string(),
                _ => "unknown_honeypot".to_string(),
            };

            let is_dynamic = self.ssid_tracker.active_dynamic_ssids.contains(&connected_ssid);

            // CORRELATE: This is where the magic happens
            let correlation = self.correlate_connection(&mac, &connected_ssid);

            let conn = HoneypotConnection {
                mac_address: mac,
                ip_address: ip,
                hostname,
                connected_ssid,
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                is_dynamic_ssid: is_dynamic,
                correlation,
                dns_queries: Vec::new(),
            };

            new_connections.push(conn.clone());
            self.connections.push(conn);
        }

        new_connections
    }

    // ─────────────────────────────────────────────────────────────────────
    // DNS tailing (for additional intelligence)
    // ─────────────────────────────────────────────────────────────────────

    fn tail_dns_log(&mut self) {
        let file = match fs::File::open(DNS_LOG) {
            Ok(f) => f,
            Err(_) => return,
        };

        let file_size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => return,
        };

        if file_size < self.dns_log_pos {
            self.dns_log_pos = 0;
        }

        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.dns_log_pos)).is_err() {
            return;
        }

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    self.dns_log_pos += n as u64;
                    // Extract domain queries and map to connections by IP
                    if let Some(query_pos) = line.find("query[") {
                        let after = &line[query_pos..];
                        if let Some(from_pos) = after.find(" from ") {
                            let domain_end = after[7..].find(' ').unwrap_or(0) + 7;
                            let from_ip = after[from_pos + 6..].trim().to_string();

                            // Attach DNS query to the matching connection
                            if let Some(conn) = self.connections.iter_mut()
                                .find(|c| c.ip_address == from_ip) {
                                let domain = after[after.find(']').unwrap_or(0) + 2..domain_end].to_string();
                                if conn.dns_queries.len() < 50 {
                                    conn.dns_queries.push(domain);
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────

    pub fn get_all_connections(&self) -> &[HoneypotConnection] {
        &self.connections
    }

    pub fn get_stats(&self) -> HoneypotStats {
        let confirmed = self.connections.iter().filter(|c| c.correlation.is_some()).count();
        let dynamic = self.connections.iter().filter(|c| c.is_dynamic_ssid).count();

        HoneypotStats {
            total_connections: self.connections.len(),
            confirmed_attackers: confirmed,
            dynamic_ssid_catches: dynamic,
            active_dynamic_ssids: self.ssid_tracker.active_dynamic_ssids.len(),
            tracked_unserved_ssids: self.ssid_tracker.ssid_probes.len(),
            correlated_rogue_operators: self.suspected_rogue_operators.len(),
            correlated_deauth_sources: self.known_deauth_sources.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HoneypotStats {
    pub total_connections: usize,
    pub confirmed_attackers: usize,
    pub dynamic_ssid_catches: usize,
    pub active_dynamic_ssids: usize,
    pub tracked_unserved_ssids: usize,
    pub correlated_rogue_operators: usize,
    pub correlated_deauth_sources: usize,
}

pub type SharedHoneypotMonitor = Arc<Mutex<HoneypotMonitor>>;

/// Global shared monitor reference for API access
pub static SHARED_MONITOR: std::sync::Mutex<Option<SharedHoneypotMonitor>> = std::sync::Mutex::new(None);

// ---------------------------------------------------------------------------
// Spawn the honeypot monitoring thread
// ---------------------------------------------------------------------------
pub fn spawn_monitor(
    threat_scorer: Arc<Mutex<ThreatScorer>>,
    sse_broadcaster: SharedBroadcaster,
) -> SharedHoneypotMonitor {
    let monitor = Arc::new(Mutex::new(HoneypotMonitor::new()));
    let monitor_clone = Arc::clone(&monitor);

    // Store global reference for API access
    *SHARED_MONITOR.lock().unwrap() = Some(Arc::clone(&monitor));

    thread::spawn(move || {
        println!("[honeypot] Dynamic honeypot confirmation system started");
        println!("[honeypot] Purpose: Eliminate false positives from IDS detections");
        println!("[honeypot] Method: Correlate honeypot connections with rogue AP / deauth suspects");

        loop {
            thread::sleep(POLL_INTERVAL);

            // Phase 1: Check for new connections
            let new_connections = {
                let mut m = monitor_clone.lock().unwrap();
                m.tail_dns_log();
                m.ssid_tracker.expire_old();
                m.check_for_new_connections()
            };

            // Phase 2: Process and alert on correlations
            for conn in &new_connections {
                if let Some(ref correlation) = conn.correlation {
                    // ═══════════════════════════════════════════════════════════
                    // CORRELATED CONFIRMATION — This is the high-value output
                    // ═══════════════════════════════════════════════════════════
                    println!(
                        "[HONEYPOT] ✓ CONFIRMED: {} | {} | MAC: {}",
                        correlation.confirmation_type,
                        conn.connected_ssid,
                        conn.mac_address,
                    );

                    // Feed high-confidence evidence to threat scorer
                    threat_scorer.lock().unwrap().add_evidence(
                        &conn.mac_address,
                        Some(&conn.connected_ssid),
                        "honeypot",
                        correlation.confidence_weight,
                        &format!(
                            "Honeypot correlation: {} — {}",
                            correlation.confirmation_type,
                            correlation.evidence_chain.first().unwrap_or(&String::new()),
                        ),
                    );

                    // Fire high-severity alert with full evidence chain
                    alert::fire(
                        Severity::Critical,
                        &format!("Honeypot Confirms: {}", correlation.confirmation_type),
                        &format!(
                            "MAC: {} | Honeypot SSID: '{}' | Dynamic: {}\n\
                             \n\
                             ═══ EVIDENCE CHAIN ═══\n\
                             {}\n\
                             \n\
                             This correlation ELIMINATES the false-positive possibility.\n\
                             The device is definitively engaged in malicious activity.\n\
                             Confidence: {:.0}/100",
                            conn.mac_address,
                            conn.connected_ssid,
                            if conn.is_dynamic_ssid { "Yes (trap SSID)" } else { "No (static lure)" },
                            correlation.evidence_chain.iter()
                                .enumerate()
                                .map(|(i, e)| format!("  {}. {}", i + 1, e))
                                .collect::<Vec<_>>()
                                .join("\n"),
                            correlation.confidence_weight,
                        ),
                    );

                    // Push structured event to dashboard
                    if let Ok(json) = serde_json::to_string(&correlation) {
                        if let Ok(mut b) = sse_broadcaster.lock() {
                            b.push("honeypot_confirmation", &json);
                        }
                    }

                    // Save forensic record
                    let filename = format!(
                        "{}/confirmed_{}_{}.json",
                        FORENSIC_REPORT_DIR,
                        conn.mac_address.replace(':', ""),
                        chrono::Local::now().format("%Y%m%d_%H%M%S"),
                    );
                    if let Ok(json) = serde_json::to_string_pretty(&conn) {
                        let _ = fs::write(&filename, json);
                    }

                } else {
                    // Uncorrelated connection — still suspicious but lower confidence
                    println!(
                        "[HONEYPOT] ? UNCORRELATED: MAC {} → '{}' (no prior IDS data for this device)",
                        conn.mac_address,
                        conn.connected_ssid,
                    );

                    threat_scorer.lock().unwrap().add_evidence(
                        &conn.mac_address,
                        Some(&conn.connected_ssid),
                        "honeypot",
                        25.0, // Lower weight — we can't confirm intent yet
                        &format!(
                            "Device connected to honeypot '{}' — no prior IDS correlation (monitoring)",
                            conn.connected_ssid,
                        ),
                    );

                    alert::fire(
                        Severity::Medium,
                        "Honeypot Connection (Uncorrelated)",
                        &format!(
                            "MAC: {} connected to honeypot SSID '{}'\n\
                             No prior detection data for this device.\n\
                             Could be: attacker reconnaissance, misconfigured device, or curious user.\n\
                             Monitoring for further activity.",
                            conn.mac_address,
                            conn.connected_ssid,
                        ),
                    );
                }
            }

            // Phase 3: Check for dynamic SSID deployment candidates
            let candidates = {
                let m = monitor_clone.lock().unwrap();
                m.ssid_tracker.get_deployment_candidates()
            };

            if !candidates.is_empty() {
                // Write deployment candidates to a file that the setup script reads
                let deploy_json = serde_json::to_string(&candidates).unwrap_or_default();
                let _ = fs::write("/tmp/widps_honeypot_deploy.json", &deploy_json);

                for (ssid, device_count) in &candidates {
                    println!(
                        "[HONEYPOT] 📡 Dynamic SSID candidate: '{}' ({} devices probing)",
                        ssid, device_count,
                    );
                }
            }
        }
    });

    monitor
}
