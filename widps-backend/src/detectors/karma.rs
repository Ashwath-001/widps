use crate::alert::{self, Severity};
use std::collections::{HashMap, HashSet, VecDeque};

const DISTINCT_SSID_THRESHOLD: usize = 5;

pub struct KarmaDetector {
    known_ssids: HashSet<String>,
    responses_by_bssid: HashMap<String, HashSet<String>>,
    // RC-6 FIX: Pending queue for probe responses received before the beacon.
    // Holds (ssid, bssid, client_mac) tuples for one processing cycle.
    // After all beacons in a batch are registered, pending probes are re-evaluated.
    pending_probes: VecDeque<(String, String, String)>,
}

impl KarmaDetector {
    pub fn new() -> Self {
        Self {
            known_ssids: HashSet::new(),
            responses_by_bssid: HashMap::new(),
            pending_probes: VecDeque::new(),
        }
    }

    pub fn register_beacon_ssid(&mut self, ssid: &str) {
        if !ssid.is_empty() && ssid != "<hidden>" {
            self.known_ssids.insert(ssid.to_string());
        }
    }

    pub fn process_probe_response(&mut self, ssid: &str, bssid: &str, client_mac: &str) {
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }

        let set = self.responses_by_bssid.entry(bssid.to_string()).or_insert_with(HashSet::new);
        set.insert(ssid.to_string());

        if !self.known_ssids.contains(ssid) {
            // RC-6 FIX: Instead of immediately alerting, queue for re-check.
            // The beacon may arrive in the same pcap batch but after this probe response.
            self.pending_probes.push_back((ssid.to_string(), bssid.to_string(), client_mac.to_string()));
        }

        if set.len() == DISTINCT_SSID_THRESHOLD {
            alert::fire(
                Severity::High,
                "Possible Wi-Fi Pineapple / Karma AP",
                &format!(
                    "BSSID {} has answered probes for {} different SSIDs - typical of a rogue AP impersonating whatever clients ask for",
                    bssid, set.len()
                ),
            );
        }
    }

    /// RC-6 FIX: Call this after processing all frames in a batch/tick.
    /// Any pending probes whose SSID was NOT registered by a beacon in this batch
    /// are genuine Karma alerts.
    pub fn flush_pending(&mut self) {
        while let Some((ssid, bssid, client_mac)) = self.pending_probes.pop_front() {
            if !self.known_ssids.contains(&ssid) {
                alert::fire(
                    Severity::Medium,
                    "Possible Karma Attack",
                    &format!(
                        "BSSID {} answered client {}'s probe for SSID '{}', which has no known legitimate beacon",
                        bssid, client_mac, ssid
                    ),
                );
            }
        }
    }
}
