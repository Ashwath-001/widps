use std::collections::{HashMap, HashSet};
use std::time::Instant;

pub struct ClientInfo {
    pub probed_ssids: HashSet<String>,
    pub associated_bssid: Option<String>,
    pub last_seen: Instant,
    pub deauth_count: u32,
}

pub struct ClientTracker {
    clients: HashMap<String, ClientInfo>,
}

impl ClientTracker {
    pub fn new() -> Self {
        Self { clients: HashMap::new() }
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    fn entry(&mut self, mac: &str) -> &mut ClientInfo {
        self.clients.entry(mac.to_string()).or_insert_with(|| ClientInfo {
            probed_ssids: HashSet::new(),
            associated_bssid: None,
            last_seen: Instant::now(),
            deauth_count: 0,
        })
    }

    pub fn record_probe(&mut self, client_mac: &str, ssid: &str) {
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }
        let c = self.entry(client_mac);
        c.probed_ssids.insert(ssid.to_string());
        c.last_seen = Instant::now();
    }

    pub fn record_association_hint(&mut self, client_mac: &str, bssid: &str) {
        let c = self.entry(client_mac);
        c.associated_bssid = Some(bssid.to_string());
        c.last_seen = Instant::now();
    }

    pub fn record_deauth_victim(&mut self, client_mac: &str) -> u32 {
        let c = self.entry(client_mac);
        c.deauth_count += 1;
        c.last_seen = Instant::now();
        c.deauth_count
    }
}