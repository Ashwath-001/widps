use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Deserialize, Serialize)]
struct WhitelistFile {
    known_aps: Vec<KnownAp>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct KnownAp {
    ssid: String,
    bssid: String,
}

pub struct Whitelist {
    trusted: HashMap<String, HashSet<String>>, // ssid -> trusted bssids
    file_path: String,
}

pub type SharedWhitelist = Arc<Mutex<Whitelist>>;

/// Global reference for API access
pub static SHARED_WHITELIST: std::sync::Mutex<Option<SharedWhitelist>> = std::sync::Mutex::new(None);

impl Whitelist {
    pub fn load(path: &str) -> Self {
        let mut trusted: HashMap<String, HashSet<String>> = HashMap::new();

        match fs::read_to_string(path) {
            Ok(contents) => match toml::from_str::<WhitelistFile>(&contents) {
                Ok(parsed) => {
                    for ap in parsed.known_aps {
                        trusted
                            .entry(ap.ssid)
                            .or_insert_with(HashSet::new)
                            .insert(ap.bssid.to_uppercase());
                    }
                }
                Err(e) => eprintln!("[whitelist] failed to parse {}: {}", path, e),
            },
            Err(e) => eprintln!(
                "[whitelist] could not read {} ({}). Starting with empty whitelist.",
                path, e
            ),
        }

        Self { trusted, file_path: path.to_string() }
    }

    pub fn is_trusted(&self, ssid: &str, bssid: &str) -> bool {
        self.trusted
            .get(ssid)
            .map(|set| set.contains(&bssid.to_uppercase()))
            .unwrap_or(false)
    }

    pub fn has_entries_for(&self, ssid: &str) -> bool {
        self.trusted.contains_key(ssid)
    }

    /// Add a new trusted AP at runtime and persist to disk.
    pub fn add_trusted(&mut self, ssid: &str, bssid: &str) -> bool {
        let bssid_upper = bssid.to_uppercase();
        let set = self.trusted.entry(ssid.to_string()).or_insert_with(HashSet::new);

        if set.contains(&bssid_upper) {
            return false; // already trusted
        }

        set.insert(bssid_upper);
        self.persist();
        true
    }

    /// Remove a trusted AP.
    pub fn remove_trusted(&mut self, ssid: &str, bssid: &str) -> bool {
        let bssid_upper = bssid.to_uppercase();
        if let Some(set) = self.trusted.get_mut(ssid) {
            let removed = set.remove(&bssid_upper);
            if removed {
                if set.is_empty() {
                    self.trusted.remove(ssid);
                }
                self.persist();
            }
            return removed;
        }
        false
    }

    /// Get all trusted APs as a serializable list.
    pub fn get_all(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (ssid, bssids) in &self.trusted {
            for bssid in bssids {
                result.push((ssid.clone(), bssid.clone()));
            }
        }
        result.sort();
        result
    }

    /// Write current state back to the TOML file.
    fn persist(&self) {
        let entries: Vec<KnownAp> = self.get_all().into_iter()
            .map(|(ssid, bssid)| KnownAp { ssid, bssid })
            .collect();

        let file = WhitelistFile { known_aps: entries };

        if let Ok(toml_str) = toml::to_string_pretty(&file) {
            let _ = fs::write(&self.file_path, toml_str);
        }
    }
}
