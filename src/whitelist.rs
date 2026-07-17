use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Deserialize)]
struct WhitelistFile {
    known_aps: Vec<KnownAp>,
}

#[derive(Debug, Deserialize, Clone)]
struct KnownAp {
    ssid: String,
    bssid: String,
}

pub struct Whitelist {
    trusted: HashMap<String, HashSet<String>>, // ssid -> trusted bssids
}

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

        Self { trusted }
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
}