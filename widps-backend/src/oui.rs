use std::collections::HashMap;
use std::fs;

pub struct OuiDb {
    table: HashMap<String, String>, 
}

impl OuiDb {
    pub fn load(path: &str) -> Self {
        let mut table = HashMap::new();

        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((prefix, vendor)) = line.split_once(',') {
                        table.insert(prefix.trim().to_uppercase(), vendor.trim().to_string());
                    }
                }
            }
            Err(e) => eprintln!(
                "[oui] could not read {} ({}). Vendor lookups will show 'Unknown'.",
                path, e
            ),
        }

        Self { table }
    }

    pub fn lookup(&self, mac: &str) -> String {
        if mac.len() < 8 {
            return "Unknown".to_string();
        }
        let prefix = mac[0..8].to_uppercase(); // "XX:XX:XX"
        self.table.get(&prefix).cloned().unwrap_or_else(|| "Unknown".to_string())
    }
}