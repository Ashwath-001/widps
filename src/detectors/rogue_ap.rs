use crate::alert::{self, Severity};
use crate::oui::OuiDb;
use crate::whitelist::Whitelist;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct ApRecord {
    bssid: String,
    rssi: Option<i8>,
    channel: u8,
    security: String,
    vendor: String,
}

pub struct RogueApDetector {
    seen: HashMap<String, HashMap<String, ApRecord>>, // ssid -> bssid -> record
}

impl RogueApDetector {
    pub fn new() -> Self {
        Self { seen: HashMap::new() }
    }

    pub fn process(
        &mut self,
        ssid: &str,
        bssid: &str,
        channel: u8,
        rssi: Option<i8>,
        security: &str,
        oui_db: &OuiDb,
        whitelist: &Whitelist,
    ) {
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }

        let vendor = oui_db.lookup(bssid);
        let record = ApRecord {
            bssid: bssid.to_string(),
            rssi,
            channel,
            security: security.to_string(),
            vendor: vendor.clone(),
        };

        let bssid_map = self.seen.entry(ssid.to_string()).or_insert_with(HashMap::new);
        let is_new = !bssid_map.contains_key(bssid);
        bssid_map.insert(bssid.to_string(), record.clone());

        if !is_new || bssid_map.len() <= 1 {
            return;
        }
        if whitelist.is_trusted(ssid, bssid) {
            return;
        }

        let fmt = |r: &ApRecord| {
            format!(
                "SSID: {} | BSSID: {} | RSSI: {} | Vendor: {} | Sec: {}",
                ssid,
                r.bssid,
                r.rssi.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                r.vendor,
                r.security
            )
        };

        let mut lines = vec![fmt(&record)];
        let mut security_mismatch = false;
        for (other_bssid, other) in bssid_map.iter() {
            if other_bssid == bssid {
                continue;
            }
            lines.push(fmt(other));
            if other.security != record.security {
                security_mismatch = true;
            }
        }

        let vendor_suspicious = whitelist.has_entries_for(ssid) && !whitelist.is_trusted(ssid, bssid);
        let severity = if security_mismatch { Severity::Critical } else { Severity::High };

        let mut detail = lines.join("\n");
        if security_mismatch {
            detail.push_str("\n>> Security (cipher/AKM) differs between BSSIDs - strong Evil Twin indicator.");
        }
        if vendor_suspicious {
            detail.push_str("\n>> This SSID has whitelist entries, but this BSSID is not one of them.");
        }

        alert::fire(severity, "Possible Rogue AP / Evil Twin", &detail);
    }
}