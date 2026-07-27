use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFingerprint {
    pub supported_rates: Vec<u8>,
    pub extended_rates: Vec<u8>,
    pub ht_capabilities: Option<u16>,
    pub ds_channel: Option<u8>,
    pub country_code: Option<String>,
    pub has_wmm: bool,
    pub has_wps: bool,
}

impl DeviceFingerprint {
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &r in &self.supported_rates {
            h ^= r as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for &r in &self.extended_rates {
            h ^= r as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        if let Some(ht) = self.ht_capabilities {
            h ^= ht as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        if let Some(ch) = self.ds_channel {
            h ^= ch as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        if let Some(ref cc) = self.country_code {
            for b in cc.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h ^= self.has_wmm as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= self.has_wps as u64;
        h = h.wrapping_mul(0x100000001b3);
        h
    }
}

pub fn extract_fingerprint(data: &[u8], ie_start: usize) -> DeviceFingerprint {
    let mut supported_rates = Vec::new();
    let mut extended_rates = Vec::new();
    let mut ht_capabilities = None;
    let mut ds_channel = None;
    let mut country_code = None;
    let mut has_wmm = false;
    let mut has_wps = false;

    let mut pos = ie_start;
    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        if pos + 2 + len > data.len() {
            break;
        }
        let body = &data[pos + 2..pos + 2 + len];

        match tag {
            1 => {
                supported_rates = body.to_vec();
            }
            3 => {
                if len >= 1 {
                    ds_channel = Some(body[0]);
                }
            }
            7 => {
                if len >= 2 {
                    country_code = Some(String::from_utf8_lossy(&body[0..2]).to_string());
                }
            }
            45 => {
                if len >= 2 {
                    ht_capabilities = Some(u16::from_le_bytes([body[0], body[1]]));
                }
            }
            50 => {
                extended_rates = body.to_vec();
            }
            221 => {
                if len >= 4 {
                    if body[0..3] == [0x00, 0x50, 0xF2] && body[3] == 0x02 {
                        has_wmm = true;
                    }
                    if body[0..3] == [0x00, 0x50, 0xF2] && body[3] == 0x04 {
                        has_wps = true;
                    }
                }
            }
            _ => {}
        }

        pos += 2 + len;
    }

    DeviceFingerprint {
        supported_rates,
        extended_rates,
        ht_capabilities,
        ds_channel,
        country_code,
        has_wmm,
        has_wps,
    }
}

pub struct FingerprintStore {
    fingerprints: HashMap<String, u64>,
}

impl FingerprintStore {
    pub fn new() -> Self {
        Self { fingerprints: HashMap::new() }
    }

    pub fn check_and_store(&mut self, bssid: &str, fingerprint: &DeviceFingerprint) -> Option<FingerprintMismatch> {
        let new_hash = fingerprint.hash();
        if let Some(&stored_hash) = self.fingerprints.get(bssid) {
            if stored_hash != new_hash {
                return Some(FingerprintMismatch {
                    bssid: bssid.to_string(),
                    old_hash: stored_hash,
                    new_hash,
                });
            }
        } else {
            self.fingerprints.insert(bssid.to_string(), new_hash);
        }
        None
    }
}

pub struct FingerprintMismatch {
    pub bssid: String,
    pub old_hash: u64,
    pub new_hash: u64,
}
