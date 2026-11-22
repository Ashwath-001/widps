// Tamper-evident record hashing: HMAC key loading and hash-chain helpers.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS: &str = "genesis";
pub const MIN_KEY_BYTES: usize = 32;
pub const KEY_ENV: &str = "WIDPS_HMAC_KEY";
pub const KEY_FILE_ENV: &str = "WIDPS_HMAC_KEY_FILE";

static KEY: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Debug, PartialEq)]
pub enum KeyError {
    Missing,
    NotHex,
    TooShort(usize),
    Unreadable(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Missing => write!(
                f,
                "no audit key: set {} (hex) or {} (path to a file containing hex). Generate one with: openssl rand -hex 32",
                KEY_ENV, KEY_FILE_ENV
            ),
            KeyError::NotHex => write!(f, "audit key is not valid hex"),
            KeyError::TooShort(n) => write!(f, "audit key is {} bytes; at least {} are required", n, MIN_KEY_BYTES),
            KeyError::Unreadable(e) => write!(f, "cannot read audit key file: {}", e),
        }
    }
}

pub fn parse_key(text: &str) -> Result<Vec<u8>, KeyError> {
    let bytes = hex::decode(text.trim()).map_err(|_| KeyError::NotHex)?;
    if bytes.len() < MIN_KEY_BYTES {
        return Err(KeyError::TooShort(bytes.len()));
    }
    Ok(bytes)
}

/// Reads the key from WIDPS_HMAC_KEY, else from the file named by WIDPS_HMAC_KEY_FILE.
pub fn load_key_from_env() -> Result<Vec<u8>, KeyError> {
    if let Ok(v) = std::env::var(KEY_ENV) {
        if !v.trim().is_empty() {
            return parse_key(&v);
        }
    }
    if let Ok(path) = std::env::var(KEY_FILE_ENV) {
        let text = std::fs::read_to_string(&path).map_err(|e| KeyError::Unreadable(format!("{}: {}", path, e)))?;
        return parse_key(&text);
    }
    Err(KeyError::Missing)
}

/// Sets the process-wide key. Returns false if a key was already set.
pub fn init(key: Vec<u8>) -> bool {
    KEY.set(key).is_ok()
}

fn key() -> &'static [u8] {
    KEY.get().expect("audit key not initialised; call audit::init at startup")
}

/// HMAC over length-prefixed fields, so no separator inside a field can shift the boundaries.
pub fn mac_fields(fields: &[&str]) -> String {
    let mut mac = HmacSha256::new_from_slice(key()).expect("HMAC accepts any key length");
    for f in fields {
        mac.update(&(f.len() as u64).to_le_bytes());
        mac.update(f.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

pub fn alert_record_hash(prev: &str, ts: &str, severity: &str, title: &str, detail: &str, bssid: &str, source: &str) -> String {
    mac_fields(&["alert-v1", prev, ts, severity, title, detail, bssid, source])
}

pub fn audit_record_hash(prev: &str, ts: &str, actor: &str, action: &str, target: &str, detail: &str) -> String {
    mac_fields(&["audit-v1", prev, ts, actor, action, target, detail])
}

/// Constant-time comparison of two hex digests.
pub fn digest_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
pub fn init_for_tests() {
    let _ = KEY.set(vec![0x42; MIN_KEY_BYTES]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_accepts_32_bytes_of_hex() {
        let k = "ab".repeat(32);
        assert_eq!(parse_key(&k).unwrap().len(), 32);
        assert_eq!(parse_key(&format!("  {}\n", k)).unwrap().len(), 32);
    }

    #[test]
    fn parse_key_rejects_short_and_non_hex() {
        assert_eq!(parse_key(&"ab".repeat(16)), Err(KeyError::TooShort(16)));
        assert_eq!(parse_key("not-hex-at-all"), Err(KeyError::NotHex));
        assert_eq!(parse_key(""), Err(KeyError::TooShort(0)));
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        init_for_tests();
        assert_ne!(mac_fields(&["ab", "c"]), mac_fields(&["a", "bc"]));
        assert_ne!(mac_fields(&["a|b", "c"]), mac_fields(&["a", "b|c"]));
    }

    #[test]
    fn hash_depends_on_every_field_and_on_prev() {
        init_for_tests();
        let base = alert_record_hash(GENESIS, "t", "High", "x", "d", "b", "rule");
        assert_ne!(base, alert_record_hash("other", "t", "High", "x", "d", "b", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t2", "High", "x", "d", "b", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t", "Medium", "x", "d", "b", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t", "High", "y", "d", "b", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t", "High", "x", "e", "b", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t", "High", "x", "d", "c", "rule"));
        assert_ne!(base, alert_record_hash(GENESIS, "t", "High", "x", "d", "b", "ml"));
        assert_ne!(base, audit_record_hash(GENESIS, "t", "High", "x", "d", "b"));
    }

    #[test]
    fn digest_eq_matches_only_identical() {
        assert!(digest_eq("abcd", "abcd"));
        assert!(!digest_eq("abcd", "abce"));
        assert!(!digest_eq("abcd", "abc"));
    }
}
