use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

/// Settings the dashboard can change at runtime; every field changes sensor behaviour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeConfig {
    pub channel_hopping: bool,
    pub client_tracking: bool,
    #[serde(default)]
    pub retention_days: u32,       // 0 = keep forever
    #[serde(default)]
    pub auto_archive_hours: u32,   // 0 = disabled; otherwise mark alerts read after N hours
    #[serde(default = "default_true")]
    pub passive_blocking: bool,    // Critical alert when a blacklisted MAC is seen again
}

fn default_true() -> bool { true }

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self { channel_hopping: true, client_tracking: true, retention_days: 0, auto_archive_hours: 0, passive_blocking: true }
    }
}

/// Fields earlier dashboards sent that no longer exist; accepted and ignored.
const RETIRED_FIELDS: &[&str] = &["passive_scan", "client_warnings"];
const MAX_RETENTION_DAYS: u64 = 3650;
const MAX_ARCHIVE_HOURS: u64 = 8760;

/// Applies a partial update; only the keys present change. Returns the new config and the changed keys.
pub fn merge_patch(current: &RuntimeConfig, patch: &serde_json::Value) -> Result<(RuntimeConfig, Vec<String>), String> {
    let obj = patch.as_object().ok_or("config update must be a JSON object")?;
    let mut next = current.clone();
    let mut changed = Vec::new();
    for (k, v) in obj {
        let want_bool = || v.as_bool().ok_or_else(|| format!("{} must be true or false", k));
        let want_u32 = |max: u64| {
            v.as_u64().filter(|n| *n <= max).map(|n| n as u32).ok_or_else(|| format!("{} must be an integer from 0 to {}", k, max))
        };
        match k.as_str() {
            "channel_hopping" => next.channel_hopping = want_bool()?,
            "client_tracking" => next.client_tracking = want_bool()?,
            "passive_blocking" => next.passive_blocking = want_bool()?,
            "retention_days" => next.retention_days = want_u32(MAX_RETENTION_DAYS)?,
            "auto_archive_hours" => next.auto_archive_hours = want_u32(MAX_ARCHIVE_HOURS)?,
            other if RETIRED_FIELDS.contains(&other) => continue,
            other => return Err(format!("unknown setting '{}'", other)),
        }
        changed.push(k.clone());
    }
    changed.retain(|k| {
        let before = serde_json::to_value(current).ok().and_then(|v| v.get(k).cloned());
        let after = serde_json::to_value(&next).ok().and_then(|v| v.get(k).cloned());
        before != after
    });
    Ok((next, changed))
}

pub struct ConfigFlags {
    pub hopping_enabled: Arc<AtomicBool>,
    pub client_tracking_enabled: Arc<AtomicBool>,
    pub passive_blocking_enabled: Arc<AtomicBool>,
    pub retention_days: Arc<AtomicU32>,
    pub auto_archive_hours: Arc<AtomicU32>,
}

impl ConfigFlags {
    pub fn new() -> Self {
        let d = RuntimeConfig::default();
        Self {
            hopping_enabled: Arc::new(AtomicBool::new(d.channel_hopping)),
            client_tracking_enabled: Arc::new(AtomicBool::new(d.client_tracking)),
            passive_blocking_enabled: Arc::new(AtomicBool::new(d.passive_blocking)),
            retention_days: Arc::new(AtomicU32::new(d.retention_days)),
            auto_archive_hours: Arc::new(AtomicU32::new(d.auto_archive_hours)),
        }
    }

    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            channel_hopping: self.hopping_enabled.load(Ordering::Acquire),
            client_tracking: self.client_tracking_enabled.load(Ordering::Acquire),
            retention_days: self.retention_days.load(Ordering::Acquire),
            auto_archive_hours: self.auto_archive_hours.load(Ordering::Acquire),
            passive_blocking: self.passive_blocking_enabled.load(Ordering::Acquire),
        }
    }

    pub fn apply(&self, config: &RuntimeConfig) {
        self.hopping_enabled.store(config.channel_hopping, Ordering::Release);
        self.client_tracking_enabled.store(config.client_tracking, Ordering::Release);
        self.passive_blocking_enabled.store(config.passive_blocking, Ordering::Release);
        self.retention_days.store(config.retention_days, Ordering::Release);
        self.auto_archive_hours.store(config.auto_archive_hours, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn patch_changes_only_given_keys() {
        let cur = RuntimeConfig { retention_days: 30, auto_archive_hours: 24, ..Default::default() };
        let (next, changed) = merge_patch(&cur, &json!({"channel_hopping": false})).unwrap();
        assert!(!next.channel_hopping);
        assert_eq!((next.retention_days, next.auto_archive_hours), (30, 24), "untouched settings keep their values");
        assert_eq!(changed, vec!["channel_hopping".to_string()]);
    }

    #[test]
    fn patch_validates_types_ranges_and_names() {
        let cur = RuntimeConfig::default();
        assert!(merge_patch(&cur, &json!({"channel_hopping": "yes"})).is_err());
        assert!(merge_patch(&cur, &json!({"retention_days": -1})).is_err());
        assert!(merge_patch(&cur, &json!({"retention_days": 99999})).is_err());
        assert!(merge_patch(&cur, &json!({"retention_days": 1.5})).is_err());
        assert!(merge_patch(&cur, &json!({"bogus": true})).unwrap_err().contains("unknown"));
        assert!(merge_patch(&cur, &json!([1, 2])).is_err());
        let (next, changed) = merge_patch(&cur, &json!({"passive_scan": true, "client_warnings": true})).unwrap();
        assert_eq!((next, changed.len()), (cur.clone(), 0), "retired fields are ignored");
    }

    #[test]
    fn unchanged_values_are_not_reported() {
        let cur = RuntimeConfig::default();
        let (_, changed) = merge_patch(&cur, &json!({"channel_hopping": true, "retention_days": 7})).unwrap();
        assert_eq!(changed, vec!["retention_days".to_string()]);
    }
}
