// "Passive blocking": a Critical alert when a blacklisted MAC transmits again. The sensor never transmits.
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const REALERT_INTERVAL: Duration = Duration::from_secs(300);

pub struct BlacklistWatch {
    last_alert: HashMap<String, Instant>,
    interval: Duration,
}

impl BlacklistWatch {
    pub fn new(interval: Duration) -> Self {
        Self { last_alert: HashMap::new(), interval }
    }

    /// True at most once per `interval` for each MAC.
    pub fn should_alert(&mut self, mac: &str, now: Instant) -> bool {
        let key = mac.to_ascii_uppercase();
        match self.last_alert.get(&key) {
            Some(t) if now.duration_since(*t) < self.interval => false,
            _ => {
                self.last_alert.insert(key, now);
                if self.last_alert.len() > 10_000 {
                    let interval = self.interval;
                    self.last_alert.retain(|_, t| now.duration_since(*t) < interval);
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_once_per_interval_per_mac() {
        let mut w = BlacklistWatch::new(Duration::from_secs(300));
        let t0 = Instant::now();
        assert!(w.should_alert("aa:bb:cc:dd:ee:ff", t0));
        assert!(!w.should_alert("AA:BB:CC:DD:EE:FF", t0 + Duration::from_secs(10)), "case-insensitive");
        assert!(w.should_alert("11:22:33:44:55:66", t0 + Duration::from_secs(10)), "other MACs are independent");
        assert!(!w.should_alert("aa:bb:cc:dd:ee:ff", t0 + Duration::from_secs(299)));
        assert!(w.should_alert("aa:bb:cc:dd:ee:ff", t0 + Duration::from_secs(300)));
    }
}
