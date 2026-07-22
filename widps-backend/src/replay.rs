use pcap::Capture;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn open_pcap_file(path: &str) -> Option<Capture<pcap::Offline>> {
    if !Path::new(path).exists() {
        eprintln!("[replay] File not found: {}", path);
        return None;
    }

    match Capture::from_file(path) {
        Ok(cap) => {
            println!("[replay] Opened pcap: {}", path);
            Some(cap)
        }
        Err(e) => {
            eprintln!("[replay] Failed to open {}: {}", path, e);
            None
        }
    }
}

pub fn replay_with_timing(delay_ms: u64) -> Duration {
    Duration::from_millis(delay_ms)
}
