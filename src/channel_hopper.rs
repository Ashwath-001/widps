use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const CHANNELS: [u8; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

pub fn spawn(iface: &'static str, current_channel: Arc<AtomicU8>, hop_interval: Duration) {
    thread::spawn(move || loop {
        for ch in CHANNELS {
            set_channel(iface, ch);
            current_channel.store(ch, Ordering::Relaxed);
            println!("[hopper] -> channel {}", ch);
            thread::sleep(hop_interval);
        }
    });
}

fn set_channel(iface: &str, channel: u8) {
    let _ = Command::new("iw")
        .args(["dev", iface, "set", "channel", &channel.to_string()])
        .status();
}