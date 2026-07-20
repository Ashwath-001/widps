use pcap::{Active, Capture};

pub fn open_monitor(iface: &str) -> Option<Capture<Active>> {
    match Capture::from_device(iface) {
        Ok(builder) => match builder.immediate_mode(true).open() {
            Ok(cap) => Some(cap),
            Err(e) => {
                eprintln!("[capture] Failed to open capture on '{}': {}", iface, e);
                None
            }
        },
        Err(e) => {
            eprintln!("[capture] Interface '{}' not found: {}", iface, e);
            None
        }
    }
}