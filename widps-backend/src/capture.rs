use pcap::{Active, Capture};

/// BPF filter keeping only 802.11 management frames.
const MANAGEMENT_ONLY_FILTER: &str = "type mgt";

pub fn open_monitor(iface: &str) -> Option<Capture<Active>> {
    match Capture::from_device(iface) {
        Ok(builder) => match builder.immediate_mode(true).open() {
            Ok(mut cap) => {
                // Drop data and control frames in the kernel. The parser also
                // rejects them, so a failed filter only costs CPU.
                if let Err(e) = cap.filter(MANAGEMENT_ONLY_FILTER, true) {
                    eprintln!("[capture] Could not apply BPF filter '{}': {} (continuing unfiltered)", MANAGEMENT_ONLY_FILTER, e);
                }
                Some(cap)
            }
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