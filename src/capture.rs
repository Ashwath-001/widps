use pcap::{Active, Capture};

pub fn open_monitor(iface: &str) -> Capture<Active> {
    Capture::from_device(iface)
        .expect("interface not found")
        .immediate_mode(true)
        .open()
        .expect("failed to open capture - is the interface in monitor mode and are you root?")
}