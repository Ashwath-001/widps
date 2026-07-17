mod alert;
mod capture;
mod channel_hopper;
mod client_tracker;
mod detectors;
mod frame;
mod ie_parser;
mod oui;
mod radiotap;
mod whitelist;

use client_tracker::ClientTracker;
use detectors::deauth_flood::DeauthFloodDetector;
use detectors::karma::KarmaDetector;
use detectors::rogue_ap::RogueApDetector;
use frame::FrameType;
use oui::OuiDb;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use whitelist::Whitelist;

const IFACE: &str = "wlan1mon";

fn main() {
    let mut cap = capture::open_monitor(IFACE);

    let whitelist = Whitelist::load("config/whitelist.toml");
    let oui_db = OuiDb::load("config/oui.csv");

    let current_channel = Arc::new(AtomicU8::new(1));
    channel_hopper::spawn(IFACE, Arc::clone(&current_channel), Duration::from_millis(300));

    let mut seen_aps: HashSet<String> = HashSet::new();
    let mut rogue_detector = RogueApDetector::new();
    let mut deauth_detector = DeauthFloodDetector::new();
    let mut karma_detector = KarmaDetector::new();
    let mut client_tracker = ClientTracker::new();

    println!("WIDPS Scanner Started on {} (dedicated hopper thread active)", IFACE);

    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let data = packet.data;
        let channel = current_channel.load(Ordering::Relaxed);

        let rt = match radiotap::parse(data) {
            Some(r) => r,
            None => continue,
        };

        let parsed = match frame::parse_frame(data, rt.header_len, rt.rssi) {
            Some(f) => f,
            None => continue,
        };

        match parsed.frame_type {
            FrameType::Beacon => {
                if let Some(ssid) = &parsed.ssid {
                    let key = format!("{}|{}", ssid, parsed.bssid);
                    if seen_aps.insert(key) {
                        println!(
                            "[NEW AP] CH:{} | SSID:{} | BSSID:{} | RSSI:{} | Vendor:{}",
                            channel,
                            ssid,
                            parsed.bssid,
                            parsed.rssi.map(|r| r.to_string()).unwrap_or_else(|| "?".into()),
                            oui_db.lookup(&parsed.bssid)
                        );
                    }
                    let security = parsed.security.clone().unwrap_or_else(|| "OPEN".to_string());
                    rogue_detector.process(
                        ssid,
                        &parsed.bssid,
                        channel,
                        parsed.rssi,
                        &security,
                        &oui_db,
                        &whitelist,
                    );
                    karma_detector.register_beacon_ssid(ssid);
                }
            }
            FrameType::ProbeResponse => {
                if let Some(ssid) = &parsed.ssid {
                    karma_detector.process_probe_response(ssid, &parsed.bssid, &parsed.dst);
                    client_tracker.record_association_hint(&parsed.dst, &parsed.bssid);
                }
            }
            FrameType::ProbeRequest => {
                if let Some(ssid) = &parsed.ssid {
                    client_tracker.record_probe(&parsed.src, ssid);
                }
            }
            FrameType::Deauth | FrameType::Disassoc => {
                deauth_detector.process(parsed.frame_type, &parsed.bssid, &parsed.dst);
                client_tracker.record_deauth_victim(&parsed.dst);
            }
            FrameType::Other => {}
        }
    }
}