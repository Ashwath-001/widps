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
mod api_server;

use api_server::{ScannedAp, SharedApStore};
use client_tracker::ClientTracker;
use detectors::deauth_flood::DeauthFloodDetector;
use detectors::karma::KarmaDetector;
use detectors::rogue_ap::RogueApDetector;
use frame::FrameType;
use oui::OuiDb;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use whitelist::Whitelist;

const IFACE: &str = "wlan1mon";

fn main() {
    let current_channel = Arc::new(AtomicU8::new(1));
    let ap_store: SharedApStore = Arc::new(Mutex::new(HashMap::new()));

    api_server::spawn(8787, Arc::clone(&ap_store), Arc::clone(&current_channel));

    let mut cap = capture::open_monitor(IFACE);

    let whitelist = Whitelist::load("config/whitelist.toml");
    let oui_db = OuiDb::load("config/oui.csv");

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
                    let now_str = chrono::Local::now().format("%H:%M:%S").to_string();
                    let vendor = oui_db.lookup(&parsed.bssid);
                    let rssi_val = parsed.rssi.unwrap_or(-70);
                    let security = parsed.security.clone().unwrap_or_else(|| "OPEN".to_string());

                    {
                        let mut store = ap_store.lock().unwrap();
                        let entry = store.entry(parsed.bssid.clone()).or_insert_with(|| ScannedAp {
                            id: format!("ap-{}", parsed.bssid.replace(':', "")),
                            ssid: ssid.clone(),
                            bssid: parsed.bssid.clone(),
                            channel,
                            rssi: rssi_val,
                            vendor: vendor.clone(),
                            encryption: security.clone(),
                            beaconIntervalMs: 100,
                            clientCount: 0,
                            status: "Normal".into(),
                            firstSeen: now_str.clone(),
                            lastSeen: now_str.clone(),
                        });

                        entry.ssid = ssid.clone();
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.encryption = security.clone();
                        entry.lastSeen = now_str;
                    }

                    let key = format!("{}|{}", ssid, parsed.bssid);
                    if seen_aps.insert(key) {
                        println!(
                            "[NEW AP] CH:{} | SSID:{} | BSSID:{} | RSSI:{} | Vendor:{}",
                            channel,
                            ssid,
                            parsed.bssid,
                            parsed.rssi.map(|r| r.to_string()).unwrap_or_else(|| "?".into()),
                            vendor
                        );
                    }

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