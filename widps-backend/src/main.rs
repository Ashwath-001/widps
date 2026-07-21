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
use detectors::sequence_anomaly::SequenceAnomalyDetector;
use detectors::probe_flood::ProbeFloodDetector;
use frame::FrameType;
use oui::OuiDb;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use whitelist::Whitelist;

const IFACE: &str = "wlan1mon";

fn main() {
    let current_channel = Arc::new(AtomicU8::new(1));
    let ap_store: SharedApStore = Arc::new(Mutex::new(HashMap::new()));
    let client_tracker = Arc::new(Mutex::new(ClientTracker::new()));
    let packets_per_second = Arc::new(AtomicU32::new(0));

    // Atomic frame type counters for 5s reporting window
    let beacon_cnt = Arc::new(AtomicU32::new(0));
    let probe_resp_cnt = Arc::new(AtomicU32::new(0));
    let probe_req_cnt = Arc::new(AtomicU32::new(0));
    let deauth_cnt = Arc::new(AtomicU32::new(0));
    let disassoc_cnt = Arc::new(AtomicU32::new(0));
    let other_cnt = Arc::new(AtomicU32::new(0));

    api_server::spawn(
        8787,
        Arc::clone(&ap_store),
        Arc::clone(&current_channel),
        Arc::clone(&client_tracker),
        Arc::clone(&packets_per_second),
    );

    let whitelist = Whitelist::load("config/whitelist.toml");
    let oui_db = OuiDb::load("config/oui.csv");

    channel_hopper::spawn(IFACE, Arc::clone(&current_channel), Duration::from_millis(300));

    // Spawn 5s frame counter reporting thread
    {
        let b_cnt = Arc::clone(&beacon_cnt);
        let pr_resp_cnt = Arc::clone(&probe_resp_cnt);
        let pr_req_cnt = Arc::clone(&probe_req_cnt);
        let de_cnt = Arc::clone(&deauth_cnt);
        let dis_cnt = Arc::clone(&disassoc_cnt);
        let ot_cnt = Arc::clone(&other_cnt);
        let pps_target = Arc::clone(&packets_per_second);

        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let b = b_cnt.swap(0, Ordering::Relaxed);
            let pr_resp = pr_resp_cnt.swap(0, Ordering::Relaxed);
            let pr_req = pr_req_cnt.swap(0, Ordering::Relaxed);
            let de = de_cnt.swap(0, Ordering::Relaxed);
            let dis = dis_cnt.swap(0, Ordering::Relaxed);
            let ot = ot_cnt.swap(0, Ordering::Relaxed);

            let total_5s = b + pr_resp + pr_req + de + dis + ot;
            let pps = total_5s / 5;
            // RC-4 FIX: Use Release so the API server's Acquire load sees the latest value.
            // The swap(0) above already provides atomicity for the counter reset.
            pps_target.store(pps, Ordering::Release);

            println!(
                "[FRAME COUNTER (5s window)] Beacons: {} | ProbeResp: {} | ProbeReq: {} | Deauth: {} | Disassoc: {} | Other: {} | Total Throughput: {} pkts/sec",
                b, pr_resp, pr_req, de, dis, ot, pps
            );
        });
    }

    let cap_opt = capture::open_monitor(IFACE);

    if let Some(mut cap) = cap_opt {
        let mut seen_aps: HashSet<String> = HashSet::new();
        let mut rogue_detector = RogueApDetector::new();
        let mut deauth_detector = DeauthFloodDetector::new();
        let mut karma_detector = KarmaDetector::new();
        let mut sequence_detector = SequenceAnomalyDetector::new();
        let mut probe_flood_detector = ProbeFloodDetector::new();

        println!("WIDPS Hardware Scanner Started on {} (monitor mode active)", IFACE);

        loop {
            let packet = match cap.next_packet() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let data = packet.data;
            let channel = current_channel.load(Ordering::Acquire);

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
                    beacon_cnt.fetch_add(1, Ordering::Relaxed);
                    let ssid = parsed.ssid.clone().unwrap_or_else(|| "<hidden>".to_string());
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

                        if (!ssid.is_empty() && ssid != "<hidden>" && !ssid.starts_with("<unresolved")) || entry.ssid == "<hidden>" || entry.ssid.starts_with("<unresolved") {
                            entry.ssid = ssid.clone();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.encryption = security.clone();
                        entry.lastSeen = now_str;
                    }

                    // RC-2 FIX: Serialize outside the lock to avoid blocking capture
                    {
                        let list: Vec<ScannedAp> = ap_store.lock().unwrap().values().cloned().collect();
                        if let Ok(json_str) = serde_json::to_string(&list) {
                            let _ = fs::write("widps_networks.json", json_str);
                        }
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
                        &ssid,
                        &parsed.bssid,
                        channel,
                        parsed.rssi,
                        &security,
                        &oui_db,
                        &whitelist,
                    );
                    karma_detector.register_beacon_ssid(&ssid);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, "Beacon", Some(&ssid));
                    }
                }
                FrameType::ProbeResponse => {
                    probe_resp_cnt.fetch_add(1, Ordering::Relaxed);
                    let ssid = parsed.ssid.clone().unwrap_or_else(|| "<hidden>".to_string());
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

                        if (!ssid.is_empty() && ssid != "<hidden>" && !ssid.starts_with("<unresolved")) || entry.ssid == "<hidden>" || entry.ssid.starts_with("<unresolved") {
                            entry.ssid = ssid.clone();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.encryption = security;
                        entry.lastSeen = now_str;
                    }

                    // RC-2 FIX: Serialize outside the lock
                    {
                        let list: Vec<ScannedAp> = ap_store.lock().unwrap().values().cloned().collect();
                        if let Ok(json_str) = serde_json::to_string(&list) {
                            let _ = fs::write("widps_networks.json", json_str);
                        }
                    }

                    karma_detector.process_probe_response(&ssid, &parsed.bssid, &parsed.dst);
                    client_tracker.lock().unwrap().record_association_hint(&parsed.dst, &parsed.bssid);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, "ProbeResponse", Some(&ssid));
                    }
                }
                FrameType::ProbeRequest => {
                    probe_req_cnt.fetch_add(1, Ordering::Relaxed);
                    let ssid_str = parsed.ssid.clone().unwrap_or_else(|| "<hidden>".to_string());
                    probe_flood_detector.process(&parsed.src, &ssid_str);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.src, seq, "ProbeRequest", parsed.ssid.as_deref());
                    }
                    if let Some(ssid) = &parsed.ssid {
                        client_tracker.lock().unwrap().record_probe(&parsed.src, ssid);
                    }
                }
                FrameType::Deauth | FrameType::Disassoc => {
                    if parsed.frame_type == FrameType::Deauth {
                        deauth_cnt.fetch_add(1, Ordering::Relaxed);
                    } else {
                        disassoc_cnt.fetch_add(1, Ordering::Relaxed);
                    }
                    deauth_detector.process(parsed.frame_type, &parsed.bssid, &parsed.dst);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, "Deauth/Disassoc", None);
                    }
                    client_tracker.lock().unwrap().record_deauth_victim(&parsed.dst);

                    let now_str = chrono::Local::now().format("%H:%M:%S").to_string();
                    let vendor = oui_db.lookup(&parsed.bssid);
                    let rssi_val = parsed.rssi.unwrap_or(-70);

                    {
                        let mut store = ap_store.lock().unwrap();
                        let entry = store.entry(parsed.bssid.clone()).or_insert_with(|| ScannedAp {
                            id: format!("ap-{}", parsed.bssid.replace(':', "")),
                            ssid: "<unresolved - deauth traffic only>".to_string(),
                            bssid: parsed.bssid.clone(),
                            channel,
                            rssi: rssi_val,
                            vendor: vendor.clone(),
                            encryption: "UNKNOWN".to_string(),
                            beaconIntervalMs: 100,
                            clientCount: 0,
                            status: "Suspicious".into(),
                            firstSeen: now_str.clone(),
                            lastSeen: now_str.clone(),
                        });

                        if entry.ssid == "<hidden>" || entry.ssid.is_empty() {
                            entry.ssid = "<unresolved - deauth traffic only>".to_string();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.lastSeen = now_str;
                        if entry.status == "Normal" {
                            entry.status = "Suspicious".into();
                        }
                    }

                    // RC-2 FIX: Serialize outside the lock
                    {
                        let list: Vec<ScannedAp> = ap_store.lock().unwrap().values().cloned().collect();
                        if let Ok(json_str) = serde_json::to_string(&list) {
                            let _ = fs::write("widps_networks.json", json_str);
                        }
                    }
                }
                FrameType::Other => {
                    other_cnt.fetch_add(1, Ordering::Relaxed);
                }
            }

            // RC-6 FIX: After processing each frame, flush any pending karma probes
            // whose SSIDs may have been registered by beacons in prior iterations.
            karma_detector.flush_pending();
        }
    } else {
        println!("[WIDPS] Interface {} not available on host. Starting simulated wireless network scanner...", IFACE);

        let initial_sim_aps = vec![
          ("CollegeWiFi", "AA:BB:CC:DD:EE:FF", 6, -42, "Cisco Systems", "WPA2-Enterprise"),
          ("CollegeWiFi-5G", "AA:BB:CC:DD:EE:00", 44, -55, "Cisco Systems", "WPA2-Enterprise"),
          ("Hostel_Block_C", "5C:F9:38:22:AB:10", 11, -62, "TP-Link", "WPA2-PSK"),
          ("eduroam", "00:1A:2B:3C:4D:5E", 1, -48, "Aruba Networks", "WPA2-Enterprise"),
          ("Lab304_IoT", "B8:27:EB:77:2C:19", 9, -65, "Raspberry Pi Foundation", "WPA2-PSK"),
          ("FreeCollegeWiFi", "3C:71:BF:44:21:98", 6, -38, "Espressif Inc.", "Open"),
        ];

        let now_str = chrono::Local::now().format("%H:%M:%S").to_string();
        {
            let mut store = ap_store.lock().unwrap();
            for (ssid, bssid, channel, rssi, vendor, enc) in initial_sim_aps {
                store.insert(bssid.to_string(), ScannedAp {
                    id: format!("ap-{}", bssid.replace(':', "")),
                    ssid: ssid.to_string(),
                    bssid: bssid.to_string(),
                    channel,
                    rssi,
                    vendor: vendor.to_string(),
                    encryption: enc.to_string(),
                    beaconIntervalMs: 100,
                    clientCount: 4,
                    status: if ssid.contains("Free") { "Suspicious".into() } else { "Normal".into() },
                    firstSeen: now_str.clone(),
                    lastSeen: now_str.clone(),
                });
            }
            let list: Vec<ScannedAp> = store.values().cloned().collect();
            if let Ok(json_str) = serde_json::to_string(&list) {
                let _ = fs::write("widps_networks.json", json_str);
            }
        }

        let mut loop_counter = 0;
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let ch = (current_channel.load(Ordering::Relaxed) % 11) + 1;
            current_channel.store(ch, Ordering::Relaxed);

            let now = chrono::Local::now().format("%H:%M:%S").to_string();
            {
                let mut store = ap_store.lock().unwrap();
                for ap in store.values_mut() {
                    ap.lastSeen = now.clone();
                }
                let list: Vec<ScannedAp> = store.values().cloned().collect();
                if let Ok(json_str) = serde_json::to_string(&list) {
                    let _ = fs::write("widps_networks.json", json_str);
                }
            }

            loop_counter += 1;
            if loop_counter % 5 == 0 {
                match loop_counter % 25 {
                    5 => alert::fire(
                        alert::Severity::Critical,
                        "Deauthentication Flood Detected (Simulated)",
                        "45 deauth/disassoc frames from BSSID AA:BB:CC:DD:EE:FF within 5s (target client: 00:11:22:33:44:55)",
                    ),
                    10 => alert::fire(
                        alert::Severity::High,
                        "Possible Rogue AP / Evil Twin (Simulated)",
                        "SSID: CollegeWiFi | BSSID: AA:BB:CC:DD:EE:FF | CH: 6 | RSSI: -42 | Vendor: Cisco Systems
SSID: CollegeWiFi | BSSID: 99:88:77:66:55:44 | CH: 6 | RSSI: -45 | Vendor: Unknown
>> Security differs between BSSIDs - strong Evil Twin indicator.",
                    ),
                    15 => alert::fire(
                        alert::Severity::High,
                        "MAC Spoofing / Sequence Anomaly Detected (Simulated)",
                        "Device MAC AA:BB:CC:DD:EE:FF (SSID: 'CollegeWiFi') exhibits severe sequence number anomalies.
Reason: Sequence number went backwards from 1205 to 452 (diff: -753) in 0.8s
Total anomalies tracked for this device: 4",
                    ),
                    20 => alert::fire(
                        alert::Severity::Medium,
                        "Probe Request Flood / Reconnaissance (Simulated)",
                        "Device MAC 00:11:22:33:44:55 sent 42 Probe Requests within 5s (latest requested SSID: 'CollegeWiFi'). Possible network reconnaissance.",
                    ),
                    0 => alert::fire(
                        alert::Severity::Medium,
                        "Possible Karma Attack (Simulated)",
                        "BSSID AA:BB:CC:DD:EE:FF answered client 00:11:22:33:44:55's probe for SSID 'MyHomeWiFi', which has no known legitimate beacon",
                    ),
                    _ => {}
                }
            }
        }
    }
}
