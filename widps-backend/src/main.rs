mod alert;
mod behavioral_profiler;
mod capture;
mod channel_hopper;
mod client_tracker;
mod config;
mod db;
mod detectors;
mod fingerprint;
mod frame;
mod honeypot;
mod ie_parser;
mod logger;
mod ml_bridge;
mod oui;
mod packet_stats;
mod radiotap;
mod report_generator;
mod sse;
mod threat_intel;
mod threat_scorer;
mod whitelist;
mod api_server;
mod siem_forwarder;

use api_server::{ScannedAp, SharedApStore};
use client_tracker::ClientTracker;
use config::ConfigFlags;
use db::Database;
use detectors::auth_flood::AuthFloodDetector;
use detectors::beacon_flood::BeaconFloodDetector;
use detectors::deauth_flood::DeauthFloodDetector;
use detectors::karma::KarmaDetector;
use detectors::rogue_ap::RogueApDetector;
use detectors::sequence_anomaly::SequenceAnomalyDetector;
use detectors::probe_flood::ProbeFloodDetector;
use frame::FrameType;
use fingerprint::FingerprintStore;
use ml_bridge::{FrameForMl, MlBridge};
use oui::OuiDb;
use packet_stats::PacketCounters;
use sse::SseBroadcaster;
use threat_scorer::ThreatScorer;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use whitelist::Whitelist;

const IFACE: &str = "wlan1mon";

fn main() {
    // Initialize structured logging system
    logger::init(logger::Level::Info);
    log_info!("main", "WIDPS starting up");

    let current_channel = Arc::new(AtomicU8::new(1));
    let ap_store: SharedApStore = Arc::new(Mutex::new(HashMap::new()));
    let client_tracker = Arc::new(Mutex::new(ClientTracker::new()));
    let packets_per_second = Arc::new(AtomicU32::new(0));

    let counters = PacketCounters::new();
    let traffic_history = packet_stats::spawn_reporter(&counters, Arc::clone(&packets_per_second));

    let database = Arc::new(Mutex::new(Database::open("data/widps.db")));
    log_info!("main", "Database opened", "path" => "data/widps.db");

    let whitelist = Arc::new(Mutex::new(Whitelist::load("config/whitelist.toml")));
    *whitelist::SHARED_WHITELIST.lock().unwrap() = Some(Arc::clone(&whitelist));
    let oui_db = OuiDb::load("config/oui.csv");
    log_info!("main", "Configuration loaded", "whitelist" => "config/whitelist.toml", "oui" => "config/oui.csv");

    let config_flags = Arc::new(ConfigFlags::new());

    channel_hopper::spawn(
        IFACE,
        Arc::clone(&current_channel),
        Duration::from_millis(300),
        Arc::clone(&config_flags.hopping_enabled),
    );

    let mut ml = MlBridge::spawn("ml/.venv/bin/python", "ml/inference.py");
    let ml_prediction = ml.as_ref()
        .map(|m| Arc::clone(&m.latest_prediction))
        .unwrap_or_else(|| Arc::new(Mutex::new(None)));

    let threat_scorer = Arc::new(Mutex::new(ThreatScorer::new()));
    let sse_broadcaster = Arc::new(Mutex::new(SseBroadcaster::new()));
    alert::set_broadcaster(Arc::clone(&sse_broadcaster));
    alert::set_database(Arc::clone(&database));

    // SIEM forwarder — reads config from environment or defaults to disabled
    let siem_config = siem_forwarder::SiemConfig {
        enabled: std::env::var("WIDPS_SIEM_ENABLED").unwrap_or_default() == "1",
        target_host: std::env::var("WIDPS_SIEM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        target_port: std::env::var("WIDPS_SIEM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(514),
        protocol: if std::env::var("WIDPS_SIEM_TCP").unwrap_or_default() == "1" {
            siem_forwarder::SiemProtocol::Tcp
        } else {
            siem_forwarder::SiemProtocol::Udp
        },
        format: match std::env::var("WIDPS_SIEM_FORMAT").unwrap_or_default().as_str() {
            "cef" => siem_forwarder::SiemFormat::Cef,
            "syslog" => siem_forwarder::SiemFormat::Syslog,
            _ => siem_forwarder::SiemFormat::Json,
        },
        ..Default::default()
    };
    let _siem = siem_forwarder::spawn_siem_listener(Arc::clone(&sse_broadcaster), siem_config);

    // Honeypot monitor — watches for devices connecting to the fake AP
    let _honeypot = honeypot::spawn_monitor(
        Arc::clone(&threat_scorer),
        Arc::clone(&sse_broadcaster),
    );

    // Behavioral profiler — tracks per-device long-term patterns
    let profiler: behavioral_profiler::SharedProfiler = Arc::new(Mutex::new(behavioral_profiler::BehavioralProfiler::new()));
    log_info!("main", "Behavioral profiler initialized");

    // Set global reference for API access
    *behavioral_profiler::SHARED_PROFILER.lock().unwrap() = Some(Arc::clone(&profiler));

    // Threat Intelligence Platform
    let threat_intel: threat_intel::SharedThreatIntel = Arc::new(Mutex::new(threat_intel::ThreatIntelPlatform::new()));
    *threat_intel::SHARED_INTEL.lock().unwrap() = Some(Arc::clone(&threat_intel));
    // Register known SSIDs for similarity detection
    {
        let wl = whitelist.lock().unwrap();
        let known_ssids: Vec<String> = wl.get_all().into_iter().map(|(ssid, _)| ssid).collect();
        threat_intel.lock().unwrap().register_known_ssids(&known_ssids);
    }
    log_info!("main", "Threat intelligence platform initialized");

    // Background maintenance thread (data retention + auto-archive)
    {
        let db_clone = Arc::clone(&database);
        let flags_clone = Arc::clone(&config_flags);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(300)); // Run every 5 minutes

                let retention = flags_clone.retention_days.load(std::sync::atomic::Ordering::Acquire);
                let archive_hours = flags_clone.auto_archive_hours.load(std::sync::atomic::Ordering::Acquire);

                if let Ok(db) = db_clone.lock() {
                    // Data retention pruning
                    if retention > 0 {
                        let pruned_alerts = db.prune_alerts_older_than(retention);
                        let pruned_preds = db.prune_predictions_older_than(retention);
                        if pruned_alerts > 0 || pruned_preds > 0 {
                            println!("[maintenance] Pruned {} alerts + {} predictions (>{} days old)",
                                pruned_alerts, pruned_preds, retention);
                        }
                    }

                    // Auto-archive old alerts
                    if archive_hours > 0 {
                        let archived = db.auto_archive_older_than(archive_hours);
                        if archived > 0 {
                            println!("[maintenance] Auto-archived {} alerts (>{}h old)", archived, archive_hours);
                        }
                    }
                }
            }
        });
        log_info!("main", "Background maintenance thread started");
    }

    api_server::spawn(
        8787,
        Arc::clone(&ap_store),
        Arc::clone(&current_channel),
        Arc::clone(&client_tracker),
        Arc::clone(&packets_per_second),
        Arc::clone(&traffic_history),
        Arc::clone(&ml_prediction),
        Arc::clone(&threat_scorer),
        Arc::clone(&sse_broadcaster),
        Arc::clone(&config_flags),
        Arc::clone(&database),
    );

    let cap_opt = capture::open_monitor(IFACE);

    if let Some(mut cap) = cap_opt {
        let mut seen_aps: HashSet<String> = HashSet::new();
        let mut rogue_detector = RogueApDetector::new();
        let mut deauth_detector = DeauthFloodDetector::new();
        let mut karma_detector = KarmaDetector::new();
        let mut sequence_detector = SequenceAnomalyDetector::new();
        let mut probe_flood_detector = ProbeFloodDetector::new();
        let mut beacon_flood_detector = BeaconFloodDetector::new();
        let mut auth_flood_detector = AuthFloodDetector::new();
        let mut fingerprint_store = FingerprintStore::new();

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

            if let Some(ref mut bridge) = ml {
                let ml_frame = FrameForMl {
                    fc_type: match parsed.frame_type {
                        FrameType::Beacon | FrameType::ProbeRequest | FrameType::ProbeResponse
                        | FrameType::Deauth | FrameType::Disassoc | FrameType::Auth | FrameType::AssocRequest => 0,
                        _ => 2,
                    },
                    fc_subtype: match parsed.frame_type {
                        FrameType::Beacon => 8,
                        FrameType::ProbeRequest => 4,
                        FrameType::ProbeResponse => 5,
                        FrameType::Deauth => 12,
                        FrameType::Disassoc => 10,
                        FrameType::Auth => 11,
                        FrameType::AssocRequest => 0,
                        _ => 0,
                    },
                    dst: parsed.dst.clone(),
                    src: parsed.src.clone(),
                    rssi: parsed.rssi.unwrap_or(-90),
                    frame_length: data.len() as u16,
                    duration: 0,
                    protected: if parsed.retry { 0 } else { 0 },
                    retry: if parsed.retry { 1 } else { 0 },
                    reason_code: 0,
                    seq_num: parsed.seq_num.unwrap_or(0),
                    inter_frame_time: 0.001,
                    timestamp: chrono::Local::now().timestamp_millis() as f64 / 1000.0,
                };
                bridge.send_frame(&ml_frame);
            }

            match parsed.frame_type {
                FrameType::Beacon => {
                    counters.beacon.fetch_add(1, Ordering::Relaxed);
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
                            beacon_interval_ms: 100,
                            client_count: 0,
                            status: "Normal".into(),
                            first_seen: now_str.clone(),
                            last_seen: now_str.clone(),
                            rssi_history: Vec::with_capacity(20),
                        });

                        if (!ssid.is_empty() && ssid != "<hidden>" && !ssid.starts_with("<unresolved")) || entry.ssid == "<hidden>" || entry.ssid.starts_with("<unresolved") {
                            entry.ssid = ssid.clone();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.encryption = security.clone();
                        entry.last_seen = now_str;
                        entry.push_rssi(rssi_val);
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
                        database.lock().unwrap().insert_network(
                            &parsed.bssid, &ssid, channel, rssi_val, &vendor, &security, "Normal",
                        );
                    }

                    rogue_detector.process(
                        &ssid,
                        &parsed.bssid,
                        channel,
                        parsed.rssi,
                        &security,
                        &oui_db,
                        &whitelist.lock().unwrap(),
                    );

                    if data.len() > rt.header_len + 36 {
                        let fp = fingerprint::extract_fingerprint(data, rt.header_len + 36);
                        if let Some(mismatch) = fingerprint_store.check_and_store(&parsed.bssid, &fp) {
                            threat_scorer.lock().unwrap().add_evidence(
                                &mismatch.bssid,
                                Some(&ssid),
                                "fingerprint",
                                30.0,
                                &format!("Device fingerprint changed (hash {:x} → {:x}) — possible hardware swap or Evil Twin", mismatch.old_hash, mismatch.new_hash),
                            );
                        }
                    }

                    karma_detector.register_beacon_ssid(&ssid);
                    beacon_flood_detector.process(&parsed.bssid, &ssid);
                    // Feed rogue AP evidence if not whitelisted and multiple BSSIDs seen
                    if !whitelist.lock().unwrap().is_trusted(&ssid, &parsed.bssid) && whitelist.lock().unwrap().has_entries_for(&ssid) {
                        threat_scorer.lock().unwrap().add_evidence(
                            &parsed.bssid, Some(&ssid), "rogue_ap", 15.0,
                            "BSSID not in whitelist for known SSID",
                        );
                    }
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, FrameType::Beacon, "Beacon", Some(&ssid), parsed.retry, parsed.is_qos, parsed.rssi);
                    }
                }
                FrameType::ProbeResponse => {
                    counters.probe_resp.fetch_add(1, Ordering::Relaxed);
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
                            beacon_interval_ms: 100,
                            client_count: 0,
                            status: "Normal".into(),
                            first_seen: now_str.clone(),
                            last_seen: now_str.clone(),
                            rssi_history: Vec::with_capacity(20),
                        });

                        if (!ssid.is_empty() && ssid != "<hidden>" && !ssid.starts_with("<unresolved")) || entry.ssid == "<hidden>" || entry.ssid.starts_with("<unresolved") {
                            entry.ssid = ssid.clone();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.encryption = security;
                        entry.last_seen = now_str;
                        entry.push_rssi(rssi_val);
                    }

                    // RC-2 FIX: Serialize outside the lock
                    {
                        let list: Vec<ScannedAp> = ap_store.lock().unwrap().values().cloned().collect();
                        if let Ok(json_str) = serde_json::to_string(&list) {
                            let _ = fs::write("widps_networks.json", json_str);
                        }
                    }

                    karma_detector.process_probe_response(&ssid, &parsed.bssid, &parsed.dst);
                    // Karma probe responses add suspicion to the AP
                    threat_scorer.lock().unwrap().add_evidence(
                        &parsed.bssid, Some(&ssid), "karma_detector", 3.0,
                        "Probe response observed (monitoring for karma behavior)",
                    );
                    client_tracker.lock().unwrap().record_association_hint(&parsed.dst, &parsed.bssid);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, FrameType::ProbeResponse, "ProbeResponse", Some(&ssid), parsed.retry, parsed.is_qos, parsed.rssi);
                    }
                }
                FrameType::ProbeRequest => {
                    counters.probe_req.fetch_add(1, Ordering::Relaxed);
                    let ssid_str = parsed.ssid.clone().unwrap_or_else(|| "<hidden>".to_string());
                    probe_flood_detector.process(&parsed.src, &ssid_str);
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.src, seq, FrameType::ProbeRequest, "ProbeRequest", parsed.ssid.as_deref(), parsed.retry, parsed.is_qos, parsed.rssi);
                    }
                    if let Some(ssid) = &parsed.ssid {
                        client_tracker.lock().unwrap().record_probe(&parsed.src, ssid);
                    }
                    // Behavioral profiler: observe this device's probe behavior
                    {
                        let anomalies = profiler.lock().unwrap().observe(
                            &parsed.src,
                            parsed.ssid.as_deref(),
                            channel,
                            parsed.rssi,
                        );
                        if !anomalies.is_empty() {
                            behavioral_profiler::handle_anomalies(&parsed.src, &anomalies, &threat_scorer);
                        }
                    }
                }
                FrameType::Deauth | FrameType::Disassoc => {
                    if parsed.frame_type == FrameType::Deauth {
                        counters.deauth.fetch_add(1, Ordering::Relaxed);
                    } else {
                        counters.disassoc.fetch_add(1, Ordering::Relaxed);
                    }
                    deauth_detector.process(parsed.frame_type, &parsed.bssid, &parsed.dst);
                    // Feed deauth evidence to threat scorer
                    threat_scorer.lock().unwrap().add_evidence(
                        &parsed.bssid, None, "deauth_detector", 5.0,
                        "Deauth/disassoc frame observed",
                    );
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.bssid, seq, FrameType::Deauth, "Deauth/Disassoc", None, parsed.retry, parsed.is_qos, parsed.rssi);
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
                            beacon_interval_ms: 100,
                            client_count: 0,
                            status: "Suspicious".into(),
                            first_seen: now_str.clone(),
                            last_seen: now_str.clone(),
                            rssi_history: Vec::with_capacity(20),
                        });

                        if entry.ssid == "<hidden>" || entry.ssid.is_empty() {
                            entry.ssid = "<unresolved - deauth traffic only>".to_string();
                        }
                        entry.channel = channel;
                        entry.rssi = rssi_val;
                        entry.last_seen = now_str;
                        entry.push_rssi(rssi_val);
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
                FrameType::Auth | FrameType::AssocRequest => {
                    counters.auth.fetch_add(1, Ordering::Relaxed);
                    auth_flood_detector.process(&parsed.bssid, &parsed.src);
                    // Feed auth flood evidence to threat scorer
                    threat_scorer.lock().unwrap().add_evidence(
                        &parsed.bssid, None, "auth_flood", 3.0,
                        "Auth/Assoc frame targeting this BSSID",
                    );
                    if let Some(seq) = parsed.seq_num {
                        sequence_detector.process(&parsed.src, seq, FrameType::Auth, "Auth/Assoc", None, parsed.retry, parsed.is_qos, parsed.rssi);
                    }
                }
                FrameType::Other => {
                    counters.other.fetch_add(1, Ordering::Relaxed);
                }
            }

            // RC-6 FIX: After processing each frame, flush any pending karma probes
            // whose SSIDs may have been registered by beacons in prior iterations.
            karma_detector.flush_pending();

            // Feed ML predictions to the threat scorer when available
            if let Some(pred) = ml_prediction.lock().unwrap().clone() {
                if pred.label != "Normal" && pred.confidence > 0.5 {
                    let bssid_guess = parsed.bssid.clone();
                    threat_scorer.lock().unwrap().add_ml_evidence(
                        &bssid_guess,
                        &pred.label,
                        pred.confidence,
                        pred.threat_score,
                    );
                    database.lock().unwrap().insert_ml_prediction(
                        &pred.label,
                        pred.confidence,
                        pred.threat_score,
                        pred.frame_count,
                    );
                    if let Ok(json) = serde_json::to_string(&pred) {
                        sse_broadcaster.lock().unwrap().push("ml_prediction", &json);
                    }
                }
            }
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
                    beacon_interval_ms: 100,
                    client_count: 4,
                    status: if ssid.contains("Free") { "Suspicious".into() } else { "Normal".into() },
                    first_seen: now_str.clone(),
                    last_seen: now_str.clone(),
                    rssi_history: vec![rssi],
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
                    ap.last_seen = now.clone();
                    // Simulate RSSI fluctuation for sparkline
                    let jitter = (loop_counter as i8 % 7) - 3; // -3 to +3
                    let new_rssi = (ap.rssi as i16 + jitter as i16).clamp(-95, -20) as i8;
                    ap.push_rssi(new_rssi);
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
