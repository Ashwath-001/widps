use pcap::Capture;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant};
use std::{thread};

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn set_channel(channel: u8) {
    let _ = Command::new("iw")
        .args(["dev", "wlan1mon", "set", "channel", &channel.to_string()])
        .status();
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FrameType {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Deauth,
    Disassoc,
    Other,
}

fn frame_type_from_fc1(fc1: u8) -> FrameType {
    match fc1 {
        0x80 => FrameType::Beacon,
        0x40 => FrameType::ProbeRequest,
        0x50 => FrameType::ProbeResponse,
        0xC0 => FrameType::Deauth,
        0xA0 => FrameType::Disassoc,
        _ => FrameType::Other,
    }
}

// SSID tag parsing, given the correct starting offset for tagged params
fn parse_ssid(data: &[u8], mut pos: usize) -> Option<String> {
    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        if pos + 2 + len > data.len() {
            break;
        }
        if tag == 0 {
            return Some(if len == 0 {
                "<hidden>".to_string()
            } else {
                String::from_utf8_lossy(&data[pos + 2..pos + 2 + len]).to_string()
            });
        }
        pos += 2 + len;
    }
    None
}

// ---------- Alerting ----------

#[derive(Debug, Clone)]
enum Severity {
    Medium,
    High,
    Critical,
}

fn fire_alert(sev: Severity, title: &str, detail: &str) {
    let ts = chrono_like_timestamp();
    println!("[{}] [{:?}] {} — {}", ts, sev, title, detail);

    let line = format!(
        "{{\"time\":\"{}\",\"severity\":\"{:?}\",\"title\":\"{}\",\"detail\":\"{}\"}}",
        ts, sev, title, detail.replace('"', "'")
    );
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("widps_alerts.jsonl")
    {
        let _ = writeln!(f, "{}", line);
    }
}

// avoids pulling in chrono just for this — replace with chrono if you already use it elsewhere
fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}", now.as_secs())
}

// ---------- Detectors ----------

struct RogueApDetector {
    ssid_to_bssids: HashMap<String, HashSet<String>>,
}

impl RogueApDetector {
    fn new() -> Self {
        Self { ssid_to_bssids: HashMap::new() }
    }

    fn process(&mut self, ssid: &str, bssid: &str, channel: u8) {
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }
        let set = self.ssid_to_bssids.entry(ssid.to_string()).or_insert_with(HashSet::new);
        let was_new = set.insert(bssid.to_string());
        if was_new && set.len() > 1 {
            fire_alert(
                Severity::High,
                "Possible Rogue AP / Evil Twin",
                &format!(
                    "SSID '{}' now seen on {} BSSIDs (new: {}, channel {})",
                    ssid, set.len(), bssid, channel
                ),
            );
        }
    }
}

struct DeauthFloodDetector {
    counts: HashMap<String, (u32, Instant)>,
}

const DEAUTH_WINDOW: Duration = Duration::from_secs(5);
const DEAUTH_THRESHOLD: u32 = 10;

impl DeauthFloodDetector {
    fn new() -> Self {
        Self { counts: HashMap::new() }
    }

    fn process(&mut self, frame_type: FrameType, bssid: &str) {
        if !matches!(frame_type, FrameType::Deauth | FrameType::Disassoc) {
            return;
        }
        let entry = self.counts.entry(bssid.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() > DEAUTH_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;

        if entry.0 == DEAUTH_THRESHOLD {
            fire_alert(
                Severity::Critical,
                "Deauthentication Flood Detected",
                &format!(
                    "{} deauth/disassoc frames from BSSID {} within {:?}",
                    entry.0, bssid, DEAUTH_WINDOW
                ),
            );
        }
    }
}

// Day 2 stretch: Karma detection — AP responds to probe for SSID it never beaconed
struct KarmaDetector {
    known_ssids: HashSet<String>, // legit SSIDs seen via beacons
}

impl KarmaDetector {
    fn new() -> Self {
        Self { known_ssids: HashSet::new() }
    }

    fn register_beacon_ssid(&mut self, ssid: &str) {
        if !ssid.is_empty() && ssid != "<hidden>" {
            self.known_ssids.insert(ssid.to_string());
        }
    }

    fn process_probe_response(&self, ssid: &str, bssid: &str) {
        if ssid.is_empty() || ssid == "<hidden>" {
            return;
        }
        // Heuristic: responding to an SSID we've NEVER seen beaconed by anyone
        // is suspicious (classic karma/pineapple behavior)
        if !self.known_ssids.contains(ssid) {
            fire_alert(
                Severity::Medium,
                "Possible Karma Attack",
                &format!(
                    "BSSID {} responded to probe for SSID '{}' which has no known legitimate beacon",
                    bssid, ssid
                ),
            );
        }
    }
}

fn main() {
    let mut cap = Capture::from_device("wlan1mon")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut seen_aps = HashSet::new();
    let mut rogue_detector = RogueApDetector::new();
    let mut deauth_detector = DeauthFloodDetector::new();
    let mut karma_detector = KarmaDetector::new();

    println!("WIDPS Scanner Started");
    let channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    loop {
        for channel in channels {
            println!("\n=== Channel {} ===", channel);
            set_channel(channel);
            thread::sleep(Duration::from_millis(500));
            let start = Instant::now();

            while start.elapsed().as_secs() < 3 {
                match cap.next_packet() {
                    Ok(packet) => {
                        let data = packet.data;
                        if data.len() < 4 {
                            continue;
                        }
                        let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                        if data.len() < radiotap_len + 24 {
                            continue;
                        }

                        let fc1 = data[radiotap_len];
                        let frame_type = frame_type_from_fc1(fc1);
                        if frame_type == FrameType::Other {
                            continue;
                        }

                        let dst = format_mac(&data[radiotap_len + 4..radiotap_len + 10]);
                        let src = format_mac(&data[radiotap_len + 10..radiotap_len + 16]);
                        let bssid = format_mac(&data[radiotap_len + 16..radiotap_len + 22]);

                        match frame_type {
                            FrameType::Beacon => {
                                // fixed fields (timestamp+interval+capability) = 12 bytes before tags
                                if data.len() < radiotap_len + 36 { continue; }
                                if let Some(ssid) = parse_ssid(data, radiotap_len + 36) {
                                    let key = format!("{}|{}", ssid, bssid);
                                    if seen_aps.insert(key) {
                                        println!("[NEW AP] CH:{} | SSID:{} | BSSID:{}", channel, ssid, bssid);
                                    }
                                    rogue_detector.process(&ssid, &bssid, channel);
                                    karma_detector.register_beacon_ssid(&ssid);
                                }
                            }
                            FrameType::ProbeResponse => {
                                if data.len() < radiotap_len + 36 { continue; }
                                if let Some(ssid) = parse_ssid(data, radiotap_len + 36) {
                                    karma_detector.process_probe_response(&ssid, &bssid);
                                }
                            }
                            FrameType::ProbeRequest => {
                                // no fixed fields, tags start right after 24-byte header
                                let _ = parse_ssid(data, radiotap_len + 24);
                                // could track requesting client (src) for further correlation
                                let _ = src;
                            }
                            FrameType::Deauth | FrameType::Disassoc => {
                                deauth_detector.process(frame_type, &bssid);
                                let _ = dst;
                            }
                            FrameType::Other => {}
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
}
