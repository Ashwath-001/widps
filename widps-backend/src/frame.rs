use crate::ie_parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Deauth,
    Disassoc,
    Other,
}

pub struct Dot11Frame {
    pub frame_type: FrameType,
    pub bssid: String,
    pub src: String,
    pub dst: String,
    pub ssid: Option<String>,
    pub security: Option<String>,
    pub rssi: Option<i8>,
}

pub fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

pub fn frame_type_from_fc1(fc1: u8) -> FrameType {
    match fc1 & 0xF0 {
        0x80 => FrameType::Beacon,
        0x40 => FrameType::ProbeRequest,
        0x50 => FrameType::ProbeResponse,
        0xC0 => FrameType::Deauth,
        0xA0 => FrameType::Disassoc,
        _ => FrameType::Other,
    }
}

pub fn parse_ssid(data: &[u8], mut pos: usize) -> Option<String> {
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

pub fn parse_frame(data: &[u8], radiotap_len: usize, rssi: Option<i8>) -> Option<Dot11Frame> {
    if data.len() < radiotap_len + 24 {
        return None;
    }

    let fc1 = data[radiotap_len];
    let frame_type = frame_type_from_fc1(fc1);
    if frame_type == FrameType::Other {
        return None;
    }

    let dst = format_mac(&data[radiotap_len + 4..radiotap_len + 10]);
    let src = format_mac(&data[radiotap_len + 10..radiotap_len + 16]);
    let bssid = format_mac(&data[radiotap_len + 16..radiotap_len + 22]);

    let mut ssid = None;
    let mut security = None;

    match frame_type {
        FrameType::Beacon | FrameType::ProbeResponse => {
            if data.len() >= radiotap_len + 36 {
                let tag_start = radiotap_len + 36;
                ssid = parse_ssid(data, tag_start);
                security = ie_parser::security_signature(data, tag_start);
            }
        }
        FrameType::ProbeRequest => {
            if data.len() >= radiotap_len + 24 {
                ssid = parse_ssid(data, radiotap_len + 24);
            }
        }
        _ => {}
    }

    Some(Dot11Frame { frame_type, bssid, src, dst, ssid, security, rssi })
}