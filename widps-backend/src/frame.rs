use crate::ie_parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Beacon,
    ProbeRequest,
    ProbeResponse,
    Deauth,
    Disassoc,
    Auth,
    AssocRequest,
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
    pub seq_num: Option<u16>,
    pub retry: bool,
    pub is_qos: bool,
    /// Protected Frame bit (frame control byte 2, bit 6).
    pub protected: bool,
    /// Duration/ID field as sent on air.
    pub duration: u16,
    /// Reason code for deauthentication and disassociation frames, else 0.
    pub reason_code: u16,
}

pub fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

/// Classify a frame from the first Frame Control byte.
pub fn frame_type_from_fc1(fc1: u8) -> FrameType {
    let version = fc1 & 0x03;
    let ftype = (fc1 >> 2) & 0x03;
    if version != 0 || ftype != 0 {
        return FrameType::Other;
    }
    match fc1 & 0xF0 {
        0x80 => FrameType::Beacon,
        0x40 => FrameType::ProbeRequest,
        0x50 => FrameType::ProbeResponse,
        0xC0 => FrameType::Deauth,
        0xA0 => FrameType::Disassoc,
        0xB0 => FrameType::Auth,
        0x00 => FrameType::AssocRequest,
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
    let fc2 = data[radiotap_len + 1];
    let frame_type = frame_type_from_fc1(fc1);
    if frame_type == FrameType::Other {
        return None;
    }

    let retry = (fc2 & 0x08) != 0;
    let protected = (fc2 & 0x40) != 0;
    let duration = u16::from_le_bytes([data[radiotap_len + 2], data[radiotap_len + 3]]);
    // QoS is a data-frame property; only management frames reach this point.
    let is_qos = false;

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
        FrameType::AssocRequest => {
            if data.len() >= radiotap_len + 28 {
                ssid = parse_ssid(data, radiotap_len + 28);
            }
        }
        _ => {}
    }

    let seq_ctrl = u16::from_le_bytes([data[radiotap_len + 22], data[radiotap_len + 23]]);
    let seq_num = seq_ctrl >> 4;

    let reason_code = match frame_type {
        FrameType::Deauth | FrameType::Disassoc if data.len() >= radiotap_len + 26 => {
            u16::from_le_bytes([data[radiotap_len + 24], data[radiotap_len + 25]])
        }
        _ => 0,
    };

    Some(Dot11Frame {
        frame_type, bssid, src, dst, ssid, security, rssi,
        seq_num: Some(seq_num), retry, is_qos, protected, duration, reason_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RT_LEN: usize = 8;

    /// Minimal radiotap header (no present fields) followed by an 802.11 header of 24 bytes and the given...
    fn build(fc1: u8, fc2: u8, seq: u16, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8, 0, RT_LEN as u8, 0, 0, 0, 0, 0];
        v.push(fc1);
        v.push(fc2);
        v.extend_from_slice(&[0, 0]); // duration
        v.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // addr1 (dst)
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // addr2 (src)
        v.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // addr3 (bssid)
        v.extend_from_slice(&((seq << 4).to_le_bytes())); // sequence control
        v.extend_from_slice(body);
        v
    }

    fn ssid_tag(name: &str) -> Vec<u8> {
        let mut t = vec![0u8, name.len() as u8];
        t.extend_from_slice(name.as_bytes());
        t
    }

    fn beacon_body(name: &str) -> Vec<u8> {
        let mut b = vec![0u8; 12]; // timestamp(8) + interval(2) + capability(2)
        b.extend(ssid_tag(name));
        b
    }

    fn parse(data: &[u8]) -> Option<Dot11Frame> {
        parse_frame(data, RT_LEN, Some(-50))
    }

    // management frames are classified correctly

    #[test]
    fn classifies_management_subtypes() {
        let cases = [
            (0x00u8, FrameType::AssocRequest),
            (0x40, FrameType::ProbeRequest),
            (0x50, FrameType::ProbeResponse),
            (0x80, FrameType::Beacon),
            (0xA0, FrameType::Disassoc),
            (0xB0, FrameType::Auth),
            (0xC0, FrameType::Deauth),
        ];
        for (fc1, expected) in cases {
            assert_eq!(frame_type_from_fc1(fc1), expected, "fc1 = {:#04x}", fc1);
        }
    }

    // non-management frames must never be classified as management

    #[test]
    fn data_frames_are_not_management() {
        // 0x08 plain data, 0x88 QoS data, 0x48 null data, 0xC8 QoS null, 0x28 data+CF-poll, 0xA8 QoS...
        for fc1 in [0x08u8, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x98, 0xB8] {
            assert_eq!(frame_type_from_fc1(fc1), FrameType::Other, "fc1 = {:#04x}", fc1);
        }
    }

    #[test]
    fn control_frames_are_not_management() {
        // 0xB4 RTS, 0xC4 CTS, 0xD4 ACK, 0xA4 PS-Poll, 0xE4 CF-End, 0x84 BlockAckReq, 0x94 BlockAck
        for fc1 in [0xB4u8, 0xC4, 0xD4, 0xA4, 0xE4, 0x84, 0x94] {
            assert_eq!(frame_type_from_fc1(fc1), FrameType::Other, "fc1 = {:#04x}", fc1);
        }
    }

    #[test]
    fn unhandled_management_subtypes_are_other() {
        // 0x10 assoc response, 0x20 reassoc request, 0x30 reassoc response, 0x90 ATIM, 0xD0 action
        for fc1 in [0x10u8, 0x20, 0x30, 0x90, 0xD0] {
            assert_eq!(frame_type_from_fc1(fc1), FrameType::Other, "fc1 = {:#04x}", fc1);
        }
    }

    #[test]
    fn nonzero_protocol_version_is_rejected() {
        for fc1 in [0x81u8, 0x82, 0x83, 0xC1, 0x41] {
            assert_eq!(frame_type_from_fc1(fc1), FrameType::Other, "fc1 = {:#04x}", fc1);
        }
    }

    #[test]
    fn parse_frame_rejects_data_and_control_frames_even_when_long_enough() {
        // Each frame is padded to a full 24-byte header so only the type bits can reject it (the old...
        for fc1 in [0x88u8, 0x08, 0x48, 0xB4, 0xC4, 0xA4] {
            let data = build(fc1, 0, 1, &beacon_body("X"));
            assert!(parse(&data).is_none(), "fc1 = {:#04x} must be rejected", fc1);
        }
    }

    // field extraction

    #[test]
    fn parses_beacon_fields() {
        let data = build(0x80, 0x00, 1234, &beacon_body("CollegeWiFi"));
        let f = parse(&data).expect("beacon must parse");
        assert_eq!(f.frame_type, FrameType::Beacon);
        assert_eq!(f.dst, "11:22:33:44:55:66");
        assert_eq!(f.src, "AA:BB:CC:DD:EE:FF");
        assert_eq!(f.bssid, "01:02:03:04:05:06");
        assert_eq!(f.ssid.as_deref(), Some("CollegeWiFi"));
        assert_eq!(f.seq_num, Some(1234));
        assert_eq!(f.rssi, Some(-50));
        assert!(!f.retry);
        assert!(!f.is_qos);
    }

    #[test]
    fn parses_hidden_ssid_beacon() {
        let data = build(0x80, 0x00, 1, &beacon_body(""));
        let f = parse(&data).unwrap();
        assert_eq!(f.ssid.as_deref(), Some("<hidden>"));
    }

    #[test]
    fn parses_probe_request_ssid() {
        let data = build(0x40, 0x00, 5, &ssid_tag("HomeNet"));
        let f = parse(&data).unwrap();
        assert_eq!(f.frame_type, FrameType::ProbeRequest);
        assert_eq!(f.ssid.as_deref(), Some("HomeNet"));
    }

    #[test]
    fn parses_assoc_request_ssid_after_fixed_params() {
        let mut body = vec![0u8; 4]; // capability + listen interval
        body.extend(ssid_tag("CorpNet"));
        let data = build(0x00, 0x00, 5, &body);
        let f = parse(&data).unwrap();
        assert_eq!(f.frame_type, FrameType::AssocRequest);
        assert_eq!(f.ssid.as_deref(), Some("CorpNet"));
    }

    #[test]
    fn parses_deauth_with_reason_body() {
        let data = build(0xC0, 0x00, 77, &[0x07, 0x00]);
        let f = parse(&data).unwrap();
        assert_eq!(f.frame_type, FrameType::Deauth);
        assert_eq!(f.seq_num, Some(77));
    }

    #[test]
    fn retry_flag_is_read_from_fc2() {
        let data = build(0xC0, 0x08, 1, &[0x07, 0x00]);
        assert!(parse(&data).unwrap().retry);
        let data = build(0xC0, 0x00, 1, &[0x07, 0x00]);
        assert!(!parse(&data).unwrap().retry);
    }

    #[test]
    fn sequence_number_uses_upper_twelve_bits() {
        let data = build(0x80, 0x00, 4095, &beacon_body("A"));
        assert_eq!(parse(&data).unwrap().seq_num, Some(4095));
    }

    // robustness

    #[test]
    fn truncated_frames_return_none_without_panicking() {
        let data = build(0x80, 0x00, 1, &beacon_body("CollegeWiFi"));
        for cut in 0..(RT_LEN + 24) {
            assert!(parse(&data[..cut]).is_none(), "cut at {}", cut);
        }
    }

    #[test]
    fn truncated_ie_does_not_panic() {
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&[0, 40, b'A']); // claims 40 bytes, has 1
        let data = build(0x80, 0x00, 1, &body);
        let f = parse(&data).unwrap();
        assert_eq!(f.ssid, None);
    }

    #[test]
    fn short_beacon_body_has_no_ssid() {
        let data = build(0x80, 0x00, 1, &[0u8; 6]);
        let f = parse(&data).unwrap();
        assert_eq!(f.ssid, None);
    }

    #[test]
    fn radiotap_length_longer_than_data_returns_none() {
        let data = build(0x80, 0x00, 1, &beacon_body("A"));
        assert!(parse_frame(&data, data.len(), None).is_none());
    }

    #[test]
    fn every_first_byte_with_full_header_never_panics() {
        for fc1 in 0..=255u8 {
            for fc2 in [0u8, 0x08, 0x40, 0xFF] {
                let data = build(fc1, fc2, 1, &beacon_body("Z"));
                let _ = parse(&data);
            }
        }
    }

    #[test]
    fn only_management_type_frames_are_ever_parsed() {
        for fc1 in 0..=255u8 {
            let data = build(fc1, 0, 1, &beacon_body("Z"));
            if parse(&data).is_some() {
                assert_eq!((fc1 >> 2) & 0x03, 0, "fc1 = {:#04x} parsed but is not management", fc1);
                assert_eq!(fc1 & 0x03, 0, "fc1 = {:#04x} parsed with non-zero version", fc1);
            }
        }
    }

    #[test]
    fn extracts_reason_code_protected_and_duration() {
        let mut data = build(0xC0, 0x40, 1, &[0x07, 0x00]);
        data[RT_LEN + 2] = 0x2C; // duration low byte
        data[RT_LEN + 3] = 0x01; // duration high byte -> 0x012C = 300
        let f = parse(&data).unwrap();
        assert_eq!(f.reason_code, 7);
        assert!(f.protected);
        assert_eq!(f.duration, 300);
    }

    #[test]
    fn reason_code_is_zero_when_body_missing_or_not_deauth() {
        let f = parse(&build(0xC0, 0x00, 1, &[])).unwrap();
        assert_eq!(f.reason_code, 0);
        let f = parse(&build(0xC0, 0x00, 1, &[0x07])).unwrap();
        assert_eq!(f.reason_code, 0);
        let f = parse(&build(0x80, 0x00, 1, &[0x07, 0x00, 0, 0])).unwrap();
        assert_eq!(f.reason_code, 0);
    }
}
