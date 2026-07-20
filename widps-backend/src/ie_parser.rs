pub fn security_signature(data: &[u8], mut pos: usize) -> Option<String> {
    let mut sig = String::new();

    while pos + 2 <= data.len() {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        if pos + 2 + len > data.len() {
            break;
        }
        let body = &data[pos + 2..pos + 2 + len];

        match tag {
            48 => {
                if let Some(s) = parse_cipher_block(body, 2) {
                    sig.push_str("RSN[");
                    sig.push_str(&s);
                    sig.push(']');
                }
            }
            221 => {
                // Microsoft WPA OUI 00:50:F2, type 1
                if body.len() >= 4 && body[0..3] == [0x00, 0x50, 0xF2] && body[3] == 0x01 {
                    if let Some(s) = parse_cipher_block(body, 4 + 2) {
                        sig.push_str("WPA[");
                        sig.push_str(&s);
                        sig.push(']');
                    }
                }
            }
            _ => {}
        }

        pos += 2 + len;
    }

    Some(if sig.is_empty() { "OPEN".to_string() } else { sig })
}

fn cipher_name(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "?".to_string();
    }
    match suite[3] {
        1 => "WEP40".into(),
        2 => "TKIP".into(),
        4 => "CCMP".into(),
        5 => "WEP104".into(),
        8 => "GCMP".into(),
        n => format!("C{}", n),
    }
}

fn akm_name(suite: &[u8]) -> String {
    if suite.len() != 4 {
        return "?".to_string();
    }
    match suite[3] {
        1 => "802.1X".into(),
        2 => "PSK".into(),
        8 => "SAE".into(), // WPA3
        n => format!("A{}", n),
    }
}

// `skip` = bytes to skip before the group-cipher field (differs between
// RSN's 2-byte version prefix and WPA's OUI+type+version prefix).
fn parse_cipher_block(body: &[u8], skip: usize) -> Option<String> {
    if body.len() < skip + 6 {
        return None;
    }
    let mut pos = skip;
    let group = cipher_name(&body[pos..pos + 4]);
    pos += 4;

    if pos + 2 > body.len() {
        return Some(format!("grp={}", group));
    }
    let pairwise_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let mut pairwise = Vec::new();
    for _ in 0..pairwise_count {
        if pos + 4 > body.len() { break; }
        pairwise.push(cipher_name(&body[pos..pos + 4]));
        pos += 4;
    }

    let mut akms = Vec::new();
    if pos + 2 <= body.len() {
        let akm_count = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..akm_count {
            if pos + 4 > body.len() { break; }
            akms.push(akm_name(&body[pos..pos + 4]));
            pos += 4;
        }
    }

    Some(format!("grp={},pw={:?},akm={:?}", group, pairwise, akms))
}