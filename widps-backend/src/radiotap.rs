pub struct RadiotapInfo {
    pub header_len: usize,
    pub rssi: Option<i8>,
}

struct FieldSpec {
    align: usize,
    size: usize,
}

fn field_spec(bit: u32) -> Option<FieldSpec> {
    match bit {
        0 => Some(FieldSpec { align: 8, size: 8 }),  // TSFT
        1 => Some(FieldSpec { align: 1, size: 1 }),  // Flags
        2 => Some(FieldSpec { align: 1, size: 1 }),  // Rate
        3 => Some(FieldSpec { align: 2, size: 4 }),  // Channel
        4 => Some(FieldSpec { align: 2, size: 2 }),  // FHSS
        5 => Some(FieldSpec { align: 1, size: 1 }),  // Antenna Signal (dBm)
        6 => Some(FieldSpec { align: 1, size: 1 }),  // Antenna Noise (dBm)
        7 => Some(FieldSpec { align: 2, size: 2 }),  // Lock Quality
        8 => Some(FieldSpec { align: 2, size: 2 }),  // TX Attenuation
        9 => Some(FieldSpec { align: 2, size: 2 }),  // dB TX Attenuation
        10 => Some(FieldSpec { align: 1, size: 1 }), // dBm TX Power
        11 => Some(FieldSpec { align: 1, size: 1 }), // Antenna
        12 => Some(FieldSpec { align: 1, size: 1 }), // dB Antenna Signal (relative)
        13 => Some(FieldSpec { align: 1, size: 1 }), // dB Antenna Noise
        14 => Some(FieldSpec { align: 2, size: 2 }), // RX Flags
        15 => Some(FieldSpec { align: 2, size: 2 }), // TX Flags
        16 => Some(FieldSpec { align: 1, size: 1 }), // RTS Retries
        _ => None,
    }
}

pub fn parse(data: &[u8]) -> Option<RadiotapInfo> {
    if data.len() < 8 {
        return None;
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < header_len {
        return None;
    }

    let first_present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut word_offset = 8;
    let mut last_word = first_present;

    // Consume any extended present words so field data offset is correct,
    // even though we only inspect bits from the first word.
    while last_word & 0x8000_0000 != 0 {
        if data.len() < word_offset + 4 {
            break;
        }
        last_word = u32::from_le_bytes([
            data[word_offset],
            data[word_offset + 1],
            data[word_offset + 2],
            data[word_offset + 3],
        ]);
        word_offset += 4;
    }

    let mut offset = word_offset;
    let mut rssi_dbm: Option<i8> = None;
    let mut rssi_relative: Option<i8> = None;

    for bit in 0..17u32 {
        if first_present & (1 << bit) == 0 {
            continue;
        }
        let spec = field_spec(bit)?;

        if spec.align > 1 {
            let rem = offset % spec.align;
            if rem != 0 {
                offset += spec.align - rem;
            }
        }
        if offset + spec.size > data.len() || offset + spec.size > header_len {
            break;
        }

        if bit == 5 {
            rssi_dbm = Some(data[offset] as i8);
        }
        if bit == 12 {
            rssi_relative = Some(data[offset] as i8);
        }

        offset += spec.size;
    }

    Some(RadiotapInfo {
        header_len,
        rssi: rssi_dbm.or(rssi_relative),
    })
}