use base64::{engine::general_purpose::STANDARD, Engine};

/// ECH config parameter key in SVCB/HTTPS records
const ECH_PARAM_KEY: u16 = 5;

/// Parse ECH config from raw DNS response data
pub fn parse_ech_config(raw_data: &[u8]) -> Option<Vec<String>> {
    // Try to find and parse ECH parameter from HTTPS/SVCB record
    let ech_configs = extract_ech_from_svcb(raw_data)?;

    if ech_configs.is_empty() {
        return None;
    }

    Some(ech_configs)
}

/// Extract ECH config from SVCB/HTTPS record wire format
fn extract_ech_from_svcb(data: &[u8]) -> Option<Vec<String>> {
    // SVCB/HTTPS record format:
    // - Priority (2 bytes)
    // - Target name (variable, DNS name format)
    // - SvcParams (variable)

    if data.len() < 3 {
        return None;
    }

    let mut pos = 0;

    // Skip priority (2 bytes)
    pos += 2;

    // Skip target name (DNS name format)
    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + label_len;
    }

    let mut ech_configs = Vec::new();

    // Parse SvcParams
    while pos + 4 <= data.len() {
        let param_key = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let param_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + param_len > data.len() {
            break;
        }

        if param_key == ECH_PARAM_KEY {
            // Found ECH parameter
            let ech_data = &data[pos..pos + param_len];
            if let Some(config_info) = parse_ech_config_list(ech_data) {
                ech_configs.extend(config_info);
            }
        }

        pos += param_len;
    }

    if ech_configs.is_empty() {
        None
    } else {
        Some(ech_configs)
    }
}

/// Parse ECHConfigList structure
fn parse_ech_config_list(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut configs = Vec::new();

    // ECHConfigList length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    if data.len() < 2 + list_len {
        // If we can't parse structure, return base64 encoded raw data
        let base64_config = STANDARD.encode(data);
        configs.push(format!("Raw ECH Config (base64): {}", base64_config));
        return Some(configs);
    }

    let mut pos = 2;

    while pos + 4 <= data.len() && pos < 2 + list_len {
        // ECHConfig structure:
        // - version (2 bytes)
        // - length (2 bytes)
        // - contents (variable)

        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let config_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if pos + 4 + config_len > data.len() {
            break;
        }

        let config_data = &data[pos..pos + 4 + config_len];
        let base64_config = STANDARD.encode(config_data);

        // Try to parse ECHConfigContents
        if let Some(info) = parse_ech_config_contents(version, &data[pos + 4..pos + 4 + config_len])
        {
            configs.push(format!(
                "ECH Config v{}: ConfigID={}, KEM=0x{:04X}, PublicName=\"{}\", Base64: {}",
                version, info.config_id, info.kem_id, info.public_name, base64_config
            ));
        } else {
            configs.push(format!(
                "ECH Config v{}: Base64: {}",
                version, base64_config
            ));
        }

        pos += 4 + config_len;
    }

    if configs.is_empty() {
        let base64_config = STANDARD.encode(data);
        configs.push(format!("Raw ECH Config (base64): {}", base64_config));
    }

    Some(configs)
}

/// Parsed ECH configuration info (minimal fields used)
struct EchConfigContents {
    config_id: u8,
    kem_id: u16,
    public_name: String,
}

/// Parse ECHConfigContents for detailed info
fn parse_ech_config_contents(version: u16, data: &[u8]) -> Option<EchConfigContents> {
    // Only parse draft versions we understand
    if version != 0xfe0d && version != 0xfe0e {
        return None;
    }

    if data.len() < 10 {
        return None;
    }

    let mut pos = 0;

    // config_id (1 byte)
    let config_id = data[pos];
    pos += 1;

    // kem_id (2 bytes)
    let kem_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // public_key length (2 bytes)
    let pk_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + pk_len > data.len() {
        return None;
    }

    // Skip public key bytes
    pos += pk_len;

    // cipher_suites length (2 bytes)
    if pos + 2 > data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    // Skip cipher suites
    pos += cs_len;
    if pos > data.len() {
        return None;
    }

    // maximum_name_length (1 byte)
    if pos >= data.len() {
        return None;
    }
    pos += 1;

    // public_name length (1 byte) and value
    if pos >= data.len() {
        return None;
    }
    let name_len = data[pos] as usize;
    pos += 1;

    if pos + name_len > data.len() {
        return None;
    }
    let public_name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();

    Some(EchConfigContents {
        config_id,
        kem_id,
        public_name,
    })
}
