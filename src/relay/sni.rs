/// Zero-allocation TLS ClientHello Server Name Indication (SNI) parser.
/// Safely extracts the domain name from a TLS handshake peek buffer.
#[inline]
pub fn parse_tls_sni(buf: &[u8]) -> Option<&str> {
    // TLS Record Header (5 bytes): ContentType=0x16 (Handshake), Version=0x03xx
    if buf.len() < 5 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let limit = (5 + record_len).min(buf.len());
    if limit < 44 {
        return None;
    }

    // Handshake Header: Type=0x01 (ClientHello)
    if buf[5] != 0x01 {
        return None;
    }

    // Skip Handshake header (4 bytes: 1 type + 3 length) + Version (2 bytes) + Random (32 bytes) = offset 43
    let session_id_len = buf[43] as usize;
    let mut pos = 44 + session_id_len;
    if pos + 2 > limit {
        return None;
    }

    // Cipher Suites
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos + 1 > limit {
        return None;
    }

    // Compression Methods
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > limit {
        return None;
    }

    // Extensions
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(limit);

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0 {
            // Extension: server_name (RFC 6066)
            if pos + 2 > ext_end || pos + ext_len > ext_end {
                return None;
            }
            let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            let list_end = (pos + 2 + list_len).min(pos + ext_len).min(ext_end);
            let mut name_pos = pos + 2;

            while name_pos + 3 <= list_end {
                let name_type = buf[name_pos];
                let name_len = u16::from_be_bytes([buf[name_pos + 1], buf[name_pos + 2]]) as usize;
                name_pos += 3;

                if name_type == 0 && name_len > 0 && name_pos + name_len <= list_end {
                    let domain_bytes = &buf[name_pos..name_pos + name_len];
                    if let Ok(domain_str) = std::str::from_utf8(domain_bytes) {
                        return Some(domain_str);
                    }
                }
                name_pos += name_len;
            }
        }
        pos += ext_len;
    }

    None
}

