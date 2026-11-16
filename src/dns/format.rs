pub fn is_aaaa_query(query: &[u8]) -> bool {
    if query.len() < 12 {
        return false;
    }
    let mut i = 12;
    while i < query.len() {
        let len_byte = query[i] as usize;
        if len_byte == 0 {
            i += 1;
            break;
        }
        if len_byte & 0xc0 == 0xc0 {
            i += 2;
            break;
        }
        i += 1 + len_byte;
    }
    if i + 4 <= query.len() {
        let q_type = u16::from_be_bytes([query[i], query[i + 1]]);
        return q_type == 28; // AAAA (RFC 3596)
    }
    false
}

pub fn make_dns_nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut i = 12;
    while i < query.len() {
        let len_byte = query[i] as usize;
        if len_byte == 0 {
            i += 1;
            break;
        }
        if len_byte & 0xc0 == 0xc0 {
            i += 2;
            break;
        }
        i += 1 + len_byte;
    }
    if i + 4 > query.len() {
        return None;
    }
    let question_end = i + 4;
    let mut resp = vec![0u8; question_end];
    resp[..question_end].copy_from_slice(&query[..question_end]);

    // RFC 1035: QR=1 (response), RD preserved, RA=1 (Recursion Available), RCODE=0 (NOERROR)
    resp[2] = (query[2] & 0x01) | 0x81;
    resp[3] = 0x80;

    // QDCOUNT = 1, ANCOUNT = 0 (NODATA), NSCOUNT = 0, ARCOUNT = 0
    resp[4..6].copy_from_slice(&1u16.to_be_bytes());
    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());

    Some(resp)
}

pub fn make_dns_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    // Flags: Response (QR=1), RA=1, RCODE=2 (Server Failure)
    resp[2] = (query[2] & 0x01) | 0x81;
    resp[3] = 0x82;
    Some(resp)
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xc0) == 0xc0 {
            return (pos + 2 <= pkt.len()).then_some(pos + 2);
        }
        if (len & 0xc0) != 0 {
            return None;
        }
        pos = pos.checked_add(1 + len)?;
    }
    None
}

#[inline]
fn is_poisoned_or_bogon_v4(ip: [u8; 4]) -> bool {
    ip[0] == 10
        || ip[0] == 0
        || ip[0] == 127
        || (ip[0] == 192 && ip[1] == 168)
        || (ip[0] == 172 && (16..=31).contains(&ip[1]))
        || (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19))
}

/// Validates a DNS wire response (`NOERROR`, `ANCOUNT > 0`, not truncated) and rejects bogon/DPI-poisoned A records.
pub fn is_valid_unpoisoned_dns_response(resp: &[u8]) -> bool {
    if resp.len() < 12 || (resp[2] & 0x80) == 0 || (resp[2] & 0x02) != 0 || (resp[3] & 0x0f) != 0 {
        return false;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return false;
    }
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = match skip_dns_name(resp, pos) {
            Some(next) if next + 4 <= resp.len() => next + 4,
            _ => return false,
        };
    }
    for _ in 0..ancount {
        pos = match skip_dns_name(resp, pos) {
            Some(next) if next + 10 <= resp.len() => next,
            _ => return false,
        };
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return false;
        }
        if rtype == 1 && rdlen == 4 && is_poisoned_or_bogon_v4([resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]]) {
            return false;
        }
        pos += rdlen;
    }
    true
}
