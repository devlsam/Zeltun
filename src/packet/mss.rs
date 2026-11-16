use super::checksum::update_checksum1;

/// In-place clamps the TCP MSS option on IPv4 SYN packets to `max_mss`.
/// Updates the TCP checksum incrementally per RFC 1624.
/// Returns `true` if an MSS option was found and clamped, `false` otherwise.
#[inline]
pub fn clamp_tcp_mss(pkt: &mut [u8], max_mss: u16) -> bool {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) * 4) as usize;
    if pkt.len() < ihl + 20 {
        return false;
    }

    // SYN flag is bit 1 (0x02)
    let tcp_flags = pkt[ihl + 13];
    if (tcp_flags & 0x02) == 0 {
        return false;
    }

    let tcp_hdr_len = ((pkt[ihl + 12] >> 4) * 4) as usize;
    if tcp_hdr_len < 24 || pkt.len() < ihl + tcp_hdr_len {
        return false;
    }

    let opt_start = ihl + 20;
    let opt_end = ihl + tcp_hdr_len;
    let mut i = opt_start;

    while i < opt_end {
        let kind = pkt[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= opt_end {
            break;
        }
        let len = pkt[i + 1] as usize;
        if len < 2 || i + len > opt_end {
            break;
        }

        // Kind 2 = Maximum Segment Size (MSS), Length must be 4
        if kind == 2 && len == 4 {
            let old_mss = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
            if old_mss > max_mss {
                pkt[i + 2..i + 4].copy_from_slice(&max_mss.to_be_bytes());
                let old_csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
                let new_csum = update_checksum1(old_csum, old_mss, max_mss);
                pkt[ihl + 16..ihl + 18].copy_from_slice(&new_csum.to_be_bytes());
                return true;
            }
            return false;
        }
        i += len;
    }

    false
}

