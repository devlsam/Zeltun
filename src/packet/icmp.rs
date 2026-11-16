use super::checksum::{calc_icmp_checksum, calc_ipv4_checksum};

/// Builds an RFC 792 ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable) packet
/// in response to an unexpected or blocked UDP packet.
/// Zero-allocation: writes directly into `out_buf` on the stack.
/// Returns the length of the written packet, or `None` if invalid inputs.
#[inline]
pub fn build_icmp_port_unreachable(orig_pkt: &[u8], out_buf: &mut [u8]) -> Option<usize> {
    if orig_pkt.len() < 28 || (orig_pkt[0] >> 4) != 4 {
        return None;
    }
    let orig_ihl = ((orig_pkt[0] & 0x0f) * 4) as usize;
    if orig_pkt.len() < orig_ihl + 8 {
        return None;
    }

    let icmp_body_len = orig_ihl + 8;
    let tot_len = 20 + 8 + icmp_body_len;
    if out_buf.len() < tot_len {
        return None;
    }

    let orig_src_ip: [u8; 4] = orig_pkt[12..16].try_into().ok()?;
    let orig_dst_ip: [u8; 4] = orig_pkt[16..20].try_into().ok()?;

    // 1. IPv4 Header (20 bytes)
    out_buf[0] = 0x45;
    out_buf[1] = 0x00;
    out_buf[2..4].copy_from_slice(&(tot_len as u16).to_be_bytes());
    out_buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    out_buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    out_buf[8] = 64; // TTL
    out_buf[9] = 1;  // Protocol ICMP
    out_buf[10..12].copy_from_slice(&[0, 0]);
    out_buf[12..16].copy_from_slice(&orig_dst_ip); // Source: remote server
    out_buf[16..20].copy_from_slice(&orig_src_ip); // Destination: local client
    let ip_csum = calc_ipv4_checksum(&out_buf[0..20]);
    out_buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // 2. ICMP Header (8 bytes) at offset 20
    out_buf[20] = 3; // Type 3: Destination Unreachable
    out_buf[21] = 3; // Code 3: Port Unreachable
    out_buf[22..24].copy_from_slice(&[0, 0]); // Checksum zeroed for calc
    out_buf[24..28].copy_from_slice(&[0, 0, 0, 0]); // Unused 4 bytes

    // 3. ICMP Payload: Original IPv4 header + 8 bytes of original datagram
    out_buf[28..tot_len].copy_from_slice(&orig_pkt[0..icmp_body_len]);

    // 4. Calculate ICMP checksum over ICMP header + payload (bytes 20..tot_len)
    let icmp_csum = calc_icmp_checksum(&out_buf[20..tot_len]);
    out_buf[22..24].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(tot_len)
}
