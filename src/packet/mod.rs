pub mod checksum;
pub mod sessions;
pub mod mss;
pub mod icmp;

#[cfg(test)]
mod tests;

pub use checksum::*;
pub use sessions::*;
pub use mss::*;
pub use icmp::*;

pub fn build_udp_packet_into(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    pkt: &mut [u8],
) -> usize {
    let tot_len = 20 + 8 + payload.len();
    if pkt.len() < tot_len || tot_len > u16::MAX as usize {
        return 0;
    }
    pkt[..28].fill(0);

    // IPv4 Header (20 bytes)
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(tot_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
    pkt[8] = 64; // TTL
    pkt[9] = 17; // Protocol UDP
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);
    let ip_csum = calc_ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP Header (8 bytes)
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..tot_len].copy_from_slice(payload);

    let udp_csum = calc_udp_checksum(src_ip, dst_ip, &pkt[20..tot_len]);
    pkt[26..28].copy_from_slice(&udp_csum.to_be_bytes());

    tot_len
}

pub fn build_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + payload.len()];
    build_udp_packet_into(src_ip, dst_ip, src_port, dst_port, payload, &mut pkt);
    pkt
}

/// Rewrites an outbound TCP packet (Client -> Destination) to (TunGateway -> TunIP:ListenPort).
/// Saves the original destination in `SESSIONS` and incrementally updates RFC 1624 checksums in-place.
#[inline]
pub fn rewrite_outbound_tcp(
    pkt: &mut [u8],
    tun_ip: [u8; 4],
    tun_gw: [u8; 4],
    listen_port: u16,
) -> bool {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) * 4) as usize;
    if pkt.len() < ihl + 20 {
        return false;
    }

    let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap();
    let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap();
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

    if src_ip != tun_ip || dst_ip == tun_ip || dst_ip == tun_gw {
        return false;
    }

    // 1. Record session mapping in Lock-Free SESSIONS array
    SESSIONS.store(src_port, dst_ip, dst_port);

    // 2. Compute incremental checksum updates via RFC 1624
    let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    let old_tcp_csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);

    let dst_ip_hi = u16::from_be_bytes([dst_ip[0], dst_ip[1]]);
    let dst_ip_lo = u16::from_be_bytes([dst_ip[2], dst_ip[3]]);
    let tun_gw_hi = u16::from_be_bytes([tun_gw[0], tun_gw[1]]);
    let tun_gw_lo = u16::from_be_bytes([tun_gw[2], tun_gw[3]]);

    let new_ip_csum = update_checksum2(old_ip_csum, dst_ip_hi, dst_ip_lo, tun_gw_hi, tun_gw_lo);
    let new_tcp_csum = update_checksum3(
        old_tcp_csum,
        dst_ip_hi,
        dst_ip_lo,
        dst_port,
        tun_gw_hi,
        tun_gw_lo,
        listen_port,
    );

    // 3. In-place rewrite
    pkt[12..16].copy_from_slice(&tun_gw);
    pkt[16..20].copy_from_slice(&tun_ip);
    pkt[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&listen_port.to_be_bytes());
    pkt[ihl + 16..ihl + 18].copy_from_slice(&new_tcp_csum.to_be_bytes());

    true
}

/// Rewrites a return TCP packet (TunIP:ListenPort -> TunGateway:dstPort) back to (origDstIP:origDstPort -> TunIP).
#[inline]
pub fn rewrite_inbound_tcp(
    pkt: &mut [u8],
    tun_ip: [u8; 4],
    tun_gw: [u8; 4],
    listen_port: u16,
) -> bool {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) * 4) as usize;
    if pkt.len() < ihl + 20 {
        return false;
    }

    let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap();
    let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap();
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);

    if src_ip != tun_ip || dst_ip != tun_gw || src_port != listen_port {
        return false;
    }

    let Some((orig_dst_ip, orig_dst_port)) = SESSIONS.load(dst_port) else {
        return false;
    };

    let old_ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
    let old_tcp_csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);

    let tun_gw_hi = u16::from_be_bytes([tun_gw[0], tun_gw[1]]);
    let tun_gw_lo = u16::from_be_bytes([tun_gw[2], tun_gw[3]]);
    let orig_dst_hi = u16::from_be_bytes([orig_dst_ip[0], orig_dst_ip[1]]);
    let orig_dst_lo = u16::from_be_bytes([orig_dst_ip[2], orig_dst_ip[3]]);

    let new_ip_csum = update_checksum2(old_ip_csum, tun_gw_hi, tun_gw_lo, orig_dst_hi, orig_dst_lo);
    let new_tcp_csum = update_checksum3(
        old_tcp_csum,
        tun_gw_hi,
        tun_gw_lo,
        listen_port,
        orig_dst_hi,
        orig_dst_lo,
        orig_dst_port,
    );

    pkt[12..16].copy_from_slice(&orig_dst_ip);
    pkt[16..20].copy_from_slice(&tun_ip);
    pkt[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());
    pkt[ihl..ihl + 2].copy_from_slice(&orig_dst_port.to_be_bytes());
    pkt[ihl + 16..ihl + 18].copy_from_slice(&new_tcp_csum.to_be_bytes());

    true
}
