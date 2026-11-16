/// RFC 791, RFC 768, RFC 793, RFC 1624 checksum calculations for IPv4, UDP, and TCP.

/// Computes RFC 791 16-bit one's complement sum over an IPv4 header.
#[inline]
pub fn calc_ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        let w = u16::from_be_bytes([hdr[i], hdr[i + 1]]);
        sum += w as u32;
        i += 2;
    }
    if hdr.len() % 2 != 0 {
        sum += (hdr[hdr.len() - 1] as u32) << 8;
    }
    fold_checksum(sum)
}

/// Computes RFC 792 16-bit one's complement sum over an ICMP message.
#[inline]
pub fn calc_icmp_checksum(icmp_msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < icmp_msg.len() {
        if i == 2 {
            i += 2;
            continue;
        }
        let w = u16::from_be_bytes([icmp_msg[i], icmp_msg[i + 1]]);
        sum += w as u32;
        i += 2;
    }
    if icmp_msg.len() % 2 != 0 {
        sum += (icmp_msg[icmp_msg.len() - 1] as u32) << 8;
    }
    fold_checksum(sum)
}

/// Computes RFC 768 UDP checksum over pseudo-header + datagram.
#[inline]
pub fn calc_udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17; // protocol UDP
    sum += udp_segment.len() as u32;

    let mut i = 0;
    while i + 1 < udp_segment.len() {
        if i == 6 {
            i += 2;
            continue;
        }
        let w = u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]);
        sum += w as u32;
        i += 2;
    }
    if udp_segment.len() % 2 != 0 {
        sum += (udp_segment[udp_segment.len() - 1] as u32) << 8;
    }
    let mut res = fold_checksum(sum);
    if res == 0 {
        res = 0xffff;
    }
    res
}

/// Computes RFC 793 TCP checksum over pseudo-header + segment.
#[inline]
pub fn calc_tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6; // protocol TCP
    sum += tcp_segment.len() as u32;

    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i == 16 {
            i += 2;
            continue;
        }
        let w = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
        sum += w as u32;
        i += 2;
    }
    if tcp_segment.len() % 2 != 0 {
        sum += (tcp_segment[tcp_segment.len() - 1] as u32) << 8;
    }
    fold_checksum(sum)
}

/// Incremental checksum update according to RFC 1624 (Eq. 3) when 1 16-bit word changes.
#[inline(always)]
pub fn update_checksum1(old_csum: u16, o1: u16, n1: u16) -> u16 {
    let sum = (!old_csum as u32) + (!o1 as u32) + (n1 as u32);
    fold_checksum(sum)
}

/// Incremental checksum update according to RFC 1624 (Eq. 3) when 2 16-bit words change.
#[inline(always)]
pub fn update_checksum2(old_csum: u16, o1: u16, o2: u16, n1: u16, n2: u16) -> u16 {
    let sum = (!old_csum as u32)
        + (!o1 as u32)
        + (!o2 as u32)
        + (n1 as u32)
        + (n2 as u32);
    fold_checksum(sum)
}

/// Incremental checksum update according to RFC 1624 (Eq. 3) when 3 16-bit words change.
#[inline(always)]
pub fn update_checksum3(
    old_csum: u16,
    o1: u16,
    o2: u16,
    o3: u16,
    n1: u16,
    n2: u16,
    n3: u16,
) -> u16 {
    let sum = (!old_csum as u32)
        + (!o1 as u32)
        + (!o2 as u32)
        + (!o3 as u32)
        + (n1 as u32)
        + (n2 as u32)
        + (n3 as u32);
    fold_checksum(sum)
}

#[inline(always)]
pub fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let res = !sum as u16;
    if res == 0 {
        0xffff
    } else {
        res
    }
}
