use super::*;

#[test]
fn test_phase1_packet_rewrite() {
    let tun_ip = [198, 19, 0, 1];
    let tun_gw = [198, 19, 0, 2];
    let orig_dst_ip = [1, 1, 1, 1];
    let orig_dst_port: u16 = 443;
    let client_port: u16 = 51234;
    let listen_port: u16 = 30000;

    // Construct standard IPv4 TCP SYN Packet (40 bytes)
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    pkt[1] = 0x00; // DSCP / ECN
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // Total length 40
    pkt[4..6].copy_from_slice(&12345u16.to_be_bytes()); // Identification
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: DF
    pkt[8] = 64; // TTL 64
    pkt[9] = 6; // Protocol TCP
    pkt[12..16].copy_from_slice(&tun_ip); // Source: TunIP
    pkt[16..20].copy_from_slice(&orig_dst_ip); // Destination: 1.1.1.1
    let ip_csum = calc_ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP Header (20 bytes)
    pkt[20..22].copy_from_slice(&client_port.to_be_bytes()); // SrcPort
    pkt[22..24].copy_from_slice(&orig_dst_port.to_be_bytes()); // DstPort
    pkt[24..28].copy_from_slice(&1000u32.to_be_bytes()); // SeqNum
    pkt[32] = 0x50; // Data offset 5
    pkt[33] = 0x02; // SYN flag
    pkt[34..36].copy_from_slice(&64240u16.to_be_bytes()); // Window size
    let tcp_csum = calc_tcp_checksum(tun_ip, orig_dst_ip, &pkt[20..40]);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    // Initial validation: full calculations match headers
    assert_eq!(calc_ipv4_checksum(&pkt[0..20]), u16::from_be_bytes([pkt[10], pkt[11]]));
    assert_eq!(calc_tcp_checksum(tun_ip, orig_dst_ip, &pkt[20..40]), u16::from_be_bytes([pkt[36], pkt[37]]));

    // 1. Rewrite Outbound Packet
    let ok = rewrite_outbound_tcp(&mut pkt, tun_ip, tun_gw, listen_port);
    assert!(ok, "rewrite_outbound_tcp should succeed");

    // Verify destination redirected to tun_ip:listen_port, source set to tun_gw
    assert_eq!(&pkt[12..16], &tun_gw);
    assert_eq!(&pkt[16..20], &tun_ip);
    assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), listen_port);

    // Verify incremental RFC 1624 checksums strictly match fresh full calculations
    let full_ip_csum = calc_ipv4_checksum(&pkt[0..20]);
    let full_tcp_csum = calc_tcp_checksum(tun_gw, tun_ip, &pkt[20..40]);
    assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), full_ip_csum, "IP checksum mismatch after outbound rewrite");
    assert_eq!(u16::from_be_bytes([pkt[36], pkt[37]]), full_tcp_csum, "TCP checksum mismatch after outbound rewrite");

    // Verify session retrieval from SESSIONS table
    let recovered = SESSIONS.load(client_port);
    assert_eq!(recovered, Some((orig_dst_ip, orig_dst_port)), "Session must recover original dst IP and port");

    // 2. Simulate return packet from listenPort back to client
    let mut return_pkt = vec![0u8; 40];
    return_pkt[0] = 0x45;
    return_pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    return_pkt[8] = 64;
    return_pkt[9] = 6;
    return_pkt[12..16].copy_from_slice(&tun_ip);
    return_pkt[16..20].copy_from_slice(&tun_gw);
    let ret_ip_csum = calc_ipv4_checksum(&return_pkt[0..20]);
    return_pkt[10..12].copy_from_slice(&ret_ip_csum.to_be_bytes());

    return_pkt[20..22].copy_from_slice(&listen_port.to_be_bytes());
    return_pkt[22..24].copy_from_slice(&client_port.to_be_bytes());
    return_pkt[32] = 0x50;
    return_pkt[33] = 0x12; // SYN+ACK
    let ret_tcp_csum = calc_tcp_checksum(tun_ip, tun_gw, &return_pkt[20..40]);
    return_pkt[36..38].copy_from_slice(&ret_tcp_csum.to_be_bytes());

    // Rewrite return packet back to original client view
    let ret_ok = rewrite_inbound_tcp(&mut return_pkt, tun_ip, tun_gw, listen_port);
    assert!(ret_ok, "rewrite_inbound_tcp should succeed");

    assert_eq!(&return_pkt[12..16], &orig_dst_ip);
    assert_eq!(&return_pkt[16..20], &tun_ip);
    assert_eq!(u16::from_be_bytes([return_pkt[20], return_pkt[21]]), orig_dst_port);

    let ret_full_ip = calc_ipv4_checksum(&return_pkt[0..20]);
    let ret_full_tcp = calc_tcp_checksum(orig_dst_ip, tun_ip, &return_pkt[20..40]);
    assert_eq!(u16::from_be_bytes([return_pkt[10], return_pkt[11]]), ret_full_ip);
    assert_eq!(u16::from_be_bytes([return_pkt[36], return_pkt[37]]), ret_full_tcp);
}

#[test]
fn test_mss_clamp_exact_checksum() {
    let src_ip = [192, 168, 1, 50];
    let dst_ip = [142, 250, 180, 14];
    let initial_mss_values = [1460u16, 1500, 1440, 1400];

    for &init_mss in &initial_mss_values {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let ip_csum = calc_ipv4_checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        pkt[20..22].copy_from_slice(&49152u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&0x12345678u32.to_be_bytes());
        pkt[32] = 0x60;
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());

        pkt[40] = 2; // MSS option
        pkt[41] = 4;
        pkt[42..44].copy_from_slice(&init_mss.to_be_bytes());

        let init_csum = calc_tcp_checksum(src_ip, dst_ip, &pkt[20..44]);
        pkt[36..38].copy_from_slice(&init_csum.to_be_bytes());

        let clamped = clamp_tcp_mss(&mut pkt, 1360);
        assert!(clamped, "SYN packet with MSS {} should be clamped", init_mss);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 1360);

        let incremental_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        let full_recalc_csum = calc_tcp_checksum(src_ip, dst_ip, &pkt[20..44]);
        assert_eq!(
            incremental_csum, full_recalc_csum,
            "Incremental MSS checksum must match full calculation bit-for-bit (init_mss={})",
            init_mss
        );

        // Test chaining clamp_tcp_mss followed by rewrite_outbound_tcp
        let tun_ip = [198, 19, 0, 2];
        let tun_gw = [198, 19, 0, 1];
        let listen_port = 30000u16;
        pkt[12..16].copy_from_slice(&tun_ip);
        // recompute initial before outbound rewrite
        let csum = calc_tcp_checksum(tun_ip, dst_ip, &pkt[20..44]);
        pkt[36..38].copy_from_slice(&csum.to_be_bytes());
        let ok = rewrite_outbound_tcp(&mut pkt, tun_ip, tun_gw, listen_port);
        assert!(ok);
        let final_csum = u16::from_be_bytes([pkt[36], pkt[37]]);
        let expected_final = calc_tcp_checksum(tun_gw, tun_ip, &pkt[20..44]);
        assert_eq!(final_csum, expected_final, "Chained clamp + rewrite must produce exact checksum");
    }
}

#[test]
fn test_icmp_port_unreachable_generation() {
    let udp_pkt = build_udp_packet([198, 19, 0, 2], [142, 250, 180, 14], 54321, 443, b"QUIC_DATA");
    let mut icmp_out = [0u8; 64];
    let len = build_icmp_port_unreachable(&udp_pkt, &mut icmp_out).expect("should build ICMP packet");
    assert_eq!(len, 56);
    assert_eq!(icmp_out[9], 1); // ICMP
    assert_eq!(&icmp_out[12..16], &[142, 250, 180, 14]); // src = remote server
    assert_eq!(&icmp_out[16..20], &[198, 19, 0, 2]); // dst = local client
    assert_eq!(icmp_out[20], 3); // Type 3
    assert_eq!(icmp_out[21], 3); // Code 3
    assert_eq!(calc_ipv4_checksum(&icmp_out[0..20]), u16::from_be_bytes([icmp_out[10], icmp_out[11]]));
    assert_eq!(calc_icmp_checksum(&icmp_out[20..56]), u16::from_be_bytes([icmp_out[22], icmp_out[23]]));
}
