use super::*;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::packet::{calc_ipv4_checksum, calc_udp_checksum};

#[tokio::test]
async fn test_dns_resolution_over_socks() {
    let socks_addr: SocketAddr = "127.0.0.1:10808".parse().unwrap();
    let rt = tokio::runtime::Handle::current();
    let resolver = DnsResolver::new(socks_addr, 20, [0, 0, 0, 0], rt);

    let query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        0x00, 0x01, 0x00, 0x01,
    ];

    let resp = resolver.resolve(&query).await;
    if let Some(resp_bytes) = resp {
        assert!(resp_bytes.len() >= 12);
        assert_eq!(resp_bytes[0], 0x12);
        assert_eq!(resp_bytes[1], 0x34);
    }
}

#[tokio::test]
async fn test_dns_fallback_and_source_ip_restore() {
    // 1. Mock Direct UDP DNS Server (simulating fallback upstream)
    let mock_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_port = mock_sock.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, from) = mock_sock.recv_from(&mut buf).await.unwrap();
        let mut resp = buf[..n].to_vec();
        // RFC 1035: Set Response flag (QR=1)
        resp[2] = 0x81;
        resp[3] = 0x80;
        let _ = mock_sock.send_to(&resp, from).await;
    });

    // 2. Setup DnsResolver with broken SOCKS5 port to trigger fallback
    let broken_socks: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let rt = tokio::runtime::Handle::current();
    let resolver = DnsResolver::new(broken_socks, 0, [0, 0, 0, 0], rt);

    let query = [
        0x9a, 0xbc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        0x00, 0x01, 0x00, 0x01,
    ];

    // Fallback query to Direct UDP
    let resp = resolver.query_dns_direct_udp_port([127, 0, 0, 1], mock_port, &query).await;
    assert!(resp.is_some(), "Direct UDP DNS fallback must succeed when SOCKS5 fails");
    let resp_bytes = resp.unwrap();
    assert_eq!(resp_bytes[0], 0x9a);
    assert_eq!(resp_bytes[1], 0xbc);

    // 3. Verify that response IPv4 packet header has src_ip restored to orig_dst_ip
    let orig_dst_ip = [8, 8, 8, 8];
    let client_ip = [198, 19, 0, 2];
    let client_port = 53321u16;

    let wintun_pkt = build_udp_packet(orig_dst_ip, client_ip, 53, client_port, &resp_bytes);
    assert_eq!(&wintun_pkt[12..16], &orig_dst_ip, "Source IP must equal original DNS target");
    assert_eq!(&wintun_pkt[16..20], &client_ip, "Destination IP must equal local client TunIP");
    assert_eq!(u16::from_be_bytes([wintun_pkt[20], wintun_pkt[21]]), 53);
    assert_eq!(u16::from_be_bytes([wintun_pkt[22], wintun_pkt[23]]), client_port);

    // Verify valid IPv4 and UDP checksums
    assert_eq!(calc_ipv4_checksum(&wintun_pkt[0..20]), u16::from_be_bytes([wintun_pkt[10], wintun_pkt[11]]));
    assert_eq!(calc_udp_checksum(orig_dst_ip, client_ip, &wintun_pkt[20..]), u16::from_be_bytes([wintun_pkt[26], wintun_pkt[27]]));
}

#[tokio::test]
async fn test_dns_cache_skips_servfail_and_preserves_txid() {
    let resolver = DnsResolver::new("127.0.0.1:1".parse().unwrap(), 0, [0; 4], tokio::runtime::Handle::current());
    let q_key = b"discord.com".to_vec();
    let mut servfail = vec![0xAA, 0xBB, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0];
    resolver.store.store(q_key.clone(), 0, &servfail);
    assert!(resolver.store.lookup(&q_key, 0, &[0x11, 0x22]).is_none(), "SERVFAIL must not be cached");

    servfail[3] = 0x80; // RCODE=0 (NOERROR)
    resolver.store.store(q_key.clone(), 0, &servfail);
    let hit = resolver.store.lookup(&q_key, 0, &[0x33, 0x44]).expect("NOERROR must be cached");
    assert_eq!(&hit[0..2], &[0x33, 0x44]);
}

fn build_dns_a_response(ip: [u8; 4], rcode: u8) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, 0x81, 0x80 | (rcode & 0x0f),
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // QD=1, AN=1
        7, b'd', b'i', b's', b'c', b'o', b'r', b'd', 3, b'c', b'o', b'm', 0,
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
        0xc0, 0x0c,             // NAME pointer -> offset 12
        0x00, 0x01, 0x00, 0x01, // TYPE=A, CLASS=IN
        0x00, 0x00, 0x00, 0x3c, // TTL=60
        0x00, 0x04,             // RDLENGTH=4
    ];
    pkt.extend_from_slice(&ip);
    pkt
}

#[test]
fn test_dns_poison_filter_rejects_dpi_and_accepts_clean_a_record() {
    let poisoned = build_dns_a_response([10, 10, 34, 35], 0);
    assert!(!is_valid_unpoisoned_dns_response(&poisoned), "Must reject 10.10.34.35 poisoned response");

    let bogon_tun = build_dns_a_response([198, 18, 0, 10], 0);
    assert!(!is_valid_unpoisoned_dns_response(&bogon_tun), "Must reject 198.18.0.0/15 bogon response");

    let nxdomain = build_dns_a_response([142, 250, 180, 14], 3);
    assert!(!is_valid_unpoisoned_dns_response(&nxdomain), "Must reject non-zero RCODE");

    let clean = build_dns_a_response([142, 250, 180, 14], 0);
    assert!(is_valid_unpoisoned_dns_response(&clean), "Must accept valid public A record");
}
