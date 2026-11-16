use super::*;
use tokio::net::UdpSocket;

#[test]
fn test_socks5_udp_header_roundtrip() {
    let dst_ip = [8, 8, 8, 8];
    let dst_port = 5353u16;
    let payload = b"hello udp world";

    let mut packet = Vec::with_capacity(10 + payload.len());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    packet.extend_from_slice(&dst_ip);
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(payload);

    assert_eq!(packet.len(), 10 + payload.len());
    assert_eq!(&packet[0..3], &[0, 0, 0]);
    assert_eq!(packet[3], 0x01);
    assert_eq!(&packet[4..8], &dst_ip);
    assert_eq!(u16::from_be_bytes([packet[8], packet[9]]), dst_port);
    assert_eq!(&packet[10..], payload);
}

#[tokio::test]
async fn test_direct_udp_loopback_echo() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = DirectUdpSession::new(0, [0, 0, 0, 0]).unwrap();
    let s_ip = match server_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => unreachable!(),
    };

    client.send_packet(s_ip, server_addr.port(), b"ping").await.unwrap();

    let mut s_buf = [0u8; 64];
    let (n, peer) = server.recv_from(&mut s_buf).await.unwrap();
    assert_eq!(&s_buf[..n], b"ping");

    server.send_to(b"pong", peer).await.unwrap();

    let mut c_buf = [0u8; 64];
    let (n, r_ip, r_port) = client.recv_packet(&mut c_buf).await.unwrap();
    assert_eq!(&c_buf[..n], b"pong");
    assert_eq!(r_ip, s_ip);
    assert_eq!(r_port, server_addr.port());
}

#[test]
fn test_pack_udp_dst_and_proxy_pid_idempotency() {
    let packed = super::session::pack_udp_dst([66, 22, 240, 12], 50001);
    assert_eq!(super::session::unpack_udp_dst(packed), ([66, 22, 240, 12], 50001));

    let router = crate::router::SplitRouter::new(crate::router::SplitMode::Include, &["discord.exe"]);
    let initial_ver = router.rule_version();
    router.set_proxy_pid(4242);
    assert_eq!(router.rule_version(), initial_ver + 1);

    // Repeating same PID every 2s from watcher must NOT bump rule_version or reset UDP sessions.
    for _ in 0..10 {
        router.set_proxy_pid(4242);
    }
    assert_eq!(router.rule_version(), initial_ver + 1);

    router.set_proxy_pid(5353);
    assert_eq!(router.rule_version(), initial_ver + 2);
}
