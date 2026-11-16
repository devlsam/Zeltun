use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_socks5_loopback_connect() {
    let socks_addr: SocketAddr = "127.0.0.1:10808".parse().unwrap();
    if let Ok(stream) = dial_socks5_tcp(socks_addr, [1, 1, 1, 1], 80, 20, [0, 0, 0, 0]).await {
        assert!(stream.writable().await.is_ok());
    }
}

#[tokio::test]
async fn test_direct_dial_physical_adapter() {
    let target: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let phy = crate::engine::detect_physical_adapter();
    if phy.if_index > 0 {
        if let Ok(mut stream) = dial_direct_tcp(target, phy.if_index, phy.lan_ip).await {
            let _ = stream.write_all(b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n").await;
            let mut buf = [0u8; 32];
            let _ = stream.read(&mut buf).await;
        }
    }
}

#[tokio::test]
async fn test_real_phys_if_loopback_socks5_connect() {
    let phy = crate::engine::detect_physical_adapter();
    let real_if_index = if phy.if_index > 0 { phy.if_index } else { 12 };
    let real_lan_ip = phy.lan_ip;

    let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = mock_listener.accept().await.unwrap();
            let mut auth = [0u8; 3];
            s.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, &[0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req_hdr = [0u8; 4];
            s.read_exact(&mut req_hdr).await.unwrap();
            assert_eq!(req_hdr[0], 0x05);
            assert_eq!(req_hdr[1], 0x01);

            match req_hdr[3] {
                0x01 => {
                    let mut drain = [0u8; 6];
                    s.read_exact(&mut drain).await.unwrap();
                }
                0x03 => {
                    let mut dlen = [0u8; 1];
                    s.read_exact(&mut dlen).await.unwrap();
                    let mut dom = vec![0u8; dlen[0] as usize + 2];
                    s.read_exact(&mut dom).await.unwrap();
                }
                _ => panic!("Unexpected ATYP"),
            }

            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 1, 187]).await.unwrap();

            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
        }
    });

    let mut ip_conn = dial_socks5_tcp(mock_addr, [1, 1, 1, 1], 80, real_if_index, real_lan_ip)
        .await
        .expect("Loopback SOCKS5 must connect successfully even when real phys_if_index is passed");

    ip_conn.write_all(b"PING_SOCKS5_IP").await.unwrap();
    let mut echo_buf = [0u8; 32];
    let n1 = ip_conn.read(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf[..n1], b"PING_SOCKS5_IP");

    let mut dom_conn = dial_socks5_tcp_domain(mock_addr, "youtube.com", 443, real_if_index, real_lan_ip)
        .await
        .expect("Loopback SOCKS5 Domain must connect successfully even when real phys_if_index is passed");

    dom_conn.write_all(b"PING_SOCKS5_DOM").await.unwrap();
    let mut echo_buf2 = [0u8; 32];
    let n2 = dom_conn.read(&mut echo_buf2).await.unwrap();
    assert_eq!(&echo_buf2[..n2], b"PING_SOCKS5_DOM");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_redirect_loopback_socks5_with_phys_if() {
    let router = crate::ffi::ROUTER.get_or_init(|| Arc::new(crate::router::SplitRouter::new(crate::router::SplitMode::Global, &[])));
    router.set_rules(crate::router::SplitMode::Global, "");
    router.set_self_pid_for_test(999_999);

    let phy = crate::engine::detect_physical_adapter();
    let real_if_index = if phy.if_index > 0 { phy.if_index } else { 12 };
    let real_lan_ip = phy.lan_ip;

    // 1. Mock SOCKS5 upstream server on loopback
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = socks_listener.accept().await.unwrap();
        let mut auth = [0u8; 3];
        s.read_exact(&mut auth).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();

        let mut req_hdr = [0u8; 4];
        s.read_exact(&mut req_hdr).await.unwrap();
        let mut drain = [0u8; 6];
        s.read_exact(&mut drain).await.unwrap();
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 1, 187]).await.unwrap();

        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    // 2. Redirect listener
    let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_addr = redirect_listener.local_addr().unwrap();
    let running = Arc::new(AtomicBool::new(true));

    crate::driver::start_tcp_redirect_router(
        redirect_listener,
        running.clone(),
        socks_addr.to_string(),
        real_if_index,
        real_lan_ip,
    );

    // 3. Pre-bind client socket to know port *before* connect triggers accept()
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ).unwrap();
    sock.set_nonblocking(true).unwrap();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    sock.bind(&bind_addr.into()).unwrap();
    let client_port = sock.local_addr().unwrap().as_socket_ipv4().unwrap().port();

    crate::packet::SESSIONS.store(client_port, [142, 250, 180, 14], 80);

    let _ = sock.connect(&redirect_addr.into());
    let std_stream: std::net::TcpStream = sock.into();
    let mut client = TcpStream::from_std(std_stream).unwrap();
    client.writable().await.unwrap();

    client.write_all(b"REDIRECT_TRAFFIC").await.unwrap();
    let mut echo = [0u8; 32];
    let n = client.read(&mut echo).await.unwrap();
    assert_eq!(&echo[..n], b"REDIRECT_TRAFFIC");

    running.store(false, Ordering::Release);
    router.set_self_pid_for_test(std::process::id());
}

#[test]
fn test_direct_dialed_ip_ring_buffer() {
    let cdn_ip = [142, 250, 180, 46];
    let other_ip = [1, 1, 1, 2];
    record_direct_dialed_ip([0, 0, 0, 0]);
    assert!(!is_direct_dialed_ip([0, 0, 0, 0]));
    record_direct_dialed_ip(cdn_ip);
    assert!(is_direct_dialed_ip(cdn_ip));
    assert!(!is_direct_dialed_ip(other_ip));
}
