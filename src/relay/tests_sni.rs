use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

pub fn build_mock_tls_client_hello(domain: &str) -> Vec<u8> {
    let mut ext_sni = Vec::new();
    let domain_bytes = domain.as_bytes();
    let name_len = domain_bytes.len() as u16;
    let list_len = name_len + 3;

    ext_sni.extend_from_slice(&0u16.to_be_bytes()); // Ext Type: 0 (server_name)
    ext_sni.extend_from_slice(&(list_len + 2).to_be_bytes()); // Ext Length
    ext_sni.extend_from_slice(&list_len.to_be_bytes()); // ServerNameList Length
    ext_sni.push(0); // NameType: 0 (host_name)
    ext_sni.extend_from_slice(&name_len.to_be_bytes());
    ext_sni.extend_from_slice(domain_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Client Version TLS 1.2
    body.extend_from_slice(&[0xaa; 32]);   // Random
    body.push(0);                          // Session ID length: 0
    body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites length: 2
    body.extend_from_slice(&[0x13, 0x01]);       // TLS_AES_128_GCM_SHA256
    body.push(1);                          // Compression methods len: 1
    body.push(0);                          // Compression: null
    body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_sni);

    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    let handshake_len = (4 + body.len()) as u16;
    record.extend_from_slice(&handshake_len.to_be_bytes());

    // Handshake header
    record.push(0x01); // ClientHello
    let body_len_24 = body.len() as u32;
    record.push((body_len_24 >> 16) as u8);
    record.push((body_len_24 >> 8) as u8);
    record.push(body_len_24 as u8);
    record.extend_from_slice(&body);

    record
}

#[tokio::test]
async fn test_sni_peek_preserves_stream() {
    let test_domain = "youtube.com";
    let original_payload = build_mock_tls_client_hello(test_domain);
    let original_len = original_payload.len();

    // 1. Mock SOCKS5 Server
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let socks_server_task = tokio::spawn(async move {
        let (mut stream, _) = socks_listener.accept().await.unwrap();

        // SOCKS5 Handshake
        let mut auth_req = [0u8; 3];
        stream.read_exact(&mut auth_req).await.unwrap();
        assert_eq!(&auth_req, &[0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).await.unwrap();

        // SOCKS5 CONNECT
        let mut cmd_hdr = [0u8; 4];
        stream.read_exact(&mut cmd_hdr).await.unwrap();
        assert_eq!(cmd_hdr[0], 0x05);
        assert_eq!(cmd_hdr[1], 0x01); // CONNECT
        assert_eq!(cmd_hdr[3], 0x03, "Must use ATYP=0x03 (Domain Name)");

        let mut dlen = [0u8; 1];
        stream.read_exact(&mut dlen).await.unwrap();
        let mut dom_buf = vec![0u8; dlen[0] as usize];
        stream.read_exact(&mut dom_buf).await.unwrap();
        assert_eq!(String::from_utf8(dom_buf).unwrap(), "youtube.com");

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await.unwrap();
        assert_eq!(u16::from_be_bytes(port_buf), 443);

        // Reply SUCCESS
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 1, 187]).await.unwrap();

        // Read forwarded payload
        let mut received = Vec::new();
        let mut chunk = [0u8; 1024];
        while received.len() < original_len {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 { break; }
            received.extend_from_slice(&chunk[..n]);
        }
        received
    });

    // 2. Intercepting Proxy Listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_task = tokio::spawn(async move {
        let (client_conn, _) = proxy_listener.accept().await.unwrap();

        // Peek with short timeout
        let mut peek_buf = [0u8; 2048];
        let peek_res = tokio::time::timeout(Duration::from_millis(50), client_conn.peek(&mut peek_buf)).await;
        let mut detected_domain = None;
        if let Ok(Ok(n)) = peek_res {
            if let Some(domain) = parse_tls_sni(&peek_buf[..n]) {
                detected_domain = Some(domain.to_string());
            }
        }

        let domain_str = detected_domain.expect("SNI sniffing must extract domain via peek");
        assert_eq!(domain_str, "youtube.com");

        let upstream = dial_socks5_tcp_domain(socks_addr, &domain_str, 443, 0, [0, 0, 0, 0]).await.unwrap();
        relay_tcp(client_conn, upstream).await.unwrap();
    });

    // 3. Client connection sending the TLS ClientHello
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&original_payload).await.unwrap();
    client.shutdown().await.unwrap();

    let received_by_socks = socks_server_task.await.unwrap();
    let _ = proxy_task.await;

    // 4. Verify 100% preservation of all bytes
    assert_eq!(received_by_socks.len(), original_len, "All ClientHello bytes must be preserved");
    assert_eq!(received_by_socks, original_payload, "Stream bytes must match bit-for-bit with no loss");
}
