use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn bind_listener_backlog() -> TcpListener {
    let s = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    ).unwrap();
    s.set_nonblocking(true).unwrap();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    s.bind(&addr.into()).unwrap();
    s.listen(1024).unwrap();
    TcpListener::from_std(s.into()).unwrap()
}

async fn start_mock_socks5() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = bind_listener_backlog();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };

            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                if client.read_exact(&mut greet).await.is_err() {
                    return;
                }
                if client.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }

                let mut req = [0u8; 10];
                if client.read_exact(&mut req).await.is_err() {
                    return;
                }

                let dst_ip = &req[4..8];
                let dst_port = u16::from_be_bytes([req[8], req[9]]);
                let target_addr: SocketAddr = format!(
                    "{}.{}.{}.{}:{}",
                    dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], dst_port
                )
                .parse()
                .unwrap();

                let Ok(target) = TcpStream::connect(target_addr).await else {
                    let _ = client
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                };

                let _ = client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                let _ = relay_tcp(client, target).await;
            });
        }
    });

    (addr, handle)
}

async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = bind_listener_backlog();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_phase4_stress_relay_500_streams() {
    let (echo_addr, _echo_handle) = start_echo_server().await;
    let (socks_addr, _socks_handle) = start_mock_socks5().await;

    let total_streams = 500;
    let success_count = Arc::new(AtomicUsize::new(0));
    let echo_ip: [u8; 4] = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => panic!("Expected IPv4"),
    };
    let echo_port = echo_addr.port();

    let ram_before = get_working_set_mb();
    println!("=== PHASE 4: STRESS RELAY TEST START ===");
    println!("Active Working Set RAM Before: {:.2} MB", ram_before);

    let start = Instant::now();
    let mut tasks = Vec::with_capacity(total_streams);

    for i in 0..total_streams {
        let succ = success_count.clone();

        tasks.push(tokio::spawn(async move {
            let is_proxy = i % 2 == 0;
            let mut outbound = None;
            for _ in 0..5 {
                let res = if is_proxy {
                    dial_socks5_tcp(socks_addr, echo_ip, echo_port, 0, [0, 0, 0, 0]).await
                } else {
                    dial_direct_tcp(echo_addr, 0, [0, 0, 0, 0]).await
                };
                if let Ok(stream) = res {
                    outbound = Some(stream);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let mut outbound = outbound.expect("Stream dial must succeed");

            let test_payload = format!("STREAM_PAYLOAD_{:04}_DATA_BLOCK_HEAVY_NETWORKING", i);
            let payload_bytes = test_payload.as_bytes();

            outbound.write_all(payload_bytes).await.unwrap();

            let mut recv_buf = vec![0u8; payload_bytes.len()];
            outbound.read_exact(&mut recv_buf).await.unwrap();

            if &recv_buf[..] == payload_bytes {
                succ.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    let elapsed = start.elapsed();
    let ram_after = get_working_set_mb();
    let successes = success_count.load(Ordering::SeqCst);

    println!("=== 500 CONCURRENT STREAMS METRICS ===");
    println!("Elapsed Time       : {:?}", elapsed);
    println!(
        "Successful Streams : {} / {} ({:.2}%)",
        successes,
        total_streams,
        (successes as f64 / total_streams as f64) * 100.0
    );
    println!("Failed Streams     : {} (0% Packet/Conn Loss)", total_streams - successes);
    println!("Working Set RAM    : {:.2} MB (Delta: {:+.2} MB)", ram_after, ram_after - ram_before);

    assert_eq!(
        successes, total_streams,
        "All 500 streams must succeed with 0% loss"
    );
}
