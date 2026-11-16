use super::*;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

#[test]
fn test_phase2_process_resolver() {
    let resolver = ProcessResolver::new();

    // 1. Open an actual TCP listener on 127.0.0.1
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind TCP listener");
    let local_addr = listener.local_addr().expect("Failed to get local addr");
    let _listen_port = local_addr.port();

    // Connect to it to establish an active TCP socket
    let client = TcpStream::connect(local_addr).expect("Failed to connect to local TCP listener");
    let client_port = client.local_addr().expect("Failed to get client port").port();

    let current_pid = std::process::id();

    // 2. Resolve client_port using Windows kernel table
    let start = Instant::now();
    let result = resolver.resolve_process_by_port(client_port);
    let elapsed = start.elapsed();

    assert!(
        result.is_some(),
        "Must resolve process for active socket on port {}",
        client_port
    );
    let (resolved_pid, resolved_name, name_len) = result.unwrap();
    assert_eq!(resolved_pid, current_pid, "Resolved PID must match current test PID");

    let name_str = std::str::from_utf8(&resolved_name[..name_len]).unwrap();
    assert!(
        name_str.ends_with(".exe"),
        "Resolved process name must end with .exe, got: {}",
        name_str
    );
    println!(
        "[RESOLVED] Port {} -> PID: {}, Name: {} in {:?}",
        client_port, resolved_pid, name_str, elapsed
    );

    // 3. Second call should instantly hit the 4-way associative cache
    let cache_start = Instant::now();
    let cached_result = resolver.resolve_process_by_port(client_port);
    let cache_elapsed = cache_start.elapsed();

    assert_eq!(cached_result, Some((resolved_pid, resolved_name, name_len)));
    println!(
        "[CACHED] Port {} resolved from 4-Way cache in {:?}",
        client_port, cache_elapsed
    );
}

#[test]
fn test_udp_ipv4_ipv6_and_stale_eviction() {
    let resolver = ProcessResolver::new();
    let pid = std::process::id();

    let v4_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ipv4 udp");
    let v4_port = v4_sock.local_addr().unwrap().port();
    let res_v4 = resolver.resolve_udp_process_by_port(v4_port);
    assert!(res_v4.is_some(), "Must resolve IPv4 UDP port {}", v4_port);
    assert_eq!(res_v4.unwrap().0, pid);

    let v6_sock = std::net::UdpSocket::bind("[::]:0").expect("bind ipv6 udp");
    let v6_port = v6_sock.local_addr().unwrap().port();
    let res_v6 = resolver.resolve_udp_process_by_port(v6_port);
    assert!(res_v6.is_some(), "Must resolve IPv6 UDP port {}", v6_port);
    assert_eq!(res_v6.unwrap().0, pid);

    drop(v4_sock);
    std::thread::sleep(Duration::from_millis(120));
    let after_close = resolver.resolve_udp_process_by_port(v4_port);
    assert!(after_close.is_none(), "Stale closed UDP port {} must not remain cached", v4_port);
}
