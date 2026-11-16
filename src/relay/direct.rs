use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use tokio::net::TcpStream;
use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, SOCKET};

pub const IP_UNICAST_IF: i32 = 31;
pub const IPV6_UNICAST_IF: i32 = 31;

const ZERO_U32: AtomicU32 = AtomicU32::new(0);
static DIRECT_DIALED_IPS: [AtomicU32; 64] = [ZERO_U32; 64];
static DIRECT_DIAL_IDX: AtomicUsize = AtomicUsize::new(0);

/// Records an IPv4 address dialed directly by this process so `sync_bypass_routes` won't mistake it for a proxy IP.
pub fn record_direct_dialed_ip(ip: [u8; 4]) {
    let packed = u32::from_ne_bytes(ip);
    if packed == 0 || DIRECT_DIALED_IPS.iter().any(|s| s.load(Ordering::Relaxed) == packed) {
        return;
    }
    let idx = DIRECT_DIAL_IDX.fetch_add(1, Ordering::Relaxed) % DIRECT_DIALED_IPS.len();
    DIRECT_DIALED_IPS[idx].store(packed, Ordering::Release);
}

/// Returns `true` if `ip` was recently dialed directly via `create_bound_tcp_socket`.
pub fn is_direct_dialed_ip(ip: [u8; 4]) -> bool {
    let packed = u32::from_ne_bytes(ip);
    packed != 0 && DIRECT_DIALED_IPS.iter().any(|s| s.load(Ordering::Acquire) == packed)
}

#[inline(always)]
pub fn bind_socket_to_if(raw_sock: SOCKET, if_index: u32) {
    if if_index > 0 {
        let if_index_be = if_index.to_be();
        unsafe {
            setsockopt(
                raw_sock,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &if_index_be as *const u32 as *const _,
                4,
            );
            setsockopt(
                raw_sock,
                IPPROTO_IPV6,
                IPV6_UNICAST_IF,
                &if_index as *const u32 as *const _,
                4,
            );
        }
    }
}

pub fn create_bound_tcp_socket(
    dest_addr: SocketAddr,
    if_index: u32,
    lan_ip: [u8; 4],
) -> std::io::Result<TcpStream> {
    let domain = if dest_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_nodelay(true)?;
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_recv_buffer_size(524288);
    let _ = sock.set_send_buffer_size(524288);

    if let IpAddr::V4(v4) = dest_addr.ip() {
        if !v4.is_loopback() && !v4.is_unspecified() && IpAddr::V4(v4) != crate::config::live_config().socks_addr().ip() {
            record_direct_dialed_ip(v4.octets());
        }
    }

    if !dest_addr.ip().is_loopback() {
        if if_index > 0 {
            bind_socket_to_if(sock.as_raw_socket() as _, if_index);
        }
        if lan_ip != [0, 0, 0, 0] && dest_addr.is_ipv4() {
            let local_ip = std::net::Ipv4Addr::from(lan_ip);
            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
            let _ = sock.bind(&local_addr.into());
        }
    }

    match sock.connect(&dest_addr.into()) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK) => {}
        Err(e) => return Err(e),
    }

    let std_stream: std::net::TcpStream = sock.into();
    TcpStream::from_std(std_stream)
}

pub async fn dial_direct_tcp(
    dest_addr: SocketAddr,
    if_index: u32,
    lan_ip: [u8; 4],
) -> std::io::Result<TcpStream> {
    let stream = create_bound_tcp_socket(dest_addr, if_index, lan_ip)?;
    tokio::time::timeout(std::time::Duration::from_secs(8), stream.writable())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "direct connect timeout"))??;
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}
