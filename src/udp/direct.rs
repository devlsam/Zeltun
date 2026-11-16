use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::config::{OPTIONS, OPT_GAMING_QOS};
use crate::relay::bind_socket_to_if;

#[cfg(windows)]
#[link(name = "ws2_32")]
extern "system" {
    fn WSAIoctl(
        s: windows_sys::Win32::Networking::WinSock::SOCKET,
        dwIoControlCode: u32,
        lpvInBuffer: *const std::ffi::c_void,
        cbInBuffer: u32,
        lpvOutBuffer: *mut std::ffi::c_void,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;
}

#[cfg(windows)]
pub fn disable_udp_connreset(raw_sock: windows_sys::Win32::Networking::WinSock::SOCKET) {
    const SIO_UDP_CONNRESET: u32 = 0x9800000c;
    let flag: u32 = 0; // FALSE
    let mut bytes_returned: u32 = 0;
    unsafe {
        WSAIoctl(
            raw_sock,
            SIO_UDP_CONNRESET,
            &flag as *const u32 as *const _,
            4,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

pub struct DirectUdpSession {
    socket: Arc<UdpSocket>,
}

impl DirectUdpSession {
    pub fn new(phys_if_index: u32, lan_ip: [u8; 4]) -> std::io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_nonblocking(true)?;
        let _ = sock.set_reuse_address(true);

        let buf_size = if OPTIONS.is_enabled(OPT_GAMING_QOS) { 2_097_152 } else { 524_288 };
        let _ = sock.set_recv_buffer_size(buf_size);
        let _ = sock.set_send_buffer_size(buf_size);

        if lan_ip != [0, 0, 0, 0] {
            let local_ip = std::net::Ipv4Addr::from(lan_ip);
            let local_addr = SocketAddr::new(std::net::IpAddr::V4(local_ip), 0);
            let _ = sock.bind(&local_addr.into());
        }

        if phys_if_index > 0 {
            bind_socket_to_if(sock.as_raw_socket() as _, phys_if_index);
        }

        disable_udp_connreset(sock.as_raw_socket() as _);

        let std_sock: std::net::UdpSocket = sock.into();
        let tokio_sock = UdpSocket::from_std(std_sock)?;

        Ok(Self {
            socket: Arc::new(tokio_sock),
        })
    }

    #[inline]
    pub fn try_send_packet(&self, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> std::io::Result<usize> {
        let target = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(dst_ip)), dst_port);
        self.socket.try_send_to(payload, target)
    }

    pub async fn send_packet(&self, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> std::io::Result<()> {
        let target = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(dst_ip)), dst_port);
        self.socket.send_to(payload, target).await?;
        Ok(())
    }

    pub async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, [u8; 4], u16)> {
        loop {
            match self.socket.recv_from(buf).await {
                Ok((n, SocketAddr::V4(v4))) => return Ok((n, v4.ip().octets(), v4.port())),
                Ok(_) => continue,
                Err(ref e) if super::socks5::is_transient_udp_err(e) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}
