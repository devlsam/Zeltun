use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::direct::disable_udp_connreset;
use crate::config::{OPTIONS, OPT_GAMING_QOS};

/// RFC 1928 SOCKS5 UDP Associate client.
pub struct Socks5UdpClient {
    _tcp: TcpStream,
    udp: Arc<UdpSocket>,
    relay_addr: SocketAddr,
}

#[inline]
pub(super) fn is_transient_udp_err(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(10054 | 10052 | 10040))
        || matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
}

#[inline]
fn encode_socks5_udp_hdr(dst_ip: [u8; 4], dst_port: u16, out: &mut [u8]) {
    out[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    out[4..8].copy_from_slice(&dst_ip);
    out[8..10].copy_from_slice(&dst_port.to_be_bytes());
}

impl Socks5UdpClient {
    pub async fn connect(socks_addr: SocketAddr, phys_if_index: u32) -> std::io::Result<Self> {
        let (tcp, relay_addr) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut tcp = if socks_addr.ip().is_loopback() {
                TcpStream::connect(socks_addr).await?
            } else {
                crate::relay::dial_direct_tcp(socks_addr, phys_if_index, [0, 0, 0, 0]).await?
            };
            let _ = tcp.set_nodelay(true);

            tcp.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut auth_resp = [0u8; 2];
            tcp.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 auth rejected: {:?}", auth_resp)));
            }

            tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            let mut reply_hdr = [0u8; 4];
            tcp.read_exact(&mut reply_hdr).await?;
            if reply_hdr[1] != 0x00 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 UDP Associate rejected with code {}", reply_hdr[1])));
            }

            let relay_addr = match reply_hdr[3] {
                0x01 => {
                    let mut bnd = [0u8; 6];
                    tcp.read_exact(&mut bnd).await?;
                    let mut ip = [bnd[0], bnd[1], bnd[2], bnd[3]];
                    let port = match u16::from_be_bytes([bnd[4], bnd[5]]) { 0 => socks_addr.port(), p => p };
                    if ip == [0, 0, 0, 0] {
                        ip = match socks_addr.ip() { std::net::IpAddr::V4(v4) => v4.octets(), _ => [127, 0, 0, 1] };
                    }
                    SocketAddr::from((ip, port))
                }
                0x03 => {
                    let mut len_buf = [0u8; 1];
                    tcp.read_exact(&mut len_buf).await?;
                    let mut domain_buf = vec![0u8; len_buf[0] as usize + 2];
                    tcp.read_exact(&mut domain_buf).await?;
                    let pi = domain_buf.len() - 2;
                    let port = match u16::from_be_bytes([domain_buf[pi], domain_buf[pi + 1]]) { 0 => socks_addr.port(), p => p };
                    SocketAddr::new(socks_addr.ip(), port)
                }
                _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Unsupported SOCKS5 ATYP: {}", reply_hdr[3]))),
            };
            Ok::<_, std::io::Error>((tcp, relay_addr))
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 UDP associate timed out"))??;

        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        sock.set_nonblocking(true)?;
        let buf_size = if OPTIONS.is_enabled(OPT_GAMING_QOS) { 2_097_152 } else { 524_288 };
        let _ = sock.set_recv_buffer_size(buf_size);
        let _ = sock.set_send_buffer_size(buf_size);
        disable_udp_connreset(sock.as_raw_socket() as _);

        let bind_addr: SocketAddr = if socks_addr.ip().is_loopback() {
            "127.0.0.1:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        sock.bind(&bind_addr.into())?;
        let udp = UdpSocket::from_std(sock.into())?;

        Ok(Self {
            _tcp: tcp,
            udp: Arc::new(udp),
            relay_addr,
        })
    }

    #[inline]
    pub fn try_send_packet(&self, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> std::io::Result<usize> {
        let total = 10 + payload.len();
        if total > 2048 {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "oversized"));
        }
        let mut packet = [0u8; 2048];
        encode_socks5_udp_hdr(dst_ip, dst_port, &mut packet);
        packet[10..total].copy_from_slice(payload);
        self.udp.try_send_to(&packet[..total], self.relay_addr)
    }

    pub async fn send_packet(&self, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> std::io::Result<()> {
        let total = 10 + payload.len();
        if total <= 2048 {
            let mut packet = [0u8; 2048];
            encode_socks5_udp_hdr(dst_ip, dst_port, &mut packet);
            packet[10..total].copy_from_slice(payload);
            self.udp.send_to(&packet[..total], self.relay_addr).await?;
        } else {
            let mut packet = vec![0u8; total];
            encode_socks5_udp_hdr(dst_ip, dst_port, &mut packet);
            packet[10..total].copy_from_slice(payload);
            self.udp.send_to(&packet, self.relay_addr).await?;
        }
        Ok(())
    }

    pub async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, [u8; 4], u16)> {
        let mut raw = [0u8; 4096];
        loop {
            let (n, from) = match self.udp.recv_from(&mut raw).await {
                Ok(res) => res,
                Err(ref e) if is_transient_udp_err(e) => continue,
                Err(e) => return Err(e),
            };
            if n < 10 || (from != self.relay_addr && from.port() != self.relay_addr.port()) {
                continue;
            }
            if raw[0] != 0 || raw[1] != 0 || raw[2] != 0 {
                continue;
            }

            match raw[3] {
                0x01 => {
                    let src_ip = [raw[4], raw[5], raw[6], raw[7]];
                    let src_port = u16::from_be_bytes([raw[8], raw[9]]);
                    let payload_len = (n - 10).min(buf.len());
                    buf[..payload_len].copy_from_slice(&raw[10..10 + payload_len]);
                    return Ok((payload_len, src_ip, src_port));
                }
                0x03 => {
                    let domain_len = raw[4] as usize;
                    if n < 5 + domain_len + 2 { continue; }
                    let port_offset = 5 + domain_len;
                    let src_port = u16::from_be_bytes([raw[port_offset], raw[port_offset + 1]]);
                    let payload_offset = port_offset + 2;
                    let payload_len = (n - payload_offset).min(buf.len());
                    buf[..payload_len].copy_from_slice(&raw[payload_offset..payload_offset + payload_len]);
                    return Ok((payload_len, [0, 0, 0, 0], src_port));
                }
                _ => continue,
            }
        }
    }

    pub async fn wait_tcp_closed(&self) {
        let mut buf = [0u8; 1];
        loop {
            if self._tcp.readable().await.is_err() { break; }
            match self._tcp.try_read(&mut buf) {
                Ok(0) => break,
                Err(ref e)
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) =>
                {
                    continue
                }
                Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}
