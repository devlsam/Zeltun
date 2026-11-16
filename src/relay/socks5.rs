use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::direct::dial_direct_tcp;

async fn socks5_handshake(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;
    if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 auth rejected: {:?}", auth_resp),
        ));
    }
    Ok(())
}

async fn drain_socks5_reply(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut reply_hdr = [0u8; 4];
    stream.read_exact(&mut reply_hdr).await?;
    if reply_hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 connect failed with status: {}", reply_hdr[1]),
        ));
    }
    match reply_hdr[3] {
        0x01 => {
            let mut drain = [0u8; 6];
            stream.read_exact(&mut drain).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut drain = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut drain).await?;
        }
        0x04 => {
            let mut drain = [0u8; 18];
            stream.read_exact(&mut drain).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn connect_socks5_stream(
    socks_addr: SocketAddr,
    if_index: u32,
    lan_ip: [u8; 4],
) -> std::io::Result<TcpStream> {
    if socks_addr.ip().is_loopback() {
        let stream = TcpStream::connect(socks_addr).await?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    } else {
        dial_direct_tcp(socks_addr, if_index, lan_ip).await
    }
}

pub async fn dial_socks5_tcp(
    socks_addr: SocketAddr,
    dst_ip: [u8; 4],
    dst_port: u16,
    if_index: u32,
    lan_ip: [u8; 4],
) -> std::io::Result<TcpStream> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut stream = connect_socks5_stream(socks_addr, if_index, lan_ip).await?;
        socks5_handshake(&mut stream).await?;

        let req = [
            0x05, 0x01, 0x00, 0x01,
            dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
            (dst_port >> 8) as u8, (dst_port & 0xff) as u8,
        ];
        stream.write_all(&req).await?;
        drain_socks5_reply(&mut stream).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "socks5 connect timeout"))?
}

pub async fn dial_socks5_tcp_domain(
    socks_addr: SocketAddr,
    domain: &str,
    dst_port: u16,
    if_index: u32,
    lan_ip: [u8; 4],
) -> std::io::Result<TcpStream> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut stream = connect_socks5_stream(socks_addr, if_index, lan_ip).await?;
        socks5_handshake(&mut stream).await?;

        let domain_bytes = domain.as_bytes();
        let dlen = domain_bytes.len().min(255) as u8;
        let mut req = Vec::with_capacity(7 + dlen as usize);
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, dlen]);
        req.extend_from_slice(&domain_bytes[..dlen as usize]);
        req.extend_from_slice(&dst_port.to_be_bytes());

        stream.write_all(&req).await?;
        drain_socks5_reply(&mut stream).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "socks5 connect timeout"))?
}
