use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::config::{OPTIONS, OPT_STRICT_ANTI_LEAK};
use crate::ffi::DROPPED_PKTS;
use crate::relay::dial_socks5_tcp;
use crate::udp::DirectUdpSession;

pub async fn query_dns_over_socks_ep(
    socks_addr: SocketAddr,
    phys_if: u32,
    lan_ip: [u8; 4],
    dns_server: [u8; 4],
    query: &[u8],
) -> Option<Vec<u8>> {
    let res = timeout(Duration::from_millis(1200), async {
        let mut stream = dial_socks5_tcp(socks_addr, dns_server, 53, phys_if, lan_ip).await.ok()?;
        let len_bytes = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.ok()?;
        stream.write_all(query).await.ok()?;
        stream.flush().await.ok()?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await.ok()?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        if resp_len > 4096 || resp_len < 12 { return None; }

        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await.ok()?;
        Some(resp)
    }).await;

    match res {
        Ok(Some(mut resp)) if resp.len() >= 12 => {
            resp[0] = query[0];
            resp[1] = query[1];
            Some(resp)
        }
        _ => None,
    }
}

pub async fn query_dns_direct_udp_ep(
    phys_if: u32,
    lan_ip: [u8; 4],
    dns_server: [u8; 4],
    port: u16,
    query: &[u8],
) -> Option<Vec<u8>> {
    let res = timeout(Duration::from_millis(1200), async {
        let sock = DirectUdpSession::new(phys_if, lan_ip).ok()?;
        sock.send_packet(dns_server, port, query).await.ok()?;
        let mut buf = vec![0u8; 1500];
        let (n, _, _) = sock.recv_packet(&mut buf).await.ok()?;
        if n >= 12 {
            buf.truncate(n);
            Some(buf)
        } else {
            None
        }
    }).await;

    match res {
        Ok(Some(mut resp)) if resp.len() >= 12 => {
            resp[0] = query[0];
            resp[1] = query[1];
            Some(resp)
        }
        _ => None,
    }
}

async fn resolve_socks_hedged(
    socks_addr: SocketAddr,
    phys_if: u32,
    lan_ip: [u8; 4],
    p_dns: [u8; 4],
    s_dns_opt: Option<[u8; 4]>,
    query: &[u8],
) -> Option<Vec<u8>> {
    let p_fut = query_dns_over_socks_ep(socks_addr, phys_if, lan_ip, p_dns, query);
    let Some(s_dns) = s_dns_opt else {
        return p_fut.await;
    };
    tokio::pin!(p_fut);
    tokio::select! {
        res = &mut p_fut => {
            if res.is_some() {
                return res;
            }
            query_dns_over_socks_ep(socks_addr, phys_if, lan_ip, s_dns, query).await
        }
        _ = tokio::time::sleep(Duration::from_millis(450)) => {
            let s_fut = query_dns_over_socks_ep(socks_addr, phys_if, lan_ip, s_dns, query);
            tokio::pin!(s_fut);
            tokio::select! {
                res = &mut p_fut => if res.is_some() { res } else { s_fut.await },
                res = &mut s_fut => if res.is_some() { res } else { p_fut.await },
            }
        }
    }
}

async fn fallback_direct_udp(
    phys_if: u32,
    lan_ip: [u8; 4],
    p_dns: [u8; 4],
    s_dns_opt: Option<[u8; 4]>,
    query: &[u8],
) -> Option<Vec<u8>> {
    if let Some(r) = query_dns_direct_udp_ep(phys_if, lan_ip, p_dns, 53, query).await {
        return Some(r);
    }
    if let Some(s_dns) = s_dns_opt {
        return query_dns_direct_udp_ep(phys_if, lan_ip, s_dns, 53, query).await;
    }
    None
}

/// Resolves DNS via hedged primary/secondary SOCKS5 TCP, or fast unpoisoned Direct UDP race in `SplitMode::Include`.
pub async fn resolve_upstream(
    socks_addr: SocketAddr,
    phys_if: u32,
    lan_ip: [u8; 4],
    p_dns: [u8; 4],
    s_dns_opt: Option<[u8; 4]>,
    query: &[u8],
) -> Option<Vec<u8>> {
    let fast_include = !OPTIONS.is_enabled(OPT_STRICT_ANTI_LEAK)
        && crate::ffi::ROUTER
            .get()
            .is_some_and(|r| r.get_mode() == crate::router::SplitMode::Include);

    if fast_include {
        let direct_fut = timeout(
            Duration::from_millis(250),
            query_dns_direct_udp_ep(phys_if, lan_ip, p_dns, 53, query),
        );
        let socks_fut = resolve_socks_hedged(socks_addr, phys_if, lan_ip, p_dns, s_dns_opt, query);
        tokio::pin!(direct_fut);
        tokio::pin!(socks_fut);
        tokio::select! {
            res = &mut direct_fut => {
                if let Ok(Some(resp)) = res {
                    if super::format::is_valid_unpoisoned_dns_response(&resp) {
                        return Some(resp);
                    }
                }
                if let Some(r) = socks_fut.await {
                    return Some(r);
                }
            }
            res = &mut socks_fut => {
                if let Some(r) = res {
                    return Some(r);
                }
            }
        }
        return fallback_direct_udp(phys_if, lan_ip, p_dns, s_dns_opt, query).await;
    }

    if let Some(r) = resolve_socks_hedged(socks_addr, phys_if, lan_ip, p_dns, s_dns_opt, query).await {
        return Some(r);
    }
    if OPTIONS.is_enabled(OPT_STRICT_ANTI_LEAK) {
        DROPPED_PKTS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    fallback_direct_udp(phys_if, lan_ip, p_dns, s_dns_opt, query).await
}

