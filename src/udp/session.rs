use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::sync::mpsc;

use crate::config::{OPTIONS, OPT_STRICT_ANTI_LEAK};
use crate::driver::WintunSession;
use crate::ffi::{DIRECT_BYTES, DROPPED_PKTS, PROXY_BYTES, TX_BYTES};
use crate::packet::{build_udp_packet, build_udp_packet_into};
use crate::router::RouteAction;
use super::direct::DirectUdpSession;
use super::socks5::Socks5UdpClient;

#[inline(always)]
pub(super) fn elapsed_ms(start: Instant) -> i64 {
    (start.elapsed().as_millis() & 0x7fffffffffffffff) as i64
}

pub struct UdpNatEntry {
    pub sender: mpsc::Sender<([u8; 4], u16, Vec<u8>)>,
    pub direct: Option<Arc<DirectUdpSession>>,
    pub proxy: OnceLock<Arc<Socks5UdpClient>>,
    pub last_dst: AtomicU64,
    pub last_active: AtomicI64,
    pub closed: Arc<AtomicBool>,
    pub is_dns: bool,
    pub action: RouteAction,
    pub rule_ver: AtomicU32,
}

#[inline(always)]
fn record_udp_bytes(action: RouteAction, bytes: usize) {
    let n = bytes as u64;
    if action == RouteAction::Direct { DIRECT_BYTES.fetch_add(n, Ordering::Relaxed); } else { PROXY_BYTES.fetch_add(n, Ordering::Relaxed); }
}

impl UdpNatEntry {
    #[inline]
    pub fn touch_and_send(&self, now_ms: i64, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) {
        self.last_active.store(now_ms, Ordering::Relaxed);
        self.send_outbound(dst_ip, dst_port, payload);
    }

    #[inline]
    pub fn send_outbound(&self, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) {
        self.last_dst.store(pack_udp_dst(dst_ip, dst_port), Ordering::Relaxed);
        let sent = self.direct.as_ref().is_some_and(|d| d.try_send_packet(dst_ip, dst_port, payload).is_ok())
            || self.proxy.get().is_some_and(|p| p.try_send_packet(dst_ip, dst_port, payload).is_ok());
        if sent {
            record_udp_bytes(self.action, payload.len());
        } else {
            let _ = self.sender.try_send((dst_ip, dst_port, payload.to_vec()));
        }
    }
}

#[inline(always)]
pub(crate) fn pack_udp_dst(ip: [u8; 4], port: u16) -> u64 {
    (u32::from_le_bytes(ip) as u64) | ((port as u64) << 32)
}

#[inline(always)]
pub(crate) fn unpack_udp_dst(val: u64) -> ([u8; 4], u16) {
    ((val as u32).to_le_bytes(), (val >> 32) as u16)
}

#[inline]
fn inject_udp_reply(
    session_pkt: &Arc<WintunSession>,
    entry: &UdpNatEntry,
    mut r_ip: [u8; 4],
    tun_ip: [u8; 4],
    mut r_port: u16,
    src_port: u16,
    payload: &[u8],
    start_time: Instant,
) {
    entry.last_active.store(elapsed_ms(start_time), Ordering::Relaxed);
    if r_ip == [0, 0, 0, 0] || r_port == 0 {
        let (fb_ip, fb_port) = unpack_udp_dst(entry.last_dst.load(Ordering::Relaxed));
        if r_ip == [0, 0, 0, 0] { r_ip = fb_ip; }
        if r_port == 0 { r_port = fb_port; }
    }
    let mut pkt_buf = [0u8; 4096];
    let pkt_len = build_udp_packet_into(r_ip, tun_ip, r_port, src_port, payload, &mut pkt_buf);
    let ok = if pkt_len > 0 {
        session_pkt.inject_packet(&pkt_buf[..pkt_len]).then(|| TX_BYTES.fetch_add(pkt_len as u64, Ordering::Relaxed)).is_some()
    } else {
        let resp = build_udp_packet(r_ip, tun_ip, r_port, src_port, payload);
        session_pkt.inject_packet(&resp).then(|| TX_BYTES.fetch_add(resp.len() as u64, Ordering::Relaxed)).is_some()
    };
    if ok { record_udp_bytes(entry.action, payload.len()); }
}

pub fn spawn_udp_session_worker(
    handle: &tokio::runtime::Handle,
    entry: Arc<UdpNatEntry>,
    mut rx: mpsc::Receiver<([u8; 4], u16, Vec<u8>)>,
    socks_addr: SocketAddr,
    phys_if: u32,
    lan_ip: [u8; 4],
    tun_ip: [u8; 4],
    src_port: u16,
    session_pkt: Arc<WintunSession>,
    start_time: Instant,
) {
    handle.spawn(async move {
        match entry.action {
            RouteAction::Direct => {
                run_direct_udp_worker(&entry, rx, phys_if, lan_ip, tun_ip, src_port, &session_pkt, start_time).await;
            }
            RouteAction::Proxy => match Socks5UdpClient::connect(socks_addr, phys_if).await {
                Ok(proxy) => {
                    let proxy = Arc::new(proxy);
                    while let Ok((d_ip, d_port, data)) = rx.try_recv() {
                        if entry.closed.load(Ordering::Acquire) { break; }
                        let _ = proxy.send_packet(d_ip, d_port, &data).await;
                    }
                    let _ = entry.proxy.set(proxy.clone());

                    let proxy_send = proxy.clone();
                    let closed_send = entry.closed.clone();
                    tokio::spawn(async move {
                        while let Some((d_ip, d_port, data)) = rx.recv().await {
                            if closed_send.load(Ordering::Acquire) { break; }
                            let _ = proxy_send.send_packet(d_ip, d_port, &data).await;
                        }
                    });

                    let mut buf = [0u8; 4096];
                    while !entry.closed.load(Ordering::Acquire) {
                        tokio::select! {
                            res = proxy.recv_packet(&mut buf) => match res {
                                Ok((n, r_ip, r_port)) => {
                                    inject_udp_reply(&session_pkt, &entry, r_ip, tun_ip, r_port, src_port, &buf[..n], start_time);
                                }
                                Err(_) => break,
                            },
                            _ = proxy.wait_tcp_closed() => break,
                        }
                    }
                }
                Err(e) => {
                    crate::config::push_log(crate::config::LOG_WARN, format!("SOCKS5 UDP Associate failed: {}", e));
                    if entry.is_dns && !OPTIONS.is_enabled(OPT_STRICT_ANTI_LEAK) {
                        run_direct_udp_worker(&entry, rx, phys_if, lan_ip, tun_ip, src_port, &session_pkt, start_time).await;
                    } else {
                        DROPPED_PKTS.fetch_add(1, Ordering::Relaxed);
                    }
                }
            },
            RouteAction::Drop => {}
        }

        entry.closed.store(true, Ordering::Release);
    });
}

async fn run_direct_udp_worker(
    entry: &UdpNatEntry,
    mut rx: mpsc::Receiver<([u8; 4], u16, Vec<u8>)>,
    phys_if: u32,
    lan_ip: [u8; 4],
    tun_ip: [u8; 4],
    src_port: u16,
    session_pkt: &Arc<WintunSession>,
    start_time: Instant,
) {
    let direct = match entry.direct {
        Some(ref d) => d.clone(),
        None => match DirectUdpSession::new(phys_if, lan_ip) {
            Ok(d) => Arc::new(d),
            Err(_) => {
                entry.closed.store(true, Ordering::Release);
                return;
            }
        },
    };

    let direct_send = direct.clone();
    let closed_send = entry.closed.clone();
    tokio::spawn(async move {
        while let Some((d_ip, d_port, data)) = rx.recv().await {
            if closed_send.load(Ordering::Acquire) { break; }
            let _ = direct_send.send_packet(d_ip, d_port, &data).await;
        }
    });

    let mut buf = [0u8; 4096];
    while !entry.closed.load(Ordering::Acquire) {
        match direct.recv_packet(&mut buf).await {
            Ok((n, r_ip, r_port)) => {
                inject_udp_reply(session_pkt, entry, r_ip, tun_ip, r_port, src_port, &buf[..n], start_time);
            }
            Err(_) => break,
        }
    }
}
