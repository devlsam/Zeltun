pub mod direct;
pub mod session;
pub mod socks5;

#[cfg(test)]
mod tests;

pub use direct::*;
pub use session::*;
pub use socks5::*;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::config::live_config;
use crate::driver::WintunSession;
use crate::ffi::{ACTIVE_UDP, DROPPED_PKTS, ROUTER};
use crate::proc::RESOLVER;
use crate::router::RouteAction;

pub struct UdpManager {
    sessions: Arc<RwLock<HashMap<u16, Arc<UdpNatEntry>>>>,
    socks_addr: SocketAddr,
    phys_if_index: u32,
    lan_ip: [u8; 4],
    tun_ip: [u8; 4],
    use_live: bool,
    handle: tokio::runtime::Handle,
    start_time: Instant,
}

impl UdpManager {
    pub fn new(socks_addr: SocketAddr, phys_if_index: u32, lan_ip: [u8; 4], tun_ip: [u8; 4], handle: tokio::runtime::Handle) -> Self {
        Self::new_inner(socks_addr, phys_if_index, lan_ip, tun_ip, false, handle)
    }

    pub fn new_live(handle: tokio::runtime::Handle) -> Self {
        let cfg = live_config();
        Self::new_inner(cfg.socks_addr(), cfg.phys_if_index(), cfg.phys_lan_ip(), cfg.tun_ip(), true, handle)
    }

    fn new_inner(socks_addr: SocketAddr, phys_if_index: u32, lan_ip: [u8; 4], tun_ip: [u8; 4], use_live: bool, handle: tokio::runtime::Handle) -> Self {
        let mgr = Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            socks_addr,
            phys_if_index,
            lan_ip,
            tun_ip,
            use_live,
            handle,
            start_time: Instant::now(),
        };
        let sessions_clean = mgr.sessions.clone();
        let start_time = mgr.start_time;
        mgr.handle.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let now_ms = elapsed_ms(start_time);
                let idle_ms = if use_live { live_config().udp_timeout_ms() as i64 } else { 60_000 };
                let mut to_remove = Vec::new();
                if let Ok(g) = sessions_clean.read() {
                    for (&port, entry) in g.iter() {
                        let timeout = if entry.is_dns { 5_000 } else { idle_ms };
                        if now_ms.saturating_sub(entry.last_active.load(Ordering::Relaxed)) > timeout || entry.closed.load(Ordering::Acquire) {
                            entry.closed.store(true, Ordering::Release);
                            to_remove.push(port);
                        }
                    }
                }
                if !to_remove.is_empty() {
                    if let Ok(mut g) = sessions_clean.write() {
                        for p in to_remove { g.remove(&p); }
                        if use_live { ACTIVE_UDP.store(g.len() as u32, Ordering::Release); }
                    }
                }
            }
        });
        mgr
    }

    fn resolve_action(src_port: u16, dst_ip: [u8; 4]) -> (u32, RouteAction) {
        let (pid, name_bytes, name_len) = RESOLVER.resolve_udp_process_by_port(src_port).unwrap_or((0, [0u8; 64], 0));
        let action = ROUTER
            .get()
            .map_or(RouteAction::Proxy, |r| r.decide(pid, &name_bytes[..name_len], dst_ip));
        (pid, action)
    }

    pub fn handle_outbound(
        &self,
        session_pkt: &Arc<WintunSession>,
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) {
        let now_ms = elapsed_ms(self.start_time);
        let is_dns = dst_port == 53;
        let cur_ver = ROUTER.get().map_or(0, |r| r.rule_version());

        let existing = self
            .sessions
            .read()
            .ok()
            .and_then(|g| g.get(&src_port).cloned())
            .filter(|e| !e.closed.load(Ordering::Acquire));

        let mut resolved = None;
        if let Some(entry) = existing {
            let ev = entry.rule_ver.load(Ordering::Acquire);
            if (ev == cur_ver && ev != 0) || cur_ver == 0 {
                entry.touch_and_send(now_ms, dst_ip, dst_port, payload);
                return;
            }
            let (pid, new_action) = Self::resolve_action(src_port, dst_ip);
            if new_action == entry.action {
                entry.rule_ver.store(cur_ver, Ordering::Release);
                entry.touch_and_send(now_ms, dst_ip, dst_port, payload);
                return;
            }
            entry.closed.store(true, Ordering::Release);
            resolved = Some((pid, new_action));
        }

        let (_, action) = resolved.unwrap_or_else(|| Self::resolve_action(src_port, dst_ip));
        if action == RouteAction::Drop {
            DROPPED_PKTS.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let (socks_addr, phys_if, lan_ip, tun_ip) = if self.use_live {
            let cfg = live_config();
            (cfg.socks_addr(), cfg.phys_if_index(), cfg.phys_lan_ip(), cfg.tun_ip())
        } else {
            (self.socks_addr, self.phys_if_index, self.lan_ip, self.tun_ip)
        };

        let direct = if action == RouteAction::Direct {
            let _guard = self.handle.enter();
            DirectUdpSession::new(phys_if, lan_ip).ok().map(Arc::new)
        } else {
            None
        };

        let (tx, rx) = mpsc::channel::<([u8; 4], u16, Vec<u8>)>(1024);
        let entry = Arc::new(UdpNatEntry {
            sender: tx,
            direct,
            proxy: OnceLock::new(),
            last_dst: AtomicU64::new(pack_udp_dst(dst_ip, dst_port)),
            last_active: AtomicI64::new(now_ms),
            closed: Arc::new(AtomicBool::new(false)),
            is_dns,
            action,
            rule_ver: AtomicU32::new(cur_ver),
        });

        if let Ok(mut g) = self.sessions.write() {
            if g.len() >= 512 {
                if let Some(p) = g.iter().min_by_key(|(_, e)| e.last_active.load(Ordering::Relaxed)).map(|(&p, _)| p) {
                    if let Some(old) = g.remove(&p) {
                        old.closed.store(true, Ordering::Release);
                    }
                }
            }
            g.insert(src_port, entry.clone());
            if self.use_live {
                ACTIVE_UDP.store(g.len() as u32, Ordering::Release);
            }
        }

        entry.send_outbound(dst_ip, dst_port, payload);
        spawn_udp_session_worker(
            &self.handle,
            entry,
            rx,
            socks_addr,
            phys_if,
            lan_ip,
            tun_ip,
            src_port,
            session_pkt.clone(),
            self.start_time,
        );
    }
}
