mod cache;
pub mod format;
mod upstream;

#[cfg(test)]
mod tests;

pub use format::*;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use cache::{patch_txid, DnsCacheStore, InflightSlot};
use upstream::{query_dns_direct_udp_ep, query_dns_over_socks_ep, resolve_upstream};

use crate::config::live_config;
use crate::driver::WintunSession;
use crate::ffi::TX_BYTES;
use crate::packet::build_udp_packet;

#[derive(Clone)]
pub struct DnsResolver {
    pub socks_addr: SocketAddr,
    pub phys_if_index: u32,
    pub lan_ip: [u8; 4],
    pub use_live: bool,
    handle: tokio::runtime::Handle,
    store: DnsCacheStore,
}

impl DnsResolver {
    pub fn new(
        socks_addr: SocketAddr,
        phys_if_index: u32,
        lan_ip: [u8; 4],
        handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            socks_addr,
            phys_if_index,
            lan_ip,
            use_live: false,
            handle,
            store: DnsCacheStore::new(0),
        }
    }

    pub fn new_live(handle: tokio::runtime::Handle) -> Self {
        let cfg = live_config();
        Self {
            socks_addr: cfg.socks_addr(),
            phys_if_index: cfg.phys_if_index(),
            lan_ip: cfg.phys_lan_ip(),
            use_live: true,
            handle,
            store: DnsCacheStore::new(cfg.dns_epoch()),
        }
    }

    fn effective_endpoints(&self) -> (SocketAddr, u32, [u8; 4], [u8; 4], Option<[u8; 4]>, u64) {
        if self.use_live {
            let cfg = live_config();
            (
                cfg.socks_addr(),
                cfg.phys_if_index(),
                cfg.phys_lan_ip(),
                cfg.primary_dns(),
                cfg.secondary_dns(),
                cfg.dns_epoch(),
            )
        } else {
            (self.socks_addr, self.phys_if_index, self.lan_ip, [1, 1, 1, 1], Some([8, 8, 8, 8]), 0)
        }
    }

    pub fn set_phys_if_index(&mut self, if_index: u32) {
        self.phys_if_index = if_index;
    }

    /// Resolves a DNS query with AAAA suppression, caching, in-flight deduplication, and upstream fallback.
    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 { return None; }
        if is_aaaa_query(query) {
            if let Some(nodata) = make_dns_nodata_response(query) {
                return Some(nodata);
            }
        }

        let (socks_addr, phys_if, lan_ip, p_dns, s_dns_opt, cur_epoch) = self.effective_endpoints();
        let q_key = query[2..].to_vec();
        if let Some(hit) = self.store.lookup(&q_key, cur_epoch, query) {
            return Some(hit);
        }

        let guard = match self.store.acquire_inflight(cur_epoch, &q_key) {
            InflightSlot::Waiter(mut rx) => {
                if let Ok(shared) = rx.wait_for(|v| v.is_some()).await {
                    if let Some(pkt) = shared.clone() {
                        return Some(patch_txid(pkt, query));
                    }
                }
                if let Some(hit) = self.store.lookup(&q_key, cur_epoch, query) {
                    return Some(hit);
                }
                None
            }
            InflightSlot::Leader(g) => Some(g),
        };

        let upstream = resolve_upstream(socks_addr, phys_if, lan_ip, p_dns, s_dns_opt, query).await;
        let resp = upstream.or_else(|| make_dns_servfail_response(query));
        if let Some(r) = &resp {
            self.store.store(q_key, cur_epoch, r);
        }
        if let Some(g) = guard {
            let _ = g.tx.send(resp.clone());
        }
        resp
    }

    pub async fn query_dns_over_socks(&self, dns_server: [u8; 4], query: &[u8]) -> Option<Vec<u8>> {
        query_dns_over_socks_ep(self.socks_addr, self.phys_if_index, self.lan_ip, dns_server, query).await
    }

    pub async fn query_dns_direct_udp(&self, dns_server: [u8; 4], query: &[u8]) -> Option<Vec<u8>> {
        self.query_dns_direct_udp_port(dns_server, 53, query).await
    }

    pub async fn query_dns_direct_udp_port(&self, dns_server: [u8; 4], port: u16, query: &[u8]) -> Option<Vec<u8>> {
        query_dns_direct_udp_ep(self.phys_if_index, self.lan_ip, dns_server, port, query).await
    }

    pub fn handle_and_respond(
        &self,
        session_pkt: &Arc<WintunSession>,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        query: &[u8],
    ) {
        let resolver = self.clone();
        let session = session_pkt.clone();
        let query_owned = query.to_vec();

        self.handle.spawn(async move {
            if let Some(resp) = resolver.resolve(&query_owned).await {
                // Restore src_ip to orig_dst_ip so Windows accepts the DNS response
                let raw_pkt = build_udp_packet(dst_ip, src_ip, dst_port, src_port, &resp);
                if session.inject_packet(&raw_pkt) {
                    TX_BYTES.fetch_add(raw_pkt.len() as u64, Ordering::Relaxed);
                }
            }
        });
    }
}
