use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

use super::adapter::*;
use super::lifecycle::*;
use super::redirect::start_tcp_redirect_router_live;
use super::routes::*;
use super::session::{WintunAdapter, WintunSession};
use super::worker::start_packet_worker;
use crate::config::{fmt_ipv4, live_config, push_log, set_last_error, LOG_INFO};
use crate::dns::DnsResolver;
use crate::ffi::{ROUTER, RUNNING};
use crate::udp::UdpManager;

pub struct TunnelEngine {
    pub adapter_name: String,
    pub tun_ip: [u8; 4],
    pub tun_gw: [u8; 4],
    pub socks_addr: String,
    pub phys_if_index: u32,
    pub phys_gateway: String,
    pub phys_lan_ip: [u8; 4],
    pub ring_capacity: u32,
    pub running: Arc<AtomicBool>,
    adapter: Option<WintunAdapter>,
    session: Option<Arc<WintunSession>>,
    bypassed_routes: Arc<Mutex<Vec<[u8; 4]>>>,
}

unsafe impl Send for TunnelEngine {}
unsafe impl Sync for TunnelEngine {}

impl TunnelEngine {
    pub fn new(socks_addr: &str, phys_if_index: u32, ring_capacity: u32) -> Self {
        let cfg = live_config();
        if let Ok(parsed) = socks_addr.parse() {
            cfg.set_socks_addr(parsed);
        }
        Self {
            adapter_name: cfg.adapter_name(),
            tun_ip: cfg.tun_ip(),
            tun_gw: cfg.tun_gw(),
            socks_addr: cfg.socks_addr().to_string(),
            phys_if_index: if phys_if_index > 0 { phys_if_index } else { cfg.phys_if_index() },
            phys_gateway: cfg.phys_gateway(),
            phys_lan_ip: cfg.phys_lan_ip(),
            ring_capacity: if ring_capacity == 0 { 0x400000 } else { ring_capacity.clamp(0x100000, 0x2000000) },
            running: Arc::new(AtomicBool::new(false)),
            adapter: None,
            session: None,
            bypassed_routes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let cfg = live_config();
        let rt = crate::ffi::RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap()
        });

        let gw_str = fmt_ipv4(self.tun_gw);
        cleanup_stale_tun_state(&self.adapter_name, &gw_str);

        if let Some(r) = ROUTER.get() {
            r.set_tun_endpoints(self.tun_ip, self.tun_gw);
        }

        push_log(LOG_INFO, format!("Opening Wintun adapter '{}' ({})", self.adapter_name, fmt_ipv4(self.tun_ip)));
        let adapter = WintunAdapter::create_or_open(&self.adapter_name, "Byp").map_err(|e| {
            self.running.store(false, Ordering::Release);
            set_last_error(e)
        })?;
        let tun_if_index = adapter.if_index();
        cfg.set_tun_if_index(tun_if_index);

        if self.phys_if_index == 0 || is_virtual_adapter(self.phys_if_index) || self.phys_lan_ip == [0, 0, 0, 0] || self.phys_gateway.is_empty() {
            let phy = detect_physical_adapter();
            if self.phys_if_index == 0 || is_virtual_adapter(self.phys_if_index) {
                self.phys_if_index = phy.if_index;
                self.phys_gateway = phy.gateway.clone();
            } else if self.phys_gateway.is_empty() || (self.phys_if_index == phy.if_index && self.phys_gateway == "192.168.1.1") {
                self.phys_gateway = phy.gateway.clone();
            }
            if self.phys_lan_ip == [0, 0, 0, 0] {
                self.phys_lan_ip = if self.phys_if_index == phy.if_index { phy.lan_ip } else { find_ip_by_interface(self.phys_if_index).unwrap_or(phy.lan_ip) };
            }
        }
        cfg.set_physical_if(self.phys_if_index, Some(&self.phys_gateway), Some(self.phys_lan_ip));

        setup_adapter_interface(&self.adapter_name, tun_if_index, self.tun_ip, cfg.mtu());

        let tun_bind = format!("{}:0", fmt_ipv4(self.tun_ip));
        let mut std_listener = None;
        for _ in 0..20 {
            if let Ok(l) = std::net::TcpListener::bind(&tun_bind) { std_listener = Some(l); break; }
            std::thread::sleep(Duration::from_millis(25));
        }
        let std_listener = match std_listener {
            Some(l) => l,
            None => std::net::TcpListener::bind("0.0.0.0:0").map_err(|e| {
                self.running.store(false, Ordering::Release);
                set_last_error(format!("Redirect listener bind error: {}", e))
            })?,
        };
        std_listener.set_nonblocking(true).unwrap();
        let listen_port = std_listener.local_addr().unwrap().port();

        let init_socks_port = cfg.socks_addr().port();
        sync_bypass_routes(init_socks_port, &self.phys_gateway, self.phys_if_index, &self.bypassed_routes);

        let session = Arc::new(adapter.start_session(self.ring_capacity).map_err(|e| {
            self.running.store(false, Ordering::Release);
            set_last_error(e)
        })?);
        let dns_resolver = Arc::new(DnsResolver::new_live(rt.handle().clone()));
        let udp_manager = Arc::new(UdpManager::new_live(rt.handle().clone()));

        start_packet_worker(session.clone(), self.running.clone(), self.tun_ip, self.tun_gw, listen_port, dns_resolver, udp_manager);

        let _guard = rt.enter();
        let listener = TcpListener::from_std(std_listener).map_err(|e| set_last_error(format!("TcpListener error: {}", e)))?;
        start_tcp_redirect_router_live(listener, self.running.clone());

        install_two_halves_routes(tun_if_index, &gw_str);
        run_quiet("ipconfig", &["/flushdns"]);

        let running_watcher = self.running.clone();
        let bypassed_routes_arc = self.bypassed_routes.clone();
        rt.spawn(async move {
            while running_watcher.load(Ordering::Acquire) {
                let c = live_config();
                let sp = c.socks_addr().port();
                let gw = c.phys_gateway();
                let idx = c.phys_if_index();
                sync_bypass_routes(sp, &gw, idx, &bypassed_routes_arc);
                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
        });

        self.session = Some(session);
        self.adapter = Some(adapter);
        RUNNING.store(true, Ordering::Release);
        push_log(LOG_INFO, format!("Zeltun active on '{}' (MTU={}, Ring={}MB)", self.adapter_name, cfg.mtu(), self.ring_capacity / (1024 * 1024)));
        Ok(())
    }

    pub fn update_physical_if(&mut self, if_idx: u32, gw: &str, lan_ip: [u8; 4]) {
        let old_gw = self.phys_gateway.clone();
        let target_gw = if gw.is_empty() { old_gw.clone() } else { gw.to_string() };
        let target_idx = if if_idx > 0 { if_idx } else { self.phys_if_index };
        let target_ip = if lan_ip != [0, 0, 0, 0] { lan_ip } else { self.phys_lan_ip };
        live_config().set_physical_if(target_idx, Some(&target_gw), Some(target_ip));
        self.phys_if_index = target_idx;
        self.phys_gateway = target_gw.clone();
        self.phys_lan_ip = target_ip;
        migrate_bypass_routes(&old_gw, &target_gw, target_idx, &self.bypassed_routes);
    }

    pub fn add_bypass_ip_runtime(&self, ip: [u8; 4]) {
        if let Some(r) = ROUTER.get() {
            if r.add_bypassed_ip(ip) {
                let ip_s = fmt_ipv4(ip);
                let cfg = live_config();
                install_bypass_route(&ip_s, &cfg.phys_gateway(), cfg.phys_if_index());
                if let Ok(mut g) = self.bypassed_routes.lock() {
                    if !g.contains(&ip) { g.push(ip); }
                }
            }
        }
    }

    pub fn refresh_dns(&self) { apply_adapter_dns_and_nrpt(&self.adapter_name); }

    pub fn refresh_ipv6(&self) {
        if live_config().ipv6_block() { install_ipv6_blackhole(); } else { remove_ipv6_blackhole(); }
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) { return; }
        let gw_str = fmt_ipv4(self.tun_gw);
        cleanup_stale_tun_state(&self.adapter_name, &gw_str);
        if let Ok(mut g) = self.bypassed_routes.lock() {
            for b_ip in g.drain(..) { remove_bypass_route(&fmt_ipv4(b_ip), &self.phys_gateway); }
        }
        live_config().set_tun_if_index(0);
        self.session.take();
        if let Some(mut ad) = self.adapter.take() { ad.close(); }
        RUNNING.store(false, Ordering::Release);
        push_log(LOG_INFO, "Zeltun tunnel engine stopped.");
    }
}
