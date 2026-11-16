use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

#[inline(always)]
pub fn pack_ip(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes(ip)
}

#[inline(always)]
pub fn unpack_ip(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    s.trim().parse::<Ipv4Addr>().ok().map(|ip| ip.octets())
}

pub fn fmt_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Shared live configuration updated safely over FFI and read by workers without contention.
pub struct LiveConfig {
    adapter_name: RwLock<String>,
    socks_addr: RwLock<SocketAddr>,
    phys_gateway: RwLock<String>,
    custom_bypass_ips: RwLock<Vec<[u8; 4]>>,
    tun_ip: AtomicU32,
    tun_gw: AtomicU32,
    tun_if_index: AtomicU32,
    mtu: AtomicU32,
    primary_dns: AtomicU32,
    secondary_dns: AtomicU32,
    enable_nrpt: AtomicBool,
    ipv6_block: AtomicBool,
    udp_timeout_ms: AtomicU64,
    phys_if_index: AtomicU32,
    phys_lan_ip: AtomicU32,
    dns_epoch: AtomicU64,
}

static LIVE_CONFIG: OnceLock<LiveConfig> = OnceLock::new();

pub fn live_config() -> &'static LiveConfig {
    LIVE_CONFIG.get_or_init(LiveConfig::default)
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            adapter_name: RwLock::new("BYPTUN-CORE".to_string()),
            socks_addr: RwLock::new("127.0.0.1:10808".parse().unwrap()),
            phys_gateway: RwLock::new("192.168.1.1".to_string()),
            custom_bypass_ips: RwLock::new(Vec::new()),
            tun_ip: AtomicU32::new(pack_ip([198, 19, 0, 2])),
            tun_gw: AtomicU32::new(pack_ip([198, 19, 0, 1])),
            tun_if_index: AtomicU32::new(0),
            mtu: AtomicU32::new(1500),
            primary_dns: AtomicU32::new(pack_ip([1, 1, 1, 1])),
            secondary_dns: AtomicU32::new(pack_ip([8, 8, 8, 8])),
            enable_nrpt: AtomicBool::new(true),
            ipv6_block: AtomicBool::new(true),
            udp_timeout_ms: AtomicU64::new(120_000),
            phys_if_index: AtomicU32::new(0),
            phys_lan_ip: AtomicU32::new(0),
            dns_epoch: AtomicU64::new(1),
        }
    }
}

impl LiveConfig {
    pub fn set_adapter(&self, name: Option<&str>, tun_ip: Option<[u8; 4]>, tun_gw: Option<[u8; 4]>, mtu: u32) {
        if let Some(n) = name.filter(|s| !s.trim().is_empty()) {
            *self.adapter_name.write().unwrap() = n.trim().to_string();
        }
        if let Some(ip) = tun_ip {
            self.tun_ip.store(pack_ip(ip), Ordering::Release);
        }
        if let Some(gw) = tun_gw {
            self.tun_gw.store(pack_ip(gw), Ordering::Release);
        }
        if mtu >= 576 && mtu <= 9000 {
            self.mtu.store(mtu, Ordering::Release);
        }
    }

    pub fn adapter_name(&self) -> String { self.adapter_name.read().unwrap().clone() }
    pub fn tun_ip(&self) -> [u8; 4] { unpack_ip(self.tun_ip.load(Ordering::Acquire)) }
    pub fn tun_gw(&self) -> [u8; 4] { unpack_ip(self.tun_gw.load(Ordering::Acquire)) }
    pub fn mtu(&self) -> u32 { self.mtu.load(Ordering::Acquire) }
    pub fn set_tun_if_index(&self, idx: u32) { self.tun_if_index.store(idx, Ordering::Release); }
    pub fn tun_if_index(&self) -> u32 { self.tun_if_index.load(Ordering::Acquire) }

    pub fn set_dns(&self, primary: Option<[u8; 4]>, secondary: Option<[u8; 4]>, enable_nrpt: bool) {
        if let Some(p) = primary {
            self.primary_dns.store(pack_ip(p), Ordering::Release);
        }
        if let Some(s) = secondary {
            self.secondary_dns.store(pack_ip(s), Ordering::Release);
        } else if primary.is_some() {
            self.secondary_dns.store(0, Ordering::Release);
        }
        self.enable_nrpt.store(enable_nrpt, Ordering::Release);
        self.dns_epoch.fetch_add(1, Ordering::AcqRel);
    }

    pub fn primary_dns(&self) -> [u8; 4] { unpack_ip(self.primary_dns.load(Ordering::Acquire)) }
    pub fn secondary_dns(&self) -> Option<[u8; 4]> {
        let v = self.secondary_dns.load(Ordering::Acquire);
        if v == 0 { None } else { Some(unpack_ip(v)) }
    }
    pub fn enable_nrpt(&self) -> bool { self.enable_nrpt.load(Ordering::Acquire) }
    pub fn dns_epoch(&self) -> u64 { self.dns_epoch.load(Ordering::Acquire) }
    pub fn set_ipv6_block(&self, block: bool) { self.ipv6_block.store(block, Ordering::Release); }
    pub fn ipv6_block(&self) -> bool { self.ipv6_block.load(Ordering::Acquire) }
    pub fn set_udp_timeout_secs(&self, secs: u32) {
        self.udp_timeout_ms.store((secs.clamp(10, 600) as u64) * 1000, Ordering::Release);
    }
    pub fn udp_timeout_ms(&self) -> u64 { self.udp_timeout_ms.load(Ordering::Acquire) }
    pub fn set_socks_addr(&self, addr: SocketAddr) { *self.socks_addr.write().unwrap() = addr; }
    pub fn socks_addr(&self) -> SocketAddr { *self.socks_addr.read().unwrap() }

    pub fn set_physical_if(&self, if_index: u32, gw: Option<&str>, lan_ip: Option<[u8; 4]>) {
        self.phys_if_index.store(if_index, Ordering::Release);
        if let Some(ip) = lan_ip {
            self.phys_lan_ip.store(pack_ip(ip), Ordering::Release);
        }
        if let Some(g) = gw.filter(|s| !s.trim().is_empty()) {
            *self.phys_gateway.write().unwrap() = g.trim().to_string();
        }
    }

    pub fn phys_if_index(&self) -> u32 {
        self.phys_if_index.load(Ordering::Acquire)
    }

    pub fn phys_lan_ip(&self) -> [u8; 4] {
        unpack_ip(self.phys_lan_ip.load(Ordering::Acquire))
    }

    pub fn phys_gateway(&self) -> String {
        self.phys_gateway.read().unwrap().clone()
    }

    pub fn add_custom_bypass_ip(&self, ip: [u8; 4]) -> bool {
        let mut guard = self.custom_bypass_ips.write().unwrap();
        if !guard.contains(&ip) {
            guard.push(ip);
            return true;
        }
        false
    }

    pub fn clear_custom_bypass_ips(&self) {
        self.custom_bypass_ips.write().unwrap().clear();
    }

    pub fn custom_bypass_ips(&self) -> Vec<[u8; 4]> {
        self.custom_bypass_ips.read().unwrap().clone()
    }
}
