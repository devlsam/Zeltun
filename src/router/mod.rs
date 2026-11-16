pub mod rules;

#[cfg(test)]
mod tests;

pub use rules::*;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::RwLock;

use crate::config::{pack_ip, unpack_ip};

pub struct SplitRouter {
    mode: AtomicU8,
    rule_version: AtomicU32,
    self_pid: AtomicU32,
    proxy_pid: AtomicU32,
    app_hashes: RwLock<HashSet<u64>>,
    bypassed_ips: RwLock<HashSet<[u8; 4]>>,
    fast_bypass_ips: [AtomicU32; 16],
    fast_bypass_len: AtomicU32,
    tun_ip: AtomicU32,
    tun_gw: AtomicU32,
}

impl SplitRouter {
    pub fn new(mode: SplitMode, apps: &[&str]) -> Self {
        Self::new_with_tun(mode, apps, [198, 19, 0, 2], [198, 19, 0, 1])
    }

    pub fn new_with_tun(mode: SplitMode, apps: &[&str], tun_ip: [u8; 4], tun_gw: [u8; 4]) -> Self {
        let mut hashes = HashSet::new();
        for &app in apps {
            let h = normalize_and_hash_app(app);
            if h > 0 {
                hashes.insert(h);
            }
        }

        Self {
            mode: AtomicU8::new(mode as u8),
            rule_version: AtomicU32::new(1),
            self_pid: AtomicU32::new(std::process::id()),
            proxy_pid: AtomicU32::new(0),
            app_hashes: RwLock::new(hashes),
            bypassed_ips: RwLock::new(HashSet::new()),
            fast_bypass_ips: std::array::from_fn(|_| AtomicU32::new(0)),
            fast_bypass_len: AtomicU32::new(0),
            tun_ip: AtomicU32::new(pack_ip(tun_ip)),
            tun_gw: AtomicU32::new(pack_ip(tun_gw)),
        }
    }

    pub fn set_tun_endpoints(&self, tun_ip: [u8; 4], tun_gw: [u8; 4]) {
        self.tun_ip.store(pack_ip(tun_ip), Ordering::Release);
        self.tun_gw.store(pack_ip(tun_gw), Ordering::Release);
    }

    #[inline(always)]
    pub fn rule_version(&self) -> u32 { self.rule_version.load(Ordering::Acquire) }
    pub fn set_self_pid_for_test(&self, pid: u32) { self.self_pid.store(pid, Ordering::Release); }
    pub fn set_proxy_pid(&self, pid: u32) {
        if self.proxy_pid.swap(pid, Ordering::AcqRel) != pid { self.rule_version.fetch_add(1, Ordering::AcqRel); }
    }
    pub fn get_mode(&self) -> SplitMode { SplitMode::from(self.mode.load(Ordering::Acquire)) }

    fn sync_fast_bypass(&self, guard: &HashSet<[u8; 4]>) {
        self.fast_bypass_len.store(17, Ordering::Release);
        if guard.len() <= 16 {
            for (slot, ip) in self.fast_bypass_ips.iter().zip(guard.iter()) {
                slot.store(u32::from_ne_bytes(*ip), Ordering::Relaxed);
            }
            self.fast_bypass_len.store(guard.len() as u32, Ordering::Release);
        }
    }

    pub fn add_bypassed_ip(&self, ip: [u8; 4]) -> bool {
        let mut guard = self.bypassed_ips.write().unwrap();
        let inserted = guard.insert(ip);
        if inserted {
            self.sync_fast_bypass(&guard);
            self.rule_version.fetch_add(1, Ordering::AcqRel);
        }
        inserted
    }

    pub fn remove_bypassed_ip(&self, ip: [u8; 4]) -> bool {
        let mut guard = self.bypassed_ips.write().unwrap();
        let removed = guard.remove(&ip);
        if removed {
            self.sync_fast_bypass(&guard);
            self.rule_version.fetch_add(1, Ordering::AcqRel);
        }
        removed
    }

    pub fn clear_bypassed_ips(&self) {
        let mut guard = self.bypassed_ips.write().unwrap();
        if !guard.is_empty() {
            guard.clear();
            self.sync_fast_bypass(&guard);
            self.rule_version.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[inline(always)]
    pub fn is_bypassed_ip(&self, ip: [u8; 4]) -> bool {
        let len = self.fast_bypass_len.load(Ordering::Acquire) as usize;
        if len == 0 { return false; }
        if len <= 16 {
            let target = u32::from_ne_bytes(ip);
            return self.fast_bypass_ips[..len].iter().any(|s| s.load(Ordering::Relaxed) == target);
        }
        self.bypassed_ips.read().unwrap().contains(&ip)
    }

    pub fn get_bypassed_ips(&self) -> Vec<[u8; 4]> { self.bypassed_ips.read().unwrap().iter().copied().collect() }

    pub fn set_rules(&self, mode: SplitMode, apps_csv: &str) {
        let mut new_hashes = HashSet::new();
        for item in apps_csv.split([',', ';', '\n', '\r']) {
            let item = item.trim();
            if !item.is_empty() {
                let h = normalize_and_hash_app(item);
                if h > 0 {
                    new_hashes.insert(h);
                }
            }
        }

        {
            let mut write_guard = self.app_hashes.write().unwrap();
            *write_guard = new_hashes;
        }
        self.mode.store(mode as u8, Ordering::Release);
        self.rule_version.fetch_add(1, Ordering::AcqRel);
    }

    pub fn decide(&self, pid: u32, app_name_bytes: &[u8], dst_ip: [u8; 4]) -> RouteAction {
        if self.is_bypassed_ip(dst_ip) {
            return RouteAction::Direct;
        }
        let self_p = self.self_pid.load(Ordering::Acquire);
        if pid > 0 && pid == self_p {
            return RouteAction::Direct;
        }
        let proxy_p = self.proxy_pid.load(Ordering::Acquire);
        if proxy_p > 0 && pid == proxy_p {
            return RouteAction::Direct;
        }
        if is_known_proxy_bytes(app_name_bytes) {
            return RouteAction::Direct;
        }
        let tun_ip = unpack_ip(self.tun_ip.load(Ordering::Relaxed));
        let tun_gw = unpack_ip(self.tun_gw.load(Ordering::Relaxed));
        if crate::config::OPTIONS.is_enabled(crate::config::OPT_BYPASS_LAN)
            && is_lan_ip(dst_ip)
            && dst_ip != tun_ip
            && dst_ip != tun_gw
        {
            return RouteAction::Direct;
        }

        let mode = self.get_mode();
        if mode == SplitMode::Global {
            return RouteAction::Proxy;
        }

        let app_hash = fnv1a_hash(app_name_bytes);
        let in_list = {
            let guard = self.app_hashes.read().unwrap();
            guard.contains(&app_hash)
        };

        match (mode, in_list) {
            (SplitMode::Include, true) | (SplitMode::Exclude, false) | (SplitMode::Global, _) => {
                RouteAction::Proxy
            }
            (SplitMode::Include, false) | (SplitMode::Exclude, true) => RouteAction::Direct,
        }
    }
}
