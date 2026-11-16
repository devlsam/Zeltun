use std::ffi::c_char;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use crate::config::{fmt_ipv4, live_config, parse_ipv4, set_last_error};
use crate::driver::routes::remove_bypass_route;

use super::diag_hooks::cstr_to_opt;
use super::{ENGINE, ROUTER, RUNNING};

fn parse_opt_ip(raw: Option<&str>, label: &str) -> Result<Option<[u8; 4]>, i32> {
    let Some(s) = raw.filter(|s| !s.trim().is_empty()) else { return Ok(None); };
    parse_ipv4(s).map(Some).ok_or_else(|| {
        set_last_error(format!("Invalid {} IP '{}'", label, s));
        -1
    })
}

/// Configures virtual TUN adapter name, subnet IPv4/gateway, and MTU (576..9000).
#[no_mangle]
pub extern "C" fn zeltun_configure_adapter(
    adapter_name: *const c_char,
    tun_ip: *const c_char,
    tun_gw: *const c_char,
    mtu: u32,
) -> i32 {
    let name = unsafe { cstr_to_opt(adapter_name) };
    let ip_s = unsafe { cstr_to_opt(tun_ip) };
    let gw_s = unsafe { cstr_to_opt(tun_gw) };

    let Ok(parsed_ip) = parse_opt_ip(ip_s.as_deref(), "tun_ip") else { return -1; };
    let Ok(parsed_gw) = parse_opt_ip(gw_s.as_deref(), "tun_gw") else { return -1; };

    live_config().set_adapter(name.as_deref(), parsed_ip, parsed_gw, mtu);
    0
}

/// Configures Primary/Secondary IPv4 DNS resolvers and NRPT enforcement, applying live if running.
#[no_mangle]
pub extern "C" fn zeltun_set_dns(primary_dns: *const c_char, secondary_dns: *const c_char, enable_nrpt: u8) -> i32 {
    let p_s = unsafe { cstr_to_opt(primary_dns) };
    let s_s = unsafe { cstr_to_opt(secondary_dns) };

    let Ok(p_ip) = parse_opt_ip(p_s.as_deref(), "primary DNS") else { return -1; };
    let Ok(s_ip) = parse_opt_ip(s_s.as_deref(), "secondary DNS") else { return -1; };

    live_config().set_dns(p_ip, s_ip, enable_nrpt != 0);
    if RUNNING.load(Ordering::Acquire) {
        if let Ok(lock) = ENGINE.lock() {
            if let Some(eng) = lock.as_ref() { eng.refresh_dns(); }
        }
    }
    0
}

/// Tunes IPv6 anti-leak blackhole (0=block, 1=allow/system), strict split anti-leak, and UDP timeout (10..600s).
#[no_mangle]
pub extern "C" fn zeltun_set_tun_behavior(ipv6_mode: u8, strict_anti_leak: u8, udp_timeout_secs: u32) -> i32 {
    let cfg = live_config();
    cfg.set_ipv6_block(ipv6_mode == 0);
    if udp_timeout_secs > 0 { cfg.set_udp_timeout_secs(udp_timeout_secs); }
    crate::config::OPTIONS.set_flag(crate::config::OPT_STRICT_ANTI_LEAK, strict_anti_leak != 0);

    if RUNNING.load(Ordering::Acquire) {
        if let Ok(lock) = ENGINE.lock() {
            if let Some(eng) = lock.as_ref() { eng.refresh_ipv6(); }
        }
    }
    0
}

/// Hot-swaps physical adapter index, gateway, and LAN IP without tearing down TUN.
#[no_mangle]
pub extern "C" fn zeltun_update_physical_if(phys_if_index: u32, gateway: *const c_char, lan_ip: *const c_char) -> i32 {
    let gw_s = unsafe { cstr_to_opt(gateway) }.unwrap_or_default();
    let lan_s = unsafe { cstr_to_opt(lan_ip) };
    let parsed_lan = lan_s.as_deref().and_then(parse_ipv4).unwrap_or([0, 0, 0, 0]);

    if RUNNING.load(Ordering::Acquire) {
        if let Ok(mut lock) = ENGINE.lock() {
            if let Some(eng) = lock.as_mut() {
                eng.update_physical_if(phys_if_index, &gw_s, parsed_lan);
                return 0;
            }
        }
    }
    live_config().set_physical_if(
        phys_if_index,
        if gw_s.is_empty() { None } else { Some(gw_s.as_str()) },
        if parsed_lan == [0, 0, 0, 0] { None } else { Some(parsed_lan) },
    );
    0
}

/// Hot-swaps upstream SOCKS5 endpoint (e.g. "127.0.0.1:10808") without restarting Wintun.
#[no_mangle]
pub extern "C" fn zeltun_set_socks(socks_addr: *const c_char) -> i32 {
    let Some(s) = (unsafe { cstr_to_opt(socks_addr) }) else {
        set_last_error("Null socks_addr passed to zeltun_set_socks");
        return -1;
    };
    let Ok(parsed) = s.trim().parse::<SocketAddr>() else {
        set_last_error(format!("Invalid SOCKS5 SocketAddr '{}'", s));
        return -1;
    };
    live_config().set_socks_addr(parsed);
    0
}

#[no_mangle]
pub extern "C" fn zeltun_add_bypass_ip(ip_cstr: *const c_char) -> i32 {
    let Some(s) = (unsafe { cstr_to_opt(ip_cstr) }) else { return -1; };
    let Some(ip) = parse_ipv4(&s) else {
        set_last_error(format!("Invalid bypass IP '{}'", s));
        return -1;
    };
    live_config().add_custom_bypass_ip(ip);
    if RUNNING.load(Ordering::Acquire) {
        if let Ok(lock) = ENGINE.lock() {
            if let Some(eng) = lock.as_ref() { eng.add_bypass_ip_runtime(ip); }
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn zeltun_clear_bypass_ips() -> i32 {
    live_config().clear_custom_bypass_ips();
    if let Some(r) = ROUTER.get() {
        let gw = live_config().phys_gateway();
        for ip in r.get_bypassed_ips() { remove_bypass_route(&fmt_ipv4(ip), &gw); }
        r.clear_bypassed_ips();
    }
    0
}
