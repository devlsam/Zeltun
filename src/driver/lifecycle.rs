use std::sync::{Arc, Mutex};
use super::adapter::{assign_ip_to_adapter, CREATE_NO_WINDOW};
use super::routes::*;
use crate::config::{fmt_ipv4, live_config, push_log, LOG_INFO};
use crate::ffi::ROUTER;
use crate::proc::RESOLVER;
use crate::router::is_private_ip;

/// Applies interface metric, IPv4 address, MTU, firewall allow rule, and DNS/NRPT.
pub fn setup_adapter_interface(adapter_name: &str, tun_if_index: u32, tun_ip: [u8; 4], mtu: u32) {
    let _ = assign_ip_to_adapter(tun_if_index, tun_ip, 16);
    let tun_ip_str = fmt_ipv4(tun_ip);
    let name_arg = format!("name={}", adapter_name);
    let addr_arg = format!("address={}", tun_ip_str);
    let mtu_arg = format!("mtu={}", mtu);
    let fw_rule = format!("{}-IN", adapter_name);
    let subnet = format!("{}.{}.0.0/16", tun_ip[0], tun_ip[1]);

    run_quiet("netsh", &["interface", "ipv4", "set", "interface", adapter_name, "metric=1", "dadtransmits=0", "store=active"]);
    run_quiet("netsh", &["interface", "ipv4", "set", "address", &name_arg, "source=static", &addr_arg, "mask=255.255.0.0", "store=active"]);
    run_quiet("netsh", &["interface", "ipv4", "set", "subinterface", adapter_name, &mtu_arg, "store=active"]);
    apply_adapter_dns_and_nrpt(adapter_name);

    run_quiet("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={}", fw_rule)]);
    run_quiet("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name={}", fw_rule), "dir=in", "action=allow", &format!("remoteip={}", subnet), "enable=yes"]);
    let _ = CREATE_NO_WINDOW;
}

/// Syncs proxy process remote IPs and user-configured bypass IPs into both SplitRouter and OS /32 routes.
pub fn sync_bypass_routes(
    socks_port: u16,
    phys_gw: &str,
    phys_if: u32,
    bypassed: &Arc<Mutex<Vec<[u8; 4]>>>,
) {
    let mut targets: Vec<[u8; 4]> = live_config().custom_bypass_ips();

    if let Some((proxy_pid, _, _)) = RESOLVER.resolve_process_by_port(socks_port) {
        if let Some(r) = ROUTER.get() {
            r.set_proxy_pid(proxy_pid);
        }
        let is_in_process = proxy_pid == std::process::id();
        if !is_in_process || targets.is_empty() {
            for ip in RESOLVER.get_process_remote_ips(proxy_pid) {
                if !is_private_ip(ip) && !crate::relay::is_direct_dialed_ip(ip) {
                    targets.push(ip);
                }
            }
        }
    }

    for ip in targets {
        if is_private_ip(ip) {
            continue;
        }
        if let Some(r) = ROUTER.get() {
            if r.add_bypassed_ip(ip) {
                let ip_s = fmt_ipv4(ip);
                install_bypass_route(&ip_s, phys_gw, phys_if);
                if let Ok(mut g) = bypassed.lock() {
                    if !g.contains(&ip) {
                        g.push(ip);
                    }
                }
            }
        }
    }
}

/// Moves tracked /32 bypass routes onto a new physical gateway/interface during network handoff.
pub fn migrate_bypass_routes(old_gw: &str, new_gw: &str, new_if: u32, bypassed: &Arc<Mutex<Vec<[u8; 4]>>>) {
    if let Ok(g) = bypassed.lock() {
        for &ip in g.iter() {
            let ip_s = fmt_ipv4(ip);
            remove_bypass_route(&ip_s, old_gw);
            install_bypass_route(&ip_s, new_gw, new_if);
        }
    }
    push_log(LOG_INFO, format!("Migrated bypass routes: {} -> {} (if={})", old_gw, new_gw, new_if));
}

pub fn cleanup_stale_tun_state(adapter_name: &str, tun_gw: &str) {
    remove_two_halves_routes(tun_gw);
    if !adapter_name.is_empty() {
        run_quiet("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={}-IN", adapter_name)]);
    }
    run_quiet("netsh", &["advfirewall", "firewall", "delete", "rule", "name=BYPTUN-CORE-IN"]);
    revert_nrpt_and_smhnr();
}

