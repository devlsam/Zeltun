use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use super::adapter::CREATE_NO_WINDOW;
use crate::config::{fmt_ipv4, live_config};

pub fn run_quiet(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

pub fn enforce_nrpt_and_smhnr(dns_servers: &str) {
    run_quiet(
        "reg",
        &[
            "add",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v",
            "DisableSmartNameResolution",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    );

    let reg_path = r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\ByptunRule";
    run_quiet("reg", &["add", reg_path, "/v", "Name", "/t", "REG_MULTI_SZ", "/d", ".", "/f"]);
    run_quiet("reg", &["add", reg_path, "/v", "GenericDNSServers", "/t", "REG_MULTI_SZ", "/d", dns_servers, "/f"]);
    run_quiet("reg", &["add", reg_path, "/v", "ConfigOptions", "/t", "REG_DWORD", "/d", "8", "/f"]);
    run_quiet("reg", &["add", reg_path, "/v", "Version", "/t", "REG_DWORD", "/d", "2", "/f"]);
}

pub fn revert_nrpt_and_smhnr() {
    run_quiet(
        "reg",
        &[
            "delete",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\ByptunRule",
            "/f",
        ],
    );
    run_quiet(
        "reg",
        &[
            "delete",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v",
            "DisableSmartNameResolution",
            "/f",
        ],
    );
}

/// Applies Primary/Secondary DNS to the named adapter and updates NRPT + Windows DNS cache.
pub fn apply_adapter_dns_and_nrpt(adapter_name: &str) {
    let cfg = live_config();
    let p_dns = fmt_ipv4(cfg.primary_dns());
    let s_dns_opt = cfg.secondary_dns().map(fmt_ipv4);
    let name_arg = format!("name={}", adapter_name);

    run_quiet(
        "netsh",
        &["interface", "ip", "set", "dns", &name_arg, "static", &p_dns, "primary", "validate=no"],
    );
    if let Some(ref s_dns) = s_dns_opt {
        run_quiet(
            "netsh",
            &["interface", "ip", "add", "dns", &name_arg, s_dns, "index=2", "validate=no"],
        );
    }

    if cfg.enable_nrpt() {
        enforce_nrpt_and_smhnr(&p_dns);
    } else {
        revert_nrpt_and_smhnr();
    }
    run_quiet("ipconfig", &["/flushdns"]);
}

pub fn install_ipv4_two_halves(tun_if_index: u32, tun_gw: &str) {
    let tun_if_str = format!("{}", tun_if_index);
    run_quiet("route", &["add", "0.0.0.0", "mask", "128.0.0.0", tun_gw, "metric", "1", "if", &tun_if_str]);
    run_quiet("route", &["add", "128.0.0.0", "mask", "128.0.0.0", tun_gw, "metric", "1", "if", &tun_if_str]);
}

pub fn remove_ipv4_two_halves(tun_gw: &str) {
    run_quiet("route", &["delete", "0.0.0.0", "mask", "128.0.0.0", tun_gw]);
    run_quiet("route", &["delete", "128.0.0.0", "mask", "128.0.0.0", tun_gw]);
}

pub fn install_ipv6_blackhole() {
    run_quiet("route", &["add", "::/1", "::", "if", "1", "metric", "5"]);
    run_quiet("route", &["add", "8000::/1", "::", "if", "1", "metric", "5"]);
}

pub fn remove_ipv6_blackhole() {
    run_quiet("route", &["delete", "::/1"]);
    run_quiet("route", &["delete", "8000::/1"]);
}

pub fn install_two_halves_routes(tun_if_index: u32, tun_gw: &str) {
    install_ipv4_two_halves(tun_if_index, tun_gw);
    if live_config().ipv6_block() {
        install_ipv6_blackhole();
    }
}

pub fn remove_two_halves_routes(tun_gw: &str) {
    remove_ipv4_two_halves(tun_gw);
    remove_ipv6_blackhole();
}

pub fn install_bypass_route(ip_str: &str, gw: &str, if_idx: u32) {
    if if_idx > 0 {
        let if_str = format!("{}", if_idx);
        run_quiet("route", &["add", ip_str, "mask", "255.255.255.255", gw, "metric", "1", "if", &if_str]);
    } else {
        run_quiet("route", &["add", ip_str, "mask", "255.255.255.255", gw, "metric", "1"]);
    }
}

pub fn remove_bypass_route(ip_str: &str, gw: &str) {
    run_quiet("route", &["delete", ip_str, "mask", "255.255.255.255", gw]);
}
