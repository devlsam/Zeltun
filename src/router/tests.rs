use super::*;
use crate::config::{OPTIONS, OPT_BYPASS_LAN};
use crate::packet::{calc_ipv4_checksum, calc_tcp_checksum, rewrite_inbound_tcp, rewrite_outbound_tcp};

#[test]
fn test_phase3_split_decision() {
    let router = SplitRouter::new(SplitMode::Include, &["chrome.exe", "discord"]);
    let my_pid = 99999;
    router.set_self_pid_for_test(my_pid);
    router.set_proxy_pid(88888);

    let public_dst = [8, 8, 8, 8];
    let proxy_server_ip = [63, 177, 179, 170];

    // 1. Verify Anti-Loopback on Self PID & Proxy PID
    assert_eq!(router.decide(my_pid, b"byptun.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(88888, b"xray.exe", public_dst), RouteAction::Direct);

    // 2. Verify Known Proxy Executables
    assert_eq!(router.decide(1234, b"sing-box.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(5678, b"clash.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(9012, b"hysteria.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(3456, b"naive.exe", public_dst), RouteAction::Direct);

    // 3. Verify Server Bypass IP is ALWAYS Direct
    router.add_bypassed_ip(proxy_server_ip);
    assert_eq!(router.decide(1001, b"chrome.exe", proxy_server_ip), RouteAction::Direct);

    // 4. Mode 1 (Include): only chrome.exe and discord.exe should be Proxy
    assert_eq!(router.decide(1001, b"chrome.exe", public_dst), RouteAction::Proxy);
    assert_eq!(router.decide(1002, b"discord.exe", public_dst), RouteAction::Proxy);
    assert_eq!(router.decide(1003, b"firefox.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(1004, b"system", public_dst), RouteAction::Direct);

    // 5. Live rule update: switch to Mode 2 (Exclude) with chrome.exe excluded
    router.set_rules(SplitMode::Exclude, "chrome.exe,telegram.exe");
    assert_eq!(router.get_mode(), SplitMode::Exclude);

    // In Exclude mode: chrome & telegram are Direct, all others are Proxy
    assert_eq!(router.decide(1001, b"chrome.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(1005, b"telegram.exe", public_dst), RouteAction::Direct);
    assert_eq!(router.decide(1002, b"discord.exe", public_dst), RouteAction::Proxy);
    assert_eq!(router.decide(1003, b"firefox.exe", public_dst), RouteAction::Proxy);

    // 6. Switch to Mode 0 (Global): all non-loopback apps should be Proxy
    router.set_rules(SplitMode::Global, "");
    assert_eq!(router.get_mode(), SplitMode::Global);
    assert_eq!(router.decide(1001, b"chrome.exe", public_dst), RouteAction::Proxy);
    assert_eq!(router.decide(1003, b"firefox.exe", public_dst), RouteAction::Proxy);
    assert_eq!(router.decide(my_pid, b"byptun.exe", public_dst), RouteAction::Direct);
}

#[test]
fn test_lan_bypass_does_not_break_wintun_nat() {
    OPTIONS.set_options(OPT_BYPASS_LAN, 1360);

    // Wintun adapter configured on a 10.x.x.x network
    let tun_ip = [10, 0, 0, 2];
    let tun_gw = [10, 0, 0, 1];
    let router = SplitRouter::new_with_tun(SplitMode::Global, &[], tun_ip, tun_gw);

    // Real LAN destinations MUST be routed Direct
    assert_eq!(router.decide(100, b"chrome.exe", [192, 168, 1, 1]), RouteAction::Direct);
    assert_eq!(router.decide(100, b"chrome.exe", [10, 1, 2, 3]), RouteAction::Direct);
    assert_eq!(router.decide(100, b"chrome.exe", [172, 20, 0, 5]), RouteAction::Direct);

    // Public Internet destinations MUST be routed to Proxy in Global mode
    assert_eq!(router.decide(100, b"chrome.exe", [1, 1, 1, 1]), RouteAction::Proxy);
    assert_eq!(router.decide(100, b"chrome.exe", [142, 250, 180, 14]), RouteAction::Proxy);

    // Local redirect NAT test: packets destined to local listener on 10.x.x.x
    let client_port = 52345u16;
    let listen_port = 30000u16;
    let orig_dst_ip = [1, 1, 1, 1];
    let orig_dst_port = 443u16;

    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&tun_ip);
    pkt[16..20].copy_from_slice(&orig_dst_ip);
    let ip_csum = calc_ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&client_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&orig_dst_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02; // SYN
    let tcp_csum = calc_tcp_checksum(tun_ip, orig_dst_ip, &pkt[20..40]);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    // 1. Outbound rewrite
    let out_ok = rewrite_outbound_tcp(&mut pkt, tun_ip, tun_gw, listen_port);
    assert!(out_ok);
    assert_eq!(&pkt[12..16], &tun_gw);
    assert_eq!(&pkt[16..20], &tun_ip);
    assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), listen_port);

    // 2. Return packet from local listener: src=tun_ip:listen_port, dst=tun_gw:client_port
    let mut ret_pkt = vec![0u8; 40];
    ret_pkt[0] = 0x45;
    ret_pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    ret_pkt[8] = 64;
    ret_pkt[9] = 6;
    ret_pkt[12..16].copy_from_slice(&tun_ip);
    ret_pkt[16..20].copy_from_slice(&tun_gw);
    let ret_ip_csum = calc_ipv4_checksum(&ret_pkt[0..20]);
    ret_pkt[10..12].copy_from_slice(&ret_ip_csum.to_be_bytes());

    ret_pkt[20..22].copy_from_slice(&listen_port.to_be_bytes());
    ret_pkt[22..24].copy_from_slice(&client_port.to_be_bytes());
    ret_pkt[32] = 0x50;
    ret_pkt[33] = 0x12; // SYN-ACK
    let ret_tcp_csum = calc_tcp_checksum(tun_ip, tun_gw, &ret_pkt[20..40]);
    ret_pkt[36..38].copy_from_slice(&ret_tcp_csum.to_be_bytes());

    // Inbound rewrite MUST restore original dst IP & port, unhindered by LAN bypass
    let in_ok = rewrite_inbound_tcp(&mut ret_pkt, tun_ip, tun_gw, listen_port);
    assert!(in_ok);
    assert_eq!(&ret_pkt[12..16], &orig_dst_ip);
    assert_eq!(&ret_pkt[16..20], &tun_ip);
    assert_eq!(u16::from_be_bytes([ret_pkt[20], ret_pkt[21]]), orig_dst_port);
    assert_eq!(u16::from_be_bytes([ret_pkt[22], ret_pkt[23]]), client_port);
}

#[test]
fn test_split_path_normalization_and_anti_poisoning() {
    OPTIONS.set_options(OPT_BYPASS_LAN, 1360);
    let router = SplitRouter::new(
        SplitMode::Include,
        &[r#""C:\Users\gamer\AppData\Local\Discord\app-1.0\Discord.exe""#],
    );
    let v0 = router.rule_version();
    assert_eq!(router.decide(100, b"discord.exe", [1, 1, 1, 1]), RouteAction::Proxy);

    // Iranian ISP poisoned DNS IP (10.10.34.0/24) must NOT bypass via LAN rule
    assert!(!is_lan_ip([10, 10, 34, 35]));
    assert!(is_lan_ip([10, 1, 2, 3]));
    assert_eq!(router.decide(100, b"discord.exe", [10, 10, 34, 35]), RouteAction::Proxy);

    router.set_proxy_pid(5555);
    assert_eq!(router.rule_version(), v0 + 1);
    router.add_bypassed_ip([20, 30, 40, 50]);
    assert_eq!(router.rule_version(), v0 + 2);
    router.set_rules(SplitMode::Include, "chrome.exe; C:\\Games\\cs2.exe\nvalorant");
    assert_eq!(router.rule_version(), v0 + 3);

    assert_eq!(router.decide(101, b"cs2.exe", [8, 8, 8, 8]), RouteAction::Proxy);
    assert_eq!(router.decide(102, b"valorant.exe", [8, 8, 8, 8]), RouteAction::Proxy);
    assert_eq!(router.decide(103, b"discord.exe", [8, 8, 8, 8]), RouteAction::Direct);
}
