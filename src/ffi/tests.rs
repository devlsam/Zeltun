use super::*;
use std::ffi::CString;
use std::sync::Mutex;

static FFI_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_phase5_ffi_lifecycle() {
    let _guard = FFI_TEST_LOCK.lock().unwrap();
    let socks_str = CString::new("127.0.0.1:10808").unwrap();

    // 1. Start engine via FFI
    let ret = byptun_start(socks_str.as_ptr(), 0, 0x400000);
    assert_eq!(ret, 0, "byptun_start must return 0");
    assert!(RUNNING.load(Ordering::Acquire), "Engine must be running");

    // 2. Set Split Rules (Mode 1 = Include: chrome.exe, telegram.exe)
    let apps_include = CString::new("chrome.exe,telegram.exe").unwrap();
    let ret = byptun_set_rules(1, apps_include.as_ptr());
    assert_eq!(ret, 0, "byptun_set_rules must return 0");

    // 2b. Test byptun_set_options live update
    let opt_ret = byptun_set_options(63, 1360);
    assert_eq!(opt_ret, 0);
    assert_eq!(crate::config::OPTIONS.get_flags(), 63);
    assert_eq!(crate::config::OPTIONS.get_mss(), 1360);

    let router = ROUTER.get().unwrap();
    assert_eq!(router.get_mode(), SplitMode::Include);
    assert_eq!(router.decide(1001, b"chrome.exe", [8, 8, 8, 8]), crate::router::RouteAction::Proxy);
    assert_eq!(router.decide(1002, b"edge.exe", [8, 8, 8, 8]), crate::router::RouteAction::Direct);

    // 3. Record mock stats & fetch via FFI
    RX_BYTES.store(1048576, Ordering::Release);
    TX_BYTES.store(2097152, Ordering::Release);
    ACTIVE_CONNS.store(15, Ordering::Release);

    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut conns = 0u32;
    let stat_ret = byptun_get_stats(&mut rx, &mut tx, &mut conns);
    assert_eq!(stat_ret, 0);
    assert_eq!(rx, 1048576);
    assert_eq!(tx, 2097152);
    assert_eq!(conns, 15);

    // 4. Change rules live without restarting (Mode 2 = Exclude: firefox.exe)
    let apps_exclude = CString::new("firefox.exe").unwrap();
    let ret = byptun_set_rules(2, apps_exclude.as_ptr());
    assert_eq!(ret, 0);
    assert_eq!(router.get_mode(), SplitMode::Exclude);
    assert_eq!(router.decide(1003, b"firefox.exe", [8, 8, 8, 8]), crate::router::RouteAction::Direct);
    assert_eq!(router.decide(1001, b"chrome.exe", [8, 8, 8, 8]), crate::router::RouteAction::Proxy);

    // 5. Stop engine via FFI
    let stop_ret = byptun_stop();
    assert_eq!(stop_ret, 0);
    assert!(!RUNNING.load(Ordering::Acquire));

    // Reset router back to Global so other parallel unit tests are unaffected
    let _ = byptun_set_rules(0, std::ptr::null());
}

#[test]
fn test_zeltun_ffi_hooks_and_stats_layout() {
    let _guard = FFI_TEST_LOCK.lock().unwrap();
    use crate::config::{live_config, OPTIONS, OPT_STRICT_ANTI_LEAK};

    assert_eq!(std::mem::size_of::<ZeltunStatsEx>(), 56);

    let name = CString::new("BYP-TUN").unwrap();
    let ip = CString::new("198.18.0.2").unwrap();
    let gw = CString::new("198.18.0.1").unwrap();
    assert_eq!(zeltun_configure_adapter(name.as_ptr(), ip.as_ptr(), gw.as_ptr(), 1420), 0);

    let cfg = live_config();
    assert_eq!(cfg.adapter_name(), "BYP-TUN");
    assert_eq!(cfg.tun_ip(), [198, 18, 0, 2]);
    assert_eq!(cfg.tun_gw(), [198, 18, 0, 1]);
    assert_eq!(cfg.mtu(), 1420);

    let p_dns = CString::new("178.22.122.100").unwrap();
    let s_dns = CString::new("185.51.200.2").unwrap();
    let prev_epoch = cfg.dns_epoch();
    assert_eq!(zeltun_set_dns(p_dns.as_ptr(), s_dns.as_ptr(), 0), 0);
    assert_eq!(cfg.primary_dns(), [178, 22, 122, 100]);
    assert_eq!(cfg.secondary_dns(), Some([185, 51, 200, 2]));
    assert!(!cfg.enable_nrpt());
    assert!(cfg.dns_epoch() > prev_epoch);

    let bad_dns = CString::new("not-an-ip").unwrap();
    assert_eq!(zeltun_set_dns(bad_dns.as_ptr(), std::ptr::null(), 1), -1);
    let mut err_buf = [0i8; 256];
    let err_len = zeltun_get_last_error(err_buf.as_mut_ptr(), err_buf.len() as u32);
    assert!(err_len > 0);

    assert_eq!(zeltun_set_tun_behavior(1, 1, 120), 0);
    assert!(!cfg.ipv6_block());
    assert_eq!(cfg.udp_timeout_ms(), 120_000);
    assert!(OPTIONS.is_enabled(OPT_STRICT_ANTI_LEAK));

    let phy_gw = CString::new("10.0.0.1").unwrap();
    let phy_lan = CString::new("10.0.0.42").unwrap();
    assert_eq!(zeltun_update_physical_if(17, phy_gw.as_ptr(), phy_lan.as_ptr()), 0);
    assert_eq!(cfg.phys_if_index(), 17);
    assert_eq!(cfg.phys_gateway(), "10.0.0.1");
    assert_eq!(cfg.phys_lan_ip(), [10, 0, 0, 42]);

    let new_socks = CString::new("127.0.0.1:20808").unwrap();
    assert_eq!(zeltun_set_socks(new_socks.as_ptr()), 0);
    assert_eq!(cfg.socks_addr().to_string(), "127.0.0.1:20808");

    let srv_ip = CString::new("93.184.216.34").unwrap();
    assert_eq!(zeltun_add_bypass_ip(srv_ip.as_ptr()), 0);
    assert!(cfg.custom_bypass_ips().contains(&[93, 184, 216, 34]));
    assert_eq!(zeltun_clear_bypass_ips(), 0);
    assert!(cfg.custom_bypass_ips().is_empty());

    let mut stats = ZeltunStatsEx {
        struct_size: 0,
        is_running: 99,
        rx_bytes: 0,
        tx_bytes: 0,
        proxy_bytes: 0,
        direct_bytes: 0,
        dropped_packets: 0,
        active_tcp_conns: 0,
        active_udp_sessions: 0,
    };
    assert_eq!(zeltun_get_stats_ex(&mut stats), 0);
    assert_eq!(stats.struct_size, 56);

    let mut log_buf = [0i8; 256];
    let mut lvl = 0u8;
    assert!(zeltun_poll_log(log_buf.as_mut_ptr(), log_buf.len() as u32, &mut lvl) > 0);

    // Reset global state cleanly for other tests
    let def_name = CString::new("BYPTUN-CORE").unwrap();
    let def_ip = CString::new("198.19.0.2").unwrap();
    let def_gw = CString::new("198.19.0.1").unwrap();
    let _ = zeltun_configure_adapter(def_name.as_ptr(), def_ip.as_ptr(), def_gw.as_ptr(), 1500);
    let d1 = CString::new("1.1.1.1").unwrap();
    let d2 = CString::new("8.8.8.8").unwrap();
    let _ = zeltun_set_dns(d1.as_ptr(), d2.as_ptr(), 1);
    assert_eq!(zeltun_set_tun_behavior(0, 0, 60), 0);
    let def_socks = CString::new("127.0.0.1:10808").unwrap();
    let _ = zeltun_set_socks(def_socks.as_ptr());
}

#[test]
fn test_strict_anti_leak_blocks_direct_dns_fallback() {
    let _guard = FFI_TEST_LOCK.lock().unwrap();
    use crate::config::{DEFAULT_OPTS, DEFAULT_TCP_MSS, OPTIONS};
    use crate::dns::DnsResolver;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mock_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_port = mock_sock.local_addr().unwrap().port();
        // Even if primary DNS is a valid UDP server, SOCKS is dead (port 1) and we force strict mode.
        let p_dns = CString::new("127.0.0.1").unwrap();
        assert_eq!(zeltun_set_dns(p_dns.as_ptr(), std::ptr::null(), 1), 0);
        let dead_socks = CString::new("127.0.0.1:1").unwrap();
        assert_eq!(zeltun_set_socks(dead_socks.as_ptr()), 0);
        assert_eq!(zeltun_set_tun_behavior(0, 1, 60), 0);

        let resolver = DnsResolver::new_live(tokio::runtime::Handle::current());
        let query = [
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            0x00, 0x01, 0x00, 0x01,
        ];
        // Note: RCODE in byte 3 & 0x0f must be 2 (SERVFAIL) because direct UDP fallback is suppressed!
        let _ = mock_port;
        let resp = resolver.resolve(&query).await.unwrap();
        assert_eq!(resp[3] & 0x0f, 2, "Strict anti-leak must return SERVFAIL instead of direct ISP DNS fallback");
    });

    // Restore clean defaults
    let d1 = CString::new("1.1.1.1").unwrap();
    let d2 = CString::new("8.8.8.8").unwrap();
    let _ = zeltun_set_dns(d1.as_ptr(), d2.as_ptr(), 1);
    let _ = zeltun_set_tun_behavior(0, 0, 60);
    let def_socks = CString::new("127.0.0.1:10808").unwrap();
    let _ = zeltun_set_socks(def_socks.as_ptr());
    OPTIONS.set_options(DEFAULT_OPTS, DEFAULT_TCP_MSS);
}
