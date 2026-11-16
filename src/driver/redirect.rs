use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

use crate::config::{live_config, OPTIONS, OPT_SNI_SNIFF};
use crate::ffi::{ACTIVE_CONNS, DIRECT_BYTES, DROPPED_PKTS, PROXY_BYTES, ROUTER};
use crate::packet::SESSIONS;
use crate::proc::RESOLVER;
use crate::relay::{dial_direct_tcp, dial_socks5_tcp, dial_socks5_tcp_domain, parse_tls_sni, relay_tcp_counted};
use crate::router::{RouteAction, SplitMode};

async fn resolve_tcp_action(src_port: u16, dst_ip: [u8; 4]) -> RouteAction {
    let Some(router) = ROUTER.get() else {
        return RouteAction::Proxy;
    };
    if router.is_bypassed_ip(dst_ip) {
        return RouteAction::Direct;
    }
    let is_global = router.get_mode() == SplitMode::Global;
    let proc_info = match RESOLVER.resolve_process_by_port_once(src_port) {
        Some(hit) => Some(hit),
        None if !is_global => {
            tokio::time::sleep(Duration::from_millis(2)).await;
            RESOLVER.resolve_process_by_port_once(src_port)
        }
        None => None,
    };
    let (pid, name_bytes, name_len) = proc_info.unwrap_or((0, [0u8; 64], 0));
    router.decide(pid, &name_bytes[..name_len], dst_ip)
}

#[inline(never)]
async fn peek_sni_domain(client_conn: &TcpStream) -> Option<String> {
    let mut peek_buf = Box::new([0u8; 2048]);
    let peek_res = tokio::time::timeout(
        Duration::from_millis(15),
        client_conn.peek(&mut peek_buf[..]),
    )
    .await;
    if let Ok(Ok(n)) = peek_res {
        if let Some(domain) = parse_tls_sni(&peek_buf[..n]) {
            return Some(domain.to_string());
        }
    }
    None
}

pub fn start_tcp_redirect_router_live(listener: TcpListener, running: Arc<AtomicBool>) {
    start_tcp_redirect_router_inner(listener, running, true, "127.0.0.1:10808".to_string(), 0, [0; 4]);
}

pub fn start_tcp_redirect_router(
    listener: TcpListener,
    running: Arc<AtomicBool>,
    socks_target: String,
    phys_idx: u32,
    phys_lan_ip: [u8; 4],
) {
    start_tcp_redirect_router_inner(listener, running, false, socks_target, phys_idx, phys_lan_ip);
}

fn start_tcp_redirect_router_inner(
    listener: TcpListener,
    running: Arc<AtomicBool>,
    use_live: bool,
    socks_target: String,
    fixed_idx: u32,
    fixed_lan_ip: [u8; 4],
) {
    let fixed_socks: SocketAddr = socks_target.parse().unwrap_or_else(|_| "127.0.0.1:10808".parse().unwrap());
    tokio::spawn(async move {
        while running.load(Ordering::Acquire) {
            let Ok((client_conn, client_addr)) = listener.accept().await else { break };
            let src_port = client_addr.port();
            tokio::spawn(async move {
                ACTIVE_CONNS.fetch_add(1, Ordering::Relaxed);
                let session_info = SESSIONS.load(src_port);
                if let Some((dst_ip, dst_port)) = session_info {
                    let action = resolve_tcp_action(src_port, dst_ip).await;

                    let (parsed_socks, phys_idx, phys_lan_ip) = if use_live {
                        let cfg = live_config();
                        (cfg.socks_addr(), cfg.phys_if_index(), cfg.phys_lan_ip())
                    } else {
                        (fixed_socks, fixed_idx, fixed_lan_ip)
                    };

                    match action {
                        RouteAction::Proxy => {
                            let detected_domain = if dst_port == 443 && OPTIONS.is_enabled(OPT_SNI_SNIFF) {
                                peek_sni_domain(&client_conn).await
                            } else {
                                None
                            };

                            let upstream = if let Some(domain) = detected_domain {
                                dial_socks5_tcp_domain(parsed_socks, &domain, dst_port, phys_idx, phys_lan_ip).await
                            } else {
                                dial_socks5_tcp(parsed_socks, dst_ip, dst_port, phys_idx, phys_lan_ip).await
                            };
                            if let Ok(up) = upstream {
                                let _ = relay_tcp_counted(client_conn, up, &PROXY_BYTES).await;
                            } else {
                                DROPPED_PKTS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        RouteAction::Direct => {
                            let addr = SocketAddr::from((dst_ip, dst_port));
                            if let Ok(up) = dial_direct_tcp(addr, phys_idx, phys_lan_ip).await {
                                let _ = relay_tcp_counted(client_conn, up, &DIRECT_BYTES).await;
                            }
                        }
                        RouteAction::Drop => {
                            DROPPED_PKTS.fetch_add(1, Ordering::Relaxed);
                        }
                    };
                }
                ACTIVE_CONNS.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
}

