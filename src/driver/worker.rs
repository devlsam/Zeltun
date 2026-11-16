use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::session::WintunSession;
use crate::config::{OPTIONS, OPT_BLOCK_QUIC, OPT_CLEAN_DNS, OPT_MSS_CLAMP};
use crate::dns::DnsResolver;
use crate::ffi::{RX_BYTES, TX_BYTES};
use crate::packet::{
    build_icmp_port_unreachable, calc_icmp_checksum, calc_ipv4_checksum, clamp_tcp_mss,
    rewrite_inbound_tcp, rewrite_outbound_tcp,
};
use crate::udp::UdpManager;

pub fn start_packet_worker(
    session: Arc<WintunSession>,
    running: Arc<AtomicBool>,
    tun_ip: [u8; 4],
    tun_gw: [u8; 4],
    listen_port: u16,
    dns_resolver: Arc<DnsResolver>,
    udp_manager: Arc<UdpManager>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let read_event = session.read_event();

        while running.load(Ordering::Acquire) {
            let mut processed = false;
            for _ in 0..64 {
                let Some(pkt) = session.receive_packet() else { break };
                processed = true;
                let pkt_len = pkt.len();
                RX_BYTES.fetch_add(pkt_len as u64, Ordering::Relaxed);

                if pkt_len >= 20 && (pkt[0] >> 4) == 4 {
                    let ihl = ((pkt[0] & 0x0f) * 4) as usize;
                    let proto = pkt[9];

                    if proto == 6 && pkt_len >= ihl + 20 {
                        let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap();
                        let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap();
                        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);

                        // 1. Inbound return packet from local redirect listener MUST BE REWRITTEN FIRST
                        if src_ip == tun_ip && dst_ip == tun_gw && src_port == listen_port {
                            if (pkt[ihl + 13] & 0x02) != 0 && OPTIONS.is_enabled(OPT_MSS_CLAMP) {
                                clamp_tcp_mss(pkt, OPTIONS.get_mss());
                            }
                            if rewrite_inbound_tcp(pkt, tun_ip, tun_gw, listen_port) {
                                if session.inject_packet(pkt) {
                                    TX_BYTES.fetch_add(pkt_len as u64, Ordering::Relaxed);
                                }
                            }
                        } else if src_ip == tun_ip && dst_ip != tun_ip && dst_ip != tun_gw {
                            if (pkt[ihl + 13] & 0x02) != 0 && OPTIONS.is_enabled(OPT_MSS_CLAMP) {
                                clamp_tcp_mss(pkt, OPTIONS.get_mss());
                            }
                            if rewrite_outbound_tcp(pkt, tun_ip, tun_gw, listen_port) {
                                if session.inject_packet(pkt) {
                                    TX_BYTES.fetch_add(pkt_len as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    } else if proto == 17 && pkt_len >= ihl + 8 {
                        let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap();
                        let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap();
                        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                        let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;

                        if src_ip == tun_ip && udp_len >= 8 && pkt_len >= ihl + udp_len {
                            let payload = &pkt[ihl + 8..ihl + udp_len];
                            let is_quic_long = dst_port == 443
                                && payload.len() >= 64
                                && (payload[0] & 0xc0) == 0xc0
                                && OPTIONS.is_enabled(OPT_BLOCK_QUIC);
                            if is_quic_long {
                                let mut icmp_buf = [0u8; 64];
                                if let Some(icmp_len) = build_icmp_port_unreachable(pkt, &mut icmp_buf) {
                                    if session.inject_packet(&icmp_buf[..icmp_len]) {
                                        TX_BYTES.fetch_add(icmp_len as u64, Ordering::Relaxed);
                                    }
                                }
                            } else if dst_port == 53 && OPTIONS.is_enabled(OPT_CLEAN_DNS) {
                                dns_resolver.handle_and_respond(&session, src_ip, dst_ip, src_port, dst_port, payload);
                            } else {
                                udp_manager.handle_outbound(&session, src_port, dst_ip, dst_port, payload);
                            }
                        }
                    } else if proto == 1 && pkt_len >= ihl + 8 && pkt[ihl] == 8 {
                        let orig_src: [u8; 4] = pkt[12..16].try_into().unwrap();
                        pkt.copy_within(16..20, 12);
                        pkt[16..20].copy_from_slice(&orig_src);
                        pkt[10..12].copy_from_slice(&[0, 0]);
                        let ip_csum = calc_ipv4_checksum(&pkt[..ihl]);
                        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                        pkt[ihl] = 0;
                        pkt[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
                        let icmp_csum = calc_icmp_checksum(&pkt[ihl..pkt_len]);
                        pkt[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());
                        if session.inject_packet(pkt) {
                            TX_BYTES.fetch_add(pkt_len as u64, Ordering::Relaxed);
                        }
                    }
                }
                session.release_receive_packet(pkt);
            }

            if !processed {
                if !read_event.is_null() {
                    unsafe { WaitForSingleObject(read_event, 25); }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    })
}
