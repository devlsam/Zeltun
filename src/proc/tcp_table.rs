use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::cache::PORT_COUNT;
use crate::config::live_config;

const AF_INET_U32: u32 = AF_INET as u32;
const AF_INET6_U32: u32 = AF_INET6 as u32;
const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
const UDP_TABLE_OWNER_PID: i32 = 1;

const TCP_STATE_CLOSED: u32 = 1;
const TCP_STATE_TIME_WAIT: u32 = 11;
const TCP_STATE_DELETE_TCB: u32 = 12;
const TUN_PRIO_BIT: u64 = 1u64 << 63;

fn fetch_ip_table(buf: &mut Vec<u8>, is_tcp: bool, family: u32) -> bool {
    let mut size = buf.len() as u32;
    let call = |b: &mut Vec<u8>, sz: &mut u32| unsafe {
        if is_tcp {
            GetExtendedTcpTable(b.as_mut_ptr() as _, sz, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(b.as_mut_ptr() as _, sz, 0, family, UDP_TABLE_OWNER_PID, 0)
        }
    };
    let mut res = call(buf, &mut size);
    if res == ERROR_INSUFFICIENT_BUFFER as WIN32_ERROR {
        buf.resize(size as usize, 0);
        res = call(buf, &mut size);
    }
    res == 0 && buf.len() >= 4
}

#[inline(always)]
fn store_port(table: &[AtomicU64; PORT_COUNT], port: u16, pid: u32, stamp: u64, is_tun_prio: bool) {
    if is_tun_prio {
        table[port as usize].store((pid as u64) | (stamp << 32) | TUN_PRIO_BIT, Ordering::Release);
    } else {
        let cur = table[port as usize].load(Ordering::Relaxed);
        let same_stamp = (cur & (0x7fffffffu64 << 32)) == (stamp << 32);
        if !same_stamp || (cur & TUN_PRIO_BIT) == 0 {
            table[port as usize].store((pid as u64) | (stamp << 32), Ordering::Release);
        }
    }
}

pub fn refresh_tcp_table_locked(port_table: &[AtomicU64; PORT_COUNT], buf: &mut Vec<u8>, now_ms: u32) {
    let stamp = (now_ms & 0x7fffffff) as u64;

    if fetch_ip_table(buf, true, AF_INET6_U32) {
        let num = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut off = 4;
        const ROW6: usize = 56;
        for _ in 0..num {
            if off + ROW6 > buf.len() { break; }
            let state = u32::from_le_bytes(buf[off + 48..off + 52].try_into().unwrap());
            let row_pid = u32::from_le_bytes(buf[off + 52..off + 56].try_into().unwrap());
            if row_pid > 0 && state != TCP_STATE_CLOSED && state != TCP_STATE_TIME_WAIT && state != TCP_STATE_DELETE_TCB {
                let port = u16::from_be_bytes([buf[off + 20], buf[off + 21]]);
                store_port(port_table, port, row_pid, stamp, false);
            }
            off += ROW6;
        }
    }

    let cfg = live_config();
    let tun_ip = cfg.tun_ip();
    let tun_gw = cfg.tun_gw();

    if fetch_ip_table(buf, true, AF_INET_U32) {
        let num = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut off = 4;
        const ROW4: usize = 24;
        for _ in 0..num {
            if off + ROW4 > buf.len() { break; }
            let state = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let local_ip: [u8; 4] = buf[off + 4..off + 8].try_into().unwrap();
            let remote_ip: [u8; 4] = buf[off + 12..off + 16].try_into().unwrap();
            let row_pid = u32::from_le_bytes(buf[off + 20..off + 24].try_into().unwrap());
            if row_pid > 0
                && state != TCP_STATE_CLOSED
                && state != TCP_STATE_TIME_WAIT
                && state != TCP_STATE_DELETE_TCB
                && remote_ip != tun_gw
                && remote_ip != [198, 19, 0, 1]
            {
                let port = u16::from_be_bytes([buf[off + 8], buf[off + 9]]);
                let is_tun = local_ip == tun_ip || local_ip == [198, 19, 0, 2];
                store_port(port_table, port, row_pid, stamp, is_tun);
            }
            off += ROW4;
        }
    }
}

pub fn refresh_udp_table_locked(udp_port_table: &[AtomicU64; PORT_COUNT], buf: &mut Vec<u8>, now_ms: u32) {
    let stamp = (now_ms & 0x7fffffff) as u64;

    if fetch_ip_table(buf, false, AF_INET6_U32) {
        let num = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut off = 4;
        const ROW6: usize = 28;
        for _ in 0..num {
            if off + ROW6 > buf.len() { break; }
            let row_pid = u32::from_le_bytes(buf[off + 24..off + 28].try_into().unwrap());
            if row_pid > 0 {
                let port = u16::from_be_bytes([buf[off + 20], buf[off + 21]]);
                store_port(udp_port_table, port, row_pid, stamp, false);
            }
            off += ROW6;
        }
    }

    let cfg = live_config();
    let tun_ip = cfg.tun_ip();

    if fetch_ip_table(buf, false, AF_INET_U32) {
        let num = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut off = 4;
        const ROW4: usize = 12;
        for _ in 0..num {
            if off + ROW4 > buf.len() { break; }
            let local_ip: [u8; 4] = buf[off..off + 4].try_into().unwrap();
            let row_pid = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
            if row_pid > 0 {
                let port = u16::from_be_bytes([buf[off + 4], buf[off + 5]]);
                let is_tun = local_ip == tun_ip || local_ip == [198, 19, 0, 2] || local_ip == [0, 0, 0, 0];
                store_port(udp_port_table, port, row_pid, stamp, is_tun);
            }
            off += ROW4;
        }
    }
}

pub fn get_process_remote_ips_internal(
    port_table: &[AtomicU64; PORT_COUNT],
    table_buf: &Mutex<Vec<u8>>,
    pid: u32,
    now_sec: u32,
) -> Vec<[u8; 4]> {
    if pid == 0 {
        return Vec::new();
    }
    let mut buf = table_buf.lock().unwrap();
    refresh_tcp_table_locked(port_table, &mut buf, now_sec);

    if buf.len() < 4 {
        return Vec::new();
    }

    let num_entries = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut offset = 4;
    const ROW_SIZE: usize = 24;
    let mut result = Vec::new();

    for _ in 0..num_entries {
        if offset + ROW_SIZE > buf.len() {
            break;
        }

        let state = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        let row_pid = u32::from_le_bytes([
            buf[offset + 20],
            buf[offset + 21],
            buf[offset + 22],
            buf[offset + 23],
        ]);

        if row_pid == pid
            && state != TCP_STATE_CLOSED
            && state != TCP_STATE_TIME_WAIT
            && state != TCP_STATE_DELETE_TCB
        {
            let r_ip = [buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]];
            if r_ip[0] != 127 && r_ip[0] != 0 && r_ip[0] != 169 && !result.contains(&r_ip) {
                result.push(r_ip);
            }
        }

        offset += ROW_SIZE;
    }

    result
}
