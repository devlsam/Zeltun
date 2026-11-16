use std::ffi::{c_char, CStr};
use std::sync::atomic::Ordering;

use crate::config::{
    get_last_error_str, live_config, poll_log_entry, set_log_callback, ZeltunLogCallback,
};
use crate::driver::lifecycle::cleanup_stale_tun_state;

use super::{
    ACTIVE_CONNS, ACTIVE_UDP, DIRECT_BYTES, DROPPED_PKTS, PROXY_BYTES, RUNNING, RX_BYTES, TX_BYTES,
};

#[repr(C)]
pub struct ZeltunStatsEx {
    pub struct_size: u32,
    pub is_running: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub proxy_bytes: u64,
    pub direct_bytes: u64,
    pub dropped_packets: u64,
    pub active_tcp_conns: u32,
    pub active_udp_sessions: u32,
}

pub(crate) unsafe fn cstr_to_opt(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() { None } else { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

unsafe fn write_cstr_buf(s: &str, buf: *mut c_char, buf_len: u32) -> i32 {
    if buf.is_null() || buf_len == 0 { return -1; }
    let bytes = s.as_bytes();
    let n = bytes.len().min((buf_len as usize).saturating_sub(1));
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
    *((buf as *mut u8).add(n)) = 0;
    n as i32
}

#[no_mangle]
pub extern "C" fn zeltun_get_stats_ex(out: *mut ZeltunStatsEx) -> i32 {
    if out.is_null() { return -1; }
    let st = unsafe { &mut *out };
    st.struct_size = std::mem::size_of::<ZeltunStatsEx>() as u32;
    st.is_running = u32::from(RUNNING.load(Ordering::Acquire));
    st.rx_bytes = RX_BYTES.load(Ordering::Acquire);
    st.tx_bytes = TX_BYTES.load(Ordering::Acquire);
    st.proxy_bytes = PROXY_BYTES.load(Ordering::Acquire);
    st.direct_bytes = DIRECT_BYTES.load(Ordering::Acquire);
    st.dropped_packets = DROPPED_PKTS.load(Ordering::Acquire);
    st.active_tcp_conns = ACTIVE_CONNS.load(Ordering::Acquire);
    st.active_udp_sessions = ACTIVE_UDP.load(Ordering::Acquire);
    0
}

#[no_mangle]
pub extern "C" fn zeltun_cleanup_stale(adapter_name: *const c_char, tun_gw: *const c_char) -> i32 {
    let ad = unsafe { cstr_to_opt(adapter_name) }.filter(|s| !s.is_empty()).unwrap_or_else(|| live_config().adapter_name());
    let gw = unsafe { cstr_to_opt(tun_gw) }.filter(|s| !s.is_empty()).unwrap_or_else(|| crate::config::fmt_ipv4(live_config().tun_gw()));
    cleanup_stale_tun_state(&ad, &gw);
    0
}

#[no_mangle]
pub extern "C" fn zeltun_set_log_callback(cb: Option<ZeltunLogCallback>) -> i32 {
    set_log_callback(cb);
    0
}

#[no_mangle]
pub extern "C" fn zeltun_poll_log(buf: *mut c_char, buf_len: u32, out_level: *mut u8) -> i32 {
    let Some((lvl, msg)) = poll_log_entry() else { return 0; };
    if !out_level.is_null() { unsafe { *out_level = lvl }; }
    unsafe { write_cstr_buf(&msg, buf, buf_len) }
}

#[no_mangle]
pub extern "C" fn zeltun_get_last_error(buf: *mut c_char, buf_len: u32) -> i32 {
    let err = get_last_error_str();
    unsafe { write_cstr_buf(&err, buf, buf_len) }
}

