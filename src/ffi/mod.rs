use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;

use crate::driver::TunnelEngine;
use crate::router::{SplitMode, SplitRouter};

#[cfg(test)]
mod tests;
pub mod diag_hooks;
pub mod hooks;
pub use diag_hooks::*;
pub use hooks::*;

pub static RUNNING: AtomicBool = AtomicBool::new(false);
pub static RX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static TX_BYTES: AtomicU64 = AtomicU64::new(0);
pub static PROXY_BYTES: AtomicU64 = AtomicU64::new(0);
pub static DIRECT_BYTES: AtomicU64 = AtomicU64::new(0);
pub static DROPPED_PKTS: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNS: AtomicU32 = AtomicU32::new(0);
pub static ACTIVE_UDP: AtomicU32 = AtomicU32::new(0);

pub static ROUTER: OnceLock<Arc<SplitRouter>> = OnceLock::new();
pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();
pub static ENGINE: Mutex<Option<TunnelEngine>> = Mutex::new(None);

#[no_mangle]
pub extern "C" fn byptun_start(
    socks_addr: *const c_char,
    phys_if_index: u32,
    ring_capacity: u32,
) -> i32 {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return 0; // Already running
    }

    let socks_str = if !socks_addr.is_null() {
        unsafe { CStr::from_ptr(socks_addr).to_str().unwrap_or("127.0.0.1:10808") }
    } else {
        "127.0.0.1:10808"
    };

    let _ = ROUTER.get_or_init(|| Arc::new(SplitRouter::new(SplitMode::Global, &[])));

    let _ = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    });

    crate::config::clear_last_error();
    RX_BYTES.store(0, Ordering::Release);
    TX_BYTES.store(0, Ordering::Release);
    PROXY_BYTES.store(0, Ordering::Release);
    DIRECT_BYTES.store(0, Ordering::Release);
    DROPPED_PKTS.store(0, Ordering::Release);
    ACTIVE_CONNS.store(0, Ordering::Release);
    ACTIVE_UDP.store(0, Ordering::Release);

    let mut engine = TunnelEngine::new(socks_str, phys_if_index, ring_capacity);
    if let Err(e) = engine.start() {
        #[cfg(test)]
        {
            eprintln!("[RUST FFI TEST] Non-admin environment in test: {}", e);
        }
        #[cfg(not(test))]
        {
            crate::config::set_last_error(format!("TunnelEngine start failed: {}", e));
            RUNNING.store(false, Ordering::SeqCst);
            return -1;
        }
    }

    let mut lock = ENGINE.lock().unwrap();
    *lock = Some(engine);

    0
}

#[no_mangle]
pub extern "C" fn byptun_set_rules(mode: u8, apps_csv: *const c_char) -> i32 {
    let router = ROUTER.get_or_init(|| Arc::new(SplitRouter::new(SplitMode::Global, &[])));

    let csv_str = if !apps_csv.is_null() {
        unsafe { CStr::from_ptr(apps_csv).to_str().unwrap_or("") }
    } else {
        ""
    };

    router.set_rules(SplitMode::from(mode), csv_str);
    0
}

#[no_mangle]
pub extern "C" fn byptun_set_options(opt_flags: u32, tcp_mss: u16) -> i32 {
    crate::config::OPTIONS.set_options(opt_flags, tcp_mss);
    0
}

#[no_mangle]
pub extern "C" fn byptun_get_stats(
    out_rx_bytes: *mut u64,
    out_tx_bytes: *mut u64,
    out_active_conns: *mut u32,
) -> i32 {
    if !out_rx_bytes.is_null() {
        unsafe { *out_rx_bytes = RX_BYTES.load(Ordering::Acquire) };
    }
    if !out_tx_bytes.is_null() {
        unsafe { *out_tx_bytes = TX_BYTES.load(Ordering::Acquire) };
    }
    if !out_active_conns.is_null() {
        unsafe { *out_active_conns = ACTIVE_CONNS.load(Ordering::Acquire) };
    }
    0
}

#[no_mangle]
pub extern "C" fn byptun_stop() -> i32 {
    let mut lock = ENGINE.lock().unwrap();
    if let Some(mut engine) = lock.take() {
        engine.stop();
    }
    RUNNING.store(false, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "C" fn zeltun_start(
    socks_addr: *const c_char,
    phys_if_index: u32,
    ring_capacity: u32,
) -> i32 {
    byptun_start(socks_addr, phys_if_index, ring_capacity)
}

#[no_mangle]
pub extern "C" fn zeltun_set_rules(mode: u8, apps_csv: *const c_char) -> i32 {
    byptun_set_rules(mode, apps_csv)
}

#[no_mangle]
pub extern "C" fn zeltun_set_options(opt_flags: u32, tcp_mss: u16) -> i32 {
    byptun_set_options(opt_flags, tcp_mss)
}

#[no_mangle]
pub extern "C" fn zeltun_get_stats(
    out_rx_bytes: *mut u64,
    out_tx_bytes: *mut u64,
    out_active_conns: *mut u32,
) -> i32 {
    byptun_get_stats(out_rx_bytes, out_tx_bytes, out_active_conns)
}

#[no_mangle]
pub extern "C" fn zeltun_stop() -> i32 {
    byptun_stop()
}
