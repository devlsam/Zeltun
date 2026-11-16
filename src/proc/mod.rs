pub mod cache;
pub mod image;
pub mod tcp_table;

#[cfg(test)]
mod tests;

pub use cache::{NAME_MAX_LEN, PORT_COUNT, PROC_CACHE_SETS, PROC_CACHE_WAYS, ProcCacheSlot};

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct ProcessResolver {
    port_table: Box<[AtomicU64; PORT_COUNT]>,
    udp_port_table: Box<[AtomicU64; PORT_COUNT]>,
    tcp_table_buf: Mutex<Vec<u8>>,
    udp_table_buf: Mutex<Vec<u8>>,
    last_table_fetch_ms: AtomicI64,
    last_tcp_miss_ms: AtomicI64,
    last_udp_miss_ms: AtomicI64,
    proc_cache: Mutex<[[ProcCacheSlot; PROC_CACHE_WAYS]; PROC_CACHE_SETS]>,
    start_time: Instant,
}

impl ProcessResolver {
    pub fn new() -> Self {
        let port_table = cache::allocate_port_table();
        let udp_port_table = cache::allocate_port_table();

        Self {
            port_table,
            udp_port_table,
            tcp_table_buf: Mutex::new(vec![0u8; 65536]),
            udp_table_buf: Mutex::new(vec![0u8; 65536]),
            last_table_fetch_ms: AtomicI64::new(-1000),
            last_tcp_miss_ms: AtomicI64::new(-1000),
            last_udp_miss_ms: AtomicI64::new(-1000),
            proc_cache: Mutex::new([[ProcCacheSlot::empty(); PROC_CACHE_WAYS]; PROC_CACHE_SETS]),
            start_time: Instant::now(),
        }
    }

    #[inline(always)]
    fn now_secs(&self) -> u32 {
        self.start_time.elapsed().as_secs() as u32
    }

    #[inline(always)]
    fn now_u32_ms(&self) -> u32 {
        (self.start_time.elapsed().as_millis() as u32 & 0x7fffffff).max(1)
    }

    #[inline(always)]
    fn now_millis(&self) -> i64 {
        self.start_time.elapsed().as_millis() as i64
    }

    pub fn clear_port_table(&self) {
        for slot in self.port_table.iter() {
            slot.store(0, Ordering::Release);
        }
        for slot in self.udp_port_table.iter() {
            slot.store(0, Ordering::Release);
        }
        self.last_table_fetch_ms.store(-1000, Ordering::Release);
        self.last_tcp_miss_ms.store(-1000, Ordering::Release);
        self.last_udp_miss_ms.store(-1000, Ordering::Release);
    }

    pub fn set_port_pid_for_test(&self, port: u16, pid: u32) {
        let val = (pid as u64) | ((self.now_u32_ms() as u64) << 32);
        self.port_table[port as usize].store(val, Ordering::Release);
        self.udp_port_table[port as usize].store(val, Ordering::Release);
    }

    pub fn set_proc_name_for_test(&self, pid: u32, name: &str) {
        let set_idx = ((pid >> 2) & ((PROC_CACHE_SETS - 1) as u32)) as usize;
        let mut cache = self.proc_cache.lock().unwrap();
        let now = self.now_secs();

        let bytes = name.as_bytes();
        let mut name_arr = [0u8; NAME_MAX_LEN];
        let len = bytes.len().min(NAME_MAX_LEN);
        name_arr[..len].copy_from_slice(&bytes[..len]);

        cache[set_idx][0] = ProcCacheSlot {
            pid,
            name_len: len as u8,
            name: name_arr,
            cached_secs: now,
        };
    }

    /// Fast lock-free cached port lookup (returns `None` on miss without syscalling).
    #[inline]
    pub fn lookup_cached_port_fast(&self, port: u16) -> Option<(u32, [u8; NAME_MAX_LEN], usize)> {
        self.lookup_cached_port(&self.port_table, port, self.now_u32_ms(), 100)
    }

    /// Resolves executable name and PID for an active local TCP port without blocking sleeps.
    pub fn resolve_process_by_port_once(&self, port: u16) -> Option<(u32, [u8; NAME_MAX_LEN], usize)> {
        let now_ms = self.now_u32_ms();
        if let Some(hit) = self.lookup_cached_port(&self.port_table, port, now_ms, 100) {
            return Some(hit);
        }

        let mut buf = self.tcp_table_buf.lock().unwrap();
        if let Some(hit) = self.lookup_cached_port(&self.port_table, port, now_ms, 100) {
            return Some(hit);
        }

        let now_i64 = self.now_millis();
        if now_i64 - self.last_tcp_miss_ms.load(Ordering::Acquire) < 15 {
            return None;
        }

        self.port_table[port as usize].store(0, Ordering::Release);
        let stamp = self.now_u32_ms();
        tcp_table::refresh_tcp_table_locked(&self.port_table, &mut buf, stamp);
        self.last_table_fetch_ms.store(self.now_millis(), Ordering::Release);
        let res = self.lookup_cached_port(&self.port_table, port, stamp, 0);
        if res.is_none() {
            self.last_tcp_miss_ms.store(self.now_millis(), Ordering::Release);
        }
        res
    }

    /// Resolves executable name and PID for an active local TCP port, with one 2ms sync retry.
    pub fn resolve_process_by_port(&self, port: u16) -> Option<(u32, [u8; NAME_MAX_LEN], usize)> {
        if let Some(hit) = self.resolve_process_by_port_once(port) {
            return Some(hit);
        }
        std::thread::sleep(Duration::from_millis(2));
        self.resolve_process_by_port_once(port)
    }

    /// Resolves executable name and PID for an active local UDP port without sleeping.
    pub fn resolve_udp_process_by_port(&self, port: u16) -> Option<(u32, [u8; NAME_MAX_LEN], usize)> {
        let now_ms = self.now_u32_ms();
        if let Some(hit) = self.lookup_cached_port(&self.udp_port_table, port, now_ms, 100) {
            return Some(hit);
        }
        let mut buf = self.udp_table_buf.lock().unwrap();
        if let Some(hit) = self.lookup_cached_port(&self.udp_port_table, port, now_ms, 100) {
            return Some(hit);
        }
        let now_i64 = self.now_millis();
        if now_i64 - self.last_udp_miss_ms.load(Ordering::Acquire) < 15 {
            return None;
        }
        self.udp_port_table[port as usize].store(0, Ordering::Release);
        let stamp = self.now_u32_ms();
        tcp_table::refresh_udp_table_locked(&self.udp_port_table, &mut buf, stamp);
        let res = self.lookup_cached_port(&self.udp_port_table, port, stamp, 0);
        if res.is_none() {
            self.last_udp_miss_ms.store(self.now_millis(), Ordering::Release);
        }
        res
    }

    #[inline]
    fn lookup_cached_port(
        &self,
        table: &[AtomicU64; PORT_COUNT],
        port: u16,
        now_ms: u32,
        max_age_ms: u32,
    ) -> Option<(u32, [u8; NAME_MAX_LEN], usize)> {
        let slot_val = table[port as usize].load(Ordering::Acquire);
        let pid = (slot_val & 0xffffffff) as u32;
        let updated_ms = ((slot_val >> 32) & 0x7fffffff) as u32;
        if pid > 0 && updated_ms > 0 && now_ms.saturating_sub(updated_ms) <= max_age_ms {
            return Some(
                self.get_process_image(pid)
                    .map_or((pid, [0u8; NAME_MAX_LEN], 0), |(n, l)| (pid, n, l)),
            );
        }
        None
    }

    #[inline]
    pub fn get_process_remote_ips(&self, pid: u32) -> Vec<[u8; 4]> {
        tcp_table::get_process_remote_ips_internal(&self.port_table, &self.tcp_table_buf, pid, self.now_u32_ms())
    }

    #[inline]
    pub fn get_process_image(&self, pid: u32) -> Option<([u8; NAME_MAX_LEN], usize)> {
        image::get_process_image_internal(&self.proc_cache, pid, self.now_secs())
    }
}

pub static RESOLVER: std::sync::LazyLock<ProcessResolver> =
    std::sync::LazyLock::new(ProcessResolver::new);
