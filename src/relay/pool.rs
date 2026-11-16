use std::sync::Mutex;
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const BUFFER_SIZE: usize = 32768; // 32 KB
pub const MAX_RELAY_BUFS: usize = 32; // 32 * 32KB = 1 MB absolute hard ceiling

pub struct BufferPool {
    bufs: Mutex<Vec<Box<[u8; BUFFER_SIZE]>>>,
}

impl BufferPool {
    pub fn new(capacity: usize) -> Self {
        let mut v = Vec::with_capacity(capacity);
        for _ in 0..capacity.min(8) {
            v.push(Box::new([0u8; BUFFER_SIZE]));
        }
        Self { bufs: Mutex::new(v) }
    }

    #[inline]
    pub fn acquire(&self) -> Box<[u8; BUFFER_SIZE]> {
        if let Ok(mut g) = self.bufs.lock() {
            if let Some(buf) = g.pop() {
                return buf;
            }
        }
        Box::new([0u8; BUFFER_SIZE])
    }

    #[inline]
    pub fn release(&self, buf: Box<[u8; BUFFER_SIZE]>) {
        if let Ok(mut g) = self.bufs.lock() {
            if g.len() < MAX_RELAY_BUFS {
                g.push(buf);
            }
        }
    }
}

pub static BUFFER_POOL: std::sync::LazyLock<BufferPool> =
    std::sync::LazyLock::new(|| BufferPool::new(MAX_RELAY_BUFS));

/// Returns the exact physical working-set memory used by the current process in megabytes.
pub fn get_working_set_mb() -> f64 {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let h = GetCurrentProcess();
        if K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb) != 0 {
            return pmc.WorkingSetSize as f64 / (1024.0 * 1024.0);
        }
    }
    0.0
}
