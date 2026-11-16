use std::sync::atomic::AtomicU64;

pub const PORT_COUNT: usize = 65536;
pub const PROC_CACHE_SETS: usize = 256;
pub const PROC_CACHE_WAYS: usize = 4;
pub const NAME_MAX_LEN: usize = 64;

#[derive(Clone, Copy)]
pub struct ProcCacheSlot {
    pub pid: u32,
    pub name_len: u8,
    pub name: [u8; NAME_MAX_LEN],
    pub cached_secs: u32,
}

impl ProcCacheSlot {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            name_len: 0,
            name: [0u8; NAME_MAX_LEN],
            cached_secs: 0,
        }
    }
}

pub fn allocate_port_table() -> Box<[AtomicU64; PORT_COUNT]> {
    unsafe {
        let layout = std::alloc::Layout::new::<[AtomicU64; PORT_COUNT]>();
        let ptr = std::alloc::alloc_zeroed(layout) as *mut [AtomicU64; PORT_COUNT];
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(ptr)
    }
}
