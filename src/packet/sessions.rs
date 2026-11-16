use std::sync::atomic::{AtomicU64, Ordering};

pub const PORT_COUNT: usize = 65536;

/// Lock-free NAT session table mapping client ephemeral port (0..65535)
/// to original destination IP and Port.
pub struct NatSessionTable {
    slots: Box<[AtomicU64; PORT_COUNT]>,
}

impl NatSessionTable {
    pub fn new() -> Self {
        let slots = unsafe {
            let layout = std::alloc::Layout::new::<[AtomicU64; PORT_COUNT]>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut [AtomicU64; PORT_COUNT];
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Box::from_raw(ptr)
        };
        Self { slots }
    }

    #[inline(always)]
    pub fn store(&self, port: u16, ip: [u8; 4], dst_port: u16) {
        let raw = pack_nat_session(ip, dst_port);
        self.slots[port as usize].store(raw, Ordering::Release);
    }

    #[inline(always)]
    pub fn load(&self, port: u16) -> Option<([u8; 4], u16)> {
        let raw = self.slots[port as usize].load(Ordering::Acquire);
        unpack_nat_session(raw)
    }

    #[inline(always)]
    pub fn load_raw(&self, port: u16) -> (Option<([u8; 4], u16)>, u64) {
        let raw = self.slots[port as usize].load(Ordering::Acquire);
        (unpack_nat_session(raw), raw)
    }

    #[inline(always)]
    pub fn compare_and_clear(&self, port: u16, expected_raw: u64) -> bool {
        self.slots[port as usize]
            .compare_exchange(expected_raw, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }
}

#[inline(always)]
pub fn pack_nat_session(ip: [u8; 4], port: u16) -> u64 {
    let ip_val = u32::from_le_bytes(ip) as u64;
    ip_val | ((port as u64) << 32) | (1u64 << 48)
}

#[inline(always)]
pub fn unpack_nat_session(val: u64) -> Option<([u8; 4], u16)> {
    if (val >> 48) == 0 {
        return None;
    }
    let ip_bytes = (val as u32).to_le_bytes();
    let port = ((val >> 32) & 0xffff) as u16;
    Some((ip_bytes, port))
}

pub static SESSIONS: std::sync::LazyLock<NatSessionTable> =
    std::sync::LazyLock::new(NatSessionTable::new);
