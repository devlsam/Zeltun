use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

pub const OPT_BLOCK_QUIC: u32 = 1 << 0; // 1
pub const OPT_MSS_CLAMP: u32 = 1 << 1;  // 2
pub const OPT_SNI_SNIFF: u32 = 1 << 2;  // 4
pub const OPT_BYPASS_LAN: u32 = 1 << 3; // 8
pub const OPT_GAMING_QOS: u32 = 1 << 4; // 16
pub const OPT_CLEAN_DNS: u32 = 1 << 5;  // 32
pub const OPT_STRICT_ANTI_LEAK: u32 = 1 << 6; // 64

pub const DEFAULT_OPTS: u32 = OPT_BLOCK_QUIC
    | OPT_BYPASS_LAN
    | OPT_GAMING_QOS
    | OPT_CLEAN_DNS; // 57 (0x39)

pub const DEFAULT_TCP_MSS: u16 = 1360;

pub struct RuntimeOptions {
    pub flags: AtomicU32,
    pub tcp_mss: AtomicU16,
}

impl RuntimeOptions {
    pub const fn new() -> Self {
        Self {
            flags: AtomicU32::new(DEFAULT_OPTS),
            tcp_mss: AtomicU16::new(DEFAULT_TCP_MSS),
        }
    }

    #[inline(always)]
    pub fn is_enabled(&self, flag: u32) -> bool {
        (self.flags.load(Ordering::Relaxed) & flag) != 0
    }

    #[inline(always)]
    pub fn get_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn get_mss(&self) -> u16 {
        self.tcp_mss.load(Ordering::Relaxed)
    }

    pub fn set_options(&self, flags: u32, mss: u16) {
        self.flags.store(flags, Ordering::Release);
        if mss > 0 {
            self.tcp_mss.store(mss, Ordering::Release);
        }
    }

    /// Toggles an individual option bit without clobbering sibling flags.
    pub fn set_flag(&self, flag: u32, enabled: bool) {
        let mut cur = self.flags.load(Ordering::Acquire);
        loop {
            let next = if enabled { cur | flag } else { cur & !flag };
            match self
                .flags
                .compare_exchange_weak(cur, next, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }
}

pub static OPTIONS: RuntimeOptions = RuntimeOptions::new();

