pub mod logbuf;
pub mod options;
pub mod runtime;
pub use logbuf::*;
pub use options::*;
pub use runtime::*;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub adapter_name: String,
    pub tun_ip: [u8; 4],
    pub tun_gw: [u8; 4],
    pub socks_addr: String,
    pub phys_if_index: u32,
    pub ring_capacity: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            adapter_name: "BYPTUN-CORE".to_string(),
            tun_ip: [198, 19, 0, 2],
            tun_gw: [198, 19, 0, 1],
            socks_addr: "127.0.0.1:10808".to_string(),
            phys_if_index: 0,
            ring_capacity: 0x400000, // 4 MB
        }
    }
}

impl EngineConfig {
    pub fn new(socks_addr: &str, phys_if_index: u32, ring_capacity: u32) -> Self {
        Self {
            adapter_name: "BYPTUN-CORE".to_string(),
            tun_ip: [198, 19, 0, 2],
            tun_gw: [198, 19, 0, 1],
            socks_addr: if socks_addr.is_empty() {
                "127.0.0.1:10808".to_string()
            } else {
                socks_addr.to_string()
            },
            phys_if_index,
            ring_capacity: if ring_capacity == 0 {
                0x400000
            } else {
                ring_capacity
            },
        }
    }
}
