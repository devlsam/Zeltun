pub mod config;
pub mod driver;
pub mod packet;
pub mod proc;
pub mod router;
pub mod relay;
pub mod dns;
pub mod udp;
pub mod ffi;

pub use driver::{detect_physical_adapter, PhysicalAdapterInfo, TunnelEngine, WintunAdapter, WintunSession};
pub use ffi::{byptun_get_stats, byptun_set_options, byptun_set_rules, byptun_start, byptun_stop};
pub use packet::{calc_ipv4_checksum, rewrite_inbound_tcp, rewrite_outbound_tcp, SESSIONS};
pub use proc::RESOLVER;
pub use relay::{dial_direct_tcp, dial_socks5_tcp, relay_tcp};
pub use router::{RouteAction, SplitMode, SplitRouter};

pub mod decision {
    pub use crate::router::*;
}
pub mod engine {
    pub use crate::driver::*;
}
pub mod outbound {
    pub use crate::relay::*;
}
pub mod resolver {
    pub use crate::proc::*;
}
pub mod session {
    pub use crate::packet::sessions::*;
}
pub mod wintun {
    pub use crate::driver::*;
}
