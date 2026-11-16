pub mod adapter;
pub mod adapter_detect;
pub mod engine;
pub mod lifecycle;
pub mod redirect;
pub mod routes;
pub mod session;
pub mod sys;
pub mod worker;

#[cfg(test)]
mod tests;

pub use adapter::{detect_physical_adapter, PhysicalAdapterInfo};
pub use engine::TunnelEngine;
pub use redirect::*;
pub use session::{WintunAdapter, WintunSession};
pub use worker::*;
