//! Scanner implementations. Each scanner produces a `Scan` populated with
//! `Finding` records that the dedup layer then promotes into the inventory.

pub mod cert_store;
pub mod codebase;
pub mod tls;
