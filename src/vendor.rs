//! Vendor PQC registry loader. Bundled file lives in `data/vendor-pqc-registry.json`.

use anyhow::{Context, Result};

use crate::model::vendor::VendorRegistry;
use crate::storage;
use crate::workspace::Workspace;

/// The bundled vendor PQC registry, embedded at compile time.
pub const BUNDLED_REGISTRY: &str = include_str!("../data/vendor-pqc-registry.json");

pub fn load_bundled() -> Result<VendorRegistry> {
    serde_json::from_str(BUNDLED_REGISTRY).context("parse bundled vendor PQC registry")
}

pub fn load_merged(ws: &Workspace) -> Result<VendorRegistry> {
    let bundled = load_bundled()?;
    let overrides = storage::load_vendor_overrides(ws)?;
    Ok(bundled.merge_overrides(&overrides))
}
