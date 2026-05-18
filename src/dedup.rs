//! Dedup pipeline that promotes findings into the canonical inventory.
//! Implemented in Phase 2.

use anyhow::Result;

use crate::model::asset::CryptoAsset;
use crate::model::scan::Scan;

pub fn promote_findings(_scan: &mut Scan, inventory: Vec<CryptoAsset>) -> Result<Vec<CryptoAsset>> {
    // Phase 1 stub: no findings to promote yet.
    Ok(inventory)
}
