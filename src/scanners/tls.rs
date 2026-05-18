//! TLS endpoint scanner. Implemented in Phase 3.

use anyhow::Result;

use crate::model::scan::Scan;

#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub rate_limit: Option<String>,
    pub timeout_seconds: u64,
    pub probe_hsts: bool,
    pub exclude: Vec<String>,
    pub name: Option<String>,
    pub air_gapped: bool,
}

pub async fn scan_targets(_targets: &[String], _options: &TlsOptions) -> Result<Vec<Scan>> {
    unimplemented!("TLS scanner is implemented in Phase 3")
}
