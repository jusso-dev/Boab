//! Certificate store scanner. Implemented in Phase 3.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::model::scan::Scan;

#[derive(Debug, Clone, Default)]
pub struct CertStoreOptions {
    pub password_file: Option<PathBuf>,
    pub name: Option<String>,
}

pub fn scan_path(_path: &Path, _options: &CertStoreOptions) -> Result<Scan> {
    unimplemented!("certificate store scanner is implemented in Phase 3")
}
