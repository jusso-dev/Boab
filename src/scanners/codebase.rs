//! Codebase scanner. Implemented in Phase 2.

use std::path::Path;

use anyhow::Result;

use crate::model::scan::Scan;

pub mod patterns;

/// Options for the codebase scanner.
#[derive(Debug, Clone, Default)]
pub struct CodebaseOptions {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub name: Option<String>,
}

pub fn scan_path(_path: &Path, _options: &CodebaseOptions) -> Result<Scan> {
    unimplemented!("codebase scanner is implemented in Phase 2")
}
