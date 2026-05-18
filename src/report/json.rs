//! Native JSON report. Implemented in Phase 5.

use std::path::Path;

use anyhow::Result;

use crate::workspace::Workspace;

pub fn write(_ws: &Workspace, _out: &Path) -> Result<()> {
    unimplemented!("JSON report is implemented in Phase 5")
}
