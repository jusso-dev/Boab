//! Boab workspace layout: `.boab/` directory handling.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

pub const WORKSPACE_DIR: &str = ".boab";
pub const CONFIG_FILE: &str = "config.toml";
pub const SYSTEMS_FILE: &str = "systems.json";
pub const INVENTORY_FILE: &str = "inventory.json";
pub const SCANS_DIR: &str = "scans";
pub const PLANS_DIR: &str = "plans";
pub const REPORTS_DIR: &str = "reports";
pub const VENDOR_OVERRIDES_FILE: &str = "vendor-overrides.json";

pub const DEFAULT_CONFIG: &str = "# Boab configuration\n\nschema_version = 1\n\n[scanner]\ndefault_rate_limit = \"1/second\"\ntls_timeout_seconds = 10\nair_gapped = true\n\n[reporting]\ndefault_format = \"md\"\n";

/// Represents an initialised Boab workspace.
#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// Resolve and validate an existing workspace at the given root.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().canonicalize().with_context(|| {
            format!(
                "could not resolve workspace path {}",
                root.as_ref().display()
            )
        })?;
        let dir = root.join(WORKSPACE_DIR);
        if !dir.exists() {
            return Err(anyhow!(
                "workspace not initialised: {} is missing. Run `boab init` first.",
                dir.display()
            ));
        }
        if !dir.is_dir() {
            return Err(anyhow!("{} exists but is not a directory", dir.display()));
        }
        let config_path = dir.join(CONFIG_FILE);
        if !config_path.exists() {
            return Err(anyhow!(
                "workspace at {} is malformed: missing {}",
                dir.display(),
                CONFIG_FILE
            ));
        }
        Ok(Self { root })
    }

    /// Create a new workspace at the given root.
    /// Returns Ok with `existed = true` if it was already initialised.
    pub fn init(root: impl AsRef<Path>, force: bool) -> Result<(Self, bool)> {
        let root = root.as_ref().canonicalize().with_context(|| {
            format!(
                "could not resolve workspace path {}",
                root.as_ref().display()
            )
        })?;
        let dir = root.join(WORKSPACE_DIR);

        if dir.exists() {
            if force {
                fs::remove_dir_all(&dir)
                    .with_context(|| format!("could not remove existing {}", dir.display()))?;
            } else {
                let cfg = dir.join(CONFIG_FILE);
                if cfg.exists() {
                    let ws = Self { root };
                    return Ok((ws, true));
                }
                return Err(anyhow!(
                    "{} exists but is malformed (no {}). Use `boab init --force --yes` to recreate.",
                    dir.display(),
                    CONFIG_FILE
                ));
            }
        }

        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        fs::create_dir_all(dir.join(SCANS_DIR))?;
        fs::create_dir_all(dir.join(PLANS_DIR))?;
        fs::create_dir_all(dir.join(REPORTS_DIR))?;
        fs::write(dir.join(CONFIG_FILE), DEFAULT_CONFIG)?;
        fs::write(dir.join(SYSTEMS_FILE), "[]\n")?;
        fs::write(dir.join(INVENTORY_FILE), "[]\n")?;
        fs::write(dir.join(VENDOR_OVERRIDES_FILE), "{\"entries\":[]}\n")?;

        Ok((Self { root }, false))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir(&self) -> PathBuf {
        self.root.join(WORKSPACE_DIR)
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir().join(CONFIG_FILE)
    }

    pub fn systems_path(&self) -> PathBuf {
        self.dir().join(SYSTEMS_FILE)
    }

    pub fn inventory_path(&self) -> PathBuf {
        self.dir().join(INVENTORY_FILE)
    }

    pub fn scans_dir(&self) -> PathBuf {
        self.dir().join(SCANS_DIR)
    }

    pub fn plans_dir(&self) -> PathBuf {
        self.dir().join(PLANS_DIR)
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.dir().join(REPORTS_DIR)
    }

    pub fn vendor_overrides_path(&self) -> PathBuf {
        self.dir().join(VENDOR_OVERRIDES_FILE)
    }
}
