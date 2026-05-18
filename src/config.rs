//! Workspace configuration: `.boab/config.toml`.

use std::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::workspace::Workspace;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema_version: u32,
    pub scanner: ScannerConfig,
    pub reporting: ReportingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            scanner: ScannerConfig::default(),
            reporting: ReportingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub default_rate_limit: String,
    pub tls_timeout_seconds: u64,
    pub air_gapped: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            default_rate_limit: "1/second".to_string(),
            tls_timeout_seconds: 10,
            air_gapped: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    pub default_format: String,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            default_format: "md".to_string(),
        }
    }
}

pub fn load(ws: &Workspace) -> Result<Config> {
    let path = ws.config_path();
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse TOML from {}", path.display()))?;
    Ok(cfg)
}

pub fn save(ws: &Workspace, cfg: &Config) -> Result<()> {
    let text = toml::to_string_pretty(cfg).context("serialise config")?;
    fs::write(ws.config_path(), text)?;
    Ok(())
}

/// Get a single config value by dotted key, e.g. `scanner.air_gapped`.
pub fn get_value(cfg: &Config, key: &str) -> Option<String> {
    match key {
        "schema_version" => Some(cfg.schema_version.to_string()),
        "scanner.default_rate_limit" => Some(cfg.scanner.default_rate_limit.clone()),
        "scanner.tls_timeout_seconds" => Some(cfg.scanner.tls_timeout_seconds.to_string()),
        "scanner.air_gapped" => Some(cfg.scanner.air_gapped.to_string()),
        "reporting.default_format" => Some(cfg.reporting.default_format.clone()),
        _ => None,
    }
}

/// Set a single config value by dotted key. Returns an error if the key is unknown
/// or the value cannot be parsed for the target field.
pub fn set_value(cfg: &mut Config, key: &str, value: &str) -> Result<()> {
    match key {
        "schema_version" => {
            cfg.schema_version = value.parse().context("schema_version must be a u32")?;
        }
        "scanner.default_rate_limit" => {
            cfg.scanner.default_rate_limit = value.to_string();
        }
        "scanner.tls_timeout_seconds" => {
            cfg.scanner.tls_timeout_seconds =
                value.parse().context("tls_timeout_seconds must be a u64")?;
        }
        "scanner.air_gapped" => {
            cfg.scanner.air_gapped = value.parse().context("air_gapped must be true or false")?;
        }
        "reporting.default_format" => {
            if !matches!(value, "json" | "md" | "cbom") {
                return Err(anyhow::anyhow!(
                    "default_format must be one of: json, md, cbom"
                ));
            }
            cfg.reporting.default_format = value.to_string();
        }
        other => return Err(anyhow::anyhow!("unknown config key: {}", other)),
    }
    Ok(())
}
