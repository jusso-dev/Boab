//! JSON file-backed storage for workspace artefacts.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::model::asset::CryptoAsset;
use crate::model::plan::Plan;
use crate::model::scan::Scan;
use crate::model::system::System;
use crate::model::vendor::VendorRegistry;
use crate::workspace::Workspace;

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON from {}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)
        .with_context(|| format!("serialise JSON for {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// Systems -------------------------------------------------------------------

pub fn load_systems(ws: &Workspace) -> Result<Vec<System>> {
    let path = ws.systems_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_json(&path)
}

pub fn save_systems(ws: &Workspace, systems: &[System]) -> Result<()> {
    write_json(&ws.systems_path(), &systems)
}

// Inventory -----------------------------------------------------------------

pub fn load_inventory(ws: &Workspace) -> Result<Vec<CryptoAsset>> {
    let path = ws.inventory_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    read_json(&path)
}

pub fn save_inventory(ws: &Workspace, inventory: &[CryptoAsset]) -> Result<()> {
    write_json(&ws.inventory_path(), &inventory)
}

// Scans ---------------------------------------------------------------------

pub fn save_scan(ws: &Workspace, scan: &Scan) -> Result<()> {
    let path = ws.scans_dir().join(format!("{}.json", scan.id));
    write_json(&path, scan)
}

pub fn load_scan(ws: &Workspace, id: Uuid) -> Result<Scan> {
    read_json(&ws.scans_dir().join(format!("{}.json", id)))
}

pub fn list_scans(ws: &Workspace) -> Result<Vec<Scan>> {
    let dir = ws.scans_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut scans = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            scans.push(read_json::<Scan>(&path)?);
        }
    }
    scans.sort_by_key(|s| s.started_at);
    Ok(scans)
}

// Plans ---------------------------------------------------------------------

pub fn save_plan(ws: &Workspace, plan: &Plan) -> Result<()> {
    let path = ws.plans_dir().join(format!("{}.json", plan.id));
    write_json(&path, plan)
}

pub fn load_plan(ws: &Workspace, id: Uuid) -> Result<Plan> {
    read_json(&ws.plans_dir().join(format!("{}.json", id)))
}

pub fn list_plans(ws: &Workspace) -> Result<Vec<Plan>> {
    let dir = ws.plans_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut plans = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            plans.push(read_json::<Plan>(&path)?);
        }
    }
    plans.sort_by_key(|p| p.generated_at);
    Ok(plans)
}

// Vendor overrides ----------------------------------------------------------

pub fn load_vendor_overrides(ws: &Workspace) -> Result<VendorRegistry> {
    let path = ws.vendor_overrides_path();
    if !path.exists() {
        return Ok(VendorRegistry::default());
    }
    read_json(&path)
}

pub fn save_vendor_overrides(ws: &Workspace, registry: &VendorRegistry) -> Result<()> {
    write_json(&ws.vendor_overrides_path(), registry)
}
