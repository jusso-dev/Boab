//! Native JSON report. Full workspace state plus generation metadata.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use time::OffsetDateTime;

use crate::model::asset::CryptoAsset;
use crate::model::plan::Plan;
use crate::model::scan::{ScanStatus, ScanType};
use crate::model::score::RiskScore;
use crate::model::system::System;
use crate::model::vendor::VendorRegistry;
use crate::scoring;
use crate::storage;
use crate::workspace::Workspace;

#[derive(Debug, Serialize)]
struct ScanSummary {
    id: uuid::Uuid,
    name: String,
    scan_type: ScanType,
    status: ScanStatus,
    target: String,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
    finding_count: usize,
}

#[derive(Debug, Serialize)]
struct AssetWithScore<'a> {
    #[serde(flatten)]
    asset: &'a CryptoAsset,
    risk_score: RiskScore,
}

#[derive(Debug, Serialize)]
struct GenerationMetadata {
    tool: &'static str,
    version: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct VendorCoverageSummary {
    total: usize,
    by_status: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Report<'a> {
    metadata: GenerationMetadata,
    systems: &'a [System],
    inventory: Vec<AssetWithScore<'a>>,
    scans: Vec<ScanSummary>,
    plans: &'a [Plan],
    vendor_coverage: VendorCoverageSummary,
    vendor_registry: &'a VendorRegistry,
}

pub fn write(ws: &Workspace, out: &Path) -> Result<()> {
    let systems = storage::load_systems(ws)?;
    let inventory = storage::load_inventory(ws)?;
    let scans = storage::list_scans(ws)?;
    let plans = storage::list_plans(ws)?;
    let registry = crate::vendor::load_merged(ws)?;
    let today = OffsetDateTime::now_utc();

    let scored: Vec<AssetWithScore<'_>> = inventory
        .iter()
        .map(|a| {
            let sys = a
                .system_id
                .and_then(|id| systems.iter().find(|s| s.id == id));
            AssetWithScore {
                asset: a,
                risk_score: scoring::score_asset(a, sys, today),
            }
        })
        .collect();

    let scan_summaries: Vec<ScanSummary> = scans
        .into_iter()
        .map(|s| ScanSummary {
            id: s.id,
            name: s.name,
            scan_type: s.scan_type,
            status: s.status,
            target: s.target,
            started_at: s.started_at,
            finding_count: s.findings.len(),
        })
        .collect();

    let mut by_status = serde_json::Map::new();
    for entry in &registry.entries {
        let key = format!("{:?}", entry.pqc_status).to_ascii_lowercase();
        let v = by_status
            .entry(key)
            .or_insert_with(|| serde_json::Value::from(0u64));
        if let Some(n) = v.as_u64() {
            *v = serde_json::Value::from(n + 1);
        }
    }
    let vendor_coverage = VendorCoverageSummary {
        total: registry.entries.len(),
        by_status: serde_json::Value::Object(by_status),
    };

    let report = Report {
        metadata: GenerationMetadata {
            tool: "boab",
            version: env!("CARGO_PKG_VERSION"),
            generated_at: today,
        },
        systems: &systems,
        inventory: scored,
        scans: scan_summaries,
        plans: &plans,
        vendor_coverage,
        vendor_registry: &registry,
    };

    let json = serde_json::to_string_pretty(&report).context("serialise JSON report")?;
    if let Some(parent) = out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(out, json).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}
