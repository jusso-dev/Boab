//! Report writers. JSON, CycloneDX 1.6 CBOM, Markdown, and HTML.

pub mod cbom;
pub mod html;
pub mod json;
pub mod markdown;

use anyhow::Result;
use time::OffsetDateTime;

use crate::model::asset::{CryptoAsset, PqcStatus};
use crate::model::plan::Plan;
use crate::model::score::RiskScore;
use crate::model::system::System;
use crate::model::vendor::VendorRegistry;
use crate::scoring;
use crate::storage;
use crate::workspace::Workspace;

/// Workspace state shared by the readiness reports (Markdown and HTML), with
/// every asset scored and sorted by descending priority.
pub(crate) struct Readiness {
    pub systems: Vec<System>,
    pub scored: Vec<(CryptoAsset, RiskScore)>,
    pub plans: Vec<Plan>,
    pub registry: VendorRegistry,
    pub today: OffsetDateTime,
}

impl Readiness {
    pub fn load(ws: &Workspace) -> Result<Self> {
        let systems = storage::load_systems(ws)?;
        let inventory = storage::load_inventory(ws)?;
        let plans = storage::list_plans(ws)?;
        let registry = crate::vendor::load_merged(ws)?;
        let today = OffsetDateTime::now_utc();

        let mut scored: Vec<(CryptoAsset, RiskScore)> = inventory
            .into_iter()
            .map(|a| {
                let sys = a
                    .system_id
                    .and_then(|id| systems.iter().find(|s| s.id == id));
                let s = scoring::score_asset(&a, sys, today);
                (a, s)
            })
            .collect();
        scored.sort_by(|a, b| {
            b.1.priority
                .partial_cmp(&a.1.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(Self {
            systems,
            scored,
            plans,
            registry,
            today,
        })
    }

    /// Assets that are quantum-vulnerable or could not be classified.
    pub fn vulnerable_count(&self) -> usize {
        self.scored
            .iter()
            .filter(|(a, _)| matches!(a.pqc_status, PqcStatus::Vulnerable | PqcStatus::Unknown))
            .count()
    }

    pub fn vulnerable_pct(&self) -> f32 {
        let total = self.scored.len();
        if total == 0 {
            0.0
        } else {
            (self.vulnerable_count() as f32) * 100.0 / (total as f32)
        }
    }

    pub fn has_plan_for(&self, year: u16) -> bool {
        self.plans.iter().any(|p| p.milestone.year() == year)
    }
}

pub(crate) fn pqc_status_str(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "vulnerable",
        PqcStatus::Hybrid => "hybrid",
        PqcStatus::Resistant => "resistant",
        PqcStatus::SymmetricOk => "symmetric_ok",
        PqcStatus::Unknown => "unknown",
    }
}
