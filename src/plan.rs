//! Plan generation.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::asset::{CryptoAsset, TargetMilestone};
use crate::model::plan::{front_loaded_target_date, Plan, PlanItem, PlanItemStatus};
use crate::model::score::RiskScore;
use crate::scoring;
use crate::storage;
use crate::workspace::Workspace;

/// Map an asset's triage tier to the earliest milestone that should pick it up.
fn milestone_for_tier(tier: u8) -> TargetMilestone {
    match tier {
        1 => TargetMilestone::Y2028,
        2 => TargetMilestone::Y2028,
        3 => TargetMilestone::Y2030,
        _ => TargetMilestone::Y2030,
    }
}

/// Generate a plan against the given milestone.
///
/// Pulls inventory entries whose triage_tier maps to that milestone or earlier,
/// ordered by priority (desc) then migration_difficulty (asc).
pub fn generate(ws: &Workspace, milestone: TargetMilestone, name: Option<String>) -> Result<Plan> {
    let inventory = storage::load_inventory(ws)?;
    let systems = storage::load_systems(ws)?;
    let today = OffsetDateTime::now_utc();

    let mut scored: Vec<(CryptoAsset, RiskScore, Option<TargetMilestone>)> = inventory
        .into_iter()
        .map(|a| {
            let sys = a
                .system_id
                .and_then(|id| systems.iter().find(|s| s.id == id));
            let s = scoring::score_asset(&a, sys, today);
            let ms = milestone_for_tier(s.triage_tier);
            (a, s, Some(ms))
        })
        .collect();

    scored.retain(|(_, _, ms)| ms.map(|m| m.year() <= milestone.year()).unwrap_or(false));

    scored.sort_by(|a, b| {
        b.1.priority
            .partial_cmp(&a.1.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.migration_difficulty.cmp(&b.1.migration_difficulty))
            .then(a.0.name.cmp(&b.0.name))
    });

    let mut plan = Plan::new(
        name.unwrap_or_else(|| format!("PQC transition plan {}", milestone.year())),
        milestone,
    );
    for (asset, score, _) in scored {
        let target_date = front_loaded_target_date(milestone, score.triage_tier);
        let dt = target_date
            .with_hms(0, 0, 0)
            .context("compose target datetime")?
            .assume_utc();
        plan.items.push(PlanItem {
            id: Uuid::new_v4(),
            crypto_asset_id: asset.id,
            asset_name: asset.name.clone(),
            algorithm_name: asset.algorithm_name.clone(),
            triage_tier: score.triage_tier,
            priority: score.priority,
            target_action: score.recommended_action.clone(),
            target_date: Some(dt),
            assignee: None,
            notes: None,
            status: PlanItemStatus::Pending,
        });
    }
    Ok(plan)
}

/// Regenerate a plan in place, preserving user edits where the asset is
/// unchanged. User-editable fields are `target_action`, `target_date`,
/// `assignee`, `notes`, `status`.
pub fn regenerate(ws: &Workspace, plan_id: Uuid) -> Result<Plan> {
    let existing = storage::load_plan(ws, plan_id)?;
    let user_edits: HashMap<Uuid, PlanItem> = existing
        .items
        .iter()
        .map(|i| (i.crypto_asset_id, i.clone()))
        .collect();

    let mut regenerated = generate(ws, existing.milestone, Some(existing.name.clone()))?;
    regenerated.id = existing.id;

    for item in regenerated.items.iter_mut() {
        if let Some(prev) = user_edits.get(&item.crypto_asset_id) {
            if prev.target_action != item.target_action {
                item.target_action = prev.target_action.clone();
            }
            if prev.target_date != item.target_date && prev.target_date.is_some() {
                item.target_date = prev.target_date;
            }
            if prev.assignee.is_some() {
                item.assignee = prev.assignee.clone();
            }
            if prev.notes.is_some() {
                item.notes = prev.notes.clone();
            }
            if prev.status != PlanItemStatus::Pending {
                item.status = prev.status;
            }
        }
    }

    Ok(regenerated)
}

pub fn save(ws: &Workspace, plan: &Plan) -> Result<()> {
    storage::save_plan(ws, plan)
}

pub fn parse_milestone(value: &str) -> Result<TargetMilestone> {
    TargetMilestone::parse(value)
        .ok_or_else(|| anyhow!("milestone must be one of 2026, 2028, 2030"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_to_milestone_mapping() {
        assert_eq!(milestone_for_tier(1).year(), 2028);
        assert_eq!(milestone_for_tier(2).year(), 2028);
        assert_eq!(milestone_for_tier(3).year(), 2030);
        assert_eq!(milestone_for_tier(4).year(), 2030);
    }
}
