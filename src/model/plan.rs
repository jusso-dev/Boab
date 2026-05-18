use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use super::asset::TargetMilestone;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanItemStatus {
    Pending,
    InProgress,
    Complete,
    Deferred,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanItem {
    pub id: Uuid,
    pub crypto_asset_id: Uuid,
    pub asset_name: String,
    pub algorithm_name: String,
    pub triage_tier: u8,
    pub priority: f32,
    pub target_action: String,
    #[serde(with = "time::serde::iso8601::option")]
    pub target_date: Option<OffsetDateTime>,
    pub assignee: Option<String>,
    pub notes: Option<String>,
    pub status: PlanItemStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: Uuid,
    pub name: String,
    pub milestone: TargetMilestone,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub items: Vec<PlanItem>,
}

impl Plan {
    pub fn new(name: String, milestone: TargetMilestone) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            milestone,
            generated_at: OffsetDateTime::now_utc(),
            items: Vec::new(),
        }
    }
}

pub fn front_loaded_target_date(milestone: TargetMilestone, tier: u8) -> Date {
    let year = milestone.year() as i32;
    let month = match tier {
        1 => time::Month::March,
        2 => time::Month::June,
        3 => time::Month::September,
        _ => time::Month::December,
    };
    Date::from_calendar_date(year, month, 1).expect("valid front-loaded date")
}
