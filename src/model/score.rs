use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub algorithm_vulnerability: u8,
    pub data_sensitivity: u8,
    pub harvest_now_decrypt_later: u8,
    pub system_criticality: u8,
    pub migration_difficulty: u8,
    pub priority: f32,
    pub triage_tier: u8,
    pub recommended_action: String,
}
