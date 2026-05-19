use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::system::Classification;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    Algorithm,
    Certificate,
    Key,
    ProtocolEndpoint,
    LibraryDependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Primitive {
    BlockCipher,
    StreamCipher,
    Hash,
    Signature,
    KeyAgreement,
    Kem,
    Pke,
    Mac,
    Drbg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqcStatus {
    Vulnerable,
    Hybrid,
    Resistant,
    SymmetricOk,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDifficulty {
    Trivial,
    Low,
    Medium,
    High,
    HardwareLocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    NotStarted,
    Planned,
    InProgress,
    Migrated,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetMilestone {
    Y2026,
    Y2028,
    Y2030,
}

impl TargetMilestone {
    pub fn year(self) -> u16 {
        match self {
            TargetMilestone::Y2026 => 2026,
            TargetMilestone::Y2028 => 2028,
            TargetMilestone::Y2030 => 2030,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "2026" => Some(Self::Y2026),
            "2028" => Some(Self::Y2028),
            "2030" => Some(Self::Y2030),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    pub id: Uuid,
    pub asset_type: AssetType,
    pub algorithm_name: String,
    pub algorithm_oid: Option<String>,
    pub primitive: Option<Primitive>,
    pub parameter_set: serde_json::Value,
    pub pqc_status: PqcStatus,
    pub quantum_vulnerable: bool,
    pub name: String,
    pub description: Option<String>,
    pub system_id: Option<Uuid>,
    pub data_classification: Option<Classification>,
    pub data_retention_horizon_year: Option<u16>,
    pub migration_difficulty: MigrationDifficulty,
    pub migration_status: MigrationStatus,
    pub target_milestone: Option<TargetMilestone>,
    pub tags: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    pub notes: Option<String>,
}

impl CryptoAsset {
    pub fn new(
        asset_type: AssetType,
        algorithm_name: String,
        name: String,
        pqc_status: PqcStatus,
        quantum_vulnerable: bool,
        migration_difficulty: MigrationDifficulty,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Uuid::new_v4(),
            asset_type,
            algorithm_name,
            algorithm_oid: None,
            primitive: None,
            parameter_set: serde_json::Value::Object(serde_json::Map::new()),
            pqc_status,
            quantum_vulnerable,
            name,
            description: None,
            system_id: None,
            data_classification: None,
            data_retention_horizon_year: None,
            migration_difficulty,
            migration_status: MigrationStatus::NotStarted,
            target_milestone: None,
            tags: Vec::new(),
            first_seen_at: now,
            last_seen_at: now,
            notes: None,
        }
    }
}
