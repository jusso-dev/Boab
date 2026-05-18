use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    File,
    Url,
    CertSubject,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Confirmed,
    FalsePositive,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub crypto_asset_id: Option<Uuid>,
    pub source_type: SourceType,
    pub source_location: String,
    pub evidence: serde_json::Value,
    pub confidence: Confidence,
    pub status: FindingStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub discovered_at: OffsetDateTime,
}

impl Finding {
    pub fn new(
        scan_id: Uuid,
        source_type: SourceType,
        source_location: String,
        evidence: serde_json::Value,
        confidence: Confidence,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            scan_id,
            crypto_asset_id: None,
            source_type,
            source_location,
            evidence,
            confidence,
            status: FindingStatus::New,
            discovered_at: OffsetDateTime::now_utc(),
        }
    }
}
