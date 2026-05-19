use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::finding::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Codebase,
    TlsEndpoint,
    CertificateStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub name: String,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub target: String,
    pub config: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    pub findings: Vec<Finding>,
    pub error_message: Option<String>,
}

impl Scan {
    pub fn new(name: String, scan_type: ScanType, target: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            scan_type,
            status: ScanStatus::Queued,
            target,
            config: serde_json::Value::Object(serde_json::Map::new()),
            started_at: OffsetDateTime::now_utc(),
            completed_at: None,
            findings: Vec::new(),
            error_message: None,
        }
    }
}
