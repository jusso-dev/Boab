use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Unofficial,
    Official,
    OfficialSensitive,
    Protected,
    Secret,
    TopSecret,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Unofficial => "unofficial",
            Classification::Official => "official",
            Classification::OfficialSensitive => "official_sensitive",
            Classification::Protected => "protected",
            Classification::Secret => "secret",
            Classification::TopSecret => "top_secret",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "unofficial" => Some(Self::Unofficial),
            "official" => Some(Self::Official),
            "official_sensitive" | "official-sensitive" => Some(Self::OfficialSensitive),
            "protected" => Some(Self::Protected),
            "secret" => Some(Self::Secret),
            "top_secret" | "top-secret" => Some(Self::TopSecret),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Standard,
    Essential,
    MissionCritical,
}

impl Criticality {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "standard" => Some(Self::Standard),
            "essential" => Some(Self::Essential),
            "mission_critical" | "mission-critical" => Some(Self::MissionCritical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Criticality::Low => "low",
            Criticality::Standard => "standard",
            Criticality::Essential => "essential",
            Criticality::MissionCritical => "mission_critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub classification: Classification,
    pub criticality: Criticality,
    pub is_soci: bool,
    pub expected_data_lifetime_years: Option<u16>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl System {
    pub fn new(
        name: String,
        description: Option<String>,
        classification: Classification,
        criticality: Criticality,
        is_soci: bool,
        expected_data_lifetime_years: Option<u16>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            classification,
            criticality,
            is_soci,
            expected_data_lifetime_years,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
