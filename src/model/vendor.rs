use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::asset::PqcStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorEntry {
    pub vendor: String,
    pub product: String,
    pub pqc_status: PqcStatus,
    pub target_date: Option<String>,
    pub source_url: Option<String>,
    pub source_note: Option<String>,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_verified_at: Option<OffsetDateTime>,
}

impl VendorEntry {
    pub fn key(&self) -> (String, String) {
        (
            self.vendor.to_ascii_lowercase(),
            self.product.to_ascii_lowercase(),
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VendorRegistry {
    pub entries: Vec<VendorEntry>,
}

impl VendorRegistry {
    pub fn new(entries: Vec<VendorEntry>) -> Self {
        Self { entries }
    }

    pub fn merge_overrides(&self, overrides: &VendorRegistry) -> VendorRegistry {
        let mut merged: Vec<VendorEntry> = self.entries.clone();
        for ov in &overrides.entries {
            let key = ov.key();
            if let Some(existing) = merged.iter_mut().find(|e| e.key() == key) {
                *existing = ov.clone();
            } else {
                merged.push(ov.clone());
            }
        }
        merged.sort_by(|a, b| {
            a.vendor
                .to_ascii_lowercase()
                .cmp(&b.vendor.to_ascii_lowercase())
                .then(
                    a.product
                        .to_ascii_lowercase()
                        .cmp(&b.product.to_ascii_lowercase()),
                )
        });
        VendorRegistry { entries: merged }
    }

    pub fn search(&self, term: &str) -> Vec<&VendorEntry> {
        let needle = term.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.vendor.to_ascii_lowercase().contains(&needle)
                    || e.product.to_ascii_lowercase().contains(&needle)
            })
            .collect()
    }
}
