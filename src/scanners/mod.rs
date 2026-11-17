//! Scanner implementations. Each scanner produces a `Scan` populated with
//! `Finding` records that the dedup layer then promotes into the inventory.

pub mod cert_store;
pub mod codebase;
pub mod host;
pub mod jks;
pub mod kms;
pub mod tls;

use std::path::Path;

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::model::asset::{AssetType, PqcStatus};
use crate::model::finding::{Confidence, Finding, SourceType};

/// Finding kinds produced by the host crypto, keystore and KMS scanners.
///
/// Every one of them carries `kind`, `host` and `location` inside
/// `parameter_set`, so the inventory and the CBOM can say where the asset
/// lives. See `docs/cbom.md` ("GRiCk import contract").
pub const HOST_CRYPTO_KINDS: &[&str] = &[
    KIND_SSH_HOST_KEY,
    KIND_SSH_CONFIG_ALGORITHM,
    KIND_OS_CRYPTO_POLICY,
    KIND_OPENSSL_CONFIG,
    KIND_KEYSTORE_ENTRY,
    KIND_KMS_KEY,
];

pub const KIND_SSH_HOST_KEY: &str = "ssh_host_key";
pub const KIND_SSH_CONFIG_ALGORITHM: &str = "ssh_config_algorithm";
pub const KIND_OS_CRYPTO_POLICY: &str = "os_crypto_policy";
pub const KIND_OPENSSL_CONFIG: &str = "openssl_config";
pub const KIND_KEYSTORE_ENTRY: &str = "keystore_entry";
pub const KIND_KMS_KEY: &str = "kms_key";

/// Asset type for a host crypto finding kind, or `None` for any other kind.
pub fn host_crypto_asset_type(kind: &str) -> Option<AssetType> {
    match kind {
        KIND_SSH_HOST_KEY | KIND_KEYSTORE_ENTRY | KIND_KMS_KEY => Some(AssetType::Key),
        KIND_SSH_CONFIG_ALGORITHM => Some(AssetType::Algorithm),
        KIND_OS_CRYPTO_POLICY | KIND_OPENSSL_CONFIG => Some(AssetType::ProtocolEndpoint),
        _ => None,
    }
}

/// Inventory dedup key for a host crypto asset. Built only from fields that
/// are stored in `parameter_set`, so the key computed from a fresh finding and
/// the key computed from an inventory entry always agree.
pub fn host_crypto_dedup_key(kind: &str, algorithm_name: &str, params: &Value) -> Option<String> {
    let s = |k: &str| params.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let key = match kind {
        KIND_SSH_HOST_KEY => {
            let id = if s("fingerprint_sha256").is_empty() {
                s("location")
            } else {
                s("fingerprint_sha256")
            };
            format!("ssh_host_key:{}:{}", s("host"), id)
        }
        KIND_SSH_CONFIG_ALGORITHM => format!(
            "ssh_alg:{}:{}:{}",
            s("host"),
            s("directive"),
            if s("ssh_name").is_empty() {
                algorithm_name.to_ascii_lowercase()
            } else {
                s("ssh_name").to_ascii_lowercase()
            }
        ),
        KIND_OS_CRYPTO_POLICY => format!("crypto_policy:{}", s("host")),
        KIND_OPENSSL_CONFIG => format!("openssl_config:{}:{}", s("host"), s("location")),
        KIND_KEYSTORE_ENTRY => format!("keystore:{}:{}:{}", s("host"), s("location"), s("alias")),
        KIND_KMS_KEY => format!("kms:{}:{}", s("provider"), s("key_id")),
        _ => return None,
    };
    Some(key)
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

/// Fields shared by every host crypto finding.
pub(crate) struct HostAsset<'a> {
    pub kind: &'static str,
    pub host: &'a str,
    pub location: &'a str,
    /// Display name for the inventory entry. Unique per asset.
    pub asset_name: String,
    /// Canonical algorithm name used by the scoring rubric.
    pub algorithm_name: String,
    pub pqc_status: PqcStatus,
    /// `parameter_set.primitive`, in the snake_case `Primitive` spelling.
    pub primitive: Option<&'static str>,
    pub key_size_bits: Option<u64>,
    /// Kind-specific metadata. Never contains key material or secrets.
    pub extra: Map<String, Value>,
}

impl HostAsset<'_> {
    pub fn into_finding(
        self,
        scan_id: Uuid,
        source_type: SourceType,
        confidence: Confidence,
    ) -> Finding {
        let mut params = Map::new();
        params.insert("kind".into(), Value::from(self.kind));
        params.insert("host".into(), Value::from(self.host));
        params.insert("location".into(), Value::from(self.location));
        if let Some(p) = self.primitive {
            params.insert("primitive".into(), Value::from(p));
        }
        if let Some(b) = self.key_size_bits {
            params.insert("key_size_bits".into(), Value::from(b));
        }
        for (k, v) in self.extra {
            params.entry(k).or_insert(v);
        }
        let asset_key = host_crypto_dedup_key(
            self.kind,
            &self.algorithm_name,
            &Value::Object(params.clone()),
        )
        .unwrap_or_default();
        params.insert("asset_key".into(), Value::from(asset_key));
        let source_location = format!("{}:{}", self.host, self.location);
        Finding::new(
            scan_id,
            source_type,
            source_location,
            json!({
                "kind": self.kind,
                "asset_name": self.asset_name,
                "algorithm_name": self.algorithm_name,
                "pqc_status": pqc_status_str(self.pqc_status),
                "target": self.location,
                "parameter_set": Value::Object(params),
            }),
            confidence,
        )
    }
}

/// Best-effort label for the machine Boab runs on. Reads no network state.
pub fn local_host_label() -> String {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    for file in ["/etc/hostname", "/proc/sys/kernel/hostname"] {
        if let Some(h) = read_hostname_file(Path::new(file)) {
            return h;
        }
    }
    "localhost".to_string()
}

/// First non-empty, non-comment line of a hostname file.
pub(crate) fn read_hostname_file(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    raw.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
}

/// Canonical name and status for a public key algorithm seen in an X.509
/// certificate, used for keystore entries.
pub(crate) fn classify_public_key(
    pk_algorithm: &str,
    key_bits: Option<u64>,
) -> (String, PqcStatus, &'static str) {
    let lower = pk_algorithm.to_ascii_lowercase();
    if lower == "rsa" {
        return ("RSA".into(), PqcStatus::Vulnerable, "signature");
    }
    if lower == "ec" {
        let name = match key_bits {
            Some(256) => "ECDSA-P256",
            Some(384) => "ECDSA-P384",
            Some(521) => "ECDSA-P521",
            _ => "ECDSA",
        };
        return (name.into(), PqcStatus::Vulnerable, "signature");
    }
    if lower == "ed25519" || lower == "ed448" {
        return (pk_algorithm.into(), PqcStatus::Vulnerable, "signature");
    }
    if lower.contains("ml-dsa") || lower.contains("mldsa") || lower.contains("slh-dsa") {
        return (pk_algorithm.into(), PqcStatus::Resistant, "signature");
    }
    (pk_algorithm.into(), PqcStatus::Unknown, "signature")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_an_asset_type_and_key() {
        for kind in HOST_CRYPTO_KINDS {
            assert!(host_crypto_asset_type(kind).is_some(), "{kind}");
            assert!(host_crypto_dedup_key(kind, "x", &json!({})).is_some());
        }
        assert!(host_crypto_asset_type("algorithm_match").is_none());
        assert!(host_crypto_dedup_key("algorithm_match", "x", &json!({})).is_none());
    }
}
