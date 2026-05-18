//! Dedup pipeline that promotes findings into the canonical inventory.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::model::asset::{AssetType, CryptoAsset, MigrationDifficulty, PqcStatus, Primitive};
use crate::model::finding::Finding;
use crate::model::scan::Scan;

/// Group findings into inventory upserts. Returns the merged inventory.
///
/// Preserves user-set fields on existing assets: owner-related metadata,
/// classification, notes, migration_status, target_milestone, system_id,
/// data_retention_horizon_year, description, tags.
pub fn promote_findings(
    scan: &mut Scan,
    mut inventory: Vec<CryptoAsset>,
) -> Result<Vec<CryptoAsset>> {
    let now = OffsetDateTime::now_utc();
    let mut index: BTreeMap<String, usize> = inventory
        .iter()
        .enumerate()
        .map(|(i, a)| (asset_dedup_key(a, None), i))
        .collect();

    for finding in scan.findings.iter_mut() {
        let key_data = finding_dedup_key(finding)?;
        let key = key_data.dedup_key.clone();

        if let Some(&existing_idx) = index.get(&key) {
            inventory[existing_idx].last_seen_at = now;
            finding.crypto_asset_id = Some(inventory[existing_idx].id);
            continue;
        }

        let asset = build_asset_from_finding(finding, key_data)?;
        finding.crypto_asset_id = Some(asset.id);
        let new_key = asset_dedup_key(&asset, None);
        inventory.push(asset);
        index.insert(new_key, inventory.len() - 1);
    }

    Ok(inventory)
}

struct FindingKey {
    dedup_key: String,
    asset_type: AssetType,
    algorithm_name: String,
    pqc_status: PqcStatus,
    primitive: Option<Primitive>,
    key_size_bits: Option<u64>,
    source_root: String,
    library_name: Option<String>,
}

fn parse_primitive(s: &str) -> Option<Primitive> {
    match s {
        "block_cipher" => Some(Primitive::BlockCipher),
        "stream_cipher" => Some(Primitive::StreamCipher),
        "hash" => Some(Primitive::Hash),
        "signature" => Some(Primitive::Signature),
        "key_agreement" => Some(Primitive::KeyAgreement),
        "kem" => Some(Primitive::Kem),
        "pke" => Some(Primitive::Pke),
        "mac" => Some(Primitive::Mac),
        "drbg" => Some(Primitive::Drbg),
        _ => None,
    }
}

fn parse_pqc_status(v: &Value) -> PqcStatus {
    match v.as_str() {
        Some("vulnerable") => PqcStatus::Vulnerable,
        Some("hybrid") => PqcStatus::Hybrid,
        Some("resistant") => PqcStatus::Resistant,
        Some("symmetric_ok") => PqcStatus::SymmetricOk,
        _ => PqcStatus::Unknown,
    }
}

fn source_root_of(source_location: &str) -> String {
    // Strip line number suffix, then take the first path component as the root,
    // so duplicates of the same algorithm across the same module collapse.
    let path_only = source_location
        .rsplit_once(':')
        .map(|(p, _)| p)
        .unwrap_or(source_location);
    let comp = std::path::Path::new(path_only)
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_else(|| path_only.to_string());
    comp
}

fn finding_dedup_key(finding: &Finding) -> Result<FindingKey> {
    let kind = finding
        .evidence
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let source_root = source_root_of(&finding.source_location);

    match kind {
        "cert_or_keystore_file" => {
            // Cert/keystore files: fingerprint the bytes.
            let path = std::path::PathBuf::from(&finding.source_location);
            let bytes = fs::read(&path).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hex::encode(hasher.finalize());
            Ok(FindingKey {
                dedup_key: format!("cert:{}", digest),
                asset_type: AssetType::Certificate,
                algorithm_name: "x509".to_string(),
                pqc_status: PqcStatus::Unknown,
                primitive: None,
                key_size_bits: None,
                source_root,
                library_name: None,
            })
        }
        "algorithm_match" => {
            let algo = finding
                .evidence
                .get("algorithm_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let pqc = parse_pqc_status(finding.evidence.get("pqc_status").unwrap_or(&Value::Null));
            let params = finding
                .evidence
                .get("parameter_set")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
            let primitive = params
                .get("primitive")
                .and_then(|v| v.as_str())
                .and_then(parse_primitive);
            let key_size_bits = params.get("key_size_bits").and_then(|v| v.as_u64());

            let dedup_key = format!(
                "algo:{}:{}:{}",
                algo.to_ascii_lowercase(),
                key_size_bits
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "_".to_string()),
                source_root
            );
            Ok(FindingKey {
                dedup_key,
                asset_type: AssetType::Algorithm,
                algorithm_name: algo,
                pqc_status: pqc,
                primitive,
                key_size_bits,
                source_root,
                library_name: None,
            })
        }
        "library_import" => {
            let lib = finding
                .evidence
                .get("library_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let dedup_key = format!("lib:{}:{}", lib.to_ascii_lowercase(), source_root);
            Ok(FindingKey {
                dedup_key,
                asset_type: AssetType::LibraryDependency,
                algorithm_name: lib.clone(),
                pqc_status: PqcStatus::Unknown,
                primitive: None,
                key_size_bits: None,
                source_root,
                library_name: Some(lib),
            })
        }
        "tls_certificate" => {
            let fp = finding
                .evidence
                .get("fingerprint_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Ok(FindingKey {
                dedup_key: format!("cert:{}", fp),
                asset_type: AssetType::Certificate,
                algorithm_name: finding
                    .evidence
                    .get("signature_algorithm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("x509")
                    .to_string(),
                pqc_status: parse_pqc_status(
                    finding.evidence.get("pqc_status").unwrap_or(&Value::Null),
                ),
                primitive: Some(Primitive::Signature),
                key_size_bits: finding
                    .evidence
                    .get("public_key_bits")
                    .and_then(|v| v.as_u64()),
                source_root,
                library_name: None,
            })
        }
        "tls_endpoint" => {
            let suite = finding
                .evidence
                .get("cipher_suite")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(FindingKey {
                dedup_key: format!("tls_endpoint:{}:{}", finding.source_location, suite),
                asset_type: AssetType::ProtocolEndpoint,
                algorithm_name: suite.to_string(),
                pqc_status: parse_pqc_status(
                    finding.evidence.get("pqc_status").unwrap_or(&Value::Null),
                ),
                primitive: None,
                key_size_bits: None,
                source_root: source_root.clone(),
                library_name: None,
            })
        }
        "tls_supported_group" => {
            let group = finding
                .evidence
                .get("group")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(FindingKey {
                dedup_key: format!("tls_group:{}:{}", finding.source_location, group),
                asset_type: AssetType::ProtocolEndpoint,
                algorithm_name: group.to_string(),
                pqc_status: parse_pqc_status(
                    finding.evidence.get("pqc_status").unwrap_or(&Value::Null),
                ),
                primitive: Some(Primitive::Kem),
                key_size_bits: None,
                source_root: source_root.clone(),
                library_name: None,
            })
        }
        _ => Ok(FindingKey {
            dedup_key: format!("other:{}", finding.source_location),
            asset_type: AssetType::Algorithm,
            algorithm_name: "unknown".to_string(),
            pqc_status: PqcStatus::Unknown,
            primitive: None,
            key_size_bits: None,
            source_root,
            library_name: None,
        }),
    }
}

fn asset_dedup_key(asset: &CryptoAsset, source_root_override: Option<&str>) -> String {
    let key_size = asset
        .parameter_set
        .get("key_size_bits")
        .and_then(|v| v.as_u64());
    let root = source_root_override
        .map(str::to_string)
        .or_else(|| {
            asset
                .parameter_set
                .get("source_root")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "_".to_string());

    match asset.asset_type {
        AssetType::Algorithm => format!(
            "algo:{}:{}:{}",
            asset.algorithm_name.to_ascii_lowercase(),
            key_size
                .map(|b| b.to_string())
                .unwrap_or_else(|| "_".to_string()),
            root
        ),
        AssetType::Certificate => format!(
            "cert:{}",
            asset
                .parameter_set
                .get("fingerprint_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or(&asset.name)
        ),
        AssetType::LibraryDependency => {
            format!("lib:{}:{}", asset.algorithm_name.to_ascii_lowercase(), root)
        }
        AssetType::ProtocolEndpoint => {
            let kind = if asset.parameter_set.get("kind").and_then(|v| v.as_str())
                == Some("tls_supported_group")
            {
                "tls_group"
            } else {
                "tls_endpoint"
            };
            format!(
                "{}:{}:{}",
                kind,
                asset
                    .parameter_set
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&asset.name),
                asset.algorithm_name
            )
        }
        AssetType::Key => format!("key:{}", asset.name),
    }
}

fn migration_difficulty_for(asset_type: AssetType, pqc_status: PqcStatus) -> MigrationDifficulty {
    match (asset_type, pqc_status) {
        (AssetType::Certificate, _) => MigrationDifficulty::Medium,
        (AssetType::Key, _) => MigrationDifficulty::Medium,
        (AssetType::LibraryDependency, _) => MigrationDifficulty::Low,
        (AssetType::ProtocolEndpoint, _) => MigrationDifficulty::Medium,
        (AssetType::Algorithm, PqcStatus::SymmetricOk) => MigrationDifficulty::Trivial,
        (AssetType::Algorithm, PqcStatus::Resistant) => MigrationDifficulty::Trivial,
        (AssetType::Algorithm, _) => MigrationDifficulty::Medium,
    }
}

fn build_asset_from_finding(finding: &Finding, key: FindingKey) -> Result<CryptoAsset> {
    let now = OffsetDateTime::now_utc();
    let quantum_vulnerable = matches!(
        key.pqc_status,
        PqcStatus::Vulnerable | PqcStatus::Unknown | PqcStatus::Hybrid
    );
    let mig_diff = migration_difficulty_for(key.asset_type, key.pqc_status);
    let display_name = match key.asset_type {
        AssetType::LibraryDependency => key
            .library_name
            .clone()
            .unwrap_or_else(|| key.algorithm_name.clone()),
        AssetType::Certificate => finding.source_location.clone(),
        AssetType::ProtocolEndpoint => format!("{}@{}", key.algorithm_name, key.source_root),
        _ => key.algorithm_name.clone(),
    };

    let mut params = serde_json::Map::new();
    if let Some(b) = key.key_size_bits {
        params.insert("key_size_bits".to_string(), Value::from(b));
    }
    if let Some(p) = key.primitive {
        params.insert(
            "primitive".to_string(),
            Value::from(format!("{:?}", p).to_ascii_lowercase()),
        );
    }
    params.insert(
        "source_root".to_string(),
        Value::from(key.source_root.clone()),
    );
    if let Some(extra) = finding
        .evidence
        .get("parameter_set")
        .and_then(|v| v.as_object())
    {
        for (k, v) in extra.iter() {
            params.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    if let Some(target) = finding.evidence.get("target").and_then(|v| v.as_str()) {
        params.insert("target".to_string(), Value::from(target.to_string()));
    }
    if let Some(fp) = finding
        .evidence
        .get("fingerprint_sha256")
        .and_then(|v| v.as_str())
    {
        params.insert(
            "fingerprint_sha256".to_string(),
            Value::from(fp.to_string()),
        );
    }

    let mut asset = CryptoAsset::new(
        key.asset_type,
        key.algorithm_name,
        display_name,
        key.pqc_status,
        quantum_vulnerable,
        mig_diff,
    );
    asset.primitive = key.primitive;
    asset.parameter_set = Value::Object(params);
    asset.first_seen_at = now;
    asset.last_seen_at = now;
    Ok(asset)
}

/// Convenience: run dedup against the workspace inventory file and persist.
pub fn promote_into_workspace(
    scan: &mut Scan,
    ws: &crate::workspace::Workspace,
) -> Result<Vec<CryptoAsset>> {
    let inventory = crate::storage::load_inventory(ws)?;
    let updated = promote_findings(scan, inventory)?;
    crate::storage::save_inventory(ws, &updated)?;
    Ok(updated)
}

// Helper for tests in other modules.
pub fn _path_to_string(p: &Path) -> String {
    p.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::{Confidence, Finding, SourceType};
    use crate::model::scan::{Scan, ScanType};
    use serde_json::json;
    use uuid::Uuid;

    fn make_scan_with(findings: Vec<Finding>) -> Scan {
        let mut s = Scan::new("t".into(), ScanType::Codebase, "x".into());
        s.findings = findings;
        s
    }

    fn algo_finding(
        scan_id: Uuid,
        algo: &str,
        status: &str,
        src: &str,
        bits: Option<u64>,
    ) -> Finding {
        let mut params = serde_json::Map::new();
        if let Some(b) = bits {
            params.insert("key_size_bits".into(), json!(b));
        }
        let ev = json!({
            "kind": "algorithm_match",
            "algorithm_name": algo,
            "pqc_status": status,
            "parameter_set": params,
        });
        Finding::new(scan_id, SourceType::File, src.into(), ev, Confidence::High)
    }

    #[test]
    fn first_run_creates_inventory_entries() {
        let mut scan = make_scan_with(vec![]);
        let scan_id = scan.id;
        scan.findings = vec![
            algo_finding(scan_id, "MD5", "vulnerable", "src/a.rs:10", None),
            algo_finding(scan_id, "AES-256", "symmetric_ok", "src/b.rs:5", Some(256)),
        ];
        let inv = promote_findings(&mut scan, vec![]).unwrap();
        assert_eq!(inv.len(), 2);
        assert!(scan.findings.iter().all(|f| f.crypto_asset_id.is_some()));
    }

    #[test]
    fn second_run_does_not_duplicate() {
        let mut scan1 = make_scan_with(vec![]);
        let sid = scan1.id;
        scan1.findings = vec![algo_finding(
            sid,
            "RSA",
            "vulnerable",
            "src/a.rs:1",
            Some(2048),
        )];
        let inv = promote_findings(&mut scan1, vec![]).unwrap();
        assert_eq!(inv.len(), 1);

        let mut scan2 = make_scan_with(vec![]);
        let sid2 = scan2.id;
        scan2.findings = vec![algo_finding(
            sid2,
            "RSA",
            "vulnerable",
            "src/a.rs:1",
            Some(2048),
        )];
        let inv2 = promote_findings(&mut scan2, inv).unwrap();
        assert_eq!(inv2.len(), 1, "second run should not add a duplicate");
    }

    #[test]
    fn user_set_fields_preserved_on_rescan() {
        let mut scan1 = make_scan_with(vec![]);
        let sid = scan1.id;
        scan1.findings = vec![algo_finding(
            sid,
            "RSA",
            "vulnerable",
            "src/a.rs:1",
            Some(2048),
        )];
        let mut inv = promote_findings(&mut scan1, vec![]).unwrap();
        // User annotates.
        inv[0].notes = Some("Owned by Payments team".into());
        inv[0].migration_status = crate::model::asset::MigrationStatus::InProgress;

        let mut scan2 = make_scan_with(vec![]);
        let sid2 = scan2.id;
        scan2.findings = vec![algo_finding(
            sid2,
            "RSA",
            "vulnerable",
            "src/a.rs:1",
            Some(2048),
        )];
        let inv2 = promote_findings(&mut scan2, inv).unwrap();
        assert_eq!(inv2.len(), 1);
        assert_eq!(inv2[0].notes.as_deref(), Some("Owned by Payments team"));
        assert!(matches!(
            inv2[0].migration_status,
            crate::model::asset::MigrationStatus::InProgress
        ));
    }
}
