//! CycloneDX 1.6 CBOM JSON report.
//!
//! Conforms to CycloneDX 1.6: `bomFormat`, `specVersion`, `serialNumber`,
//! `metadata`, `components[].type = "cryptographic-asset"` with the
//! `cryptoProperties` sub-object populated for each asset type.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::asset::{AssetType, CryptoAsset, PqcStatus};
use crate::storage;
use crate::workspace::Workspace;

pub fn write(ws: &Workspace, out: &Path) -> Result<()> {
    let inventory = storage::load_inventory(ws)?;
    let bom = build_bom(&inventory)?;
    let s = serde_json::to_string_pretty(&bom).context("serialise CBOM")?;
    if let Some(parent) = out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(out, s).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

pub fn build_bom(inventory: &[CryptoAsset]) -> Result<Value> {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let mut components = Vec::with_capacity(inventory.len());
    for asset in inventory {
        components.push(component_for(asset));
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "boab",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                ]
            }
        },
        "components": components
    }))
}

fn component_for(asset: &CryptoAsset) -> Value {
    if let Some(kind) = host_crypto_kind(asset) {
        return host_crypto_component(asset, kind);
    }
    let bom_ref = format!("boab:{}", asset.id);
    let mut crypto_props = serde_json::Map::new();
    match asset.asset_type {
        AssetType::Algorithm => {
            crypto_props.insert("assetType".into(), Value::String("algorithm".into()));
            crypto_props.insert("algorithmProperties".into(), algorithm_properties(asset));
        }
        AssetType::Certificate => {
            crypto_props.insert("assetType".into(), Value::String("certificate".into()));
            crypto_props.insert(
                "certificateProperties".into(),
                certificate_properties(asset),
            );
        }
        AssetType::Key => {
            crypto_props.insert(
                "assetType".into(),
                Value::String("related-crypto-material".into()),
            );
            crypto_props.insert(
                "relatedCryptoMaterialProperties".into(),
                related_material_properties(asset),
            );
        }
        AssetType::ProtocolEndpoint => {
            crypto_props.insert("assetType".into(), Value::String("protocol".into()));
            crypto_props.insert("protocolProperties".into(), protocol_properties(asset));
        }
        AssetType::LibraryDependency => {
            crypto_props.insert("assetType".into(), Value::String("algorithm".into()));
            crypto_props.insert("algorithmProperties".into(), algorithm_properties(asset));
        }
    }
    crypto_props.insert(
        "oid".into(),
        Value::String(asset.algorithm_oid.clone().unwrap_or_default()),
    );
    json!({
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": asset.name,
        "description": asset.description,
        "cryptoProperties": crypto_props,
    })
}

fn primitive_str(p: Option<crate::model::asset::Primitive>) -> &'static str {
    use crate::model::asset::Primitive::*;
    match p {
        Some(BlockCipher) => "block-cipher",
        Some(StreamCipher) => "stream-cipher",
        Some(Hash) => "hash",
        Some(Signature) => "signature",
        Some(KeyAgreement) => "key-agree",
        Some(Kem) => "kem",
        Some(Pke) => "pke",
        Some(Mac) => "mac",
        Some(Drbg) => "drbg",
        None => "unknown",
    }
}

fn nist_quantum_security_level(asset: &CryptoAsset) -> u32 {
    if matches!(asset.pqc_status, PqcStatus::Vulnerable | PqcStatus::Unknown) {
        return 0;
    }
    let algo = asset.algorithm_name.to_ascii_lowercase();
    if algo.contains("ml-kem-512") || algo.contains("mlkem-512") || algo.contains("kyber512") {
        return 1;
    }
    if algo.contains("ml-kem-768") || algo.contains("mlkem-768") || algo.contains("kyber768") {
        return 3;
    }
    if algo.contains("ml-kem-1024") || algo.contains("mlkem-1024") || algo.contains("kyber1024") {
        return 5;
    }
    if algo.contains("ml-dsa-44") || algo.contains("dilithium2") {
        return 2;
    }
    if algo.contains("ml-dsa-65") || algo.contains("dilithium3") {
        return 3;
    }
    if algo.contains("ml-dsa-87") || algo.contains("dilithium5") {
        return 5;
    }
    if matches!(asset.pqc_status, PqcStatus::SymmetricOk) {
        return 1;
    }
    if matches!(asset.pqc_status, PqcStatus::Resistant) {
        return 1;
    }
    0
}

fn algorithm_properties(asset: &CryptoAsset) -> Value {
    let primitive = primitive_str(asset.primitive);
    let parameter_set = asset
        .parameter_set
        .get("key_size_bits")
        .map(|b| format!("{} bits", b))
        .unwrap_or_else(|| asset.algorithm_name.clone());
    json!({
        "primitive": primitive,
        "parameterSetIdentifier": parameter_set,
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "generic",
        "certificationLevel": ["none"],
        "cryptoFunctions": ["generate", "verify"],
        "nistQuantumSecurityLevel": nist_quantum_security_level(asset)
    })
}

fn certificate_properties(asset: &CryptoAsset) -> Value {
    let subject = asset
        .parameter_set
        .get("subject")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| asset.name.clone());
    let issuer = asset
        .parameter_set
        .get("issuer")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    let nbf = asset
        .parameter_set
        .get("not_before_unix")
        .and_then(|v| v.as_i64())
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .and_then(|d| d.format(&Rfc3339).ok())
        .unwrap_or_default();
    let naf = asset
        .parameter_set
        .get("not_after_unix")
        .and_then(|v| v.as_i64())
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .and_then(|d| d.format(&Rfc3339).ok())
        .unwrap_or_default();
    json!({
        "subjectName": subject,
        "issuerName": issuer,
        "notValidBefore": nbf,
        "notValidAfter": naf,
        "signatureAlgorithmRef": asset.algorithm_name,
        "certificateFormat": "X.509"
    })
}

fn related_material_properties(asset: &CryptoAsset) -> Value {
    json!({
        "type": "key",
        "format": "raw",
        "size": asset
            .parameter_set
            .get("key_size_bits")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    })
}

fn protocol_properties(asset: &CryptoAsset) -> Value {
    let version = asset
        .parameter_set
        .get("tls_version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    json!({
        "type": "tls",
        "version": version,
        "cipherSuites": [
            { "name": asset.algorithm_name }
        ]
    })
}

// --- Host crypto, keystore and KMS assets -----------------------------------------
//
// These components carry extra, standard CycloneDX fields that the older asset
// kinds do not: a `properties` array (namespaced `boab:`) and
// `evidence.occurrences[].location`. The field list is the GRiCk import contract
// documented in docs/cbom.md; change both together.

fn host_crypto_kind(asset: &CryptoAsset) -> Option<&str> {
    asset
        .parameter_set
        .get("kind")
        .and_then(|v| v.as_str())
        .filter(|k| crate::scanners::HOST_CRYPTO_KINDS.contains(k))
}

fn param_str<'a>(asset: &'a CryptoAsset, key: &str) -> Option<&'a str> {
    asset
        .parameter_set
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn rfc3339(value: &str) -> Option<String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
}

fn unix_rfc3339(asset: &CryptoAsset, key: &str) -> Option<String> {
    asset
        .parameter_set
        .get(key)
        .and_then(|v| v.as_i64())
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .and_then(|d| d.format(&Rfc3339).ok())
}

/// CycloneDX `relatedCryptoMaterialProperties.type` for a key asset.
fn material_type(asset: &CryptoAsset, kind: &str) -> &'static str {
    match kind {
        crate::scanners::KIND_SSH_HOST_KEY => "public-key",
        crate::scanners::KIND_KEYSTORE_ENTRY => match param_str(asset, "entry_type") {
            Some("private_key") => "private-key",
            Some("secret_key") => "secret-key",
            _ => "public-key",
        },
        crate::scanners::KIND_KMS_KEY => {
            if asset
                .parameter_set
                .get("symmetric")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                "secret-key"
            } else {
                "private-key"
            }
        }
        _ => "key",
    }
}

/// CycloneDX key state for a provider's key state string.
fn material_state(asset: &CryptoAsset) -> Option<&'static str> {
    let state = param_str(asset, "key_state")?.to_ascii_lowercase();
    Some(match state.as_str() {
        "enabled" => "active",
        "disabled" => "suspended",
        "pendingimport" | "pending_import" | "pending_generation" | "creating" => "pre-activation",
        "pendingdeletion" | "pendingreplicadeletion" | "destroy_scheduled" | "unavailable" => {
            "deactivated"
        }
        "destroyed" => "destroyed",
        _ => return None,
    })
}

fn host_crypto_component(asset: &CryptoAsset, kind: &str) -> Value {
    let mut crypto = serde_json::Map::new();
    match asset.asset_type {
        AssetType::Key => {
            crypto.insert("assetType".into(), json!("related-crypto-material"));
            let mut m = serde_json::Map::new();
            m.insert("type".into(), json!(material_type(asset, kind)));
            let id = match kind {
                crate::scanners::KIND_KMS_KEY => param_str(asset, "key_ref"),
                crate::scanners::KIND_SSH_HOST_KEY => param_str(asset, "fingerprint_sha256"),
                _ => param_str(asset, "certificate_sha256"),
            };
            if let Some(id) = id {
                m.insert("id".into(), json!(id));
            }
            if let Some(state) = material_state(asset) {
                m.insert("state".into(), json!(state));
            }
            let created = match kind {
                crate::scanners::KIND_KMS_KEY => param_str(asset, "created").and_then(rfc3339),
                _ => unix_rfc3339(asset, "not_before_unix"),
            };
            let expires = match kind {
                crate::scanners::KIND_KMS_KEY => param_str(asset, "expires").and_then(rfc3339),
                _ => unix_rfc3339(asset, "not_after_unix"),
            };
            if let Some(c) = created {
                m.insert("creationDate".into(), json!(c));
            }
            if let Some(e) = expires {
                m.insert("expirationDate".into(), json!(e));
            }
            if let Some(size) = asset
                .parameter_set
                .get("key_size_bits")
                .and_then(|v| v.as_u64())
            {
                m.insert("size".into(), json!(size));
            }
            let format = match kind {
                crate::scanners::KIND_SSH_HOST_KEY => Some("OpenSSH"),
                crate::scanners::KIND_KEYSTORE_ENTRY => param_str(asset, "store_type"),
                _ => None,
            };
            if let Some(f) = format {
                m.insert("format".into(), json!(f));
            }
            crypto.insert("relatedCryptoMaterialProperties".into(), Value::Object(m));
        }
        AssetType::ProtocolEndpoint => {
            crypto.insert("assetType".into(), json!("protocol"));
            let mut suites: Vec<Value> = Vec::new();
            for key in ["ciphersuites", "groups"] {
                if let Some(list) = asset.parameter_set.get(key).and_then(|v| v.as_array()) {
                    if key == "ciphersuites" {
                        suites.extend(
                            list.iter()
                                .filter_map(|v| v.as_str())
                                .map(|n| json!({ "name": n })),
                        );
                    }
                }
            }
            if let Some(cs) = param_str(asset, "cipher_string") {
                suites.push(json!({ "name": cs }));
            }
            let version = param_str(asset, "min_protocol").unwrap_or("unknown");
            crypto.insert(
                "protocolProperties".into(),
                json!({
                    "type": if kind == crate::scanners::KIND_OPENSSL_CONFIG { "tls" } else { "other" },
                    "version": version,
                    "cipherSuites": suites,
                }),
            );
        }
        _ => {
            crypto.insert("assetType".into(), json!("algorithm"));
            crypto.insert("algorithmProperties".into(), algorithm_properties(asset));
        }
    }
    if let Some(oid) = asset
        .algorithm_oid
        .as_deref()
        .or_else(|| param_str(asset, "public_key_algorithm_oid"))
    {
        crypto.insert("oid".into(), json!(oid));
    }

    let location = param_str(asset, "location").unwrap_or_default();
    json!({
        "type": "cryptographic-asset",
        "bom-ref": format!("boab:{}", asset.id),
        "name": asset.name,
        "description": asset.description,
        "cryptoProperties": crypto,
        "evidence": { "occurrences": [ { "location": location } ] },
        "properties": host_crypto_properties(asset, kind),
    })
}

/// `boab:` properties, in a fixed order. Absent values are omitted. This is the
/// list GRiCk maps; see docs/cbom.md.
pub const HOST_CRYPTO_PROPERTY_FIELDS: &[&str] = &[
    // kind-specific parameter_set fields, copied as strings when present
    "provider",
    "key_id",
    "key_ref",
    "key_spec",
    "key_usage",
    "key_state",
    "protection_level",
    "key_manager",
    "alias",
    "store_type",
    "entry_type",
    "subject",
    "ssh_key_type",
    "fingerprint_sha256",
    "directive",
    "ssh_name",
    "policy",
    "min_protocol",
    "max_protocol",
    "cipher_string",
];

fn host_crypto_properties(asset: &CryptoAsset, kind: &str) -> Value {
    let mut props: Vec<Value> = Vec::new();
    let mut push = |name: &str, value: String| {
        props.push(json!({ "name": format!("boab:{}", name), "value": value }));
    };
    let asset_type = serde_json::to_value(asset.asset_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    push("asset_type", asset_type);
    push("kind", kind.to_string());
    push(
        "host",
        param_str(asset, "host").unwrap_or_default().to_string(),
    );
    push(
        "location",
        param_str(asset, "location").unwrap_or_default().to_string(),
    );
    push("algorithm", asset.algorithm_name.clone());
    push(
        "pqc_status",
        crate::scanners::pqc_status_str(asset.pqc_status).to_string(),
    );
    push("quantum_vulnerable", asset.quantum_vulnerable.to_string());
    if let Some(b) = asset
        .parameter_set
        .get("key_size_bits")
        .and_then(|v| v.as_u64())
    {
        push("key_size_bits", b.to_string());
    }
    if let Some(k) = param_str(asset, "asset_key") {
        push("asset_key", k.to_string());
    }
    for field in HOST_CRYPTO_PROPERTY_FIELDS {
        if let Some(v) = param_str(asset, field) {
            push(field, v.to_string());
        }
    }
    for list in ["allowed_protocols", "groups", "ciphersuites", "subpolicies"] {
        if let Some(a) = asset.parameter_set.get(list).and_then(|v| v.as_array()) {
            let joined: Vec<&str> = a.iter().filter_map(|v| v.as_str()).collect();
            if !joined.is_empty() {
                push(list, joined.join(","));
            }
        }
    }
    Value::Array(props)
}
