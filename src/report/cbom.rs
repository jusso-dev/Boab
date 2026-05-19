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
