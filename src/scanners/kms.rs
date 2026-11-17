//! Cloud KMS listing scanner. Parses JSON the user exports from the AWS,
//! Azure or Google Cloud CLIs. Boab makes no cloud calls.
//!
//! Supported exports:
//!
//! - AWS: `aws kms list-keys` and `aws kms describe-key` (one or many
//!   documents per file, or a JSON array of them).
//! - Azure: `az keyvault key list` and `az keyvault key show`.
//! - Google Cloud: `gcloud kms keys list --format=json`.
//!
//! Only key metadata is recorded: provider, id, ARN or URI, key spec,
//! algorithm, size, usage, state and protection level. Public key components
//! that Azure includes in `key show` (`n`, `x`) are used to work out the key
//! size and are then dropped. Descriptions, tags and labels are not recorded.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use super::{HostAsset, KIND_KMS_KEY};
use crate::model::asset::PqcStatus;
use crate::model::finding::{Confidence, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Aws,
    Azure,
    Gcp,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Azure => "azure",
            Provider::Gcp => "gcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aws" => Some(Provider::Aws),
            "azure" => Some(Provider::Azure),
            "gcp" | "google" => Some(Provider::Gcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KmsOptions {
    /// Force the provider instead of detecting it from each file's shape.
    pub provider: Option<Provider>,
    pub name: Option<String>,
}

/// One KMS key, normalised across providers. Metadata only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KmsKey {
    pub provider: Option<Provider>,
    /// Provider key id: AWS KeyId, Azure key URI without version, GCP key resource name.
    pub key_id: String,
    /// Full identifier: AWS key ARN, Azure key URI, GCP key resource name.
    pub key_ref: String,
    /// Account and region, vault, or project/location/key ring.
    pub scope: String,
    pub key_spec: Option<String>,
    pub key_usage: Option<String>,
    pub key_state: Option<String>,
    pub enabled: Option<bool>,
    pub protection_level: Option<String>,
    pub key_manager: Option<String>,
    pub origin: Option<String>,
    pub key_size_bits: Option<u64>,
    pub curve: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub version: Option<String>,
    /// Which export(s) the key was seen in, e.g. `describe-key`.
    pub sources: Vec<String>,
}

pub fn scan_files(files: &[PathBuf], options: &KmsOptions) -> Result<Scan> {
    if files.is_empty() {
        return Err(anyhow!("no KMS listing files given"));
    }
    let target = files
        .iter()
        .map(|f| f.display().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut scan = Scan::new(
        options
            .name
            .clone()
            .unwrap_or_else(|| format!("kms:{}", target)),
        ScanType::KmsListing,
        target,
    );
    scan.status = ScanStatus::Running;

    // Merge the same key seen in several exports (list + describe/show).
    let mut keys: BTreeMap<(String, String), KmsKey> = BTreeMap::new();
    let mut per_file = Vec::new();
    for file in files {
        let raw = fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
        let parsed = parse_listing(&raw, options.provider)
            .with_context(|| format!("parse KMS listing {}", file.display()))?;
        per_file.push(json!({ "file": file.display().to_string(), "keys": parsed.len() }));
        for k in parsed {
            let provider = k.provider.map(Provider::as_str).unwrap_or("").to_string();
            match keys.entry((provider, k.key_id.clone())) {
                std::collections::btree_map::Entry::Occupied(mut e) => merge(e.get_mut(), k),
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(k);
                }
            }
        }
    }
    scan.config = json!({
        "provider": options.provider.map(Provider::as_str),
        "files": per_file,
    });

    let scan_id = scan.id;
    for key in keys.values() {
        scan.findings.push(key_finding(key).into_finding(
            scan_id,
            SourceType::Url,
            if key.key_spec.is_some() {
                Confidence::High
            } else {
                Confidence::Medium
            },
        ));
    }
    scan.status = ScanStatus::Completed;
    scan.completed_at = Some(OffsetDateTime::now_utc());
    Ok(scan)
}

fn merge(into: &mut KmsKey, from: KmsKey) {
    macro_rules! fill {
        ($($f:ident),*) => { $( if into.$f.is_none() { into.$f = from.$f; } )* };
    }
    fill!(
        key_spec,
        key_usage,
        key_state,
        enabled,
        protection_level,
        key_manager,
        origin,
        key_size_bits,
        curve,
        created,
        expires,
        version
    );
    // Prefer the longer reference (an ARN over a bare id).
    if from.key_ref.len() > into.key_ref.len() {
        into.key_ref = from.key_ref;
    }
    if into.scope.is_empty() {
        into.scope = from.scope;
    }
    for s in from.sources {
        if !into.sources.contains(&s) {
            into.sources.push(s);
        }
    }
}

/// Parse one exported file. Accepts a single JSON document, a JSON array, or
/// several JSON documents back to back (a shell loop over `describe-key`).
pub fn parse_listing(raw: &str, provider: Option<Provider>) -> Result<Vec<KmsKey>> {
    let mut docs = Vec::new();
    for v in serde_json::Deserializer::from_str(raw).into_iter::<Value>() {
        docs.push(v.context("invalid JSON")?);
    }
    if docs.is_empty() {
        return Err(anyhow!("file contains no JSON"));
    }
    let mut out = Vec::new();
    for doc in docs {
        let items: Vec<Value> = match doc {
            Value::Array(a) => a,
            other => vec![other],
        };
        for item in items {
            let p = match provider {
                Some(p) => p,
                None => detect(&item).ok_or_else(|| {
                    anyhow!("could not tell which cloud this listing is from; pass --provider")
                })?,
            };
            match p {
                Provider::Aws => out.extend(parse_aws(&item)),
                Provider::Azure => out.extend(parse_azure(&item)),
                Provider::Gcp => out.extend(parse_gcp(&item)),
            }
        }
    }
    Ok(out)
}

fn detect(v: &Value) -> Option<Provider> {
    if v.get("KeyMetadata").is_some() || v.get("Keys").is_some() || v.get("KeyArn").is_some() {
        return Some(Provider::Aws);
    }
    if v.get("kid").is_some() || v.pointer("/key/kid").is_some() {
        return Some(Provider::Azure);
    }
    if v.get("name")
        .and_then(Value::as_str)
        .is_some_and(|n| n.starts_with("projects/") && n.contains("/cryptoKeys/"))
    {
        return Some(Provider::Gcp);
    }
    None
}

fn s(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

// --- AWS -------------------------------------------------------------------

fn parse_aws(v: &Value) -> Vec<KmsKey> {
    if let Some(keys) = v.get("Keys").and_then(Value::as_array) {
        return keys.iter().filter_map(aws_list_entry).collect();
    }
    if let Some(m) = v.get("KeyMetadata") {
        return aws_metadata(m).into_iter().collect();
    }
    if v.get("KeyArn").is_some() || v.get("KeyId").is_some() {
        if v.get("KeySpec").is_some() || v.get("KeyUsage").is_some() {
            return aws_metadata(v).into_iter().collect();
        }
        return aws_list_entry(v).into_iter().collect();
    }
    Vec::new()
}

fn aws_scope(arn: &str, account: Option<&str>) -> String {
    // arn:aws:kms:<region>:<account>:key/<id>
    let parts: Vec<&str> = arn.split(':').collect();
    let region = parts.get(3).copied().unwrap_or("");
    let acct = account.or(parts.get(4).copied()).unwrap_or("");
    format!("aws:{}:{}", acct, region)
}

fn aws_list_entry(v: &Value) -> Option<KmsKey> {
    let key_id = s(v, "KeyId")?;
    let arn = s(v, "KeyArn").unwrap_or_else(|| key_id.clone());
    Some(KmsKey {
        provider: Some(Provider::Aws),
        scope: aws_scope(&arn, None),
        key_id,
        key_ref: arn,
        sources: vec!["list-keys".into()],
        ..Default::default()
    })
}

fn aws_metadata(m: &Value) -> Option<KmsKey> {
    let key_id = s(m, "KeyId")?;
    let arn = s(m, "Arn").unwrap_or_else(|| key_id.clone());
    let spec = s(m, "KeySpec").or_else(|| s(m, "CustomerMasterKeySpec"));
    Some(KmsKey {
        provider: Some(Provider::Aws),
        scope: aws_scope(&arn, s(m, "AWSAccountId").as_deref()),
        key_id,
        key_ref: arn,
        key_usage: s(m, "KeyUsage"),
        key_state: s(m, "KeyState"),
        enabled: m.get("Enabled").and_then(Value::as_bool),
        protection_level: s(m, "Origin").map(|o| match o.as_str() {
            "AWS_CLOUDHSM" => "HSM (CloudHSM)".to_string(),
            "EXTERNAL_KEY_STORE" => "EXTERNAL".to_string(),
            _ => "HSM (AWS KMS)".to_string(),
        }),
        key_manager: s(m, "KeyManager"),
        origin: s(m, "Origin"),
        created: aws_time(m.get("CreationDate")),
        expires: aws_time(m.get("ValidTo")),
        key_spec: spec,
        sources: vec!["describe-key".into()],
        ..Default::default()
    })
}

/// AWS CLI prints timestamps as ISO 8601 strings, or as epoch seconds with
/// `--cli-timestamp-format none`.
fn aws_time(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => n
            .as_f64()
            .and_then(|f| OffsetDateTime::from_unix_timestamp(f as i64).ok())
            .and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
        _ => None,
    }
}

// --- Azure -----------------------------------------------------------------

fn parse_azure(v: &Value) -> Vec<KmsKey> {
    // `key show` nests the JWK under "key"; `key list` items carry "kid".
    let (jwk, source) = match v.get("key") {
        Some(k) if k.get("kid").is_some() => (k, "key show"),
        _ => (v, "key list"),
    };
    let Some(kid) = s(jwk, "kid") else {
        return Vec::new();
    };
    let (key_id, version) = azure_split_kid(&kid);
    let vault = kid
        .split("//")
        .nth(1)
        .and_then(|h| h.split('/').next())
        .and_then(|h| h.split('.').next())
        .unwrap_or("")
        .to_string();
    let kty = s(jwk, "kty");
    let attrs = v.get("attributes").cloned().unwrap_or(Value::Null);
    let enabled = attrs.get("enabled").and_then(Value::as_bool);
    let ops = jwk
        .get("keyOps")
        .or_else(|| jwk.get("key_ops"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|s| !s.is_empty());
    // Public modulus / coordinate length gives the size. The values are not kept.
    let b64len = |k: &str| {
        s(jwk, k).and_then(|x| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x.trim_end_matches('='))
                .ok()
                .map(|b| b.len())
        })
    };
    let curve = s(jwk, "crv");
    let size = match kty.as_deref() {
        Some(t) if t.starts_with("RSA") => b64len("n").map(|n| {
            let n = n as u64 * 8;
            // Round to the usual sizes in case of a leading zero byte.
            [2048, 3072, 4096]
                .into_iter()
                .find(|b| n <= *b && n + 8 >= *b)
                .unwrap_or(n)
        }),
        Some(t) if t.starts_with("EC") => curve.as_deref().and_then(curve_bits),
        _ => s(jwk, "keySize")
            .or_else(|| s(jwk, "key_size"))
            .and_then(|k| k.parse().ok()),
    };
    vec![KmsKey {
        provider: Some(Provider::Azure),
        scope: format!("azure:{}", vault),
        key_id,
        key_ref: kid,
        protection_level: kty.as_deref().map(|t| {
            if t.ends_with("-HSM") {
                "HSM".to_string()
            } else {
                "SOFTWARE".to_string()
            }
        }),
        key_spec: kty,
        key_usage: ops,
        key_state: enabled.map(|e| if e { "Enabled" } else { "Disabled" }.to_string()),
        enabled,
        key_manager: v
            .get("managed")
            .and_then(Value::as_bool)
            .map(|m| if m { "AZURE" } else { "CUSTOMER" }.to_string()),
        key_size_bits: size,
        curve,
        created: s(&attrs, "created"),
        expires: s(&attrs, "expires"),
        version,
        sources: vec![source.into()],
        ..Default::default()
    }]
}

/// `https://v.vault.azure.net/keys/<name>/<version>` -> (URI without version, version).
fn azure_split_kid(kid: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = kid.trim_end_matches('/').split('/').collect();
    match parts.iter().position(|p| *p == "keys") {
        Some(i) if parts.len() > i + 2 => {
            (parts[..i + 2].join("/"), Some(parts[i + 2].to_string()))
        }
        _ => (kid.trim_end_matches('/').to_string(), None),
    }
}

fn curve_bits(c: &str) -> Option<u64> {
    match c {
        "P-256" | "P-256K" | "SECP256K1" => Some(256),
        "P-384" => Some(384),
        "P-521" => Some(521),
        _ => None,
    }
}

// --- Google Cloud ----------------------------------------------------------

fn parse_gcp(v: &Value) -> Vec<KmsKey> {
    let Some(name) = s(v, "name") else {
        return Vec::new();
    };
    // projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>
    let parts: Vec<&str> = name.split('/').collect();
    let part = |label: &str| {
        parts
            .iter()
            .position(|p| *p == label)
            .and_then(|i| parts.get(i + 1))
            .copied()
            .unwrap_or("")
    };
    let scope = format!(
        "gcp:{}/{}/{}",
        part("projects"),
        part("locations"),
        part("keyRings")
    );
    let primary = v.get("primary").cloned().unwrap_or(Value::Null);
    let template = v.get("versionTemplate").cloned().unwrap_or(Value::Null);
    let algorithm = s(&primary, "algorithm").or_else(|| s(&template, "algorithm"));
    let state = s(&primary, "state");
    vec![KmsKey {
        provider: Some(Provider::Gcp),
        scope,
        key_id: name.clone(),
        key_ref: name,
        key_usage: s(v, "purpose"),
        enabled: state.as_deref().map(|st| st == "ENABLED"),
        key_state: state,
        protection_level: s(&primary, "protectionLevel")
            .or_else(|| s(&template, "protectionLevel")),
        created: s(v, "createTime"),
        expires: s(&primary, "destroyTime"),
        version: s(&primary, "name").and_then(|n| n.rsplit('/').next().map(str::to_string)),
        key_spec: algorithm,
        sources: vec!["keys list".into()],
        ..Default::default()
    }]
}

// --- Classification ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct KmsAlgorithm {
    pub name: String,
    pub status: PqcStatus,
    pub primitive: &'static str,
    pub bits: Option<u64>,
    /// True for symmetric and MAC keys (no public half).
    pub symmetric: bool,
}

/// Map a provider key spec to Boab's canonical algorithm name.
pub fn classify(key: &KmsKey) -> KmsAlgorithm {
    use PqcStatus::*;
    let spec = key.key_spec.clone().unwrap_or_default();
    let up = spec.to_ascii_uppercase();
    let usage = key
        .key_usage
        .clone()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let agree = usage.contains("KEY_AGREEMENT");
    let a = |name: &str, status, primitive, bits: Option<u64>, symmetric| KmsAlgorithm {
        name: name.to_string(),
        status,
        primitive,
        bits,
        symmetric,
    };
    let digits = |s: &str| -> Option<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter_map(|d| d.parse::<u64>().ok())
            .find(|n| matches!(n, 1024 | 2048 | 3072 | 4096))
    };
    let ec = |bits: Option<u64>, label: &str| {
        let base = if agree { "ECDH" } else { "ECDSA" };
        let name = match bits {
            Some(256) if label.contains("K1") => format!("{}-secp256k1", base),
            Some(b) => format!("{}-P{}", base, b),
            None => base.to_string(),
        };
        a(
            &name,
            Vulnerable,
            if agree { "key_agreement" } else { "signature" },
            bits,
            false,
        )
    };

    if spec.is_empty() {
        return a("unknown", Unknown, "signature", key.key_size_bits, false);
    }
    // Post-quantum and hybrid first: names such as KEM_XWING contain no RSA/EC hint.
    if up.contains("XWING") {
        return a("X-Wing", Hybrid, "kem", None, false);
    }
    for (needle, name, prim) in [
        ("ML_DSA_44", "ML-DSA-44", "signature"),
        ("ML_DSA_65", "ML-DSA-65", "signature"),
        ("ML_DSA_87", "ML-DSA-87", "signature"),
        ("ML_KEM_512", "ML-KEM-512", "kem"),
        ("ML_KEM_768", "ML-KEM-768", "kem"),
        ("ML_KEM_1024", "ML-KEM-1024", "kem"),
    ] {
        if up.contains(needle) {
            return a(name, Resistant, prim, None, false);
        }
    }
    if up.contains("SLH_DSA") {
        return a("SLH-DSA", Resistant, "signature", None, false);
    }
    if up == "SYMMETRIC_DEFAULT" || up == "GOOGLE_SYMMETRIC_ENCRYPTION" {
        return a("AES-256-GCM", SymmetricOk, "block_cipher", Some(256), true);
    }
    if let Some(rest) = up.strip_prefix("AES_") {
        let bits = rest.split('_').next().and_then(|b| b.parse().ok());
        let name = match bits {
            Some(b) => format!("AES-{}", b),
            None => "AES".to_string(),
        };
        return a(&name, SymmetricOk, "block_cipher", bits, true);
    }
    if up.starts_with("OCT") {
        let name = match key.key_size_bits {
            Some(b) => format!("AES-{}", b),
            None => "AES".to_string(),
        };
        return a(&name, SymmetricOk, "block_cipher", key.key_size_bits, true);
    }
    if up.starts_with("HMAC") {
        // AWS and GCP both spell these `HMAC_SHA256`; the digest size is the trailing number.
        let bits = up
            .rsplit('_')
            .next()
            .map(|b| b.trim_start_matches("SHA"))
            .and_then(|b| b.parse::<u64>().ok());
        let name = match bits {
            Some(b) => format!("HMAC-SHA{}", b),
            None => "HMAC".to_string(),
        };
        return a(&name, SymmetricOk, "mac", bits, true);
    }
    if up.contains("RSA") {
        let bits = digits(&up).or(key.key_size_bits);
        let prim = if up.contains("DECRYPT") || usage.contains("ENCRYPT") {
            "pke"
        } else {
            "signature"
        };
        return a("RSA", Vulnerable, prim, bits, false);
    }
    if up.contains("ED25519") {
        return a("Ed25519", Vulnerable, "signature", Some(256), false);
    }
    if up.contains("SECP256K1") || up.contains("P256K") {
        return ec(Some(256), "K1");
    }
    if up == "SM2" {
        return a("SM2", Vulnerable, "signature", Some(256), false);
    }
    if up.starts_with("EC") {
        let bits = if up.contains("P256") || up.contains("P_256") {
            Some(256)
        } else if up.contains("P384") || up.contains("P_384") {
            Some(384)
        } else if up.contains("P521") || up.contains("P_521") {
            Some(521)
        } else {
            key.key_size_bits
                .or_else(|| key.curve.as_deref().and_then(curve_bits))
        };
        return ec(bits, &up);
    }
    a(&spec, Unknown, "signature", key.key_size_bits, false)
}

fn key_finding(key: &KmsKey) -> HostAsset<'_> {
    let alg = classify(key);
    let provider = key.provider.map(Provider::as_str).unwrap_or("unknown");
    let mut extra = Map::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            extra.insert(k.into(), Value::from(v));
        }
    };
    put("provider", Some(provider.to_string()));
    put("key_id", Some(key.key_id.clone()));
    put("key_ref", Some(key.key_ref.clone()));
    put("key_spec", key.key_spec.clone());
    put("key_usage", key.key_usage.clone());
    put("key_state", key.key_state.clone());
    put("protection_level", key.protection_level.clone());
    put("key_manager", key.key_manager.clone());
    put("origin", key.origin.clone());
    put("curve", key.curve.clone());
    put("created", key.created.clone());
    put("expires", key.expires.clone());
    put("key_version", key.version.clone());
    if let Some(e) = key.enabled {
        extra.insert("enabled".into(), Value::from(e));
    }
    extra.insert("symmetric".into(), Value::from(alg.symmetric));
    extra.insert("listing_sources".into(), json!(key.sources));
    HostAsset {
        kind: KIND_KMS_KEY,
        host: &key.scope,
        location: &key.key_ref,
        asset_name: key.key_ref.clone(),
        algorithm_name: alg.name,
        pqc_status: alg.status,
        primitive: Some(alg.primitive),
        key_size_bits: alg.bits,
        extra,
    }
}

/// Convenience for tests and callers holding a single path.
pub fn scan_file(path: &Path, options: &KmsOptions) -> Result<Scan> {
    scan_files(&[path.to_path_buf()], options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(spec: &str, usage: &str) -> KmsKey {
        KmsKey {
            key_spec: Some(spec.into()),
            key_usage: Some(usage.into()),
            ..Default::default()
        }
    }

    #[test]
    fn classifies_provider_specs() {
        let c = classify(&key("RSA_3072", "SIGN_VERIFY"));
        assert_eq!(
            (c.name.as_str(), c.bits, c.status),
            ("RSA", Some(3072), PqcStatus::Vulnerable)
        );
        let c = classify(&key("ECC_NIST_P384", "KEY_AGREEMENT"));
        assert_eq!(c.name, "ECDH-P384");
        let c = classify(&key("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT"));
        assert_eq!(c.status, PqcStatus::SymmetricOk);
        let c = classify(&key("ML_DSA_65", "SIGN_VERIFY"));
        assert_eq!(
            (c.name.as_str(), c.status),
            ("ML-DSA-65", PqcStatus::Resistant)
        );
        let c = classify(&key("EC_SIGN_P256_SHA256", "ASYMMETRIC_SIGN"));
        assert_eq!(c.name, "ECDSA-P256");
        let c = classify(&key("RSA_DECRYPT_OAEP_4096_SHA256", "ASYMMETRIC_DECRYPT"));
        assert_eq!((c.bits, c.primitive), (Some(4096), "pke"));
        let c = classify(&key("HMAC_SHA256", "MAC"));
        assert_eq!(c.name, "HMAC-SHA256");
        let c = classify(&key("KEM_XWING", "KEY_ENCAPSULATION"));
        assert_eq!(c.status, PqcStatus::Hybrid);
    }

    #[test]
    fn azure_kid_split() {
        assert_eq!(
            azure_split_kid("https://v.vault.azure.net/keys/k1/abc123"),
            (
                "https://v.vault.azure.net/keys/k1".to_string(),
                Some("abc123".to_string())
            )
        );
        assert_eq!(
            azure_split_kid("https://v.vault.azure.net/keys/k1").0,
            "https://v.vault.azure.net/keys/k1"
        );
    }

    #[test]
    fn concatenated_documents_parse() {
        let raw = r#"{"KeyMetadata":{"KeyId":"a","Arn":"arn:aws:kms:ap-southeast-2:111122223333:key/a","KeySpec":"RSA_2048","KeyUsage":"SIGN_VERIFY"}}
{"KeyMetadata":{"KeyId":"b","Arn":"arn:aws:kms:ap-southeast-2:111122223333:key/b","KeySpec":"SYMMETRIC_DEFAULT"}}"#;
        let keys = parse_listing(raw, None).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].scope, "aws:111122223333:ap-southeast-2");
    }

    #[test]
    fn unknown_shape_needs_provider() {
        assert!(parse_listing(r#"{"foo":1}"#, None).is_err());
    }
}
