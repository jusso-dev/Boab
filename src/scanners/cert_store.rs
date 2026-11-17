//! Certificate store scanner. Walks a directory for PEM/DER/PKCS#12/JKS
//! certificates and parses each one with `x509-parser`.
//!
//! Keystores (PKCS#12, JKS, JCEKS) also produce one `keystore_entry` finding
//! per alias, with the key algorithm and size taken from the entry's
//! certificate public key. Private key bytes are never recorded or logged.
//!
//! How each format treats private key bytes:
//! - JKS and JCEKS: protected key blobs are skipped by length and never
//!   decrypted or decoded (`src/scanners/jks.rs`).
//! - PKCS#12: the `p12-keystore` importer decrypts shrouded key bags with the
//!   store password as part of parsing and holds the plaintext in memory until
//!   the store is dropped at the end of `parse_pkcs12`. Boab never reads those
//!   bytes (`PrivateKeyChain::key` is not called) and they never leave the
//!   function. Use a certificate-only truststore, or JKS, where even in-memory
//!   decryption is not acceptable.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::asset::PqcStatus;
use crate::model::finding::{Confidence, Finding, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};
use crate::scanners::{classify_public_key, HostAsset, KIND_KEYSTORE_ENTRY};

#[derive(Debug, Clone, Default)]
pub struct CertStoreOptions {
    pub password_file: Option<PathBuf>,
    pub name: Option<String>,
    /// Host label recorded on keystore entries. Defaults to the local host name.
    pub host: Option<String>,
}

const SUPPORTED_EXTS: &[&str] = &[
    "pem", "crt", "cer", "der", "p7b", "p12", "pfx", "jks", "jceks",
];

pub fn scan_path(path: &Path, options: &CertStoreOptions) -> Result<Scan> {
    let root = path
        .canonicalize()
        .with_context(|| format!("could not resolve cert store path {}", path.display()))?;
    let mut scan = Scan::new(
        options
            .name
            .clone()
            .unwrap_or_else(|| format!("certs:{}", root.display())),
        ScanType::CertificateStore,
        root.display().to_string(),
    );
    scan.status = ScanStatus::Running;
    scan.config = json!({
        "password_provided": options.password_file.is_some(),
    });

    let password = match &options.password_file {
        Some(p) => Some(load_password(p)?),
        None => None,
    };

    let host = options
        .host
        .clone()
        .unwrap_or_else(crate::scanners::local_host_label);
    let scan_id = scan.id;
    walk_files(&root, |file| {
        let ext = file
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase());
        let Some(ext) = ext else {
            return;
        };
        if !SUPPORTED_EXTS.contains(&ext.as_str()) {
            return;
        }
        match parse_cert_file(scan_id, file, ext.as_str(), password.as_deref(), &host) {
            Ok(mut fs) => scan.findings.append(&mut fs),
            Err(e) => tracing::debug!("skip {}: {}", file.display(), e),
        }
    });

    scan.status = ScanStatus::Completed;
    scan.completed_at = Some(OffsetDateTime::now_utc());
    Ok(scan)
}

fn load_password(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.trim().to_string())
}

fn walk_files<F: FnMut(&Path)>(root: &Path, mut f: F) {
    use ignore::WalkBuilder;
    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(false)
        .require_git(false)
        .build();
    for dent in walker.flatten() {
        if dent.file_type().map(|t| t.is_file()).unwrap_or(false) {
            f(dent.path());
        }
    }
}

fn parse_cert_file(
    scan_id: Uuid,
    file: &Path,
    ext: &str,
    _password: Option<&str>,
    _host: &str,
) -> Result<Vec<Finding>> {
    let bytes = fs::read(file).with_context(|| format!("read {}", file.display()))?;
    match ext {
        "pem" | "crt" | "cer" | "p7b" => parse_pem_blocks(scan_id, file, &bytes),
        "der" => parse_der(scan_id, file, &bytes),
        #[cfg(feature = "pkcs12")]
        "p12" | "pfx" => parse_pkcs12(scan_id, file, &bytes, _password, _host),
        #[cfg(not(feature = "pkcs12"))]
        "p12" | "pfx" => Ok(vec![keystore_placeholder(
            scan_id,
            file,
            "PKCS12 (feature disabled)",
        )]),
        // JKS and JCEKS are read by the in-tree parser. Anything it cannot
        // read still appears in the inventory as a placeholder.
        "jks" | "jceks" => match parse_jks(scan_id, file, &bytes, _password, _host) {
            Ok(f) => Ok(f),
            Err(e) => {
                tracing::debug!("JKS parse failed for {}: {}", file.display(), e);
                Ok(vec![keystore_placeholder(
                    scan_id,
                    file,
                    "JKS (could not be parsed; convert to PKCS12 with keytool)",
                )])
            }
        },
        _ => Ok(Vec::new()),
    }
}

#[allow(dead_code)]
fn keystore_placeholder(scan_id: Uuid, file: &Path, kind: &str) -> Finding {
    Finding::new(
        scan_id,
        SourceType::File,
        file.display().to_string(),
        json!({
            "kind": "cert_or_keystore_file",
            "store_type": kind,
        }),
        Confidence::Low,
    )
}

fn parse_pem_blocks(scan_id: Uuid, file: &Path, bytes: &[u8]) -> Result<Vec<Finding>> {
    use x509_parser::pem::Pem;
    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(bytes) {
        match pem {
            Ok(pem) => {
                let der = pem.contents.clone();
                if let Ok(f) = finding_from_der(scan_id, file, &der) {
                    out.push(f);
                }
            }
            Err(e) => {
                tracing::debug!("PEM read error in {}: {}", file.display(), e);
                break;
            }
        }
    }
    if out.is_empty() {
        // Best effort: try as DER.
        if let Ok(f) = finding_from_der(scan_id, file, bytes) {
            out.push(f);
        }
    }
    Ok(out)
}

fn parse_der(scan_id: Uuid, file: &Path, bytes: &[u8]) -> Result<Vec<Finding>> {
    let f = finding_from_der(scan_id, file, bytes)?;
    Ok(vec![f])
}

#[cfg(feature = "pkcs12")]
fn parse_pkcs12(
    scan_id: Uuid,
    file: &Path,
    bytes: &[u8],
    password: Option<&str>,
    host: &str,
) -> Result<Vec<Finding>> {
    use p12_keystore::{KeyStore, KeyStoreEntry};
    // `from_pkcs12` verifies the MAC only when the file carries one, so
    // record whether there was one to verify.
    let mac_present = pkcs12_has_mac(bytes);
    let store = KeyStore::from_pkcs12(bytes, password.unwrap_or(""))
        .with_context(|| format!("parse PKCS12 {}", file.display()))?;
    let mut out = Vec::new();
    let mut entries = Vec::new();
    for (alias, entry) in store.entries() {
        match entry {
            KeyStoreEntry::Certificate(c) => {
                if let Ok(f) = finding_from_der(scan_id, file, c.as_der()) {
                    out.push(f);
                }
                entries.push((alias.clone(), "trusted_certificate", vec![c.as_der()]));
            }
            // Only the certificate chain is read. `chain.key()` is never called.
            KeyStoreEntry::PrivateKeyChain(chain) => {
                for c in chain.chain() {
                    if let Ok(f) = finding_from_der(scan_id, file, c.as_der()) {
                        out.push(f);
                    }
                }
                let certs = chain.chain().iter().map(|c| c.as_der()).collect();
                entries.push((alias.clone(), "private_key", certs));
            }
        }
    }
    let meta = KeystoreMeta {
        store_type: "PKCS12",
        // A successful parse with a MAC means the MAC matched; without one,
        // nothing was checked.
        integrity_verified: mac_present.then_some(true),
    };
    for (alias, entry_type, certs) in entries {
        out.push(keystore_entry_finding(
            scan_id, file, host, &meta, &alias, entry_type, &certs, None,
        ));
    }
    Ok(out)
}

/// True when a PFX carries `macData`: the outer SEQUENCE has a third element
/// after `version` and `authSafe`.
#[cfg(feature = "pkcs12")]
fn pkcs12_has_mac(bytes: &[u8]) -> bool {
    fn tlv(b: &[u8]) -> Option<(usize, usize)> {
        // Returns (header length, content length).
        let first = *b.get(1)?;
        if first < 0x80 {
            return Some((2, first as usize));
        }
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        Some((2 + n, len))
    }
    let Some((h, len)) = tlv(bytes) else {
        return false;
    };
    let Some(mut body) = bytes.get(h..h.saturating_add(len)) else {
        return false;
    };
    let mut count = 0;
    while !body.is_empty() {
        let Some((eh, el)) = tlv(body) else {
            return false;
        };
        let Some(rest) = body.get(eh.saturating_add(el)..) else {
            return false;
        };
        body = rest;
        count += 1;
    }
    count >= 3
}

fn parse_jks(
    scan_id: Uuid,
    file: &Path,
    bytes: &[u8],
    password: Option<&str>,
    host: &str,
) -> Result<Vec<Finding>> {
    let store = crate::scanners::jks::parse(bytes, password)
        .with_context(|| format!("parse JKS {}", file.display()))?;
    if store.integrity_verified == Some(false) {
        tracing::warn!(
            "keystore integrity check failed for {} (wrong password or tampered file); entries listed unverified",
            file.display()
        );
    }
    let meta = KeystoreMeta {
        store_type: store.store_type,
        integrity_verified: store.integrity_verified,
    };
    let mut out = Vec::new();
    for entry in &store.entries {
        for der in &entry.certificates {
            if let Ok(f) = finding_from_der(scan_id, file, der) {
                out.push(f);
            }
        }
        let certs: Vec<&[u8]> = entry.certificates.iter().map(Vec::as_slice).collect();
        out.push(keystore_entry_finding(
            scan_id,
            file,
            host,
            &meta,
            &entry.alias,
            entry.entry_type.as_str(),
            &certs,
            entry.seal_algorithm.as_deref(),
        ));
    }
    Ok(out)
}

struct KeystoreMeta {
    store_type: &'static str,
    integrity_verified: Option<bool>,
}

/// One inventory key per keystore alias. Algorithm and size come from the
/// leaf certificate's public key. Secret key entries have no certificate and
/// are recorded with an unknown algorithm and no primitive (the key could be
/// AES, HMAC or anything else; its type is inside the sealed bytes).
#[allow(clippy::too_many_arguments)]
fn keystore_entry_finding(
    scan_id: Uuid,
    file: &Path,
    host: &str,
    store: &KeystoreMeta,
    alias: &str,
    entry_type: &str,
    certs: &[&[u8]],
    seal_algorithm: Option<&str>,
) -> Finding {
    use x509_parser::prelude::*;
    let location = file.display().to_string();
    let mut extra = Map::new();
    extra.insert("store_type".into(), Value::from(store.store_type));
    extra.insert("alias".into(), Value::from(alias));
    extra.insert("entry_type".into(), Value::from(entry_type));
    extra.insert("chain_length".into(), Value::from(certs.len()));
    extra.insert("integrity_verified".into(), json!(store.integrity_verified));
    if let Some(seal) = seal_algorithm {
        extra.insert("seal_algorithm".into(), Value::from(seal));
    }
    let mut algorithm = "unknown".to_string();
    let mut status = PqcStatus::Unknown;
    let mut primitive = None;
    let mut bits = None;
    if let Some(Ok((_, cert))) = certs.first().map(|d| X509Certificate::from_der(d)) {
        let pk_oid = cert.public_key().algorithm.algorithm.to_id_string();
        let pk_name = friendly_pk_oid(&pk_oid);
        bits = public_key_bits(&cert);
        let (name, st, prim) = classify_public_key(&pk_name, bits);
        algorithm = name;
        status = st;
        primitive = Some(prim);
        let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
        extra.insert("public_key_algorithm".into(), Value::from(pk_name));
        extra.insert("public_key_algorithm_oid".into(), Value::from(pk_oid));
        extra.insert(
            "signature_algorithm".into(),
            Value::from(friendly_sig_oid(&sig_oid)),
        );
        extra.insert("subject".into(), Value::from(cert.subject().to_string()));
        extra.insert("issuer".into(), Value::from(cert.issuer().to_string()));
        extra.insert(
            "not_before_unix".into(),
            Value::from(cert.validity().not_before.to_datetime().unix_timestamp()),
        );
        extra.insert(
            "not_after_unix".into(),
            Value::from(cert.validity().not_after.to_datetime().unix_timestamp()),
        );
        extra.insert(
            "certificate_sha256".into(),
            Value::from(hex::encode(Sha256::digest(certs[0]))),
        );
    }
    HostAsset {
        kind: KIND_KEYSTORE_ENTRY,
        host,
        location: &location,
        asset_name: format!("{}|{}", location, alias),
        algorithm_name: algorithm,
        pqc_status: status,
        primitive,
        key_size_bits: bits,
        extra,
    }
    .into_finding(scan_id, SourceType::File, Confidence::High)
}

fn public_key_bits(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<u64> {
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed().ok()? {
        PublicKey::RSA(rsa) => Some(rsa.key_size() as u64).filter(|b| *b > 0),
        // The named curve gives the real size; the point width does not for
        // P-521 (it is byte-aligned to 528 bits).
        PublicKey::EC(ec) => ec_curve_bits(cert).or(Some(ec.key_size() as u64).filter(|b| *b > 0)),
        _ => match cert
            .public_key()
            .algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            "1.3.101.112" => Some(256),
            "1.3.101.113" => Some(456),
            _ => None,
        },
    }
}

fn ec_curve_bits(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<u64> {
    let params = cert.public_key().algorithm.parameters.as_ref()?;
    let oid = params.as_oid().ok()?.to_id_string();
    match oid.as_str() {
        "1.2.840.10045.3.1.7" | "1.3.132.0.10" => Some(256), // P-256, secp256k1
        "1.3.132.0.34" => Some(384),
        "1.3.132.0.35" => Some(521),
        "1.2.840.10045.3.1.1" => Some(192),
        "1.3.132.0.33" => Some(224),
        _ => None,
    }
}

fn finding_from_der(scan_id: Uuid, file: &Path, der: &[u8]) -> Result<Finding> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).context("x509 parse")?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let pk_oid = cert.public_key().algorithm.algorithm.to_id_string();
    let sig_name = friendly_sig_oid(&sig_oid);
    let pk_name = friendly_pk_oid(&pk_oid);
    let not_before = cert.validity().not_before.to_datetime().unix_timestamp();
    let not_after = cert.validity().not_after.to_datetime().unix_timestamp();
    let mut hasher = Sha256::new();
    hasher.update(der);
    let fp = hex::encode(hasher.finalize());

    let pqc = pqc_status_for_sig_alg(&sig_name);

    let ev = json!({
        "kind": "tls_certificate",
        "target": file.display().to_string(),
        "subject": subject,
        "issuer": issuer,
        "signature_algorithm": sig_name,
        "signature_algorithm_oid": sig_oid,
        "public_key_algorithm": pk_name,
        "public_key_algorithm_oid": pk_oid,
        "not_before_unix": not_before,
        "not_after_unix": not_after,
        "fingerprint_sha256": fp,
        "pqc_status": pqc_status_str(pqc),
    });

    Ok(Finding::new(
        scan_id,
        SourceType::CertSubject,
        format!("{}|{}", file.display(), subject),
        ev,
        Confidence::High,
    ))
}

fn pqc_status_str(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "vulnerable",
        PqcStatus::Hybrid => "hybrid",
        PqcStatus::Resistant => "resistant",
        PqcStatus::SymmetricOk => "symmetric_ok",
        PqcStatus::Unknown => "unknown",
    }
}

fn friendly_sig_oid(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => oid,
    }
    .to_string()
}

fn friendly_pk_oid(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => oid,
    }
    .to_string()
}

fn pqc_status_for_sig_alg(name: &str) -> PqcStatus {
    let lower = name.to_ascii_lowercase();
    if lower.contains("sha1") {
        return PqcStatus::Vulnerable;
    }
    if lower.contains("rsa")
        || lower.contains("ecdsa")
        || lower.contains("ed25519")
        || lower.contains("ed448")
    {
        return PqcStatus::Vulnerable;
    }
    if lower.contains("mldsa") || lower.contains("ml-dsa") || lower.contains("slhdsa") {
        return PqcStatus::Resistant;
    }
    PqcStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // A self-signed RSA-2048 cert (sha256) is bundled below as a base64-encoded PEM
    // so the test does not need network access. Generated once and checked in
    // as a test fixture below.

    const SAMPLE_PEM: &str = include_str!("../../tests/fixtures/certs/rsa2048-selfsigned.pem");

    #[test]
    fn scans_pem_directory() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("rsa.pem");
        std::fs::write(&f, SAMPLE_PEM).unwrap();
        let scan = scan_path(dir.path(), &CertStoreOptions::default()).unwrap();
        assert!(!scan.findings.is_empty(), "expected at least one finding");
        let evidence = &scan.findings[0].evidence;
        assert_eq!(
            evidence.get("kind").and_then(|v| v.as_str()),
            Some("tls_certificate")
        );
        assert!(evidence
            .get("public_key_algorithm")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("RSA"))
            .unwrap_or(false));
    }
}
