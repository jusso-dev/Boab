//! Certificate store scanner. Walks a directory for PEM/DER/PKCS#12/JKS
//! certificates and parses each one with `x509-parser`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::asset::PqcStatus;
use crate::model::finding::{Confidence, Finding, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};

#[derive(Debug, Clone, Default)]
pub struct CertStoreOptions {
    pub password_file: Option<PathBuf>,
    pub name: Option<String>,
}

const SUPPORTED_EXTS: &[&str] = &["pem", "crt", "cer", "der", "p7b", "p12", "pfx", "jks"];

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
        match parse_cert_file(scan_id, file, ext.as_str(), password.as_deref()) {
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
) -> Result<Vec<Finding>> {
    let bytes = fs::read(file).with_context(|| format!("read {}", file.display()))?;
    match ext {
        "pem" | "crt" | "cer" | "p7b" => parse_pem_blocks(scan_id, file, &bytes),
        "der" => parse_der(scan_id, file, &bytes),
        #[cfg(feature = "pkcs12")]
        "p12" | "pfx" => parse_pkcs12(scan_id, file, &bytes, _password),
        #[cfg(not(feature = "pkcs12"))]
        "p12" | "pfx" => Ok(vec![keystore_placeholder(
            scan_id,
            file,
            "PKCS12 (feature disabled)",
        )]),
        // JKS parsing is not provided by a maintained pure-Rust crate compatible
        // with our API expectations; emit a placeholder finding so customers
        // still see the file in the inventory. Convert JKS to PKCS12 with
        // `keytool` before scanning for full parsing.
        "jks" => Ok(vec![keystore_placeholder(
            scan_id,
            file,
            "JKS (convert to PKCS12 with keytool for full parsing)",
        )]),
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
) -> Result<Vec<Finding>> {
    use p12_keystore::{KeyStore, KeyStoreEntry};
    let store = KeyStore::from_pkcs12(bytes, password.unwrap_or(""))
        .with_context(|| format!("parse PKCS12 {}", file.display()))?;
    let mut out = Vec::new();
    for (_alias, entry) in store.entries() {
        match entry {
            KeyStoreEntry::Certificate(c) => {
                if let Ok(f) = finding_from_der(scan_id, file, c.as_der()) {
                    out.push(f);
                }
            }
            KeyStoreEntry::PrivateKeyChain(chain) => {
                for c in chain.chain() {
                    if let Ok(f) = finding_from_der(scan_id, file, c.as_der()) {
                        out.push(f);
                    }
                }
            }
        }
    }
    Ok(out)
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
