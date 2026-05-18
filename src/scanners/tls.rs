//! TLS endpoint scanner. Uses rustls + tokio-rustls.
//!
//! Performs a TLS handshake against each target and records the negotiated
//! cipher suite, certificate chain, and the supported_groups extension where
//! it can be inferred from a key share retry. Air-gapped by default: no
//! outbound calls other than the configured targets.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::SupportedProtocolVersion;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use crate::model::asset::PqcStatus;
use crate::model::finding::{Confidence, Finding, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub rate_limit: Option<String>,
    pub timeout_seconds: u64,
    pub probe_hsts: bool,
    pub exclude: Vec<String>,
    pub name: Option<String>,
    pub air_gapped: bool,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            rate_limit: None,
            timeout_seconds: 10,
            probe_hsts: false,
            exclude: Vec::new(),
            name: None,
            air_gapped: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersionPolicy {
    PreferTls13,
    Tls12Only,
}

/// Map a TLS 1.3 supported-group codepoint to a friendly name. Includes the
/// PQ hybrid groups standardised by the IETF.
pub fn group_name(codepoint: u16) -> &'static str {
    match codepoint {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001D => "x25519",
        0x001E => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x11EC => "X25519MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        _ => "unknown",
    }
}

pub fn is_hybrid_group(codepoint: u16) -> bool {
    matches!(codepoint, 0x11EC | 0x6399)
}

/// Scan a list of TLS targets in sequence. Returns one Scan per target.
pub async fn scan_targets(targets: &[String], options: &TlsOptions) -> Result<Vec<Scan>> {
    if options.probe_hsts && options.air_gapped {
        return Err(anyhow!("--probe-hsts is not allowed in air-gapped mode"));
    }

    let mut scans = Vec::new();
    for target in targets {
        if options.exclude.iter().any(|x| x == target) {
            continue;
        }
        let scan = scan_one(target, options).await;
        scans.push(scan);
        // Simple sequential rate limit: 1 host/sec by default unless overridden.
        if let Some(rl) = &options.rate_limit {
            if let Some(delay) = parse_rate_limit(rl) {
                tokio::time::sleep(delay).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(scans)
}

fn parse_rate_limit(s: &str) -> Option<Duration> {
    let (n, unit) = s.split_once('/')?;
    let n: u64 = n.trim().parse().ok()?;
    if n == 0 {
        return None;
    }
    match unit.trim() {
        "second" | "sec" | "s" => Some(Duration::from_millis(1000 / n)),
        "minute" | "min" => Some(Duration::from_millis(60_000 / n)),
        _ => None,
    }
}

async fn scan_one(target: &str, options: &TlsOptions) -> Scan {
    let mut scan = Scan::new(
        options
            .name
            .clone()
            .unwrap_or_else(|| format!("tls:{}", target)),
        ScanType::TlsEndpoint,
        target.to_string(),
    );
    scan.status = ScanStatus::Running;

    match handshake(
        target,
        options.timeout_seconds,
        TlsVersionPolicy::PreferTls13,
    )
    .await
    {
        Ok(result) => {
            populate_findings(&mut scan, target, &result);
            scan.status = ScanStatus::Completed;
        }
        Err(e_first) => {
            match handshake(target, options.timeout_seconds, TlsVersionPolicy::Tls12Only).await {
                Ok(result) => {
                    populate_findings(&mut scan, target, &result);
                    scan.status = ScanStatus::Completed;
                }
                Err(e_second) => {
                    scan.status = ScanStatus::Failed;
                    scan.error_message = Some(format!(
                        "TLS handshake failed: tls13={} tls12={}",
                        e_first, e_second
                    ));
                }
            }
        }
    }

    scan.completed_at = Some(OffsetDateTime::now_utc());
    scan
}

struct HandshakeResult {
    negotiated_version: &'static str,
    cipher_suite: String,
    cert_chain: Vec<Vec<u8>>,
    alpn: Option<String>,
}

async fn handshake(
    target: &str,
    timeout_seconds: u64,
    policy: TlsVersionPolicy,
) -> Result<HandshakeResult> {
    let (host, port) = parse_target(target)?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions: &[&SupportedProtocolVersion] = match policy {
        TlsVersionPolicy::PreferTls13 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        TlsVersionPolicy::Tls12Only => &[&rustls::version::TLS12],
    };

    let mut cfg = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.enable_sni = true;
    let connector = TlsConnector::from(Arc::new(cfg));

    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid server name: {}", host))?;

    let stream = timeout(
        Duration::from_secs(timeout_seconds),
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await
    .map_err(|_| anyhow!("TCP connect timeout"))?
    .context("TCP connect")?;
    let tls = timeout(
        Duration::from_secs(timeout_seconds),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake timeout"))?
    .context("TLS handshake")?;

    let (_, session) = tls.get_ref();
    let proto = session
        .protocol_version()
        .ok_or_else(|| anyhow!("no negotiated TLS version"))?;
    let suite = session
        .negotiated_cipher_suite()
        .ok_or_else(|| anyhow!("no negotiated cipher suite"))?;
    let cipher_name = format!("{:?}", suite.suite());
    let cert_chain: Vec<Vec<u8>> = session
        .peer_certificates()
        .map(|cs| cs.iter().map(|c| c.as_ref().to_vec()).collect())
        .unwrap_or_default();
    let alpn = session
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).into_owned());

    let version_name = match proto {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
        _ => "TLS",
    };

    Ok(HandshakeResult {
        negotiated_version: version_name,
        cipher_suite: cipher_name,
        cert_chain,
        alpn,
    })
}

fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target must be host:port, got {}", target))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in target {}", target))?;
    Ok((host.to_string(), port))
}

fn populate_findings(scan: &mut Scan, target: &str, result: &HandshakeResult) {
    let scan_id = scan.id;
    let endpoint_pqc_status = if result.cipher_suite.to_ascii_lowercase().contains("aes")
        || result
            .cipher_suite
            .to_ascii_lowercase()
            .contains("chacha20")
    {
        PqcStatus::SymmetricOk
    } else {
        PqcStatus::Unknown
    };
    let endpoint_ev = json!({
        "kind": "tls_endpoint",
        "target": target,
        "tls_version": result.negotiated_version,
        "cipher_suite": result.cipher_suite,
        "alpn": result.alpn,
        "pqc_status": pqc_status_str(endpoint_pqc_status),
    });
    scan.findings.push(Finding::new(
        scan_id,
        SourceType::Host,
        target.to_string(),
        endpoint_ev,
        Confidence::High,
    ));

    for cert_der in &result.cert_chain {
        match cert_finding_from_der(scan_id, target, cert_der) {
            Ok(f) => scan.findings.push(f),
            Err(e) => tracing::debug!("could not parse cert from {}: {}", target, e),
        }
    }
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

fn cert_finding_from_der(scan_id: Uuid, target: &str, der: &[u8]) -> Result<Finding> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).context("x509 parse")?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let sig_alg = cert.signature_algorithm.algorithm.to_id_string();
    let sig_name = friendly_sig_oid(&sig_alg);
    let pk_alg = cert.public_key().algorithm.algorithm.to_id_string();
    let pk_name = friendly_pk_oid(&pk_alg);
    let not_before = cert.validity().not_before.to_datetime().unix_timestamp();
    let not_after = cert.validity().not_after.to_datetime().unix_timestamp();
    let pk_bits = approximate_key_bits(&cert);
    let mut hasher = Sha256::new();
    hasher.update(der);
    let fp = hex::encode(hasher.finalize());

    let pqc = pqc_status_for_sig_alg(&sig_name);
    let ev = json!({
        "kind": "tls_certificate",
        "target": target,
        "subject": subject,
        "issuer": issuer,
        "signature_algorithm": sig_name,
        "signature_algorithm_oid": sig_alg,
        "public_key_algorithm": pk_name,
        "public_key_algorithm_oid": pk_alg,
        "public_key_bits": pk_bits,
        "not_before_unix": not_before,
        "not_after_unix": not_after,
        "fingerprint_sha256": fp,
        "pqc_status": pqc_status_str(pqc),
    });

    Ok(Finding::new(
        scan_id,
        SourceType::CertSubject,
        format!("{}|{}", target, subject),
        ev,
        Confidence::High,
    ))
}

fn approximate_key_bits<'a>(
    cert: &'a x509_parser::certificate::X509Certificate<'a>,
) -> Option<u64> {
    use x509_parser::public_key::PublicKey;
    match cert.public_key().parsed().ok()? {
        PublicKey::RSA(rsa) => Some(rsa.key_size() as u64),
        PublicKey::EC(ec) => Some(((ec.data().len().saturating_sub(1)) * 8 / 2) as u64),
        _ => None,
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

    #[test]
    fn rate_limit_parses() {
        assert_eq!(
            parse_rate_limit("1/second"),
            Some(Duration::from_millis(1000))
        );
        assert_eq!(parse_rate_limit("2/sec"), Some(Duration::from_millis(500)));
        assert_eq!(
            parse_rate_limit("60/minute"),
            Some(Duration::from_millis(1000))
        );
        assert!(parse_rate_limit("garbage").is_none());
        assert!(parse_rate_limit("0/second").is_none());
    }

    #[test]
    fn parse_target_works() {
        let (h, p) = parse_target("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
        assert!(parse_target("no-port").is_err());
        assert!(parse_target("bad:port").is_err());
    }

    #[test]
    fn hybrid_groups_classified() {
        assert!(is_hybrid_group(0x11EC));
        assert!(is_hybrid_group(0x6399));
        assert!(!is_hybrid_group(0x001D));
        assert_eq!(group_name(0x11EC), "X25519MLKEM768");
        assert_eq!(group_name(0x001D), "x25519");
    }

    #[test]
    fn pqc_status_classification() {
        assert!(matches!(
            pqc_status_for_sig_alg("sha1WithRSAEncryption"),
            PqcStatus::Vulnerable
        ));
        assert!(matches!(
            pqc_status_for_sig_alg("ecdsa-with-SHA256"),
            PqcStatus::Vulnerable
        ));
        assert!(matches!(
            pqc_status_for_sig_alg("ML-DSA-65"),
            PqcStatus::Resistant
        ));
    }

    #[test]
    fn probe_hsts_rejected_in_air_gapped_mode() {
        // We use a runtime locally to drive the async function.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let opts = TlsOptions {
            probe_hsts: true,
            air_gapped: true,
            ..Default::default()
        };
        let err = rt
            .block_on(scan_targets(&["example.com:443".to_string()], &opts))
            .unwrap_err();
        assert!(err.to_string().contains("air-gapped"));
    }
}
