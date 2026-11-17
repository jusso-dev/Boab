//! Host crypto scanner: SSH host keys, sshd_config algorithm lists, the
//! RHEL/Fedora system-wide crypto policy and OpenSSL configuration.
//!
//! Reads files under a root directory (`/` for the running host, or a mounted
//! image or exported copy of a host's `/etc`). Every recorded path is the path
//! on the scanned host, so `/mnt/web01/etc/ssh/sshd_config` is recorded as
//! `/etc/ssh/sshd_config`.
//!
//! Only public material and configuration are read. SSH private host key files
//! (`ssh_host_*_key`) are recognised from the directory listing by name and are
//! never opened.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    HostAsset, KIND_OPENSSL_CONFIG, KIND_OS_CRYPTO_POLICY, KIND_SSH_CONFIG_ALGORITHM,
    KIND_SSH_HOST_KEY,
};
use crate::model::asset::PqcStatus;
use crate::model::finding::{Confidence, Finding, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};

#[derive(Debug, Clone, Default)]
pub struct HostScanOptions {
    /// Label recorded as `host` on every asset. Defaults to the scanned
    /// root's `etc/hostname`, then the local host name when the root is `/`.
    pub host: Option<String>,
    pub name: Option<String>,
}

/// sshd_config directives whose algorithm lists Boab records.
pub const SSH_DIRECTIVES: &[&str] = &["HostKeyAlgorithms", "KexAlgorithms", "Ciphers", "MACs"];

const OPENSSL_CONFIG_PATHS: &[&str] = &[
    "etc/ssl/openssl.cnf",
    "etc/pki/tls/openssl.cnf",
    "usr/lib/ssl/openssl.cnf",
    "usr/local/ssl/openssl.cnf",
    "etc/openssl/openssl.cnf",
];

pub fn scan_root(root: &Path, options: &HostScanOptions) -> Result<Scan> {
    let root = root
        .canonicalize()
        .with_context(|| format!("could not resolve host root {}", root.display()))?;
    let host = options
        .host
        .clone()
        .unwrap_or_else(|| host_label_for(&root));
    let mut scan = Scan::new(
        options
            .name
            .clone()
            .unwrap_or_else(|| format!("host:{}", host)),
        ScanType::HostCrypto,
        root.display().to_string(),
    );
    scan.status = ScanStatus::Running;
    scan.config = json!({ "host": host });

    let ctx = Ctx {
        root: &root,
        host: &host,
        scan_id: scan.id,
    };
    let ssh = SshConfig::load(&ctx);
    ctx.ssh_host_keys(&ssh, &mut scan.findings);
    ctx.ssh_algorithms(&ssh, &mut scan.findings);
    ctx.crypto_policy(&mut scan.findings);
    ctx.openssl_configs(&mut scan.findings);

    scan.status = ScanStatus::Completed;
    scan.completed_at = Some(OffsetDateTime::now_utc());
    Ok(scan)
}

fn host_label_for(root: &Path) -> String {
    if let Some(h) = super::read_hostname_file(&root.join("etc/hostname")) {
        return h;
    }
    if root.parent().is_none() {
        return super::local_host_label();
    }
    root.display().to_string()
}

struct Ctx<'a> {
    root: &'a Path,
    host: &'a str,
    scan_id: Uuid,
}

impl Ctx<'_> {
    /// Path on the scanned host for a file under the root, with `/` separators.
    fn host_path(&self, path: &Path) -> String {
        match path.strip_prefix(self.root) {
            Ok(rel) => {
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                format!("/{}", parts.join("/"))
            }
            Err(_) => path.display().to_string(),
        }
    }

    /// Map an absolute path on the scanned host to a path under the root.
    fn rebase(&self, host_path: &str) -> PathBuf {
        self.root.join(host_path.trim_start_matches(['/', '\\']))
    }

    fn finding(&self, asset: HostAsset<'_>) -> Finding {
        asset.into_finding(self.scan_id, SourceType::Host, Confidence::High)
    }

    // --- SSH host keys --------------------------------------------------------

    fn ssh_host_keys(&self, ssh: &SshConfig, out: &mut Vec<Finding>) {
        let ssh_dir = self.root.join("etc/ssh");
        // Private key files are identified by name from the directory listing only.
        let mut private_names: BTreeSet<PathBuf> = BTreeSet::new();
        let mut public_files: BTreeSet<PathBuf> = BTreeSet::new();
        if let Ok(rd) = fs::read_dir(&ssh_dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.starts_with("ssh_host_") {
                    continue;
                }
                if name.ends_with("_key.pub") || name.ends_with("_key-cert.pub") {
                    public_files.insert(e.path());
                } else if name.ends_with("_key") {
                    private_names.insert(e.path());
                }
            }
        }
        for hk in &ssh.host_keys {
            let private = self.rebase(hk);
            let public = PathBuf::from(format!("{}.pub", private.display()));
            if public.is_file() {
                public_files.insert(public);
            } else if private.exists() {
                private_names.insert(private);
            }
        }

        for pub_path in &public_files {
            let private = pub_path
                .to_string_lossy()
                .strip_suffix(".pub")
                .map(PathBuf::from)
                .filter(|p| !p.to_string_lossy().ends_with("-cert"));
            let private_present = private.as_ref().is_some_and(|p| p.exists());
            let line = match fs::read_to_string(pub_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("skip {}: {}", pub_path.display(), e);
                    continue;
                }
            };
            match parse_ssh_public_key(&line) {
                Some(key) => out.push(self.ssh_key_finding(pub_path, &key, private_present)),
                None => tracing::debug!("not an SSH public key: {}", pub_path.display()),
            }
        }

        // Private key files with no readable `.pub` beside them: record the
        // algorithm implied by the file name, without opening the file.
        for private in &private_names {
            let public = PathBuf::from(format!("{}.pub", private.display()));
            if public_files.contains(&public) {
                continue;
            }
            let name = private
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let kind = name
                .strip_prefix("ssh_host_")
                .and_then(|s| s.strip_suffix("_key"))
                .unwrap_or("");
            let key_type = match kind {
                "rsa" => "ssh-rsa",
                "dsa" => "ssh-dss",
                "ecdsa" => "ecdsa-sha2",
                "ed25519" => "ssh-ed25519",
                _ => continue,
            };
            let key = SshPublicKey {
                key_type: key_type.to_string(),
                // OpenSSH only generates 1024-bit DSA host keys.
                key_bits: match kind {
                    "ed25519" => Some(256),
                    "dsa" => Some(1024),
                    _ => None,
                },
                curve: None,
                fingerprint: None,
                certificate: false,
            };
            out.push(self.ssh_key_finding(private, &key, true));
        }
    }

    fn ssh_key_finding(&self, path: &Path, key: &SshPublicKey, private_present: bool) -> Finding {
        let location = self.host_path(path);
        let (algorithm, status) = ssh_key_algorithm(&key.key_type, key.curve.as_deref());
        let mut extra = Map::new();
        extra.insert("ssh_key_type".into(), Value::from(key.key_type.clone()));
        if let Some(fp) = &key.fingerprint {
            extra.insert("fingerprint_sha256".into(), Value::from(fp.clone()));
        }
        extra.insert(
            "public_key_available".into(),
            Value::from(key.fingerprint.is_some()),
        );
        extra.insert("private_key_present".into(), Value::from(private_present));
        extra.insert("certificate".into(), Value::from(key.certificate));
        self.finding(HostAsset {
            kind: KIND_SSH_HOST_KEY,
            host: self.host,
            location: &location,
            asset_name: format!("{}:{}", self.host, location),
            algorithm_name: algorithm.to_string(),
            pqc_status: status,
            primitive: Some("signature"),
            key_size_bits: key.key_bits,
            extra,
        })
    }

    // --- sshd_config algorithm lists -----------------------------------------

    fn ssh_algorithms(&self, ssh: &SshConfig, out: &mut Vec<Finding>) {
        let mut directives = ssh.directives.clone();
        // On RHEL/Fedora the crypto policy back-end supplies the lists when
        // sshd_config does not set them itself.
        let backend = self
            .root
            .join("etc/crypto-policies/back-ends/opensshserver.config");
        if !ssh.visited.contains(&backend) {
            if let Ok(raw) = fs::read_to_string(&backend) {
                let location = self.host_path(&backend);
                for (k, v) in parse_openssh_backend(&raw) {
                    directives.entry(k).or_insert((v, location.clone()));
                }
            }
        }
        for directive in SSH_DIRECTIVES {
            let Some((value, location)) = directives.get(&directive.to_ascii_lowercase()) else {
                continue;
            };
            let (modifier, list) = match value.chars().next() {
                Some('+') => ("append", &value[1..]),
                Some('-') => continue, // removals from the default list: nothing is enabled
                Some('^') => ("prepend", &value[1..]),
                _ => ("replace", value.as_str()),
            };
            for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Some(alg) = classify_ssh_algorithm(directive, name) else {
                    continue;
                };
                let mut extra = Map::new();
                extra.insert("directive".into(), Value::from(*directive));
                extra.insert("ssh_name".into(), Value::from(name));
                extra.insert("list_modifier".into(), Value::from(modifier));
                out.push(self.finding(HostAsset {
                    kind: KIND_SSH_CONFIG_ALGORITHM,
                    host: self.host,
                    location,
                    asset_name: format!("{} sshd {}: {}", self.host, directive, name),
                    algorithm_name: alg.name.to_string(),
                    pqc_status: alg.status,
                    primitive: Some(alg.primitive),
                    key_size_bits: alg.bits,
                    extra,
                }));
            }
        }
    }

    // --- RHEL/Fedora crypto policy -------------------------------------------

    fn crypto_policy(&self, out: &mut Vec<Finding>) {
        let base = self.root.join("etc/crypto-policies");
        let state = base.join("state/current");
        let config = base.join("config");
        let (policy, source) = match first_value_line(&state) {
            Some(p) => (p, state),
            None => match first_value_line(&config) {
                Some(p) => (p, config),
                None => return,
            },
        };
        let mut parts = policy.split(':');
        let base_policy = parts.next().unwrap_or("").to_string();
        let subpolicies: Vec<String> = parts.map(str::to_string).collect();

        let mut backends: Vec<String> = fs::read_dir(base.join("back-ends"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".config"))
                    .collect()
            })
            .unwrap_or_default();
        backends.sort();

        let mut extra = Map::new();
        extra.insert("policy".into(), Value::from(policy.clone()));
        extra.insert("base_policy".into(), Value::from(base_policy.clone()));
        extra.insert("subpolicies".into(), json!(subpolicies));
        extra.insert("backends".into(), json!(backends));
        let openssl_backend = base.join("back-ends/opensslcnf.config");
        let tls = fs::read_to_string(&openssl_backend)
            .map(|raw| OpenSslSettings::parse_text(&raw))
            .unwrap_or_default();
        tls.write_into(&mut extra);

        let pq_subpolicy = subpolicies
            .iter()
            .any(|s| s.to_ascii_uppercase().contains("PQ"))
            || base_policy.to_ascii_uppercase().contains("PQ");
        let (status, reason) = if tls.has_hybrid_group() || pq_subpolicy {
            (
                PqcStatus::Hybrid,
                "policy enables post-quantum hybrid key exchange",
            )
        } else {
            (
                PqcStatus::Vulnerable,
                "policy allows classical key exchange only",
            )
        };
        extra.insert("pqc_reason".into(), Value::from(reason));
        let location = self.host_path(&source);
        out.push(self.finding(HostAsset {
            kind: KIND_OS_CRYPTO_POLICY,
            host: self.host,
            location: &location,
            asset_name: format!("{} crypto-policies {}", self.host, policy),
            algorithm_name: format!("crypto-policies:{}", policy),
            pqc_status: status,
            primitive: None,
            key_size_bits: None,
            extra,
        }));
    }

    // --- OpenSSL configuration -----------------------------------------------

    fn openssl_configs(&self, out: &mut Vec<Finding>) {
        let mut seen = BTreeSet::new();
        for rel in OPENSSL_CONFIG_PATHS {
            let path = self.root.join(rel);
            if !path.is_file() {
                continue;
            }
            // Distro symlinks often point several of these at one file.
            let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !seen.insert(canon) {
                continue;
            }
            let mut settings = OpenSslSettings::default();
            let mut files = Vec::new();
            self.read_openssl_file(&path, &mut settings, &mut files, 0);
            let location = self.host_path(&path);
            let mut extra = Map::new();
            settings.write_into(&mut extra);
            extra.insert("config_files".into(), json!(files));
            let (status, reason) = if settings.has_hybrid_group() {
                (
                    PqcStatus::Hybrid,
                    "Groups include a post-quantum hybrid group",
                )
            } else {
                (
                    PqcStatus::Vulnerable,
                    "no post-quantum hybrid group configured; TLS key exchange is classical",
                )
            };
            extra.insert("pqc_reason".into(), Value::from(reason));
            let min = settings.min_protocol.as_deref().unwrap_or("default");
            out.push(self.finding(HostAsset {
                kind: KIND_OPENSSL_CONFIG,
                host: self.host,
                location: &location,
                asset_name: format!("{}:{}", self.host, location),
                algorithm_name: format!("OpenSSL MinProtocol {}", min),
                pqc_status: status,
                primitive: None,
                key_size_bits: None,
                extra,
            }));
        }
    }

    fn read_openssl_file(
        &self,
        path: &Path,
        settings: &mut OpenSslSettings,
        files: &mut Vec<String>,
        depth: usize,
    ) {
        if depth > 8 {
            return;
        }
        let host_path = self.host_path(path);
        if files.contains(&host_path) {
            return;
        }
        let Ok(raw) = fs::read_to_string(path) else {
            return;
        };
        files.push(host_path);
        for line in raw.lines() {
            let line = strip_comment(line).trim();
            let include = line
                .strip_prefix(".include")
                .map(|r| r.trim_start_matches([' ', '\t', '=']).trim());
            if let Some(target) = include {
                let target = target.trim_matches('"');
                let p = if target.starts_with('/') {
                    self.rebase(target)
                } else {
                    path.parent().unwrap_or(self.root).join(target)
                };
                if p.is_dir() {
                    let mut entries: Vec<PathBuf> = fs::read_dir(&p)
                        .map(|rd| {
                            rd.flatten()
                                .map(|e| e.path())
                                .filter(|f| {
                                    matches!(
                                        f.extension().and_then(|x| x.to_str()),
                                        Some("cnf") | Some("conf")
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    entries.sort();
                    for e in entries {
                        self.read_openssl_file(&e, settings, files, depth + 1);
                    }
                } else {
                    self.read_openssl_file(&p, settings, files, depth + 1);
                }
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                settings.set(k.trim(), v.trim());
            }
        }
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map(|(a, _)| a).unwrap_or(line)
}

fn first_value_line(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    raw.lines()
        .map(|l| strip_comment(l).trim())
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

// --- sshd_config -------------------------------------------------------------

#[derive(Debug, Default)]
struct SshConfig {
    /// Lower-cased directive -> (value, host path of the file that set it).
    /// sshd uses the first value it reads for each directive.
    directives: BTreeMap<String, (String, String)>,
    /// HostKey paths on the scanned host.
    host_keys: Vec<String>,
    visited: BTreeSet<PathBuf>,
}

impl SshConfig {
    fn load(ctx: &Ctx<'_>) -> Self {
        let mut cfg = SshConfig::default();
        let main = ctx.root.join("etc/ssh/sshd_config");
        cfg.read(ctx, &main, 0);
        cfg
    }

    fn read(&mut self, ctx: &Ctx<'_>, path: &Path, depth: usize) {
        if depth > 16 || !self.visited.insert(path.to_path_buf()) {
            return;
        }
        let Ok(raw) = fs::read_to_string(path) else {
            return;
        };
        let location = ctx.host_path(path);
        let mut in_match = false;
        for line in raw.lines() {
            let Some((key, value)) = split_ssh_line(line) else {
                continue;
            };
            let key_l = key.to_ascii_lowercase();
            if key_l == "match" {
                // Conditional block: its settings do not apply globally.
                in_match = !value.eq_ignore_ascii_case("all");
                continue;
            }
            if in_match {
                continue;
            }
            match key_l.as_str() {
                "include" => {
                    for pattern in value.split_whitespace() {
                        for p in expand_include(ctx, pattern) {
                            self.read(ctx, &p, depth + 1);
                        }
                    }
                }
                "hostkey" => self.host_keys.push(value.to_string()),
                _ => {
                    self.directives
                        .entry(key_l)
                        .or_insert_with(|| (value.to_string(), location.clone()));
                }
            }
        }
    }
}

fn split_ssh_line(line: &str) -> Option<(&str, &str)> {
    let line = strip_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    let idx = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..idx];
    let value = line[idx..]
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim()
        .trim_matches('"');
    Some((key, value))
}

/// Expand an sshd `Include` pattern. Relative paths are under `/etc/ssh`.
/// Wildcards are supported in the last path component.
fn expand_include(ctx: &Ctx<'_>, pattern: &str) -> Vec<PathBuf> {
    let host_pattern = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/etc/ssh/{}", pattern)
    };
    let full = ctx.rebase(&host_pattern);
    let file_pat = full
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !file_pat.contains(['*', '?']) {
        return vec![full];
    }
    let dir = full.parent().unwrap_or(ctx.root).to_path_buf();
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| wildcard_match(&file_pat, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

/// Parse `opensshserver.config`: either sshd_config lines (RHEL 9 and later)
/// or a `CRYPTO_POLICY='-oKey=value ...'` line (RHEL 8).
fn parse_openssh_backend(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("CRYPTO_POLICY=") {
            let rest = rest.trim_matches(['\'', '"']);
            for tok in rest.split_whitespace() {
                if let Some((k, v)) = tok.strip_prefix("-o").and_then(|t| t.split_once('=')) {
                    out.push((k.to_ascii_lowercase(), v.to_string()));
                }
            }
        } else if let Some((k, v)) = split_ssh_line(line) {
            out.push((k.to_ascii_lowercase(), v.to_string()));
        }
    }
    out
}

// --- SSH public keys ---------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SshPublicKey {
    pub key_type: String,
    pub key_bits: Option<u64>,
    pub curve: Option<String>,
    /// OpenSSH-style `SHA256:<base64>` fingerprint of the public key blob.
    pub fingerprint: Option<String>,
    pub certificate: bool,
}

/// Parse one OpenSSH public key line (`type base64 [comment]`). The comment
/// is ignored and never recorded.
pub fn parse_ssh_public_key(text: &str) -> Option<SshPublicKey> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let mut fields = line.split_whitespace();
    let declared = fields.next()?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(fields.next()?)
        .ok()?;
    let mut r = SshReader(&blob);
    let key_type = String::from_utf8(r.string()?.to_vec()).ok()?;
    if key_type != declared {
        return None;
    }
    let certificate = key_type.ends_with("-cert-v01@openssh.com");
    if certificate {
        r.string()?; // nonce
    }
    let base = key_type.trim_end_matches("-cert-v01@openssh.com");
    let (bits, curve) = match base {
        "ssh-rsa" => {
            r.string()?; // e
            (Some(mpint_bits(r.string()?)), None)
        }
        "ssh-dss" => (Some(mpint_bits(r.string()?)), None),
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => (Some(256), None),
        "ssh-ed448" => (Some(456), None),
        t if t.starts_with("ecdsa-sha2-") || t.starts_with("sk-ecdsa-sha2-") => {
            let curve = String::from_utf8(r.string()?.to_vec()).ok()?;
            let bits = match curve.as_str() {
                "nistp256" => Some(256),
                "nistp384" => Some(384),
                "nistp521" => Some(521),
                _ => None,
            };
            (bits, Some(curve))
        }
        _ => (None, None),
    };
    let digest = Sha256::digest(&blob);
    Some(SshPublicKey {
        key_type,
        key_bits: bits,
        curve,
        fingerprint: Some(format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
        )),
        certificate,
    })
}

struct SshReader<'a>(&'a [u8]);

impl<'a> SshReader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        if self.0.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        let rest = &self.0[4..];
        if rest.len() < len {
            return None;
        }
        let (s, tail) = rest.split_at(len);
        self.0 = tail;
        Some(s)
    }
}

fn mpint_bits(m: &[u8]) -> u64 {
    let m = match m.iter().position(|b| *b != 0) {
        Some(i) => &m[i..],
        None => return 0,
    };
    (m.len() as u64 - 1) * 8 + (8 - m[0].leading_zeros() as u64)
}

/// Canonical algorithm name and PQC status for an SSH public key type.
fn ssh_key_algorithm(key_type: &str, curve: Option<&str>) -> (&'static str, PqcStatus) {
    let base = key_type.trim_end_matches("-cert-v01@openssh.com");
    let name = match base {
        "ssh-rsa" => "RSA",
        "ssh-dss" => "DSA",
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => "Ed25519",
        "ssh-ed448" => "Ed448",
        _ if base.contains("ecdsa-sha2") => match curve.or_else(|| base.rsplit('-').next()) {
            Some(c) if c.starts_with("nistp256") => "ECDSA-P256",
            Some(c) if c.starts_with("nistp384") => "ECDSA-P384",
            Some(c) if c.starts_with("nistp521") => "ECDSA-P521",
            _ => "ECDSA",
        },
        _ => return ("unknown", PqcStatus::Unknown),
    };
    (name, PqcStatus::Vulnerable)
}

// --- SSH algorithm names -----------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SshAlgorithm {
    /// Canonical name used by the scoring rubric.
    pub name: &'static str,
    pub status: PqcStatus,
    /// `Primitive` in snake_case.
    pub primitive: &'static str,
    pub bits: Option<u64>,
}

/// Classify one entry from an sshd algorithm list. Returns `None` for
/// pseudo-algorithms such as `ext-info-c` and `kex-strict-*`.
pub fn classify_ssh_algorithm(directive: &str, name: &str) -> Option<SshAlgorithm> {
    use PqcStatus::*;
    let n = name.to_ascii_lowercase();
    let n = n.as_str();
    let a = |name, status, primitive, bits| {
        Some(SshAlgorithm {
            name,
            status,
            primitive,
            bits,
        })
    };
    match directive {
        "HostKeyAlgorithms" => {
            let base = n
                .trim_end_matches("-cert-v01@openssh.com")
                .trim_start_matches("sk-");
            match base {
                "ssh-rsa" => a("RSA-SHA-1", Vulnerable, "signature", None),
                "rsa-sha2-256" | "rsa-sha2-512" => a("RSA", Vulnerable, "signature", None),
                "ssh-dss" => a("DSA", Vulnerable, "signature", Some(1024)),
                "ssh-ed25519" | "ssh-ed25519@openssh.com" => {
                    a("Ed25519", Vulnerable, "signature", Some(256))
                }
                "ssh-ed448" => a("Ed448", Vulnerable, "signature", Some(456)),
                b if b.starts_with("ecdsa-sha2-nistp256") => {
                    a("ECDSA-P256", Vulnerable, "signature", Some(256))
                }
                b if b.starts_with("ecdsa-sha2-nistp384") => {
                    a("ECDSA-P384", Vulnerable, "signature", Some(384))
                }
                b if b.starts_with("ecdsa-sha2-nistp521") => {
                    a("ECDSA-P521", Vulnerable, "signature", Some(521))
                }
                b if b.contains("mldsa") || b.contains("ml-dsa") => {
                    a("ML-DSA", Resistant, "signature", None)
                }
                _ => a("unknown", Unknown, "signature", None),
            }
        }
        "KexAlgorithms" => match n {
            "ext-info-c" | "ext-info-s" => None,
            _ if n.starts_with("kex-strict-") => None,
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
                a("X25519", Vulnerable, "key_agreement", Some(256))
            }
            "curve448-sha512" => a("X448", Vulnerable, "key_agreement", Some(448)),
            "ecdh-sha2-nistp256" => a("ECDH-P256", Vulnerable, "key_agreement", Some(256)),
            "ecdh-sha2-nistp384" => a("ECDH-P384", Vulnerable, "key_agreement", Some(384)),
            "ecdh-sha2-nistp521" => a("ECDH-P521", Vulnerable, "key_agreement", Some(521)),
            "diffie-hellman-group1-sha1" => a("DH-SHA-1", Vulnerable, "key_agreement", Some(1024)),
            "diffie-hellman-group14-sha1" => a("DH-SHA-1", Vulnerable, "key_agreement", Some(2048)),
            "diffie-hellman-group-exchange-sha1" => {
                a("DH-SHA-1", Vulnerable, "key_agreement", None)
            }
            "diffie-hellman-group14-sha256" => a("DH", Vulnerable, "key_agreement", Some(2048)),
            "diffie-hellman-group15-sha512" => a("DH", Vulnerable, "key_agreement", Some(3072)),
            "diffie-hellman-group16-sha512" => a("DH", Vulnerable, "key_agreement", Some(4096)),
            "diffie-hellman-group17-sha512" => a("DH", Vulnerable, "key_agreement", Some(6144)),
            "diffie-hellman-group18-sha512" => a("DH", Vulnerable, "key_agreement", Some(8192)),
            "diffie-hellman-group-exchange-sha256" => a("DH", Vulnerable, "key_agreement", None),
            _ if n.starts_with("sntrup761x25519") => a("sntrup761x25519", Hybrid, "kem", None),
            _ if n.starts_with("mlkem768x25519") => a("X25519MLKEM768", Hybrid, "kem", None),
            _ if n.starts_with("mlkem768nistp256") => a("SecP256r1MLKEM768", Hybrid, "kem", None),
            _ if n.starts_with("mlkem1024nistp384") => a("SecP384r1MLKEM1024", Hybrid, "kem", None),
            _ => a("unknown", Unknown, "key_agreement", None),
        },
        "Ciphers" => match n {
            "aes128-ctr" => a("AES-128-CTR", SymmetricOk, "block_cipher", Some(128)),
            "aes192-ctr" => a("AES-192-CTR", SymmetricOk, "block_cipher", Some(192)),
            "aes256-ctr" => a("AES-256-CTR", SymmetricOk, "block_cipher", Some(256)),
            "aes128-gcm@openssh.com" => a("AES-128-GCM", SymmetricOk, "block_cipher", Some(128)),
            "aes256-gcm@openssh.com" => a("AES-256-GCM", SymmetricOk, "block_cipher", Some(256)),
            "aes128-cbc" => a("AES-128-CBC", SymmetricOk, "block_cipher", Some(128)),
            "aes192-cbc" => a("AES-192-CBC", SymmetricOk, "block_cipher", Some(192)),
            "aes256-cbc" | "rijndael-cbc@lysator.liu.se" => {
                a("AES-256-CBC", SymmetricOk, "block_cipher", Some(256))
            }
            "chacha20-poly1305@openssh.com" => {
                a("ChaCha20-Poly1305", SymmetricOk, "stream_cipher", Some(256))
            }
            "3des-cbc" => a("3DES", Vulnerable, "block_cipher", Some(168)),
            "blowfish-cbc" => a("Blowfish", Vulnerable, "block_cipher", Some(128)),
            "cast128-cbc" => a("CAST-128", Vulnerable, "block_cipher", Some(128)),
            _ if n.starts_with("arcfour") => a("RC4", Vulnerable, "stream_cipher", None),
            "none" => a("none", Vulnerable, "block_cipher", None),
            _ => a("unknown", Unknown, "block_cipher", None),
        },
        "MACs" => {
            let base = n.trim_end_matches("-etm@openssh.com");
            match base {
                "hmac-sha2-256" => a("HMAC-SHA256", SymmetricOk, "mac", Some(256)),
                "hmac-sha2-512" => a("HMAC-SHA512", SymmetricOk, "mac", Some(512)),
                "hmac-sha1" | "hmac-sha1-96" => a("HMAC-SHA1", Vulnerable, "mac", Some(160)),
                "hmac-md5" | "hmac-md5-96" => a("HMAC-MD5", Vulnerable, "mac", Some(128)),
                "umac-128@openssh.com" | "umac-128" => a("UMAC-128", SymmetricOk, "mac", Some(128)),
                "umac-64@openssh.com" | "umac-64" => a("UMAC-64", Unknown, "mac", Some(64)),
                _ => a("unknown", Unknown, "mac", None),
            }
        }
        _ => None,
    }
}

// --- OpenSSL settings ----------------------------------------------------------

const TLS_VERSIONS: &[&str] = &["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

#[derive(Debug, Clone, Default)]
pub struct OpenSslSettings {
    pub min_protocol: Option<String>,
    pub max_protocol: Option<String>,
    pub cipher_string: Option<String>,
    pub ciphersuites: Vec<String>,
    pub groups: Vec<String>,
    pub signature_algorithms: Vec<String>,
}

impl OpenSslSettings {
    pub fn parse_text(raw: &str) -> Self {
        let mut s = Self::default();
        for line in raw.lines() {
            let line = strip_comment(line).trim();
            if let Some((k, v)) = line.split_once('=') {
                s.set(k.trim(), v.trim());
            }
        }
        s
    }

    /// First value wins, matching how Boab records sshd settings.
    fn set(&mut self, key: &str, value: &str) {
        let list = |v: &str| -> Vec<String> {
            v.split([':', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        let key = key.to_ascii_lowercase();
        // crypto-policies writes `TLS.MinProtocol` and `DTLS.MinProtocol`; Boab records TLS.
        if key.starts_with("dtls.") {
            return;
        }
        match key.strip_prefix("tls.").unwrap_or(&key) {
            "minprotocol" if self.min_protocol.is_none() => {
                self.min_protocol = Some(value.to_string())
            }
            "maxprotocol" if self.max_protocol.is_none() => {
                self.max_protocol = Some(value.to_string())
            }
            "cipherstring" if self.cipher_string.is_none() => {
                self.cipher_string = Some(value.to_string())
            }
            "ciphersuites" if self.ciphersuites.is_empty() => self.ciphersuites = list(value),
            "groups" | "curves" if self.groups.is_empty() => self.groups = list(value),
            "signaturealgorithms" if self.signature_algorithms.is_empty() => {
                self.signature_algorithms = list(value)
            }
            _ => {}
        }
    }

    /// TLS versions allowed by MinProtocol/MaxProtocol, or `None` when
    /// MinProtocol is not set (OpenSSL built-in defaults apply).
    pub fn allowed_protocols(&self) -> Option<Vec<String>> {
        let idx = |v: &str| TLS_VERSIONS.iter().position(|t| t.eq_ignore_ascii_case(v));
        let min = idx(self.min_protocol.as_deref()?)?;
        let max = self
            .max_protocol
            .as_deref()
            .and_then(idx)
            .unwrap_or(TLS_VERSIONS.len() - 1);
        Some(
            TLS_VERSIONS[min..=max.max(min)]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    }

    pub fn has_hybrid_group(&self) -> bool {
        self.groups.iter().any(|g| {
            let g = g.to_ascii_lowercase();
            g.contains("mlkem") || g.contains("kyber")
        })
    }

    fn write_into(&self, m: &mut Map<String, Value>) {
        m.insert("min_protocol".into(), json!(self.min_protocol));
        m.insert("max_protocol".into(), json!(self.max_protocol));
        m.insert("allowed_protocols".into(), json!(self.allowed_protocols()));
        m.insert("cipher_string".into(), json!(self.cipher_string));
        m.insert("ciphersuites".into(), json!(self.ciphersuites));
        m.insert("groups".into(), json!(self.groups));
        m.insert(
            "signature_algorithms".into(),
            json!(self.signature_algorithms),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_bit_lengths() {
        assert_eq!(mpint_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(mpint_bits(&[0x01]), 1);
        assert_eq!(mpint_bits(&[0x00]), 0);
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("*.conf", "50-redhat.conf"));
        assert!(!wildcard_match("*.conf", "50-redhat.conf.bak"));
        assert!(wildcard_match("a?c", "abc"));
    }

    #[test]
    fn ssh_line_splitting() {
        assert_eq!(
            split_ssh_line("  Ciphers aes256-ctr  # c"),
            Some(("Ciphers", "aes256-ctr"))
        );
        assert_eq!(
            split_ssh_line("MACs=hmac-sha2-256"),
            Some(("MACs", "hmac-sha2-256"))
        );
        assert_eq!(split_ssh_line("# only a comment"), None);
    }

    #[test]
    fn rhel8_backend_is_parsed() {
        let v = parse_openssh_backend(
            "CRYPTO_POLICY='-oCiphers=aes256-gcm@openssh.com,aes128-ctr -oMACs=hmac-sha2-256'",
        );
        assert_eq!(
            v,
            vec![
                (
                    "ciphers".to_string(),
                    "aes256-gcm@openssh.com,aes128-ctr".to_string()
                ),
                ("macs".to_string(), "hmac-sha2-256".to_string()),
            ]
        );
    }

    #[test]
    fn ssh_algorithm_classification() {
        let k =
            classify_ssh_algorithm("KexAlgorithms", "sntrup761x25519-sha512@openssh.com").unwrap();
        assert_eq!(k.status, PqcStatus::Hybrid);
        let k = classify_ssh_algorithm("KexAlgorithms", "diffie-hellman-group14-sha256").unwrap();
        assert_eq!((k.name, k.bits), ("DH", Some(2048)));
        assert!(classify_ssh_algorithm("KexAlgorithms", "ext-info-c").is_none());
        let c = classify_ssh_algorithm("Ciphers", "chacha20-poly1305@openssh.com").unwrap();
        assert_eq!(c.status, PqcStatus::SymmetricOk);
        let m = classify_ssh_algorithm("MACs", "hmac-sha2-512-etm@openssh.com").unwrap();
        assert_eq!(m.name, "HMAC-SHA512");
        let h =
            classify_ssh_algorithm("HostKeyAlgorithms", "ssh-rsa-cert-v01@openssh.com").unwrap();
        assert_eq!(h.name, "RSA-SHA-1");
    }

    #[test]
    fn openssl_protocol_range() {
        let s = OpenSslSettings::parse_text(
            "MinProtocol = TLSv1.2\nGroups = X25519MLKEM768:X25519:secp256r1\n",
        );
        assert_eq!(
            s.allowed_protocols(),
            Some(vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()])
        );
        assert!(s.has_hybrid_group());
        assert_eq!(OpenSslSettings::default().allowed_protocols(), None);
    }
}
