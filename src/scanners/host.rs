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
//!
//! Symlinks are resolved inside the root: an absolute link target such as
//! `/usr/share/crypto-policies/...` is read from `<root>/usr/share/...`, never
//! from the machine running Boab, and `..` cannot climb above the root.
//! Files that exist but cannot be read are recorded in the scan record
//! (`config.collection_errors` and `error_message`) and logged as warnings,
//! so a partial collection is never reported as a clean one.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

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
    let rootfs = RootFs::new(root.clone());
    let host = options
        .host
        .clone()
        .unwrap_or_else(|| host_label_for(&rootfs));
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
        fs: &rootfs,
        root: &root,
        host: &host,
        scan_id: scan.id,
    };
    let ssh = SshConfig::load(&ctx);
    ctx.ssh_host_keys(&ssh, &mut scan.findings);
    ctx.ssh_algorithms(&ssh, &mut scan.findings);
    ctx.crypto_policy(&mut scan.findings);
    ctx.openssl_configs(&mut scan.findings);

    let errors = rootfs.errors.into_inner();
    if !errors.is_empty() {
        for e in &errors {
            tracing::warn!("host scan could not read {}", e);
        }
        scan.error_message = Some(format!(
            "{} path(s) under {} could not be read; inventory for this host may be incomplete",
            errors.len(),
            root.display()
        ));
        if let Some(cfg) = scan.config.as_object_mut() {
            cfg.insert("collection_errors".into(), json!(errors));
        }
    }
    scan.status = ScanStatus::Completed;
    scan.completed_at = Some(OffsetDateTime::now_utc());
    Ok(scan)
}

fn host_label_for(rootfs: &RootFs) -> String {
    if let Some(raw) = rootfs.read_text(&rootfs.root.join("etc/hostname")) {
        if let Some(h) = raw
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
        {
            return h.to_string();
        }
    }
    if rootfs.root.parent().is_none() {
        return super::local_host_label();
    }
    rootfs.root.display().to_string()
}

const MAX_SYMLINK_HOPS: usize = 40;

/// Filesystem access confined to the scanned root.
///
/// Paths handed to these methods are "logical" paths: `root` joined with the
/// path as seen on the scanned host. Each component is resolved with
/// `symlink_metadata`/`read_link`, so links are followed inside the root only.
struct RootFs {
    root: PathBuf,
    /// `<host path>: <error>` for every path that exists but could not be read.
    errors: RefCell<Vec<String>>,
}

impl RootFs {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            errors: RefCell::new(Vec::new()),
        }
    }

    /// Path on the scanned host for a logical path, with `/` separators.
    fn host_path(&self, path: &Path) -> String {
        match path.strip_prefix(&self.root) {
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

    /// Resolve a logical path to a real path inside the root.
    fn resolve(&self, logical: &Path) -> io::Result<PathBuf> {
        let rel = logical.strip_prefix(&self.root).unwrap_or(logical);
        let mut pending: VecDeque<OsString> = components_of(rel).into();
        let mut current: Vec<OsString> = Vec::new();
        let mut hops = 0usize;
        while let Some(comp) = pending.pop_front() {
            if comp == ".." {
                current.pop();
                continue;
            }
            let mut candidate = self.root.clone();
            candidate.extend(&current);
            candidate.push(&comp);
            let meta = fs::symlink_metadata(&candidate)?;
            if meta.file_type().is_symlink() {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(io::Error::other("too many levels of symbolic links"));
                }
                let target = fs::read_link(&candidate)?;
                if target.has_root() {
                    current.clear();
                }
                for c in components_of(&target).into_iter().rev() {
                    pending.push_front(c);
                }
            } else {
                current.push(comp);
            }
        }
        let mut real = self.root.clone();
        real.extend(&current);
        Ok(real)
    }

    fn note(&self, logical: &Path, err: &io::Error) {
        if err.kind() != io::ErrorKind::NotFound {
            self.errors
                .borrow_mut()
                .push(format!("{}: {}", self.host_path(logical), err));
        }
    }

    fn exists(&self, logical: &Path) -> bool {
        self.resolve(logical).is_ok()
    }

    fn is_file(&self, logical: &Path) -> bool {
        self.resolve(logical)
            .and_then(fs::metadata)
            .is_ok_and(|m| m.is_file())
    }

    fn is_dir(&self, logical: &Path) -> bool {
        self.resolve(logical)
            .and_then(fs::metadata)
            .is_ok_and(|m| m.is_dir())
    }

    /// Read a text file. A missing file is `None` without a diagnostic; any
    /// other failure is recorded.
    fn read_text(&self, logical: &Path) -> Option<String> {
        match self.resolve(logical).and_then(fs::read_to_string) {
            Ok(s) => Some(s),
            Err(e) => {
                self.note(logical, &e);
                None
            }
        }
    }

    /// Entry names and logical paths of a directory, sorted by name. A missing
    /// directory is empty without a diagnostic; other failures are recorded.
    fn list_dir(&self, logical: &Path) -> Vec<(String, PathBuf)> {
        let rd = match self.resolve(logical).and_then(fs::read_dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.note(logical, &e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for entry in rd {
            match entry {
                Ok(e) => {
                    let name = e.file_name().to_string_lossy().into_owned();
                    out.push((name.clone(), logical.join(&name)));
                }
                Err(e) => self.note(logical, &e),
            }
        }
        out.sort();
        out
    }
}

/// Normal components of a path, ignoring roots, prefixes and `.`.
fn components_of(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

struct Ctx<'a> {
    fs: &'a RootFs,
    root: &'a Path,
    host: &'a str,
    scan_id: Uuid,
}

impl Ctx<'_> {
    /// Path on the scanned host for a logical path under the root.
    fn host_path(&self, path: &Path) -> String {
        self.fs.host_path(path)
    }

    /// Map an absolute path on the scanned host to a logical path under the root.
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
        for (name, path) in self.fs.list_dir(&ssh_dir) {
            if !name.starts_with("ssh_host_") {
                continue;
            }
            if name.ends_with("_key.pub") || name.ends_with("_key-cert.pub") {
                public_files.insert(path);
            } else if name.ends_with("_key") {
                private_names.insert(path);
            }
        }
        for hk in &ssh.host_keys {
            let private = self.rebase(hk);
            let public = PathBuf::from(format!("{}.pub", private.display()));
            if self.fs.is_file(&public) {
                public_files.insert(public);
            } else if self.fs.exists(&private) {
                private_names.insert(private);
            }
        }

        // Only a public key that was read and parsed stands in for its private
        // key file; otherwise the name-based record below is still emitted.
        let mut parsed_public: BTreeSet<PathBuf> = BTreeSet::new();

        for pub_path in &public_files {
            let private = pub_path
                .to_string_lossy()
                .strip_suffix(".pub")
                .map(PathBuf::from)
                .filter(|p| !p.to_string_lossy().ends_with("-cert"));
            let private_present = private.as_ref().is_some_and(|p| self.fs.exists(p));
            let Some(line) = self.fs.read_text(pub_path) else {
                continue;
            };
            match parse_ssh_public_key(&line) {
                Some(key) => {
                    out.push(self.ssh_key_finding(pub_path, &key, private_present));
                    parsed_public.insert(pub_path.clone());
                }
                None => tracing::warn!(
                    "{} is not a readable SSH public key",
                    self.host_path(pub_path)
                ),
            }
        }

        // Private key files with no readable `.pub` beside them: record the
        // algorithm implied by the file name, without opening the file.
        for private in &private_names {
            let public = PathBuf::from(format!("{}.pub", private.display()));
            if parsed_public.contains(&public) {
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
        let already_read = self
            .fs
            .resolve(&backend)
            .is_ok_and(|real| ssh.visited.contains(&real));
        if !already_read {
            if let Some(raw) = self.fs.read_text(&backend) {
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
        let (policy, source) = match self.first_value_line(&state) {
            Some(p) => (p, state),
            None => match self.first_value_line(&config) {
                Some(p) => (p, config),
                None => return,
            },
        };
        let mut parts = policy.split(':');
        let base_policy = parts.next().unwrap_or("").to_string();
        let subpolicies: Vec<String> = parts.map(str::to_string).collect();

        let backends: Vec<String> = self
            .fs
            .list_dir(&base.join("back-ends"))
            .into_iter()
            .map(|(name, _)| name)
            .filter(|n| n.ends_with(".config"))
            .collect();

        let mut extra = Map::new();
        extra.insert("policy".into(), Value::from(policy.clone()));
        extra.insert("base_policy".into(), Value::from(base_policy.clone()));
        extra.insert("subpolicies".into(), json!(subpolicies));
        extra.insert("backends".into(), json!(backends));
        let openssl_backend = base.join("back-ends/opensslcnf.config");
        // The back-end is the body of the policy's SSL section, a flat list.
        let tls = self
            .fs
            .read_text(&openssl_backend)
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
            if !self.fs.is_file(&path) {
                continue;
            }
            // Distro symlinks often point several of these at one file. Resolve
            // inside the scanned root, never on the machine running Boab.
            let real = self.fs.resolve(&path).unwrap_or_else(|_| path.clone());
            if !seen.insert(real) {
                continue;
            }
            let mut conf = OpenSslConf::default();
            let mut files = Vec::new();
            self.read_openssl_file(&path, &mut conf, &mut files, 0);
            let (settings, ssl_section) = conf.system_default();
            let location = self.host_path(&path);
            let mut extra = Map::new();
            settings.write_into(&mut extra);
            extra.insert("config_files".into(), json!(files));
            extra.insert("ssl_section".into(), json!(ssl_section));
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

    /// Read an OpenSSL config file into `conf`, splicing `.include` files in
    /// at the point they appear, as OpenSSL does.
    fn read_openssl_file(
        &self,
        path: &Path,
        conf: &mut OpenSslConf,
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
        let Some(raw) = self.fs.read_text(path) else {
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
                if self.fs.is_dir(&p) {
                    for (name, e) in self.fs.list_dir(&p) {
                        if name.ends_with(".cnf") || name.ends_with(".conf") {
                            self.read_openssl_file(&e, conf, files, depth + 1);
                        }
                    }
                } else {
                    self.read_openssl_file(&p, conf, files, depth + 1);
                }
                continue;
            }
            conf.line(line);
        }
    }

    fn first_value_line(&self, path: &Path) -> Option<String> {
        let raw = self.fs.read_text(path)?;
        raw.lines()
            .map(|l| strip_comment(l).trim())
            .find(|l| !l.is_empty())
            .map(str::to_string)
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map(|(a, _)| a).unwrap_or(line)
}

// --- sshd_config -------------------------------------------------------------

#[derive(Debug, Default)]
struct SshConfig {
    /// Lower-cased directive -> (value, host path of the file that set it).
    /// sshd uses the first value it reads for each directive.
    directives: BTreeMap<String, (String, String)>,
    /// HostKey paths on the scanned host.
    host_keys: Vec<String>,
    /// Resolved (in-root) paths of every config file read, so each is read once.
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
        let real = ctx.fs.resolve(path).unwrap_or_else(|_| path.to_path_buf());
        if depth > 16 || !self.visited.insert(real) {
            return;
        }
        let Some(raw) = ctx.fs.read_text(path) else {
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
    ctx.fs
        .list_dir(&dir)
        .into_iter()
        .filter(|(name, _)| wildcard_match(&file_pat, name))
        .map(|(_, p)| p)
        .collect()
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

    /// Later assignments replace earlier ones, as in OpenSSL config sections.
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
            "minprotocol" => self.min_protocol = Some(value.to_string()),
            "maxprotocol" => self.max_protocol = Some(value.to_string()),
            "cipherstring" => self.cipher_string = Some(value.to_string()),
            "ciphersuites" => self.ciphersuites = list(value),
            "groups" | "curves" => self.groups = list(value),
            "signaturealgorithms" => self.signature_algorithms = list(value),
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

/// An OpenSSL config file split into sections. Within a section a later
/// assignment of the same name replaces an earlier one.
#[derive(Debug, Default)]
pub struct OpenSslConf {
    /// Section name -> (lower-cased key, value) in file order. The unnamed
    /// leading section is `""`.
    sections: BTreeMap<String, Vec<(String, String)>>,
    current: String,
}

impl OpenSslConf {
    pub fn parse_text(raw: &str) -> Self {
        let mut c = Self::default();
        for line in raw.lines() {
            c.line(strip_comment(line).trim());
        }
        c
    }

    fn line(&mut self, line: &str) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            self.current = name.trim().to_string();
            return;
        }
        if let Some((k, v)) = line.split_once('=') {
            self.sections
                .entry(self.current.clone())
                .or_default()
                .push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    /// Last value of `key` in `section`, OpenSSL's precedence.
    fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)?
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Settings OpenSSL applies to every TLS context: the section named by
    /// `system_default` in the `ssl_conf` module that `openssl_conf` selects.
    /// Returns empty settings and `None` when that chain is not configured,
    /// meaning OpenSSL's built-in defaults apply.
    pub fn system_default(&self) -> (OpenSslSettings, Option<String>) {
        let mut settings = OpenSslSettings::default();
        let section = self
            .get("", "openssl_conf")
            .and_then(|init| self.get(init, "ssl_conf"))
            .and_then(|ssl| self.get(ssl, "system_default"));
        let Some(section) = section else {
            return (settings, None);
        };
        if let Some(entries) = self.sections.get(section) {
            for (k, v) in entries {
                settings.set(k, v);
            }
        }
        (settings, Some(section.to_string()))
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
    fn openssl_last_value_wins_within_a_section() {
        let s = OpenSslSettings::parse_text(
            "MinProtocol = TLSv1\nGroups = X25519MLKEM768\nMinProtocol = TLSv1.2\nGroups = X25519\n",
        );
        assert_eq!(s.min_protocol.as_deref(), Some("TLSv1.2"));
        assert!(!s.has_hybrid_group());
    }

    #[test]
    fn openssl_settings_come_from_the_system_default_section_only() {
        let c = OpenSslConf::parse_text(
            "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = sys\n\
             [unused]\nGroups = X25519MLKEM768\nMinProtocol = TLSv1\n\
             [sys]\nGroups = X25519:secp256r1\nMinProtocol = TLSv1.2\n",
        );
        let (s, section) = c.system_default();
        assert_eq!(section.as_deref(), Some("sys"));
        assert_eq!(s.min_protocol.as_deref(), Some("TLSv1.2"));
        assert!(!s.has_hybrid_group());

        // No system_default chain: OpenSSL defaults apply, nothing is recorded.
        let (s, section) = OpenSslConf::parse_text("[x]\nMinProtocol = TLSv1\n").system_default();
        assert_eq!((s.min_protocol, section), (None, None));
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
