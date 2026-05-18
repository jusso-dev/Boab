//! Codebase scanner: walks a directory, applies per-language pattern packs,
//! and emits findings.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use serde_json::json;
use uuid::Uuid;

use crate::model::finding::{Confidence, Finding, SourceType};
use crate::model::scan::{Scan, ScanStatus, ScanType};
use time::OffsetDateTime;

pub mod patterns;

use patterns::{Language, GENERIC, LIBRARIES};

const DEFAULT_EXCLUDES: &[&str] = &[
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "target",
    "dist",
    "build",
    ".git",
];

/// Files matching these extensions are bytes-only and treated as crypto material findings.
const CERT_KEY_EXTS: &[&str] = &[
    "pem", "crt", "cer", "der", "p7b", "p12", "pfx", "jks", "key",
];

/// Options for the codebase scanner.
#[derive(Debug, Clone, Default)]
pub struct CodebaseOptions {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub name: Option<String>,
}

/// Scan a path on disk.
pub fn scan_path(path: &Path, options: &CodebaseOptions) -> Result<Scan> {
    let root = path
        .canonicalize()
        .with_context(|| format!("could not resolve scan path {}", path.display()))?;
    let mut scan = Scan::new(
        options
            .name
            .clone()
            .unwrap_or_else(|| format!("codebase:{}", root.display())),
        ScanType::Codebase,
        root.display().to_string(),
    );
    scan.config = json!({
        "include": options.include,
        "exclude": options.exclude,
        "default_excludes": DEFAULT_EXCLUDES,
    });
    scan.status = ScanStatus::Running;

    let mut builder = WalkBuilder::new(&root);
    builder
        .standard_filters(true)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .hidden(true)
        .require_git(false);

    let mut overrides = ignore::overrides::OverrideBuilder::new(&root);
    let all_excludes: Vec<String> = DEFAULT_EXCLUDES
        .iter()
        .map(|s| s.to_string())
        .chain(options.exclude.iter().cloned())
        .collect();
    for ex in &all_excludes {
        let _ = overrides.add(&format!("!{}/", ex));
        let _ = overrides.add(&format!("!**/{}/**", ex));
    }
    for inc in &options.include {
        let _ = overrides.add(inc);
    }
    if let Ok(ov) = overrides.build() {
        builder.overrides(ov);
    }

    let walker = builder.build();
    let scan_id = scan.id;
    for dent in walker.flatten() {
        let path = dent.path();
        if !dent.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        match scan_file(scan_id, path, &root) {
            Ok(mut new_findings) => scan.findings.append(&mut new_findings),
            Err(e) => {
                tracing::debug!("skip {}: {}", path.display(), e);
            }
        }
    }

    scan.status = ScanStatus::Completed;
    scan.completed_at = Some(OffsetDateTime::now_utc());
    Ok(scan)
}

fn relative(root: &Path, file: &Path) -> PathBuf {
    file.strip_prefix(root)
        .map(PathBuf::from)
        .unwrap_or_else(|_| file.to_path_buf())
}

fn scan_file(scan_id: Uuid, file: &Path, root: &Path) -> Result<Vec<Finding>> {
    let rel = relative(root, file).display().to_string();
    let mut out = Vec::new();

    // Cert/key/keystore files: emit a finding directly.
    if let Some(ext) = file
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        if CERT_KEY_EXTS.contains(&ext.as_str()) {
            let metadata = fs::metadata(file).ok();
            let size = metadata.map(|m| m.len()).unwrap_or(0);
            let evidence = json!({
                "kind": "cert_or_keystore_file",
                "extension": ext,
                "size_bytes": size,
            });
            out.push(Finding::new(
                scan_id,
                SourceType::File,
                rel.clone(),
                evidence,
                Confidence::Low,
            ));
            return Ok(out);
        }
    }

    // Skip binaries above a sane threshold: avoid huge memory spikes.
    let metadata = fs::metadata(file).context("metadata")?;
    if metadata.len() > 4 * 1024 * 1024 {
        return Ok(out);
    }

    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return Ok(out), // binary or non-UTF8
    };

    let language = Language::from_path(file).unwrap_or(Language::Generic);

    // Algorithm-name patterns (generic, language-agnostic).
    for pat in GENERIC.iter() {
        for m in pat.regex.find_iter(&content) {
            let (line, snippet) = line_and_snippet(&content, m.start(), m.end());
            let mut params = serde_json::Map::new();
            if let Some(bits) = pat.key_size_bits {
                params.insert("key_size_bits".to_string(), json!(bits));
            }
            if let Some(p) = pat.primitive {
                params.insert("primitive".to_string(), json!(p));
            }
            let evidence = json!({
                "kind": "algorithm_match",
                "algorithm_name": pat.algorithm_name,
                "pqc_status": pat.pqc_status,
                "parameter_set": params,
                "language": format!("{:?}", language),
                "match": m.as_str(),
                "line": line,
                "snippet": snippet,
            });
            out.push(Finding::new(
                scan_id,
                SourceType::File,
                format!("{}:{}", rel, line),
                evidence,
                pat.confidence,
            ));
        }
    }

    // Library-import patterns: only those matching the language.
    for pat in LIBRARIES.iter() {
        if pat.language != language {
            continue;
        }
        for m in pat.regex.find_iter(&content) {
            let (line, snippet) = line_and_snippet(&content, m.start(), m.end());
            let evidence = json!({
                "kind": "library_import",
                "library_name": pat.library_name,
                "language": format!("{:?}", language),
                "match": m.as_str(),
                "line": line,
                "snippet": snippet,
            });
            out.push(Finding::new(
                scan_id,
                SourceType::File,
                format!("{}:{}", rel, line),
                evidence,
                pat.confidence,
            ));
        }
    }

    Ok(out)
}

fn line_and_snippet(content: &str, start: usize, _end: usize) -> (u32, String) {
    let mut line_no: u32 = 1;
    let mut line_start: usize = 0;
    for (i, b) in content.bytes().enumerate() {
        if i == start {
            break;
        }
        if b == b'\n' {
            line_no += 1;
            line_start = i + 1;
        }
    }
    // 3 lines of context: previous, current, next.
    let lines: Vec<&str> = content.lines().collect();
    let idx = (line_no as usize).saturating_sub(1);
    let lo = idx.saturating_sub(1);
    let hi = (idx + 2).min(lines.len());
    let snippet = lines[lo..hi].join("\n");
    // line_start is unused except to anchor the future column calculation; suppress warning.
    let _ = line_start;
    (line_no, snippet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_md5_in_rust() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.rs");
        std::fs::write(&f, "use sha2;\n// MD5 is dangerous\nlet h = md5();\n").unwrap();
        let scan = scan_path(dir.path(), &CodebaseOptions::default()).unwrap();
        assert!(scan.findings.iter().any(|f| f
            .evidence
            .get("algorithm_name")
            .and_then(|v| v.as_str())
            == Some("MD5")));
    }

    #[test]
    fn detects_python_import() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.py");
        std::fs::write(&f, "from cryptography.hazmat import primitives\n").unwrap();
        let scan = scan_path(dir.path(), &CodebaseOptions::default()).unwrap();
        assert!(scan.findings.iter().any(|f| f
            .evidence
            .get("library_name")
            .and_then(|v| v.as_str())
            == Some("cryptography")));
    }

    #[test]
    fn detects_ml_kem_resistant() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.go");
        std::fs::write(&f, "// switching to ML-KEM-768 next quarter\n").unwrap();
        let scan = scan_path(dir.path(), &CodebaseOptions::default()).unwrap();
        assert!(scan.findings.iter().any(|f| f
            .evidence
            .get("algorithm_name")
            .and_then(|v| v.as_str())
            == Some("ML-KEM")));
    }

    #[test]
    fn detects_cert_file_extension() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("server.pem");
        std::fs::write(&f, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let scan = scan_path(dir.path(), &CodebaseOptions::default()).unwrap();
        assert!(scan
            .findings
            .iter()
            .any(|f| f.evidence.get("kind").and_then(|v| v.as_str())
                == Some("cert_or_keystore_file")));
    }

    #[test]
    fn default_excludes_skip_node_modules() {
        let dir = TempDir::new().unwrap();
        let inner = dir.path().join("node_modules").join("forge");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("index.js"), "const md5 = require('crypto');\n").unwrap();
        let scan = scan_path(dir.path(), &CodebaseOptions::default()).unwrap();
        assert!(scan.findings.is_empty(), "node_modules should be excluded");
    }
}
