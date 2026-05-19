//! Per-language regex packs for the codebase scanner.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::model::asset::PqcStatus;
use crate::model::finding::Confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Go,
    Python,
    JavaScript,
    Java,
    DotNet,
    Generic,
}

impl Language {
    pub fn from_path(path: &std::path::Path) -> Option<Self> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())?
            .to_ascii_lowercase();
        match ext.as_str() {
            "rs" => Some(Language::Rust),
            "go" => Some(Language::Go),
            "py" => Some(Language::Python),
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => Some(Language::JavaScript),
            "java" | "kt" | "kts" => Some(Language::Java),
            "cs" | "vb" | "fs" => Some(Language::DotNet),
            "toml" | "yaml" | "yml" | "json" | "xml" | "conf" | "ini" => Some(Language::Generic),
            _ => None,
        }
    }
}

/// A matchable pattern with the algorithm it represents.
#[derive(Debug, Clone)]
pub struct AlgorithmPattern {
    pub regex: Regex,
    pub algorithm_name: &'static str,
    pub pqc_status: PqcStatus,
    pub confidence: Confidence,
    pub primitive: Option<&'static str>,
    pub key_size_bits: Option<u32>,
}

fn rx(s: &str) -> Regex {
    Regex::new(s).expect("invalid built-in regex")
}

/// Patterns shared across every language (algorithm names in literal strings).
pub static GENERIC: Lazy<Vec<AlgorithmPattern>> = Lazy::new(|| {
    vec![
        // Broken hashes.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bMD5\b"#),
            algorithm_name: "MD5",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("hash"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bSHA[-_]?1\b"#),
            algorithm_name: "SHA-1",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("hash"),
            key_size_bits: None,
        },
        // RSA sizes.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bRSA[-_]?1024\b"#),
            algorithm_name: "RSA",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(1024),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bRSA[-_]?2048\b"#),
            algorithm_name: "RSA",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(2048),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bRSA[-_]?3072\b"#),
            algorithm_name: "RSA",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(3072),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bRSA[-_]?4096\b"#),
            algorithm_name: "RSA",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(4096),
        },
        // Elliptic.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bECDSA[-_]?P[-_]?256\b"#),
            algorithm_name: "ECDSA-P-256",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(256),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bECDSA[-_]?P[-_]?384\b"#),
            algorithm_name: "ECDSA-P-384",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(384),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bED25519\b"#),
            algorithm_name: "Ed25519",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(255),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bX25519\b"#),
            algorithm_name: "X25519",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("key_agreement"),
            key_size_bits: Some(255),
        },
        // Symmetric ok.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bAES[-_]?256(?:[-_]?(?:GCM|CBC|CCM|CTR))?\b"#),
            algorithm_name: "AES-256",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("block_cipher"),
            key_size_bits: Some(256),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bAES[-_]?128(?:[-_]?(?:GCM|CBC|CCM|CTR))?\b"#),
            algorithm_name: "AES-128",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("block_cipher"),
            key_size_bits: Some(128),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bChaCha20(?:[-_]?Poly1305)?\b"#),
            algorithm_name: "ChaCha20-Poly1305",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("stream_cipher"),
            key_size_bits: Some(256),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bSHA[-_]?256\b"#),
            algorithm_name: "SHA-256",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("hash"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bSHA[-_]?384\b"#),
            algorithm_name: "SHA-384",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("hash"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bSHA[-_]?512\b"#),
            algorithm_name: "SHA-512",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("hash"),
            key_size_bits: None,
        },
        // PQC.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bML[-_]?KEM[-_]?(?:512|768|1024)?\b"#),
            algorithm_name: "ML-KEM",
            pqc_status: PqcStatus::Resistant,
            confidence: Confidence::High,
            primitive: Some("kem"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bML[-_]?DSA[-_]?(?:44|65|87)?\b"#),
            algorithm_name: "ML-DSA",
            pqc_status: PqcStatus::Resistant,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bSLH[-_]?DSA\b"#),
            algorithm_name: "SLH-DSA",
            pqc_status: PqcStatus::Resistant,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bKyber(?:512|768|1024)?\b"#),
            algorithm_name: "Kyber",
            pqc_status: PqcStatus::Resistant,
            confidence: Confidence::High,
            primitive: Some("kem"),
            key_size_bits: None,
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bDilithium[2-5]?\b"#),
            algorithm_name: "Dilithium",
            pqc_status: PqcStatus::Resistant,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: None,
        },
        // Hybrid signal.
        AlgorithmPattern {
            regex: rx(r#"(?i)\bX25519MLKEM768\b"#),
            algorithm_name: "X25519MLKEM768",
            pqc_status: PqcStatus::Hybrid,
            confidence: Confidence::High,
            primitive: Some("kem"),
            key_size_bits: None,
        },
        // Other broken or weak primitives.
        AlgorithmPattern {
            regex: rx(r#"(?i)\b3DES\b|\bTripleDES\b|\bDES[-_]EDE3?\b"#),
            algorithm_name: "3DES",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("block_cipher"),
            key_size_bits: Some(168),
        },
        AlgorithmPattern {
            regex: rx(r#"(?i)\bRC4\b"#),
            algorithm_name: "RC4",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("stream_cipher"),
            key_size_bits: None,
        },
        // JWT alg tokens (often appear inside JSON or code).
        AlgorithmPattern {
            regex: rx(r#""alg"\s*:\s*"RS256""#),
            algorithm_name: "RSA",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(2048),
        },
        AlgorithmPattern {
            regex: rx(r#""alg"\s*:\s*"ES256""#),
            algorithm_name: "ECDSA-P-256",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(256),
        },
        AlgorithmPattern {
            regex: rx(r#""alg"\s*:\s*"EdDSA""#),
            algorithm_name: "Ed25519",
            pqc_status: PqcStatus::Vulnerable,
            confidence: Confidence::High,
            primitive: Some("signature"),
            key_size_bits: Some(255),
        },
        AlgorithmPattern {
            regex: rx(r#""alg"\s*:\s*"HS256""#),
            algorithm_name: "HMAC-SHA256",
            pqc_status: PqcStatus::SymmetricOk,
            confidence: Confidence::High,
            primitive: Some("mac"),
            key_size_bits: None,
        },
    ]
});

/// Lower-confidence library import patterns. Detect that crypto is in use,
/// even when we cannot infer the algorithm.
#[derive(Debug, Clone)]
pub struct LibraryPattern {
    pub regex: Regex,
    pub library_name: &'static str,
    pub language: Language,
    pub confidence: Confidence,
}

pub static LIBRARIES: Lazy<Vec<LibraryPattern>> = Lazy::new(|| {
    vec![
        // Rust.
        LibraryPattern {
            regex: rx(r#"\buse\s+ring(?:::|;)"#),
            library_name: "ring",
            language: Language::Rust,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"\buse\s+rustls(?:::|;)"#),
            library_name: "rustls",
            language: Language::Rust,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"\buse\s+openssl(?:::|;)"#),
            library_name: "openssl",
            language: Language::Rust,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"\buse\s+sha2(?:::|;)"#),
            library_name: "sha2",
            language: Language::Rust,
            confidence: Confidence::Medium,
        },
        // Go.
        LibraryPattern {
            regex: rx(r#""crypto/[a-z0-9]+""#),
            library_name: "stdlib crypto",
            language: Language::Go,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#""golang\.org/x/crypto/[a-z0-9]+""#),
            library_name: "x/crypto",
            language: Language::Go,
            confidence: Confidence::Medium,
        },
        // Python.
        LibraryPattern {
            regex: rx(r#"(?m)^\s*(?:from|import)\s+cryptography(?:\.|\s|$)"#),
            library_name: "cryptography",
            language: Language::Python,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"(?m)^\s*(?:from|import)\s+Crypto(?:\.|\s|$)"#),
            library_name: "pycryptodome",
            language: Language::Python,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"(?m)^\s*(?:from|import)\s+hashlib"#),
            library_name: "hashlib",
            language: Language::Python,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"(?m)^\s*(?:from|import)\s+ssl"#),
            library_name: "ssl",
            language: Language::Python,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"(?m)^\s*(?:from|import)\s+jwt"#),
            library_name: "pyjwt",
            language: Language::Python,
            confidence: Confidence::Medium,
        },
        // JavaScript.
        LibraryPattern {
            regex: rx(r#"require\(\s*["']crypto["']\s*\)"#),
            library_name: "node:crypto",
            language: Language::JavaScript,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"from\s+["']crypto["']"#),
            library_name: "node:crypto",
            language: Language::JavaScript,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"require\(\s*["']node-forge["']\s*\)"#),
            library_name: "node-forge",
            language: Language::JavaScript,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"require\(\s*["']tweetnacl["']\s*\)"#),
            library_name: "tweetnacl",
            language: Language::JavaScript,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"require\(\s*["']jsonwebtoken["']\s*\)"#),
            library_name: "jsonwebtoken",
            language: Language::JavaScript,
            confidence: Confidence::Medium,
        },
        // Java.
        LibraryPattern {
            regex: rx(r#"\bimport\s+javax\.crypto\."#),
            library_name: "javax.crypto",
            language: Language::Java,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"\bimport\s+java\.security\."#),
            library_name: "java.security",
            language: Language::Java,
            confidence: Confidence::Medium,
        },
        LibraryPattern {
            regex: rx(r#"\bimport\s+org\.bouncycastle\."#),
            library_name: "BouncyCastle",
            language: Language::Java,
            confidence: Confidence::Medium,
        },
        // .NET.
        LibraryPattern {
            regex: rx(r#"\busing\s+System\.Security\.Cryptography\b"#),
            library_name: "System.Security.Cryptography",
            language: Language::DotNet,
            confidence: Confidence::Medium,
        },
    ]
});
