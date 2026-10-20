//! Golden fixture generator for the PowerShell port of Boab.
//!
//! Uses the real Rust library so the Pester suite can assert byte-level parity
//! without needing a Rust toolchain at test time.
//!
//! Usage:
//!   boab-golden-gen numbers  <out.json>
//!   boab-golden-gen scores   <out.json>
//!   boab-golden-gen workspace <fixture-scans-dir> <workspace-root>

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use boab::model::asset::{AssetType, CryptoAsset, MigrationDifficulty, PqcStatus};
use boab::model::scan::Scan;
use boab::model::system::{Classification, Criticality, System};
use boab::model::vendor::VendorEntry;
use boab::workspace::Workspace;
use boab::{dedup, plan, report, scoring, storage};
use serde_json::{json, Value};
use time::macros::datetime;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("numbers") => numbers(Path::new(&args[2])),
        Some("scores") => scores(Path::new(&args[2])),
        Some("workspace") => workspace(Path::new(&args[2]), Path::new(&args[3])),
        _ => anyhow::bail!("usage: boab-golden-gen numbers|scores|workspace ..."),
    }
}

/// Float formatting references: serde_json f64/f32 output and `{:.1}` output.
fn numbers(out: &Path) -> Result<()> {
    let f64s: Vec<f64> = vec![
        0.0, -0.0, 0.1, 0.3, 1.0, 2.5, 5.4, 10.0, 100.0, 1234.5678, 1e15, 1e16, 1.5e16, 1e21,
        123456789012345680.0, 0.0001, 0.00001, 1e-7, 3.0e-5, 5e-324, 1.7976931348623157e308,
        -42.125, 0.1 + 0.2, 1.0 / 3.0,
    ];
    let f32s: Vec<f32> = vec![
        0.0, 0.1, 0.3, 1.0, 2.7, 5.4, 5.7, 7.0, 10.0, 1e7, 1e13, 1e14, 1e-5, 1e-6, 1e-7,
        123.456, 16777216.0, 3.4028235e38,
    ];
    let fixed: Vec<String> = f32s.iter().map(|v| format!("{:.1}", v)).collect();
    let mut pct = Vec::new();
    for total in 1u32..=64 {
        for vulnerable in 0..=total {
            let p = (vulnerable as f32) * 100.0 / (total as f32);
            pct.push(json!([vulnerable, total, format!("{:.1}", p)]));
        }
    }
    let doc = json!({
        "f64": serde_json::to_string(&f64s)?,
        "f32": serde_json::to_string(&f32s)?,
        "f32_fixed1": fixed,
        "percent": pct,
    });
    fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

fn algo_asset(name: &str, params: Value, status: PqcStatus) -> CryptoAsset {
    let mut a = CryptoAsset::new(
        AssetType::Algorithm,
        name.to_string(),
        name.to_string(),
        status,
        true,
        MigrationDifficulty::Medium,
    );
    a.parameter_set = params;
    a
}

/// Priority/tier for every combination of LATICE sub-scores, plus algorithm
/// vulnerability scores and full RiskScores for representative assets.
fn scores(out: &Path) -> Result<()> {
    let mut table = Vec::new();
    for a in 0u8..=10 {
        for h in [0u8, 3, 5, 6, 8, 10] {
            for d in [0u8, 2, 4, 6, 8, 10] {
                for s in [1u8, 4, 7, 10] {
                    for m in [1u8, 3, 6, 8, 10] {
                        let p = scoring::priority(a, h, d, s, m);
                        let t = scoring::triage_tier(p, m, a);
                        table.push(json!([a, h, d, s, m, p, t]));
                    }
                }
            }
        }
    }

    let names: Vec<(&str, Value)> = vec![
        ("MD5", json!({})), ("md4", json!({})), ("SHA-1", json!({})), ("sha1", json!({})),
        ("SHA0", json!({})), ("RSA", json!({"key_size_bits": 1024})), ("RSA", json!({"bits": 1024})),
        ("RSA", json!({"key_size_bits": 2048})), ("RSA", json!({"key_size_bits": 3072})),
        ("RSA", json!({"key_size_bits": 4096})), ("RSA", json!({"key_size_bits": 8192})),
        ("RSA", json!({"key_size_bits": 4294969344u64})), ("RSA", json!({"key_size_bits": 2048.0})),
        ("RSA", json!({"key_size_bits": "2048"})), ("RSA", json!({"key_size_bits": null, "bits": 1024})),
        ("RSA", json!({})), ("rsaEncryption", json!({"key_size_bits": 2048})),
        ("DSA", json!({"key_size_bits": 1024})), ("DSA", json!({})), ("ECDSA", json!({"key_size_bits": 1024})),
        ("3DES", json!({})), ("RC4", json!({})), ("DES", json!({})), ("des-ede3-cbc", json!({})),
        ("ECDSA-P-256", json!({})), ("ECDSA-256", json!({})), ("ecdsa_p256", json!({})), ("P-256", json!({})),
        ("ECDH-256", json!({})), ("DH", json!({"key_size_bits": 2048})), ("ffdhe-2048", json!({"key_size_bits": 2048})),
        ("ECDSA-P-384", json!({})), ("ECDSA-P-521", json!({})), ("secp384r1", json!({})), ("P384", json!({})),
        ("X25519", json!({})), ("Ed25519", json!({})), ("X448", json!({})), ("Ed448", json!({})),
        ("ML-KEM-768", json!({})), ("ML-DSA-65", json!({})), ("dilithium3", json!({})),
        ("SLH-DSA-SHA2-128s", json!({})), ("falcon-512", json!({})), ("kyber768", json!({})),
        ("hqc-128", json!({})), ("sphincs+", json!({})), ("X25519MLKEM768", json!({})),
        ("AES-256-GCM", json!({})), ("AES256", json!({})), ("AES-GCM", json!({"key_size_bits": 256})),
        ("AES-GCM", json!({"key_size_bits": 128})), ("AES-128-GCM", json!({})), ("SHA-256", json!({})),
        ("SHA384", json!({})), ("SHA-512", json!({})), ("SHA3-256", json!({})), ("SHAKE128", json!({})),
        ("ChaCha20-Poly1305", json!({})), ("HMAC-SHA256", json!({})), ("hmac_sha512", json!({})),
        ("FrobnicatorCipher", json!({})), ("Blowfish", json!({})), ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", json!({})),
        ("TLS_AES_256_GCM_SHA384", json!({})), ("secp256r1", json!({})), ("x25519_mlkem768", json!({})),
        ("sha256WithRSAEncryption", json!({"key_size_bits": 2048})), ("ecdsa-with-SHA256", json!({})),
        ("RSA  2048", json!({"key_size_bits": 2048})), ("rsa--pss", json!({})), ("RSA/ECB/PKCS1Padding", json!({})),
        ("ÉCDSA-256", json!({})), ("", json!({})), ("RSA", json!(null)), ("RSA", json!([1024])),
    ];
    let mut algos = Vec::new();
    for (name, params) in &names {
        for status in [PqcStatus::Vulnerable, PqcStatus::Unknown] {
            let a = algo_asset(name, params.clone(), status);
            algos.push(json!({
                "name": name, "params": params, "pqc_status": status,
                "score": scoring::algo_vuln_score(&a),
            }));
        }
    }

    // Full scores for a grid of asset/system shapes at a fixed date.
    let today = datetime!(2026-05-18 12:00 UTC);
    let mut full = Vec::new();
    let systems = vec![
        None,
        Some(System::new("S1".into(), None, Classification::Official, Criticality::Low, false, None)),
        Some(System::new("S2".into(), None, Classification::Protected, Criticality::Standard, false, Some(3))),
        Some(System::new("S3".into(), None, Classification::Secret, Criticality::Essential, false, Some(12))),
        Some(System::new("S4".into(), None, Classification::TopSecret, Criticality::MissionCritical, false, Some(30))),
        Some(System::new("S5".into(), None, Classification::Unofficial, Criticality::Low, true, Some(0))),
    ];
    let types = [
        AssetType::Algorithm, AssetType::Certificate, AssetType::Key,
        AssetType::ProtocolEndpoint, AssetType::LibraryDependency,
    ];
    let classes = [
        None, Some(Classification::Unofficial), Some(Classification::Official),
        Some(Classification::OfficialSensitive), Some(Classification::Protected),
        Some(Classification::Secret), Some(Classification::TopSecret),
    ];
    let difficulties = [
        MigrationDifficulty::Trivial, MigrationDifficulty::Low, MigrationDifficulty::Medium,
        MigrationDifficulty::High, MigrationDifficulty::HardwareLocked,
    ];
    let statuses = [
        PqcStatus::Vulnerable, PqcStatus::Hybrid, PqcStatus::Resistant, PqcStatus::SymmetricOk, PqcStatus::Unknown,
    ];
    let algos_for_full = [("RSA", json!({"key_size_bits": 2048})), ("MD5", json!({})), ("X25519", json!({})), ("AES-256-GCM", json!({})), ("Unknown", json!({}))];
    let retention = [None, Some(2020u16), Some(2027), Some(2029), Some(2032), Some(2037), Some(2060)];
    let mut i = 0usize;
    for (si, sys) in systems.iter().enumerate() {
        for at in types {
            for (ai, (algo, params)) in algos_for_full.iter().enumerate() {
                let mut a = algo_asset(algo, params.clone(), statuses[(i + ai) % statuses.len()]);
                a.asset_type = at;
                a.data_classification = classes[(i + si) % classes.len()];
                a.migration_difficulty = difficulties[(i + ai + si) % difficulties.len()];
                a.data_retention_horizon_year = retention[(i * 3 + ai) % retention.len()];
                let score = scoring::score_asset(&a, sys.as_ref(), today);
                full.push(json!({
                    "system": sys,
                    "asset": a,
                    "score": score,
                }));
                i += 1;
            }
        }
    }

    let doc = json!({ "table": table, "algorithms": algos, "full": full, "year": 2026 });
    fs::write(out, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// Build a workspace from fixture scan files exactly as the CLI would.
fn workspace(scans_dir: &Path, root: &Path) -> Result<()> {
    fs::create_dir_all(root)?;
    let (ws, _) = Workspace::init(root, true)?;

    let systems = vec![
        System::new("Demo Payments".into(), None, Classification::Protected, Criticality::MissionCritical, true, Some(25)),
        System::new(
            "HR | People".into(),
            Some("Human \"resources\"\nline two".into()),
            Classification::OfficialSensitive,
            Criticality::Essential,
            false,
            None,
        ),
    ];
    storage::save_systems(&ws, &systems)?;

    let mut files: Vec<PathBuf> = fs::read_dir(scans_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    files.sort();
    for f in &files {
        let mut scan: Scan = storage::read_json(f).with_context(|| format!("{}", f.display()))?;
        for finding in scan.findings.iter_mut() {
            finding.crypto_asset_id = None;
        }
        dedup::promote_into_workspace(&mut scan, &ws)?;
        storage::save_scan(&ws, &scan)?;
    }

    // Exercise system linkage, classification and retention in scoring.
    let mut inv = storage::load_inventory(&ws)?;
    if inv.len() > 6 {
        inv[0].system_id = Some(systems[0].id);
        inv[1].data_classification = Some(Classification::Secret);
        inv[2].data_retention_horizon_year = Some(2060);
        inv[3].system_id = Some(systems[1].id);
        inv[4].data_retention_horizon_year = Some(2020);
        inv[5].migration_difficulty = MigrationDifficulty::HardwareLocked;
        inv[6].notes = Some("Owned by | payments".into());
    }
    storage::save_inventory(&ws, &inv)?;

    let mut overrides = storage::load_vendor_overrides(&ws)?;
    overrides.entries.push(VendorEntry {
        vendor: "Microsoft".into(),
        product: "Azure".into(),
        pqc_status: PqcStatus::Resistant,
        target_date: Some("2026-Q4".into()),
        source_url: None,
        source_note: Some("override".into()),
        last_verified_at: Some(time::OffsetDateTime::now_utc()),
    });
    overrides.entries.push(VendorEntry {
        vendor: "Acme".into(),
        product: "Widget".into(),
        pqc_status: PqcStatus::Hybrid,
        target_date: None,
        source_url: Some("https://example.com".into()),
        source_note: None,
        last_verified_at: None,
    });
    storage::save_vendor_overrides(&ws, &overrides)?;

    let p2028 = plan::generate(&ws, boab::model::asset::TargetMilestone::Y2028, None)?;
    plan::save(&ws, &p2028)?;
    std::thread::sleep(std::time::Duration::from_millis(5));
    let p2030 = plan::generate(&ws, boab::model::asset::TargetMilestone::Y2030, Some("Demo rollout".into()))?;
    plan::save(&ws, &p2030)?;

    let reports = ws.reports_dir();
    report::json::write(&ws, &reports.join("report.json"))?;
    report::cbom::write(&ws, &reports.join("bom.cdx.json"))?;
    report::markdown::write(&ws, &reports.join("readiness.md"))?;
    Ok(())
}
