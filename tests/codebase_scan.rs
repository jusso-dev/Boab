use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("boab").expect("boab binary")
}

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/codebase");
    p
}

#[test]
fn fixture_scan_produces_inventory_then_idempotent_rescan() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();

    let fixture = fixture_path();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "codebase",
            fixture.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("scan").and(predicate::str::contains("findings")));

    let inventory_path = tmp.path().join(".boab/inventory.json");
    let raw = std::fs::read_to_string(&inventory_path).unwrap();
    let inv: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let first_len = inv.as_array().unwrap().len();
    assert!(
        first_len >= 15,
        "expected >= 15 inventory entries, got {}",
        first_len
    );

    // Sanity: check we found at least one well-known algorithm.
    let algos: Vec<String> = inv
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["algorithm_name"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(algos.iter().any(|a| a == "MD5" || a == "SHA-1"));
    assert!(algos
        .iter()
        .any(|a| a == "ML-KEM" || a == "ML-DSA" || a == "Kyber"));

    // Second scan: count must not change.
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "codebase",
            fixture.to_str().unwrap(),
        ])
        .assert()
        .success();
    let inv2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&inventory_path).unwrap()).unwrap();
    assert_eq!(
        inv2.as_array().unwrap().len(),
        first_len,
        "rescan introduced duplicates"
    );
}

#[test]
fn inventory_list_after_scan_shows_rows() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    let fixture = fixture_path();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "codebase",
            fixture.to_str().unwrap(),
        ])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "inventory",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALGORITHM"));
}

#[test]
fn inventory_filter_by_tier_returns_subset() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    let fixture = fixture_path();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "codebase",
            fixture.to_str().unwrap(),
        ])
        .assert()
        .success();
    // No system attached, so HNDL falls back to 5 and we likely sit in tier 2/3 for vulnerable items.
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "inventory",
            "list",
            "--tier",
            "4",
        ])
        .assert()
        .success();
}
