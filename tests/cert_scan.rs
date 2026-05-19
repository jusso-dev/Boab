use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("boab").expect("boab binary")
}

fn pem_fixture() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/certs");
    p
}

#[test]
fn scan_certs_picks_up_rsa_certificate() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "certs",
            pem_fixture().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("cert scan"));

    let inv_raw = std::fs::read_to_string(tmp.path().join(".boab/inventory.json")).unwrap();
    let inv: serde_json::Value = serde_json::from_str(&inv_raw).unwrap();
    let arr = inv.as_array().unwrap();
    assert!(!arr.is_empty(), "expected at least one cert in inventory");
    let has_cert = arr
        .iter()
        .any(|a| a.get("asset_type").and_then(|v| v.as_str()) == Some("certificate"));
    assert!(has_cert);
}

#[test]
fn tls_probe_hsts_in_air_gapped_mode_errors() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "tls",
            "example.com:443",
            "--probe-hsts",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("air-gapped"));
}

#[test]
fn tls_scan_no_targets_errors() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "scan", "tls"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no TLS targets"));
}
