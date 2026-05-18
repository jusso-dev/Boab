//! End-to-end happy path: fresh workspace, scan codebase, scan certs,
//! generate plan, emit all three reports.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("boab").expect("boab binary")
}

fn fixture_codebase() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/codebase");
    p
}

fn fixture_certs() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/certs");
    p
}

#[test]
fn full_happy_path() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().to_str().unwrap();

    bin().args(["--workspace", ws, "init"]).assert().success();

    bin()
        .args([
            "--workspace",
            ws,
            "system",
            "add",
            "--name",
            "Payments",
            "--classification",
            "protected",
            "--criticality",
            "mission_critical",
            "--soci",
            "--lifetime-years",
            "25",
        ])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            ws,
            "scan",
            "codebase",
            fixture_codebase().to_str().unwrap(),
        ])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            ws,
            "scan",
            "certs",
            fixture_certs().to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .args(["--workspace", ws, "plan", "generate", "--milestone", "2028"])
        .assert()
        .success();

    for fmt in ["json", "cbom", "md"] {
        bin()
            .args(["--workspace", ws, "report", "--format", fmt])
            .assert()
            .success();
    }

    let reports = tmp.path().join(".boab/reports");
    assert!(reports.join("report.json").is_file());
    assert!(reports.join("bom.cdx.json").is_file());
    assert!(reports.join("readiness.md").is_file());
}
