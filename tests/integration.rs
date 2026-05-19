use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("boab").expect("boab binary")
}

#[test]
fn init_creates_workspace_layout() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("workspace initialised"));

    let dir = tmp.path().join(".boab");
    assert!(dir.is_dir());
    assert!(dir.join("config.toml").is_file());
    assert!(dir.join("systems.json").is_file());
    assert!(dir.join("inventory.json").is_file());
    assert!(dir.join("scans").is_dir());
    assert!(dir.join("plans").is_dir());
    assert!(dir.join("reports").is_dir());
    assert!(dir.join("vendor-overrides.json").is_file());
}

#[test]
fn init_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already initialised"));
}

#[test]
fn system_add_then_list_roundtrip() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
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
        .success()
        .stdout(predicate::str::contains("added system Payments"));

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "system",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Payments"))
        .stdout(predicate::str::contains("protected"))
        .stdout(predicate::str::contains("mission_critical"));
}

#[test]
fn inventory_list_on_empty_workspace_says_so() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
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
        .stdout(predicate::str::contains("(no inventory entries)"));
}

#[test]
fn config_get_and_set() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "config",
            "set",
            "scanner.tls_timeout_seconds",
            "30",
        ])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "config",
            "get",
            "scanner.tls_timeout_seconds",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("30"));
}

#[test]
fn report_empty_workspace_still_emits_file() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "report",
            "--format",
            "json",
        ])
        .assert()
        .success();
    let p = tmp.path().join(".boab/reports/report.json");
    assert!(p.is_file());
}

#[test]
fn plan_list_on_empty_workspace_says_so() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "plan", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no plans)"));
}

#[test]
fn workspace_not_initialised_errors() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "system",
            "list",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not initialised"));
}
