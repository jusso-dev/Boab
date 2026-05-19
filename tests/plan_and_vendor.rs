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

fn init_and_scan() -> TempDir {
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
            "codebase",
            fixture_path().to_str().unwrap(),
        ])
        .assert()
        .success();
    tmp
}

#[test]
fn plan_generate_2028_contains_tier_1_and_2_items() {
    let tmp = init_and_scan();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "plan",
            "generate",
            "--milestone",
            "2028",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("plan").and(predicate::str::contains("items")));

    let plans_dir = tmp.path().join(".boab/plans");
    let entries: Vec<_> = std::fs::read_dir(&plans_dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let plan_path = entries[0].as_ref().unwrap().path();
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(plan["milestone"].as_str(), Some("y2028"));
    let items = plan["items"].as_array().unwrap();
    for item in items {
        let tier = item["triage_tier"].as_u64().unwrap();
        assert!(
            tier <= 2,
            "2028 plan must only contain tier 1 or 2 items, got {}",
            tier
        );
    }
}

#[test]
fn plan_generate_2030_includes_lower_tiers() {
    let tmp = init_and_scan();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "plan",
            "generate",
            "--milestone",
            "2030",
        ])
        .assert()
        .success();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "plan", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2030"));
}

#[test]
fn plan_regenerate_preserves_user_edits() {
    let tmp = init_and_scan();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "plan",
            "generate",
            "--milestone",
            "2030",
        ])
        .assert()
        .success();

    let plans_dir = tmp.path().join(".boab/plans");
    let plan_path = std::fs::read_dir(&plans_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    let plan_id = plan["id"].as_str().unwrap().to_string();
    plan["items"][0]["assignee"] = serde_json::Value::String("payments-team".into());
    plan["items"][0]["notes"] = serde_json::Value::String("Owned by Sue".into());
    plan["items"][0]["target_action"] = serde_json::Value::String("Custom action".into());
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).unwrap();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "plan",
            "regenerate",
            &plan_id,
        ])
        .assert()
        .success();
    let updated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    let first = &updated["items"][0];
    assert_eq!(first["assignee"].as_str(), Some("payments-team"));
    assert_eq!(first["notes"].as_str(), Some("Owned by Sue"));
    assert_eq!(first["target_action"].as_str(), Some("Custom action"));
}

#[test]
fn vendor_list_shows_bundled_entries() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "vendor",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Microsoft"));
}

#[test]
fn vendor_override_takes_precedence() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["--workspace", tmp.path().to_str().unwrap(), "init"])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "vendor",
            "add",
            "--vendor",
            "Microsoft",
            "--product",
            "Azure",
            "--pqc-status",
            "resistant",
            "--target-date",
            "2026-Q4",
        ])
        .assert()
        .success();

    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "vendor",
            "search",
            "Azure",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("resistant"))
        .stdout(predicate::str::contains("2026-Q4"));
}
