use assert_cmd::Command;
use predicates::prelude::*;
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

fn init_scan_plan() -> TempDir {
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
            fixture_codebase().to_str().unwrap(),
        ])
        .assert()
        .success();
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
    tmp
}

#[test]
fn json_report_round_trips() {
    let tmp = init_scan_plan();
    let out = tmp.path().join("report.json");
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "report",
            "--format",
            "json",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["metadata"]["tool"], "boab");
    assert!(v["inventory"].as_array().unwrap().len() > 5);
    assert!(v["vendor_registry"]["entries"].as_array().unwrap().len() >= 20);
}

#[test]
fn cbom_report_validates_against_subset_schema() {
    let tmp = init_scan_plan();
    let out = tmp.path().join("bom.cdx.json");
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "report",
            "--format",
            "cbom",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bom_bytes = std::fs::read(&out).unwrap();
    let bom_value: serde_json::Value = serde_json::from_slice(&bom_bytes).unwrap();
    assert_eq!(bom_value["bomFormat"], "CycloneDX");
    assert_eq!(bom_value["specVersion"], "1.6");

    let schema_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cyclonedx-1.6.schema.json");
    let schema_raw = std::fs::read_to_string(&schema_path).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_raw).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).expect("compile schema");
    let result = validator.validate(&bom_value);
    if let Err(errors) = result {
        let msgs: Vec<String> = errors.map(|e| format!("{}", e)).collect();
        panic!("CBOM failed schema validation: {:?}", msgs);
    }
}

#[test]
fn md_report_contains_executive_summary() {
    let tmp = init_scan_plan();
    let out = tmp.path().join("readiness.md");
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "report",
            "--format",
            "md",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let md = std::fs::read_to_string(&out).unwrap();
    assert!(md.contains("# Boab PQC Readiness Report"));
    assert!(md.contains("Executive summary"));
    assert!(md.contains("ASD LATICE phase status"));
    assert!(md.contains("Methodology"));
}

#[test]
fn report_invalid_format_errors() {
    let tmp = init_scan_plan();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "report",
            "--format",
            "pdf",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown report format: pdf"));
}

#[test]
fn html_report_is_self_contained() {
    let tmp = init_scan_plan();
    let ws = tmp.path().to_str().unwrap();
    bin()
        .args([
            "--workspace",
            ws,
            "system",
            "add",
            "--name",
            "<script>alert(1)</script> & co",
            "--classification",
            "protected",
            "--criticality",
            "mission_critical",
            "--soci",
        ])
        .assert()
        .success();
    bin()
        .args([
            "--workspace",
            ws,
            "vendor",
            "add",
            "--vendor",
            "Evil",
            "--product",
            "Link",
            "--pqc-status",
            "unknown",
            "--source-url",
            "javascript:alert(1)",
        ])
        .assert()
        .success();
    bin()
        .args(["--workspace", ws, "report", "--format", "html"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote html report to"));
    let out = tmp.path().join(".boab/reports/readiness.html");
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>\n"));
    assert!(html.ends_with("</html>\n"));
    for section in [
        "Overall posture",
        "Recommended actions",
        "Quantum exposure",
        "Migration priority",
        "ASD transition milestones",
        "Highest-priority assets",
        "Exposure by business system",
        "Transition plans",
        "Vendor PQC dependencies",
        "Full cryptographic inventory",
        "Methodology",
    ] {
        assert!(html.contains(section), "missing section {section}");
    }
    // Self-contained: no external stylesheets, scripts, images or fonts.
    assert!(html.contains("default-src 'none'"));
    for needle in ["<link", "src=\"http", "url(", "@import"] {
        assert!(!html.contains(needle), "unexpected {needle}");
    }
    // User data is escaped and only http(s) URLs become links.
    assert!(html.contains(
        "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co <span class=\"tag\">SOCI</span>"
    ));
    assert!(!html.contains("<script>alert(1)"));
    assert!(!html.contains("href=\"javascript:"));
    // Only the CSP-hashed print helper runs.
    assert_eq!(html.matches("<script>").count(), 1);
    // The highest system classification marks the top and bottom of the
    // page on screen and every printed page's header and footer.
    assert_eq!(
        html.matches("<div class=\"marking\">PROTECTED</div>")
            .count(),
        2
    );
    assert!(html.contains("@top-center{content:\"PROTECTED\"}"));
    assert!(html.contains("@bottom-center{content:\"PROTECTED\"}"));
    assert!(html.contains("counter(pages)"));
}

#[test]
fn html_report_renders_an_empty_workspace() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().to_str().unwrap();
    bin().args(["--workspace", ws, "init"]).assert().success();
    let out = tmp.path().join("empty.html");
    bin()
        .args([
            "--workspace",
            ws,
            "report",
            "--format",
            "HTML",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.contains("Not yet assessed"));
    assert!(html.contains("No assets inventoried yet."));
    assert!(html.contains("No transition plans generated yet."));
    // No systems, so no protective marking is claimed.
    assert!(!html.contains("<div class=\"marking\">"));
    assert!(!html.contains("@top-center{content:"));
}
