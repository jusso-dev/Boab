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
fn html_report_is_self_contained_and_escaped() {
    let tmp = init_scan_plan();
    let ws = tmp.path().to_str().unwrap();
    bin()
        .args([
            "--workspace",
            ws,
            "system",
            "add",
            "--name",
            "<script>alert('x')</script> & Co",
            "--classification",
            "official_sensitive",
            "--criticality",
            "essential",
        ])
        .assert()
        .success();
    bin()
        .args(["--workspace", ws, "report", "--format", "html"])
        .assert()
        .success()
        .stdout(predicate::str::contains("readiness.html"));
    let html = std::fs::read_to_string(tmp.path().join(".boab/reports/readiness.html")).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>\n"));
    assert!(html.ends_with("</html>\n"));
    for section in [
        "Executive summary",
        "ASD transition milestones",
        "Highest-priority assets",
        "Systems in scope",
        "Transition plans on file",
        "Vendor PQC dependencies",
        "Methodology",
    ] {
        assert!(html.contains(section), "missing section {section}");
    }
    // No scripts, stylesheets, or fonts fetched from anywhere: the file must
    // render offline and pass strict email and document gateways.
    assert!(!html.contains("<script"));
    assert!(!html.contains("<link"));
    assert!(!html.contains("@import"));
    assert!(!html.contains("url("));
    assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; Co"));
    assert!(html.contains("OFFICIAL: Sensitive"));
}

#[test]
fn report_data_copies_match() {
    // The PowerShell module ships its own copy of the theme; both writers must
    // embed identical CSS for the reports to match byte for byte.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (a, b) in [
        (
            "data/report-theme.css",
            "powershell/Boab/Data/report-theme.css",
        ),
        (
            "data/vendor-pqc-registry.json",
            "powershell/Boab/Data/vendor-pqc-registry.json",
        ),
    ] {
        assert_eq!(
            std::fs::read(root.join(a)).unwrap(),
            std::fs::read(root.join(b)).unwrap(),
            "{a} and {b} differ"
        );
    }
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
        .stderr(predicate::str::contains("unknown report format"));
}
