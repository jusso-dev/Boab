//! Host crypto discovery: SSH host keys, sshd_config, crypto policy, OpenSSL
//! config, keystore entries and KMS listings. Checks the inventory, dedup,
//! scoring, the CBOM import contract and that no secret material is emitted.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("boab").expect("boab binary")
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn boab(ws: &Path, args: &[&str]) {
    let mut argv = vec!["--workspace", ws.to_str().unwrap()];
    argv.extend_from_slice(args);
    bin().args(argv).assert().success();
}

fn init() -> TempDir {
    let tmp = TempDir::new().unwrap();
    boab(tmp.path(), &["init"]);
    tmp
}

fn inventory(ws: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(ws.join(".boab/inventory.json")).unwrap();
    serde_json::from_str::<Value>(&raw)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn of_kind<'a>(inv: &'a [Value], kind: &str) -> Vec<&'a Value> {
    inv.iter()
        .filter(|a| a["parameter_set"]["kind"] == kind)
        .collect()
}

/// Every file Boab wrote into the workspace, concatenated.
fn workspace_text(ws: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![ws.join(".boab")];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push_str(&String::from_utf8_lossy(&fs::read(&p).unwrap()));
            }
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap().flatten() {
        let dest = to.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn report(ws: &Path, format: &str) -> Value {
    let out = ws.join(format!("out.{}", format));
    boab(
        ws,
        &["report", "--format", format, "-o", out.to_str().unwrap()],
    );
    serde_json::from_slice(&fs::read(out).unwrap()).unwrap()
}

fn prop<'a>(component: &'a Value, name: &str) -> Option<&'a str> {
    component["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p["value"].as_str())
}

#[test]
fn host_scan_records_ssh_keys_config_and_policy() {
    let tmp = init();
    let root = fixture("host/rhel9");
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "host",
            root.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("host scan"));
    let inv = inventory(tmp.path());

    let keys = of_kind(&inv, "ssh_host_key");
    assert_eq!(
        keys.len(),
        4,
        "rsa, ecdsa, ed25519 public keys and dsa by name"
    );
    let rsa = keys
        .iter()
        .find(|a| a["algorithm_name"] == "RSA")
        .expect("RSA host key");
    assert_eq!(rsa["asset_type"], "key");
    assert_eq!(rsa["parameter_set"]["key_size_bits"], 3072);
    assert_eq!(rsa["parameter_set"]["host"], "web01.example.internal");
    assert_eq!(
        rsa["parameter_set"]["location"],
        "/etc/ssh/ssh_host_rsa_key.pub"
    );
    assert_eq!(rsa["pqc_status"], "vulnerable");
    assert_eq!(rsa["quantum_vulnerable"], true);
    assert!(rsa["parameter_set"]["fingerprint_sha256"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    let dsa = keys
        .iter()
        .find(|a| a["algorithm_name"] == "DSA")
        .expect("DSA key recognised by file name");
    assert_eq!(dsa["parameter_set"]["public_key_available"], false);

    let algs = of_kind(&inv, "ssh_config_algorithm");
    let names: Vec<&str> = algs
        .iter()
        .map(|a| a["parameter_set"]["ssh_name"].as_str().unwrap())
        .collect();
    // sshd_config Ciphers win over the policy back-end; Match blocks are ignored.
    assert!(names.contains(&"3des-cbc"));
    assert!(!names.contains(&"aes128-cbc"));
    assert!(!names.contains(&"aes256-ctr"));
    // KexAlgorithms come from the Include, HostKeyAlgorithms from the back-end.
    let hybrid = algs
        .iter()
        .find(|a| a["parameter_set"]["ssh_name"] == "mlkem768x25519-sha256")
        .unwrap();
    assert_eq!(hybrid["pqc_status"], "hybrid");
    assert_eq!(
        hybrid["parameter_set"]["location"],
        "/etc/ssh/sshd_config.d/40-pqc.conf"
    );
    assert!(algs.iter().any(|a| {
        a["parameter_set"]["directive"] == "HostKeyAlgorithms"
            && a["parameter_set"]["location"]
                == "/etc/crypto-policies/back-ends/opensshserver.config"
    }));

    let policy = of_kind(&inv, "os_crypto_policy");
    assert_eq!(policy.len(), 1);
    let p = &policy[0]["parameter_set"];
    assert_eq!(p["policy"], "DEFAULT:SHA1");
    assert_eq!(p["subpolicies"], serde_json::json!(["SHA1"]));
    assert_eq!(p["min_protocol"], "TLSv1.2");
    assert_eq!(
        p["allowed_protocols"],
        serde_json::json!(["TLSv1.2", "TLSv1.3"])
    );

    let openssl = of_kind(&inv, "openssl_config");
    assert_eq!(openssl.len(), 1);
    let o = &openssl[0]["parameter_set"];
    assert_eq!(o["location"], "/etc/pki/tls/openssl.cnf");
    assert_eq!(o["min_protocol"], "TLSv1.2");
    assert!(o["cipher_string"].as_str().unwrap().contains("SECLEVEL=1"));
    assert_eq!(
        o["config_files"],
        serde_json::json!([
            "/etc/pki/tls/openssl.cnf",
            "/etc/crypto-policies/back-ends/opensslcnf.config"
        ])
    );
}

#[test]
fn host_scan_never_opens_private_host_keys() {
    let tmp = init();
    let root = tmp.path().join("root");
    copy_tree(&fixture("host/rhel9"), &root);
    let marker = "PRIVATE-KEY-MARKER-7f3a";
    for t in ["rsa", "ecdsa", "ed25519", "dsa"] {
        let p = root.join(format!("etc/ssh/ssh_host_{}_key", t));
        fs::write(&p, marker).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    boab(tmp.path(), &["scan", "host", root.to_str().unwrap()]);
    let text = workspace_text(tmp.path());
    assert!(!text.contains(marker), "private key file content leaked");
    let inv = inventory(tmp.path());
    let keys = of_kind(&inv, "ssh_host_key");
    assert_eq!(keys.len(), 4);
    assert!(keys
        .iter()
        .all(|k| k["parameter_set"]["private_key_present"] == true));
}

#[test]
fn host_rescan_is_idempotent_and_host_label_overrides() {
    let tmp = init();
    let root = fixture("host/rhel9");
    let r = root.to_str().unwrap();
    boab(tmp.path(), &["scan", "host", r]);
    let first = inventory(tmp.path()).len();
    boab(tmp.path(), &["scan", "host", r]);
    assert_eq!(
        inventory(tmp.path()).len(),
        first,
        "rescan duplicated assets"
    );
    boab(tmp.path(), &["scan", "host", r, "--host", "web02"]);
    let inv = inventory(tmp.path());
    assert_eq!(inv.len(), first * 2, "a second host gets its own assets");
    assert!(inv.iter().any(|a| a["parameter_set"]["host"] == "web02"));
}

#[test]
fn keystore_entries_become_key_assets_without_secrets() {
    let tmp = init();
    let dir = fixture("keystores");
    let pw = dir.join("password.txt");
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            dir.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
            "--host",
            "app01.example.internal",
        ],
    );
    let inv = inventory(tmp.path());
    let entries = of_kind(&inv, "keystore_entry");
    assert_eq!(entries.len(), 4, "three JKS aliases and one PKCS#12 entry");
    let tomcat = entries
        .iter()
        .find(|a| a["parameter_set"]["alias"] == "tomcat")
        .unwrap();
    assert_eq!(tomcat["asset_type"], "key");
    assert_eq!(tomcat["algorithm_name"], "RSA");
    assert_eq!(tomcat["parameter_set"]["key_size_bits"], 2048);
    assert_eq!(tomcat["parameter_set"]["store_type"], "JKS");
    assert_eq!(tomcat["parameter_set"]["entry_type"], "private_key");
    assert_eq!(tomcat["parameter_set"]["host"], "app01.example.internal");
    assert_eq!(tomcat["parameter_set"]["integrity_verified"], true);
    assert!(tomcat["parameter_set"]["location"]
        .as_str()
        .unwrap()
        .ends_with("app.jks"));
    let ec = entries
        .iter()
        .find(|a| a["parameter_set"]["alias"] == "partner-ca")
        .unwrap();
    assert_eq!(ec["algorithm_name"], "ECDSA-P256");
    let p12 = entries
        .iter()
        .find(|a| a["parameter_set"]["store_type"] == "PKCS12")
        .unwrap();
    assert_eq!(p12["parameter_set"]["key_size_bits"], 4096);

    let text = workspace_text(tmp.path());
    assert!(!text.contains("changeit"), "keystore password leaked");
    assert!(
        !text.contains("BOAB-TEST-FILLER"),
        "protected key blob leaked"
    );

    // Rescan does not duplicate entries.
    let before = inv.len();
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            dir.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
            "--host",
            "app01.example.internal",
        ],
    );
    assert_eq!(inventory(tmp.path()).len(), before);
}

#[test]
fn jks_with_wrong_password_is_listed_unverified() {
    let tmp = init();
    let dir = tmp.path().join("ks");
    fs::create_dir_all(&dir).unwrap();
    fs::copy(fixture("keystores/app.jks"), dir.join("app.jks")).unwrap();
    let pw = tmp.path().join("pw");
    fs::write(&pw, "wrong\n").unwrap();
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            dir.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    let inv = inventory(tmp.path());
    let entries = of_kind(&inv, "keystore_entry");
    assert_eq!(entries.len(), 3);
    assert!(entries
        .iter()
        .all(|e| e["parameter_set"]["integrity_verified"] == false));
}

#[test]
fn kms_listings_record_metadata_only() {
    let tmp = init();
    let files: Vec<String> = [
        "aws-list-keys.json",
        "aws-describe-key.json",
        "azure-key-list.json",
        "azure-key-show.json",
        "gcp-keys-list.json",
    ]
    .iter()
    .map(|f| fixture(&format!("kms/{}", f)).display().to_string())
    .collect();
    let mut args = vec!["scan", "kms"];
    args.extend(files.iter().map(String::as_str));
    boab(tmp.path(), &args);
    let inv = inventory(tmp.path());
    let keys = of_kind(&inv, "kms_key");
    assert_eq!(keys.len(), 8, "list and describe/show merge per key");

    let aws_rsa = keys
        .iter()
        .find(|k| k["parameter_set"]["key_id"] == "1234abcd-12ab-34cd-56ef-1234567890ab")
        .unwrap();
    let p = &aws_rsa["parameter_set"];
    assert_eq!(aws_rsa["asset_type"], "key");
    assert_eq!(aws_rsa["algorithm_name"], "RSA");
    assert_eq!(p["provider"], "aws");
    assert_eq!(
        p["key_ref"],
        "arn:aws:kms:ap-southeast-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    );
    assert_eq!(p["key_spec"], "RSA_2048");
    assert_eq!(p["key_usage"], "SIGN_VERIFY");
    assert_eq!(p["key_state"], "Enabled");
    assert_eq!(p["key_size_bits"], 2048);
    assert_eq!(p["host"], "aws:111122223333:ap-southeast-2");
    assert_eq!(
        p["listing_sources"],
        serde_json::json!(["list-keys", "describe-key"])
    );
    assert_eq!(aws_rsa["quantum_vulnerable"], true);

    let azure = keys
        .iter()
        .find(|k| k["parameter_set"]["provider"] == "azure" && k["algorithm_name"] == "RSA")
        .unwrap();
    assert_eq!(azure["parameter_set"]["key_size_bits"], 3072);
    assert_eq!(azure["parameter_set"]["protection_level"], "HSM");
    assert_eq!(
        azure["parameter_set"]["key_ref"],
        "https://example-vault.vault.azure.net/keys/payments-signing"
    );

    // Template-only GCP key: the template is recorded but does not classify
    // existing versions.
    let pq = keys
        .iter()
        .find(|k| k["parameter_set"]["template_algorithm"] == "PQ_SIGN_ML_DSA_65")
        .unwrap();
    assert_eq!(pq["algorithm_name"], "unknown");
    assert_eq!(pq["pqc_status"], "unknown");
    let sym = keys
        .iter()
        .find(|k| k["parameter_set"]["key_spec"] == "GOOGLE_SYMMETRIC_ENCRYPTION")
        .unwrap();
    assert_eq!(sym["pqc_status"], "symmetric_ok");

    // Metadata only: no public key components, descriptions or tags.
    let text = workspace_text(tmp.path());
    assert!(!text.contains("AQAB"), "Azure public exponent copied");
    assert!(!text.contains("\"n\":"), "Azure modulus copied");
    assert!(
        !text.contains("Example data only"),
        "key description copied"
    );
}

#[test]
fn kms_rejects_unknown_provider_and_unrecognised_files() {
    let tmp = init();
    let f = fixture("kms/aws-list-keys.json");
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "kms",
            f.to_str().unwrap(),
            "--provider",
            "oracle",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown provider"));
    let junk = tmp.path().join("junk.json");
    fs::write(&junk, "{\"hello\": 1}").unwrap();
    bin()
        .args([
            "--workspace",
            tmp.path().to_str().unwrap(),
            "scan",
            "kms",
            junk.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--provider"));
}

/// The GRiCk import contract (docs/cbom.md): every host crypto component has
/// boab:asset_type, boab:kind, boab:host and boab:location properties and an
/// evidence occurrence, and the CBOM still validates.
#[test]
fn cbom_carries_host_and_location_for_every_new_asset() {
    let tmp = init();
    let ws = tmp.path();
    boab(
        ws,
        &["scan", "host", fixture("host/rhel9").to_str().unwrap()],
    );
    let ks = fixture("keystores");
    boab(
        ws,
        &[
            "scan",
            "certs",
            ks.to_str().unwrap(),
            "--password-file",
            ks.join("password.txt").to_str().unwrap(),
            "--host",
            "app01",
        ],
    );
    boab(
        ws,
        &[
            "scan",
            "kms",
            fixture("kms/aws-describe-key.json").to_str().unwrap(),
        ],
    );
    let bom = report(ws, "cbom");

    let schema: Value =
        serde_json::from_str(&fs::read_to_string(fixture("cyclonedx-1.6.schema.json")).unwrap())
            .unwrap();
    let compiled = jsonschema::JSONSchema::compile(&schema).unwrap();
    if let Err(errors) = compiled.validate(&bom) {
        let msgs: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("CBOM failed schema: {:?}", msgs);
    }

    let mut kinds = std::collections::BTreeSet::new();
    for c in bom["components"].as_array().unwrap() {
        let Some(kind) = prop(c, "boab:kind") else {
            continue;
        };
        kinds.insert(kind.to_string());
        for name in [
            "boab:asset_type",
            "boab:host",
            "boab:location",
            "boab:algorithm",
            "boab:pqc_status",
            "boab:quantum_vulnerable",
            "boab:asset_key",
        ] {
            assert!(
                prop(c, name).is_some_and(|v| !v.is_empty()),
                "{} missing {}",
                c["name"],
                name
            );
        }
        assert_eq!(
            c["evidence"]["occurrences"][0]["location"].as_str(),
            prop(c, "boab:location")
        );
        assert!(c.get("description").is_none_or(|d| d.is_string()));
        if prop(c, "boab:asset_type") == Some("key") {
            let m = &c["cryptoProperties"]["relatedCryptoMaterialProperties"];
            assert!(m["type"].is_string());
        }
    }
    let expected: std::collections::BTreeSet<String> = [
        "keystore_entry",
        "kms_key",
        "openssl_config",
        "os_crypto_policy",
        "ssh_config_algorithm",
        "ssh_host_key",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(kinds, expected);

    let rsa = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            prop(c, "boab:kind") == Some("ssh_host_key") && prop(c, "boab:algorithm") == Some("RSA")
        })
        .unwrap();
    let m = &rsa["cryptoProperties"]["relatedCryptoMaterialProperties"];
    assert_eq!(m["type"], "public-key");
    assert_eq!(m["size"], 3072);
    assert_eq!(prop(rsa, "boab:quantum_vulnerable"), Some("true"));
    assert_eq!(prop(rsa, "boab:host"), Some("web01.example.internal"));
}

#[test]
fn json_report_scores_new_assets_and_plans_pick_them_up() {
    let tmp = init();
    let ws = tmp.path();
    boab(
        ws,
        &["scan", "host", fixture("host/rhel9").to_str().unwrap()],
    );
    boab(ws, &["plan", "generate", "--milestone", "2030"]);
    let r = report(ws, "json");
    let inv = r["inventory"].as_array().unwrap();
    let rsa = inv
        .iter()
        .find(|a| a["parameter_set"]["kind"] == "ssh_host_key" && a["algorithm_name"] == "RSA")
        .unwrap();
    assert_eq!(rsa["risk_score"]["algorithm_vulnerability"], 8);
    let dsa = inv
        .iter()
        .find(|a| a["parameter_set"]["kind"] == "ssh_host_key" && a["algorithm_name"] == "DSA")
        .unwrap();
    assert_eq!(rsa["asset_type"], "key");
    assert_eq!(dsa["risk_score"]["algorithm_vulnerability"], 10);

    let plan = &r["plans"][0];
    assert_eq!(plan["milestone"], "y2030");
    let ids: Vec<&str> = plan["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["crypto_asset_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&rsa["id"].as_str().unwrap()));
    assert!(r["scans"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["scan_type"] == "host_crypto"));
}

#[cfg(unix)]
fn scan_record(ws: &Path) -> Value {
    let dir = ws.join(".boab/scans");
    let f = fs::read_dir(dir).unwrap().flatten().next().unwrap().path();
    serde_json::from_slice(&fs::read(f).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn host_scan_resolves_symlinks_inside_the_root() {
    use std::os::unix::fs::symlink;
    let tmp = init();
    let root = tmp.path().join("image");
    fs::create_dir_all(root.join("etc/ssl")).unwrap();
    fs::create_dir_all(root.join("etc/pki/tls")).unwrap();
    // Absolute link, as on a real Debian or RHEL image. It must resolve to
    // <root>/etc/pki/tls/openssl.cnf, never to the scanning machine's file.
    fs::write(
        root.join("etc/pki/tls/openssl.cnf"),
        "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = sys\n[sys]\nMinProtocol = TLSv1.3\nMarkerInRoot = yes\n",
    )
    .unwrap();
    symlink("/etc/pki/tls/openssl.cnf", root.join("etc/ssl/openssl.cnf")).unwrap();
    // A link that tries to climb out of the root stays inside it.
    fs::create_dir_all(root.join("etc/ssh")).unwrap();
    symlink(
        "../../../../../../../../etc/ssh/sshd_config",
        root.join("etc/ssh/sshd_config"),
    )
    .unwrap();
    boab(
        tmp.path(),
        &["scan", "host", root.to_str().unwrap(), "--host", "img"],
    );
    let inv = inventory(tmp.path());
    let openssl = of_kind(&inv, "openssl_config");
    assert_eq!(openssl.len(), 1, "one file behind two names");
    assert_eq!(openssl[0]["parameter_set"]["min_protocol"], "TLSv1.3");
    assert_eq!(openssl[0]["parameter_set"]["ssl_section"], "sys");
    // The climbing link resolved to <root>/etc/ssh/sshd_config, which is the
    // link itself: nothing from the scanning machine was read.
    assert!(of_kind(&inv, "ssh_config_algorithm").is_empty());
}

#[cfg(unix)]
#[test]
fn host_scan_reports_unreadable_paths() {
    use std::os::unix::fs::PermissionsExt;
    if std::env::var("USER").as_deref() == Ok("root") {
        return; // root ignores permissions
    }
    let tmp = init();
    let root = tmp.path().join("root");
    copy_tree(&fixture("host/rhel9"), &root);
    let cfg = root.join("etc/ssh/sshd_config");
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o000)).unwrap();
    boab(tmp.path(), &["scan", "host", root.to_str().unwrap()]);
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
    let scan = scan_record(tmp.path());
    assert_eq!(scan["scan_type"], "host_crypto");
    let errors = scan["config"]["collection_errors"].as_array().unwrap();
    assert!(errors
        .iter()
        .any(|e| e.as_str().unwrap().starts_with("/etc/ssh/sshd_config:")));
    assert!(scan["error_message"]
        .as_str()
        .unwrap()
        .contains("may be incomplete"));
}

#[test]
fn malformed_public_key_keeps_the_name_based_record() {
    let tmp = init();
    let root = tmp.path().join("root");
    copy_tree(&fixture("host/rhel9"), &root);
    fs::write(root.join("etc/ssh/ssh_host_rsa_key.pub"), "not a key\n").unwrap();
    boab(tmp.path(), &["scan", "host", root.to_str().unwrap()]);
    let inv = inventory(tmp.path());
    let rsa: Vec<_> = of_kind(&inv, "ssh_host_key")
        .into_iter()
        .filter(|a| a["algorithm_name"] == "RSA")
        .collect();
    assert_eq!(rsa.len(), 1, "RSA host key still inventoried");
    assert_eq!(rsa[0]["parameter_set"]["public_key_available"], false);
    assert_eq!(
        rsa[0]["parameter_set"]["location"],
        "/etc/ssh/ssh_host_rsa_key"
    );
}

#[test]
fn rescan_refreshes_scanner_fields_and_keeps_user_fields() {
    let tmp = init();
    let root = tmp.path().join("root");
    copy_tree(&fixture("host/rhel9"), &root);
    boab(tmp.path(), &["scan", "host", root.to_str().unwrap()]);
    // User annotates the TLS policy asset.
    let inv_path = tmp.path().join(".boab/inventory.json");
    let mut inv: Vec<Value> = serde_json::from_slice(&fs::read(&inv_path).unwrap()).unwrap();
    let idx = inv
        .iter()
        .position(|a| a["parameter_set"]["kind"] == "openssl_config")
        .unwrap();
    let id = inv[idx]["id"].clone();
    inv[idx]["notes"] = Value::from("owned by platform team");
    inv[idx]["migration_status"] = Value::from("in_progress");
    fs::write(&inv_path, serde_json::to_vec_pretty(&inv).unwrap()).unwrap();

    // The host enables a hybrid group; same identity, new content.
    let backend = root.join("etc/crypto-policies/back-ends/opensslcnf.config");
    let text = fs::read_to_string(&backend)
        .unwrap()
        .replace("Groups = X25519:", "Groups = X25519MLKEM768:X25519:");
    fs::write(&backend, text).unwrap();
    boab(tmp.path(), &["scan", "host", root.to_str().unwrap()]);

    let inv = inventory(tmp.path());
    let a: Vec<_> = of_kind(&inv, "openssl_config");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0]["id"], id, "asset id kept");
    assert_eq!(a[0]["pqc_status"], "hybrid", "scanner fields refreshed");
    assert_eq!(a[0]["notes"], "owned by platform team");
    assert_eq!(a[0]["migration_status"], "in_progress");
    assert_eq!(a[0]["primitive"], Value::Null);
}

#[test]
fn jceks_secret_keys_do_not_hide_later_entries() {
    let tmp = init();
    let dir = fixture("jceks");
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            dir.to_str().unwrap(),
            "--password-file",
            dir.join("password.txt").to_str().unwrap(),
        ],
    );
    let inv = inventory(tmp.path());
    let entries = of_kind(&inv, "keystore_entry");
    let mut aliases: Vec<&str> = entries
        .iter()
        .map(|e| e["parameter_set"]["alias"].as_str().unwrap())
        .collect();
    aliases.sort();
    assert_eq!(aliases, vec!["aes-data", "hmac-sig", "zz-partner"]);
    for e in &entries {
        if e["parameter_set"]["entry_type"] == "secret_key" {
            assert_eq!(e["algorithm_name"], "unknown");
            assert_eq!(e["primitive"], Value::Null, "no guessed primitive");
            assert_eq!(
                e["parameter_set"]["seal_algorithm"],
                "PBEWithMD5AndTripleDES"
            );
        }
        assert_eq!(e["parameter_set"]["integrity_verified"], true);
    }
}

#[test]
fn pkcs12_without_a_mac_is_not_reported_as_verified() {
    let tmp = init();
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            fixture("pkcs12-nomac").to_str().unwrap(),
            "--password-file",
            fixture("keystores/password.txt").to_str().unwrap(),
        ],
    );
    let inv = inventory(tmp.path());
    let e = of_kind(&inv, "keystore_entry");
    assert_eq!(e.len(), 1);
    assert_eq!(e[0]["parameter_set"]["integrity_verified"], Value::Null);
}

#[test]
fn p521_keystore_entry_has_its_curve_size() {
    let tmp = init();
    let ks = fixture("keystores");
    boab(
        tmp.path(),
        &[
            "scan",
            "certs",
            ks.to_str().unwrap(),
            "--password-file",
            ks.join("password.txt").to_str().unwrap(),
        ],
    );
    let inv = inventory(tmp.path());
    let p521 = of_kind(&inv, "keystore_entry")
        .into_iter()
        .find(|e| e["parameter_set"]["alias"] == "p521-ca")
        .unwrap();
    assert_eq!(p521["algorithm_name"], "ECDSA-P521");
    assert_eq!(p521["parameter_set"]["key_size_bits"], 521);
}

#[test]
fn html_scope_line_names_host_and_kms_scans() {
    let tmp = init();
    let ws = tmp.path();
    boab(
        ws,
        &["scan", "host", fixture("host/rhel9").to_str().unwrap()],
    );
    boab(
        ws,
        &[
            "scan",
            "kms",
            fixture("kms/aws-describe-key.json").to_str().unwrap(),
        ],
    );
    let out = ws.join("r.html");
    boab(
        ws,
        &["report", "--format", "html", "-o", out.to_str().unwrap()],
    );
    let html = fs::read_to_string(out).unwrap();
    assert!(html.contains(
        "0 certificate store scans &middot; 1 host crypto scan &middot; 1 KMS listing import"
    ));
}
