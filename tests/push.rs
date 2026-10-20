//! `boab push` against an in-process mock HTTP server.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const TOKEN: &str = "tok-secret-0d6f1c2a9b";
const CBOM: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}"#;

enum Reply {
    Status(
        u16,
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static str,
    ),
    /// Read the request, then never answer.
    Hang,
}

#[derive(Clone, Debug)]
struct Captured {
    head: String,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }
}

struct Mock {
    url: String,
    requests: Arc<Mutex<Vec<Captured>>>,
}

impl Mock {
    fn start(replies: Vec<Reply>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ingest/cbom", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        thread::spawn(move || {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                seen.lock().unwrap().push(read_request(&mut stream));
                match reply {
                    Reply::Status(code, reason, headers, body) => {
                        let mut response = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            code,
                            reason,
                            body.len()
                        );
                        for (k, v) in headers {
                            response.push_str(&format!("{}: {}\r\n", k, v));
                        }
                        response.push_str("\r\n");
                        response.push_str(body);
                        let _ = stream.write_all(response.as_bytes());
                    }
                    // Hold the connection open on its own thread so retries are still accepted.
                    Reply::Hang => {
                        thread::spawn(move || {
                            thread::sleep(Duration::from_secs(3));
                            drop(stream);
                        });
                    }
                }
            }
        });
        Mock { url, requests }
    }

    fn requests(&self) -> Vec<Captured> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break raw.len();
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = raw[head_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Captured { head, body }
}

fn bin() -> Command {
    let mut cmd = Command::cargo_bin("boab").expect("boab binary");
    for var in [
        "BOAB_PUSH_URL",
        "BOAB_PUSH_TOKEN",
        "BOAB_PUSH_RUN_ID",
        "RUST_LOG",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn cbom_file(dir: &TempDir) -> String {
    let path = dir.path().join("bom.cdx.json");
    std::fs::write(&path, CBOM).unwrap();
    path.to_str().unwrap().to_string()
}

fn push(dir: &TempDir, mock: &Mock) -> Command {
    let mut cmd = bin();
    cmd.env("BOAB_PUSH_TOKEN", TOKEN).args([
        "push",
        "--file",
        &cbom_file(dir),
        "--url",
        &mock.url,
        "--insecure",
        "--retry-delay-ms",
        "10",
    ]);
    cmd
}

#[test]
fn posts_the_cbom_with_auth_and_content_type_on_2xx() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![Reply::Status(
        201,
        "Created",
        &[("X-Request-Id", "req-7f3a")],
        r#"{"requestId":"req-7f3a"}"#,
    )]);
    push(&tmp, &mock)
        .args(["--run-id", "pipeline-42", "--header", "X-Team=platform"])
        .assert()
        .success()
        .stdout(predicate::str::contains("HTTP 201 Created"))
        .stdout(predicate::str::contains("request id req-7f3a"));

    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert!(req.head.starts_with("POST /ingest/cbom HTTP/1.1\r\n"));
    assert_eq!(
        req.header("content-type").as_deref(),
        Some("application/vnd.cyclonedx+json; version=1.6")
    );
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {}", TOKEN))
    );
    assert_eq!(req.header("x-boab-run-id").as_deref(), Some("pipeline-42"));
    assert_eq!(req.header("x-team").as_deref(), Some("platform"));
    assert!(req.header("idempotency-key").is_some());
    assert_eq!(req.body, CBOM.as_bytes());
}

#[test]
fn reads_the_cbom_from_stdin() {
    let mock = Mock::start(vec![Reply::Status(202, "Accepted", &[], "")]);
    bin()
        .args(["push", "--file", "-", "--url", &mock.url, "--insecure"])
        .write_stdin(CBOM)
        .assert()
        .success()
        .stdout(predicate::str::contains("HTTP 202 Accepted"));
    assert_eq!(mock.requests()[0].body, CBOM.as_bytes());
}

#[test]
fn does_not_retry_4xx_and_shows_the_response_body() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![
        Reply::Status(
            400,
            "Bad Request",
            &[],
            r#"{"error":"specVersion must be 1.6"}"#,
        ),
        Reply::Status(201, "Created", &[], ""),
    ]);
    push(&tmp, &mock)
        .assert()
        .failure()
        .stderr(predicate::str::contains("rejected: HTTP 400 Bad Request"))
        .stderr(predicate::str::contains("specVersion must be 1.6"));
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn retries_5xx_with_the_same_idempotency_key() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![
        Reply::Status(503, "Service Unavailable", &[], ""),
        Reply::Status(201, "Created", &[("X-Request-Id", "req-2")], ""),
    ]);
    push(&tmp, &mock)
        .assert()
        .success()
        .stdout(predicate::str::contains("request id req-2"))
        .stdout(predicate::str::contains("after 2 attempts"));
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].header("idempotency-key"),
        requests[1].header("idempotency-key")
    );
}

#[test]
fn gives_up_after_the_retry_budget_on_5xx() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![
        Reply::Status(500, "Internal Server Error", &[], "boom"),
        Reply::Status(500, "Internal Server Error", &[], "boom"),
        Reply::Status(500, "Internal Server Error", &[], "boom"),
    ]);
    push(&tmp, &mock)
        .args(["--retries", "2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed after 3 attempt(s)"))
        .stderr(predicate::str::contains("HTTP 500"));
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn times_out_retries_and_fails() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![Reply::Hang, Reply::Hang]);
    push(&tmp, &mock)
        .args(["--push-timeout-seconds", "1", "--retries", "1"])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure()
        .stderr(predicate::str::contains("timed out"))
        .stderr(predicate::str::contains("after 2 attempt(s)"));
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn retries_network_errors_then_fails() {
    let tmp = TempDir::new().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    bin()
        .args([
            "push",
            "--file",
            &cbom_file(&tmp),
            "--url",
            &format!("http://127.0.0.1:{}/x", port),
            "--insecure",
            "--retries",
            "1",
            "--retry-delay-ms",
            "10",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("after 2 attempt(s)"));
}

#[test]
fn rejects_plain_http_without_insecure() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![Reply::Status(201, "Created", &[], "")]);
    bin()
        .args(["push", "--file", &cbom_file(&tmp), "--url", &mock.url])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--insecure"));
    thread::sleep(Duration::from_millis(100));
    assert!(mock.requests().is_empty());
}

#[test]
fn sends_nothing_without_a_url() {
    let tmp = TempDir::new().unwrap();
    bin()
        .args(["push", "--file", &cbom_file(&tmp)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no push URL configured"));
}

#[test]
fn rejects_payloads_that_are_not_cyclonedx() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("other.json");
    std::fs::write(&path, r#"{"spdxVersion":"SPDX-2.3"}"#).unwrap();
    let mock = Mock::start(vec![Reply::Status(201, "Created", &[], "")]);
    bin()
        .args([
            "push",
            "--file",
            path.to_str().unwrap(),
            "--url",
            &mock.url,
            "--insecure",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CycloneDX"));
    assert!(mock.requests().is_empty());
}

#[test]
fn never_prints_the_token_even_when_verbose_or_echoed() {
    let tmp = TempDir::new().unwrap();
    let mock = Mock::start(vec![
        Reply::Status(
            502,
            "Bad Gateway",
            &[],
            "upstream saw tok-secret-0d6f1c2a9b",
        ),
        Reply::Status(
            401,
            "Unauthorized",
            &[],
            "invalid key tok-secret-0d6f1c2a9b",
        ),
    ]);
    let output = push(&tmp, &mock)
        .env("RUST_LOG", "trace")
        .arg("--verbose")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP 401 Unauthorized"), "{}", stderr);
    assert!(stderr.contains("[REDACTED]"), "{}", stderr);
    assert!(
        !stdout.contains(TOKEN),
        "token leaked to stdout: {}",
        stdout
    );
    assert!(
        !stderr.contains(TOKEN),
        "token leaked to stderr: {}",
        stderr
    );

    // The token is still sent, only in the Authorization header.
    assert_eq!(
        mock.requests()[0].header("authorization"),
        Some(format!("Bearer {}", TOKEN))
    );

    // Help never shows the environment value.
    let help = bin()
        .env("BOAB_PUSH_TOKEN", TOKEN)
        .args(["push", "--help"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains(TOKEN));
}

#[test]
fn report_push_uploads_the_cbom_it_wrote() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().to_str().unwrap();
    bin().args(["--workspace", ws, "init"]).assert().success();

    // A URL in the environment alone sends nothing: --push is required.
    let idle = Mock::start(vec![Reply::Status(201, "Created", &[], "")]);
    bin()
        .env("BOAB_PUSH_URL", &idle.url)
        .args(["--workspace", ws, "report", "--format", "cbom"])
        .assert()
        .success();
    thread::sleep(Duration::from_millis(100));
    assert!(idle.requests().is_empty());

    let mock = Mock::start(vec![Reply::Status(201, "Created", &[], "")]);
    bin()
        .args([
            "--workspace",
            ws,
            "report",
            "--format",
            "cbom",
            "--push",
            "--url",
            &mock.url,
            "--insecure",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote cbom report"))
        .stdout(predicate::str::contains("pushed CBOM: HTTP 201"));
    let written = std::fs::read(tmp.path().join(".boab/reports/bom.cdx.json")).unwrap();
    assert_eq!(mock.requests()[0].body, written);

    bin()
        .args([
            "--workspace",
            ws,
            "report",
            "--format",
            "md",
            "--push",
            "--url",
            &mock.url,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--push requires --format cbom"));
}
