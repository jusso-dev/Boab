//! `boab push`: send a CycloneDX CBOM to an HTTPS endpoint the user configures.
//!
//! Boab is air-gapped by default. Nothing in this module runs unless a push URL
//! is given with `--url` or `BOAB_PUSH_URL`. The request is a single
//! authenticated `POST` with the CBOM as the body; there is no telemetry and no
//! other destination.
//!
//! The HTTP client is deliberately minimal and in-tree (HTTP/1.1 over `tokio`
//! and `rustls`), matching the TLS scanner, so pushing adds no HTTP crate.
//!
//! The token is only ever written into the `Authorization` header. It is never
//! logged, never part of an error message, and redacted from any response body
//! that Boab prints.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

/// CycloneDX JSON media type. The spec version is appended as a parameter.
pub const CYCLONEDX_MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";
/// Response bodies are read up to this size; anything larger is truncated.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Response bodies are shown in error messages up to this many characters.
const MAX_BODY_IN_MESSAGE: usize = 2048;
/// Headers Boab sets itself; `--header` may not override them.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "authorization",
];

/// Everything needed to push one payload.
#[derive(Clone)]
pub struct PushRequest {
    pub url: String,
    pub token: Option<String>,
    pub headers: Vec<(String, String)>,
    pub run_id: Option<String>,
    pub insecure: bool,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub retries: u32,
    pub retry_delay: Duration,
}

// Hand-written so the token can never reach a log line through `{:?}`.
impl fmt::Debug for PushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushRequest")
            .field("url", &redact_url(&self.url))
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field("run_id", &self.run_id)
            .field("insecure", &self.insecure)
            .field("connect_timeout", &self.connect_timeout)
            .field("total_timeout", &self.total_timeout)
            .field("retries", &self.retries)
            .finish()
    }
}

/// A successful (2xx) push.
#[derive(Debug)]
pub struct PushOutcome {
    pub status: u16,
    pub reason: String,
    pub request_id: Option<String>,
    pub attempts: u32,
}

/// A parsed `http(s)://host[:port]/path?query` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self> {
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            bail!("push URL must start with https:// (or http:// with --insecure)");
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        if authority.contains('@') {
            bail!("push URL must not contain credentials; use --token or BOAB_PUSH_TOKEN");
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6
                .find(']')
                .ok_or_else(|| anyhow!("invalid IPv6 host in push URL"))?;
            let host = &v6[..end];
            let port = match &v6[end + 1..] {
                "" => default_port,
                p => parse_port(p.strip_prefix(':').unwrap_or(p))?,
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), parse_port(p)?),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() {
            bail!("push URL has no host");
        }
        if path.chars().any(|c| c.is_control() || c == ' ') {
            bail!("push URL path contains invalid characters");
        }
        Ok(Endpoint {
            https,
            host,
            port,
            path,
        })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.https { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{}:{}", host, self.port)
        }
    }
}

fn parse_port(p: &str) -> Result<u16> {
    p.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("invalid port in push URL: {}", p))
}

/// Scheme, host, port and path only: drops any query string, which may carry secrets.
pub fn redact_url(url: &str) -> String {
    match Endpoint::parse(url) {
        Ok(e) => {
            let path = e.path.split('?').next().unwrap_or("/");
            format!(
                "{}://{}{}",
                if e.https { "https" } else { "http" },
                e.host_header(),
                path
            )
        }
        Err(_) => "<invalid url>".to_string(),
    }
}

/// Parses `--header key=value` (or `key: value`) arguments.
pub fn parse_header(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw
        .split_once('=')
        .or_else(|| raw.split_once(':'))
        .ok_or_else(|| anyhow!("--header must be key=value"))?;
    let name = name.trim();
    let value = value.trim();
    let valid_name = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if !valid_name {
        bail!("invalid header name in --header: {:?}", name);
    }
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        bail!("header {} has a value with line breaks", name);
    }
    if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        bail!(
            "header {} is set by boab and cannot be overridden with --header",
            name
        );
    }
    Ok((name.to_string(), value.to_string()))
}

/// Reads and checks the CBOM. Returns the bytes and the CycloneDX spec version.
pub fn load_cbom(source: &Path) -> Result<(Vec<u8>, String)> {
    let bytes = if source == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("read CBOM from stdin")?;
        buf
    } else {
        std::fs::read(source).with_context(|| {
            format!(
                "read CBOM {} (run `boab report --format cbom` first, or pass --file)",
                source.display()
            )
        })?
    };
    let spec_version = validate_cbom(&bytes)?;
    Ok((bytes, spec_version))
}

/// Confirms the payload is a CycloneDX JSON document and returns its `specVersion`.
pub fn validate_cbom(bytes: &[u8]) -> Result<String> {
    let doc: Value = serde_json::from_slice(bytes).context("CBOM is not valid JSON")?;
    if doc.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        bail!("CBOM must have \"bomFormat\": \"CycloneDX\"");
    }
    let version = doc
        .get("specVersion")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        .ok_or_else(|| anyhow!("CBOM has no valid specVersion"))?;
    Ok(version.to_string())
}

/// Posts `body`, retrying network errors, timeouts and 5xx responses.
pub fn push(req: &PushRequest, body: &[u8], spec_version: &str) -> Result<PushOutcome> {
    let endpoint = Endpoint::parse(&req.url)?;
    if !endpoint.https && !req.insecure {
        bail!(
            "refusing to push over plain HTTP to {}; use https:// or pass --insecure",
            redact_url(&req.url)
        );
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("start async runtime")?;
    rt.block_on(push_with_retry(req, &endpoint, body, spec_version))
}

async fn push_with_retry(
    req: &PushRequest,
    endpoint: &Endpoint,
    body: &[u8],
    spec_version: &str,
) -> Result<PushOutcome> {
    // One key for every attempt, so a receiver can drop duplicates if an
    // attempt succeeded but its response was lost.
    let idempotency_key = Uuid::new_v4().to_string();
    let head = request_head(req, endpoint, body.len(), spec_version, &idempotency_key);
    let max_attempts = req.retries.saturating_add(1);
    let target = redact_url(&req.url);
    let mut last_error = String::new();

    for attempt in 1..=max_attempts {
        tracing::debug!(attempt, max_attempts, url = %target, bytes = body.len(), "pushing CBOM");
        let failure = match timeout(req.total_timeout, send_once(req, endpoint, &head, body)).await
        {
            Err(_) => format!(
                "request timed out after {}s",
                req.total_timeout.as_secs_f32()
            ),
            Ok(Err(e)) => format!("{:#}", e),
            Ok(Ok(resp)) if (200..300).contains(&resp.status) => {
                return Ok(PushOutcome {
                    request_id: request_id(&resp),
                    status: resp.status,
                    reason: resp.reason,
                    attempts: attempt,
                });
            }
            Ok(Ok(resp)) if resp.status >= 500 => describe_status(&resp, req.token.as_deref()),
            Ok(Ok(resp)) => {
                // 4xx and other non-retryable statuses fail immediately.
                bail!(
                    "push to {} rejected: {}",
                    target,
                    describe_status(&resp, req.token.as_deref())
                );
            }
        };
        last_error = redact(&failure, req.token.as_deref());
        if attempt < max_attempts {
            let delay = req.retry_delay.saturating_mul(1u32 << (attempt - 1).min(5));
            tracing::warn!(
                "push attempt {}/{} failed: {}; retrying in {:.1}s",
                attempt,
                max_attempts,
                last_error,
                delay.as_secs_f32()
            );
            tokio::time::sleep(delay).await;
        }
    }
    Err(anyhow!(
        "push to {} failed after {} attempt(s): {}",
        target,
        max_attempts,
        last_error
    ))
}

fn request_head(
    req: &PushRequest,
    endpoint: &Endpoint,
    content_length: usize,
    spec_version: &str,
    idempotency_key: &str,
) -> Vec<u8> {
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: boab/{}\r\nAccept: application/json\r\nContent-Type: {}; version={}\r\nContent-Length: {}\r\nIdempotency-Key: {}\r\nConnection: close\r\n",
        endpoint.path,
        endpoint.host_header(),
        env!("CARGO_PKG_VERSION"),
        CYCLONEDX_MEDIA_TYPE,
        spec_version,
        content_length,
        idempotency_key,
    );
    if let Some(token) = req.token.as_deref().filter(|t| !t.is_empty()) {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    if let Some(run_id) = &req.run_id {
        head.push_str(&format!("X-Boab-Run-Id: {}\r\n", run_id));
    }
    for (name, value) in &req.headers {
        head.push_str(&format!("{}: {}\r\n", name, value));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

async fn send_once(
    req: &PushRequest,
    endpoint: &Endpoint,
    head: &[u8],
    body: &[u8],
) -> Result<Response> {
    let tcp = timeout(
        req.connect_timeout,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "connection timed out after {}s",
            req.connect_timeout.as_secs_f32()
        )
    })?
    .with_context(|| format!("connect to {}:{}", endpoint.host, endpoint.port))?;

    if endpoint.https {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .context("configure TLS")?
                .with_root_certificates(roots)
                .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(endpoint.host.clone())
            .with_context(|| format!("invalid server name: {}", endpoint.host))?;
        let tls = timeout(
            req.connect_timeout,
            TlsConnector::from(Arc::new(cfg)).connect(name, tcp),
        )
        .await
        .map_err(|_| anyhow!("TLS handshake timed out"))?
        .context("TLS handshake")?;
        exchange(tls, head, body).await
    } else {
        exchange(tcp, head, body).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    head: &[u8],
    body: &[u8],
) -> Result<Response> {
    stream.write_all(head).await.context("send request")?;
    stream.write_all(body).await.context("send request body")?;
    stream.flush().await.context("send request")?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_RESPONSE_BYTES {
                    raw.truncate(MAX_RESPONSE_BYTES);
                    break;
                }
                if response_complete(&raw) {
                    break;
                }
            }
            // Servers often close TLS without close_notify after a complete response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e).context("read response"),
        }
    }
    parse_response(&raw)
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn split_head(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (&raw[..i], &raw[i + 4..]))
}

fn response_complete(raw: &[u8]) -> bool {
    let Some((head, body)) = split_head(raw) else {
        return false;
    };
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    if let Some(len) = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return body.len() >= len;
    }
    if head.contains("transfer-encoding: chunked") {
        return body.windows(5).any(|w| w == b"0\r\n\r\n");
    }
    false
}

pub fn parse_response(raw: &[u8]) -> Result<Response> {
    let (head, rest) =
        split_head(raw).ok_or_else(|| anyhow!("connection closed before a complete response"))?;
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        bail!("invalid HTTP response");
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP status line"))?;
    let reason = parts.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut resp = Response {
        status,
        reason,
        headers,
        body: Vec::new(),
    };
    resp.body = if resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        decode_chunked(rest)
    } else if let Some(len) = resp
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        rest[..len.min(rest.len())].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(resp)
}

fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&data[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .unwrap_or(0);
        data = &data[line_end + 2..];
        if size == 0 || data.len() < size {
            out.extend_from_slice(&data[..size.min(data.len())]);
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = data.get(size + 2..).unwrap_or_default();
    }
    out
}

/// Request id from common response headers, or a `requestId`/`request_id`/`id` JSON field.
fn request_id(resp: &Response) -> Option<String> {
    for name in ["x-request-id", "request-id", "x-correlation-id"] {
        if let Some(v) = resp.header(name).filter(|v| !v.is_empty()) {
            return Some(v.to_string());
        }
    }
    let body: Value = serde_json::from_slice(&resp.body).ok()?;
    ["requestId", "request_id", "id"]
        .iter()
        .find_map(|k| body.get(*k).and_then(Value::as_str).map(str::to_string))
}

fn describe_status(resp: &Response, token: Option<&str>) -> String {
    let mut text = format!("HTTP {} {}", resp.status, resp.reason)
        .trim()
        .to_string();
    if let Some(id) = request_id(resp) {
        text.push_str(&format!(" (request id: {})", id));
    }
    let body = String::from_utf8_lossy(&resp.body);
    let body = body.trim();
    if !body.is_empty() {
        let shown: String = body.chars().take(MAX_BODY_IN_MESSAGE).collect();
        text.push_str(": ");
        text.push_str(&shown);
        if body.chars().count() > MAX_BODY_IN_MESSAGE {
            text.push_str(" [truncated]");
        }
    }
    redact(&text, token)
}

/// Removes the token from text that came from the network, in case a server echoes it.
fn redact(text: &str, token: Option<&str>) -> String {
    match token {
        Some(t) if !t.is_empty() => text.replace(t, "[REDACTED]"),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let e = Endpoint::parse("https://grc.example.com/api/v1/cbom?x=1").unwrap();
        assert_eq!(
            e,
            Endpoint {
                https: true,
                host: "grc.example.com".into(),
                port: 443,
                path: "/api/v1/cbom?x=1".into()
            }
        );
        let e = Endpoint::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!((e.https, e.port, e.path.as_str()), (false, 8080, "/"));
        let e = Endpoint::parse("https://[::1]:9443/x").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("::1", 9443));
        assert_eq!(e.host_header(), "[::1]:9443");
        assert!(Endpoint::parse("ftp://example.com").is_err());
        assert!(Endpoint::parse("https://user:pw@example.com").is_err());
        assert!(Endpoint::parse("https://example.com:0").is_err());
    }

    #[test]
    fn redacts_query_strings() {
        assert_eq!(
            redact_url("https://example.com:8443/in?token=abc"),
            "https://example.com:8443/in"
        );
    }

    #[test]
    fn validates_headers() {
        assert_eq!(
            parse_header("X-Team=platform").unwrap(),
            ("X-Team".into(), "platform".into())
        );
        assert_eq!(
            parse_header("X-Env: prod").unwrap(),
            ("X-Env".into(), "prod".into())
        );
        assert!(parse_header("Authorization=Bearer x").is_err());
        assert!(parse_header("Content-Type=text/plain").is_err());
        assert!(parse_header("bad name=x").is_err());
        assert!(parse_header("X-A=1\r\nX-B: 2").is_err());
    }

    #[test]
    fn validates_cbom() {
        assert_eq!(
            validate_cbom(br#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#).unwrap(),
            "1.6"
        );
        assert!(validate_cbom(b"{}").is_err());
        assert!(validate_cbom(b"not json").is_err());
        assert!(
            validate_cbom(br#"{"bomFormat":"CycloneDX","specVersion":"1.6\r\nX: y"}"#).is_err()
        );
    }

    #[test]
    fn parses_chunked_and_length_responses() {
        let raw = b"HTTP/1.1 201 Created\r\nX-Request-Id: abc\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert!(response_complete(raw));
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"{\"a\":1}");
        assert_eq!(request_id(&resp).as_deref(), Some("abc"));

        let raw = b"HTTP/1.1 202 Accepted\r\nContent-Length: 20\r\n\r\n{\"requestId\":\"r-9\"}";
        assert!(!response_complete(raw));
        let resp = parse_response(
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 19\r\n\r\n{\"requestId\":\"r-9\"}",
        )
        .unwrap();
        assert_eq!(request_id(&resp).as_deref(), Some("r-9"));
    }

    #[test]
    fn debug_output_hides_the_token() {
        let req = PushRequest {
            url: "https://example.com/in?key=q".into(),
            token: Some("s3cr3t-token".into()),
            headers: vec![("X-Api-Key".into(), "hidden-value".into())],
            run_id: None,
            insecure: false,
            connect_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(1),
            retries: 0,
            retry_delay: Duration::from_millis(1),
        };
        let text = format!("{:?}", req);
        assert!(!text.contains("s3cr3t-token"));
        assert!(!text.contains("hidden-value"));
        assert!(!text.contains("key=q"));
    }

    #[test]
    fn redacts_echoed_tokens() {
        let resp = Response {
            status: 401,
            reason: "Unauthorized".into(),
            headers: vec![],
            body: b"bad token s3cr3t".to_vec(),
        };
        assert_eq!(
            describe_status(&resp, Some("s3cr3t")),
            "HTTP 401 Unauthorized: bad token [REDACTED]"
        );
    }
}
