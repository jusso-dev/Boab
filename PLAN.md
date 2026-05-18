# Boab Phase 0 Plan

This document is the Phase 0 deliverable for Boab, the standalone Rust
command-line tool that helps Australian organisations meet the ASD post-quantum
cryptography transition obligations. It records the crate choices, workspace
layout, and open questions before any non-placeholder code is written.

Phase 0 produces no compilable code beyond a placeholder `Cargo.toml`. All
implementation work begins in Phase 1.

Australian English is used throughout. No em dashes appear anywhere in this
plan, in source files, or in user-facing output.

## 1. Crate choices and versions

All versions below are the latest stable releases compatible with Rust 2021
edition and MSRV 1.75. Pinning is done in `Cargo.toml` using caret ranges
(for example `clap = "4.5"`) so we receive compatible patch and minor updates.
Exact patch versions are resolved by `Cargo.lock`, which is committed for the
binary.

### Core CLI and runtime

| Crate | Version | Reason |
| --- | --- | --- |
| `clap` | `4.5` | CLI parsing with derive macros; matches the spec. Features: `derive`, `wrap_help`. |
| `tokio` | `1.40` | Async runtime reserved for the TLS scanner. Features: `rt-multi-thread`, `macros`, `fs`, `net`, `time`, `signal`. |
| `anyhow` | `1` | Ergonomic error handling for the binary crate. |
| `thiserror` | `1` | Typed errors for the library crate (`lib.rs`). |
| `tracing` | `0.1` | Structured logging. |
| `tracing-subscriber` | `0.3` | Console formatter with `EnvFilter`. Features: `env-filter`, `fmt`, `ansi`. |
| `indicatif` | `0.17` | Progress bars; suppressed when stdout is not a TTY or `--no-progress` is set. |
| `comfy-table` | `7` | Console tables and Markdown table rendering. |

### Serialisation

| Crate | Version | Reason |
| --- | --- | --- |
| `serde` | `1` | Derive-based serialisation. Features: `derive`. |
| `serde_json` | `1` | JSON output for inventory, scans, plans, reports. Features: `preserve_order` for stable key ordering in reports. |
| `toml` | `0.8` | `.boab/config.toml` parsing. |

### TLS and certificates

| Crate | Version | Reason |
| --- | --- | --- |
| `rustls` | `0.23` | Pure-Rust TLS. No OpenSSL linkage. Features: `ring` provider for stability in v1; `aws-lc-rs` can be evaluated later. |
| `tokio-rustls` | `0.26` | Async glue between `tokio` and `rustls`. |
| `rustls-pki-types` | `1` | Shared PKI types used by `rustls`. |
| `webpki-roots` | `0.26` | Mozilla CA roots for TLS scanner. Bundled, no runtime fetch. |
| `x509-parser` | `0.16` | Pure-Rust X.509 parsing for the certificate store scanner. |

### Filesystem and search

| Crate | Version | Reason |
| --- | --- | --- |
| `ignore` | `0.4` | Ripgrep's walker; respects `.gitignore`, `.ignore`, and hidden file rules. |
| `regex` | `1.10` | Pattern matching for codebase scanner. `RegexSet` is used to batch language packs efficiently. |
| `sha2` | `0.10` | SHA-256 fingerprints for certs and content hashing in dedup. |
| `uuid` | `1` | Identifiers for systems, assets, findings, scans, plans. Features: `v4`, `serde`. |
| `time` | `0.3` | Timestamps. Features: `serde`, `formatting`, `parsing`, `macros`. |

### Optional and feature-gated

| Crate | Version | Feature flag | Reason |
| --- | --- | --- | --- |
| `gix` | latest stable | `git` | Pure-Rust git clone for `boab scan codebase --git`. See open question 2. |
| `p12-keystore` | latest stable | `pkcs12` | Pure-Rust PKCS12 parsing. See open question 3. |
| `jks` | latest stable | `jks` | Pure-Rust Java KeyStore parsing. See open question 3. |
| `rayon` | `1` | not feature gated; introduced only if benchmarks justify it in Phase 2 | Parallel codebase scanning. |

### Testing

| Crate | Version | Reason |
| --- | --- | --- |
| `assert_cmd` | `2` | Black-box CLI invocation tests. |
| `predicates` | `3` | Assertion helpers for `assert_cmd`. |
| `insta` | `1` | Snapshot tests for report outputs. |
| `tempfile` | `3` | Isolated workspace fixtures. |
| `jsonschema` | `0.18` | Validate the CycloneDX 1.6 CBOM output in CI. |

### Excluded from v1

| Crate | Reason for exclusion |
| --- | --- |
| `openssl` | OpenSSL linkage is explicitly out of scope. We stay on `rustls` and `x509-parser` for a single static binary. |
| `cyclonedx-bom` | Per the spec, CBOM output is hand-rolled against the 1.6 JSON schema so we can guarantee 1.6 conformance without tracking an upstream crate's lag. |
| `reqwest` and HTTP clients | Air-gapped by default. The TLS scanner uses raw `rustls`; any HSTS probe (off by default) will use a minimal `tokio` HTTP client written in-tree, not a full HTTP crate. |

### Dependency hygiene

- `cargo audit` runs in CI on every PR and on main.
- `cargo deny` is added in Phase 5 to enforce the licence allow-list and ban OpenSSL transitive pulls.
- Every new dependency added after Phase 0 must be justified in the
  corresponding phase summary.

## 2. Workspace layout

Single crate at the repository root. No sub-crates in v1. The structure
proposed in the spec is adopted verbatim, with one clarification: the term
"workspace" inside Boab refers to the `.boab/` directory that holds customer
data, not a Cargo workspace. Cargo sees a single package.

```
boab/
|-- Cargo.toml
|-- Cargo.lock
|-- README.md
|-- LICENSE-MIT
|-- LICENSE-APACHE
|-- PLAN.md
|-- src/
|   |-- main.rs
|   |-- lib.rs
|   |-- cli.rs
|   |-- config.rs
|   |-- workspace.rs
|   |-- model/
|   |   |-- mod.rs
|   |   |-- asset.rs
|   |   |-- finding.rs
|   |   |-- scan.rs
|   |   |-- system.rs
|   |   |-- score.rs
|   |   |-- plan.rs
|   |   `-- vendor.rs
|   |-- scoring.rs
|   |-- dedup.rs
|   |-- scanners/
|   |   |-- mod.rs
|   |   |-- codebase.rs
|   |   |-- codebase/
|   |   |   `-- patterns/
|   |   |       |-- mod.rs
|   |   |       |-- javascript.rs
|   |   |       |-- python.rs
|   |   |       |-- go.rs
|   |   |       |-- java.rs
|   |   |       |-- dotnet.rs
|   |   |       `-- rust.rs
|   |   |-- tls.rs
|   |   `-- cert_store.rs
|   |-- plan.rs
|   |-- vendor.rs
|   |-- report/
|   |   |-- mod.rs
|   |   |-- json.rs
|   |   |-- cbom.rs
|   |   `-- markdown.rs
|   `-- storage.rs
|-- data/
|   `-- vendor-pqc-registry.json
|-- docs/
|   |-- usage.md
|   |-- scanners.md
|   |-- vendor-registry.md
|   |-- cbom.md
|   `-- backlog-v1.1.md
|-- tests/
|   |-- fixtures/
|   |   |-- codebase/
|   |   |-- certs/
|   |   `-- cyclonedx-1.6.schema.json
|   `-- integration.rs
`-- .github/
    `-- workflows/
        |-- ci.yml
        `-- release.yml
```

Notes on the layout:

- `src/lib.rs` exposes the library surface so integration tests in `tests/`
  can call the same code paths as the binary. `src/main.rs` is a thin shell
  that calls into `boab::run`.
- `src/scanners/codebase/patterns/` is added inside the `codebase.rs`
  module so per-language pattern packs live next to the scanner that uses
  them. This is one small deviation from the spec; called out here for
  approval.
- The `data/vendor-pqc-registry.json` file is bundled with
  `include_str!`, exactly as the spec requires.
- `docs/backlog-v1.1.md` captures items deliberately deferred (KMS scanners,
  Kubernetes, SSH, live vendor fetching, and so on).

## 3. Open questions and recommendations

Each item below either flags a real ambiguity in the spec or records a
choice I want sign-off on before writing code. Recommendations are mine
unless noted otherwise.

### 3.1 PKCS12 and JKS crate choices

The spec says "the `p12` and `jks` crates if maintained, else flag the gap".

Findings:

- `p12` exists but has been quiet. `p12-keystore` is more actively maintained
  and provides a higher-level API for reading PKCS12 keystores. It still
  parses with `rustls-pki-types` compatible types.
- `jks` (the crate at `crates.io/crates/jks`) is functional but lightly
  maintained. Java is moving to PKCS12 by default since JDK 9, so JKS will
  remain a long tail.

Recommendation: use `p12-keystore` for PKCS12 and `jks` for JKS, both
behind feature flags `pkcs12` and `jks` so they can be disabled in
constrained builds. If `jks` parsing fails on real-world fixtures we
encounter in Phase 3, we will document the gap and recommend customers
convert JKS to PKCS12 with `keytool` before scanning.

### 3.2 Git cloning for `boab scan codebase --git`

The spec offers `gix` or shelling out to the `git` binary.

Recommendation: use `gix` behind a `git` feature flag, enabled by default.
`gix` is pure Rust so the single static binary story holds. If the
transitive dependency footprint blows out the binary by more than roughly
2 megabytes after stripping, fall back to shelling out to `git` and
document the requirement. Either way, the cloned working tree lives in a
`tempfile::TempDir` and is deleted at the end of the scan.

### 3.3 CycloneDX 1.6 generation

The spec says hand-roll the JSON and validate against the bundled schema.

Recommendation: confirmed. We define internal types that mirror the
CycloneDX 1.6 model, serialise them with `serde_json`, and validate the
output in tests using the `jsonschema` crate against
`tests/fixtures/cyclonedx-1.6.schema.json`. If a future minor revision of
CycloneDX (1.7, 1.8) appears, we add a feature flag at that point rather
than tracking a third-party crate's release cadence.

### 3.4 Coverage tool

The spec offers `cargo-llvm-cov` or `cargo-tarpaulin` for the 100% scoring
engine coverage requirement.

Recommendation: `cargo-llvm-cov`. It uses LLVM source-based coverage,
works on Linux, macOS, and Windows, runs fast, and produces lcov output
that GitHub Actions can render directly. Tarpaulin is Linux-only and slower.

### 3.5 Parallel codebase scanning

The spec leaves `rayon` to a quick benchmark.

Recommendation: ship Phase 2 serial. If a fixture repo of around 10000
files takes longer than a second on a developer laptop, introduce `rayon`
with `par_bridge` over the `ignore::Walk` iterator. Either way, the choice
is hidden behind the scanner's public API.

### 3.6 Logging defaults

The spec defines `--verbose` and `--quiet` but not the default level.

Recommendation: default to `WARN` for the root and `INFO` for the `boab`
target, so users see scan progress and outcomes without internal noise.
`--verbose` raises to `DEBUG`. `--quiet` lowers to `ERROR`. Override via
`RUST_LOG` per the standard `tracing-subscriber` convention.

### 3.7 Pretty JSON and stable key ordering

The native JSON report calls for "stable key ordering".

Recommendation: enable the `preserve_order` feature on `serde_json` so
field order in the Rust types determines field order in the output. For
collections like maps that we want sorted, sort the keys before
serialisation. This gives diffable, deterministic output without
introducing a separate ordered-map crate.

### 3.8 Exit codes

The spec says CLI stubs "print not yet implemented with the correct exit
code" but does not enumerate the code table.

Recommendation (mine, to be confirmed):

- 0 success
- 1 generic failure
- 2 usage error (clap returns this automatically)
- 3 workspace not initialised
- 4 scanner failure
- 5 report validation failure
- 64 not yet implemented (matches BSD `EX_USAGE` convention for "feature
  available but not invoked correctly", repurposed for stubs in Phase 1)

If you prefer a flatter scheme (0, 1, 2 only) I will collapse to that.

### 3.9 Detection confidence rubric

The spec gives high, medium, low examples. To make the codebase scanner
testable, I will pin the rubric in code as:

- High: explicit named algorithm string in source, or a call to a
  parameterised constructor whose parameters are literal constants
  (`RSA.generate(2048)`, `crypto.createHash("sha1")`).
- Medium: a call into a known crypto library whose algorithm is inferable
  from context but not literal (variable holding the algorithm name, or
  default-arg use of an algorithm).
- Low: a bare import of a crypto library with no observed call site, or a
  file extension match that we cannot parse further (a `.p12` without a
  password).

### 3.10 Vendor registry initial population

The spec lists about 20 initial vendors. Some entries will have a
`pqc_status` we cannot honestly verify by the cutover date. I will populate
the bundled JSON with `pqc_status = Unknown` and a comment-style
`source_note` for any product I cannot back with a public source. Customer
overrides then close the gap operationally. Refresh process documented in
`docs/vendor-registry.md`.

### 3.11 TLS scanner air-gap stance

The spec says "no outbound network calls except the TLS scanner against
user-specified targets". The HSTS probe is "off by default for air-gapped
mode".

Recommendation: HSTS probing requires `--probe-hsts`. The flag is denied
when `--air-gapped` is set. The TLS scanner itself records that it is the
only outbound call site and writes its targets and timings to the scan
record so customers can audit.

### 3.12 `boab init` idempotency

The spec says "idempotent (or errors with a clear message if non-empty)".

Recommendation: `boab init` succeeds silently and prints "already
initialised" if `.boab/config.toml` already exists with a valid header. It
errors with exit code 1 if `.boab/` exists but is malformed (for example
not a directory, or missing `config.toml`). Add `--force` to wipe and
recreate; require `--yes` to confirm.

### 3.13 Naming consistency: `report` versus `reports`

The spec uses `boab report` as the command name and singular subcommand
arguments. I will keep that. The output directory convention I propose is
`.boab/reports/` if customers do not pass `--output`; otherwise the file
is written wherever they ask. Confirm if you would rather the default be
the current directory.

### 3.14 Workspace flag scope

`--workspace <dir>` is global. I will resolve it to an absolute path
before any subcommand runs and store the resolved path in a `Context`
struct passed to every command. Subcommands never read the CWD again.

## 4. Stop

This concludes Phase 0. No source code beyond the placeholder
`Cargo.toml` has been written. Awaiting sign-off before starting Phase 1.
