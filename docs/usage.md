# Boab usage guide

This guide walks through Boab from a fresh install through to the first
exported readiness report. All commands assume you have run `cargo install
boab` or downloaded a Boab binary from the GitHub Releases page.

Boab is air-gapped by default. The only outbound network connections it
makes are TLS handshakes against the targets you supply to `boab scan tls`.

## 1. Initialise a workspace

A Boab workspace is just a `.boab/` directory inside the project root.

```sh
cd /path/to/project
boab init
```

This creates `.boab/` with the following layout:

```
.boab/
  config.toml
  systems.json
  inventory.json
  scans/
  plans/
  reports/
  vendor-overrides.json
```

Re-running `boab init` is safe: it prints "already initialised" and exits
0. Use `boab init --force --yes` to wipe and recreate.

## 2. Add the business systems in scope

Boab uses systems to weight assets correctly via the ASD LATICE rubric.

```sh
boab system add \
  --name "Payments" \
  --classification protected \
  --criticality mission_critical \
  --soci \
  --lifetime-years 25
```

Classification options: `unofficial`, `official`, `official_sensitive`,
`protected`, `secret`, `top_secret`. Criticality options: `low`,
`standard`, `essential`, `mission_critical`. Pass `--soci` for SOCI
critical assets, which forces system criticality to 10.

`boab system list`, `boab system edit`, and `boab system delete` round
out the system commands.

## 3. Run scanners

### Codebase

```sh
boab scan codebase ./services/payments
```

Boab walks the path with `.gitignore` semantics, applies per-language
pattern packs (Rust, Go, Python, JavaScript/TypeScript, Java/Kotlin,
.NET) plus generic algorithm-name patterns, and records every match as a
Finding. Cert and key files (`.pem`, `.crt`, `.cer`, `.der`, `.p12`,
`.pfx`, `.jks`, `.key`) are also picked up.

Use `--include` and `--exclude` to override the default exclude list
(`node_modules`, `vendor`, `.venv`, `target`, `dist`, `build`, `.git`).

### TLS endpoints

```sh
boab scan tls www.example.com:443 api.example.com:443
```

Boab runs a TLS 1.3 handshake (falling back to 1.2), records the
negotiated cipher suite, certificate chain, and ALPN, and detects PQ
hybrid groups by codepoint (`0x11EC` for `X25519MLKEM768`).

Rate limit is 1 host/second by default. Override with `--rate-limit`.
HSTS probing (`--probe-hsts`) is forbidden when the workspace is in
air-gapped mode (the default).

### Certificate stores

```sh
boab scan certs ./certs/production
```

Walks for X.509 in PEM/DER, plus PKCS#12 (with `--password-file` if
required). JKS files are flagged as present but not parsed: convert
them to PKCS12 with `keytool` first.

## 4. Inspect the inventory

```sh
boab inventory list
boab inventory list --tier 1
boab inventory list --pqc-status vulnerable
boab inventory show <asset-id>
```

`inventory list` renders a Unicode table with priority, tier, PQC status,
and the system the asset is attached to. Filter by `--tier`, `--system`,
`--algorithm`, or `--pqc-status`.

`inventory show <id>` prints the full record and its scored values as
pretty-printed JSON.

## 5. Generate transition plans

```sh
boab plan generate --milestone 2028
boab plan generate --milestone 2030 --name "Long tail rollout"
boab plan list
boab plan show <plan-id>
boab plan regenerate <plan-id>
```

The 2028 plan only contains tier 1 and tier 2 assets. The 2030 plan
extends to tier 3 and tier 4.

User edits to `target_action`, `target_date`, `assignee`, `notes`, and
`status` are preserved across `boab plan regenerate <id>`, provided the
underlying `crypto_asset_id` is unchanged.

## 6. Inspect vendor PQC roadmaps

```sh
boab vendor list
boab vendor search azure
boab vendor add --vendor Microsoft --product Azure --pqc-status resistant \
  --target-date 2026-Q4 --source-url https://...
```

Customer additions go into `.boab/vendor-overrides.json` and merge on top
of the bundled registry. There is no outbound fetching.

## 7. Export reports

```sh
boab report --format json --output board-pack.json
boab report --format cbom --output bom.cdx.json
boab report --format md --output readiness.md
```

The three formats:

- `json`: native Boab schema. Best for diffing across runs.
- `cbom`: CycloneDX 1.6 cryptographic BOM, JSON-encoded.
- `md`: board-ready Markdown readiness report.

Defaults land in `.boab/reports/` if `--output` is omitted.

## Air-gapped operation

Boab makes no outbound connections except for `boab scan tls`. If you
want to enforce that, leave `scanner.air_gapped = true` in `.boab/config.toml`
(the default) which also blocks `--probe-hsts`.

## Exit codes

- 0 success
- 1 generic failure
- 2 clap usage error
- 3 workspace not initialised (Boab error path)
- 64 subcommand not yet implemented (reserved)
