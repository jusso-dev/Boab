# Boab for PowerShell

A PowerShell 7 port of the [Boab](../README.md) PQC-readiness CLI. It reads and
writes the same `.boab/` workspace, produces the same JSON, CycloneDX 1.6 CBOM and
Markdown reports, prints the same console output and returns the same exit codes
as the Rust `boab` binary, so the two can be used interchangeably on one workspace.

Requirements: PowerShell 7.2 or later (`pwsh`) on Windows, macOS or Linux. No
other dependencies.

## Install / load

```powershell
Import-Module ./powershell/Boab          # from a clone of this repository
Get-Command -Module Boab
```

To install for the current user, copy `powershell/Boab` to a folder on
`$env:PSModulePath` (for example `~/.local/share/powershell/Modules/Boab` or
`Documents/PowerShell/Modules/Boab`) and run `Import-Module Boab`.

## Drop-in CLI: `Invoke-Boab` and `boab.ps1`

`Invoke-Boab` accepts exactly the same arguments as the Rust binary:

```powershell
Invoke-Boab init
Invoke-Boab system add --name "Demo Payments" --classification protected --criticality mission_critical --soci --lifetime-years 25
Invoke-Boab scan codebase ./src
Invoke-Boab scan certs ./certs
Invoke-Boab scan tls example.com:443 --timeout-seconds 5
Invoke-Boab inventory list --tier 1
Invoke-Boab plan generate --milestone 2030 --name "Demo rollout"
Invoke-Boab report --format md -o readiness.md
$LASTEXITCODE   # 0 ok, 1 runtime error, 2 usage error, 64 not implemented (scan codebase --git)
```

Standard output is written to the pipeline one line per string, standard error
goes straight to the console's error stream and `$LASTEXITCODE` is set.
`Invoke-BoabCli -ArgumentList ... -PassThru` returns `ExitCode`, `StdOut` and
`StdErr` (exact text) without printing, which is handy for scripting and tests.

`powershell/boab.ps1` is a thin script wrapper for shells and CI:

```sh
pwsh ./powershell/boab.ps1 init
pwsh ./powershell/boab.ps1 scan tls host:443
echo $?
```

## Cmdlets

| Cmdlet | Rust equivalent |
|--------|-----------------|
| `Initialize-BoabWorkspace [-Path] [-Force]` | `boab init [--force --yes]` |
| `Get-BoabConfig [-Key]` / `Set-BoabConfig -Key -Value` | `boab config get/set` |
| `Add-BoabSystem` / `Get-BoabSystem` / `Set-BoabSystem` / `Remove-BoabSystem` | `boab system add/list/edit/delete` |
| `Get-BoabInventory [-Id] [-PqcStatus] [-Tier] [-SystemId] [-Algorithm]` | `boab inventory list/show` (objects carry a `RiskScore`) |
| `Start-BoabCodebaseScan` / `Start-BoabTlsScan` / `Start-BoabCertificateScan` | `boab scan codebase/tls/certs` |
| `Import-BoabScan -Path <scan.json>` | (no CLI equivalent) dedup an existing scan file into the inventory |
| `New-BoabPlan` / `Get-BoabPlan` / `Update-BoabPlan` | `boab plan generate/list,show/regenerate` |
| `Get-BoabVendor [-Search]` / `Add-BoabVendor` | `boab vendor list,search/add` |
| `Export-BoabReport -Format json\|cbom\|md [-OutputPath]` | `boab report` |
| `ConvertTo-BoabJson` | `serde_json::to_string_pretty`-compatible serialiser |

Every cmdlet takes `-Workspace <path>` (default `.`). Commands that change state
support `-WhatIf`/`-Confirm`.

## Parity notes

* **JSON** is written by `ConvertTo-BoabJson`, a re-implementation of
  `serde_json::to_string_pretty` (2-space indent, struct field order, serde
  escaping, no trailing newline, shortest round-trip floats with serde's
  exponent style, `f32` priorities rendered as f32). `ConvertTo-Json` is never used.
* **Scoring** reproduces the LATICE rubric with IEEE single-precision arithmetic
  (each operation rounded to f32, `round()` half away from zero), so priorities
  and tiers are identical. `{:.1}` formatting is exact half-to-even, like Rust.
* **Timestamps** follow the `time` crate: RFC 3339 with trimmed fractional
  seconds, `Z` for UTC, and `+002030-09-01T00:00:00.000000000Z` for plan target
  dates. .NET clocks have 100 ns resolution, so fractional digits differ from a
  Rust build on Linux (nanoseconds) or macOS (microseconds); values are otherwise
  formatted identically.
* **Config** (`config.toml`) is parsed with a small TOML reader and written in
  exactly the layout and string-quoting style of `toml::to_string_pretty`.
* **Console tables** mirror comfy-table's `UTF8_FULL` preset (non-TTY layout).
* **CLI parsing** mirrors clap: `--opt=value`, `-ovalue`, global flags anywhere,
  `--`, help/version output (captured verbatim from the Rust binary), suggestion
  tips, and the same error messages with exit code 2.
* **Paths** are canonicalised like `std::fs::canonicalize` (symlinks resolved,
  `\\?\` prefix on Windows) wherever the Rust code canonicalises.
* `--verbose`, `--quiet` and `--no-progress` are accepted; the Rust binary only
  emits debug-level logs for them, which the port does not reproduce.

## Scanners

The scanner implementations (`Invoke-BoabCodebaseScan`, `Invoke-BoabTlsScan`,
`Invoke-BoabCertStoreScan`) live in `Private/ScanModel.ps1` and
`Private/Scanners/*.ps1` and are loaded automatically. Everything downstream of
a scanner (dedup, storage, scoring, plans, reports, console output) is
implemented in this module.

Scanner parity notes:

* **Codebase** walks the tree with its own port of the `ignore` crate's rules
  (`.gitignore` in every ancestor, `.ignore`, `.git/info/exclude`, the global
  excludes file, hidden files, override globs translated like `globset`) and
  visits entries in raw directory order, like the Rust walker.
* **TLS** uses a raw TLS client over `TcpClient` rather than `SslStream`, so it
  can offer exactly the cipher suites, groups and signature schemes rustls/ring
  offers and read the negotiated key-exchange group. Trust decisions use the OS
  trust store plus webpki-style checks, so rare chains (cross-signed roots,
  platform-specific policies) can pass or fail differently from webpki with the
  Mozilla roots. `CertificateVerify`/`Finished` are not verified.
* **Certificate stores** parse X.509 with a small DER reader that formats names,
  algorithms and dates like `x509-parser`; PKCS#12 entries are chosen the way
  `p12-keystore` chooses them. The DER reader is more lenient than
  `x509-parser`, so a malformed certificate Rust skips may still be reported.

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force   # once
Invoke-Pester ./powershell/tests -Output Detailed
```

* `Json`, `Scoring`, `Dedup`, `Cli`, `EndToEnd` - unit and integration tests
  ported from the Rust test suite (`tests/*.rs` and the `#[cfg(test)]` modules).
* `Golden` - byte-level comparison (after normalising UUIDs and timestamps)
  against outputs generated by the Rust library (`tests/fixtures/golden`) and
  against the committed demo in `examples/demo`.
* `Parity` - runs the same command sequence through the Rust binary and the
  module in two temporary workspaces and diffs stdout, stderr, exit codes and
  every file. It needs a built binary (`cargo build --release`, or set
  `$env:BOAB_RUST_BIN`) and is skipped otherwise.

Golden fixtures are regenerated with the small Rust program in
`tools/golden-gen` (it links against the Boab library):

```sh
cd powershell/tools/golden-gen
cargo run --release -- numbers ../../tests/fixtures/golden/numbers.json
cargo run --release -- scores  ../../tests/fixtures/golden/scores.json
cargo run --release -- workspace ../../tests/fixtures/scans /tmp/golden-ws
cp -R /tmp/golden-ws/.boab/. ../../tests/fixtures/golden/workspace/
```
