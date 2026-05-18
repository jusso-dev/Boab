# Boab

Boab is a Rust command-line tool that helps Australian organisations meet ASD's
post-quantum cryptography (PQC) transition obligations. It scans codebases,
TLS endpoints, and certificate stores; produces a deduplicated cryptographic
inventory; scores assets against the ASD LATICE framework; generates
transition plans aligned to the 2026, 2028, and 2030 milestones; and exports
the result as JSON, CycloneDX 1.6 CBOM, and Markdown reports.

Boab is air-gapped by default. The only outbound connections are TLS
handshakes against targets you supply.

## Install

```sh
cargo install boab
```

Prebuilt binaries are published on the GitHub Releases page for Linux, macOS,
and Windows.

## Quickstart

```sh
boab init
boab system add --name "Payments" --classification protected --criticality mission_critical --soci --lifetime-years 25
boab scan codebase .
boab inventory list
boab plan generate --milestone 2028
boab report --format md --output readiness.md
```

## ASD timeline

- Refined PQC transition plan due by end of 2026
- Implementation begins by 2028
- Implementation complete by 2030

## License

Dual licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
