# Boab examples

Self-contained worked example showing a Boab run against intentionally
weak cryptographic material. Use it to preview the kind of inventory,
risk-scored findings, plan, and reports Boab produces before pointing it
at your own systems.

## What the demo does

`demo/run-demo.sh` reproduces the full pipeline end-to-end:

1. `boab init` a workspace in `demo/`.
2. Register a SOCI-classified "Demo Payments" system with a 25-year
   data lifetime (forces tier elevation via the LATICE rubric).
3. Generate weak local certificates under `demo/certs/`:
   - RSA-1024 signed with SHA-1
   - RSA-2048 (quantum-vulnerable)
   - RSA-4096 with a 20-year validity window (harvest-now-decrypt-later)
   - ECDSA P-256
   - A pre-expired RSA-2048 cert
4. Scan a small Python + Go sample app under `demo/app/` that imports
   MD5, SHA-1, DES, DSA, RSA, and ECDSA P-256.
5. Run `boab scan tls` against the public badssl.com endpoints
   (expired, self-signed, RSA-2048, RSA-4096, SHA-1 chain,
   TLS 1.0, TLS 1.1, plus the healthy baseline).
6. Generate a 2030 transition plan and emit three reports:
   - `demo/reports/inventory.json` — native Boab schema
   - `demo/reports/cbom.cdx.json` — CycloneDX 1.6 CBOM
   - `demo/reports/readiness.md` — board-ready Markdown

The committed `demo/reports/` directory is the output of one such run,
so you can browse it without installing anything.

## Re-running it

```sh
cargo build --release
cd examples/demo
../../target/release/boab init --force --yes   # optional: wipe + restart
./run-demo.sh ../../target/release/boab
```

The script is idempotent (re-init is safe) and uses pinned subjects so
diffs across runs are mostly limited to UUIDs and timestamps.

The TLS step requires outbound 443 to badssl.com. Everything else is
offline.

## What you should see

Eighteen inventory items, twelve flagged `vulnerable`, three
`symmetric_ok`, three `unknown`. The Markdown readiness report ranks
the assets by LATICE priority — MD5/SHA-1 from the sample code, the
weak certs, then the badssl.com server-leaf certificates. Top of the
list is the RSA-1024 + SHA-1 cert which the rubric flags as priority
5.4, triage tier 3.

See `demo/reports/readiness.md` for the full board-pack output and
`demo/inventory.txt` for the inventory table snippet.

## Caveats

- Paths in the bundled reports are absolute and reflect the machine
  that generated them. Re-run `run-demo.sh` locally to get paths that
  match your filesystem.
- The certs under `demo/certs/` carry **real private keys**. They are
  for never-used hostnames and are safe to publish, but never reuse
  them anywhere outside this demo.
- TLS handshakes to known-broken endpoints (`expired`, `self-signed`,
  `sha1-intermediate`, `tls-v1-0`, `tls-v1-1`) are expected to fail.
  Boab records the scan as `Failed` and continues — that is the
  correct behaviour, not a bug.
