# Scanner reference

Boab ships three scanners, each producing the same shape of `Finding`
records that flow through a shared dedup pipeline into the canonical
inventory.

## Codebase scanner

Implementation: `src/scanners/codebase.rs`.

Walks the target path with the `ignore` crate (the same engine ripgrep
uses), respecting `.gitignore`, `.ignore`, and hidden file rules.
Default excludes added on top: `node_modules`, `vendor`, `.venv`,
`venv`, `target`, `dist`, `build`, `.git`. Override with `--include` and
`--exclude`.

Per-language pattern packs live in
`src/scanners/codebase/patterns/mod.rs`. The packs detect both:

- Algorithm names in literal strings (`"RSA-2048"`, `"sha1"`, JWT `alg`
  tokens such as `"RS256"`).
- Crypto library imports (`use ring`, `from cryptography`, `"crypto/sha256"`,
  `require('node:crypto')`, `import javax.crypto`,
  `using System.Security.Cryptography`).

Confidence rubric:

- High: explicit named algorithm string or a parameterised constructor
  with literal arguments.
- Medium: a call into a known crypto library whose algorithm we cannot
  infer from context.
- Low: bare imports, or cert/key files matched by extension.

## TLS endpoint scanner

Implementation: `src/scanners/tls.rs`. Async via `tokio` and `tokio-rustls`.

Per target:

- TLS 1.3 handshake attempted first; falls back to TLS 1.2.
- Captures the certificate chain (subject, issuer, signature algorithm,
  public key algorithm and approximate size, validity window, SHA-256
  fingerprint).
- Negotiated cipher suite, ALPN.
- Default rate limit 1 host/second. Override with `--rate-limit`.
- Connection timeout default 10 seconds.

Hybrid PQ groups are recognised by codepoint:

- `0x11EC` -> `X25519MLKEM768`
- `0x6399` -> `X25519Kyber768Draft00`

HSTS probing requires `--probe-hsts` and is forbidden when
`scanner.air_gapped = true` in `.boab/config.toml`.

## Certificate store scanner

Implementation: `src/scanners/cert_store.rs`.

Walks a directory for files with extensions `.pem`, `.crt`, `.cer`,
`.der`, `.p7b`, `.p12`, `.pfx`, `.jks`. Parses with `x509-parser` for
X.509 and `p12-keystore` for PKCS12.

JKS support is a documented gap: convert JKS keystores to PKCS12 with
`keytool -importkeystore -srcstoretype JKS -deststoretype PKCS12` before
scanning. JKS files are still emitted as Low-confidence findings so
they appear in your inventory.

Passwords are read from `--password-file` if needed. Boab never stores or
logs the password.

## Dedup pipeline

Implementation: `src/dedup.rs`. Runs at the end of every scan via
`promote_into_workspace`.

Dedup keys:

- Algorithms and library imports: `(algorithm_name, normalised key size,
  source root)`.
- Cert/keystore files in a codebase scan: `sha256(file bytes)`.
- TLS certificates: `sha256(DER)`.
- TLS endpoints: `target + cipher suite`.
- TLS supported groups: `target + group name`.

Promotion is idempotent. Re-running the same scan does not add duplicate
inventory entries and preserves user-set fields on existing assets:
`notes`, `migration_status`, `target_milestone`, `system_id`,
`data_retention_horizon_year`, `description`, `tags`.
