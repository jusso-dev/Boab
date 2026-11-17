# Scanner reference

Boab ships five scanners, each producing the same shape of `Finding`
records that flow through a shared dedup pipeline into the canonical
inventory. Only `boab scan tls` makes network connections. The host and
KMS scanners read local files or files you export; they make no cloud or
network calls.

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
`.der`, `.p7b`, `.p12`, `.pfx`, `.jks`, `.jceks`. Parses with
`x509-parser` for X.509, `p12-keystore` for PKCS12, and an in-tree
reader (`src/scanners/jks.rs`) for JKS and JCEKS.

Every certificate in a keystore is recorded as a certificate asset, as
before. In addition, each keystore alias becomes a `keystore_entry` key
asset:

| Field (`parameter_set`) | Meaning |
| --- | --- |
| `host` | `--host`, or this machine's host name |
| `location` | Keystore file path |
| `store_type` | `PKCS12`, `JKS` or `JCEKS` |
| `alias` | Entry alias |
| `entry_type` | `private_key`, `trusted_certificate` or `secret_key` |
| `key_size_bits` | From the entry certificate's public key |
| `public_key_algorithm`, `public_key_algorithm_oid`, `signature_algorithm`, `subject`, `issuer`, `not_before_unix`, `not_after_unix`, `certificate_sha256` | From the leaf certificate |
| `integrity_verified` | `true` when the password matched the store's integrity check, `false` when it did not, `null` with no password |

`algorithm_name` is `RSA`, `ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`,
`Ed25519` or `Ed448`, from the certificate public key only. EC sizes come
from the named curve.

Private key bytes are never recorded or logged. For JKS and JCEKS the
protected key blob is skipped by length and never decrypted. For PKCS12
the `p12-keystore` library decrypts shrouded key bags while parsing and
holds them in memory until the scan of that file ends; Boab does not
read them. Scan certificate-only truststores, or JKS, if even in-memory
decryption is not acceptable.

`integrity_verified` is `true` only when an integrity check actually ran
and passed: the JKS keyed digest, or the PKCS#12 MAC. A PKCS#12 without a
MAC gives `null`. A keystore with a wrong password is still listed, with
`integrity_verified = false` and a warning.

JCEKS secret key entries are Java-serialised `SealedObject`s. Boab walks
the serialisation only to find where each entry ends (the sealed bytes
are skipped unread), so later aliases are still listed. Secret key
entries are recorded with `algorithm_name = unknown`, no `primitive`,
and `seal_algorithm` (the algorithm protecting the key, e.g.
`PBEWithMD5AndTripleDES`, not the key's own algorithm).

Passwords are read from `--password-file` if needed. Boab never stores or
logs the password.

## Host crypto scanner

Implementation: `src/scanners/host.rs`.

```sh
boab scan host /                         # this machine
boab scan host /mnt/web01 --host web01   # a mounted image or a copied /etc tree
```

Reads files under a root directory. Every recorded path is the path on
the scanned host, so `/mnt/web01/etc/ssh/sshd_config` is recorded as
`/etc/ssh/sshd_config`. The host label is `--host`, else
`<root>/etc/hostname`, else (for `/`) the local host name.

Symlinks are resolved inside the root: an absolute target is read from
under the root, and `..` cannot climb above it, so a mounted image is
never mixed with the scanning machine's own files. A path that exists
but cannot be read (permissions, I/O error) is listed in the scan
record's `config.collection_errors`, `error_message` says the inventory
may be incomplete, and a warning is logged. Missing optional files are
not errors.

What it reads:

| Source | Files | Asset kind |
| --- | --- | --- |
| SSH host public keys | `/etc/ssh/ssh_host_*_key.pub`, `*-cert.pub`, and `HostKey` paths from sshd_config with `.pub` appended | `ssh_host_key` (`key`) |
| SSH private host keys | Names only, from the directory listing. Never opened. Recorded only when no `.pub` sits beside them | `ssh_host_key` (`key`) |
| sshd algorithm lists | `/etc/ssh/sshd_config`, its `Include` files (wildcards supported), then `/etc/crypto-policies/back-ends/opensshserver.config` for directives sshd_config leaves unset. `Match` blocks are skipped. First value wins, as in sshd | `ssh_config_algorithm` (`algorithm`), one per entry of `HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs` |
| RHEL/Fedora crypto policy | `/etc/crypto-policies/state/current`, else `/etc/crypto-policies/config`; the back-end file list; TLS settings from `back-ends/opensslcnf.config` | `os_crypto_policy` (`protocol_endpoint`) |
| OpenSSL config | `/etc/ssl/openssl.cnf`, `/etc/pki/tls/openssl.cnf`, `/usr/lib/ssl/openssl.cnf`, `/usr/local/ssl/openssl.cnf`, `/etc/openssl/openssl.cnf`, following `.include`. Settings come only from the section OpenSSL applies system-wide (`openssl_conf` -> `ssl_conf` -> `system_default`, recorded as `ssl_section`); a later assignment in that section replaces an earlier one. Without that chain nothing is recorded and `allowed_protocols` is `null` (OpenSSL defaults) | `openssl_config` (`protocol_endpoint`) |

SSH key comments (often `user@host`) are never recorded. A `.pub` file
that cannot be parsed does not hide its private key file: the key is
still recorded from the private key file's name, with
`public_key_available = false`. SSH key sizes
come from the public key blob (RSA and DSA modulus length, ECDSA curve).

PQC status:

- Host keys and host key algorithms: RSA, DSA, ECDSA, Ed25519, Ed448 are
  `vulnerable`.
- KEX: `sntrup761x25519-sha512`, `mlkem768x25519-sha256` and other ML-KEM
  hybrids are `hybrid`; classical ECDH, X25519 and DH are `vulnerable`.
- Ciphers and MACs: AES, ChaCha20-Poly1305, HMAC-SHA2 and UMAC-128 are
  `symmetric_ok`; 3DES, Blowfish, CAST-128, RC4, HMAC-SHA1 and HMAC-MD5
  are `vulnerable`.
- Crypto policy and OpenSSL config: `hybrid` when `Groups` include an
  ML-KEM or Kyber group (or a policy name or subpolicy contains `PQ`),
  otherwise `vulnerable` (TLS key exchange is classical).
  `parameter_set.pqc_reason` explains which.

OpenSSL settings recorded on both policy kinds: `min_protocol`,
`max_protocol`, `allowed_protocols` (the TLS versions between them, or
`null` when MinProtocol is unset and OpenSSL defaults apply),
`cipher_string`, `ciphersuites`, `groups`, `signature_algorithms`.
`TLS.`-prefixed keys from crypto-policies are read; `DTLS.` keys are
ignored.

## KMS listing scanner

Implementation: `src/scanners/kms.rs`.

```sh
aws kms list-keys > aws-list.json
for k in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms describe-key --key-id "$k"
done > aws-describe.json
az keyvault key list --vault-name myvault > azure-list.json
az keyvault key show --vault-name myvault --name mykey > azure-show.json
gcloud kms keys list --keyring ring --location loc --format=json > gcp.json
gcloud kms keys versions list --key k --keyring ring --location loc \
  --format=json > gcp-versions.json

boab scan kms aws-list.json aws-describe.json azure-list.json azure-show.json gcp.json
```

Boab does not call any cloud API; you run the export and pass the files.
Each file may hold one JSON document, a JSON array, or several documents
back to back. The provider is detected from the shape; pass
`--provider aws|azure|gcp` to force it. The same key seen in a listing
and a describe/show export is merged. Keys are identified by their full
reference (AWS ARN), so related multi-Region AWS keys, which share a
KeyId, stay separate per region.

GCP omits `primary` for asymmetric keys. `versionTemplate` only describes
future versions, so it is recorded as `template_algorithm` and never
used to classify the key. Without a versions export such a key is
`unknown`; with one, the enabled versions decide (`version_algorithms`),
and the weakest wins.

Recorded per key (`kms_key`, asset type `key`): `provider`, `key_id`,
`key_ref` (AWS ARN, versionless Azure key URI, GCP key resource name),
`key_spec`, `key_usage`, `key_state`, `enabled`, `protection_level`,
`key_manager`, `origin`, `created`, `expires`, `key_version`, `curve`,
`symmetric`, `listing_sources`, and for GCP `template_algorithm` and
`version_algorithms`. `host` is the account scope:
`aws:<account>:<region>`, `azure:<vault>`, or
`gcp:<project>/<location>/<keyRing>`. `location` is `key_ref`.

Metadata only. Descriptions, tags, labels and policies are not recorded.
Azure `key show` includes the public key (`n`, `e`, `x`, `y`); Boab uses
the modulus or curve length to work out the key size and drops the
values.

Key specs map to Boab algorithms: `RSA_2048` and friends to `RSA` with
the size (primitive `pke` for encrypt, decrypt, wrapKey and unwrapKey
usage), `ECC_NIST_P256`, `EC_SIGN_P256_SHA256` and `EC` with `P-256`
to `ECDSA-P256` (or `ECDH-P256` for key agreement), Azure `P-256K` and
AWS `ECC_SECG_P256K1` to `ECDSA-secp256k1`, `ECC_NIST_EDWARDS25519` to
`Ed25519`, `SYMMETRIC_DEFAULT`
and `GOOGLE_SYMMETRIC_ENCRYPTION` to `AES-256-GCM`, `HMAC_*` to
`HMAC-SHA*`, `ML_DSA_*` and `ML_KEM_*` to the matching FIPS 204 and 203
names (`resistant`), and `KEM_XWING` to `X-Wing` (`hybrid`).

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
- Host crypto, keystore and KMS assets: `parameter_set.asset_key`, built
  from stable fields only:
  - `ssh_host_key:<host>:<fingerprint_sha256 or location>`
  - `ssh_alg:<host>:<directive>:<ssh_name>`
  - `crypto_policy:<host>`
  - `openssl_config:<host>:<location>`
  - `keystore:<host>:<location>:<alias>`
  - `kms:<provider>:<key_ref>`

Host crypto, keystore and KMS assets are identified by where they live,
so on a rescan the scanner-owned fields (algorithm, size, status,
`parameter_set`, name) are refreshed from the new finding, for example
when a keystore alias is reissued with a different key.

Promotion is idempotent. Re-running the same scan does not add duplicate
inventory entries and preserves user-set fields on existing assets:
`notes`, `migration_status`, `target_milestone`, `system_id`,
`data_retention_horizon_year`, `description`, `tags`.
