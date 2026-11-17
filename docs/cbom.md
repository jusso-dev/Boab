# CycloneDX 1.6 CBOM output

`boab report --format cbom` writes a CycloneDX 1.6 cryptographic bill of
materials as JSON. The schema reference is at
https://cyclonedx.org/schema/bom-1.6.schema.json.

Boab does not depend on a third-party CycloneDX crate. It builds the BOM
in-tree from the canonical inventory so we can guarantee 1.6 conformance
without tracking an upstream release cadence.

## Top-level shape

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "...",
    "tools": { "components": [ { "type": "application", "name": "boab", "version": "..." } ] }
  },
  "components": [ ... ]
}
```

Each component has `type = "cryptographic-asset"` and a `bom-ref` set to
`boab:<UUID>` matching the Boab asset id.

## Asset mappings

| Boab `AssetType` | CycloneDX `assetType` | Properties block |
| --- | --- | --- |
| `Algorithm` | `algorithm` | `algorithmProperties` (primitive, parameterSetIdentifier, executionEnvironment, implementationPlatform, nistQuantumSecurityLevel) |
| `LibraryDependency` | `algorithm` | as above (treated as an algorithm reference) |
| `Certificate` | `certificate` | `certificateProperties` (subjectName, issuerName, notValidBefore, notValidAfter, signatureAlgorithmRef, certificateFormat = `X.509`) |
| `Key` | `related-crypto-material` | `relatedCryptoMaterialProperties` (type, format, size) |
| `ProtocolEndpoint` | `protocol` | `protocolProperties` (type = `tls`, version, cipherSuites) |

Host crypto, keystore and KMS assets (identified by
`parameter_set.kind`) use the richer mapping in the import contract
below. All other assets keep the mapping above unchanged.

## NIST quantum security levels

Boab sets `nistQuantumSecurityLevel` per asset:

- `0` for vulnerable classical primitives and unknown algorithms.
- `1` for ML-KEM-512, AES-128, symmetric algorithms by name.
- `2` for ML-DSA-44 / Dilithium2.
- `3` for ML-KEM-768, ML-DSA-65, Dilithium3.
- `5` for ML-KEM-1024, ML-DSA-87, Dilithium5.

## GRiCk import contract

This section is the contract GRiCk (and any other importer) can rely on
for host crypto discovery: SSH host keys, sshd algorithm settings, OS
crypto policy, OpenSSL configuration, Java keystore entries and cloud
KMS keys. Field names are exact. Boab writes snake_case enums and writes
absent optional values as `null` in JSON (or omits them in the CBOM).

### Asset kinds

Every new asset has `parameter_set.kind` set to one of these values:

| `parameter_set.kind` | `asset_type` | Produced by | What it is | CycloneDX `assetType` |
| --- | --- | --- | --- | --- |
| `ssh_host_key` | `key` | `boab scan host` | One SSH host key (public key file, or private key file recognised by name) | `related-crypto-material` (`type` = `public-key`) |
| `ssh_config_algorithm` | `algorithm` | `boab scan host` | One algorithm enabled in sshd `HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers` or `MACs` | `algorithm` |
| `os_crypto_policy` | `protocol_endpoint` | `boab scan host` | The RHEL/Fedora system-wide crypto policy | `protocol` (`type` = `other`) |
| `openssl_config` | `protocol_endpoint` | `boab scan host` | One openssl.cnf and its includes | `protocol` (`type` = `tls`) |
| `keystore_entry` | `key` | `boab scan certs` | One alias in a PKCS#12, JKS or JCEKS keystore | `related-crypto-material` (`type` = `private-key`, `public-key` or `secret-key` by `entry_type`) |
| `kms_key` | `key` | `boab scan kms` | One cloud KMS key from an exported listing | `related-crypto-material` (`type` = `secret-key` when `symmetric`, else `private-key`) |

Note: `asset_type` stays within the existing five values (`algorithm`,
`certificate`, `key`, `protocol_endpoint`, `library_dependency`), so
existing importers keep working. Use `parameter_set.kind` to tell the new
kinds apart.

### Fields on every new asset (native JSON)

In `.boab/inventory.json` and in `inventory[]` of
`boab report --format json` (which adds `risk_score`):

| Field | Type | Meaning |
| --- | --- | --- |
| `asset_type` | string | As in the table above |
| `algorithm_name` | string | Canonical algorithm, e.g. `RSA`, `ECDSA-P256`, `Ed25519`, `X25519MLKEM768`, `AES-256-GCM`, `ML-DSA-65`, `crypto-policies:DEFAULT:SHA1`, `OpenSSL MinProtocol TLSv1.2`, `unknown` |
| `primitive` | string or null | `signature`, `key_agreement`, `kem`, `block_cipher`, `stream_cipher`, `mac`, `pke` |
| `pqc_status` | string | `vulnerable`, `hybrid`, `resistant`, `symmetric_ok`, `unknown` |
| `quantum_vulnerable` | bool | `true` for `vulnerable`, `hybrid` and `unknown`. A quantum-vulnerable SSH host key (RSA, ECDSA, Ed25519, DSA) is `true` |
| `name` | string | Display name, unique per asset |
| `risk_score` | object | JSON report only. Scored by the standard rubric; `algorithm_vulnerability` 10 = broken today |
| `parameter_set.kind` | string | Asset kind |
| `parameter_set.host` | string | **Host**: host label for host/keystore assets, account scope for KMS (`aws:<account>:<region>`, `azure:<vault>`, `gcp:<project>/<location>/<keyRing>`) |
| `parameter_set.location` | string | **Location**: path on the scanned host (host/keystore), or the key ARN/URI/resource name (KMS) |
| `parameter_set.target` | string | Same as `location` (existing importers read `target` first) |
| `parameter_set.source_root` | string | Same as `host` |
| `parameter_set.asset_key` | string | Stable identity across scans (see dedup keys in `docs/scanners.md`). Use as the import fingerprint |
| `parameter_set.key_size_bits` | integer, optional | Key size or symmetric strength |

Kind-specific `parameter_set` fields:

| Kind | Fields |
| --- | --- |
| `ssh_host_key` | `ssh_key_type` (e.g. `ssh-rsa`, `ecdsa-sha2-nistp256`), `fingerprint_sha256` (OpenSSH `SHA256:...`, absent when only the private key file was seen), `public_key_available`, `private_key_present`, `certificate` |
| `ssh_config_algorithm` | `directive`, `ssh_name` (as written in the config), `list_modifier` (`replace`, `append`, `prepend`) |
| `os_crypto_policy` | `policy`, `base_policy`, `subpolicies[]`, `backends[]`, `min_protocol`, `max_protocol`, `allowed_protocols[]` or null, `cipher_string`, `ciphersuites[]`, `groups[]`, `signature_algorithms[]`, `pqc_reason` |
| `openssl_config` | `min_protocol`, `max_protocol`, `allowed_protocols[]` or null, `cipher_string`, `ciphersuites[]`, `groups[]`, `signature_algorithms[]`, `config_files[]`, `pqc_reason` |
| `keystore_entry` | `store_type`, `alias`, `entry_type`, `chain_length`, `integrity_verified`, `public_key_algorithm`, `public_key_algorithm_oid`, `signature_algorithm`, `subject`, `issuer`, `not_before_unix`, `not_after_unix`, `certificate_sha256` |
| `kms_key` | `provider` (`aws`, `azure`, `gcp`), `key_id`, `key_ref`, `key_spec`, `key_usage`, `key_state`, `enabled`, `protection_level`, `key_manager`, `origin`, `created`, `expires`, `key_version`, `curve`, `symmetric`, `listing_sources[]` |

Never present: private key bytes, keystore passwords, SSH key comments,
KMS public key components, descriptions, tags or labels.

Scan records for these sources have `scan_type` `host_crypto` (host
scanner) or `kms_listing` (KMS scanner). Keystores stay
`certificate_store`.

### Fields on every new component (CBOM)

Each new asset becomes one component with `type` =
`cryptographic-asset` and `bom-ref` = `boab:<asset id>`, plus:

- `evidence.occurrences[0].location`: the **location** (as above).
- `properties[]`: name/value strings, in this order, absent values
  omitted:

| Property `name` | Value |
| --- | --- |
| `boab:asset_type` | `asset_type` |
| `boab:kind` | `parameter_set.kind` |
| `boab:host` | **Host** |
| `boab:location` | **Location** |
| `boab:algorithm` | `algorithm_name` |
| `boab:pqc_status` | `pqc_status` |
| `boab:quantum_vulnerable` | `true` or `false` |
| `boab:key_size_bits` | decimal string |
| `boab:asset_key` | `parameter_set.asset_key` |
| `boab:provider`, `boab:key_id`, `boab:key_ref`, `boab:key_spec`, `boab:key_usage`, `boab:key_state`, `boab:protection_level`, `boab:key_manager` | KMS fields |
| `boab:alias`, `boab:store_type`, `boab:entry_type`, `boab:subject` | Keystore fields |
| `boab:ssh_key_type`, `boab:fingerprint_sha256` | SSH host key fields |
| `boab:directive`, `boab:ssh_name` | sshd algorithm fields |
| `boab:policy`, `boab:min_protocol`, `boab:max_protocol`, `boab:cipher_string` | Policy and OpenSSL fields |
| `boab:allowed_protocols`, `boab:groups`, `boab:ciphersuites`, `boab:subpolicies` | Comma-joined lists |

`cryptoProperties` by asset type:

- `key`: `relatedCryptoMaterialProperties` with `type`, `id` (KMS
  `key_ref`, SSH `fingerprint_sha256`, keystore `certificate_sha256`),
  `state` (KMS only: `active`, `suspended`, `pre-activation`,
  `deactivated`, `destroyed`), `creationDate` and `expirationDate` (KMS
  dates, keystore certificate validity), `size`, `format` (`OpenSSH`, or
  the keystore type). `oid` is the certificate public key OID for
  keystore entries.
- `algorithm`: `algorithmProperties` as for other algorithms, with
  `nistQuantumSecurityLevel` 0 for vulnerable algorithms.
- `protocol_endpoint`: `protocolProperties` with `type` (`tls` for
  `openssl_config`, `other` for `os_crypto_policy`), `version` (the
  `MinProtocol`, or `unknown`), and `cipherSuites[].name` (TLS 1.3
  ciphersuites, then the OpenSSL `CipherString`).

The new components validate against the full CycloneDX 1.6 schema.

### Mapping guide for importers

- Type: `boab:kind` (or `parameter_set.kind`), with `asset_type` as a
  fallback for older Boab output.
- Host: `boab:host` (or `parameter_set.host`).
- Location: `boab:location`, `evidence.occurrences[0].location`, or
  `parameter_set.location`.
- Identity across imports: `boab:asset_key` (or
  `parameter_set.asset_key`).
- Finding: flag `boab:quantum_vulnerable` = `true` (or
  `risk_score.triage_tier` <= 3 from the JSON report).

### Plan JSON shape

`boab plan generate --milestone 2026|2028|2030` writes
`.boab/plans/<id>.json`, `boab plan show <id>` prints it, and
`boab report --format json` includes every plan in `plans[]`. Shape
(`src/model/plan.rs`):

```json
{
  "id": "9199798a-974e-45ed-8726-65aae3fdcf60",
  "name": "PQC transition plan 2030",
  "milestone": "y2030",
  "generated_at": "2026-11-17T01:09:01.23728Z",
  "items": [
    {
      "id": "2e937f8c-b451-41fd-ba08-57d9ea919ecc",
      "crypto_asset_id": "bedaf286-e7c9-4678-b797-bebc64775ee8",
      "asset_name": "web01.example.internal sshd Ciphers: 3des-cbc",
      "algorithm_name": "3DES",
      "triage_tier": 3,
      "priority": 5.7,
      "target_action": "Plan replacement during the 2029 to 2030 rollout window",
      "target_date": "+002030-09-01T00:00:00.000000000Z",
      "assignee": null,
      "notes": null,
      "status": "pending"
    }
  ]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `id` | UUID string | Stable across `plan regenerate` |
| `name` | string | |
| `milestone` | string | `y2026`, `y2028` or `y2030` (serde names of `TargetMilestone`) |
| `generated_at` | RFC 3339 string | |
| `items[].id` | UUID string | New on every generate or regenerate |
| `items[].crypto_asset_id` | UUID string | The inventory asset `id`; join on this |
| `items[].asset_name`, `items[].algorithm_name` | string | Copied from the asset at generation time |
| `items[].triage_tier` | integer 1 to 4 | 1 = migrate first |
| `items[].priority` | number 0 to 10 | One decimal place |
| `items[].target_action` | string | Recommended action, user-editable |
| `items[].target_date` | string or null | ISO 8601 with a six-digit signed year, e.g. `+002030-09-01T00:00:00.000000000Z` (JavaScript `Date` parses it). Tier 1 is March, 2 June, 3 September, 4 December of the milestone year |
| `items[].assignee`, `items[].notes` | string or null | User-editable |
| `items[].status` | string | `pending`, `in_progress`, `complete`, `deferred`, `not_applicable` |

A plan for milestone M includes assets whose triage tier maps to M or
earlier (tiers 1 and 2 map to 2028, tiers 3 and 4 to 2030), ordered by
priority descending.

## Validation

The repository includes a focused subset of the CycloneDX 1.6 schema at
`tests/fixtures/cyclonedx-1.6.schema.json` and the test
`cbom_report_validates_against_subset_schema` runs in CI on every PR.
For full CycloneDX validation, run any conformant validator (e.g. the
`cyclonedx-cli` validate command) against the BOM Boab produces.
