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

## NIST quantum security levels

Boab sets `nistQuantumSecurityLevel` per asset:

- `0` for vulnerable classical primitives and unknown algorithms.
- `1` for ML-KEM-512, AES-128, symmetric algorithms by name.
- `2` for ML-DSA-44 / Dilithium2.
- `3` for ML-KEM-768, ML-DSA-65, Dilithium3.
- `5` for ML-KEM-1024, ML-DSA-87, Dilithium5.

## Validation

The repository includes a focused subset of the CycloneDX 1.6 schema at
`tests/fixtures/cyclonedx-1.6.schema.json` and the test
`cbom_report_validates_against_subset_schema` runs in CI on every PR.
For full CycloneDX validation, run any conformant validator (e.g. the
`cyclonedx-cli` validate command) against the BOM Boab produces.
