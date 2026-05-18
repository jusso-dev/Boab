# Boab v1.1 backlog

Items explicitly deferred from v1, captured here so they are not lost.

## Scanners

- KMS scanners for AWS KMS, Azure Key Vault, GCP KMS.
- Kubernetes secret enumeration (TLS secrets, sealed secrets).
- SSH and GPG key inventory across hosts.
- JKS native parsing in the certificate store scanner.

## Vendor registry

- Live fetching of vendor PQC roadmaps (currently strictly offline).
- Vendor entry approval workflow with `last_verified_by`.

## Reporting

- HTML report with embedded charts.
- ISM control mapping (specific control IDs per finding category).
- Scoring weight overrides via `.boab/config.toml`.

## Operations

- Daemon and watch mode.
- Multi-machine federation for cross-business-unit rollouts.
- Automatic remediation (e.g. opening PRs against scanned repositories).
