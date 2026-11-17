# Boab v1.1 backlog

Items explicitly deferred from v1, captured here so they are not lost.

## Scanners

- Live KMS scanners for AWS KMS, Azure Key Vault, GCP KMS. (Offline
  import of exported listings ships as `boab scan kms`.)
- Kubernetes secret enumeration (TLS secrets, sealed secrets).
- GPG key inventory, and SSH user keys (`authorized_keys`). (SSH host
  keys and sshd_config ship as `boab scan host`.)

## Vendor registry

- Live fetching of vendor PQC roadmaps (currently strictly offline).
- Vendor entry approval workflow with `last_verified_by`.

## Reporting

- ISM control mapping (specific control IDs per finding category).
- Scoring weight overrides via `.boab/config.toml`.

## Operations

- Daemon and watch mode.
- Multi-machine federation for cross-business-unit rollouts.
- Automatic remediation (e.g. opening PRs against scanned repositories).
