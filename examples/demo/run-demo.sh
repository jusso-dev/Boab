#!/usr/bin/env bash
#
# Reproduce the bundled Boab demo end-to-end.
#
# Generates a small set of intentionally-weak local certs, scans them
# alongside a tiny demo codebase, hits a handful of public badssl.com
# endpoints, then emits JSON / CBOM / Markdown readiness reports under
# ./reports/.
#
# Prereqs: OpenSSL 3.x, a built `boab` binary on PATH (or pass it as $1).

set -euo pipefail

BOAB="${1:-boab}"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DEMO_DIR"

echo "[1/6] init workspace"
"$BOAB" init >/dev/null || true

echo "[2/6] add demo system"
"$BOAB" system add \
  --name "Demo Payments" \
  --classification protected \
  --criticality mission_critical \
  --soci \
  --lifetime-years 25 >/dev/null

echo "[3/6] generate weak certificates under ./certs/"
mkdir -p certs
cd certs

# RSA-1024 with SHA-1 signature
openssl req -x509 -newkey rsa:1024 -keyout rsa1024.key -out rsa1024.crt \
  -sha1 -days 365 -nodes \
  -subj "/CN=weak-rsa1024.example/O=Boab Demo/C=AU" 2>/dev/null

# RSA-2048
openssl req -x509 -newkey rsa:2048 -keyout rsa2048.key -out rsa2048.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=rsa2048.example/O=Boab Demo/C=AU" 2>/dev/null

# RSA-4096 with 20-year validity (harvest-now-decrypt-later risk)
openssl req -x509 -newkey rsa:4096 -keyout rsa4096.key -out rsa4096.crt \
  -sha256 -days 7300 -nodes \
  -subj "/CN=long-lived-rsa4096.example/O=Boab Demo/C=AU" 2>/dev/null

# ECDSA P-256
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa-p256.key
openssl req -x509 -new -key ecdsa-p256.key -out ecdsa-p256.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=ecdsa-p256.example/O=Boab Demo/C=AU" 2>/dev/null

# Pre-expired cert
openssl req -x509 -newkey rsa:2048 -keyout expired.key -out expired.crt \
  -sha256 -nodes \
  -not_before 20240101000000Z -not_after 20240601000000Z \
  -subj "/CN=expired.example/O=Boab Demo/C=AU" 2>/dev/null

cd ..

echo "[4/6] scan TLS endpoints (badssl.com)"
"$BOAB" scan tls \
  expired.badssl.com:443 \
  self-signed.badssl.com:443 \
  rsa2048.badssl.com:443 \
  rsa4096.badssl.com:443 \
  sha1-intermediate.badssl.com:443 \
  tls-v1-0.badssl.com:1010 \
  tls-v1-1.badssl.com:1011 \
  badssl.com:443

echo "[5/6] scan certs + demo codebase"
"$BOAB" scan certs ./certs
"$BOAB" scan codebase ./app

echo "[6/6] generate plan + reports"
"$BOAB" plan generate --milestone 2030 --name "Demo rollout" >/dev/null
mkdir -p reports
"$BOAB" report --format json --output reports/inventory.json
"$BOAB" report --format cbom --output reports/cbom.cdx.json
"$BOAB" report --format md   --output reports/readiness.md

"$BOAB" inventory list | head -60 > inventory.txt

echo
echo "Done. Outputs:"
echo "  reports/inventory.json   - native Boab schema"
echo "  reports/cbom.cdx.json    - CycloneDX 1.6 CBOM"
echo "  reports/readiness.md     - board-ready Markdown"
echo "  inventory.txt            - inventory table snippet"
