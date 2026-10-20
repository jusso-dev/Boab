# Pushing a CBOM to an endpoint

`boab push` uploads a CycloneDX CBOM to an HTTPS endpoint you configure, so a
scan run in CI or on a schedule can reach your evidence or collection system
without copying files around.

Pushing is opt-in. Boab sends nothing unless a push URL is set, it sends only
to that URL, and there is no telemetry. Without a URL, every other command
behaves exactly as before and Boab stays fully usable offline.

## Usage

```sh
boab report --format cbom                      # writes .boab/reports/bom.cdx.json
export BOAB_PUSH_URL=https://collector.example.org/api/cbom
export BOAB_PUSH_TOKEN=...                     # from your CI secret store
boab push                                      # uploads .boab/reports/bom.cdx.json
```

Or write and push in one step:

```sh
boab report --format cbom --push
```

`--push` is required on `report`. Setting `BOAB_PUSH_URL` alone never
triggers an upload.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--url` | `BOAB_PUSH_URL` | none | Destination. Must be `https://` unless `--insecure`. |
| `--token` | `BOAB_PUSH_TOKEN` | none | Sent as `Authorization: Bearer <token>`. Prefer the environment variable so the token stays out of shell history and process listings. |
| `--header key=value` | | | Extra request header. Repeatable. Cannot override `Authorization`, `Content-Type`, `Content-Length`, `Host`, `Connection` or `Transfer-Encoding`. |
| `--run-id` | `BOAB_PUSH_RUN_ID` | none | Sent as `X-Boab-Run-Id`, e.g. your CI run number. |
| `--file`, `-f` | | `.boab/reports/bom.cdx.json` | CBOM to upload. `-` reads stdin. |
| `--insecure` | | off | Allow plain `http://`, for local testing only. |
| `--connect-timeout-seconds` | | 10 | Time allowed to connect and complete the TLS handshake. |
| `--push-timeout-seconds` | | 60 | Time allowed for each attempt, from connect to full response. |
| `--retries` | | 3 | Retries after a network error, timeout or 5xx response (0-10). |
| `--retry-delay-ms` | | 1000 | Delay before the first retry; doubles on each retry. |

The token is never printed, logged or shown in `--verbose` output or `--help`.
If a server echoes it back in an error body, Boab replaces it with
`[REDACTED]` before printing.

## The request

```http
POST /api/cbom HTTP/1.1
Host: collector.example.org
Content-Type: application/vnd.cyclonedx+json; version=1.6
Authorization: Bearer <token>
Idempotency-Key: 6f1d3c1e-6d1b-4f2e-9c55-0d4a8b8b6c1f
X-Boab-Run-Id: <run id, if set>
Accept: application/json
User-Agent: boab/<version>

<CBOM JSON>
```

- `version=` is taken from the CBOM's `specVersion`. Boab checks that the file
  is CycloneDX JSON before sending anything.
- `Idempotency-Key` is the same for every retry of one push, so a receiver can
  safely drop a duplicate when an attempt succeeded but its response was lost.
- TLS uses the bundled Mozilla root store (`webpki-roots`), the same as the
  TLS scanner.

## Responses and exit codes

| Response | Behaviour | Exit code |
| --- | --- | --- |
| 2xx | Prints the status and the request id from `X-Request-Id`, `Request-Id` or `X-Correlation-Id`, or a `requestId` field in a JSON body | 0 |
| 4xx | No retry. Prints the status and the response body (up to 2 KB) | 1 |
| 5xx, timeout, network error | Retried with backoff, then prints the last error | 1 |

```text
$ boab push --run-id 1234
pushed CBOM: HTTP 201 Created, request id 0b9c6d0e-2f53-4a43-9a8f-3f0c1b2d7e11
```

## CI example (GitHub Actions)

```yaml
name: CBOM
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 18 * * 1"   # weekly, so the inventory stays current

jobs:
  cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Install Boab
        run: cargo install --git https://github.com/jusso-dev/boab --locked
      - name: Scan and push
        env:
          BOAB_PUSH_URL: ${{ vars.CBOM_PUSH_URL }}
          BOAB_PUSH_TOKEN: ${{ secrets.CBOM_PUSH_TOKEN }}
          BOAB_PUSH_RUN_ID: ${{ github.repository }}#${{ github.run_number }}
        run: |
          boab init
          boab scan codebase .
          boab report --format cbom --push
      - uses: actions/upload-artifact@v4
        with:
          name: cbom
          path: .boab/reports/bom.cdx.json
```

When `BOAB_PUSH_URL` is empty (for example on forks without the variable),
`boab report --format cbom --push` fails with `no push URL configured`. Drop
`--push` from the job if you only want the artefact.

## Scheduled run (cron)

```sh
# /etc/cron.d/boab: rescan certificates and TLS endpoints nightly and push
30 2 * * * boab cd /srv/boab && . ./push.env && boab scan certs /etc/pki && boab scan tls api.internal:443 && boab report --format cbom --push --run-id "nightly-$(date +\%F)"
```

Keep `push.env` (with `BOAB_PUSH_URL` and `BOAB_PUSH_TOKEN`) readable only by
the account that runs Boab.

## Testing locally

Point Boab at a local listener with `--insecure`:

```sh
boab push --url http://127.0.0.1:8080/cbom --insecure --token test-token
```
