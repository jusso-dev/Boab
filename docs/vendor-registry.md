# Vendor registry refresh guide

Boab bundles a vendor PQC roadmap registry at
`data/vendor-pqc-registry.json`. It is compiled into the binary via
`include_str!`. There is no runtime fetch.

Customer overrides live at `.boab/vendor-overrides.json` and merge on top
of the bundled file by `(vendor, product)`. Use `boab vendor add` to add
or override entries.

## Refresh process

1. Identify the upstream source for the vendor and product (a public
   roadmap page, a documentation note, or a public commitment). Boab does
   not accept entries without a source URL or a `source_note` explaining
   the gap.
2. Edit `data/vendor-pqc-registry.json` and add the entry. Required
   fields:
   - `vendor`: vendor's display name.
   - `product`: product or service line.
   - `pqc_status`: one of `vulnerable`, `hybrid`, `resistant`,
     `symmetric_ok`, `unknown`.
   - `target_date`: free-text. Use `null` if not committed.
   - `source_url`: full URL. `null` only if no public source exists.
   - `source_note`: short note explaining the entry. Required when
     `source_url` is `null`.
   - `last_verified_at`: ISO-8601 timestamp of when the entry was last
     verified, or `null` for a fresh entry.
3. Bump the package version in `Cargo.toml` and ship a release.

## Reviewing entries

Reviewers should:

- Confirm the URL still points to a vendor page that says what the entry
  claims.
- Bump `last_verified_at` to today.
- Convert `unknown` to `hybrid` or `resistant` only when there is a
  public commitment, not a private briefing.

## Australian context

The bundled registry is biased toward products that Australian
organisations encounter inside ASD-aligned ICT estates. Suggestions for
additions, particularly Australian-developed products, are welcome via
pull request.
