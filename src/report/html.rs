//! HTML readiness report. A single self-contained file for executives: inline
//! CSS, an inline SVG logo, no scripts, and no external requests, so it opens
//! offline, survives email gateways, and prints cleanly to A4.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use time::format_description::well_known::Rfc3339;

use super::{pqc_status_str, Readiness};
use crate::model::asset::{AssetType, PqcStatus};
use crate::model::plan::PlanItemStatus;
use crate::model::system::{Classification, Criticality};
use crate::workspace::Workspace;

/// Shared with the PowerShell port (`powershell/Boab/Data/report-theme.css`).
pub const THEME_CSS: &str = include_str!("../../data/report-theme.css");

const TOP_ASSETS: usize = 25;

const STATUS_ORDER: [PqcStatus; 5] = [
    PqcStatus::Vulnerable,
    PqcStatus::Unknown,
    PqcStatus::Hybrid,
    PqcStatus::Resistant,
    PqcStatus::SymmetricOk,
];

const MILESTONES: [(u16, &str, &str); 3] = [
    (
        2026,
        "Refined transition plan",
        "Have a refined PQC transition plan in place by the end of 2026.",
    ),
    (
        2028,
        "Implementation begins",
        "Begin migrating priority systems to post-quantum cryptography.",
    ),
    (
        2030,
        "Implementation complete",
        "Retire quantum-vulnerable cryptography across the estate.",
    ),
];

const LOGO_SVG: &str = "<svg class=\"logo\" viewBox=\"0 0 48 48\" aria-hidden=\"true\"><path fill=\"currentColor\" d=\"M17 46c-4.5-8.5-4-17 1.5-23h11c5.5 6 6 14.5 1.5 23z\"/><path fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.4\" stroke-linecap=\"round\" d=\"M20 24c-2.5-5-7-7.5-12-8.5M22.5 23c-.5-6-1-10.5-3.5-15M25.5 23c1-6 3-10 6.5-13.5M28 24c3-4.5 7.5-6.5 12-6.5\"/><circle class=\"leaf\" cx=\"7\" cy=\"15\" r=\"3\"/><circle class=\"leaf\" cx=\"18.5\" cy=\"7\" r=\"3\"/><circle class=\"leaf\" cx=\"32.5\" cy=\"9\" r=\"3\"/><circle class=\"leaf\" cx=\"41\" cy=\"17.5\" r=\"3\"/></svg>";

pub fn write(ws: &Workspace, out: &Path) -> Result<()> {
    let html = render(&Readiness::load(ws)?);
    if let Some(parent) = out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(out, html).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

fn render(data: &Readiness) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let total = data.scored.len();
    let vulnerable = data.vulnerable_count();
    let tier_count = |t: u8| {
        data.scored
            .iter()
            .filter(|(_, s)| s.triage_tier == t)
            .count()
    };
    let tiers = [tier_count(1), tier_count(2), tier_count(3), tier_count(4)];
    let status_counts: Vec<usize> = STATUS_ORDER
        .iter()
        .map(|st| {
            data.scored
                .iter()
                .filter(|(a, _)| a.pqc_status == *st)
                .count()
        })
        .collect();
    let soci = data.systems.iter().filter(|s| s.is_soci).count();
    let covered = MILESTONES
        .iter()
        .filter(|(y, _, _)| data.has_plan_for(*y))
        .count();
    let vendor_unknown = data
        .registry
        .entries
        .iter()
        .filter(|e| e.pqc_status == PqcStatus::Unknown)
        .count();
    let rfc3339 = data.today.format(&Rfc3339).unwrap_or_default();

    let mut h = String::new();
    h.push_str("<!DOCTYPE html>\n<html lang=\"en-AU\">\n<head>\n<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\n");
    let _ = writeln!(h, "<meta name=\"generator\" content=\"Boab {}\">", version);
    h.push_str("<title>PQC Readiness Report | Boab</title>\n<style>\n");
    h.push_str(THEME_CSS);
    h.push_str("</style>\n");
    let marking = protective_marking(data);
    if let Some(m) = marking {
        let _ = writeln!(
            h,
            "<style>@media print {{ @page {{ @top-center {{ content: \"{m}\"; }} @bottom-center {{ content: \"{m}\"; }} }} }}</style>"
        );
    }
    h.push_str("</head>\n<body>\n");
    if let Some(m) = marking {
        let _ = writeln!(h, "<div class=\"marking\">{}</div>", m);
    }

    // Masthead.
    h.push_str("<header class=\"masthead\">\n<div class=\"page\">\n");
    h.push_str(LOGO_SVG);
    h.push('\n');
    h.push_str("<div>\n<p class=\"eyebrow\">Post-quantum cryptography transition</p>\n");
    h.push_str("<h1>PQC Readiness Report</h1>\n");
    let _ = writeln!(
        h,
        "<p class=\"meta\"><span>Generated <time datetime=\"{}\">{}</time></span><span>Boab {}</span><span>ASD milestones 2026, 2028, 2030</span></p>",
        rfc3339,
        human_timestamp(data.today),
        version
    );
    h.push_str("</div>\n</div>\n</header>\n<main class=\"page\">\n");

    // Overall posture and key findings.
    let (posture_class, posture, detail) = posture(total, vulnerable, tiers[0]);
    h.push_str("<section aria-labelledby=\"summary\">\n");
    h.push_str("<h2 id=\"summary\">Executive summary</h2>\n");
    h.push_str("<p class=\"lede\">Position of the inventoried cryptography against the ASD post-quantum transition milestones.</p>\n");
    let _ = writeln!(h, "<div class=\"card posture posture-{}\">", posture_class);
    let _ = writeln!(
        h,
        "<div class=\"posture-badge\"><p class=\"label\">Overall posture</p><p class=\"value\">{}</p><p class=\"detail\">{}</p></div>",
        posture,
        esc(&detail)
    );
    h.push_str("<div class=\"findings\">\n<h3>Key findings</h3>\n<ul>\n");
    for finding in key_findings(data, total, vulnerable, &tiers, vendor_unknown) {
        let _ = writeln!(h, "<li>{}</li>", esc(&finding));
    }
    h.push_str("</ul>\n</div>\n</div>\n");

    // Headline numbers.
    h.push_str("<div class=\"kpis\">\n");
    kpi(
        &mut h,
        "",
        "Cryptographic assets",
        &group(total),
        "Deduplicated inventory",
    );
    kpi(
        &mut h,
        if vulnerable > 0 {
            " kpi-critical"
        } else {
            " kpi-good"
        },
        "At-risk assets",
        &group(vulnerable),
        &format!(
            "{}% vulnerable or unknown",
            percent_tenths(vulnerable, total)
        ),
    );
    kpi(
        &mut h,
        if tiers[0] > 0 {
            " kpi-critical"
        } else {
            " kpi-good"
        },
        "Tier 1 (urgent)",
        &group(tiers[0]),
        "Migrate inside the 2028 window",
    );
    kpi(
        &mut h,
        "",
        "Systems in scope",
        &group(data.systems.len()),
        &format!("{} SOCI-regulated", group(soci)),
    );
    kpi(
        &mut h,
        if covered == 3 {
            " kpi-good"
        } else {
            " kpi-serious"
        },
        "Transition plans",
        &group(data.plans.len()),
        &format!("{} of 3 milestones covered", covered),
    );
    h.push_str("</div>\n</section>\n");

    // ASD milestones.
    h.push_str("<section aria-labelledby=\"milestones\">\n");
    h.push_str("<h2 id=\"milestones\">ASD transition milestones</h2>\n");
    h.push_str(
        "<p class=\"lede\">Whether a Boab transition plan is on file for each milestone.</p>\n",
    );
    h.push_str("<div class=\"card timeline\">\n");
    for (year, title, desc) in MILESTONES {
        let done = data.has_plan_for(year);
        let _ = writeln!(
            h,
            "<div class=\"milestone {}\"><p class=\"year\">{}</p><p class=\"title\">{}</p><p class=\"desc\">{}</p>{}</div>",
            if done { "done" } else { "open" },
            year,
            title,
            desc,
            if done {
                pill("s-resistant", "Plan drafted")
            } else {
                pill("s-unknown", "Plan outstanding")
            }
        );
    }
    h.push_str("</div>\n</section>\n");

    // Distributions.
    h.push_str("<section aria-labelledby=\"distribution\">\n");
    h.push_str("<h2 id=\"distribution\">Where the exposure sits</h2>\n");
    h.push_str(
        "<p class=\"lede\">Inventory broken down by post-quantum status and by triage tier.</p>\n",
    );
    h.push_str(
        "<div class=\"charts\">\n<div class=\"card chart\">\n<h3>Assets by PQC status</h3>\n",
    );
    for (st, count) in STATUS_ORDER.iter().zip(&status_counts) {
        bar_row(
            &mut h,
            &format!("s-{}", pqc_status_str(*st)),
            status_label(*st),
            *count,
            total,
        );
    }
    h.push_str("</div>\n<div class=\"card chart\">\n<h3>Assets by triage tier</h3>\n");
    for (i, count) in tiers.iter().enumerate() {
        bar_row(
            &mut h,
            &format!("t-{}", i + 1),
            tier_label(i as u8 + 1),
            *count,
            total,
        );
    }
    h.push_str("</div>\n</div>\n</section>\n");

    // Priority assets.
    h.push_str("<section aria-labelledby=\"priority\">\n");
    h.push_str("<h2 id=\"priority\">Highest-priority assets</h2>\n");
    h.push_str("<p class=\"lede\">Ranked by the Boab priority score (0 to 10). Start migration work at the top of this list.</p>\n");
    if total == 0 {
        h.push_str(
            "<div class=\"card\"><p class=\"empty\">No assets in the inventory yet.</p></div>\n",
        );
    } else {
        h.push_str("<div class=\"card table-card\">\n<table>\n<thead><tr><th class=\"num\">#</th><th>Asset</th><th>Algorithm</th><th>PQC status</th><th>Priority</th><th>Tier</th><th>Recommended action</th></tr></thead>\n<tbody>\n");
        for (i, (asset, score)) in data.scored.iter().take(TOP_ASSETS).enumerate() {
            let tenths = (score.priority * 10.0).round() as i64;
            let _ = writeln!(
                h,
                "<tr><td class=\"num\">{}</td><td class=\"name\">{}<span class=\"kind\">{}</span></td><td class=\"algo\"><code>{}</code></td><td>{}</td><td><div class=\"score\"><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{}%\"></div></div><b>{:.1}</b></div></td><td><span class=\"tier t-{}\">{}</span></td><td>{}</td></tr>",
                i + 1,
                esc(&asset.name),
                asset_type_label(asset.asset_type),
                esc(&asset.algorithm_name),
                pill(
                    &format!("s-{}", pqc_status_str(asset.pqc_status)),
                    status_label(asset.pqc_status)
                ),
                tenths.clamp(0, 100),
                score.priority,
                score.triage_tier,
                score.triage_tier,
                esc(&score.recommended_action)
            );
        }
        h.push_str("</tbody>\n</table>\n</div>\n");
        if total > TOP_ASSETS {
            let _ = writeln!(
                h,
                "<p class=\"note\">Showing the top {} of {} assets. The full inventory is in the JSON and CycloneDX reports.</p>",
                TOP_ASSETS,
                group(total)
            );
        }
    }
    h.push_str("</section>\n");

    // Systems.
    h.push_str("<section aria-labelledby=\"systems\">\n");
    h.push_str("<h2 id=\"systems\">Systems in scope</h2>\n");
    h.push_str("<p class=\"lede\">Business systems registered in the workspace and the cryptographic assets linked to each.</p>\n");
    let unassigned: Vec<_> = data
        .scored
        .iter()
        .filter(|(a, _)| {
            a.system_id
                .is_none_or(|id| !data.systems.iter().any(|s| s.id == id))
        })
        .collect();
    if data.systems.is_empty() && unassigned.is_empty() {
        h.push_str("<div class=\"card\"><p class=\"empty\">No systems registered yet.</p></div>\n");
    } else {
        h.push_str("<div class=\"card table-card\">\n<table>\n<thead><tr><th>System</th><th>Classification</th><th>Criticality</th><th>SOCI</th><th class=\"num\">Data lifetime</th><th class=\"num\">Assets</th><th class=\"num\">At risk</th></tr></thead>\n<tbody>\n");
        for s in &data.systems {
            let linked: Vec<_> = data
                .scored
                .iter()
                .filter(|(a, _)| a.system_id == Some(s.id))
                .collect();
            let vuln = linked
                .iter()
                .filter(|(a, _)| matches!(a.pqc_status, PqcStatus::Vulnerable | PqcStatus::Unknown))
                .count();
            let _ = writeln!(
                h,
                "<tr><td class=\"name\">{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                esc(&s.name),
                classification_label(s.classification),
                criticality_label(s.criticality),
                if s.is_soci { "Yes" } else { "No" },
                s.expected_data_lifetime_years
                    .map(|y| format!("{} years", y))
                    .unwrap_or_else(|| "-".to_string()),
                group(linked.len()),
                group(vuln)
            );
        }
        if !unassigned.is_empty() {
            let vuln = unassigned
                .iter()
                .filter(|(a, _)| matches!(a.pqc_status, PqcStatus::Vulnerable | PqcStatus::Unknown))
                .count();
            let _ = writeln!(
                h,
                "<tr><td class=\"name\">Not linked to a system</td><td>-</td><td>-</td><td>-</td><td class=\"num\">-</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                group(unassigned.len()),
                group(vuln)
            );
        }
        h.push_str("</tbody>\n</table>\n</div>\n");
    }
    h.push_str("</section>\n");

    // Plans.
    h.push_str("<section aria-labelledby=\"plans\">\n");
    h.push_str("<h2 id=\"plans\">Transition plans on file</h2>\n");
    h.push_str(
        "<p class=\"lede\">Transition plans generated by Boab and progress against each.</p>\n",
    );
    if data.plans.is_empty() {
        h.push_str("<div class=\"card\"><p class=\"empty\">No plans generated yet.</p></div>\n");
    } else {
        h.push_str("<div class=\"card table-card\">\n<table>\n<thead><tr><th>Plan</th><th class=\"num\">Milestone</th><th class=\"num\">Items</th><th>Progress</th><th>Generated</th></tr></thead>\n<tbody>\n");
        for p in &data.plans {
            let items = p.items.len();
            let complete = p
                .items
                .iter()
                .filter(|i| i.status == PlanItemStatus::Complete)
                .count();
            let generated = p.generated_at.format(&Rfc3339).unwrap_or_default();
            let _ = writeln!(
                h,
                "<tr><td class=\"name\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td><div class=\"progress\"><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{}%\"></div></div><span>{} of {} complete</span></div></td><td><time datetime=\"{}\">{}</time></td></tr>",
                esc(&p.name),
                p.milestone.year(),
                group(items),
                percent_tenths(complete, items),
                group(complete),
                group(items),
                generated,
                generated.get(..10).unwrap_or_default()
            );
        }
        h.push_str("</tbody>\n</table>\n</div>\n");
    }
    h.push_str("</section>\n");

    // Vendors.
    h.push_str("<section aria-labelledby=\"vendors\">\n");
    h.push_str("<h2 id=\"vendors\">Vendor PQC dependencies</h2>\n");
    h.push_str("<p class=\"lede\">Published post-quantum positions of the vendors tracked in the Boab registry, including workspace overrides.</p>\n");
    if data.registry.entries.is_empty() {
        h.push_str("<div class=\"card\"><p class=\"empty\">No vendors tracked.</p></div>\n");
    } else {
        h.push_str("<div class=\"card table-card\">\n<table>\n<thead><tr><th>Vendor</th><th>Product</th><th>PQC status</th><th>Target</th><th>Source</th></tr></thead>\n<tbody>\n");
        for e in &data.registry.entries {
            let _ = writeln!(
                h,
                "<tr><td class=\"name\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&e.vendor),
                esc(&e.product),
                pill(
                    &format!("s-{}", pqc_status_str(e.pqc_status)),
                    status_label(e.pqc_status)
                ),
                esc(e.target_date.as_deref().unwrap_or("-")),
                source_link(e.source_url.as_deref())
            );
        }
        h.push_str("</tbody>\n</table>\n</div>\n");
    }
    h.push_str("</section>\n");

    // Methodology.
    h.push_str("<section aria-labelledby=\"method\">\n");
    h.push_str("<h2 id=\"method\">Methodology</h2>\n");
    h.push_str("<div class=\"card method\">\n");
    h.push_str("<p>Boab inventories cryptography in source code, TLS endpoints and certificate stores, deduplicates the findings and scores each asset on five axes aligned to the ASD LATICE approach.</p>\n");
    h.push_str("<p><code class=\"formula\">priority = round(algo_vuln &times; 0.30 + hndl &times; 0.30 + data_sens &times; 0.15 + sys_crit &times; 0.15 + mig_diff &times; 0.10, 1)</code></p>\n");
    h.push_str("<p><strong>Tier 1</strong> assets must be migrated inside the 2028 milestone window. <strong>Tier 2</strong> fits inside the 2028 milestone but is harder to migrate. <strong>Tier 3</strong> belongs in the 2029 to 2030 rollout window. <strong>Tier 4</strong> needs monitoring only.</p>\n");
    h.push_str("<p><strong>At-risk</strong> assets use algorithms a cryptographically relevant quantum computer is expected to break (RSA, ECDSA, ECDH, classic Diffie-Hellman, and broken legacy primitives), or have a status Boab could not determine. Data protected by them today can be harvested now and decrypted later.</p>\n");
    h.push_str("<p>Refer to the ASD Information Security Manual for control mappings. Boab does not map findings to specific ISM control IDs.</p>\n");
    h.push_str("</div>\n</section>\n");

    let _ = writeln!(
        h,
        "<footer><p>Generated by Boab {} at {}. This report is self-contained and makes no network requests.</p><p>The protective marking shown is the highest classification of the systems in scope. Confirm it before release.</p></footer>",
        version, rfc3339
    );
    h.push_str("</main>\n");
    if let Some(m) = marking {
        let _ = writeln!(h, "<div class=\"marking\">{}</div>", m);
    }
    h.push_str("</body>\n</html>\n");
    h
}

fn posture(total: usize, vulnerable: usize, tier1: usize) -> (&'static str, &'static str, String) {
    if total == 0 {
        (
            "neutral",
            "Not yet assessed",
            "No cryptographic assets are in the inventory yet. Run the codebase, TLS and certificate scanners to build it.".to_string(),
        )
    } else if tier1 > 0 {
        (
            "critical",
            "Action required",
            format!(
                "{} must be migrated inside the 2028 milestone window.",
                count_noun(tier1, "asset", "assets")
            ),
        )
    } else if vulnerable > 0 {
        (
            "serious",
            "At risk",
            format!(
                "{} of {} assets rely on cryptography a quantum computer is expected to break, or have an unknown status.",
                group(vulnerable),
                group(total)
            ),
        )
    } else {
        (
            "good",
            "No exposure found",
            "No quantum-vulnerable cryptography was found in the assets inventoried so far. Keep scan coverage and transition plans current.".to_string(),
        )
    }
}

fn key_findings(
    data: &Readiness,
    total: usize,
    vulnerable: usize,
    tiers: &[usize; 4],
    vendor_unknown: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    if total > 0 {
        out.push(format!(
            "{} of {} cryptographic assets ({}%) are quantum-vulnerable or have an unknown status.",
            group(vulnerable),
            group(total),
            percent_tenths(vulnerable, total)
        ));
        if tiers[0] + tiers[1] > 0 {
            out.push(format!(
                "{} in tier 1 and {} in tier 2 need migration inside the 2028 milestone window.",
                group(tiers[0]),
                group(tiers[1])
            ));
        } else {
            out.push(
                "No inventoried assets fall in tiers 1 or 2, so none must be migrated inside the 2028 window."
                    .to_string(),
            );
        }
    } else {
        out.push("The cryptographic inventory is empty.".to_string());
    }
    let missing: Vec<String> = MILESTONES
        .iter()
        .filter(|(y, _, _)| !data.has_plan_for(*y))
        .map(|(y, _, _)| y.to_string())
        .collect();
    if missing.is_empty() {
        out.push("Transition plans are on file for all three ASD milestones.".to_string());
    } else {
        out.push(format!(
            "No transition plan is on file for the {} {}.",
            join_and(&missing),
            if missing.len() == 1 {
                "milestone"
            } else {
                "milestones"
            }
        ));
    }
    let vendors = data.registry.entries.len();
    if vendors > 0 {
        out.push(format!(
            "{} of {} tracked vendor products have not published a post-quantum position.",
            group(vendor_unknown),
            group(vendors)
        ));
    }
    let soci = data.systems.iter().filter(|s| s.is_soci).count();
    if soci > 0 {
        out.push(format!(
            "{} in scope {} regulated under the SOCI Act.",
            count_noun(soci, "system", "systems"),
            if soci == 1 { "is" } else { "are" }
        ));
    }
    out
}

/// The highest classification of the systems in scope, used as the report's
/// protective marking. `None` when no systems are registered.
fn protective_marking(data: &Readiness) -> Option<&'static str> {
    data.systems
        .iter()
        .map(|s| s.classification)
        .max_by_key(|c| classification_rank(*c))
        .map(classification_label)
}

fn classification_rank(c: Classification) -> u8 {
    match c {
        Classification::Unofficial => 0,
        Classification::Official => 1,
        Classification::OfficialSensitive => 2,
        Classification::Protected => 3,
        Classification::Secret => 4,
        Classification::TopSecret => 5,
    }
}

fn kpi(h: &mut String, class: &str, label: &str, value: &str, sub: &str) {
    let _ = writeln!(
        h,
        "<div class=\"kpi{}\"><p class=\"label\">{}</p><p class=\"value\">{}</p><p class=\"sub\">{}</p></div>",
        class, label, value, sub
    );
}

fn bar_row(h: &mut String, class: &str, label: &str, count: usize, total: usize) {
    let pct = percent_tenths(count, total);
    let _ = writeln!(
        h,
        "<div class=\"bar-row\" title=\"{}: {} ({}%)\"><span class=\"bar-label\"><span class=\"swatch {}\"></span>{}</span><div class=\"bar-track\"><div class=\"bar-fill {}{}\" style=\"width:{}%\"></div></div><span class=\"bar-value\"><strong>{}</strong> ({}%)</span></div>",
        label,
        group(count),
        pct,
        class,
        label,
        class,
        if count > 0 { " nonzero" } else { "" },
        pct,
        group(count),
        pct
    );
}

fn pill(class: &str, label: &str) -> String {
    format!(
        "<span class=\"pill\"><span class=\"swatch {}\"></span>{}</span>",
        class, label
    )
}

fn source_link(url: Option<&str>) -> String {
    match url {
        Some(u) if u.starts_with("https://") || u.starts_with("http://") => format!(
            "<a href=\"{}\" rel=\"noopener noreferrer\">Vendor statement</a>",
            esc(u)
        ),
        Some(u) => esc(u),
        None => "-".to_string(),
    }
}

/// `count * 100 / total` rounded half up to one decimal place using integer
/// arithmetic, so the Rust and PowerShell reports agree byte for byte.
fn percent_tenths(count: usize, total: usize) -> String {
    if total == 0 {
        return "0.0".to_string();
    }
    let per_mille = (count * 2000 + total) / (2 * total);
    format!("{}.{}", per_mille / 10, per_mille % 10)
}

/// Thousands separators, for example `12,345`.
fn group(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn count_noun(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", group(n), if n == 1 { one } else { many })
}

fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {}", init.join(", "), last),
    }
}

fn human_timestamp(t: time::OffsetDateTime) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    format!(
        "{} {} {}, {:02}:{:02} UTC",
        t.day(),
        MONTHS[usize::from(u8::from(t.month())) - 1],
        t.year(),
        t.hour(),
        t.minute()
    )
}

fn status_label(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "Quantum-vulnerable",
        PqcStatus::Unknown => "Unknown",
        PqcStatus::Hybrid => "PQ/T hybrid",
        PqcStatus::Resistant => "Quantum-resistant",
        PqcStatus::SymmetricOk => "Symmetric (adequate)",
    }
}

fn tier_label(tier: u8) -> &'static str {
    match tier {
        1 => "Tier 1: by 2028",
        2 => "Tier 2: 2028 window",
        3 => "Tier 3: 2029 to 2030",
        _ => "Tier 4: monitor",
    }
}

fn asset_type_label(t: AssetType) -> &'static str {
    match t {
        AssetType::Algorithm => "Algorithm",
        AssetType::Certificate => "Certificate",
        AssetType::Key => "Key",
        AssetType::ProtocolEndpoint => "TLS endpoint",
        AssetType::LibraryDependency => "Library",
    }
}

fn classification_label(c: Classification) -> &'static str {
    match c {
        Classification::Unofficial => "UNOFFICIAL",
        Classification::Official => "OFFICIAL",
        Classification::OfficialSensitive => "OFFICIAL: Sensitive",
        Classification::Protected => "PROTECTED",
        Classification::Secret => "SECRET",
        Classification::TopSecret => "TOP SECRET",
    }
}

fn criticality_label(c: Criticality) -> &'static str {
    match c {
        Criticality::Low => "Low",
        Criticality::Standard => "Standard",
        Criticality::Essential => "Essential",
        Criticality::MissionCritical => "Mission critical",
    }
}

/// Escape text for HTML element content and double-quoted attributes.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            esc("<a href=\"x\">O'Neil & co</a>"),
            "&lt;a href=&quot;x&quot;&gt;O&#39;Neil &amp; co&lt;/a&gt;"
        );
    }

    #[test]
    fn percent_rounds_half_up_to_tenths() {
        assert_eq!(percent_tenths(0, 0), "0.0");
        assert_eq!(percent_tenths(15, 18), "83.3");
        assert_eq!(percent_tenths(2, 3), "66.7");
        assert_eq!(percent_tenths(1, 2000), "0.1");
        assert_eq!(percent_tenths(1, 2001), "0.0");
        assert_eq!(percent_tenths(18, 18), "100.0");
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(1234567), "1,234,567");
    }

    #[test]
    fn percent_ties_round_up_like_the_bars() {
        // 1/16 = 6.25%: every HTML percentage must show 6.3, never 6.2.
        assert_eq!(percent_tenths(1, 16), "6.3");
        assert_eq!(percent_tenths(3, 16), "18.8");
    }

    #[test]
    fn human_timestamp_is_utc_and_readable() {
        let t = time::macros::datetime!(2026-03-05 07:04:59 UTC);
        assert_eq!(human_timestamp(t), "5 March 2026, 07:04 UTC");
    }

    #[test]
    fn joins_with_and() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(join_and(&v(&["2026"])), "2026");
        assert_eq!(join_and(&v(&["2026", "2028"])), "2026 and 2028");
        assert_eq!(
            join_and(&v(&["2026", "2028", "2030"])),
            "2026, 2028 and 2030"
        );
    }

    #[test]
    fn non_http_sources_are_not_links() {
        assert_eq!(source_link(None), "-");
        assert_eq!(
            source_link(Some("javascript:alert(1)")),
            "javascript:alert(1)"
        );
        assert!(source_link(Some("https://example.com/?a=1&b=2")).contains("a=1&amp;b=2"));
    }
}
