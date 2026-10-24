//! HTML readiness report. A single self-contained page for executives and
//! boards: inline CSS and SVG, no external resources, no network requests.
//!
//! The PowerShell port (`powershell/Boab/Private/HtmlReport.ps1`) produces the
//! same bytes, so keep the two in step. Output is ASCII apart from user data:
//! typographic characters are written as HTML entities.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::model::asset::{AssetType, CryptoAsset, PqcStatus};
use crate::model::plan::PlanItemStatus;
use crate::model::scan::ScanType;
use crate::model::score::RiskScore;
use crate::model::system::{Classification, Criticality, System};
use crate::scoring;
use crate::storage;
use crate::workspace::Workspace;

/// Number of assets shown in the "Highest-priority assets" table.
const TOP_ASSETS: usize = 10;

/// sha256 of [`PRINT_SCRIPT`], allowed by the page's Content-Security-Policy.
const PRINT_SCRIPT_HASH: &str = "sha256-YBT/WzGBpdvp2oDaNuOBJuaAuy6y0df6zOX2949BH/4=";

/// Expands collapsed appendices when the report is printed or saved as PDF.
const PRINT_SCRIPT: &str = "window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true;});});";

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

/// Status order used by the exposure bar, legend and inventory counts.
const STATUS_ORDER: [PqcStatus; 5] = [
    PqcStatus::Vulnerable,
    PqcStatus::Unknown,
    PqcStatus::Hybrid,
    PqcStatus::Resistant,
    PqcStatus::SymmetricOk,
];

pub fn write(ws: &Workspace, out: &Path) -> Result<()> {
    let html = render(ws)?;
    if let Some(parent) = out.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(out, html).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

/// Render the report for `ws` as a complete HTML document.
pub fn render(ws: &Workspace) -> Result<String> {
    let systems = storage::load_systems(ws)?;
    let inventory = storage::load_inventory(ws)?;
    let plans = storage::list_plans(ws)?;
    let scans = storage::list_scans(ws)?;
    let registry = crate::vendor::load_merged(ws)?;
    let today = OffsetDateTime::now_utc();

    let mut scored: Vec<(CryptoAsset, RiskScore)> = inventory
        .into_iter()
        .map(|a| {
            let sys = find_system(&systems, &a);
            let s = scoring::score_asset(&a, sys, today);
            (a, s)
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.priority
            .partial_cmp(&a.1.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Headline figures ---------------------------------------------------------
    let total = scored.len();
    let mut status_counts = [0usize; 5];
    let mut tier_counts = [0usize; 4];
    let mut broken = 0usize;
    let mut unassigned = 0usize;
    for (a, s) in &scored {
        status_counts[status_index(a.pqc_status)] += 1;
        tier_counts[(s.triage_tier.clamp(1, 4) - 1) as usize] += 1;
        if s.algorithm_vulnerability >= 10 {
            broken += 1;
        }
        if find_system(&systems, a).is_none() {
            unassigned += 1;
        }
    }
    let unknown = status_counts[1];
    let exposed = status_counts[0] + unknown;
    let exposed_pct = if total == 0 {
        0.0
    } else {
        (exposed as f32) * 100.0 / (total as f32)
    };
    let (t1, t2, t3) = (tier_counts[0], tier_counts[1], tier_counts[2]);
    let has_plan = |year: u16| plans.iter().any(|p| p.milestone.year() == year);
    let covered = [2026u16, 2028, 2030]
        .iter()
        .filter(|y| has_plan(**y))
        .count();
    let soci = systems.iter().filter(|s| s.is_soci).count();

    let mut h = String::new();

    // Document head ------------------------------------------------------------
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str(&format!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src '{}'; img-src data:\">\n",
        PRINT_SCRIPT_HASH
    ));
    h.push_str("<meta name=\"color-scheme\" content=\"light dark\">\n");
    h.push_str(&format!(
        "<meta name=\"generator\" content=\"Boab {}\">\n",
        env!("CARGO_PKG_VERSION")
    ));
    h.push_str("<title>Post-Quantum Cryptography Readiness Report</title>\n");
    h.push_str("<style>\n");
    h.push_str(CSS);
    h.push_str("</style>\n</head>\n<body>\n");

    // Masthead -----------------------------------------------------------------
    h.push_str("<header class=\"masthead\">\n<div class=\"wrap\">\n");
    h.push_str("<div class=\"brand\">");
    h.push_str(LOGO_SVG);
    h.push_str("<span class=\"brand-name\">Boab</span><span class=\"brand-tag\">Transitioning to post-quantum security</span></div>\n");
    h.push_str("<h1>Post-Quantum Cryptography Readiness Report</h1>\n");
    h.push_str(&format!(
        "<p class=\"meta\">Prepared {} &middot; Boab {} &middot; Aligned to the ASD 2026, 2028 and 2030 transition milestones</p>\n",
        human_date(today.date()),
        env!("CARGO_PKG_VERSION")
    ));
    let mut scan_counts = [0usize; 3];
    for s in &scans {
        scan_counts[match s.scan_type {
            ScanType::Codebase => 0,
            ScanType::TlsEndpoint => 1,
            ScanType::CertificateStore => 2,
        }] += 1;
    }
    h.push_str(&format!(
        "<p class=\"meta\">Assessment scope: {} &middot; {} &middot; {}</p>\n",
        plural(scan_counts[0], "codebase scan", "codebase scans"),
        plural(scan_counts[1], "TLS endpoint scan", "TLS endpoint scans"),
        plural(
            scan_counts[2],
            "certificate store scan",
            "certificate store scans"
        )
    ));
    h.push_str("</div>\n</header>\n<main class=\"wrap\">\n");

    // Overall posture ----------------------------------------------------------
    let (tone, posture) = if total == 0 {
        ("neutral", "Not yet assessed")
    } else if t1 > 0 {
        ("critical", "Critical exposure")
    } else if t2 > 0 || exposed * 2 >= total {
        ("serious", "High exposure")
    } else if exposed > 0 {
        ("warning", "Moderate exposure")
    } else {
        ("good", "Low exposure")
    };
    let headline = if total == 0 {
        "No cryptographic assets have been inventoried yet. Run the Boab codebase, TLS and certificate scanners to establish a baseline before the end-of-2026 planning milestone.".to_string()
    } else {
        let mut s = format!(
            "{} of {} ({}%) {} on cryptography that a future quantum computer could break, or {} not yet classified. ",
            group(exposed),
            plural(
                total,
                "inventoried cryptographic asset",
                "inventoried cryptographic assets"
            ),
            fmt1(exposed_pct),
            if exposed == 1 { "relies" } else { "rely" },
            if exposed == 1 { "is" } else { "are" }
        );
        if t1 + t2 > 0 {
            s.push_str(&format!(
                "{} {} migration inside the 2028 implementation window.",
                plural(t1 + t2, "asset", "assets"),
                if t1 + t2 == 1 { "needs" } else { "need" }
            ));
        } else if exposed > 0 {
            s.push_str("None require migration inside the 2028 window; the remainder fall into the 2029&ndash;2030 rollout or monitoring.");
        } else {
            s.push_str("No quantum-vulnerable cryptography was found in scope.");
        }
        s
    };
    h.push_str(&format!(
        "<section class=\"hero tone-{}\" aria-label=\"Overall posture\">\n",
        tone
    ));
    h.push_str("<div class=\"hero-text\">\n<p class=\"eyebrow\">Overall posture</p>\n");
    h.push_str(&format!(
        "<p class=\"posture\"><span class=\"pip\" aria-hidden=\"true\"></span>{}</p>\n",
        posture
    ));
    h.push_str(&format!("<p class=\"headline\">{}</p>\n</div>\n", headline));
    h.push_str("<div class=\"hero-figure\">\n");
    h.push_str(&format!(
        "<span class=\"big\">{}</span>\n",
        if total == 0 {
            "&ndash;".to_string()
        } else {
            format!("{}%", fmt1(exposed_pct))
        }
    ));
    h.push_str("<span class=\"cap\">of inventoried assets are quantum-vulnerable or unclassified</span>\n</div>\n</section>\n");

    // KPI tiles ----------------------------------------------------------------
    h.push_str("<section class=\"kpis\" aria-label=\"Key figures\">\n");
    kpi(
        &mut h,
        "Assets inventoried",
        &group(total),
        &if unassigned > 0 {
            format!("{} not linked to a system", group(unassigned))
        } else {
            format!("across {}", plural(systems.len(), "system", "systems"))
        },
    );
    kpi(
        &mut h,
        "Quantum-vulnerable",
        &group(exposed),
        &format!("{}% of inventory", fmt1(exposed_pct)),
    );
    kpi(
        &mut h,
        "Migrate by 2028",
        &group(t1 + t2),
        &format!("Tier 1: {} &middot; Tier 2: {}", group(t1), group(t2)),
    );
    kpi(
        &mut h,
        "Classically broken",
        &group(broken),
        "weak even without a quantum computer",
    );
    kpi(
        &mut h,
        "Milestones planned",
        &format!("{} of 3", covered),
        &format!("{} on file", plural(plans.len(), "plan", "plans")),
    );
    h.push_str("</section>\n");

    // Key actions --------------------------------------------------------------
    let mut actions: Vec<String> = Vec::new();
    if t1 > 0 {
        actions.push(format!(
            "<strong>Migrate {} now.</strong> {} high quantum exposure with a practical migration path and must be completed before the 2028 milestone.",
            plural(t1, "Tier 1 asset", "Tier 1 assets"),
            if t1 == 1 { "It combines" } else { "They combine" }
        ));
    }
    if broken > 0 {
        actions.push(format!(
            "<strong>Retire {} using classically broken algorithms</strong> (MD5, SHA-1, RSA-1024, 3DES, RC4). These are exploitable today, independent of quantum timelines.",
            plural(broken, "asset", "assets")
        ));
    }
    if t2 > 0 {
        actions.push(format!(
            "<strong>Schedule {} inside the 2028 window</strong>, starting with hardware-locked and long-lived systems that take longest to change.",
            plural(t2, "Tier 2 asset", "Tier 2 assets")
        ));
    }
    if !has_plan(2026) {
        actions.push("<strong>Agree a refined transition plan</strong> to meet the ASD end-of-2026 milestone (<code>boab plan generate --milestone 2026</code>).".to_string());
    }
    if unknown > 0 {
        actions.push(format!(
            "<strong>Classify {} with unknown quantum status.</strong> Unknowns are scored conservatively until they are reviewed.",
            plural(unknown, "asset", "assets")
        ));
    }
    if unassigned > 0 {
        actions.push(format!(
            "<strong>Link {} to business systems</strong> so data classification, SOCI status and retention are weighted correctly.",
            plural(unassigned, "asset", "assets")
        ));
    }
    if t3 > 0 {
        actions.push(format!(
            "<strong>Track {}</strong> for replacement during the 2029&ndash;2030 rollout window.",
            plural(t3, "Tier 3 asset", "Tier 3 assets")
        ));
    }
    if actions.is_empty() {
        actions.push("<strong>Maintain the inventory.</strong> Rescan after significant changes and keep monitoring vendor post-quantum roadmaps.".to_string());
    }
    h.push_str("<section class=\"card\">\n<h2>Recommended actions</h2>\n<ol class=\"actions\">\n");
    for a in &actions {
        h.push_str(&format!("<li>{}</li>\n", a));
    }
    h.push_str("</ol>\n</section>\n");

    // Charts -------------------------------------------------------------------
    h.push_str("<div class=\"grid2\">\n");
    h.push_str("<section class=\"card\">\n<h2>Quantum exposure</h2>\n<p class=\"sub\">Inventoried assets by post-quantum status</p>\n");
    if total == 0 {
        h.push_str("<p class=\"empty\">No assets inventoried yet.</p>\n");
    } else {
        h.push_str("<div class=\"stack\" role=\"img\" aria-label=\"");
        let mut aria: Vec<String> = Vec::new();
        for (i, st) in STATUS_ORDER.iter().enumerate() {
            aria.push(format!("{} {}", status_label(*st), status_counts[i]));
        }
        h.push_str(&aria.join(", "));
        h.push_str("\">");
        for (i, st) in STATUS_ORDER.iter().enumerate() {
            if status_counts[i] > 0 {
                h.push_str(&format!(
                    "<span class=\"seg s-{}\" style=\"flex-grow:{}\" title=\"{}: {}\"></span>",
                    status_key(*st),
                    status_counts[i],
                    status_label(*st),
                    status_counts[i]
                ));
            }
        }
        h.push_str("</div>\n");
    }
    h.push_str("<ul class=\"legend\">\n");
    for (i, st) in STATUS_ORDER.iter().enumerate() {
        h.push_str(&format!(
            "<li><span class=\"key s-{}\" aria-hidden=\"true\"></span><span class=\"lk\">{}</span><span class=\"lv\">{}</span><span class=\"ld\">{}</span></li>\n",
            status_key(*st),
            status_label(*st),
            group(status_counts[i]),
            status_blurb(*st)
        ));
    }
    h.push_str("</ul>\n</section>\n");

    h.push_str("<section class=\"card\">\n<h2>Migration priority</h2>\n<p class=\"sub\">Inventoried assets by triage tier</p>\n");
    let tier_max = tier_counts.iter().copied().max().unwrap_or(0);
    h.push_str("<ul class=\"bars\">\n");
    for (i, count) in tier_counts.iter().enumerate() {
        let tier = (i + 1) as u8;
        let width = (count * 1000).checked_div(tier_max).unwrap_or(0);
        h.push_str(&format!(
            "<li><span class=\"bl\"><strong>Tier {}</strong><span>{}</span></span><span class=\"track\"><span class=\"fill t-{}\" style=\"width:{}.{}%\" title=\"Tier {}: {}\"></span></span><span class=\"bv\">{}</span></li>\n",
            tier,
            tier_blurb(tier),
            tier,
            width / 10,
            width % 10,
            tier,
            count,
            group(*count)
        ));
    }
    h.push_str("</ul>\n</section>\n</div>\n");

    // Milestones ---------------------------------------------------------------
    h.push_str("<section class=\"card\">\n<h2>ASD transition milestones</h2>\n<p class=\"sub\">Australian Signals Directorate direction for post-quantum migration</p>\n<ol class=\"milestones\">\n");
    for (year, title, desc) in [
        (
            2026u16,
            "Refined transition plan",
            "Cryptographic inventory complete and a prioritised, funded transition plan agreed.",
        ),
        (
            2028,
            "Implementation begins",
            "Tier 1 and Tier 2 assets migrated or actively in flight.",
        ),
        (
            2030,
            "Implementation complete",
            "Classical public-key cryptography retired from in-scope systems.",
        ),
    ] {
        let (cls, label) = if has_plan(year) {
            ("good", "Plan on file")
        } else {
            ("warning", "Plan outstanding")
        };
        h.push_str(&format!(
            "<li><span class=\"year\">{}</span><span class=\"mt\">{}</span><span class=\"md\">{}</span>{}</li>\n",
            year,
            title,
            desc,
            badge(cls, label)
        ));
    }
    h.push_str("</ol>\n</section>\n");

    // Top assets ---------------------------------------------------------------
    h.push_str(&format!(
        "<section class=\"card\">\n<h2>Highest-priority assets</h2>\n<p class=\"sub\">Top {} by LATICE priority score (0&ndash;10)</p>\n",
        TOP_ASSETS
    ));
    asset_table(
        &mut h,
        scored.iter().take(TOP_ASSETS),
        &systems,
        "No assets inventoried yet.",
    );
    h.push_str("</section>\n");

    // Systems ------------------------------------------------------------------
    h.push_str("<section class=\"card\">\n<h2>Exposure by business system</h2>\n");
    h.push_str(&format!(
        "<p class=\"sub\">{} in scope, {} SOCI-regulated</p>\n",
        plural(systems.len(), "system", "systems"),
        group(soci)
    ));
    if systems.is_empty() && unassigned == 0 {
        h.push_str("<p class=\"empty\">No business systems recorded. Add them with <code>boab system add</code> so risk is weighted by classification and criticality.</p>\n");
    } else {
        h.push_str("<div class=\"tw\"><table>\n<thead><tr><th>System</th><th>Classification</th><th>Criticality</th><th class=\"num\">Assets</th><th class=\"num\">Vulnerable</th><th class=\"num\">Tier 1&ndash;2</th><th class=\"num\">Peak priority</th></tr></thead>\n<tbody>\n");
        for sys in &systems {
            let mine = scored
                .iter()
                .filter(|(a, _)| a.system_id == Some(sys.id))
                .map(|(a, s)| (a, s));
            let name = format!(
                "{}{}",
                esc(&sys.name),
                if sys.is_soci {
                    " <span class=\"tag\">SOCI</span>"
                } else {
                    ""
                }
            );
            system_row(
                &mut h,
                &name,
                classification_label(sys.classification),
                criticality_label(sys.criticality),
                mine,
            );
        }
        if unassigned > 0 {
            let mine = scored
                .iter()
                .filter(|(a, _)| find_system(&systems, a).is_none())
                .map(|(a, s)| (a, s));
            system_row(
                &mut h,
                "<em>Not linked to a system</em>",
                "&ndash;",
                "&ndash;",
                mine,
            );
        }
        h.push_str("</tbody>\n</table></div>\n");
    }
    h.push_str("</section>\n");

    // Plans --------------------------------------------------------------------
    h.push_str("<section class=\"card\">\n<h2>Transition plans</h2>\n");
    if plans.is_empty() {
        h.push_str("<p class=\"empty\">No transition plans generated yet. Create one with <code>boab plan generate --milestone 2028</code>.</p>\n");
    } else {
        h.push_str("<div class=\"tw\"><table>\n<thead><tr><th>Plan</th><th>Milestone</th><th class=\"num\">Items</th><th class=\"num\">In progress</th><th class=\"num\">Complete</th><th>Progress</th><th>Generated</th></tr></thead>\n<tbody>\n");
        for p in &plans {
            let items = p.items.len();
            let done = p
                .items
                .iter()
                .filter(|i| i.status == PlanItemStatus::Complete)
                .count();
            let doing = p
                .items
                .iter()
                .filter(|i| i.status == PlanItemStatus::InProgress)
                .count();
            let pct = (done * 100).checked_div(items).unwrap_or(0);
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td><span class=\"meter\"><span class=\"mf\" style=\"width:{}%\"></span></span> {}%</td><td><time datetime=\"{}\">{}</time></td></tr>\n",
                esc(&p.name),
                p.milestone.year(),
                group(items),
                group(doing),
                group(done),
                pct,
                pct,
                p.generated_at.format(&Rfc3339).unwrap_or_default(),
                human_date(p.generated_at.date())
            ));
        }
        h.push_str("</tbody>\n</table></div>\n");
    }
    h.push_str("</section>\n");

    // Vendors ------------------------------------------------------------------
    let mut vendor_counts = [0usize; 5];
    for e in &registry.entries {
        vendor_counts[status_index(e.pqc_status)] += 1;
    }
    h.push_str("<section class=\"card\">\n<h2>Vendor PQC dependencies</h2>\n");
    h.push_str(&format!(
        "<p class=\"sub\">Post-quantum readiness of {} in the vendor registry</p>\n",
        plural(
            registry.entries.len(),
            "tracked product",
            "tracked products"
        )
    ));
    h.push_str("<ul class=\"chips\">\n");
    for (i, st) in [
        PqcStatus::Resistant,
        PqcStatus::Hybrid,
        PqcStatus::Vulnerable,
        PqcStatus::Unknown,
        PqcStatus::SymmetricOk,
    ]
    .iter()
    .enumerate()
    {
        let n = vendor_counts[status_index(*st)];
        if n > 0 || i < 4 {
            h.push_str(&format!(
                "<li><span class=\"key s-{}\" aria-hidden=\"true\"></span>{} <strong>{}</strong></li>\n",
                status_key(*st),
                status_label(*st),
                group(n)
            ));
        }
    }
    h.push_str("</ul>\n");
    if !registry.entries.is_empty() {
        h.push_str(&format!(
            "<details>\n<summary>View all {} vendor products</summary>\n",
            group(registry.entries.len())
        ));
        h.push_str("<div class=\"tw\"><table>\n<thead><tr><th>Vendor</th><th>Product</th><th>Status</th><th>Target</th><th>Source</th></tr></thead>\n<tbody>\n");
        for e in &registry.entries {
            let source = match e.source_url.as_deref() {
                Some(u) if is_web_url(u) => format!(
                    "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>",
                    esc(u),
                    esc(e.source_note.as_deref().unwrap_or("source"))
                ),
                _ => match e.source_note.as_deref() {
                    Some(n) => esc(n),
                    None => "&ndash;".to_string(),
                },
            };
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                esc(&e.vendor),
                esc(&e.product),
                status_badge(e.pqc_status),
                match e.target_date.as_deref() {
                    Some(t) => esc(t),
                    None => "&ndash;".to_string(),
                },
                source
            ));
        }
        h.push_str("</tbody>\n</table></div>\n</details>\n");
    }
    h.push_str("</section>\n");

    // Appendix: full inventory -------------------------------------------------
    h.push_str(
        "<section class=\"card\">\n<h2>Appendix A &middot; Full cryptographic inventory</h2>\n",
    );
    h.push_str(&format!(
        "<p class=\"sub\">{}, ranked by priority</p>\n",
        plural(total, "asset", "assets")
    ));
    if total == 0 {
        h.push_str("<p class=\"empty\">No assets inventoried yet.</p>\n");
    } else {
        h.push_str(&format!(
            "<details>\n<summary>View all {}</summary>\n",
            plural(total, "asset", "assets")
        ));
        asset_table(&mut h, scored.iter(), &systems, "");
        h.push_str("</details>\n");
    }
    h.push_str("</section>\n");

    // Appendix: methodology ----------------------------------------------------
    h.push_str("<section class=\"card method\">\n<h2>Appendix B &middot; Methodology</h2>\n");
    h.push_str("<p>Each asset is scored with the ASD LATICE rubric on five axes, each from 0 to 10, and combined into a priority score:</p>\n");
    h.push_str("<p class=\"formula\"><code>priority = algo_vuln &times; 0.30 + hndl &times; 0.30 + data_sens &times; 0.15 + sys_crit &times; 0.15 + mig_diff &times; 0.10</code></p>\n");
    h.push_str("<dl>\n");
    h.push_str("<dt>Algorithm vulnerability</dt><dd>How exposed the algorithm is: 10 for classically broken primitives, 8&ndash;9 for RSA and elliptic-curve cryptography, 5 for PQ/T hybrids, 1 for ML-KEM, ML-DSA and SLH-DSA, 0 for strong symmetric cryptography.</dd>\n");
    h.push_str("<dt>Harvest now, decrypt later</dt><dd>How far the data&rsquo;s confidentiality horizon extends past the expected arrival of a cryptographically relevant quantum computer.</dd>\n");
    h.push_str("<dt>Data sensitivity and system criticality</dt><dd>Taken from the protective marking and criticality of the linked business system; SOCI-regulated systems score as mission critical.</dd>\n");
    h.push_str("<dt>Migration difficulty</dt><dd>Effort to replace the asset, from trivial configuration changes to hardware-locked devices.</dd>\n");
    h.push_str("</dl>\n");
    h.push_str("<p><strong>Triage tiers.</strong> Tier 1: priority &ge; 7 with a practical migration path, migrate before 2028. Tier 2: priority &ge; 6, or hardware-locked and clearly vulnerable, migrate inside the 2028 window. Tier 3: vulnerable algorithm, replace during 2029&ndash;2030. Tier 4: monitor.</p>\n");
    h.push_str("<p><strong>Overall posture.</strong> Critical when any Tier 1 asset exists; high when any Tier 2 asset exists or at least half of the inventory is quantum-vulnerable or unclassified; moderate when any vulnerable or unclassified asset remains; otherwise low.</p>\n");
    h.push_str("<p>Refer to the ASD Information Security Manual for control mappings. Boab does not map findings to specific ISM control IDs in this version.</p>\n");
    h.push_str("</section>\n</main>\n");

    // Footer -------------------------------------------------------------------
    h.push_str(&format!(
        "<footer class=\"wrap\">Generated by Boab {} at <time datetime=\"{ts}\">{ts}</time>. This report is self-contained and makes no network requests.</footer>\n",
        env!("CARGO_PKG_VERSION"),
        ts = today.format(&Rfc3339).unwrap_or_default()
    ));
    h.push_str(&format!("<script>{}</script>\n", PRINT_SCRIPT));
    h.push_str("</body>\n</html>\n");
    Ok(h)
}

fn find_system<'a>(systems: &'a [System], asset: &CryptoAsset) -> Option<&'a System> {
    asset
        .system_id
        .and_then(|id| systems.iter().find(|s| s.id == id))
}

fn kpi(h: &mut String, label: &str, value: &str, sub: &str) {
    h.push_str(&format!(
        "<div class=\"kpi\"><span class=\"kl\">{}</span><span class=\"kv\">{}</span><span class=\"ks\">{}</span></div>\n",
        label, value, sub
    ));
}

fn asset_table<'a>(
    h: &mut String,
    rows: impl Iterator<Item = &'a (CryptoAsset, RiskScore)>,
    systems: &[System],
    empty: &str,
) {
    h.push_str("<div class=\"tw\"><table>\n<thead><tr><th class=\"num\">#</th><th>Asset</th><th>System</th><th>Status</th><th>Priority</th><th>Tier</th><th>Recommended action</th></tr></thead>\n<tbody>\n");
    let mut n = 0usize;
    for (asset, score) in rows {
        n += 1;
        let p = fmt1(score.priority);
        h.push_str(&format!(
            "<tr><td class=\"num\">{}</td><td><span class=\"an\">{}</span><span class=\"aa\">{} &middot; <code>{}</code></span></td><td>{}</td><td>{}</td><td><span class=\"score\"><span class=\"meter\"><span class=\"mf t-{}\" style=\"width:{}%\"></span></span>{}</span></td><td>{}</td><td>{}</td></tr>\n",
            n,
            esc(&asset.name),
            asset_type_label(asset.asset_type),
            esc(&asset.algorithm_name),
            match find_system(systems, asset) {
                Some(s) => esc(&s.name),
                None => "&ndash;".to_string(),
            },
            status_badge(asset.pqc_status),
            score.triage_tier,
            p.replace('.', "").parse::<u32>().unwrap_or(0),
            p,
            tier_badge(score.triage_tier),
            esc(&score.recommended_action)
        ));
    }
    if n == 0 {
        h.push_str(&format!(
            "<tr><td colspan=\"7\" class=\"empty\">{}</td></tr>\n",
            empty
        ));
    }
    h.push_str("</tbody>\n</table></div>\n");
}

fn system_row<'a>(
    h: &mut String,
    name: &str,
    classification: &str,
    criticality: &str,
    assets: impl Iterator<Item = (&'a CryptoAsset, &'a RiskScore)>,
) {
    let mut count = 0usize;
    let mut vulnerable = 0usize;
    let mut urgent = 0usize;
    let mut peak: Option<f32> = None;
    for (a, s) in assets {
        count += 1;
        if matches!(a.pqc_status, PqcStatus::Vulnerable | PqcStatus::Unknown) {
            vulnerable += 1;
        }
        if s.triage_tier <= 2 {
            urgent += 1;
        }
        if peak.is_none_or(|p| s.priority > p) {
            peak = Some(s.priority);
        }
    }
    h.push_str(&format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>\n",
        name,
        classification,
        criticality,
        group(count),
        group(vulnerable),
        group(urgent),
        match peak {
            Some(p) => fmt1(p),
            None => "&ndash;".to_string(),
        }
    ));
}

fn badge(class: &str, label: &str) -> String {
    format!(
        "<span class=\"badge b-{}\"><span class=\"pip\" aria-hidden=\"true\"></span>{}</span>",
        class, label
    )
}

fn status_badge(s: PqcStatus) -> String {
    badge(status_key(s), status_label(s))
}

fn tier_badge(tier: u8) -> String {
    badge(&format!("t{}", tier), &format!("Tier {}", tier))
}

fn status_index(s: PqcStatus) -> usize {
    match s {
        PqcStatus::Vulnerable => 0,
        PqcStatus::Unknown => 1,
        PqcStatus::Hybrid => 2,
        PqcStatus::Resistant => 3,
        PqcStatus::SymmetricOk => 4,
    }
}

fn status_key(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "vulnerable",
        PqcStatus::Unknown => "unknown",
        PqcStatus::Hybrid => "hybrid",
        PqcStatus::Resistant => "resistant",
        PqcStatus::SymmetricOk => "symmetric",
    }
}

fn status_label(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "Vulnerable",
        PqcStatus::Unknown => "Unknown",
        PqcStatus::Hybrid => "Hybrid PQ/T",
        PqcStatus::Resistant => "Quantum-resistant",
        PqcStatus::SymmetricOk => "Symmetric OK",
    }
}

fn status_blurb(s: PqcStatus) -> &'static str {
    match s {
        PqcStatus::Vulnerable => "Breakable by a quantum computer",
        PqcStatus::Unknown => "Not yet classified",
        PqcStatus::Hybrid => "Classical plus post-quantum",
        PqcStatus::Resistant => "NIST post-quantum standard",
        PqcStatus::SymmetricOk => "Strong symmetric or hash",
    }
}

fn tier_blurb(tier: u8) -> &'static str {
    match tier {
        1 => "Migrate before 2028",
        2 => "Inside the 2028 window",
        3 => "Replace 2029&ndash;2030",
        _ => "Monitor",
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

fn is_web_url(u: &str) -> bool {
    let lower = u.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

fn human_date(d: Date) -> String {
    format!(
        "{} {} {}",
        d.day(),
        MONTHS[(d.month() as usize) - 1],
        d.year()
    )
}

fn fmt1(v: f32) -> String {
    format!("{:.1}", v)
}

/// `1234567` -> `1,234,567`.
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

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", group(n), if n == 1 { one } else { many })
}

/// Escape text for HTML element content and quoted attribute values.
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

const LOGO_SVG: &str = "<svg class=\"logo\" viewBox=\"0 0 32 36\" width=\"30\" height=\"34\" aria-hidden=\"true\"><path d=\"M16 1L30 6V17C30 26 24 32 16 35C8 32 2 26 2 17V6Z\" fill=\"#2a78d6\"/><path d=\"M16 1L30 6V17C30 26 24 32 16 35Z\" fill=\"#d9622b\"/><path d=\"M14.4 29C14 24 13.6 20.5 12.2 17.6C10.2 16.8 8.4 15.4 7.6 13.4C9.8 13.8 11.8 14.8 13.3 15.8C13.3 13.4 12.4 11.4 11 9.8C13.4 10.8 15 12.8 16 15.2C17 12.8 18.6 10.8 21 9.8C19.6 11.4 18.7 13.4 18.7 15.8C20.2 14.8 22.2 13.8 24.4 13.4C23.6 15.4 21.8 16.8 19.8 17.6C18.4 20.5 18 24 17.6 29Z\" fill=\"#ffffff\"/></svg>";

const CSS: &str = r#":root{color-scheme:light;--page:#f3f4f6;--surface:#ffffff;--ink:#101b2b;--ink-2:#46505e;--muted:#6b7482;--line:#e2e5e9;--track:#edf0f3;--brand:#13233a;--brand-2:#1d3a5f;--accent:#d9622b;--critical:#d03b3b;--serious:#ec835a;--warning:#fab219;--good:#0ca30c;--neutral:#8a94a6;--hybrid:#2a78d6;--symmetric:#1c5cab}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0e1319;--surface:#161d26;--ink:#edf1f5;--ink-2:#b9c1cc;--muted:#8d96a3;--line:#2a333e;--track:#232c37;--hybrid:#3987e5;--symmetric:#5598e7}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:0 28px}
code{font:0.88em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
a{color:var(--hybrid)}
.masthead{background:linear-gradient(135deg,var(--brand) 0%,var(--brand-2) 100%);color:#ffffff;padding:28px 0 30px;border-bottom:4px solid var(--accent)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.logo{flex:none}
.brand-name{font-weight:700;font-size:20px;letter-spacing:0.02em}
.brand-tag{font-size:12px;text-transform:uppercase;letter-spacing:0.12em;color:#c8d3e1;border-left:1px solid #4a6283;padding-left:10px}
.masthead h1{margin:0 0 8px;font-size:30px;line-height:1.2;font-weight:700;letter-spacing:-0.01em}
.masthead .meta{margin:2px 0 0;color:#c8d3e1;font-size:14px}
main{padding:28px 0 8px}
.card,.hero,.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.card{padding:22px 24px;margin:0 0 20px}
.card h2{margin:0 0 4px;font-size:18px;line-height:1.3}
.sub{margin:0 0 16px;color:var(--muted);font-size:13px}
.empty{color:var(--muted);font-style:italic;margin:4px 0}
.hero{display:flex;gap:28px;align-items:center;justify-content:space-between;padding:26px 28px;margin:0 0 20px;border-left:8px solid var(--tone)}
.tone-critical{--tone:var(--critical)}
.tone-serious{--tone:var(--serious)}
.tone-warning{--tone:var(--warning)}
.tone-good{--tone:var(--good)}
.tone-neutral{--tone:var(--neutral)}
.eyebrow{margin:0;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.1em;font-weight:600}
.posture{margin:4px 0 8px;font-size:26px;font-weight:700;display:flex;align-items:center;gap:10px}
.posture .pip{width:14px;height:14px;border-radius:50%;background:var(--tone);flex:none}
.headline{margin:0;color:var(--ink-2);max-width:660px}
.hero-figure{flex:none;text-align:right;max-width:230px}
.hero-figure .big{display:block;font-size:56px;line-height:1;font-weight:700}
.hero-figure .cap{display:block;margin-top:8px;color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:0 0 20px}
.kpi{padding:16px 18px;display:flex;flex-direction:column;gap:4px}
.kl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.06em;font-weight:600}
.kv{font-size:30px;font-weight:700;line-height:1.1}
.ks{color:var(--ink-2);font-size:13px}
.actions{margin:8px 0 0;padding-left:22px}
.actions li{margin:0 0 8px;padding-left:4px}
.actions li::marker{color:var(--accent);font-weight:700}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
.stack{display:flex;gap:2px;height:22px;border-radius:6px;overflow:hidden;margin:0 0 16px;background:var(--track)}
.seg{display:block;min-width:4px}
.s-vulnerable{background:var(--critical)}
.s-unknown{background:var(--warning)}
.s-hybrid{background:var(--hybrid)}
.s-resistant{background:var(--good)}
.s-symmetric{background:var(--symmetric)}
.legend,.bars,.chips,.milestones{list-style:none;margin:0;padding:0}
.legend li{display:grid;grid-template-columns:14px 1fr auto;column-gap:10px;align-items:center;padding:6px 0;border-top:1px solid var(--line)}
.legend li:first-child{border-top:0}
.key{display:inline-block;width:12px;height:12px;border-radius:3px}
.lk{font-weight:600}
.lv{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.ld{grid-column:2 / 4;color:var(--muted);font-size:12px}
.bars li{display:grid;grid-template-columns:150px 1fr 44px;gap:12px;align-items:center;padding:8px 0}
.bl{display:flex;flex-direction:column;line-height:1.25}
.bl span{color:var(--muted);font-size:12px}
.track{display:block;height:18px;background:var(--track);border-radius:4px}
.fill{display:block;height:100%;border-radius:0 4px 4px 0;min-width:2px}
.mf{display:block;height:100%;background:var(--good)}
.t-1{background:var(--critical)}
.t-2{background:var(--serious)}
.t-3{background:var(--warning)}
.t-4{background:var(--neutral)}
.bv{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.milestones{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.milestones li{border:1px solid var(--line);border-top:4px solid var(--brand-2);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:6px;align-items:flex-start}
.year{font-size:26px;font-weight:700;line-height:1}
.mt{font-weight:600}
.md{color:var(--ink-2);font-size:13px;flex:1}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 9px 2px 7px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;background:var(--surface)}
.badge .pip{width:8px;height:8px;border-radius:50%;flex:none}
.b-vulnerable .pip,.b-t1 .pip{background:var(--critical)}
.b-unknown .pip,.b-warning .pip,.b-t3 .pip{background:var(--warning)}
.b-hybrid .pip{background:var(--hybrid)}
.b-resistant .pip,.b-good .pip{background:var(--good)}
.b-symmetric .pip{background:var(--symmetric)}
.b-t2 .pip{background:var(--serious)}
.b-t4 .pip{background:var(--neutral)}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border-radius:4px;background:var(--brand-2);color:#ffffff;font-size:11px;font-weight:700;letter-spacing:0.04em;vertical-align:1px}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:0.05em;font-weight:600;padding:8px 10px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums}
.an{display:block;font-weight:600;overflow-wrap:anywhere}
.aa{display:block;color:var(--muted);font-size:12px}
.score{display:inline-flex;align-items:center;gap:8px;font-weight:700;font-variant-numeric:tabular-nums}
.meter{display:inline-block;width:56px;height:6px;background:var(--track);border-radius:3px;overflow:hidden;vertical-align:middle}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}
.chips li{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--line);border-radius:8px}
details{margin-top:4px}
summary{cursor:pointer;font-weight:600;color:var(--hybrid);padding:4px 0;margin-bottom:8px}
.method p,.method dd{color:var(--ink-2)}
.method dl{margin:0 0 12px}
.method dt{font-weight:600;margin-top:8px}
.method dd{margin:2px 0 0}
.formula{background:var(--track);border-radius:8px;padding:10px 14px}
footer{color:var(--muted);font-size:12.5px;padding-top:4px;padding-bottom:36px}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2,.milestones{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}.hero-figure{text-align:left;max-width:none}}
@media print{:root{color-scheme:light;--page:#ffffff;--surface:#ffffff;--ink:#101b2b;--ink-2:#46505e;--muted:#5d6672;--line:#d9dde2;--track:#edf0f3;--hybrid:#2a78d6;--symmetric:#1c5cab}@page{size:A4;margin:14mm}body{font-size:12px;-webkit-print-color-adjust:exact;print-color-adjust:exact}.wrap{max-width:none;padding:0}.masthead{padding:18px 20px}main{padding-top:16px}.hero,.kpi,.grid2 .card,.milestones li,tr{break-inside:avoid}h2,.sub{break-after:avoid}.hero{flex-direction:row;align-items:center}.hero-figure{text-align:right;max-width:200px}.hero-figure .big{font-size:44px}.kv{font-size:24px}table{font-size:11px}th{font-size:9.5px}.badge{font-size:10px}.kpis{grid-template-columns:repeat(5,minmax(0,1fr))}.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}.milestones{grid-template-columns:repeat(3,minmax(0,1fr))}summary{display:none}.tw{overflow:visible}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            esc("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1000), "1,000");
        assert_eq!(group(1234567), "1,234,567");
    }

    #[test]
    fn only_web_urls_become_links() {
        assert!(is_web_url("https://example.com"));
        assert!(is_web_url("HTTP://example.com"));
        assert!(!is_web_url("javascript:alert(1)"));
        assert!(!is_web_url("data:text/html,x"));
    }

    #[test]
    fn print_script_hash_matches_csp() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(PRINT_SCRIPT.as_bytes());
        let expected = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        assert_eq!(PRINT_SCRIPT_HASH, expected);
    }

    #[test]
    fn human_dates_use_english_month_names() {
        let d = Date::from_calendar_date(2026, time::Month::October, 4).unwrap();
        assert_eq!(human_date(d), "4 October 2026");
    }
}
