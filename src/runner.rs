//! Subcommand dispatcher. Pure logic; I/O lives in the called modules.

use std::io::Write;

use anyhow::{anyhow, Context, Result};
use comfy_table::{presets, Cell, Table};

use crate::cli::{
    Cli, Command, ConfigCommand, InventoryCommand, PlanCommand, ScanCommand, SystemCommand,
    VendorCommand,
};
use crate::config;
use crate::model::system::{Classification, Criticality, System};
use crate::storage;
use crate::workspace::Workspace;
use crate::EXIT_NOT_IMPLEMENTED;

/// Run a parsed CLI. Returns the process exit code.
pub fn run(cli: Cli) -> i32 {
    init_logging(cli.verbose, cli.quiet);

    let result: Result<i32> = match cli.command {
        Command::Init(ref args) => cmd_init(&cli.workspace, args),
        Command::System(ref sub) => cmd_system(&cli.workspace, sub),
        Command::Inventory(ref sub) => cmd_inventory(&cli.workspace, sub),
        Command::Scan(ref sub) => cmd_scan(&cli.workspace, sub),
        Command::Plan(ref sub) => cmd_plan(&cli.workspace, sub),
        Command::Vendor(ref sub) => cmd_vendor(&cli.workspace, sub),
        Command::Report(ref args) => cmd_report(&cli.workspace, args),
        Command::Config(ref sub) => cmd_config(&cli.workspace, sub),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "error: {:#}", e);
            1
        }
    }
}

fn init_logging(verbose: bool, quiet: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = if let Ok(env) = std::env::var("RUST_LOG") {
        EnvFilter::new(env)
    } else if quiet {
        EnvFilter::new("error")
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn,boab=info")
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn cmd_init(workspace_root: &std::path::Path, args: &crate::cli::InitArgs) -> Result<i32> {
    if args.force && !args.yes {
        return Err(anyhow!("--force requires --yes"));
    }
    let (_ws, existed) = Workspace::init(workspace_root, args.force)?;
    if existed && !args.force {
        println!("workspace already initialised");
    } else {
        println!(
            "workspace initialised at {}/.boab",
            workspace_root.display()
        );
    }
    Ok(0)
}

fn cmd_system(workspace_root: &std::path::Path, sub: &SystemCommand) -> Result<i32> {
    let ws = Workspace::open(workspace_root)?;
    match sub {
        SystemCommand::Add(args) => {
            let classification = Classification::parse(&args.classification)
                .with_context(|| format!("unknown classification: {}", args.classification))?;
            let criticality = Criticality::parse(&args.criticality)
                .with_context(|| format!("unknown criticality: {}", args.criticality))?;
            let mut systems = storage::load_systems(&ws)?;
            let sys = System::new(
                args.name.clone(),
                args.description.clone(),
                classification,
                criticality,
                args.soci,
                args.lifetime_years,
            );
            println!("added system {} ({})", sys.name, sys.id);
            systems.push(sys);
            storage::save_systems(&ws, &systems)?;
            Ok(0)
        }
        SystemCommand::List => {
            let systems = storage::load_systems(&ws)?;
            if systems.is_empty() {
                println!("(no systems)");
                return Ok(0);
            }
            let mut table = Table::new();
            table.load_preset(presets::UTF8_FULL);
            table.set_header(vec!["ID", "NAME", "CLASS", "CRIT", "SOCI", "LIFETIME"]);
            for s in &systems {
                table.add_row(vec![
                    Cell::new(s.id),
                    Cell::new(&s.name),
                    Cell::new(s.classification.as_str()),
                    Cell::new(s.criticality.as_str()),
                    Cell::new(if s.is_soci { "yes" } else { "no" }),
                    Cell::new(
                        s.expected_data_lifetime_years
                            .map(|y| format!("{}y", y))
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                ]);
            }
            println!("{}", table);
            Ok(0)
        }
        SystemCommand::Edit(args) => {
            let mut systems = storage::load_systems(&ws)?;
            let s = systems
                .iter_mut()
                .find(|s| s.id == args.id)
                .ok_or_else(|| anyhow!("no system with id {}", args.id))?;
            if let Some(v) = args.name.clone() {
                s.name = v;
            }
            if args.description.is_some() {
                s.description = args.description.clone();
            }
            if let Some(v) = args.classification.as_deref() {
                s.classification = Classification::parse(v)
                    .with_context(|| format!("unknown classification: {}", v))?;
            }
            if let Some(v) = args.criticality.as_deref() {
                s.criticality =
                    Criticality::parse(v).with_context(|| format!("unknown criticality: {}", v))?;
            }
            if let Some(v) = args.soci {
                s.is_soci = v;
            }
            if let Some(v) = args.lifetime_years {
                s.expected_data_lifetime_years = Some(v);
            }
            storage::save_systems(&ws, &systems)?;
            println!("updated system {}", args.id);
            Ok(0)
        }
        SystemCommand::Delete(args) => {
            let mut systems = storage::load_systems(&ws)?;
            let before = systems.len();
            systems.retain(|s| s.id != args.id);
            if systems.len() == before {
                return Err(anyhow!("no system with id {}", args.id));
            }
            storage::save_systems(&ws, &systems)?;
            println!("deleted system {}", args.id);
            Ok(0)
        }
    }
}

fn cmd_inventory(workspace_root: &std::path::Path, sub: &InventoryCommand) -> Result<i32> {
    use crate::scoring;
    let ws = Workspace::open(workspace_root)?;
    let inventory = storage::load_inventory(&ws)?;
    let systems = storage::load_systems(&ws)?;
    let today = time::OffsetDateTime::now_utc();

    match sub {
        InventoryCommand::List(args) => {
            let mut rows: Vec<_> = inventory
                .iter()
                .filter(|a| {
                    args.pqc_status
                        .as_deref()
                        .map(|v| format!("{:?}", a.pqc_status).eq_ignore_ascii_case(v))
                        .unwrap_or(true)
                })
                .filter(|a| args.system.map(|s| a.system_id == Some(s)).unwrap_or(true))
                .filter(|a| {
                    args.algorithm
                        .as_deref()
                        .map(|v| {
                            a.algorithm_name
                                .to_ascii_lowercase()
                                .contains(&v.to_ascii_lowercase())
                        })
                        .unwrap_or(true)
                })
                .collect();

            if let Some(tier) = args.tier {
                rows.retain(|a| {
                    let sys = a
                        .system_id
                        .and_then(|id| systems.iter().find(|s| s.id == id));
                    scoring::score_asset(a, sys, today).triage_tier == tier
                });
            }

            if rows.is_empty() {
                println!("(no inventory entries)");
                return Ok(0);
            }
            let mut table = Table::new();
            table.load_preset(presets::UTF8_FULL);
            table.set_header(vec![
                "ID",
                "NAME",
                "ALGORITHM",
                "PQC",
                "PRIORITY",
                "TIER",
                "SYSTEM",
                "LAST_SEEN",
            ]);
            for a in &rows {
                let sys = a
                    .system_id
                    .and_then(|id| systems.iter().find(|s| s.id == id));
                let score = scoring::score_asset(a, sys, today);
                table.add_row(vec![
                    Cell::new(a.id),
                    Cell::new(&a.name),
                    Cell::new(&a.algorithm_name),
                    Cell::new(format!("{:?}", a.pqc_status).to_ascii_lowercase()),
                    Cell::new(format!("{:.1}", score.priority)),
                    Cell::new(score.triage_tier),
                    Cell::new(
                        sys.map(|s| s.name.clone())
                            .unwrap_or_else(|| "-".to_string()),
                    ),
                    Cell::new(
                        a.last_seen_at
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                    ),
                ]);
            }
            println!("{}", table);
            Ok(0)
        }
        InventoryCommand::Show(args) => {
            let asset = inventory
                .iter()
                .find(|a| a.id == args.id)
                .ok_or_else(|| anyhow!("no inventory entry with id {}", args.id))?;
            let sys = asset
                .system_id
                .and_then(|id| systems.iter().find(|s| s.id == id));
            let score = scoring::score_asset(asset, sys, today);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "asset": asset,
                    "score": score,
                }))?
            );
            Ok(0)
        }
    }
}

fn cmd_scan(workspace_root: &std::path::Path, sub: &ScanCommand) -> Result<i32> {
    use crate::scanners::codebase::{self, CodebaseOptions};

    match sub {
        ScanCommand::Codebase(args) => {
            let ws = Workspace::open(workspace_root)?;
            let path = match (args.path.as_ref(), args.git.as_ref()) {
                (Some(p), _) => p.clone(),
                (None, Some(_url)) => {
                    eprintln!("git cloning is not yet implemented; pass a local path instead");
                    return Ok(EXIT_NOT_IMPLEMENTED);
                }
                (None, None) => return Err(anyhow!("missing path or --git URL")),
            };
            let opts = CodebaseOptions {
                include: args.include.clone(),
                exclude: args.exclude.clone(),
                name: args.name.clone(),
            };
            let mut scan = codebase::scan_path(&path, &opts)?;
            let inventory_count = crate::dedup::promote_into_workspace(&mut scan, &ws)?.len();
            crate::storage::save_scan(&ws, &scan)?;
            println!(
                "scan {} complete: {} findings, inventory {} entries",
                scan.id,
                scan.findings.len(),
                inventory_count
            );
            Ok(0)
        }
        ScanCommand::Tls(args) => {
            use crate::scanners::tls::{self, TlsOptions};
            let ws = Workspace::open(workspace_root)?;
            let cfg = crate::config::load(&ws)?;
            let mut targets = args.targets.clone();
            if let Some(file) = &args.targets_file {
                let raw = std::fs::read_to_string(file)?;
                targets.extend(
                    raw.lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string),
                );
            }
            if targets.is_empty() {
                return Err(anyhow!(
                    "no TLS targets specified; pass host:port or --targets-file"
                ));
            }
            let opts = TlsOptions {
                rate_limit: args.rate_limit.clone(),
                timeout_seconds: args.timeout_seconds,
                probe_hsts: args.probe_hsts,
                exclude: args.exclude.clone(),
                name: args.name.clone(),
                air_gapped: cfg.scanner.air_gapped,
            };
            let rt = tokio::runtime::Runtime::new()?;
            let scans = rt.block_on(tls::scan_targets(&targets, &opts))?;
            let mut inventory_count = 0usize;
            for mut scan in scans {
                inventory_count = crate::dedup::promote_into_workspace(&mut scan, &ws)?.len();
                crate::storage::save_scan(&ws, &scan)?;
                println!(
                    "tls scan {} target={} status={:?} findings={}",
                    scan.id,
                    scan.target,
                    scan.status,
                    scan.findings.len()
                );
            }
            println!("inventory now has {} entries", inventory_count);
            Ok(0)
        }
        ScanCommand::Certs(args) => {
            use crate::scanners::cert_store::{self, CertStoreOptions};
            let ws = Workspace::open(workspace_root)?;
            let opts = CertStoreOptions {
                password_file: args.password_file.clone(),
                name: args.name.clone(),
            };
            let mut scan = cert_store::scan_path(&args.path, &opts)?;
            let inventory_count = crate::dedup::promote_into_workspace(&mut scan, &ws)?.len();
            crate::storage::save_scan(&ws, &scan)?;
            println!(
                "cert scan {} complete: {} findings, inventory {} entries",
                scan.id,
                scan.findings.len(),
                inventory_count
            );
            Ok(0)
        }
    }
}

fn cmd_plan(workspace_root: &std::path::Path, sub: &PlanCommand) -> Result<i32> {
    let ws = Workspace::open(workspace_root)?;
    match sub {
        PlanCommand::Generate(args) => {
            let milestone = crate::plan::parse_milestone(&args.milestone)?;
            let plan = crate::plan::generate(&ws, milestone, args.name.clone())?;
            crate::plan::save(&ws, &plan)?;
            println!(
                "plan {} generated for {}: {} items",
                plan.id,
                milestone.year(),
                plan.items.len()
            );
            Ok(0)
        }
        PlanCommand::List => {
            let plans = storage::list_plans(&ws)?;
            if plans.is_empty() {
                println!("(no plans)");
                return Ok(0);
            }
            let mut t = Table::new();
            t.load_preset(presets::UTF8_FULL);
            t.set_header(vec!["ID", "NAME", "MILESTONE", "ITEMS", "GENERATED"]);
            for p in &plans {
                t.add_row(vec![
                    Cell::new(p.id),
                    Cell::new(&p.name),
                    Cell::new(p.milestone.year()),
                    Cell::new(p.items.len()),
                    Cell::new(
                        p.generated_at
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                    ),
                ]);
            }
            println!("{}", t);
            Ok(0)
        }
        PlanCommand::Show(args) => {
            let plan = storage::load_plan(&ws, args.id)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(0)
        }
        PlanCommand::Regenerate(args) => {
            let plan = crate::plan::regenerate(&ws, args.id)?;
            crate::plan::save(&ws, &plan)?;
            println!(
                "plan {} regenerated: {} items (user edits preserved)",
                plan.id,
                plan.items.len()
            );
            Ok(0)
        }
    }
}

fn cmd_vendor(workspace_root: &std::path::Path, sub: &VendorCommand) -> Result<i32> {
    let ws = Workspace::open(workspace_root)?;
    match sub {
        VendorCommand::List => {
            let merged = crate::vendor::load_merged(&ws)?;
            if merged.entries.is_empty() {
                println!("(no vendor entries)");
                return Ok(0);
            }
            let mut t = Table::new();
            t.load_preset(presets::UTF8_FULL);
            t.set_header(vec!["VENDOR", "PRODUCT", "PQC", "TARGET", "SOURCE"]);
            for e in &merged.entries {
                t.add_row(vec![
                    Cell::new(&e.vendor),
                    Cell::new(&e.product),
                    Cell::new(format!("{:?}", e.pqc_status).to_ascii_lowercase()),
                    Cell::new(e.target_date.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(e.source_url.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            println!("{}", t);
            Ok(0)
        }
        VendorCommand::Search(args) => {
            let merged = crate::vendor::load_merged(&ws)?;
            let results = merged.search(&args.term);
            if results.is_empty() {
                println!("(no matches for {})", args.term);
                return Ok(0);
            }
            let mut t = Table::new();
            t.load_preset(presets::UTF8_FULL);
            t.set_header(vec!["VENDOR", "PRODUCT", "PQC", "TARGET"]);
            for e in results {
                t.add_row(vec![
                    Cell::new(&e.vendor),
                    Cell::new(&e.product),
                    Cell::new(format!("{:?}", e.pqc_status).to_ascii_lowercase()),
                    Cell::new(e.target_date.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            println!("{}", t);
            Ok(0)
        }
        VendorCommand::Add(args) => {
            use crate::model::asset::PqcStatus;
            use crate::model::vendor::VendorEntry;
            let status = match args.pqc_status.to_ascii_lowercase().as_str() {
                "vulnerable" => PqcStatus::Vulnerable,
                "hybrid" => PqcStatus::Hybrid,
                "resistant" => PqcStatus::Resistant,
                "symmetric_ok" => PqcStatus::SymmetricOk,
                "unknown" => PqcStatus::Unknown,
                other => {
                    return Err(anyhow!(
                        "unknown pqc_status: {} (expected vulnerable|hybrid|resistant|symmetric_ok|unknown)",
                        other
                    ))
                }
            };
            let mut overrides = storage::load_vendor_overrides(&ws)?;
            let entry = VendorEntry {
                vendor: args.vendor.clone(),
                product: args.product.clone(),
                pqc_status: status,
                target_date: args.target_date.clone(),
                source_url: args.source_url.clone(),
                source_note: args.source_note.clone(),
                last_verified_at: Some(time::OffsetDateTime::now_utc()),
            };
            let key = entry.key();
            if let Some(existing) = overrides.entries.iter_mut().find(|e| e.key() == key) {
                *existing = entry;
            } else {
                overrides.entries.push(entry);
            }
            storage::save_vendor_overrides(&ws, &overrides)?;
            println!("vendor override saved");
            Ok(0)
        }
    }
}

fn cmd_report(workspace_root: &std::path::Path, args: &crate::cli::ReportArgs) -> Result<i32> {
    let ws = Workspace::open(workspace_root)?;
    let format = args.format.to_ascii_lowercase();
    let default_name = match format.as_str() {
        "json" => "report.json",
        "cbom" => "bom.cdx.json",
        "md" => "readiness.md",
        other => return Err(anyhow!("unknown report format: {}", other)),
    };
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| ws.reports_dir().join(default_name));

    match format.as_str() {
        "json" => crate::report::json::write(&ws, &out_path)?,
        "cbom" => crate::report::cbom::write(&ws, &out_path)?,
        "md" => crate::report::markdown::write(&ws, &out_path)?,
        _ => unreachable!(),
    }
    println!("wrote {} report to {}", format, out_path.display());
    Ok(0)
}

fn cmd_config(workspace_root: &std::path::Path, sub: &ConfigCommand) -> Result<i32> {
    let ws = Workspace::open(workspace_root)?;
    match sub {
        ConfigCommand::Get(args) => {
            let cfg = config::load(&ws)?;
            match config::get_value(&cfg, &args.key) {
                Some(v) => println!("{}", v),
                None => return Err(anyhow!("unknown config key: {}", args.key)),
            }
            Ok(0)
        }
        ConfigCommand::Set(args) => {
            let mut cfg = config::load(&ws)?;
            config::set_value(&mut cfg, &args.key, &args.value)?;
            config::save(&ws, &cfg)?;
            println!("{} = {}", args.key, args.value);
            Ok(0)
        }
    }
}
