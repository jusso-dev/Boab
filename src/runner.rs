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

fn cmd_scan(_workspace_root: &std::path::Path, sub: &ScanCommand) -> Result<i32> {
    let name = match sub {
        ScanCommand::Codebase(_) => "scan codebase",
        ScanCommand::Tls(_) => "scan tls",
        ScanCommand::Certs(_) => "scan certs",
    };
    eprintln!("{}: not yet implemented", name);
    Ok(EXIT_NOT_IMPLEMENTED)
}

fn cmd_plan(_workspace_root: &std::path::Path, sub: &PlanCommand) -> Result<i32> {
    let name = match sub {
        PlanCommand::Generate(_) => "plan generate",
        PlanCommand::List => "plan list",
        PlanCommand::Show(_) => "plan show",
        PlanCommand::Regenerate(_) => "plan regenerate",
    };
    eprintln!("{}: not yet implemented", name);
    Ok(EXIT_NOT_IMPLEMENTED)
}

fn cmd_vendor(_workspace_root: &std::path::Path, sub: &VendorCommand) -> Result<i32> {
    let name = match sub {
        VendorCommand::List => "vendor list",
        VendorCommand::Add(_) => "vendor add",
        VendorCommand::Search(_) => "vendor search",
    };
    eprintln!("{}: not yet implemented", name);
    Ok(EXIT_NOT_IMPLEMENTED)
}

fn cmd_report(_workspace_root: &std::path::Path, _args: &crate::cli::ReportArgs) -> Result<i32> {
    eprintln!("report: not yet implemented");
    Ok(EXIT_NOT_IMPLEMENTED)
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
