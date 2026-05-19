//! Clap definitions for the Boab CLI.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Boab: PQC readiness CLI for ASD-aligned transition planning.
#[derive(Debug, Parser)]
#[command(
    name = "boab",
    version,
    about = "PQC readiness CLI for ASD-aligned transition planning",
    propagate_version = true
)]
pub struct Cli {
    /// Workspace root directory (default: current directory).
    #[arg(long, global = true, default_value = ".")]
    pub workspace: PathBuf,

    /// Increase log verbosity to DEBUG.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Reduce log verbosity to ERROR.
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Disable progress bars and spinners.
    #[arg(long, global = true)]
    pub no_progress: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialise a Boab workspace in the current directory.
    Init(InitArgs),
    /// Manage business systems.
    #[command(subcommand)]
    System(SystemCommand),
    /// Manage the deduplicated cryptographic inventory.
    #[command(subcommand)]
    Inventory(InventoryCommand),
    /// Scan codebases, TLS endpoints, or certificate stores.
    #[command(subcommand)]
    Scan(ScanCommand),
    /// Generate and inspect transition plans.
    #[command(subcommand)]
    Plan(PlanCommand),
    /// Inspect the bundled vendor PQC registry and customer overrides.
    #[command(subcommand)]
    Vendor(VendorCommand),
    /// Export the workspace state as JSON, CycloneDX 1.6 CBOM, or Markdown.
    Report(ReportArgs),
    /// Get or set workspace configuration values.
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Remove and recreate the workspace if it exists. Requires --yes.
    #[arg(long)]
    pub force: bool,
    /// Confirm destructive operations.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum SystemCommand {
    /// Add a new system.
    Add(SystemAddArgs),
    /// List all systems.
    List,
    /// Edit fields on an existing system.
    Edit(SystemEditArgs),
    /// Delete a system by id.
    Delete(SystemDeleteArgs),
}

#[derive(Debug, Args)]
pub struct SystemAddArgs {
    /// Human-readable name.
    #[arg(long)]
    pub name: String,
    /// Free-text description.
    #[arg(long)]
    pub description: Option<String>,
    /// ASD ISM classification: unofficial, official, official_sensitive, protected, secret, top_secret.
    #[arg(long, default_value = "official")]
    pub classification: String,
    /// Business criticality: low, standard, essential, mission_critical.
    #[arg(long, default_value = "standard")]
    pub criticality: String,
    /// Flag the system as a SOCI critical asset.
    #[arg(long)]
    pub soci: bool,
    /// Expected data lifetime in years (used for HNDL scoring).
    #[arg(long)]
    pub lifetime_years: Option<u16>,
}

#[derive(Debug, Args)]
pub struct SystemEditArgs {
    /// System id to edit.
    #[arg(long)]
    pub id: uuid::Uuid,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub classification: Option<String>,
    #[arg(long)]
    pub criticality: Option<String>,
    #[arg(long)]
    pub soci: Option<bool>,
    #[arg(long)]
    pub lifetime_years: Option<u16>,
}

#[derive(Debug, Args)]
pub struct SystemDeleteArgs {
    /// System id to delete.
    pub id: uuid::Uuid,
}

#[derive(Debug, Subcommand)]
pub enum InventoryCommand {
    /// List inventory entries with optional filters.
    List(InventoryListArgs),
    /// Show a single inventory entry by id.
    Show(InventoryShowArgs),
}

#[derive(Debug, Args)]
pub struct InventoryListArgs {
    #[arg(long)]
    pub pqc_status: Option<String>,
    #[arg(long)]
    pub tier: Option<u8>,
    #[arg(long)]
    pub system: Option<uuid::Uuid>,
    #[arg(long)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Args)]
pub struct InventoryShowArgs {
    pub id: uuid::Uuid,
}

#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Scan a codebase directory or git repository.
    Codebase(ScanCodebaseArgs),
    /// Scan one or more TLS endpoints.
    Tls(ScanTlsArgs),
    /// Scan a directory of certificate files.
    Certs(ScanCertsArgs),
}

#[derive(Debug, Args)]
pub struct ScanCodebaseArgs {
    /// Path to scan. Ignored when --git is provided.
    pub path: Option<PathBuf>,
    /// Clone and scan this git URL into a temporary directory.
    #[arg(long)]
    pub git: Option<String>,
    /// Additional include globs (in addition to defaults).
    #[arg(long)]
    pub include: Vec<String>,
    /// Additional exclude globs (in addition to defaults).
    #[arg(long)]
    pub exclude: Vec<String>,
    /// Name for the scan record.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct ScanTlsArgs {
    /// Target host:port pairs. May be given multiple times.
    pub targets: Vec<String>,
    /// File containing target host:port lines.
    #[arg(long)]
    pub targets_file: Option<PathBuf>,
    /// Rate limit, e.g. "1/second".
    #[arg(long)]
    pub rate_limit: Option<String>,
    /// Connection timeout in seconds.
    #[arg(long, default_value_t = 10u64)]
    pub timeout_seconds: u64,
    /// Probe HSTS via an HTTP GET. Forbidden in air-gapped mode.
    #[arg(long)]
    pub probe_hsts: bool,
    /// Targets to exclude (host:port).
    #[arg(long)]
    pub exclude: Vec<String>,
    /// Name for the scan record.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct ScanCertsArgs {
    /// Directory containing certificate files.
    pub path: PathBuf,
    /// Path to a file containing the keystore password.
    #[arg(long)]
    pub password_file: Option<PathBuf>,
    /// Name for the scan record.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PlanCommand {
    /// Generate a transition plan for a milestone.
    Generate(PlanGenerateArgs),
    /// List plans in the workspace.
    List,
    /// Show a plan by id.
    Show(PlanShowArgs),
    /// Regenerate a plan, preserving user edits where assets are unchanged.
    Regenerate(PlanRegenerateArgs),
}

#[derive(Debug, Args)]
pub struct PlanGenerateArgs {
    /// Target ASD milestone year: 2026, 2028, or 2030.
    #[arg(long)]
    pub milestone: String,
    /// Optional plan name.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct PlanShowArgs {
    pub id: uuid::Uuid,
}

#[derive(Debug, Args)]
pub struct PlanRegenerateArgs {
    pub id: uuid::Uuid,
}

#[derive(Debug, Subcommand)]
pub enum VendorCommand {
    /// List the merged vendor registry.
    List,
    /// Add or override a vendor entry.
    Add(VendorAddArgs),
    /// Search the vendor registry.
    Search(VendorSearchArgs),
}

#[derive(Debug, Args)]
pub struct VendorAddArgs {
    #[arg(long)]
    pub vendor: String,
    #[arg(long)]
    pub product: String,
    #[arg(long)]
    pub pqc_status: String,
    #[arg(long)]
    pub target_date: Option<String>,
    #[arg(long)]
    pub source_url: Option<String>,
    #[arg(long)]
    pub source_note: Option<String>,
}

#[derive(Debug, Args)]
pub struct VendorSearchArgs {
    pub term: String,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Output format: json, cbom, or md.
    #[arg(long)]
    pub format: String,
    /// Output path. Defaults to .boab/reports/.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Get a config value by dotted key.
    Get(ConfigGetArgs),
    /// Set a config value by dotted key.
    Set(ConfigSetArgs),
}

#[derive(Debug, Args)]
pub struct ConfigGetArgs {
    pub key: String,
}

#[derive(Debug, Args)]
pub struct ConfigSetArgs {
    pub key: String,
    pub value: String,
}
