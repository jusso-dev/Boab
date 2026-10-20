# Generated from the Rust binary's clap output (non-tty, 100 columns). Do not edit by hand.
$script:BoabCliHelp = @{
    '' = @{
        Usage = 'boab [OPTIONS] <COMMAND>'
        Help  = @'
PQC readiness CLI for ASD-aligned transition planning

Usage: boab [OPTIONS] <COMMAND>

Commands:
  init       Initialise a Boab workspace in the current directory
  system     Manage business systems
  inventory  Manage the deduplicated cryptographic inventory
  scan       Scan codebases, TLS endpoints, or certificate stores
  plan       Generate and inspect transition plans
  vendor     Inspect the bundled vendor PQC registry and customer overrides
  report     Export the workspace state as JSON, CycloneDX 1.6 CBOM, or Markdown
  config     Get or set workspace configuration values
  help       Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'init' = @{
        Usage = 'boab init [OPTIONS]'
        Help  = @'
Initialise a Boab workspace in the current directory

Usage: boab init [OPTIONS]

Options:
      --force                  Remove and recreate the workspace if it exists. Requires --yes
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --yes                    Confirm destructive operations
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'system' = @{
        Usage = 'boab system [OPTIONS] <COMMAND>'
        Help  = @'
Manage business systems

Usage: boab system [OPTIONS] <COMMAND>

Commands:
  add     Add a new system
  list    List all systems
  edit    Edit fields on an existing system
  delete  Delete a system by id
  help    Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'system add' = @{
        Usage = 'boab system add [OPTIONS] --name <NAME>'
        Help  = @'
Add a new system

Usage: boab system add [OPTIONS] --name <NAME>

Options:
      --name <NAME>
          Human-readable name
      --workspace <WORKSPACE>
          Workspace root directory (default: current directory) [default: .]
      --description <DESCRIPTION>
          Free-text description
      --verbose
          Increase log verbosity to DEBUG
      --classification <CLASSIFICATION>
          ASD ISM classification: unofficial, official, official_sensitive, protected, secret,
          top_secret [default: official]
      --quiet
          Reduce log verbosity to ERROR
      --criticality <CRITICALITY>
          Business criticality: low, standard, essential, mission_critical [default: standard]
      --no-progress
          Disable progress bars and spinners
      --soci
          Flag the system as a SOCI critical asset
      --lifetime-years <LIFETIME_YEARS>
          Expected data lifetime in years (used for HNDL scoring)
  -h, --help
          Print help
  -V, --version
          Print version
'@
    }
    'system list' = @{
        Usage = 'boab system list [OPTIONS]'
        Help  = @'
List all systems

Usage: boab system list [OPTIONS]

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'system edit' = @{
        Usage = 'boab system edit [OPTIONS] --id <ID>'
        Help  = @'
Edit fields on an existing system

Usage: boab system edit [OPTIONS] --id <ID>

Options:
      --id <ID>
          System id to edit
      --workspace <WORKSPACE>
          Workspace root directory (default: current directory) [default: .]
      --name <NAME>
          
      --verbose
          Increase log verbosity to DEBUG
      --description <DESCRIPTION>
          
      --quiet
          Reduce log verbosity to ERROR
      --classification <CLASSIFICATION>
          
      --no-progress
          Disable progress bars and spinners
      --criticality <CRITICALITY>
          
      --soci <SOCI>
          [possible values: true, false]
      --lifetime-years <LIFETIME_YEARS>
          
  -h, --help
          Print help
  -V, --version
          Print version
'@
    }
    'system delete' = @{
        Usage = 'boab system delete [OPTIONS] <ID>'
        Help  = @'
Delete a system by id

Usage: boab system delete [OPTIONS] <ID>

Arguments:
  <ID>  System id to delete

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'inventory' = @{
        Usage = 'boab inventory [OPTIONS] <COMMAND>'
        Help  = @'
Manage the deduplicated cryptographic inventory

Usage: boab inventory [OPTIONS] <COMMAND>

Commands:
  list  List inventory entries with optional filters
  show  Show a single inventory entry by id
  help  Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'inventory list' = @{
        Usage = 'boab inventory list [OPTIONS]'
        Help  = @'
List inventory entries with optional filters

Usage: boab inventory list [OPTIONS]

Options:
      --pqc-status <PQC_STATUS>  
      --workspace <WORKSPACE>    Workspace root directory (default: current directory) [default: .]
      --tier <TIER>              
      --verbose                  Increase log verbosity to DEBUG
      --quiet                    Reduce log verbosity to ERROR
      --system <SYSTEM>          
      --algorithm <ALGORITHM>    
      --no-progress              Disable progress bars and spinners
  -h, --help                     Print help
  -V, --version                  Print version
'@
    }
    'inventory show' = @{
        Usage = 'boab inventory show [OPTIONS] <ID>'
        Help  = @'
Show a single inventory entry by id

Usage: boab inventory show [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'scan' = @{
        Usage = 'boab scan [OPTIONS] <COMMAND>'
        Help  = @'
Scan codebases, TLS endpoints, or certificate stores

Usage: boab scan [OPTIONS] <COMMAND>

Commands:
  codebase  Scan a codebase directory or git repository
  tls       Scan one or more TLS endpoints
  certs     Scan a directory of certificate files
  help      Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'scan codebase' = @{
        Usage = 'boab scan codebase [OPTIONS] [PATH]'
        Help  = @'
Scan a codebase directory or git repository

Usage: boab scan codebase [OPTIONS] [PATH]

Arguments:
  [PATH]  Path to scan. Ignored when --git is provided

Options:
      --git <GIT>              Clone and scan this git URL into a temporary directory
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --include <INCLUDE>      Additional include globs (in addition to defaults)
      --verbose                Increase log verbosity to DEBUG
      --exclude <EXCLUDE>      Additional exclude globs (in addition to defaults)
      --quiet                  Reduce log verbosity to ERROR
      --name <NAME>            Name for the scan record
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'scan tls' = @{
        Usage = 'boab scan tls [OPTIONS] [TARGETS]...'
        Help  = @'
Scan one or more TLS endpoints

Usage: boab scan tls [OPTIONS] [TARGETS]...

Arguments:
  [TARGETS]...  Target host:port pairs. May be given multiple times

Options:
      --targets-file <TARGETS_FILE>
          File containing target host:port lines
      --workspace <WORKSPACE>
          Workspace root directory (default: current directory) [default: .]
      --rate-limit <RATE_LIMIT>
          Rate limit, e.g. "1/second"
      --verbose
          Increase log verbosity to DEBUG
      --quiet
          Reduce log verbosity to ERROR
      --timeout-seconds <TIMEOUT_SECONDS>
          Connection timeout in seconds [default: 10]
      --no-progress
          Disable progress bars and spinners
      --probe-hsts
          Probe HSTS via an HTTP GET. Forbidden in air-gapped mode
      --exclude <EXCLUDE>
          Targets to exclude (host:port)
      --name <NAME>
          Name for the scan record
  -h, --help
          Print help
  -V, --version
          Print version
'@
    }
    'scan certs' = @{
        Usage = 'boab scan certs [OPTIONS] <PATH>'
        Help  = @'
Scan a directory of certificate files

Usage: boab scan certs [OPTIONS] <PATH>

Arguments:
  <PATH>  Directory containing certificate files

Options:
      --password-file <PASSWORD_FILE>  Path to a file containing the keystore password
      --workspace <WORKSPACE>          Workspace root directory (default: current directory)
                                       [default: .]
      --name <NAME>                    Name for the scan record
      --verbose                        Increase log verbosity to DEBUG
      --quiet                          Reduce log verbosity to ERROR
      --no-progress                    Disable progress bars and spinners
  -h, --help                           Print help
  -V, --version                        Print version
'@
    }
    'plan' = @{
        Usage = 'boab plan [OPTIONS] <COMMAND>'
        Help  = @'
Generate and inspect transition plans

Usage: boab plan [OPTIONS] <COMMAND>

Commands:
  generate    Generate a transition plan for a milestone
  list        List plans in the workspace
  show        Show a plan by id
  regenerate  Regenerate a plan, preserving user edits where assets are unchanged
  help        Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'plan generate' = @{
        Usage = 'boab plan generate [OPTIONS] --milestone <MILESTONE>'
        Help  = @'
Generate a transition plan for a milestone

Usage: boab plan generate [OPTIONS] --milestone <MILESTONE>

Options:
      --milestone <MILESTONE>  Target ASD milestone year: 2026, 2028, or 2030
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --name <NAME>            Optional plan name
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'plan list' = @{
        Usage = 'boab plan list [OPTIONS]'
        Help  = @'
List plans in the workspace

Usage: boab plan list [OPTIONS]

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'plan show' = @{
        Usage = 'boab plan show [OPTIONS] <ID>'
        Help  = @'
Show a plan by id

Usage: boab plan show [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'plan regenerate' = @{
        Usage = 'boab plan regenerate [OPTIONS] <ID>'
        Help  = @'
Regenerate a plan, preserving user edits where assets are unchanged

Usage: boab plan regenerate [OPTIONS] <ID>

Arguments:
  <ID>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'vendor' = @{
        Usage = 'boab vendor [OPTIONS] <COMMAND>'
        Help  = @'
Inspect the bundled vendor PQC registry and customer overrides

Usage: boab vendor [OPTIONS] <COMMAND>

Commands:
  list    List the merged vendor registry
  add     Add or override a vendor entry
  search  Search the vendor registry
  help    Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'vendor list' = @{
        Usage = 'boab vendor list [OPTIONS]'
        Help  = @'
List the merged vendor registry

Usage: boab vendor list [OPTIONS]

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'vendor add' = @{
        Usage = 'boab vendor add [OPTIONS] --vendor <VENDOR> --product <PRODUCT> --pqc-status <PQC_STATUS>'
        Help  = @'
Add or override a vendor entry

Usage: boab vendor add [OPTIONS] --vendor <VENDOR> --product <PRODUCT> --pqc-status <PQC_STATUS>

Options:
      --vendor <VENDOR>            
      --workspace <WORKSPACE>      Workspace root directory (default: current directory) [default:
                                   .]
      --product <PRODUCT>          
      --verbose                    Increase log verbosity to DEBUG
      --pqc-status <PQC_STATUS>    
      --quiet                      Reduce log verbosity to ERROR
      --no-progress                Disable progress bars and spinners
      --target-date <TARGET_DATE>  
      --source-url <SOURCE_URL>    
      --source-note <SOURCE_NOTE>  
  -h, --help                       Print help
  -V, --version                    Print version
'@
    }
    'vendor search' = @{
        Usage = 'boab vendor search [OPTIONS] <TERM>'
        Help  = @'
Search the vendor registry

Usage: boab vendor search [OPTIONS] <TERM>

Arguments:
  <TERM>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'report' = @{
        Usage = 'boab report [OPTIONS] --format <FORMAT>'
        Help  = @'
Export the workspace state as JSON, CycloneDX 1.6 CBOM, or Markdown

Usage: boab report [OPTIONS] --format <FORMAT>

Options:
      --format <FORMAT>        Output format: json, cbom, or md
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
  -o, --output <OUTPUT>        Output path. Defaults to .boab/reports/
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'config' = @{
        Usage = 'boab config [OPTIONS] <COMMAND>'
        Help  = @'
Get or set workspace configuration values

Usage: boab config [OPTIONS] <COMMAND>

Commands:
  get   Get a config value by dotted key
  set   Set a config value by dotted key
  help  Print this message or the help of the given subcommand(s)

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'config get' = @{
        Usage = 'boab config get [OPTIONS] <KEY>'
        Help  = @'
Get a config value by dotted key

Usage: boab config get [OPTIONS] <KEY>

Arguments:
  <KEY>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'config set' = @{
        Usage = 'boab config set [OPTIONS] <KEY> <VALUE>'
        Help  = @'
Set a config value by dotted key

Usage: boab config set [OPTIONS] <KEY> <VALUE>

Arguments:
  <KEY>    
  <VALUE>  

Options:
      --workspace <WORKSPACE>  Workspace root directory (default: current directory) [default: .]
      --verbose                Increase log verbosity to DEBUG
      --quiet                  Reduce log verbosity to ERROR
      --no-progress            Disable progress bars and spinners
  -h, --help                   Print help
  -V, --version                Print version
'@
    }
    'help' = @{
        Usage = 'boab help [COMMAND]...'
        Help  = @'
Print this message or the help of the given subcommand(s)

Usage: boab help [COMMAND]...

Arguments:
  [COMMAND]...  Print help for the subcommand(s)
'@
    }
}
