#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Port of tests/integration.rs plus clap-compatibility checks of the argument
# parser (texts captured from the Rust binary).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
}

Describe 'integration.rs' {
    BeforeEach {
        $script:Tmp = New-BoabTestDirectory
    }
    AfterEach {
        Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'init creates the workspace layout' {
        $r = Invoke-BoabTest --workspace $script:Tmp init
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly "workspace initialised at $($script:Tmp)/.boab`n"
        $dir = Join-Path $script:Tmp '.boab'
        Test-Path -LiteralPath $dir -PathType Container | Should -BeTrue
        foreach ($f in 'config.toml', 'systems.json', 'inventory.json', 'vendor-overrides.json') {
            Test-Path -LiteralPath (Join-Path $dir $f) -PathType Leaf | Should -BeTrue
        }
        foreach ($d in 'scans', 'plans', 'reports') {
            Test-Path -LiteralPath (Join-Path $dir $d) -PathType Container | Should -BeTrue
        }
        [System.IO.File]::ReadAllText((Join-Path $dir 'systems.json')) | Should -BeExactly "[]`n"
        [System.IO.File]::ReadAllText((Join-Path $dir 'vendor-overrides.json')) | Should -BeExactly "{`"entries`":[]}`n"
        [System.IO.File]::ReadAllText((Join-Path $dir 'config.toml')) | Should -BeExactly "# Boab configuration`n`nschema_version = 1`n`n[scanner]`ndefault_rate_limit = `"1/second`"`ntls_timeout_seconds = 10`nair_gapped = true`n`n[reporting]`ndefault_format = `"md`"`n"
    }

    It 'init is idempotent and --force requires --yes' {
        (Invoke-BoabTest --workspace $script:Tmp init).ExitCode | Should -Be 0
        $r = Invoke-BoabTest --workspace $script:Tmp init
        $r.StdOut | Should -BeExactly "workspace already initialised`n"
        $r = Invoke-BoabTest --workspace $script:Tmp init --force
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -BeExactly "error: --force requires --yes`n"
        $r = Invoke-BoabTest --workspace $script:Tmp init --force --yes
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly "workspace initialised at $($script:Tmp)/.boab`n"
    }

    It 'system add then list round-trips' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $script:Tmp system add --name Payments --classification protected --criticality mission_critical --soci --lifetime-years 25
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match '^added system Payments \([0-9a-f-]{36}\)\n$'
        $r = Invoke-BoabTest --workspace $script:Tmp system list
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match 'Payments'
        $r.StdOut | Should -Match 'protected'
        $r.StdOut | Should -Match 'mission_critical'
        $lines = $r.StdOut.TrimEnd("`n").Split("`n")
        $lines.Count | Should -Be 5
        $lines[1] | Should -Match '^│ ID {35}┆ NAME {5}┆ CLASS {5}┆ CRIT {13}┆ SOCI ┆ LIFETIME │$'
        $lines[3] | Should -Match '^│ [0-9a-f-]{36} ┆ Payments ┆ protected ┆ mission_critical ┆ yes  ┆ 25y      │$'
        $lines[0] | Should -BeExactly ('┌' + ('─' * 38) + '┬' + ('─' * 10) + '┬' + ('─' * 11) + '┬' + ('─' * 18) + '┬' + ('─' * 6) + '┬' + ('─' * 10) + '┐')
    }

    It 'system edit and delete' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $script:Tmp system add --name HR
        $id = ([regex]::Match($r.StdOut, '[0-9a-f-]{36}')).Value
        $r = Invoke-BoabTest --workspace $script:Tmp system edit --id $id --soci true --name 'Human Resources' --lifetime-years 7
        $r.StdOut | Should -BeExactly "updated system $id`n"
        $sys = Get-BoabSystem -Workspace $script:Tmp
        $sys.name | Should -BeExactly 'Human Resources'
        $sys.is_soci | Should -BeTrue
        $sys.expected_data_lifetime_years | Should -Be 7
        $r = Invoke-BoabTest --workspace $script:Tmp system delete $id
        $r.StdOut | Should -BeExactly "deleted system $id`n"
        $r = Invoke-BoabTest --workspace $script:Tmp system delete $id
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -BeExactly "error: no system with id $id`n"
        (Invoke-BoabTest --workspace $script:Tmp system list).StdOut | Should -BeExactly "(no systems)`n"
    }

    It 'inventory list on an empty workspace says so' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        (Invoke-BoabTest --workspace $script:Tmp inventory list).StdOut | Should -BeExactly "(no inventory entries)`n"
    }

    It 'config get and set' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $script:Tmp config set scanner.tls_timeout_seconds 30
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly "scanner.tls_timeout_seconds = 30`n"
        (Invoke-BoabTest --workspace $script:Tmp config get scanner.tls_timeout_seconds).StdOut | Should -BeExactly "30`n"
        [System.IO.File]::ReadAllText((Join-Path $script:Tmp '.boab' 'config.toml')) |
            Should -BeExactly "schema_version = 1`n`n[scanner]`ndefault_rate_limit = `"1/second`"`ntls_timeout_seconds = 30`nair_gapped = true`n`n[reporting]`ndefault_format = `"md`"`n"
        $r = Invoke-BoabTest --workspace $script:Tmp config get foo
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -BeExactly "error: unknown config key: foo`n"
        $r = Invoke-BoabTest --workspace $script:Tmp config set scanner.air_gapped maybe
        $r.StdErr | Should -BeExactly "error: air_gapped must be true or false: provided string was not ``true`` or ``false```n"
    }

    It 'report on an empty workspace still emits a file' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $script:Tmp report --format json
        $r.ExitCode | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:Tmp '.boab' 'reports' 'report.json') | Should -BeTrue
        $r.StdOut | Should -Match '^wrote json report to .+report\.json\n$'
    }

    It 'plan list on an empty workspace says so' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        (Invoke-BoabTest --workspace $script:Tmp plan list).StdOut | Should -BeExactly "(no plans)`n"
    }

    It 'errors when the workspace is not initialised' {
        $r = Invoke-BoabTest --workspace $script:Tmp system list
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -Match '^error: workspace not initialised: .+\.boab is missing\. Run `boab init` first\.\n$'
    }

    It 'errors when the workspace path does not exist' {
        $missing = Join-Path $script:Tmp 'nope'
        $r = Invoke-BoabTest --workspace $missing system list
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -BeLike "error: could not resolve workspace path $missing*"
    }

    It 'reports runtime validation errors with exit code 1' {
        Invoke-BoabTest --workspace $script:Tmp init | Out-Null
        (Invoke-BoabTest --workspace $script:Tmp plan generate --milestone 2027).StdErr | Should -BeExactly "error: milestone must be one of 2026, 2028, 2030`n"
        (Invoke-BoabTest --workspace $script:Tmp system add --name x --classification foo).StdErr | Should -BeExactly "error: unknown classification: foo`n"
        (Invoke-BoabTest --workspace $script:Tmp vendor add --vendor a --product b --pqc-status zz).StdErr | Should -BeExactly "error: unknown pqc_status: zz (expected vulnerable|hybrid|resistant|symmetric_ok|unknown)`n"
        (Invoke-BoabTest --workspace $script:Tmp report --format html).StdErr | Should -BeExactly "error: unknown report format: html`n"
        (Invoke-BoabTest --workspace $script:Tmp inventory show 00000000-0000-0000-0000-000000000000).StdErr | Should -BeExactly "error: no inventory entry with id 00000000-0000-0000-0000-000000000000`n"
        (Invoke-BoabTest --workspace $script:Tmp scan codebase).StdErr | Should -BeExactly "error: missing path or --git URL`n"
        (Invoke-BoabTest --workspace $script:Tmp scan tls).StdErr | Should -BeExactly "error: no TLS targets specified; pass host:port or --targets-file`n"
        (Invoke-BoabTest --workspace $script:Tmp vendor search zzz).StdOut | Should -BeExactly "(no matches for zzz)`n"
        $r = Invoke-BoabTest --workspace $script:Tmp scan codebase --git https://example.com/repo.git
        $r.ExitCode | Should -Be 64
        $r.StdErr | Should -BeExactly "git cloning is not yet implemented; pass a local path instead`n"
        $r = Invoke-BoabTest --workspace $script:Tmp plan show 00000000-0000-0000-0000-000000000000
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -BeLike 'error: read *00000000-0000-0000-0000-000000000000.json: *'
    }
}

Describe 'clap-compatible argument parsing' {
    It 'prints top-level help and version' {
        $r = Invoke-BoabTest --help
        $r.ExitCode | Should -Be 0
        $r.StdOut.StartsWith("PQC readiness CLI for ASD-aligned transition planning`n`nUsage: boab [OPTIONS] <COMMAND>`n", [StringComparison]::Ordinal) | Should -BeTrue
        $r.StdOut | Should -Match '  -V, --version                Print version\n$'
        (Invoke-BoabTest -V).StdOut | Should -BeExactly "boab 0.1.0`n"
        (Invoke-BoabTest system add -V).StdOut | Should -BeExactly "boab-system-add 0.1.0`n"
        (Invoke-BoabTest help system add).StdOut | Should -BeExactly (Invoke-BoabTest system add --help).StdOut
    }

    It 'prints help to stderr with exit code 2 when a subcommand is missing' {
        $r = Invoke-BoabTest system
        $r.ExitCode | Should -Be 2
        $r.StdOut | Should -BeExactly ''
        $r.StdErr | Should -BeLike "Manage business systems`n`nUsage: boab system *"
        (Invoke-BoabTest).ExitCode | Should -Be 2
    }

    It 'reproduces clap error text for <Name>' -ForEach @(
        @{ Name = 'missing required'; Argv = @('system', 'add'); Err = "error: the following required arguments were not provided:`n  --name <NAME>`n`nUsage: boab system add --name <NAME>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'missing several'; Argv = @('vendor', 'add'); Err = "error: the following required arguments were not provided:`n  --vendor <VENDOR>`n  --product <PRODUCT>`n  --pqc-status <PQC_STATUS>`n`nUsage: boab vendor add --vendor <VENDOR> --product <PRODUCT> --pqc-status <PQC_STATUS>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'missing positional'; Argv = @('config', 'set', 'a'); Err = "error: the following required arguments were not provided:`n  <VALUE>`n`nUsage: boab config set <KEY> <VALUE>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'unknown subcommand'; Argv = @('frob'); Err = "error: unrecognized subcommand 'frob'`n`nUsage: boab [OPTIONS] <COMMAND>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'subcommand typo'; Argv = @('ini'); Err = "error: unrecognized subcommand 'ini'`n`n  tip: a similar subcommand exists: 'init'`n`nUsage: boab [OPTIONS] <COMMAND>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'nested subcommand typo'; Argv = @('system', 'lst'); Err = "error: unrecognized subcommand 'lst'`n`n  tip: a similar subcommand exists: 'list'`n`nUsage: boab system [OPTIONS] <COMMAND>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'argument typo'; Argv = @('system', 'add', '--nam', 'x'); Err = "error: unexpected argument '--nam' found`n`n  tip: a similar argument exists: '--name'`n`nUsage: boab system add --name <NAME>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'optional argument typo'; Argv = @('system', 'add', '--name', 'x', '--descriptio', 'y'); Err = "error: unexpected argument '--descriptio' found`n`n  tip: a similar argument exists: '--description'`n`nUsage: boab system add --name <NAME> --description <DESCRIPTION>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'global typo'; Argv = @('--verbos', 'init'); Err = "error: unexpected argument '--verbos' found`n`n  tip: a similar argument exists: '--verbose'`n`nUsage: boab --verbose <COMMAND>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'positional suggestion usage'; Argv = @('scan', 'tls', '--exclud'); Err = "error: unexpected argument '--exclud' found`n`n  tip: a similar argument exists: '--exclude'`n`nUsage: boab scan tls --exclude <EXCLUDE> [TARGETS]...`n`nFor more information, try '--help'.`n" }
        @{ Name = 'unknown flag'; Argv = @('system', 'list', '--bogus'); Err = "error: unexpected argument '--bogus' found`n`nUsage: boab system list [OPTIONS]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'unknown short'; Argv = @('report', '-x'); Err = "error: unexpected argument '-x' found`n`nUsage: boab report [OPTIONS] --format <FORMAT>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'extra positional'; Argv = @('init', 'extra'); Err = "error: unexpected argument 'extra' found`n`nUsage: boab init [OPTIONS]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'negative number'; Argv = @('config', 'set', 'schema_version', '-1'); Err = "error: unexpected argument '-1' found`n`n  tip: to pass '-1' as a value, use '-- -1'`n`nUsage: boab config set [OPTIONS] <KEY> <VALUE>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'negative option value'; Argv = @('inventory', 'list', '--tier', '-1'); Err = "error: unexpected argument '-1' found`n`nUsage: boab inventory list [OPTIONS]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'bad uuid'; Argv = @('system', 'delete', 'not-a-uuid'); Err = "error: invalid value 'not-a-uuid' for '<ID>': invalid character: found ``n`` at 0`n`nFor more information, try '--help'.`n" }
        @{ Name = 'short uuid'; Argv = @('system', 'delete', 'abc'); Err = "error: invalid value 'abc' for '<ID>': invalid length: expected length 32 for simple format, found 3`n`nFor more information, try '--help'.`n" }
        @{ Name = 'uuid group length'; Argv = @('system', 'delete', '336c086c-f5d0-4e01-854b-40dafc4f404'); Err = "error: invalid value '336c086c-f5d0-4e01-854b-40dafc4f404' for '<ID>': invalid group length in group 4: expected 12, found 11`n`nFor more information, try '--help'.`n" }
        @{ Name = 'uuid group count'; Argv = @('system', 'delete', '336c086c-f5d0-4e01-854b'); Err = "error: invalid value '336c086c-f5d0-4e01-854b' for '<ID>': invalid group count: expected 5, found 4`n`nFor more information, try '--help'.`n" }
        @{ Name = 'uuid trailing char'; Argv = @('system', 'delete', '336c086c-f5d0-4e01-854b-40dafc4f404dx'); Err = "error: invalid value '336c086c-f5d0-4e01-854b-40dafc4f404dx' for '<ID>': invalid character: found ``x`` at 36`n`nFor more information, try '--help'.`n" }
        @{ Name = 'u16 range'; Argv = @('system', 'add', '--name', 'x', '--lifetime-years', '70000'); Err = "error: invalid value '70000' for '--lifetime-years <LIFETIME_YEARS>': 70000 is not in 0..=65535`n`nFor more information, try '--help'.`n" }
        @{ Name = 'u16 digits'; Argv = @('system', 'add', '--name', 'x', '--lifetime-years', 'abc'); Err = "error: invalid value 'abc' for '--lifetime-years <LIFETIME_YEARS>': invalid digit found in string`n`nFor more information, try '--help'.`n" }
        @{ Name = 'u8 range'; Argv = @('inventory', 'list', '--tier', '300'); Err = "error: invalid value '300' for '--tier <TIER>': 300 is not in 0..=255`n`nFor more information, try '--help'.`n" }
        @{ Name = 'u64 overflow'; Argv = @('scan', 'tls', '--timeout-seconds', '99999999999999999999999'); Err = "error: invalid value '99999999999999999999999' for '--timeout-seconds <TIMEOUT_SECONDS>': number too large to fit in target type`n`nFor more information, try '--help'.`n" }
        @{ Name = 'bool value'; Argv = @('system', 'edit', '--id', '336c086c-f5d0-4e01-854b-40dafc4f404d', '--soci', 'TRUE'); Err = "error: invalid value 'TRUE' for '--soci <SOCI>'`n  [possible values: true, false]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'missing bool value'; Argv = @('system', 'edit', '--id', '336c086c-f5d0-4e01-854b-40dafc4f404d', '--soci'); Err = "error: a value is required for '--soci <SOCI>' but none was supplied`n  [possible values: true, false]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'missing value'; Argv = @('system', 'add', '--name', '--soci'); Err = "error: a value is required for '--name <NAME>' but none was supplied`n`nFor more information, try '--help'.`n" }
        @{ Name = 'missing short value'; Argv = @('report', '-o'); Err = "error: a value is required for '--output <OUTPUT>' but none was supplied`n`nFor more information, try '--help'.`n" }
        @{ Name = 'empty path'; Argv = @('report', '--output', ''); Err = "error: a value is required for '--output <OUTPUT>' but none was supplied`n`nFor more information, try '--help'.`n" }
        @{ Name = 'flag repeated'; Argv = @('init', '--force', '--yes', '--force'); Err = "error: the argument '--force' cannot be used multiple times`n`nUsage: boab init [OPTIONS]`n`nFor more information, try '--help'.`n" }
        @{ Name = 'option repeated'; Argv = @('system', 'add', '--name', 'a', '--name', 'b'); Err = "error: the argument '--name <NAME>' cannot be used multiple times`n`nUsage: boab system add [OPTIONS] --name <NAME>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'flag with value'; Argv = @('init', '--force=1'); Err = "error: unexpected value '1' for '--force' found; no more were expected`n`nUsage: boab init --force`n`nFor more information, try '--help'.`n" }
        @{ Name = 'verbose and quiet'; Argv = @('--verbose', '--quiet', 'init'); Err = "error: the argument '--verbose' cannot be used with '--quiet'`n`nUsage: boab --verbose <COMMAND>`n`nFor more information, try '--help'.`n" }
        @{ Name = 'quiet and verbose in subcommand'; Argv = @('init', '--no-progress', '--verbose', '--quiet'); Err = "error: the argument '--verbose' cannot be used with '--quiet'`n`nUsage: boab init --no-progress --verbose`n`nFor more information, try '--help'.`n" }
        @{ Name = 'help for unknown'; Argv = @('help', 'system', 'bogus'); Err = "error: unrecognized subcommand 'bogus'`n`nUsage: boab system [OPTIONS] <COMMAND>`n`nFor more information, try '--help'.`n" }
    ) {
        $r = Invoke-BoabCli -ArgumentList $Argv -PassThru
        $r.ExitCode | Should -Be 2
        $r.StdOut | Should -BeExactly ''
        $r.StdErr | Should -BeExactly $Err
    }

    It 'accepts --opt=value, -ovalue, -o=value, globals anywhere and --' {
        InModuleScope Boab {
            $p = Invoke-BoabCliParse -Arguments @('report', '-ofoo.md', '--format=md', '--workspace', '/tmp/x')
            $p.Action | Should -Be 'run'
            $p.Values.output | Should -BeExactly 'foo.md'
            $p.Values.format | Should -BeExactly 'md'
            $p.Globals.workspace | Should -BeExactly '/tmp/x'
            (Invoke-BoabCliParse -Arguments @('report', '-o=bar.md', '--format', 'md')).Values.output | Should -BeExactly 'bar.md'
            $p = Invoke-BoabCliParse -Arguments @('config', 'set', '--', 'k', '-1')
            $p.Values.key | Should -BeExactly 'k'
            $p.Values.value | Should -BeExactly '-1'
            $p = Invoke-BoabCliParse -Arguments @('scan', 'tls', 'a:1', 'b:2', '--exclude', 'x', '--exclude', 'y')
            @($p.Values.targets) | Should -Be @('a:1', 'b:2')
            @($p.Values.exclude) | Should -Be @('x', 'y')
            $p.Values.timeout_seconds | Should -Be 10
            $p = Invoke-BoabCliParse -Arguments @('system', 'add', '--name', 'x')
            $p.Values.classification | Should -BeExactly 'official'
            $p.Values.criticality | Should -BeExactly 'standard'
            $p.Values.soci | Should -BeFalse
            $p.Values.lifetime_years | Should -BeNullOrEmpty
            $p = Invoke-BoabCliParse -Arguments @('system', 'delete', '{336C086C-F5D0-4E01-854B-40DAFC4F404D}')
            $p.Values.id | Should -BeExactly '336c086c-f5d0-4e01-854b-40dafc4f404d'
        }
    }
}

Describe 'Invoke-Boab' {
    It 'writes stdout lines to the pipeline and sets $LASTEXITCODE' {
        $out = Invoke-Boab --version
        $out | Should -BeExactly 'boab 0.1.0'
        $LASTEXITCODE | Should -Be 0
        $null = Invoke-Boab frob 2>$null
        $LASTEXITCODE | Should -Be 2
    }
}
