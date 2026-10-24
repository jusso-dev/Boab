# Subcommand dispatcher, port of src/runner.rs. Every command writes the same
# stdout/stderr text as the Rust binary and returns the same exit code.

$script:BoabExitNotImplemented = 64

function New-BoabRunContext {
    param([switch]$Stream)
    @{
        Out    = [System.Text.StringBuilder]::new()
        Err    = [System.Text.StringBuilder]::new()
        Stream = [bool]$Stream
    }
}

function Write-BoabStdout {
    # println!
    param([hashtable]$Context, [AllowEmptyString()][string]$Text)
    $line = $Text + "`n"
    [void]$Context.Out.Append($line)
    if ($Context.Stream) { [Console]::Out.Write($line); [Console]::Out.Flush() }
}

function Write-BoabStderr {
    # eprintln!
    param([hashtable]$Context, [AllowEmptyString()][string]$Text)
    $line = $Text + "`n"
    [void]$Context.Err.Append($line)
    if ($Context.Stream) { [Console]::Error.Write($line); [Console]::Error.Flush() }
}

function Get-BoabScannerCommand {
    param([string]$Name)
    $cmd = Get-Command -Name $Name -CommandType Function -ErrorAction SilentlyContinue
    if (-not $cmd) { throw (New-BoabException ("scanner {0} is not available in this build of the Boab module" -f $Name)) }
    $cmd
}

function Invoke-BoabRunInit {
    param([hashtable]$Context, [hashtable]$Parsed)
    $v = $Parsed.Values
    if ($v.force -and -not $v.yes) { throw (New-BoabException '--force requires --yes') }
    $root = [string]$Parsed.Globals.workspace
    $result = Initialize-BoabWorkspaceLayout -Root $root -Force:([bool]$v.force)
    if ($result.Existed -and -not $v.force) { Write-BoabStdout $Context 'workspace already initialised' }
    else { Write-BoabStdout $Context ("workspace initialised at {0}/.boab" -f $root) }
    0
}

function Invoke-BoabRunSystem {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $v = $Parsed.Values
    switch ($Sub) {
        'add' {
            $class = ConvertFrom-BoabClassification -Value $v.classification
            if ($null -eq $class) { throw (New-BoabException ("unknown classification: {0}" -f $v.classification)) }
            $crit = ConvertFrom-BoabCriticality -Value $v.criticality
            if ($null -eq $crit) { throw (New-BoabException ("unknown criticality: {0}" -f $v.criticality)) }
            $systems = Get-BoabStoredSystem -Workspace $ws
            $sys = New-BoabSystemRecord -Name $v.name -Description $v.description -Classification $class -Criticality $crit -IsSoci ([bool]$v.soci) -ExpectedDataLifetimeYears $v.lifetime_years
            Write-BoabStdout $Context ("added system {0} ({1})" -f $sys.name, $sys.id)
            $systems.Add($sys)
            Save-BoabStoredSystem -Workspace $ws -Systems $systems
            return 0
        }
        'list' {
            $systems = Get-BoabStoredSystem -Workspace $ws
            if ($systems.Count -eq 0) { Write-BoabStdout $Context '(no systems)'; return 0 }
            $rows = New-BoabList
            foreach ($s in $systems) {
                $life = if ($null -ne $s.expected_data_lifetime_years) { '{0}y' -f $s.expected_data_lifetime_years } else { '-' }
                $rows.Add(@([string]$s.id, $s.name, $s.classification, $s.criticality, $(if ($s.is_soci) { 'yes' } else { 'no' }), $life))
            }
            Write-BoabStdout $Context (Format-BoabTable -Header @('ID', 'NAME', 'CLASS', 'CRIT', 'SOCI', 'LIFETIME') -Rows $rows)
            return 0
        }
        'edit' {
            $systems = Get-BoabStoredSystem -Workspace $ws
            $s = Find-BoabSystemById -Systems $systems -Id $v.id
            if ($null -eq $s) { throw (New-BoabException ("no system with id {0}" -f $v.id)) }
            if ($null -ne $v.name) { $s.name = $v.name }
            if ($null -ne $v.description) { $s.description = $v.description }
            if ($null -ne $v.classification) {
                $c = ConvertFrom-BoabClassification -Value $v.classification
                if ($null -eq $c) { throw (New-BoabException ("unknown classification: {0}" -f $v.classification)) }
                $s.classification = $c
            }
            if ($null -ne $v.criticality) {
                $c = ConvertFrom-BoabCriticality -Value $v.criticality
                if ($null -eq $c) { throw (New-BoabException ("unknown criticality: {0}" -f $v.criticality)) }
                $s.criticality = $c
            }
            if ($null -ne $v.soci) { $s.is_soci = [bool]$v.soci }
            if ($null -ne $v.lifetime_years) { $s.expected_data_lifetime_years = [long]$v.lifetime_years }
            Save-BoabStoredSystem -Workspace $ws -Systems $systems
            Write-BoabStdout $Context ("updated system {0}" -f $v.id)
            return 0
        }
        'delete' {
            $systems = Get-BoabStoredSystem -Workspace $ws
            $kept = New-BoabList
            foreach ($s in $systems) { if ($s.id -cne $v.id) { $kept.Add($s) } }
            if ($kept.Count -eq $systems.Count) { throw (New-BoabException ("no system with id {0}" -f $v.id)) }
            Save-BoabStoredSystem -Workspace $ws -Systems $kept
            Write-BoabStdout $Context ("deleted system {0}" -f $v.id)
            return 0
        }
    }
}

function Select-BoabInventoryRow {
    # The `inventory list` filters. Returns a list of @{ Asset; System; Score }.
    param($Inventory, $Systems, [int]$Year, $PqcStatus, $Tier, $SystemId, $Algorithm)
    $rows = New-BoabList
    foreach ($a in $Inventory) {
        if ($null -ne $PqcStatus -and -not (Test-BoabAsciiEqualIgnoreCase (Get-BoabDebugName $a.pqc_status) ([string]$PqcStatus))) { continue }
        if ($null -ne $SystemId -and $a.system_id -cne $SystemId) { continue }
        if ($null -ne $Algorithm -and -not (ConvertTo-BoabAsciiLower $a.algorithm_name).Contains((ConvertTo-BoabAsciiLower ([string]$Algorithm)))) { continue }
        $sys = Find-BoabSystemById -Systems $Systems -Id $a.system_id
        $score = Get-BoabRiskScore -Asset $a -System $sys -CurrentYear $Year
        if ($null -ne $Tier -and [int]$score.triage_tier -ne [int]$Tier) { continue }
        $rows.Add(@{ Asset = $a; System = $sys; Score = $score })
    }
    , $rows
}

function Invoke-BoabRunInventory {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $inventory = Get-BoabStoredInventory -Workspace $ws
    $systems = Get-BoabStoredSystem -Workspace $ws
    $year = (Get-BoabNow).UtcDateTime.Year
    $v = $Parsed.Values
    if ($Sub -eq 'list') {
        $rows = Select-BoabInventoryRow -Inventory $inventory -Systems $systems -Year $year -PqcStatus $v.pqc_status -Tier $v.tier -SystemId $v.system -Algorithm $v.algorithm
        if ($rows.Count -eq 0) { Write-BoabStdout $Context '(no inventory entries)'; return 0 }
        $table = New-BoabList
        foreach ($r in $rows) {
            $a = $r.Asset
            $sysName = if ($null -ne $r.System) { $r.System.name } else { '-' }
            $table.Add(@(
                    [string]$a.id, $a.name, $a.algorithm_name, (Get-BoabDebugLower $a.pqc_status),
                    (Format-BoabFixed -Value ([double]$r.Score.priority) -Decimals 1), [string]$r.Score.triage_tier,
                    $sysName, (ConvertTo-BoabCanonicalRfc3339 -Text $a.last_seen_at)))
        }
        Write-BoabStdout $Context (Format-BoabTable -Header @('ID', 'NAME', 'ALGORITHM', 'PQC', 'PRIORITY', 'TIER', 'SYSTEM', 'LAST_SEEN') -Rows $table)
        return 0
    }
    $asset = $null
    foreach ($a in $inventory) { if ($a.id -ceq $v.id) { $asset = $a; break } }
    if ($null -eq $asset) { throw (New-BoabException ("no inventory entry with id {0}" -f $v.id)) }
    $sys = Find-BoabSystemById -Systems $systems -Id $asset.system_id
    $score = Get-BoabRiskScore -Asset $asset -System $sys -CurrentYear $year
    # serde_json::json! goes through Value, which widens the f32 priority to f64.
    $score.priority = [double]$score.priority
    Write-BoabStdout $Context (ConvertTo-BoabJson -InputObject ([ordered]@{ asset = $asset; score = $score }))
    0
}

function Invoke-BoabRunScan {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $v = $Parsed.Values
    switch ($Sub) {
        'codebase' {
            $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
            if ($null -ne $v.path) { $path = $v.path }
            elseif ($null -ne $v.git) {
                Write-BoabStderr $Context 'git cloning is not yet implemented; pass a local path instead'
                return $script:BoabExitNotImplemented
            }
            else { throw (New-BoabException 'missing path or --git URL') }
            $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabCodebaseScan'
            $splat = @{ Path = $path }
            if ($v.include.Count -gt 0) { $splat.Include = [string[]]$v.include }
            if ($v.exclude.Count -gt 0) { $splat.Exclude = [string[]]$v.exclude }
            if ($null -ne $v.name) { $splat.Name = $v.name }
            $scan = & $scanner @splat
            $count = (Invoke-BoabPromotion -Workspace $ws -Scan $scan).Count
            Save-BoabStoredScan -Workspace $ws -Scan $scan
            Write-BoabStdout $Context ("scan {0} complete: {1} findings, inventory {2} entries" -f $scan.id, @($scan.findings).Count, $count)
            return 0
        }
        'tls' {
            $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
            $cfg = Read-BoabConfig -Workspace $ws
            $targets = New-BoabList $v.targets
            if ($null -ne $v.targets_file) {
                $file = Resolve-BoabFullPath -Path $v.targets_file
                try { $raw = Read-BoabTextFile -Path $file }
                catch { throw (New-BoabException (Get-BoabIoErrorText -Exception $_ -Path $file)) }
                foreach ($line in ($raw -split "`n")) {
                    $l = $line.TrimEnd("`r").Trim()
                    if ($l.Length -gt 0 -and -not $l.StartsWith('#')) { $targets.Add($l) }
                }
            }
            if ($targets.Count -eq 0) { throw (New-BoabException 'no TLS targets specified; pass host:port or --targets-file') }
            $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabTlsScan'
            $splat = @{
                Targets        = [string[]]$targets
                TimeoutSeconds = $v.timeout_seconds
                ProbeHsts      = [bool]$v.probe_hsts
                AirGapped      = [bool]$cfg.scanner.air_gapped
            }
            if ($null -ne $v.rate_limit) { $splat.RateLimit = $v.rate_limit }
            if ($v.exclude.Count -gt 0) { $splat.Exclude = [string[]]$v.exclude }
            if ($null -ne $v.name) { $splat.Name = $v.name }
            # Invoke-BoabTlsScan emits its Scan[] as a single (non-unrolled) object; flatten it.
            $scans = @(foreach ($s in (& $scanner @splat)) { $s })
            $count = 0
            foreach ($scan in $scans) {
                $count = (Invoke-BoabPromotion -Workspace $ws -Scan $scan).Count
                Save-BoabStoredScan -Workspace $ws -Scan $scan
                Write-BoabStdout $Context ("tls scan {0} target={1} status={2} findings={3}" -f $scan.id, $scan.target, (Get-BoabDebugName $scan.status), @($scan.findings).Count)
            }
            Write-BoabStdout $Context ("inventory now has {0} entries" -f $count)
            return 0
        }
        'certs' {
            $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
            $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabCertStoreScan'
            $splat = @{ Path = $v.path }
            if ($null -ne $v.password_file) { $splat.PasswordFile = $v.password_file }
            if ($null -ne $v.name) { $splat.Name = $v.name }
            $scan = & $scanner @splat
            $count = (Invoke-BoabPromotion -Workspace $ws -Scan $scan).Count
            Save-BoabStoredScan -Workspace $ws -Scan $scan
            Write-BoabStdout $Context ("cert scan {0} complete: {1} findings, inventory {2} entries" -f $scan.id, @($scan.findings).Count, $count)
            return 0
        }
    }
}

function Invoke-BoabRunPlan {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $v = $Parsed.Values
    switch ($Sub) {
        'generate' {
            $milestone = ConvertFrom-BoabMilestone -Value $v.milestone
            if ($null -eq $milestone) { throw (New-BoabException 'milestone must be one of 2026, 2028, 2030') }
            $plan = New-BoabTransitionPlan -Workspace $ws -Milestone $milestone -Name $v.name
            Save-BoabStoredPlan -Workspace $ws -Plan $plan
            Write-BoabStdout $Context ("plan {0} generated for {1}: {2} items" -f $plan.id, (Get-BoabMilestoneYear $milestone), $plan.items.Count)
            return 0
        }
        'list' {
            $plans = Get-BoabStoredPlan -Workspace $ws
            if ($plans.Count -eq 0) { Write-BoabStdout $Context '(no plans)'; return 0 }
            $rows = New-BoabList
            foreach ($p in $plans) {
                $rows.Add(@([string]$p.id, $p.name, [string](Get-BoabMilestoneYear $p.milestone), [string]$p.items.Count, $p.generated_at))
            }
            Write-BoabStdout $Context (Format-BoabTable -Header @('ID', 'NAME', 'MILESTONE', 'ITEMS', 'GENERATED') -Rows $rows)
            return 0
        }
        'show' {
            $plan = Get-BoabStoredPlan -Workspace $ws -Id $v.id
            Write-BoabStdout $Context (ConvertTo-BoabJson -InputObject $plan)
            return 0
        }
        'regenerate' {
            $plan = Update-BoabTransitionPlan -Workspace $ws -Id $v.id
            Save-BoabStoredPlan -Workspace $ws -Plan $plan
            Write-BoabStdout $Context ("plan {0} regenerated: {1} items (user edits preserved)" -f $plan.id, $plan.items.Count)
            return 0
        }
    }
}

function Invoke-BoabRunVendor {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $v = $Parsed.Values
    switch ($Sub) {
        'list' {
            $merged = Get-BoabMergedVendorRegistry -Workspace $ws
            if ($merged.entries.Count -eq 0) { Write-BoabStdout $Context '(no vendor entries)'; return 0 }
            $rows = New-BoabList
            foreach ($e in $merged.entries) {
                $rows.Add(@($e.vendor, $e.product, (Get-BoabDebugLower $e.pqc_status),
                        $(if ($null -ne $e.target_date) { $e.target_date } else { '-' }),
                        $(if ($null -ne $e.source_url) { $e.source_url } else { '-' })))
            }
            Write-BoabStdout $Context (Format-BoabTable -Header @('VENDOR', 'PRODUCT', 'PQC', 'TARGET', 'SOURCE') -Rows $rows)
            return 0
        }
        'search' {
            $merged = Get-BoabMergedVendorRegistry -Workspace $ws
            $results = Find-BoabVendorEntry -Registry $merged -Term $v.term
            if ($results.Count -eq 0) { Write-BoabStdout $Context ("(no matches for {0})" -f $v.term); return 0 }
            $rows = New-BoabList
            foreach ($e in $results) {
                $rows.Add(@($e.vendor, $e.product, (Get-BoabDebugLower $e.pqc_status),
                        $(if ($null -ne $e.target_date) { $e.target_date } else { '-' })))
            }
            Write-BoabStdout $Context (Format-BoabTable -Header @('VENDOR', 'PRODUCT', 'PQC', 'TARGET') -Rows $rows)
            return 0
        }
        'add' {
            $splat = @{ Workspace = $ws; Vendor = $v.vendor; Product = $v.product; PqcStatus = $v.pqc_status }
            if ($null -ne $v.target_date) { $splat.TargetDate = $v.target_date }
            if ($null -ne $v.source_url) { $splat.SourceUrl = $v.source_url }
            if ($null -ne $v.source_note) { $splat.SourceNote = $v.source_note }
            [void](Add-BoabVendorOverrideEntry @splat)
            Write-BoabStdout $Context 'vendor override saved'
            return 0
        }
    }
}

function Get-BoabReportDefaultName {
    param([string]$Format)
    switch -CaseSensitive ($Format) {
        'json' { return 'report.json' }
        'cbom' { return 'bom.cdx.json' }
        'md' { return 'readiness.md' }
        'html' { return 'readiness.html' }
    }
    throw (New-BoabException ("unknown report format: {0}" -f $Format))
}

function Export-BoabReportFile {
    # Shared by `boab report` and Export-BoabReport. Returns the display path.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Format, [AllowNull()][string]$OutputPath)
    $fmt = ConvertTo-BoabAsciiLower $Format
    $defaultName = Get-BoabReportDefaultName -Format $fmt
    $display = if ($OutputPath) { $OutputPath } else { Join-BoabPath (Get-BoabWorkspacePath -Workspace $Workspace -Kind Reports) $defaultName }
    $target = Resolve-BoabFullPath -Path $display
    switch -CaseSensitive ($fmt) {
        'json' { Export-BoabJsonReport -Workspace $Workspace -Path $target }
        'cbom' { Export-BoabCbomReport -Workspace $Workspace -Path $target }
        'md' { Export-BoabMarkdownReport -Workspace $Workspace -Path $target }
        'html' { Export-BoabHtmlReport -Workspace $Workspace -Path $target }
    }
    @{ Format = $fmt; Display = $display; FullPath = $target }
}

function Invoke-BoabRunReport {
    param([hashtable]$Context, [hashtable]$Parsed)
    if ($Parsed.Values.push) { return (Invoke-BoabRunPush -Context $Context -Parsed $Parsed) }
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $r = Export-BoabReportFile -Workspace $ws -Format $Parsed.Values.format -OutputPath $Parsed.Values.output
    Write-BoabStdout $Context ("wrote {0} report to {1}" -f $r.Format, $r.Display)
    0
}

function Invoke-BoabRunPush {
    # `boab push` (and `report --push`) need the Rust binary's HTTPS client; the port does not send anything.
    param([hashtable]$Context, [hashtable]$Parsed)
    Write-BoabStderr $Context 'boab push is not yet implemented in the PowerShell port; use the boab binary to push a CBOM'
    $script:BoabExitNotImplemented
}

function Invoke-BoabRunConfig {
    param([hashtable]$Context, [hashtable]$Parsed, [string]$Sub)
    $ws = Open-BoabWorkspace -Root $Parsed.Globals.workspace
    $v = $Parsed.Values
    if ($Sub -eq 'get') {
        $cfg = Read-BoabConfig -Workspace $ws
        $value = Get-BoabConfigValue -Config $cfg -Key $v.key
        if ($null -eq $value) { throw (New-BoabException ("unknown config key: {0}" -f $v.key)) }
        Write-BoabStdout $Context $value
        return 0
    }
    $cfg = Read-BoabConfig -Workspace $ws
    Set-BoabConfigValue -Config $cfg -Key $v.key -Value $v.value
    Save-BoabConfig -Workspace $ws -Config $cfg
    Write-BoabStdout $Context ("{0} = {1}" -f $v.key, $v.value)
    0
}

function Invoke-BoabRunner {
    # runner::run for an already-parsed command line.
    param([hashtable]$Context, [hashtable]$Parsed)
    $parts = $Parsed.Path.Split(' ')
    $top = $parts[0]
    $sub = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    switch ($top) {
        'init' { return (Invoke-BoabRunInit -Context $Context -Parsed $Parsed) }
        'system' { return (Invoke-BoabRunSystem -Context $Context -Parsed $Parsed -Sub $sub) }
        'inventory' { return (Invoke-BoabRunInventory -Context $Context -Parsed $Parsed -Sub $sub) }
        'scan' { return (Invoke-BoabRunScan -Context $Context -Parsed $Parsed -Sub $sub) }
        'plan' { return (Invoke-BoabRunPlan -Context $Context -Parsed $Parsed -Sub $sub) }
        'vendor' { return (Invoke-BoabRunVendor -Context $Context -Parsed $Parsed -Sub $sub) }
        'report' { return (Invoke-BoabRunReport -Context $Context -Parsed $Parsed) }
        'push' { return (Invoke-BoabRunPush -Context $Context -Parsed $Parsed) }
        'config' { return (Invoke-BoabRunConfig -Context $Context -Parsed $Parsed -Sub $sub) }
    }
    throw (New-BoabException ("unknown command: {0}" -f $Parsed.Path))
}

function Invoke-BoabMain {
    # Parse + run. Returns @{ ExitCode; StdOut; StdErr }.
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Arguments = @(), [switch]$Stream)
    $ctx = New-BoabRunContext -Stream:$Stream
    $parsed = Invoke-BoabCliParse -Arguments $Arguments
    if ($parsed.Action -ne 'run') {
        if ($parsed.Stdout) { [void]$ctx.Out.Append($parsed.Stdout); if ($Stream) { [Console]::Out.Write($parsed.Stdout) } }
        if ($parsed.Stderr) { [void]$ctx.Err.Append($parsed.Stderr); if ($Stream) { [Console]::Error.Write($parsed.Stderr) } }
        return [pscustomobject]@{ ExitCode = [int]$parsed.ExitCode; StdOut = $ctx.Out.ToString(); StdErr = $ctx.Err.ToString() }
    }
    $code = 1
    try {
        $code = [int](Invoke-BoabRunner -Context $ctx -Parsed $parsed | Select-Object -Last 1)
    }
    catch {
        Write-BoabStderr $ctx ("error: {0}" -f (Get-BoabErrorMessage $_))
        $code = 1
    }
    [pscustomobject]@{ ExitCode = $code; StdOut = $ctx.Out.ToString(); StdErr = $ctx.Err.ToString() }
}
