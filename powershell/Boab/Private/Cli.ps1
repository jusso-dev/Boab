# Argument parser reproducing the clap 4 behaviour of src/cli.rs: same commands,
# flags, defaults, value validation, help/version output and error texts.

function New-BoabArgSpec {
    param(
        [string]$Name,
        [ValidateSet('flag', 'option', 'multi', 'pos', 'posmulti')][string]$Kind,
        [string]$Long,
        [string]$Short,
        [string]$ValueName,
        [ValidateSet('string', 'path', 'uuid', 'u8', 'u16', 'u64', 'bool')][string]$Type = 'string',
        [switch]$Required,
        $Default = $null
    )
    @{ Name = $Name; Kind = $Kind; Long = $Long; Short = $Short; ValueName = $ValueName; Type = $Type; Required = [bool]$Required; Default = $Default }
}

$script:BoabGlobalArgs = @(
    (New-BoabArgSpec -Name 'workspace' -Kind option -Long 'workspace' -ValueName 'WORKSPACE' -Type path -Default '.')
    (New-BoabArgSpec -Name 'verbose' -Kind flag -Long 'verbose')
    (New-BoabArgSpec -Name 'quiet' -Kind flag -Long 'quiet')
    (New-BoabArgSpec -Name 'no_progress' -Kind flag -Long 'no-progress')
)

$script:BoabCommandSpec = @{
    ''                = @{ Subcommands = @('init', 'system', 'inventory', 'scan', 'plan', 'vendor', 'report', 'config'); Args = @() }
    'init'            = @{ Args = @(
            (New-BoabArgSpec -Name 'force' -Kind flag -Long 'force')
            (New-BoabArgSpec -Name 'yes' -Kind flag -Long 'yes'))
    }
    'system'          = @{ Subcommands = @('add', 'list', 'edit', 'delete'); Args = @() }
    'system add'      = @{ Args = @(
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME' -Required)
            (New-BoabArgSpec -Name 'description' -Kind option -Long 'description' -ValueName 'DESCRIPTION')
            (New-BoabArgSpec -Name 'classification' -Kind option -Long 'classification' -ValueName 'CLASSIFICATION' -Default 'official')
            (New-BoabArgSpec -Name 'criticality' -Kind option -Long 'criticality' -ValueName 'CRITICALITY' -Default 'standard')
            (New-BoabArgSpec -Name 'soci' -Kind flag -Long 'soci')
            (New-BoabArgSpec -Name 'lifetime_years' -Kind option -Long 'lifetime-years' -ValueName 'LIFETIME_YEARS' -Type u16))
    }
    'system list'     = @{ Args = @() }
    'system edit'     = @{ Args = @(
            (New-BoabArgSpec -Name 'id' -Kind option -Long 'id' -ValueName 'ID' -Type uuid -Required)
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME')
            (New-BoabArgSpec -Name 'description' -Kind option -Long 'description' -ValueName 'DESCRIPTION')
            (New-BoabArgSpec -Name 'classification' -Kind option -Long 'classification' -ValueName 'CLASSIFICATION')
            (New-BoabArgSpec -Name 'criticality' -Kind option -Long 'criticality' -ValueName 'CRITICALITY')
            (New-BoabArgSpec -Name 'soci' -Kind option -Long 'soci' -ValueName 'SOCI' -Type bool)
            (New-BoabArgSpec -Name 'lifetime_years' -Kind option -Long 'lifetime-years' -ValueName 'LIFETIME_YEARS' -Type u16))
    }
    'system delete'   = @{ Args = @((New-BoabArgSpec -Name 'id' -Kind pos -ValueName 'ID' -Type uuid -Required)) }
    'inventory'       = @{ Subcommands = @('list', 'show'); Args = @() }
    'inventory list'  = @{ Args = @(
            (New-BoabArgSpec -Name 'pqc_status' -Kind option -Long 'pqc-status' -ValueName 'PQC_STATUS')
            (New-BoabArgSpec -Name 'tier' -Kind option -Long 'tier' -ValueName 'TIER' -Type u8)
            (New-BoabArgSpec -Name 'system' -Kind option -Long 'system' -ValueName 'SYSTEM' -Type uuid)
            (New-BoabArgSpec -Name 'algorithm' -Kind option -Long 'algorithm' -ValueName 'ALGORITHM'))
    }
    'inventory show'  = @{ Args = @((New-BoabArgSpec -Name 'id' -Kind pos -ValueName 'ID' -Type uuid -Required)) }
    'scan'            = @{ Subcommands = @('codebase', 'tls', 'certs'); Args = @() }
    'scan codebase'   = @{ Args = @(
            (New-BoabArgSpec -Name 'path' -Kind pos -ValueName 'PATH' -Type path)
            (New-BoabArgSpec -Name 'git' -Kind option -Long 'git' -ValueName 'GIT')
            (New-BoabArgSpec -Name 'include' -Kind multi -Long 'include' -ValueName 'INCLUDE')
            (New-BoabArgSpec -Name 'exclude' -Kind multi -Long 'exclude' -ValueName 'EXCLUDE')
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME'))
    }
    'scan tls'        = @{ Args = @(
            (New-BoabArgSpec -Name 'targets' -Kind posmulti -ValueName 'TARGETS')
            (New-BoabArgSpec -Name 'targets_file' -Kind option -Long 'targets-file' -ValueName 'TARGETS_FILE' -Type path)
            (New-BoabArgSpec -Name 'rate_limit' -Kind option -Long 'rate-limit' -ValueName 'RATE_LIMIT')
            (New-BoabArgSpec -Name 'timeout_seconds' -Kind option -Long 'timeout-seconds' -ValueName 'TIMEOUT_SECONDS' -Type u64 -Default ([long]10))
            (New-BoabArgSpec -Name 'probe_hsts' -Kind flag -Long 'probe-hsts')
            (New-BoabArgSpec -Name 'exclude' -Kind multi -Long 'exclude' -ValueName 'EXCLUDE')
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME'))
    }
    'scan certs'      = @{ Args = @(
            (New-BoabArgSpec -Name 'path' -Kind pos -ValueName 'PATH' -Type path -Required)
            (New-BoabArgSpec -Name 'password_file' -Kind option -Long 'password-file' -ValueName 'PASSWORD_FILE' -Type path)
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME'))
    }
    'plan'            = @{ Subcommands = @('generate', 'list', 'show', 'regenerate'); Args = @() }
    'plan generate'   = @{ Args = @(
            (New-BoabArgSpec -Name 'milestone' -Kind option -Long 'milestone' -ValueName 'MILESTONE' -Required)
            (New-BoabArgSpec -Name 'name' -Kind option -Long 'name' -ValueName 'NAME'))
    }
    'plan list'       = @{ Args = @() }
    'plan show'       = @{ Args = @((New-BoabArgSpec -Name 'id' -Kind pos -ValueName 'ID' -Type uuid -Required)) }
    'plan regenerate' = @{ Args = @((New-BoabArgSpec -Name 'id' -Kind pos -ValueName 'ID' -Type uuid -Required)) }
    'vendor'          = @{ Subcommands = @('list', 'add', 'search'); Args = @() }
    'vendor list'     = @{ Args = @() }
    'vendor add'      = @{ Args = @(
            (New-BoabArgSpec -Name 'vendor' -Kind option -Long 'vendor' -ValueName 'VENDOR' -Required)
            (New-BoabArgSpec -Name 'product' -Kind option -Long 'product' -ValueName 'PRODUCT' -Required)
            (New-BoabArgSpec -Name 'pqc_status' -Kind option -Long 'pqc-status' -ValueName 'PQC_STATUS' -Required)
            (New-BoabArgSpec -Name 'target_date' -Kind option -Long 'target-date' -ValueName 'TARGET_DATE')
            (New-BoabArgSpec -Name 'source_url' -Kind option -Long 'source-url' -ValueName 'SOURCE_URL')
            (New-BoabArgSpec -Name 'source_note' -Kind option -Long 'source-note' -ValueName 'SOURCE_NOTE'))
    }
    'vendor search'   = @{ Args = @((New-BoabArgSpec -Name 'term' -Kind pos -ValueName 'TERM' -Required)) }
    'report'          = @{ Args = @(
            (New-BoabArgSpec -Name 'format' -Kind option -Long 'format' -ValueName 'FORMAT' -Required)
            (New-BoabArgSpec -Name 'output' -Kind option -Long 'output' -Short 'o' -ValueName 'OUTPUT' -Type path))
    }
    'config'          = @{ Subcommands = @('get', 'set'); Args = @() }
    'config get'      = @{ Args = @((New-BoabArgSpec -Name 'key' -Kind pos -ValueName 'KEY' -Required)) }
    'config set'      = @{ Args = @(
            (New-BoabArgSpec -Name 'key' -Kind pos -ValueName 'KEY' -Required)
            (New-BoabArgSpec -Name 'value' -Kind pos -ValueName 'VALUE' -Required))
    }
}

function Get-BoabArgDisplay {
    # How clap names an argument in error messages.
    param([hashtable]$Spec)
    switch ($Spec.Kind) {
        'flag' { return '--' + $Spec.Long }
        'pos' { return '<' + $Spec.ValueName + '>' }
        'posmulti' { return '[' + $Spec.ValueName + ']...' }
        default { return '--{0} <{1}>' -f $Spec.Long, $Spec.ValueName }
    }
}

function Get-BoabArgUsageToken {
    param([hashtable]$Spec)
    switch ($Spec.Kind) {
        'flag' { return '--' + $Spec.Long }
        'pos' { if ($Spec.Required) { return '<' + $Spec.ValueName + '>' } return '[' + $Spec.ValueName + ']' }
        'posmulti' { return '[' + $Spec.ValueName + ']...' }
        default { return '--{0} <{1}>' -f $Spec.Long, $Spec.ValueName }
    }
}

function Get-BoabCliUsage {
    # Full usage (as in --help) or clap's "required + used" usage for errors.
    param([string]$Path, [switch]$Full, [object[]]$Used = @())
    if ($Full) { return $script:BoabCliHelp[$Path].Usage }
    $cmd = $script:BoabCommandSpec[$Path]
    $tokens = [System.Collections.Generic.List[string]]::new()
    $tokens.Add('boab')
    if ($Path) { $tokens.Add($Path) }
    $flagTokens = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $cmd.Args) {
        if ($a.Required -and $a.Kind -ne 'pos' -and $a.Kind -ne 'posmulti') { $flagTokens.Add((Get-BoabArgUsageToken $a)) }
    }
    foreach ($u in $Used) {
        $t = Get-BoabArgUsageToken $u
        if (-not $flagTokens.Contains($t)) { $flagTokens.Add($t) }
    }
    foreach ($t in $flagTokens) { $tokens.Add($t) }
    foreach ($a in $cmd.Args) {
        if ($a.Kind -eq 'pos' -or $a.Kind -eq 'posmulti') { $tokens.Add((Get-BoabArgUsageToken $a)) }
    }
    if ($cmd.ContainsKey('Subcommands')) { $tokens.Add('<COMMAND>') }
    $tokens -join ' '
}

function New-BoabCliError {
    param([string]$Message, [string]$Tip, [string]$Usage)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('error: ').Append($Message).Append("`n")
    if ($Tip) { [void]$sb.Append("`n  tip: ").Append($Tip).Append("`n") }
    if ($Usage) { [void]$sb.Append("`nUsage: ").Append($Usage).Append("`n") }
    [void]$sb.Append("`nFor more information, try '--help'.`n")
    @{ Action = 'error'; Stdout = ''; Stderr = $sb.ToString(); ExitCode = 2 }
}

function Get-BoabCliSuggestion {
    # clap::parser::features::suggestions::did_you_mean (jaro > 0.7, best match).
    param([string]$Value, [string[]]$Candidates)
    $best = $null; $bestScore = 0.0
    foreach ($c in $Candidates) {
        $score = Get-BoabJaro -A $Value -B $c
        if ($score -gt 0.7 -and $score -ge $bestScore) { $best = $c; $bestScore = $score }
    }
    $best
}

function ConvertFrom-BoabCliValue {
    # Value parsers. Returns @{ Ok = $true; Value = ... } or an error result.
    param([hashtable]$Spec, [string]$Raw)
    $display = Get-BoabArgDisplay $Spec
    $fail = { param($msg) @{ Ok = $false; Error = (New-BoabCliError -Message ("invalid value '{0}' for '{1}': {2}" -f $Raw, $display, $msg)) } }
    switch ($Spec.Type) {
        'path' {
            if ($Raw.Length -eq 0) { return @{ Ok = $false; Error = (New-BoabCliError -Message ("a value is required for '{0}' but none was supplied" -f $display)) } }
            return @{ Ok = $true; Value = $Raw }
        }
        'uuid' {
            try { return @{ Ok = $true; Value = (ConvertFrom-BoabUuidText -Text $Raw) } }
            catch { return (& $fail (Get-BoabErrorMessage $_)) }
        }
        'bool' {
            if ($Raw -ceq 'true') { return @{ Ok = $true; Value = $true } }
            if ($Raw -ceq 'false') { return @{ Ok = $true; Value = $false } }
            return @{ Ok = $false; Error = (New-BoabCliError -Message ("invalid value '{0}' for '{1}'`n  [possible values: true, false]" -f $Raw, $display)) }
        }
        'u64' {
            try { $v = ConvertFrom-BoabRustUnsigned -Text $Raw -Max ([ulong]::MaxValue) }
            catch { return (& $fail (Get-BoabErrorMessage $_)) }
            $val = if ($v -le [long]::MaxValue) { [long]$v } else { $v }
            return @{ Ok = $true; Value = $val }
        }
        { $_ -eq 'u8' -or $_ -eq 'u16' } {
            $max = if ($Spec.Type -eq 'u8') { 255 } else { 65535 }
            try { $v = ConvertFrom-BoabRustSigned64 -Text $Raw }
            catch { return (& $fail (Get-BoabErrorMessage $_)) }
            if ($v -lt 0 -or $v -gt $max) { return (& $fail ('{0} is not in 0..={1}' -f $v, $max)) }
            return @{ Ok = $true; Value = [long]$v }
        }
    }
    @{ Ok = $true; Value = $Raw }
}

function Invoke-BoabCliParse {
    <#
    Parse argv like the clap-derived `Cli`. Returns a hashtable:
      Action = 'run'     -> Path, Values (leaf args), Globals
      Action = 'help' / 'version' / 'error' -> Stdout, Stderr, ExitCode
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Arguments = @())
    $path = ''
    $values = @{}
    $globals = @{ workspace = '.'; verbose = $false; quiet = $false; no_progress = $false }
    $seen = @{}              # "<level>|<name>" -> $true, for "cannot be used multiple times"
    $globalOrder = [System.Collections.Generic.List[object]]::new()   # @{ Level; Spec }
    $posIndex = 0
    $trailing = $false
    $i = 0
    $n = $Arguments.Count

    $cmdSpec = { $script:BoabCommandSpec[$path] }
    $findLong = {
        param([string]$name)
        foreach ($a in (& $cmdSpec).Args) { if ($a.Long -and $a.Long -ceq $name) { return @{ Spec = $a; Global = $false } } }
        foreach ($a in $script:BoabGlobalArgs) { if ($a.Long -ceq $name) { return @{ Spec = $a; Global = $true } } }
        $null
    }
    $findShort = {
        param([string]$c)
        foreach ($a in (& $cmdSpec).Args) { if ($a.Short -and $a.Short -ceq $c) { return @{ Spec = $a; Global = $false } } }
        $null
    }
    $positionals = { @((& $cmdSpec).Args | Where-Object { $_.Kind -eq 'pos' -or $_.Kind -eq 'posmulti' }) }
    $versionText = {
        $name = if ($path) { 'boab-' + ($path -replace ' ', '-') } else { 'boab' }
        "$name 0.1.0`n"
    }
    $helpText = { param([string]$p) ($script:BoabCliHelp[$p].Help -replace "`r`n", "`n") + "`n" }

    # Store a parsed value; returns an error result or $null.
    $store = {
        param([hashtable]$found, $value, [bool]$fromFlag)
        $spec = $found.Spec
        $level = if ($found.Global) { $path } else { '' }
        $seenKey = "$path|$($spec.Name)"
        if ($spec.Kind -ne 'multi' -and $spec.Kind -ne 'posmulti' -and $seen.ContainsKey($seenKey)) {
            return (New-BoabCliError -Message ("the argument '{0}' cannot be used multiple times" -f (Get-BoabArgDisplay $spec)) -Usage (Get-BoabCliUsage -Path $path -Full))
        }
        $seen[$seenKey] = $true
        if ($found.Global) {
            $globals[$spec.Name] = $value
            $globalOrder.Add(@{ Level = $path; Spec = $spec })
        }
        elseif ($spec.Kind -eq 'multi' -or $spec.Kind -eq 'posmulti') {
            if (-not $values.ContainsKey($spec.Name)) { $values[$spec.Name] = [System.Collections.Generic.List[string]]::new() }
            $values[$spec.Name].Add([string]$value)
        }
        else {
            $values[$spec.Name] = $value
        }
        $null
    }

    while ($i -lt $n) {
        $tok = [string]$Arguments[$i]
        $i++
        $cmd = & $cmdSpec
        $hasSubs = $cmd.ContainsKey('Subcommands')

        if (-not $trailing -and $tok -ceq '--') { $trailing = $true; continue }

        if (-not $trailing -and $tok.StartsWith('--', [StringComparison]::Ordinal)) {
            $body = $tok.Substring(2)
            $inline = $null
            $eq = $body.IndexOf('=')
            if ($eq -ge 0) { $inline = $body.Substring($eq + 1); $body = $body.Substring(0, $eq) }
            if ($body -ceq 'help') { return @{ Action = 'help'; Stdout = (& $helpText $path); Stderr = ''; ExitCode = 0 } }
            if ($body -ceq 'version') { return @{ Action = 'version'; Stdout = (& $versionText); Stderr = ''; ExitCode = 0 } }
            $found = & $findLong $body
            if ($null -eq $found) {
                $longs = @($cmd.Args | Where-Object { $_.Long } | ForEach-Object { $_.Long }) + @($script:BoabGlobalArgs | ForEach-Object { $_.Long }) + @('help', 'version')
                $sugg = Get-BoabCliSuggestion -Value $body -Candidates $longs
                if ($sugg) {
                    $suggSpec = (& $findLong $sugg)
                    $used = if ($suggSpec) { @($suggSpec.Spec) } else { @() }
                    return (New-BoabCliError -Message ("unexpected argument '{0}' found" -f $tok) -Tip ("a similar argument exists: '--{0}'" -f $sugg) -Usage (Get-BoabCliUsage -Path $path -Used $used))
                }
                return (New-BoabCliError -Message ("unexpected argument '{0}' found" -f $tok) -Usage (Get-BoabCliUsage -Path $path -Full))
            }
            $spec = $found.Spec
            if ($spec.Kind -eq 'flag') {
                if ($null -ne $inline) {
                    return (New-BoabCliError -Message ("unexpected value '{0}' for '--{1}' found; no more were expected" -f $inline, $spec.Long) -Usage (Get-BoabCliUsage -Path $path -Used @($spec)))
                }
                $err = & $store $found $true $true
                if ($err) { return $err }
                continue
            }
            # option / multi
            $raw = $inline
            if ($null -eq $raw) {
                $display = Get-BoabArgDisplay $spec
                $missing = { New-BoabCliError -Message (("a value is required for '{0}' but none was supplied" -f $display) + $(if ($spec.Type -eq 'bool') { "`n  [possible values: true, false]" } else { '' })) }
                if ($i -ge $n) { return (& $missing) }
                $next = [string]$Arguments[$i]
                if ($next.Length -gt 1 -and $next.StartsWith('-') -and -not $trailing) {
                    # The next token is flag-like: clap parses it as an argument.
                    $nextName = if ($next.StartsWith('--')) { ($next.Substring(2) -split '=', 2)[0] } else { $null }
                    $known = $false
                    if ($null -ne $nextName) { $known = ($nextName -ceq 'help') -or ($nextName -ceq 'version') -or ($null -ne (& $findLong $nextName)) }
                    else {
                        $c0 = [string]$next[1]
                        $known = ($c0 -ceq 'h') -or ($c0 -ceq 'V') -or ($null -ne (& $findShort $c0))
                    }
                    if ($known) { return (& $missing) }
                    return (New-BoabCliError -Message ("unexpected argument '{0}' found" -f $next) -Usage (Get-BoabCliUsage -Path $path -Full))
                }
                $raw = $next
                $i++
            }
            $parsed = ConvertFrom-BoabCliValue -Spec $spec -Raw $raw
            if (-not $parsed.Ok) { return $parsed.Error }
            $err = & $store $found $parsed.Value $false
            if ($err) { return $err }
            continue
        }

        if (-not $trailing -and $tok.Length -gt 1 -and $tok.StartsWith('-')) {
            # Short flag cluster.
            $j = 1
            while ($j -lt $tok.Length) {
                $c = [string]$tok[$j]
                if ($c -ceq 'h') { return @{ Action = 'help'; Stdout = (& $helpText $path); Stderr = ''; ExitCode = 0 } }
                if ($c -ceq 'V') { return @{ Action = 'version'; Stdout = (& $versionText); Stderr = ''; ExitCode = 0 } }
                $found = & $findShort $c
                if ($null -eq $found) {
                    $tip = $null
                    $isNumber = $tok -match '^-\d'
                    $posLeft = @(& $positionals)
                    if ($isNumber -and $j -eq 1 -and $posLeft.Count -gt 0) { $tip = "to pass '{0}' as a value, use '-- {0}'" -f $tok }
                    $shown = if ($j -eq 1) { $tok } else { '-' + $c }
                    return (New-BoabCliError -Message ("unexpected argument '{0}' found" -f $shown) -Tip $tip -Usage (Get-BoabCliUsage -Path $path -Full))
                }
                $spec = $found.Spec
                if ($spec.Kind -eq 'flag') { $err = & $store $found $true $true; if ($err) { return $err }; $j++; continue }
                $rest = $tok.Substring($j + 1)
                if ($rest.StartsWith('=')) { $rest = $rest.Substring(1) }
                if ($rest.Length -eq 0) {
                    if ($i -ge $n) { return (New-BoabCliError -Message ("a value is required for '{0}' but none was supplied" -f (Get-BoabArgDisplay $spec))) }
                    $rest = [string]$Arguments[$i]
                    $i++
                }
                $parsed = ConvertFrom-BoabCliValue -Spec $spec -Raw $rest
                if (-not $parsed.Ok) { return $parsed.Error }
                $err = & $store $found $parsed.Value $false
                if ($err) { return $err }
                break
            }
            continue
        }

        # Positional or subcommand.
        if ($hasSubs -and -not $trailing) {
            if ($tok -ceq 'help') {
                $target = ''
                $helpPath = $path
                while ($i -lt $n) {
                    $t = [string]$Arguments[$i]; $i++
                    $spec = $script:BoabCommandSpec[$helpPath]
                    if ($null -ne $spec -and $spec.ContainsKey('Subcommands') -and $spec.Subcommands -ccontains $t) {
                        $helpPath = if ($helpPath) { "$helpPath $t" } else { $t }
                        continue
                    }
                    if (-not $helpPath -and $t -ceq 'help') { $helpPath = 'help'; continue }
                    return (New-BoabCliError -Message ("unrecognized subcommand '{0}'" -f $t) -Usage (Get-BoabCliUsage -Path $helpPath -Full))
                }
                [void]$target
                return @{ Action = 'help'; Stdout = (& $helpText $helpPath); Stderr = ''; ExitCode = 0 }
            }
            if ($cmd.Subcommands -ccontains $tok) {
                $path = if ($path) { "$path $tok" } else { $tok }
                $posIndex = 0
                continue
            }
            $sugg = Get-BoabCliSuggestion -Value $tok -Candidates (@($cmd.Subcommands) + @('help'))
            $tip = if ($sugg) { "a similar subcommand exists: '{0}'" -f $sugg } else { $null }
            return (New-BoabCliError -Message ("unrecognized subcommand '{0}'" -f $tok) -Tip $tip -Usage (Get-BoabCliUsage -Path $path -Full))
        }
        $pos = @(& $positionals)
        if ($posIndex -ge $pos.Count) {
            return (New-BoabCliError -Message ("unexpected argument '{0}' found" -f $tok) -Usage (Get-BoabCliUsage -Path $path -Full))
        }
        $spec = $pos[$posIndex]
        $parsed = ConvertFrom-BoabCliValue -Spec $spec -Raw $tok
        if (-not $parsed.Ok) { return $parsed.Error }
        $err = & $store @{ Spec = $spec; Global = $false } $parsed.Value $false
        if ($err) { return $err }
        if ($spec.Kind -ne 'posmulti') { $posIndex++ }
    }

    $cmd = & $cmdSpec
    if ($cmd.ContainsKey('Subcommands')) {
        # clap: a missing subcommand prints the help to stderr and exits 2.
        return @{ Action = 'error'; Stdout = ''; Stderr = (& $helpText $path); ExitCode = 2 }
    }
    $missing = @($cmd.Args | Where-Object { $_.Required -and -not $values.ContainsKey($_.Name) })
    if ($missing.Count -gt 0) {
        $msg = "the following required arguments were not provided:`n" + (($missing | ForEach-Object { '  ' + (Get-BoabArgDisplay $_) }) -join "`n")
        return (New-BoabCliError -Message $msg -Usage (Get-BoabCliUsage -Path $path))
    }
    # conflicts_with: --quiet vs --verbose
    if ($globals.verbose -and $globals.quiet) {
        $first = $null; $second = $null
        foreach ($g in $globalOrder) {
            if ($g.Spec.Name -eq 'verbose' -or $g.Spec.Name -eq 'quiet') {
                if ($null -eq $first) { $first = $g } elseif ($null -eq $second) { $second = $g }
            }
        }
        $levelPath = $second.Level
        $used = @($globalOrder | Where-Object { $_.Level -eq $levelPath -and $_ -ne $second } | ForEach-Object { $_.Spec })
        $usageTokens = @('boab')
        if ($levelPath) { $usageTokens += $levelPath }
        $usageTokens += @($used | ForEach-Object { Get-BoabArgUsageToken $_ })
        if ($script:BoabCommandSpec[$levelPath].ContainsKey('Subcommands')) { $usageTokens += '<COMMAND>' }
        return (New-BoabCliError -Message ("the argument '--{0}' cannot be used with '--{1}'" -f $first.Spec.Long, $second.Spec.Long) -Usage ($usageTokens -join ' '))
    }
    foreach ($a in $cmd.Args) {
        if (-not $values.ContainsKey($a.Name)) {
            if ($a.Kind -eq 'flag') { $values[$a.Name] = $false }
            elseif ($a.Kind -eq 'multi' -or $a.Kind -eq 'posmulti') { $values[$a.Name] = [System.Collections.Generic.List[string]]::new() }
            else { $values[$a.Name] = $a.Default }
        }
    }
    @{ Action = 'run'; Path = $path; Values = $values; Globals = $globals }
}
