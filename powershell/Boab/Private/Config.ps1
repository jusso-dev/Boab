# Workspace configuration (.boab/config.toml), port of src/config.rs.
# Includes a TOML reader for the subset of TOML a config file can contain and a
# writer that reproduces `toml::to_string_pretty(&Config)` byte for byte.

function New-BoabDefaultConfig {
    [CmdletBinding()]
    param()
    [ordered]@{
        schema_version = [long]1
        scanner        = [ordered]@{
            default_rate_limit  = '1/second'
            tls_timeout_seconds = [long]10
            air_gapped          = $true
        }
        reporting      = [ordered]@{
            default_format = 'md'
        }
    }
}

# --- TOML string encoding (port of toml_write::TomlStringBuilder::as_default) ---

function Get-BoabTomlStringMetrics {
    param([string]$Value)
    $m = @{ MaxSingle = 0; MaxDouble = 0; EscapeCodes = $false; Escape = $false; Newline = $false }
    $ps = 0; $pd = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq "'") { $ps++; if ($ps -gt $m.MaxSingle) { $m.MaxSingle = $ps } } else { $ps = 0 }
        if ($ch -eq '"') { $pd++; if ($pd -gt $m.MaxDouble) { $m.MaxDouble = $pd } } else { $pd = 0 }
        $c = [int]$ch
        if ($ch -eq '\') { $m.Escape = $true }
        elseif ($c -eq 9) { }
        elseif ($c -eq 10) { $m.Newline = $true }
        elseif ($c -le 0x1F -or $c -eq 0x7F) { $m.EscapeCodes = $true }
    }
    $m
}

function ConvertTo-BoabTomlBasicBody {
    param([string]$Value, [bool]$Multiline)
    $sb = [System.Text.StringBuilder]::new()
    $maxDq = if ($Multiline) { 2 } else { 0 }
    $seq = 0
    foreach ($ch in $Value.ToCharArray()) {
        $c = [int]$ch
        if ($ch -eq '"') {
            $seq++
            if ($seq -gt $maxDq) { [void]$sb.Append('\"'); $seq = 0; continue }
            [void]$sb.Append($ch); continue
        }
        $seq = 0
        switch ($c) {
            8 { [void]$sb.Append('\b'); continue }
            9 { [void]$sb.Append('\t'); continue }
            10 { if ($Multiline) { [void]$sb.Append("`n") } else { [void]$sb.Append('\n') }; continue }
            12 { [void]$sb.Append('\f'); continue }
            13 { [void]$sb.Append('\r'); continue }
            92 { [void]$sb.Append('\\'); continue }
            default {
                if ($c -le 0x1F -or $c -eq 0x7F) { [void]$sb.Append('\u').Append($c.ToString('X4')) }
                else { [void]$sb.Append($ch) }
            }
        }
    }
    $sb.ToString()
}

function ConvertTo-BoabTomlString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Value)
    $m = Get-BoabTomlStringMetrics -Value $Value
    # as_basic_pretty
    if (-not ($m.EscapeCodes -or $m.Escape -or $m.MaxDouble -gt 0 -or $m.Newline)) {
        return '"' + (ConvertTo-BoabTomlBasicBody -Value $Value -Multiline $false) + '"'
    }
    # as_literal
    if (-not ($m.EscapeCodes -or $m.MaxSingle -gt 0 -or $m.Newline)) {
        return "'" + $Value + "'"
    }
    $nlPrefix = if ($m.Newline) { "`n" } else { '' }
    # as_ml_basic_pretty
    if (-not ($m.EscapeCodes -or $m.Escape -or $m.MaxDouble -gt 2)) {
        return '"""' + $nlPrefix + (ConvertTo-BoabTomlBasicBody -Value $Value -Multiline $true) + '"""'
    }
    # as_ml_literal
    if (-not ($m.EscapeCodes -or $m.MaxSingle -gt 2)) {
        return "'''" + $nlPrefix + $Value + "'''"
    }
    if ($m.Newline) {
        return '"""' + $nlPrefix + (ConvertTo-BoabTomlBasicBody -Value $Value -Multiline $true) + '"""'
    }
    '"' + (ConvertTo-BoabTomlBasicBody -Value $Value -Multiline $false) + '"'
}

function ConvertTo-BoabConfigToml {
    # toml::to_string_pretty(&Config)
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Config)
    $b = { param($v) if ($v) { 'true' } else { 'false' } }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('schema_version = ').Append($Config.schema_version.ToString([System.Globalization.CultureInfo]::InvariantCulture)).Append("`n")
    [void]$sb.Append("`n[scanner]`n")
    [void]$sb.Append('default_rate_limit = ').Append((ConvertTo-BoabTomlString -Value $Config.scanner.default_rate_limit)).Append("`n")
    [void]$sb.Append('tls_timeout_seconds = ').Append($Config.scanner.tls_timeout_seconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)).Append("`n")
    [void]$sb.Append('air_gapped = ').Append((& $b $Config.scanner.air_gapped)).Append("`n")
    [void]$sb.Append("`n[reporting]`n")
    [void]$sb.Append('default_format = ').Append((ConvertTo-BoabTomlString -Value $Config.reporting.default_format)).Append("`n")
    $sb.ToString()
}

# --- TOML reader -----------------------------------------------------------------

function New-BoabTomlError {
    param([string]$Text, [int]$Pos, [string]$Message)
    $line = 1; $col = 1
    for ($i = 0; $i -lt [math]::Min($Pos, $Text.Length); $i++) {
        if ($Text[$i] -eq "`n") { $line++; $col = 1 } else { $col++ }
    }
    New-BoabException ("TOML parse error at line {0}, column {1}`n  |`n{0} | {2}`n  |`n{3}" -f $line, $col, (($Text -split "`n")[$line - 1]), $Message)
}

function Read-BoabTomlKey {
    param([string]$Text, [ref]$Pos)
    $parts = [System.Collections.Generic.List[string]]::new()
    while ($true) {
        while ($Pos.Value -lt $Text.Length -and ($Text[$Pos.Value] -eq ' ' -or $Text[$Pos.Value] -eq "`t")) { $Pos.Value++ }
        if ($Pos.Value -ge $Text.Length) { throw (New-BoabTomlError $Text $Pos.Value 'invalid key') }
        $ch = $Text[$Pos.Value]
        if ($ch -eq '"' -or $ch -eq "'") {
            $parts.Add((Read-BoabTomlStringValue -Text $Text -Pos $Pos))
        }
        else {
            $start = $Pos.Value
            while ($Pos.Value -lt $Text.Length -and $Text[$Pos.Value] -match '[A-Za-z0-9_-]') { $Pos.Value++ }
            if ($Pos.Value -eq $start) { throw (New-BoabTomlError $Text $Pos.Value 'invalid key') }
            $parts.Add($Text.Substring($start, $Pos.Value - $start))
        }
        while ($Pos.Value -lt $Text.Length -and ($Text[$Pos.Value] -eq ' ' -or $Text[$Pos.Value] -eq "`t")) { $Pos.Value++ }
        if ($Pos.Value -lt $Text.Length -and $Text[$Pos.Value] -eq '.') { $Pos.Value++; continue }
        break
    }
    , $parts.ToArray()
}

function Read-BoabTomlStringValue {
    param([string]$Text, [ref]$Pos)
    $p = $Pos.Value
    $sb = [System.Text.StringBuilder]::new()
    if ($Text.Substring($p).StartsWith('"""')) {
        $p += 3
        if ($p -lt $Text.Length -and $Text[$p] -eq "`n") { $p++ }
        elseif ($p + 1 -lt $Text.Length -and $Text[$p] -eq "`r" -and $Text[$p + 1] -eq "`n") { $p += 2 }
        while ($true) {
            if ($p -ge $Text.Length) { throw (New-BoabTomlError $Text $p 'invalid multiline basic string') }
            if ($Text.Substring($p).StartsWith('"""')) {
                # Up to two extra quotes may precede the closing delimiter.
                $extra = 0
                while ($p + 3 + $extra -lt $Text.Length -and $Text[$p + 3 + $extra] -eq '"' -and $extra -lt 2) { $extra++ }
                [void]$sb.Append([char]34, [int]$extra)
                $p += 3 + $extra
                break
            }
            $ch = $Text[$p]
            if ($ch -eq '\') {
                $p++
                $p = Read-BoabTomlEscape -Text $Text -Pos $p -Builder $sb -Multiline $true
                continue
            }
            [void]$sb.Append($ch); $p++
        }
        $Pos.Value = $p
        return $sb.ToString()
    }
    if ($Text.Substring($p).StartsWith("'''")) {
        $p += 3
        if ($p -lt $Text.Length -and $Text[$p] -eq "`n") { $p++ }
        elseif ($p + 1 -lt $Text.Length -and $Text[$p] -eq "`r" -and $Text[$p + 1] -eq "`n") { $p += 2 }
        $end = $Text.IndexOf("'''", $p, [StringComparison]::Ordinal)
        if ($end -lt 0) { throw (New-BoabTomlError $Text $p 'invalid multiline literal string') }
        $extra = 0
        while ($end + 3 + $extra -lt $Text.Length -and $Text[$end + 3 + $extra] -eq "'" -and $extra -lt 2) { $extra++ }
        $value = $Text.Substring($p, $end - $p) + ("'" * $extra)
        $Pos.Value = $end + 3 + $extra
        return $value
    }
    if ($Text[$p] -eq "'") {
        $end = $Text.IndexOf("'", $p + 1)
        $nl = $Text.IndexOf("`n", $p + 1)
        if ($end -lt 0 -or ($nl -ge 0 -and $nl -lt $end)) { throw (New-BoabTomlError $Text $p 'invalid literal string') }
        $Pos.Value = $end + 1
        return $Text.Substring($p + 1, $end - $p - 1)
    }
    # basic string
    $p++
    while ($true) {
        if ($p -ge $Text.Length -or $Text[$p] -eq "`n") { throw (New-BoabTomlError $Text $p 'invalid basic string') }
        $ch = $Text[$p]
        if ($ch -eq '"') { $p++; break }
        if ($ch -eq '\') {
            $p++
            $p = Read-BoabTomlEscape -Text $Text -Pos $p -Builder $sb -Multiline $false
            continue
        }
        [void]$sb.Append($ch); $p++
    }
    $Pos.Value = $p
    $sb.ToString()
}

function Read-BoabTomlEscape {
    param([string]$Text, [int]$Pos, [System.Text.StringBuilder]$Builder, [bool]$Multiline)
    if ($Pos -ge $Text.Length) { throw (New-BoabTomlError $Text $Pos 'invalid escape sequence') }
    $e = $Text[$Pos]
    switch -CaseSensitive ([string]$e) {
        'b' { [void]$Builder.Append([char]8); return $Pos + 1 }
        't' { [void]$Builder.Append("`t"); return $Pos + 1 }
        'n' { [void]$Builder.Append("`n"); return $Pos + 1 }
        'f' { [void]$Builder.Append([char]12); return $Pos + 1 }
        'r' { [void]$Builder.Append("`r"); return $Pos + 1 }
        'e' { [void]$Builder.Append([char]27); return $Pos + 1 }
        '"' { [void]$Builder.Append('"'); return $Pos + 1 }
        '\' { [void]$Builder.Append('\'); return $Pos + 1 }
        'u' {
            $hex = $Text.Substring($Pos + 1, [math]::Min(4, $Text.Length - $Pos - 1))
            if ($hex -notmatch '^[0-9A-Fa-f]{4}$') { throw (New-BoabTomlError $Text $Pos 'invalid unicode escape') }
            [void]$Builder.Append([char]::ConvertFromUtf32([Convert]::ToInt32($hex, 16))); return $Pos + 5
        }
        'U' {
            $hex = $Text.Substring($Pos + 1, [math]::Min(8, $Text.Length - $Pos - 1))
            if ($hex -notmatch '^[0-9A-Fa-f]{8}$') { throw (New-BoabTomlError $Text $Pos 'invalid unicode escape') }
            [void]$Builder.Append([char]::ConvertFromUtf32([Convert]::ToInt32($hex, 16))); return $Pos + 9
        }
    }
    if ($Multiline -and ($e -eq ' ' -or $e -eq "`t" -or $e -eq "`n" -or $e -eq "`r")) {
        # line-ending backslash: trim whitespace including newlines
        $p = $Pos
        while ($p -lt $Text.Length -and ($Text[$p] -eq ' ' -or $Text[$p] -eq "`t" -or $Text[$p] -eq "`n" -or $Text[$p] -eq "`r")) { $p++ }
        return $p
    }
    throw (New-BoabTomlError $Text $Pos 'invalid escape sequence')
}

function Read-BoabTomlValue {
    param([string]$Text, [ref]$Pos)
    $p = $Pos.Value
    if ($p -ge $Text.Length) { throw (New-BoabTomlError $Text $p 'string values must be quoted, expected literal string') }
    $ch = $Text[$p]
    if ($ch -eq '"' -or $ch -eq "'") { return Read-BoabTomlStringValue -Text $Text -Pos $Pos }
    $m = [regex]::Match($Text.Substring($p), '^[^\s#,\]\}]+')
    if (-not $m.Success) { throw (New-BoabTomlError $Text $p 'string values must be quoted, expected literal string') }
    $tok = $m.Value
    $Pos.Value = $p + $tok.Length
    if ($tok -ceq 'true') { return $true }
    if ($tok -ceq 'false') { return $false }
    if ($tok -match '^[+-]?(0|[1-9](_?[0-9])*)$') {
        $clean = $tok.Replace('_', '')
        $bi = [System.Numerics.BigInteger]::Parse($clean, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($bi -gt [long]::MaxValue -or $bi -lt [long]::MinValue) { throw (New-BoabTomlError $Text $p 'number too large to fit in target type') }
        return [long]$bi
    }
    if ($tok -match '^0x[0-9A-Fa-f](_?[0-9A-Fa-f])*$') { return [long][Convert]::ToInt64($tok.Substring(2).Replace('_', ''), 16) }
    if ($tok -match '^0o[0-7](_?[0-7])*$') { return [long][Convert]::ToInt64($tok.Substring(2).Replace('_', ''), 8) }
    if ($tok -match '^0b[01](_?[01])*$') { return [long][Convert]::ToInt64($tok.Substring(2).Replace('_', ''), 2) }
    if ($tok -match '^[+-]?(0|[1-9](_?[0-9])*)(\.[0-9](_?[0-9])*)?([eE][+-]?[0-9](_?[0-9])*)?$' -or $tok -match '^[+-]?(inf|nan)$') {
        return [double]::Parse($tok.Replace('_', '').Replace('inf', 'Infinity').Replace('nan', 'NaN'), [System.Globalization.CultureInfo]::InvariantCulture)
    }
    # Dates/times and anything else are kept as an opaque marker.
    return [pscustomobject]@{ TomlRaw = $tok }
}

function ConvertFrom-BoabToml {
    # Returns a nested [ordered] table structure.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $root = [ordered]@{}
    $current = $root
    $pos = 0
    $len = $Text.Length
    $definedTables = @{}
    while ($pos -lt $len) {
        $ch = $Text[$pos]
        if ($ch -eq ' ' -or $ch -eq "`t" -or $ch -eq "`r" -or $ch -eq "`n") { $pos++; continue }
        if ($ch -eq '#') {
            $nl = $Text.IndexOf("`n", $pos)
            $pos = if ($nl -lt 0) { $len } else { $nl + 1 }
            continue
        }
        if ($ch -eq '[') {
            $isArray = $pos + 1 -lt $len -and $Text[$pos + 1] -eq '['
            $pos += $(if ($isArray) { 2 } else { 1 })
            $keyPos = $pos
            $keys = Read-BoabTomlKey -Text $Text -Pos ([ref]$pos)
            $close = if ($isArray) { ']]' } else { ']' }
            if (-not $Text.Substring($pos).StartsWith($close)) { throw (New-BoabTomlError $Text $pos 'invalid table header') }
            $pos += $close.Length
            $tbl = $root
            for ($i = 0; $i -lt $keys.Count; $i++) {
                $k = $keys[$i]
                $last = $i -eq $keys.Count - 1
                if ($last -and $isArray) {
                    if (-not $tbl.Contains($k)) { $tbl[$k] = [System.Collections.Generic.List[object]]::new() }
                    $newT = [ordered]@{}
                    $tbl[$k].Add($newT)
                    $tbl = $newT
                    break
                }
                if (-not $tbl.Contains($k)) { $tbl[$k] = [ordered]@{} }
                elseif ($tbl[$k] -is [System.Collections.Generic.List[object]]) { $tbl = $tbl[$k][$tbl[$k].Count - 1]; continue }
                elseif ($tbl[$k] -isnot [System.Collections.IDictionary]) { throw (New-BoabTomlError $Text $keyPos 'duplicate key') }
                $tbl = $tbl[$k]
            }
            if (-not $isArray) {
                $name = $keys -join '.'
                if ($definedTables.ContainsKey($name)) { throw (New-BoabTomlError $Text $keyPos 'invalid table header') }
                $definedTables[$name] = $true
            }
            $current = $tbl
            Skip-BoabTomlLineEnd -Text $Text -Pos ([ref]$pos)
            continue
        }
        $keyPos = $pos
        $keys = Read-BoabTomlKey -Text $Text -Pos ([ref]$pos)
        if ($pos -ge $len -or $Text[$pos] -ne '=') { throw (New-BoabTomlError $Text $pos 'expected `.`, `=`') }
        $pos++
        while ($pos -lt $len -and ($Text[$pos] -eq ' ' -or $Text[$pos] -eq "`t")) { $pos++ }
        $value = Read-BoabTomlValue -Text $Text -Pos ([ref]$pos)
        $tbl = $current
        for ($i = 0; $i -lt $keys.Count - 1; $i++) {
            $k = $keys[$i]
            if (-not $tbl.Contains($k)) { $tbl[$k] = [ordered]@{} }
            $tbl = $tbl[$k]
        }
        $lastKey = $keys[$keys.Count - 1]
        if ($tbl.Contains($lastKey)) { throw (New-BoabTomlError $Text $keyPos 'duplicate key') }
        $tbl[$lastKey] = $value
        Skip-BoabTomlLineEnd -Text $Text -Pos ([ref]$pos)
    }
    , $root
}

function Skip-BoabTomlLineEnd {
    param([string]$Text, [ref]$Pos)
    $p = $Pos.Value
    while ($p -lt $Text.Length -and ($Text[$p] -eq ' ' -or $Text[$p] -eq "`t")) { $p++ }
    if ($p -lt $Text.Length -and $Text[$p] -eq '#') {
        $nl = $Text.IndexOf("`n", $p)
        $p = if ($nl -lt 0) { $Text.Length } else { $nl }
    }
    if ($p -lt $Text.Length -and $Text[$p] -eq "`r") { $p++ }
    if ($p -lt $Text.Length -and $Text[$p] -ne "`n") { throw (New-BoabTomlError $Text $p 'expected newline, `#`') }
    $Pos.Value = $p
}

function ConvertTo-BoabConfigRecord {
    # serde(default) deserialisation of Config from a parsed TOML table.
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Table)
    $cfg = New-BoabDefaultConfig
    $u = {
        param($v, [ulong]$max, [string]$bits)
        if ($v -isnot [long]) { throw (New-BoabException ("invalid type: {0}, expected u{1}" -f (Get-BoabTomlTypeName $v), $bits)) }
        if ($v -lt 0 -or [ulong]$v -gt $max) { throw (New-BoabException ("invalid value: integer ``{0}``, expected u{1}" -f $v, $bits)) }
        [long]$v
    }
    $s = {
        param($v)
        if ($v -isnot [string]) { throw (New-BoabException ("invalid type: {0}, expected a string" -f (Get-BoabTomlTypeName $v))) }
        $v
    }
    $bo = {
        param($v)
        if ($v -isnot [bool]) { throw (New-BoabException ("invalid type: {0}, expected a boolean" -f (Get-BoabTomlTypeName $v))) }
        $v
    }
    if ($Table.Contains('schema_version')) { $cfg.schema_version = & $u $Table['schema_version'] ([uint32]::MaxValue) '32' }
    if ($Table.Contains('scanner')) {
        $sc = $Table['scanner']
        if ($sc -isnot [System.Collections.IDictionary]) { throw (New-BoabException ("invalid type: {0}, expected struct ScannerConfig" -f (Get-BoabTomlTypeName $sc))) }
        if ($sc.Contains('default_rate_limit')) { $cfg.scanner.default_rate_limit = & $s $sc['default_rate_limit'] }
        if ($sc.Contains('tls_timeout_seconds')) { $cfg.scanner.tls_timeout_seconds = & $u $sc['tls_timeout_seconds'] ([ulong]::MaxValue) '64' }
        if ($sc.Contains('air_gapped')) { $cfg.scanner.air_gapped = & $bo $sc['air_gapped'] }
    }
    if ($Table.Contains('reporting')) {
        $rp = $Table['reporting']
        if ($rp -isnot [System.Collections.IDictionary]) { throw (New-BoabException ("invalid type: {0}, expected struct ReportingConfig" -f (Get-BoabTomlTypeName $rp))) }
        if ($rp.Contains('default_format')) { $cfg.reporting.default_format = & $s $rp['default_format'] }
    }
    $cfg
}

function Get-BoabTomlTypeName {
    param($Value)
    if ($Value -is [string]) { return 'string' }
    if ($Value -is [bool]) { return 'boolean' }
    if ($Value -is [long]) { return 'integer' }
    if ($Value -is [double]) { return 'float' }
    if ($Value -is [System.Collections.IDictionary]) { return 'table' }
    if ($Value -is [System.Collections.IList]) { return 'array' }
    'datetime'
}

function Read-BoabConfig {
    # config::load
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $path = Get-BoabWorkspacePath -Workspace $Workspace -Kind Config
    try {
        $text = Read-BoabTextFile -Path $path
    }
    catch {
        throw (New-BoabException ("read {0}: {1}" -f $path, (Get-BoabIoErrorText -Exception $_ -Path $path)))
    }
    try {
        $table = ConvertFrom-BoabToml -Text $text
        ConvertTo-BoabConfigRecord -Table $table
    }
    catch {
        throw (New-BoabException ("parse TOML from {0}: {1}" -f $path, (Get-BoabErrorMessage $_)))
    }
}

function Save-BoabConfig {
    # config::save
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][System.Collections.IDictionary]$Config)
    $path = Get-BoabWorkspacePath -Workspace $Workspace -Kind Config
    $text = ConvertTo-BoabConfigToml -Config $Config
    try {
        Write-BoabTextFile -Path $path -Content $text
    }
    catch {
        throw (New-BoabException (Get-BoabIoErrorText -Exception $_ -Path $path))
    }
}

function Get-BoabConfigValue {
    # config::get_value; returns $null for unknown keys.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Config, [Parameter(Mandatory)][string]$Key)
    switch -CaseSensitive ($Key) {
        'schema_version' { return $Config.schema_version.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        'scanner.default_rate_limit' { return [string]$Config.scanner.default_rate_limit }
        'scanner.tls_timeout_seconds' { return $Config.scanner.tls_timeout_seconds.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        'scanner.air_gapped' { return $(if ($Config.scanner.air_gapped) { 'true' } else { 'false' }) }
        'reporting.default_format' { return [string]$Config.reporting.default_format }
    }
    $null
}

function Set-BoabConfigValue {
    # config::set_value (mutates $Config).
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Config,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    switch -CaseSensitive ($Key) {
        'schema_version' {
            try { $Config.schema_version = [long](ConvertFrom-BoabRustUnsigned -Text $Value -Max ([uint32]::MaxValue)) }
            catch { throw (New-BoabException ("schema_version must be a u32: {0}" -f (Get-BoabErrorMessage $_))) }
            return
        }
        'scanner.default_rate_limit' { $Config.scanner.default_rate_limit = $Value; return }
        'scanner.tls_timeout_seconds' {
            try {
                $parsed = ConvertFrom-BoabRustUnsigned -Text $Value -Max ([ulong]::MaxValue)
                $Config.scanner.tls_timeout_seconds = if ($parsed -le [long]::MaxValue) { [long]$parsed } else { $parsed }
            }
            catch { throw (New-BoabException ("tls_timeout_seconds must be a u64: {0}" -f (Get-BoabErrorMessage $_))) }
            return
        }
        'scanner.air_gapped' {
            try { $Config.scanner.air_gapped = ConvertFrom-BoabRustBool -Text $Value }
            catch { throw (New-BoabException ("air_gapped must be true or false: {0}" -f (Get-BoabErrorMessage $_))) }
            return
        }
        'reporting.default_format' {
            if ($Value -cnotin @('json', 'md', 'cbom', 'html')) { throw (New-BoabException 'default_format must be one of: json, md, cbom, html') }
            $Config.reporting.default_format = $Value
            return
        }
    }
    throw (New-BoabException ("unknown config key: {0}" -f $Key))
}
