# JSON serialisation that is byte-compatible with serde_json (preserve_order).
#
# ConvertTo-BoabJson mirrors serde_json::to_string_pretty (and serde_json::to_string
# with -Compress). ConvertFrom-BoabJson parses into [ordered] hashtables and
# List[object] while keeping integers ([long]/[ulong]) and floats ([double])
# distinguishable, which is required to mirror serde_json::Value::as_u64 etc.

$script:BoabInvariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:BoabJsonEscapeRegex = [regex]::new('[\x00-\x1f"\\]', [System.Text.RegularExpressions.RegexOptions]::Compiled)

function ConvertTo-BoabJsonString {
    # serde_json string escaping: only ", \ and control characters < 0x20 are escaped.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Value)

    if (-not $script:BoabJsonEscapeRegex.IsMatch($Value)) { return '"' + $Value + '"' }
    $sb = [System.Text.StringBuilder]::new($Value.Length + 2)
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -ge 0x20 -and $ch -ne '"' -and $ch -ne '\') {
            [void]$sb.Append($ch)
            continue
        }
        switch ($code) {
            0x22 { [void]$sb.Append('\"'); break }
            0x5C { [void]$sb.Append('\\'); break }
            0x08 { [void]$sb.Append('\b'); break }
            0x0C { [void]$sb.Append('\f'); break }
            0x0A { [void]$sb.Append('\n'); break }
            0x0D { [void]$sb.Append('\r'); break }
            0x09 { [void]$sb.Append('\t'); break }
            default { [void]$sb.Append('\u00').Append($code.ToString('x2')) }
        }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function Split-BoabShortestFloat {
    # Returns @(digits, exponent) such that value = 0.digits * 10^exponent ... expressed
    # as: digits (no leading zeros) and k where value = digits * 10^k.
    param([string]$Text)
    $t = $Text.TrimStart('-')
    $exp = 0
    $eIdx = $t.IndexOfAny([char[]]@('E', 'e'))
    if ($eIdx -ge 0) {
        $exp = [int]::Parse($t.Substring($eIdx + 1), $script:BoabInvariant)
        $t = $t.Substring(0, $eIdx)
    }
    $dot = $t.IndexOf('.')
    if ($dot -ge 0) {
        $frac = $t.Substring($dot + 1)
        $t = $t.Substring(0, $dot) + $frac
        $exp -= $frac.Length
    }
    $t = $t.TrimStart('0')
    if ($t.Length -eq 0) { return , @('0', 0) }
    $trimmed = $t.TrimEnd('0')
    $exp += ($t.Length - $trimmed.Length)
    , @($trimmed, $exp)
}

function Format-BoabRyu {
    # Port of ryu's pretty formatting (format64 / format32) given shortest digits.
    param(
        [string]$Shortest,
        [bool]$Negative,
        [int]$MaxDigits  # 16 for f64, 13 for f32
    )
    $parts = Split-BoabShortestFloat -Text $Shortest
    $digits = $parts[0]
    $k = [int]$parts[1]
    $sign = if ($Negative) { '-' } else { '' }
    if ($digits -eq '0') { return "${sign}0.0" }
    $length = $digits.Length
    $kk = $length + $k
    $minNeg = if ($MaxDigits -eq 16) { -5 } else { -6 }
    if ($k -ge 0 -and $kk -le $MaxDigits) {
        return $sign + $digits + ('0' * $k) + '.0'
    }
    if ($kk -gt 0 -and $kk -le $MaxDigits) {
        return $sign + $digits.Substring(0, $kk) + '.' + $digits.Substring($kk)
    }
    if ($kk -gt $minNeg -and $kk -le 0) {
        return $sign + '0.' + ('0' * (-$kk)) + $digits
    }
    # serde_json writes positive exponents with an explicit '+' (e.g. 1e+16, 1e-7).
    $e = $kk - 1
    $expText = if ($e -ge 0) { '+' + $e.ToString($script:BoabInvariant) } else { $e.ToString($script:BoabInvariant) }
    if ($length -eq 1) {
        return $sign + $digits + 'e' + $expText
    }
    return $sign + $digits.Substring(0, 1) + '.' + $digits.Substring(1) + 'e' + $expText
}

function Format-BoabF64 {
    # Format a double the way serde_json (ryu) does. Non-finite values become null.
    [CmdletBinding()]
    [OutputType([string])]
    param([double]$Value)
    if ([double]::IsNaN($Value) -or [double]::IsInfinity($Value)) { return 'null' }
    $neg = $Value -lt 0 -or ($Value -eq 0 -and [double]::IsNegative($Value))
    Format-BoabRyu -Shortest ([math]::Abs($Value).ToString('R', $script:BoabInvariant)) -Negative $neg -MaxDigits 16
}

function Format-BoabF32 {
    # Format a single the way serde_json (ryu f32) does.
    [CmdletBinding()]
    [OutputType([string])]
    param([single]$Value)
    if ([single]::IsNaN($Value) -or [single]::IsInfinity($Value)) { return 'null' }
    $neg = $Value -lt 0 -or ($Value -eq 0 -and [single]::IsNegative($Value))
    Format-BoabRyu -Shortest ([math]::Abs($Value).ToString('R', $script:BoabInvariant)) -Negative $neg -MaxDigits 13
}

function Format-BoabFixed {
    # Mirror Rust's `{:.N}` float formatting: exact decimal expansion of the binary
    # value, rounded half-to-even.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [double]$Value,
        [int]$Decimals = 1
    )
    if ([double]::IsNaN($Value)) { return 'NaN' }
    if ([double]::IsInfinity($Value)) { return $(if ($Value -gt 0) { 'inf' } else { '-inf' }) }
    $neg = $Value -lt 0 -or ($Value -eq 0 -and [double]::IsNegative($Value))
    $bits = [BitConverter]::DoubleToInt64Bits([math]::Abs($Value))
    $expBits = [int](($bits -shr 52) -band 0x7FF)
    $mant = [long]($bits -band 0xFFFFFFFFFFFFF)
    if ($expBits -eq 0) { $e2 = -1074 } else { $mant = $mant -bor 0x10000000000000; $e2 = $expBits - 1075 }
    $scale = [System.Numerics.BigInteger]::Pow(10, $Decimals)
    $num = [System.Numerics.BigInteger]$mant * $scale
    if ($e2 -ge 0) {
        $q = $num * [System.Numerics.BigInteger]::Pow(2, $e2)
    }
    else {
        $den = [System.Numerics.BigInteger]::Pow(2, -$e2)
        $rem = [System.Numerics.BigInteger]::Zero
        $q = [System.Numerics.BigInteger]::DivRem($num, $den, [ref]$rem)
        $twice = $rem * 2
        $cmp = $twice.CompareTo($den)
        if ($cmp -gt 0 -or ($cmp -eq 0 -and -not $q.IsEven)) { $q = $q + 1 }
    }
    $s = $q.ToString()
    if ($Decimals -gt 0) {
        if ($s.Length -le $Decimals) { $s = ('0' * ($Decimals - $s.Length + 1)) + $s }
        $s = $s.Substring(0, $s.Length - $Decimals) + '.' + $s.Substring($s.Length - $Decimals)
    }
    if ($neg) { $s = '-' + $s }
    $s
}

function Test-BoabJsonObjectLike {
    param($Value)
    ($Value -is [System.Collections.IDictionary]) -or ($Value -is [System.Management.Automation.PSCustomObject])
}

function Get-BoabJsonEntries {
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in $Value.Keys) { , @([string]$k, $Value[$k]) }
    }
    else {
        foreach ($p in $Value.PSObject.Properties) { , @($p.Name, $p.Value) }
    }
}

function Write-BoabJsonValue {
    param(
        [System.Text.StringBuilder]$Builder,
        $Value,
        [int]$Indent,
        [bool]$Pretty
    )
    if ($null -eq $Value) { [void]$Builder.Append('null'); return }
    if ($Value -is [System.Management.Automation.PSObject] -and $Value -isnot [System.Management.Automation.PSCustomObject]) {
        $Value = $Value.PSObject.BaseObject
    }
    if ($Value -is [string]) { [void]$Builder.Append((ConvertTo-BoabJsonString -Value $Value)); return }
    if ($Value -is [char]) { [void]$Builder.Append((ConvertTo-BoabJsonString -Value ([string]$Value))); return }
    if ($Value -is [bool]) { [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [single]) { [void]$Builder.Append((Format-BoabF32 -Value $Value)); return }
    if ($Value -is [double]) { [void]$Builder.Append((Format-BoabF64 -Value $Value)); return }
    if ($Value -is [decimal]) { [void]$Builder.Append((Format-BoabF64 -Value ([double]$Value))); return }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [ulong] -or $Value -is [uint32] -or $Value -is [uint16] -or
        $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [System.Numerics.BigInteger]) {
        [void]$Builder.Append($Value.ToString($null, $script:BoabInvariant)); return
    }
    if ($Value -is [guid]) { [void]$Builder.Append('"' + $Value.ToString() + '"'); return }
    if ($Value -is [enum]) { [void]$Builder.Append((ConvertTo-BoabJsonString -Value ([string]$Value))); return }
    if (Test-BoabJsonObjectLike $Value) {
        $entries = @(Get-BoabJsonEntries $Value)
        if ($entries.Count -eq 0) { [void]$Builder.Append('{}'); return }
        [void]$Builder.Append('{')
        $first = $true
        foreach ($entry in $entries) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            if ($Pretty) { [void]$Builder.Append("`n").Append([char]32, [int]($Indent + 1) * 2) }
            [void]$Builder.Append((ConvertTo-BoabJsonString -Value $entry[0]))
            [void]$Builder.Append($(if ($Pretty) { ': ' } else { ':' }))
            Write-BoabJsonValue -Builder $Builder -Value $entry[1] -Indent ($Indent + 1) -Pretty $Pretty
        }
        if ($Pretty) { [void]$Builder.Append("`n").Append([char]32, [int]$Indent * 2) }
        [void]$Builder.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Value) { $items.Add($i) }
        if ($items.Count -eq 0) { [void]$Builder.Append('[]'); return }
        [void]$Builder.Append('[')
        $first = $true
        foreach ($item in $items) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            if ($Pretty) { [void]$Builder.Append("`n").Append([char]32, [int]($Indent + 1) * 2) }
            Write-BoabJsonValue -Builder $Builder -Value $item -Indent ($Indent + 1) -Pretty $Pretty
        }
        if ($Pretty) { [void]$Builder.Append("`n").Append([char]32, [int]$Indent * 2) }
        [void]$Builder.Append(']')
        return
    }
    [void]$Builder.Append((ConvertTo-BoabJsonString -Value ([string]$Value)))
}

function ConvertTo-BoabJson {
    <#
    .SYNOPSIS
    Serialise a value exactly like serde_json::to_string_pretty (or to_string with -Compress).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        $InputObject,
        [switch]$Compress
    )
    $sb = [System.Text.StringBuilder]::new()
    Write-BoabJsonValue -Builder $sb -Value $InputObject -Indent 0 -Pretty (-not $Compress)
    $sb.ToString()
}

function ConvertFrom-BoabJsonElement {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        'Object' {
            $h = [ordered]@{}
            foreach ($p in $Element.EnumerateObject()) {
                # serde_json Map: a later duplicate key overwrites the earlier value in place.
                $h[$p.Name] = ConvertFrom-BoabJsonElement -Element $p.Value
            }
            return , $h
        }
        'Array' {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($e in $Element.EnumerateArray()) { $list.Add((ConvertFrom-BoabJsonElement -Element $e)) }
            return , $list
        }
        'String' { return $Element.GetString() }
        'True' { return $true }
        'False' { return $false }
        'Null' { return $null }
        'Number' {
            $raw = $Element.GetRawText()
            if ($raw.IndexOfAny([char[]]@('.', 'e', 'E')) -lt 0) {
                $l = 0L
                if ([long]::TryParse($raw, [System.Globalization.NumberStyles]::AllowLeadingSign, $script:BoabInvariant, [ref]$l)) { return $l }
                $u = [ulong]0
                if ([ulong]::TryParse($raw, [System.Globalization.NumberStyles]::None, $script:BoabInvariant, [ref]$u)) { return $u }
            }
            return [double]::Parse($raw, [System.Globalization.NumberStyles]::Float, $script:BoabInvariant)
        }
    }
    $null
}

function ConvertFrom-BoabJson {
    <#
    .SYNOPSIS
    Parse JSON text into ordered hashtables / generic lists, preserving key order and
    the integer/float distinction (integers -> [long]/[ulong], floats -> [double]).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Json)
    $opts = [System.Text.Json.JsonDocumentOptions]::new()
    $opts.MaxDepth = 128
    $doc = $null
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse($Json, $opts)
    }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        throw (New-BoabJsonError -Message $inner.Message)
    }
    try {
        $result = ConvertFrom-BoabJsonElement -Element $doc.RootElement
        , $result
    }
    finally {
        $doc.Dispose()
    }
}

function New-BoabJsonError {
    param([string]$Message)
    # System.Text.Json reports "... LineNumber: 0 | BytePositionInLine: 5." (zero based);
    # serde_json reports "... at line 1 column 6". Translate the location part.
    if ($Message -match 'LineNumber: (\d+) \| BytePositionInLine: (\d+)') {
        $line = [int]$Matches[1] + 1
        $col = [int]$Matches[2] + 1
        $head = ($Message -replace '\s*(Path: .*)?LineNumber: .*$', '').Trim().TrimEnd('.')
        if ($head -match 'expected end of string|end of data|reached the end') {
            return "EOF while parsing a value at line $line column $col"
        }
        return "$head at line $line column $col"
    }
    $Message
}

function Get-BoabJsonU64 {
    # Mirror serde_json::Value::as_u64.
    param($Value)
    if ($Value -is [long] -and $Value -ge 0) { return [ulong]$Value }
    if ($Value -is [int] -and $Value -ge 0) { return [ulong]$Value }
    if ($Value -is [ulong]) { return $Value }
    if ($Value -is [uint32] -or $Value -is [uint16] -or $Value -is [byte]) { return [ulong]$Value }
    $null
}

function Get-BoabJsonI64 {
    # Mirror serde_json::Value::as_i64.
    param($Value)
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [int16] -or $Value -is [sbyte] -or $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32]) { return [long]$Value }
    if ($Value -is [ulong] -and $Value -le [long]::MaxValue) { return [long]$Value }
    $null
}

function Get-BoabJsonStr {
    # Mirror serde_json::Value::as_str.
    param($Value)
    if ($Value -is [string]) { return $Value }
    $null
}

function Get-BoabJsonField {
    # Mirror serde_json::Value::get(key) on objects (returns $null otherwise).
    param($Object, [string]$Key)
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return , $Object[$Key] }
        return $null
    }
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        $p = $Object.PSObject.Properties[$Key]
        if ($p) { return , $p.Value }
    }
    $null
}

function Test-BoabJsonHasField {
    param($Object, [string]$Key)
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Key) }
    if ($Object -is [System.Management.Automation.PSCustomObject]) { return $null -ne $Object.PSObject.Properties[$Key] }
    $false
}

function Copy-BoabJsonValue {
    # Deep clone of a parsed JSON value.
    param($Value)
    if ($null -eq $Value) { return $null }
    if (Test-BoabJsonObjectLike $Value) {
        $h = [ordered]@{}
        foreach ($e in @(Get-BoabJsonEntries $Value)) { $h[$e[0]] = Copy-BoabJsonValue $e[1] }
        return , $h
    }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Value) { $list.Add((Copy-BoabJsonValue $i)) }
        return , $list
    }
    $Value
}
