# Timestamps. The Rust code uses the `time` crate:
#   * time::serde::rfc3339   -> "2026-05-19T01:42:01.749119Z" (fraction trimmed, "Z" for UTC)
#   * time::serde::iso8601   -> "+002030-09-01T00:00:00.000000000Z" (plan target dates)
# Timestamps are stored as canonical strings in the PowerShell model; these helpers
# parse, canonicalise, compare and produce them.

# Tests may pin "now" by setting this to a [DateTimeOffset].
$script:BoabClockOverride = $null

function Get-BoabNow {
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param()
    if ($null -ne $script:BoabClockOverride) { return [DateTimeOffset]$script:BoabClockOverride }
    [DateTimeOffset]::UtcNow
}

function ConvertTo-BoabTimeParts {
    param([DateTimeOffset]$Value)
    $utc = $Value
    @{
        Year          = $utc.Year
        Month         = $utc.Month
        Day           = $utc.Day
        Hour          = $utc.Hour
        Minute        = $utc.Minute
        Second        = $utc.Second
        Nanosecond    = [int](($utc.Ticks % 10000000) * 100)
        OffsetMinutes = [int]$utc.Offset.TotalMinutes
    }
}

function Format-BoabOffset {
    param([int]$OffsetMinutes, [switch]$AllowZ)
    if ($OffsetMinutes -eq 0) { return 'Z' }
    $sign = if ($OffsetMinutes -lt 0) { '-' } else { '+' }
    $abs = [math]::Abs($OffsetMinutes)
    '{0}{1:00}:{2:00}' -f $sign, [math]::Floor($abs / 60), ($abs % 60)
}

function Format-BoabRfc3339Parts {
    param([hashtable]$Parts)
    if ($Parts.Year -lt 0 -or $Parts.Year -gt 9999) { throw (New-BoabException 'The year component cannot be formatted into the requested format.') }
    $s = '{0:0000}-{1:00}-{2:00}T{3:00}:{4:00}:{5:00}' -f $Parts.Year, $Parts.Month, $Parts.Day, $Parts.Hour, $Parts.Minute, $Parts.Second
    if ($Parts.Nanosecond -ne 0) {
        $s += '.' + ($Parts.Nanosecond.ToString('000000000')).TrimEnd('0')
    }
    $s + (Format-BoabOffset -OffsetMinutes $Parts.OffsetMinutes)
}

function Format-BoabRfc3339 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][DateTimeOffset]$Value)
    Format-BoabRfc3339Parts -Parts (ConvertTo-BoabTimeParts -Value $Value)
}

function Get-BoabTimestamp {
    # OffsetDateTime::now_utc() serialised with time::serde::rfc3339.
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Format-BoabRfc3339 -Value (Get-BoabNow).ToUniversalTime()
}

function ConvertFrom-BoabRfc3339 {
    # Parse an RFC 3339 timestamp into parts (throws on invalid input).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowEmptyString()][string]$Text)
    $m = [regex]::Match($Text, '^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$')
    if (-not $m.Success) { throw (New-BoabException ("invalid RFC 3339 timestamp: {0}" -f $Text)) }
    $frac = $m.Groups[7].Value
    $nanos = 0
    if ($frac.Length -gt 0) {
        $f9 = if ($frac.Length -ge 9) { $frac.Substring(0, 9) } else { $frac.PadRight(9, '0') }
        $nanos = [int]$f9
    }
    $offset = 0
    if (-not $m.Groups[8].Success) {
        $offset = [int]$m.Groups[10].Value * 60 + [int]$m.Groups[11].Value
        if ($m.Groups[9].Value -eq '-') { $offset = -$offset }
    }
    $parts = @{
        Year = [int]$m.Groups[1].Value; Month = [int]$m.Groups[2].Value; Day = [int]$m.Groups[3].Value
        Hour = [int]$m.Groups[4].Value; Minute = [int]$m.Groups[5].Value; Second = [int]$m.Groups[6].Value
        Nanosecond = $nanos; OffsetMinutes = $offset
    }
    Assert-BoabTimeParts -Parts $parts -Text $Text
    $parts
}

function Assert-BoabTimeParts {
    param([hashtable]$Parts, [string]$Text)
    if ($Parts.Month -lt 1 -or $Parts.Month -gt 12 -or $Parts.Day -lt 1 -or
        $Parts.Day -gt [DateTime]::DaysInMonth([math]::Max(1, [math]::Min(9999, $Parts.Year)), $Parts.Month) -or
        $Parts.Hour -gt 23 -or $Parts.Minute -gt 59 -or $Parts.Second -gt 59) {
        throw (New-BoabException ("invalid timestamp: {0}" -f $Text))
    }
}

function ConvertFrom-BoabIso8601 {
    # Parse the subset of ISO 8601 date-times the `time` crate accepts for
    # time::serde::iso8601 (extended year, optional fraction, Z or +HH:MM).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowEmptyString()][string]$Text)
    $m = [regex]::Match($Text, '^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?(?:(Z)|([+-])(\d{2})(?::?(\d{2}))?)$')
    if (-not $m.Success) { throw (New-BoabException ("invalid ISO 8601 timestamp: {0}" -f $Text)) }
    $frac = $m.Groups[7].Value
    $nanos = 0
    if ($frac.Length -gt 0) {
        $f9 = if ($frac.Length -ge 9) { $frac.Substring(0, 9) } else { $frac.PadRight(9, '0') }
        $nanos = [int]$f9
    }
    $offset = 0
    if (-not $m.Groups[8].Success) {
        $mins = if ($m.Groups[11].Success) { [int]$m.Groups[11].Value } else { 0 }
        $offset = [int]$m.Groups[10].Value * 60 + $mins
        if ($m.Groups[9].Value -eq '-') { $offset = -$offset }
    }
    $sec = if ($m.Groups[6].Success) { [int]$m.Groups[6].Value } else { 0 }
    $parts = @{
        Year = [int]$m.Groups[1].Value; Month = [int]$m.Groups[2].Value; Day = [int]$m.Groups[3].Value
        Hour = [int]$m.Groups[4].Value; Minute = [int]$m.Groups[5].Value; Second = $sec
        Nanosecond = $nanos; OffsetMinutes = $offset
    }
    Assert-BoabTimeParts -Parts $parts -Text $Text
    $parts
}

function Format-BoabIso8601Parts {
    param([hashtable]$Parts)
    $sign = if ($Parts.Year -lt 0) { '-' } else { '+' }
    $s = '{0}{1:000000}-{2:00}-{3:00}T{4:00}:{5:00}:{6:00}.{7:000000000}' -f $sign, [math]::Abs($Parts.Year), $Parts.Month, $Parts.Day, $Parts.Hour, $Parts.Minute, $Parts.Second, $Parts.Nanosecond
    $s + (Format-BoabOffset -OffsetMinutes $Parts.OffsetMinutes)
}

function ConvertTo-BoabCanonicalRfc3339 {
    # Round-trip through the parser/formatter, like serde deserialise + serialise.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    Format-BoabRfc3339Parts -Parts (ConvertFrom-BoabRfc3339 -Text $Text)
}

function ConvertTo-BoabCanonicalIso8601 {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    Format-BoabIso8601Parts -Parts (ConvertFrom-BoabIso8601 -Text $Text)
}

function Get-BoabInstantKey {
    # Sortable instant (UTC nanoseconds since 0001-01-01) for a parts hashtable.
    param([hashtable]$Parts)
    $y = [math]::Max(1, [math]::Min(9999, $Parts.Year))
    $dt = [DateTime]::new($y, $Parts.Month, $Parts.Day, $Parts.Hour, $Parts.Minute, $Parts.Second, [DateTimeKind]::Utc)
    $ticks = [decimal]$dt.Ticks - [decimal]$Parts.OffsetMinutes * 600000000
    $ticks * 100 + [decimal]($Parts.Nanosecond)
}

function Get-BoabRfc3339Key {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    Get-BoabInstantKey -Parts (ConvertFrom-BoabRfc3339 -Text $Text)
}

function Get-BoabIso8601Key {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    Get-BoabInstantKey -Parts (ConvertFrom-BoabIso8601 -Text $Text)
}

function Format-BoabUnixRfc3339 {
    # OffsetDateTime::from_unix_timestamp(t).format(&Rfc3339); $null when out of range.
    [CmdletBinding()]
    [OutputType([string])]
    param([long]$Seconds)
    try {
        $dto = [DateTimeOffset]::FromUnixTimeSeconds($Seconds)
    }
    catch {
        return $null
    }
    Format-BoabRfc3339 -Value $dto
}
