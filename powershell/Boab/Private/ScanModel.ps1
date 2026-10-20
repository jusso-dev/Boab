# Scan / Finding model. Port of src/model/scan.rs and src/model/finding.rs.
#
# Scans and findings are [ordered] hashtables whose key order matches the Rust
# struct field order, so `ConvertTo-Json -Depth 32` emits the same JSON shape as
# serde_json (with `preserve_order`). Enum values are the snake_case strings
# serde renders. Timestamps are RFC 3339 strings formatted like
# `time::serde::rfc3339` formats `OffsetDateTime::now_utc()`.

function Format-BoabRfc3339 {
    <#
    .SYNOPSIS
    Format a UTC DateTime the way the Rust `time` crate's RFC 3339 formatter does.
    .DESCRIPTION
    `time` prints the sub-second part with trailing zeros removed, and leaves it
    out entirely when it is zero, followed by `Z` for UTC. Rust's clock on macOS
    has microsecond precision and .NET's has 100 ns ticks, so values look the
    same (for example `2026-10-20T08:16:30.71533Z`). On Linux, Rust can print up
    to 9 fractional digits while .NET prints at most 7.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [datetime] $DateTime
    )
    $utc = $DateTime.ToUniversalTime()
    $base = $utc.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
    $ticks = $utc.Ticks % 10000000
    if ($ticks -eq 0) {
        return "${base}Z"
    }
    $frac = $ticks.ToString('0000000', [System.Globalization.CultureInfo]::InvariantCulture).TrimEnd('0')
    return "$base.${frac}Z"
}

function Get-BoabUtcNow {
    <#
    .SYNOPSIS
    The current UTC time as an RFC 3339 string (same as Rust `OffsetDateTime::now_utc()` serialised).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return Format-BoabRfc3339 -DateTime ([datetime]::UtcNow)
}

function New-BoabId {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return [guid]::NewGuid().ToString().ToLowerInvariant()
}

function New-BoabScan {
    <#
    .SYNOPSIS
    Port of `Scan::new`. Returns an [ordered] hashtable in Rust field order.
    .NOTES
    `findings` is a System.Collections.Generic.List[object] so scanners can add
    to it cheaply. ConvertTo-Json serialises it as a JSON array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('codebase', 'tls_endpoint', 'certificate_store')] [string] $ScanType,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Target
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    return [ordered]@{
        id            = New-BoabId
        name          = $Name
        scan_type     = $ScanType
        status        = 'queued'
        target        = $Target
        config        = [ordered]@{}
        started_at    = Get-BoabUtcNow
        completed_at  = $null
        findings      = $findings
        error_message = $null
    }
}

function New-BoabFinding {
    <#
    .SYNOPSIS
    Port of `Finding::new`. Returns an [ordered] hashtable in Rust field order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScanId,
        [Parameter(Mandatory)] [ValidateSet('file', 'url', 'cert_subject', 'host')] [string] $SourceType,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $SourceLocation,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Evidence,
        [Parameter(Mandatory)] [ValidateSet('low', 'medium', 'high')] [string] $Confidence
    )
    return [ordered]@{
        id              = New-BoabId
        scan_id         = $ScanId
        crypto_asset_id = $null
        source_type     = $SourceType
        source_location = $SourceLocation
        evidence        = $Evidence
        confidence      = $Confidence
        status          = 'new'
        discovered_at   = Get-BoabUtcNow
    }
}

function Get-BoabPathDisplay {
    <#
    .SYNOPSIS
    Render a canonical path the way Rust's `Path::display()` shows a
    `canonicalize()`d path: on Windows the canonical form is a verbatim
    `\\?\C:\...` (or `\\?\UNC\server\share\...`) path. Elsewhere it is unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    if (-not $IsWindows) { return $Path }
    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    return '\\?\' + $Path
}

function Resolve-BoabCanonicalPath {
    <#
    .SYNOPSIS
    Port of `std::fs::canonicalize`: absolute path with every symlink resolved.
    Throws when the path does not exist. Returns the plain (non-verbatim) path;
    use Get-BoabPathDisplay for the Rust display form.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [int] $Depth = 0
    )
    if ($Depth -gt 40) { throw "too many levels of symbolic links: $Path" }
    $cwd = (Get-Location -PSProvider FileSystem).ProviderPath
    $full = [System.IO.Path]::GetFullPath($Path, $cwd)
    if (-not ([System.IO.File]::Exists($full) -or [System.IO.Directory]::Exists($full))) {
        throw "No such file or directory: $Path"
    }
    $root = [System.IO.Path]::GetPathRoot($full)
    $rest = $full.Substring($root.Length)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $parts = $rest.Split([char[]]@('/', '\'), [System.StringSplitOptions]::RemoveEmptyEntries)
    $current = $root
    foreach ($part in $parts) {
        $candidate = [System.IO.Path]::Combine($current, $part)
        $info = [System.IO.FileInfo]::new($candidate)
        $isLink = $false
        try { $isLink = $null -ne $info.LinkTarget } catch { $isLink = $false }
        if ($isLink) {
            $target = $info.LinkTarget
            if (-not [System.IO.Path]::IsPathRooted($target)) {
                $target = [System.IO.Path]::Combine($current, $target)
            }
            $current = Resolve-BoabCanonicalPath -Path $target -Depth ($Depth + 1)
        }
        else {
            # Use the on-disk spelling where we can find it (case-insensitive filesystems).
            $current = $candidate
            try {
                $parent = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetDirectoryName($candidate))
                if ($null -ne $parent -and $parent.Exists) {
                    $match = $parent.EnumerateFileSystemInfos($part) | Select-Object -First 1
                    if ($null -ne $match -and $match.Name -ne $part -and $match.Name -ieq $part) {
                        $current = [System.IO.Path]::Combine($parent.FullName, $match.Name)
                    }
                }
            }
            catch {
                $current = $candidate
            }
        }
    }
    if ($current.Length -gt $root.Length) {
        $current = $current.TrimEnd($sep)
    }
    return $current
}
