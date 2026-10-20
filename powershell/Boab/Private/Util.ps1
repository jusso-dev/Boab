# Small helpers that reproduce Rust std semantics (ASCII case mapping, ordinal
# byte-wise string ordering, stable sorting, integer parsing, io::Error text,
# Path::canonicalize) so that the PowerShell port behaves like the Rust binary.

function New-BoabException {
    # Errors are plain exceptions whose message is the full anyhow-style chain
    # ("context: cause"), which Invoke-Boab prints as "error: <message>".
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param([Parameter(Mandatory)][string]$Message)
    [System.Exception]::new($Message)
}

function Get-BoabErrorMessage {
    # Unwrap PowerShell's MethodInvocationException etc. to the useful message.
    param($ErrorRecordOrException)
    $ex = $ErrorRecordOrException
    if ($ex -is [System.Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
    while ($ex.InnerException -and (
            $ex -is [System.Management.Automation.MethodInvocationException] -or
            $ex -is [System.Management.Automation.SetValueInvocationException] -or
            $ex -is [System.Management.Automation.GetValueInvocationException] -or
            $ex -is [System.Management.Automation.CmdletInvocationException])) {
        $ex = $ex.InnerException
    }
    $ex.Message
}

function ConvertTo-BoabAsciiLower {
    # Rust str::to_ascii_lowercase: only A-Z are mapped.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return [string]$Value }
    $chars = $Value.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 65 -and $c -le 90) { $chars[$i] = [char]($c + 32) }
    }
    [string]::new($chars)
}

function Test-BoabAsciiEqualIgnoreCase {
    param([string]$A, [string]$B)
    (ConvertTo-BoabAsciiLower $A) -ceq (ConvertTo-BoabAsciiLower $B)
}

function Compare-BoabOrdinal {
    # Rust String Ord: byte-wise UTF-8 comparison.
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $hasSurrogate = $false
    foreach ($s in @($A, $B)) {
        foreach ($ch in $s.ToCharArray()) {
            if ([char]::IsSurrogate($ch)) { $hasSurrogate = $true; break }
        }
    }
    if (-not $hasSurrogate) {
        $c = [string]::CompareOrdinal($A, $B)
        return [math]::Sign($c)
    }
    $ba = [System.Text.Encoding]::UTF8.GetBytes($A)
    $bb = [System.Text.Encoding]::UTF8.GetBytes($B)
    $n = [math]::Min($ba.Length, $bb.Length)
    for ($i = 0; $i -lt $n; $i++) {
        if ($ba[$i] -ne $bb[$i]) { return [math]::Sign([int]$ba[$i] - [int]$bb[$i]) }
    }
    [math]::Sign($ba.Length - $bb.Length)
}

function Sort-BoabStable {
    # Stable merge sort (mirrors Rust's slice::sort_by, which is stable).
    # $Compare is a scriptblock taking ($a, $b) and returning <0, 0 or >0.
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][System.Collections.IList]$Items,
        [Parameter(Mandatory)][scriptblock]$Compare
    )
    $arr = [object[]]::new($Items.Count)
    for ($i = 0; $i -lt $Items.Count; $i++) { $arr[$i] = $Items[$i] }
    $n = $arr.Length
    if ($n -gt 1) {
        $tmp = [object[]]::new($n)
        $width = 1
        while ($width -lt $n) {
            for ($lo = 0; $lo -lt $n; $lo += 2 * $width) {
                $mid = [math]::Min($lo + $width, $n)
                $hi = [math]::Min($lo + 2 * $width, $n)
                $l = $lo; $r = $mid; $k = $lo
                while ($l -lt $mid -and $r -lt $hi) {
                    if ((& $Compare $arr[$r] $arr[$l]) -lt 0) { $tmp[$k] = $arr[$r]; $r++ }
                    else { $tmp[$k] = $arr[$l]; $l++ }
                    $k++
                }
                while ($l -lt $mid) { $tmp[$k] = $arr[$l]; $l++; $k++ }
                while ($r -lt $hi) { $tmp[$k] = $arr[$r]; $r++; $k++ }
            }
            $swap = $arr; $arr = $tmp; $tmp = $swap
            $width *= 2
        }
    }
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($x in $arr) { $list.Add($x) }
    , $list
}

function New-BoabList {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()]$From)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $From) {
        foreach ($x in $From) { $list.Add($x) }
    }
    , $list
}

function ConvertFrom-BoabRustUnsigned {
    # Rust <uN as FromStr>::from_str. Returns [ulong] or throws with the ParseIntError text.
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text,
        [ulong]$Max = [ulong]::MaxValue
    )
    if ($Text.Length -eq 0) { throw (New-BoabException 'cannot parse integer from empty string') }
    $digits = $Text
    if ($digits[0] -eq '+') {
        $digits = $digits.Substring(1)
        if ($digits.Length -eq 0) { throw (New-BoabException 'invalid digit found in string') }
    }
    $value = [System.Numerics.BigInteger]::Zero
    foreach ($ch in $digits.ToCharArray()) {
        if ($ch -lt '0' -or $ch -gt '9') { throw (New-BoabException 'invalid digit found in string') }
        $value = $value * 10 + ([int]$ch - 48)
    }
    if ($value -gt [System.Numerics.BigInteger]$Max) { throw (New-BoabException 'number too large to fit in target type') }
    [ulong]$value
}

function ConvertFrom-BoabRustSigned64 {
    # Rust i64::from_str (used by clap's ranged integer parsers).
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    if ($Text.Length -eq 0) { throw (New-BoabException 'cannot parse integer from empty string') }
    $neg = $false
    $digits = $Text
    if ($digits[0] -eq '+' -or $digits[0] -eq '-') {
        $neg = $digits[0] -eq '-'
        $digits = $digits.Substring(1)
        if ($digits.Length -eq 0) { throw (New-BoabException 'invalid digit found in string') }
    }
    $value = [System.Numerics.BigInteger]::Zero
    foreach ($ch in $digits.ToCharArray()) {
        if ($ch -lt '0' -or $ch -gt '9') { throw (New-BoabException 'invalid digit found in string') }
        $value = $value * 10 + ([int]$ch - 48)
    }
    if ($neg) { $value = -$value }
    if ($value -gt [System.Numerics.BigInteger][long]::MaxValue) { throw (New-BoabException 'number too large to fit in target type') }
    if ($value -lt [System.Numerics.BigInteger][long]::MinValue) { throw (New-BoabException 'number too small to fit in target type') }
    [long]$value
}

function ConvertFrom-BoabRustBool {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    if ($Text -ceq 'true') { return $true }
    if ($Text -ceq 'false') { return $false }
    throw (New-BoabException 'provided string was not `true` or `false`')
}

function ConvertFrom-BoabUuidText {
    # Mirror uuid::Uuid::from_str (accepts simple, hyphenated, braced and urn forms)
    # including its error messages. Returns the canonical lowercase hyphenated form.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $len = $bytes.Length
    $isHex = { param([string]$s) $s -cmatch '^[0-9a-fA-F]*$' }
    $hyph = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $candidate = $null
    if ($len -eq 32 -and $Text -cmatch '^[0-9a-fA-F]{32}$') { $candidate = $Text }
    elseif ($len -eq 36 -and $Text -cmatch $hyph) { $candidate = $Text }
    elseif ($len -eq 38 -and $Text.StartsWith('{') -and $Text.EndsWith('}') -and $Text.Substring(1, 36) -cmatch $hyph) { $candidate = $Text.Substring(1, 36) }
    elseif ($len -eq 45 -and $Text.StartsWith('urn:uuid:', [StringComparison]::Ordinal) -and $Text.Substring(9) -cmatch $hyph) { $candidate = $Text.Substring(9) }
    if ($null -ne $candidate) {
        $hex = $candidate.Replace('-', '').ToLowerInvariant()
        return '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)
    }
    # Error analysis (uuid::parser::InvalidUuid::into_err).
    $inner = $Text; $offset = 0; $simple = $true
    if ($Text.Length -ge 2 -and $Text.StartsWith('{') -and $Text.EndsWith('}')) { $inner = $Text.Substring(1, $Text.Length - 2); $offset = 1; $simple = $false }
    elseif ($Text.StartsWith('urn:uuid:', [StringComparison]::Ordinal)) { $inner = $Text.Substring(9); $offset = 9; $simple = $false }
    $hyphenCount = 0
    $groupBounds = @(0, 0, 0, 0)
    $byteIndex = 0
    $i = 0
    while ($i -lt $inner.Length) {
        $ch = $inner[$i]
        $cp = [int]$ch
        $charText = [string]$ch
        if ([char]::IsHighSurrogate($ch) -and $i + 1 -lt $inner.Length) { $charText = $inner.Substring($i, 2); $cp = [char]::ConvertToUtf32($ch, $inner[$i + 1]) }
        if ($cp -gt 127) {
            throw (New-BoabException ("invalid character: found ``{0}`` at {1}" -f $charText, ($byteIndex + $offset + 1)))
        }
        elseif ($ch -eq '-') {
            if ($hyphenCount -lt 4) { $groupBounds[$hyphenCount] = $byteIndex }
            $hyphenCount++
        }
        elseif (-not ($charText -cmatch '^[0-9a-fA-F]$')) {
            throw (New-BoabException ("invalid character: found ``{0}`` at {1}" -f $charText, ($byteIndex + $offset + 1)))
        }
        $byteIndex += [System.Text.Encoding]::UTF8.GetByteCount($charText)
        $i += $charText.Length
    }
    if ($hyphenCount -eq 0 -and $simple) {
        throw (New-BoabException ("invalid length: expected length 32 for simple format, found {0}" -f $len))
    }
    if ($hyphenCount -ne 4) {
        throw (New-BoabException ("invalid group count: expected 5, found {0}" -f ($hyphenCount + 1)))
    }
    $blockStarts = @(0, 9, 14, 19, 24)
    $expected = @(8, 4, 4, 4, 12)
    for ($g = 0; $g -lt 4; $g++) {
        if ($groupBounds[$g] -ne $blockStarts[$g + 1] - 1) {
            throw (New-BoabException ("invalid group length in group {0}: expected {1}, found {2}" -f $g, $expected[$g], ($groupBounds[$g] - $blockStarts[$g])))
        }
    }
    throw (New-BoabException ("invalid group length in group 4: expected 12, found {0}" -f ($len - $blockStarts[4])))
}

function New-BoabUuid {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    [guid]::NewGuid().ToString('D')
}

function Get-BoabIoErrorText {
    # Render a .NET IO exception like Rust's io::Error Display ("<os text> (os error N)").
    [CmdletBinding()]
    [OutputType([string])]
    param($Exception, [string]$Path)
    $ex = $Exception
    if ($ex -is [System.Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
    while ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
    if ($IsWindows) {
        if ($ex -is [System.IO.FileNotFoundException]) { return 'The system cannot find the file specified. (os error 2)' }
        if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'The system cannot find the path specified. (os error 3)' }
        if ($ex -is [System.UnauthorizedAccessException]) { return 'Access is denied. (os error 5)' }
        return $ex.Message
    }
    if ($ex -is [System.IO.FileNotFoundException] -or $ex -is [System.IO.DirectoryNotFoundException]) { return 'No such file or directory (os error 2)' }
    if ($ex -is [System.UnauthorizedAccessException]) {
        if ($Path -and [System.IO.Directory]::Exists($Path)) { return 'Is a directory (os error 21)' }
        return 'Permission denied (os error 13)'
    }
    if ($ex -is [System.IO.IOException] -and $Path -and [System.IO.Directory]::Exists($Path)) { return 'Is a directory (os error 21)' }
    $ex.Message
}

function Get-BoabCurrentDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $loc = Get-Location -PSProvider FileSystem
    $loc.ProviderPath
}

function Resolve-BoabFullPath {
    # Make a path absolute against the PowerShell location (Rust resolves relative
    # paths against the process working directory, which for a CLI is the shell's).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path) -and -not ($IsWindows -and $Path -match '^[\\/][^\\/]')) { return $Path }
    if ($Path.Length -eq 0) { return (Get-BoabCurrentDirectory) }
    [System.IO.Path]::Combine((Get-BoabCurrentDirectory), $Path)
}

function Resolve-BoabCanonicalPath {
    # Mirror std::fs::canonicalize: absolute, symlinks resolved, '.'/'..' resolved
    # physically. Throws io-style text if the path does not exist.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ($Path.Length -eq 0) { throw (New-BoabException (Get-BoabIoErrorText -Exception ([System.IO.FileNotFoundException]::new()))) }
    $full = Resolve-BoabFullPath -Path $Path
    $sepChars = if ($IsWindows) { [char[]]@('\', '/') } else { [char[]]@('/') }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) { $root = [string][System.IO.Path]::DirectorySeparatorChar }
    $rest = $full.Substring($root.Length)
    $queue = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $rest.Split($sepChars, [StringSplitOptions]::RemoveEmptyEntries)) { $queue.Add($p) }
    $current = $root
    $hops = 0
    while ($queue.Count -gt 0) {
        $part = $queue[0]
        $queue.RemoveAt(0)
        if ($part -eq '.') { continue }
        if ($part -eq '..') {
            $parent = [System.IO.Path]::GetDirectoryName($current.TrimEnd($sepChars))
            if ($parent) { $current = $parent } else { $current = $root }
            continue
        }
        $candidate = [System.IO.Path]::Combine($current, $part)
        $info = $null
        if ([System.IO.Directory]::Exists($candidate)) { $info = [System.IO.DirectoryInfo]::new($candidate) }
        elseif ([System.IO.File]::Exists($candidate)) { $info = [System.IO.FileInfo]::new($candidate) }
        else {
            $fi = [System.IO.FileInfo]::new($candidate)
            if ($null -eq $fi.LinkTarget) {
                throw (New-BoabException (Get-BoabIoErrorText -Exception ([System.IO.FileNotFoundException]::new())))
            }
            $info = $fi
        }
        $target = $info.LinkTarget
        if ($null -ne $target) {
            $hops++
            if ($hops -gt 40) { throw (New-BoabException 'Too many levels of symbolic links (os error 62)') }
            if (-not [System.IO.Path]::IsPathRooted($target)) { $target = [System.IO.Path]::Combine($current, $target) }
            $troot = [System.IO.Path]::GetPathRoot($target)
            $trest = $target.Substring($troot.Length)
            $newQueue = [System.Collections.Generic.List[string]]::new()
            foreach ($p in $trest.Split($sepChars, [StringSplitOptions]::RemoveEmptyEntries)) { $newQueue.Add($p) }
            foreach ($p in $queue) { $newQueue.Add($p) }
            $queue = $newQueue
            $current = $troot
            continue
        }
        $current = $candidate
    }
    if (-not ([System.IO.Directory]::Exists($current) -or [System.IO.File]::Exists($current))) {
        throw (New-BoabException (Get-BoabIoErrorText -Exception ([System.IO.FileNotFoundException]::new())))
    }
    if ($IsWindows -and -not $current.StartsWith('\\?\')) {
        if ($current.StartsWith('\\')) { $current = '\\?\UNC\' + $current.Substring(2) }
        else { $current = '\\?\' + $current }
    }
    $current
}

function Join-BoabPath {
    # PathBuf::join: an absolute child replaces the base.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Base, [string]$Child)
    [System.IO.Path]::Combine($Base, $Child)
}

function Get-BoabPathExtension {
    # std::path::Path::extension semantics.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Path)
    $name = [System.IO.Path]::GetFileName($Path)
    if ([string]::IsNullOrEmpty($name) -or $name -eq '..') { return $null }
    $idx = $name.LastIndexOf('.')
    if ($idx -le 0) { return $null }
    $name.Substring($idx + 1)
}

function Get-BoabFirstPathComponent {
    # First component of std::path::Path::components() rendered via as_os_str().
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Path)
    if ($Path.Length -eq 0) { return $null }
    if ($IsWindows) {
        if ($Path -match '^(\\\\\?\\UNC\\[^\\]+\\[^\\]+|\\\\\?\\[A-Za-z]:|\\\\\?\\[^\\]+|\\\\\.\\[^\\]+|\\\\[^\\/]+[\\/][^\\/]+|[A-Za-z]:)') { return $Matches[1] }
        $seps = [char[]]@('\', '/')
    }
    else {
        $seps = [char[]]@('/')
    }
    if ($seps -contains $Path[0]) { return [string]$Path[0] }
    $parts = $Path.Split($seps)
    # Leading "." is preserved as CurDir; interior "." components are skipped.
    if ($parts[0] -eq '.') { return '.' }
    foreach ($p in $parts) {
        if ($p.Length -eq 0 -or $p -eq '.') { continue }
        return $p
    }
    $null
}

function Get-BoabSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    }
    finally { $sha.Dispose() }
    -join ($hash | ForEach-Object { $_.ToString('x2') })
}

function Get-BoabJaro {
    # strsim::jaro, used by clap for "did you mean" suggestions.
    [CmdletBinding()]
    [OutputType([double])]
    param([string]$A, [string]$B)
    $a = $A.ToCharArray(); $b = $B.ToCharArray()
    $la = $a.Length; $lb = $b.Length
    if ($la -eq 0 -and $lb -eq 0) { return 1.0 }
    if ($la -eq 0 -or $lb -eq 0) { return 0.0 }
    $searchRange = [int][math]::Floor([math]::Max($la, $lb) / 2) - 1
    if ($searchRange -lt 0) { $searchRange = 0 }
    $flagsA = [bool[]]::new($la); $flagsB = [bool[]]::new($lb)
    $matchCount = 0
    for ($i = 0; $i -lt $la; $i++) {
        $lo = [math]::Max(0, $i - $searchRange)
        $hi = [math]::Min($lb - 1, $i + $searchRange)
        for ($j = $lo; $j -le $hi; $j++) {
            if (-not $flagsB[$j] -and $a[$i] -ceq $b[$j]) {
                $flagsA[$i] = $true; $flagsB[$j] = $true; $matchCount++; break
            }
        }
    }
    if ($matchCount -eq 0) { return 0.0 }
    $t = 0; $k = 0
    for ($i = 0; $i -lt $la; $i++) {
        if ($flagsA[$i]) {
            while (-not $flagsB[$k]) { $k++ }
            if ($a[$i] -cne $b[$k]) { $t++ }
            $k++
        }
    }
    $transpositions = [math]::Floor($t / 2)
    $m = [double]$matchCount
    (($m / $la) + ($m / $lb) + (($m - $transpositions) / $m)) / 3.0
}

function Get-BoabDisplayWidth {
    # Approximation of unicode-width's UnicodeWidthStr::width (used by comfy-table).
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowEmptyString()][string]$Text)
    $w = 0
    $i = 0
    while ($i -lt $Text.Length) {
        $ch = $Text[$i]
        $cp = [int]$ch
        if ([char]::IsHighSurrogate($ch) -and $i + 1 -lt $Text.Length) {
            $cp = [char]::ConvertToUtf32($ch, $Text[$i + 1]); $i += 2
        }
        else { $i++ }
        if ($cp -lt 0x20 -or ($cp -ge 0x7F -and $cp -lt 0xA0)) { continue }
        if ($cp -lt 0x300) { $w += 1; continue }
        $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($cp)
        if ($cat -eq [System.Globalization.UnicodeCategory]::NonSpacingMark -or
            $cat -eq [System.Globalization.UnicodeCategory]::EnclosingMark -or
            $cat -eq [System.Globalization.UnicodeCategory]::Format -or
            ($cp -ge 0x1160 -and $cp -le 0x11FF) -or $cp -eq 0x200B) { continue }
        if (($cp -ge 0x1100 -and $cp -le 0x115F) -or
            ($cp -ge 0x2E80 -and $cp -le 0x303E) -or
            ($cp -ge 0x3041 -and $cp -le 0x33FF) -or
            ($cp -ge 0x3400 -and $cp -le 0x4DBF) -or
            ($cp -ge 0x4E00 -and $cp -le 0x9FFF) -or
            ($cp -ge 0xA000 -and $cp -le 0xA4CF) -or
            ($cp -ge 0xAC00 -and $cp -le 0xD7A3) -or
            ($cp -ge 0xF900 -and $cp -le 0xFAFF) -or
            ($cp -ge 0xFE30 -and $cp -le 0xFE4F) -or
            ($cp -ge 0xFF00 -and $cp -le 0xFF60) -or
            ($cp -ge 0xFFE0 -and $cp -le 0xFFE6) -or
            ($cp -ge 0x1F300 -and $cp -le 0x1F64F) -or
            ($cp -ge 0x1F900 -and $cp -le 0x1F9FF) -or
            ($cp -ge 0x20000 -and $cp -le 0x3FFFD)) { $w += 2; continue }
        $w += 1
    }
    $w
}

function Read-BoabTextFile {
    # fs::read_to_string: UTF-8, no BOM stripping (Rust keeps a BOM as U+FEFF).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $enc = [System.Text.UTF8Encoding]::new($false, $true)
    $enc.GetString($bytes)
}

function Write-BoabTextFile {
    # fs::write: exact bytes, UTF-8 without BOM, no newline translation.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllBytes($Path, [System.Text.UTF8Encoding]::new($false).GetBytes($Content))
}
