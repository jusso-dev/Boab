# Codebase scanner. Port of src/scanners/codebase.rs.
#
# This file also holds the directory walker shared with the certificate-store
# scanner. The walker re-implements the parts of the Rust `ignore` crate
# (v0.4.25, `WalkBuilder`) that Boab uses, rather than shelling out to
# `git ls-files`, because Boab's rules are not git's rules:
#   * `.gitignore` files are honoured even outside a git repository
#     (`require_git(false)`), and every ancestor directory's `.gitignore` is
#     read, not just those inside the repository;
#   * `.ignore` files, `.git/info/exclude` and the global excludes file
#     (core.excludesFile, else $XDG_CONFIG_HOME/git/ignore or ~/.config/git/ignore)
#     are honoured;
#   * hidden entries (name starts with '.', or the Hidden attribute on Windows)
#     are skipped unless an ignore/override rule whitelists them;
#   * override globs (default excludes, --exclude, --include) take precedence
#     over everything, with `ignore`'s inverted-gitignore semantics;
#   * symlinks are never followed and are not reported as files.
# Globs are translated to regexes the way `globset` does (literal_separator,
# backslash escapes, `**` rules, {a,b} alternates, [..] classes).
#
# One deliberate difference: Rust walks directories in the order the OS
# returns entries (e.g. hash order on APFS/ext4). This port sorts entries by
# ordinal name, so the findings are the same but their order within a scan may
# differ.

# ----------------------------------------------------------------------------
# Glob -> regex (port of globset 0.4.18 parsing for gitignore-style globs)
# ----------------------------------------------------------------------------

function ConvertTo-BoabRegexLiteral {
    param([char] $Char)
    if ([char]::IsLetterOrDigit($Char) -and [int]$Char -lt 128) { return [string]$Char }
    return ('\u{0:X4}' -f [int]$Char)
}

function ConvertTo-BoabGlobTokens {
    <#
    .SYNOPSIS
    Tokenise a glob like globset's parser. Returns a token list, or throws on an invalid glob.
    Tokens are hashtables: @{ T = 'Lit'|'Any'|'Star'|'RPre'|'RSuf'|'RZom'|'Class'|'Alt'; ... }
    #>
    param([string] $Glob)
    $chars = $Glob.ToCharArray()
    $n = $chars.Length
    $state = @{ Pos = -1; Prev = $null; Cur = $null; FoundUnclosedClass = $false }
    $branches = [System.Collections.Generic.List[object]]::new()
    $branches.Add([System.Collections.Generic.List[object]]::new())
    $altStack = [System.Collections.Generic.List[int]]::new()

    $bump = {
        $state.Prev = $state.Cur
        $state.Pos++
        if ($state.Pos -lt $n) { $state.Cur = $chars[$state.Pos] } else { $state.Cur = $null; $state.Pos = $n }
        return $state.Cur
    }
    $peek = {
        $p = $state.Pos + 1
        if ($p -lt $n) { return $chars[$p] }
        return $null
    }
    $push = {
        param($tok)
        if ($branches.Count -eq 0) { throw 'unopened alternates' }
        $branches[$branches.Count - 1].Add($tok)
    }

    while ($true) {
        $c = & $bump
        if ($null -eq $c) { break }
        switch -CaseSensitive ([string]$c) {
            '?' { & $push @{ T = 'Any' }; break }
            '*' {
                $prev = $state.Prev
                if ((& $peek) -ne [char]'*') { & $push @{ T = 'Star' }; break }
                [void](& $bump)
                $last = $branches[$branches.Count - 1]
                if ($last.Count -eq 0) {
                    $pk = & $peek
                    if ($null -ne $pk -and $pk -ne [char]'/') {
                        & $push @{ T = 'Star' }; & $push @{ T = 'Star' }
                    }
                    else {
                        & $push @{ T = 'RPre' }
                        [void](& $bump)
                    }
                    break
                }
                if (-not ($null -ne $prev -and $prev -eq [char]'/')) {
                    if ($branches.Count -le 1 -or ($prev -ne [char]',' -and $prev -ne [char]'{')) {
                        & $push @{ T = 'Star' }; & $push @{ T = 'Star' }
                        break
                    }
                }
                $pk = & $peek
                $isSuffix = $false
                if ($null -eq $pk) {
                    [void](& $bump)
                    $isSuffix = $true
                }
                elseif (($pk -eq [char]',' -or $pk -eq [char]'}') -and $branches.Count -ge 2) {
                    $isSuffix = $true
                }
                elseif ($pk -eq [char]'/') {
                    [void](& $bump)
                    $isSuffix = $false
                }
                else {
                    & $push @{ T = 'Star' }; & $push @{ T = 'Star' }
                    break
                }
                $popped = $last[$last.Count - 1]
                $last.RemoveAt($last.Count - 1)
                if ($popped.T -eq 'RPre') { & $push @{ T = 'RPre' } }
                elseif ($popped.T -eq 'RSuf') { & $push @{ T = 'RSuf' } }
                elseif ($isSuffix) { & $push @{ T = 'RSuf' } }
                else { & $push @{ T = 'RZom' } }
                break
            }
            '[' {
                if ($state.FoundUnclosedClass) { & $push @{ T = 'Lit'; C = $c }; break }
                $savedPos = $state.Pos; $savedPrev = $state.Prev; $savedCur = $state.Cur
                $ranges = [System.Collections.Generic.List[object]]::new()
                $negated = $false
                $pk = & $peek
                if ($pk -eq [char]'!' -or $pk -eq [char]'^') { [void](& $bump); $negated = $true }
                $first = $true; $inRange = $false; $closed = $false
                while ($true) {
                    $cc = & $bump
                    if ($null -eq $cc) { break }
                    if ($cc -eq [char]']') {
                        if ($first) { $ranges.Add(@([char]']', [char]']')) }
                        else { $closed = $true; break }
                    }
                    elseif ($cc -eq [char]'-') {
                        if ($first) { $ranges.Add(@([char]'-', [char]'-')) }
                        elseif ($inRange) {
                            $r = $ranges[$ranges.Count - 1]
                            if ([int][char]'-' -lt [int]$r[0]) { throw 'invalid range' }
                            $ranges[$ranges.Count - 1] = @($r[0], [char]'-')
                            $inRange = $false
                        }
                        else { $inRange = $true }
                    }
                    else {
                        if ($inRange) {
                            $r = $ranges[$ranges.Count - 1]
                            if ([int]$cc -lt [int]$r[0]) { throw 'invalid range' }
                            $ranges[$ranges.Count - 1] = @($r[0], $cc)
                        }
                        else { $ranges.Add(@($cc, $cc)) }
                        $inRange = $false
                    }
                    $first = $false
                }
                if (-not $closed) {
                    # allow_unclosed_class: treat '[' literally and re-parse what followed.
                    $state.Pos = $savedPos; $state.Prev = $savedPrev; $state.Cur = $savedCur
                    $state.FoundUnclosedClass = $true
                    & $push @{ T = 'Lit'; C = [char]'[' }
                    break
                }
                if ($inRange) { $ranges.Add(@([char]'-', [char]'-')) }
                & $push @{ T = 'Class'; Negated = $negated; Ranges = $ranges }
                break
            }
            '{' {
                $altStack.Add($branches.Count)
                $branches.Add([System.Collections.Generic.List[object]]::new())
                break
            }
            '}' {
                if ($altStack.Count -eq 0) { throw 'unopened alternates' }
                $start = $altStack[$altStack.Count - 1]
                $altStack.RemoveAt($altStack.Count - 1)
                $alts = [System.Collections.Generic.List[object]]::new()
                while ($branches.Count -gt $start) {
                    $alts.Add($branches[$start])
                    $branches.RemoveAt($start)
                }
                & $push @{ T = 'Alt'; Branches = $alts }
                break
            }
            ',' {
                if ($altStack.Count -eq 0) { & $push @{ T = 'Lit'; C = $c } }
                else { $branches.Add([System.Collections.Generic.List[object]]::new()) }
                break
            }
            '\' {
                $nx = & $bump
                if ($null -eq $nx) { throw 'dangling escape' }
                & $push @{ T = 'Lit'; C = $nx }
                break
            }
            default { & $push @{ T = 'Lit'; C = $c } }
        }
    }
    if ($altStack.Count -gt 0) { throw 'unclosed alternates' }
    if ($branches.Count -ne 1) { throw 'unopened alternates' }
    return , $branches[0]
}

function ConvertTo-BoabTokenRegex {
    param($Tokens)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($tok in $Tokens) {
        switch ($tok.T) {
            'Lit' { [void]$sb.Append((ConvertTo-BoabRegexLiteral $tok.C)) }
            'Any' { [void]$sb.Append('[^/]') }
            'Star' { [void]$sb.Append('[^/]*') }
            'RPre' { [void]$sb.Append('(?:/?|.*/)') }
            'RSuf' { [void]$sb.Append('/.*') }
            'RZom' { [void]$sb.Append('(?:/|/.*/)') }
            'Class' {
                [void]$sb.Append('[')
                if ($tok.Negated) { [void]$sb.Append('^') }
                foreach ($r in $tok.Ranges) {
                    [void]$sb.Append(('\u{0:X4}' -f [int]$r[0]))
                    if ([int]$r[0] -ne [int]$r[1]) {
                        [void]$sb.Append('-')
                        [void]$sb.Append(('\u{0:X4}' -f [int]$r[1]))
                    }
                }
                [void]$sb.Append(']')
            }
            'Alt' {
                $parts = [System.Collections.Generic.List[string]]::new()
                foreach ($b in $tok.Branches) {
                    $s = ConvertTo-BoabTokenRegex -Tokens $b
                    if ($s.Length -gt 0) { $parts.Add($s) }
                }
                if ($parts.Count -gt 0) {
                    [void]$sb.Append('(?:')
                    [void]$sb.Append(($parts -join '|'))
                    [void]$sb.Append(')')
                }
            }
        }
    }
    return $sb.ToString()
}

function ConvertTo-BoabGlobRegex {
    <#
    .SYNOPSIS
    Translate a globset glob (literal_separator = true, backslash_escape = true)
    into an anchored .NET regex string. Throws on invalid globs.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Glob)
    $tokens = ConvertTo-BoabGlobTokens -Glob $Glob
    if ($tokens.Count -eq 1 -and $tokens[0].T -eq 'RPre') {
        return '^.*\z'
    }
    # \z rather than $: .NET's $ also matches before a trailing newline.
    return '^' + (ConvertTo-BoabTokenRegex -Tokens $tokens) + '\z'
}

# ----------------------------------------------------------------------------
# Gitignore matcher (port of ignore::gitignore)
# ----------------------------------------------------------------------------

function ConvertTo-BoabMatchPath {
    param([string] $Path)
    if ($IsWindows) { return $Path.Replace('\', '/') }
    return $Path
}

function New-BoabGitignoreMatcher {
    <#
    .SYNOPSIS
    Create an empty gitignore matcher rooted at -Root (port of GitignoreBuilder::new).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Root)
    $r = ConvertTo-BoabMatchPath $Root
    if ($r.StartsWith('./')) { $r = $r.Substring(2) }
    return [pscustomobject]@{
        Root  = $r
        Globs = [System.Collections.Generic.List[object]]::new()
    }
}

function Add-BoabGitignoreLine {
    <#
    .SYNOPSIS
    Port of GitignoreBuilder::add_line. Invalid globs are silently skipped
    (the Rust callers discard those errors too).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Matcher,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Line
    )
    if ($Line.StartsWith('#')) { return }
    if (-not $Line.EndsWith('\ ')) { $Line = $Line.TrimEnd() }
    if ($Line.Length -eq 0) { return }
    $isWhitelist = $false
    $isOnlyDir = $false
    $isAbsolute = $false
    if ($Line.StartsWith('\!') -or $Line.StartsWith('\#')) {
        $Line = $Line.Substring(1)
        $isAbsolute = $Line.StartsWith('/')
    }
    else {
        if ($Line.StartsWith('!')) {
            $isWhitelist = $true
            $Line = $Line.Substring(1)
        }
        if ($Line.StartsWith('/')) {
            $Line = $Line.Substring(1)
            $isAbsolute = $true
        }
    }
    if ($Line.EndsWith('/')) {
        $isOnlyDir = $true
        $Line = $Line.Substring(0, $Line.Length - 1)
        if ($Line.EndsWith('\')) {
            $Line = $Line.Substring(0, $Line.Length - 1)
        }
    }
    $actual = $Line
    if (-not $isAbsolute -and -not $Line.Contains('/')) {
        if (-not ($actual.StartsWith('**/') -or $actual -eq '**')) {
            $actual = "**/$actual"
        }
    }
    if ($actual.EndsWith('/**')) {
        $actual = "$actual/*"
    }
    try {
        $rx = ConvertTo-BoabGlobRegex -Glob $actual
    }
    catch {
        return
    }
    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $Matcher.Globs.Add([pscustomobject]@{
            Original    = $Line
            Actual      = $actual
            Regex       = [regex]::new($rx, $opts)
            IsWhitelist = $isWhitelist
            IsOnlyDir   = $isOnlyDir
        })
}

function Read-BoabIgnoreFile {
    <#
    .SYNOPSIS
    Port of GitignoreBuilder::add(path): read lines (LF or CRLF), strip a
    leading UTF-8 BOM, stop at the first line that is not valid UTF-8.
    Returns a matcher, or $null if the file can't be read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $File
    )
    if (-not [System.IO.File]::Exists($File)) { return $null }
    try { $bytes = [System.IO.File]::ReadAllBytes($File) } catch { return $null }
    $matcher = New-BoabGitignoreMatcher -Root $Root
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $start = 0
    $lineNo = 0
    while ($start -lt $bytes.Length) {
        $end = [Array]::IndexOf($bytes, [byte]10, $start)
        $next = 0
        if ($end -lt 0) { $end = $bytes.Length; $next = $bytes.Length } else { $next = $end + 1 }
        $len = $end - $start
        if ($len -gt 0 -and $bytes[$end - 1] -eq 13) { $len-- }
        try {
            $line = $utf8.GetString($bytes, $start, $len)
        }
        catch {
            break
        }
        if ($lineNo -eq 0) { $line = $line.TrimStart([char]0xFEFF) }
        Add-BoabGitignoreLine -Matcher $matcher -Line $line
        $lineNo++
        $start = $next
    }
    return $matcher
}

function Get-BoabStrippedMatchPath {
    param($Matcher, [string] $Path)
    $p = ConvertTo-BoabMatchPath $Path
    if ($p.StartsWith('./')) { $p = $p.Substring(2) }
    $root = $Matcher.Root
    if ($root -ne '.' -and $p.Contains('/')) {
        if ($root.Length -le $p.Length -and $p.StartsWith($root, [System.StringComparison]::Ordinal)) {
            $p = $p.Substring($root.Length)
            if ($p.StartsWith('/')) { $p = $p.Substring(1) }
        }
    }
    return $p
}

function Test-BoabGitignoreMatch {
    <#
    .SYNOPSIS
    Port of Gitignore::matched. Returns 'ignore', 'whitelist' or $null. The last
    matching glob wins; directory-only globs are skipped for non-directories.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Matcher,
        [Parameter(Mandatory)] [string] $Path,
        [bool] $IsDir
    )
    if ($null -eq $Matcher -or $Matcher.Globs.Count -eq 0) { return $null }
    $p = Get-BoabStrippedMatchPath -Matcher $Matcher -Path $Path
    for ($i = $Matcher.Globs.Count - 1; $i -ge 0; $i--) {
        $g = $Matcher.Globs[$i]
        if ($g.Regex.IsMatch($p)) {
            if (-not $g.IsOnlyDir -or $IsDir) {
                if ($g.IsWhitelist) { return 'whitelist' }
                return 'ignore'
            }
        }
    }
    return $null
}

function Test-BoabOverrideMatch {
    <#
    .SYNOPSIS
    Port of ignore::overrides::Override::matched: gitignore semantics inverted,
    plus "if there are any whitelist globs, files matching none of them are ignored".
    #>
    param([AllowNull()] $Matcher, [string] $Path, [bool] $IsDir)
    if ($null -eq $Matcher -or $Matcher.Globs.Count -eq 0) { return $null }
    $m = Test-BoabGitignoreMatch -Matcher $Matcher -Path $Path -IsDir $IsDir
    if ($m -eq 'ignore') { return 'whitelist' }
    if ($m -eq 'whitelist') { return 'ignore' }
    if (-not $IsDir) {
        foreach ($g in $Matcher.Globs) {
            # A non-'!' override glob is a whitelist (an include).
            if (-not $g.IsWhitelist) { return 'ignore' }
        }
    }
    return $null
}

# ----------------------------------------------------------------------------
# Walker (port of the parts of ignore::WalkBuilder Boab relies on)
# ----------------------------------------------------------------------------

function Get-BoabHomeDirectory {
    if ($IsWindows) {
        $h = [Environment]::GetEnvironmentVariable('USERPROFILE')
        if ($h) { return $h }
    }
    $h = [Environment]::GetEnvironmentVariable('HOME')
    if ($h) { return $h }
    return $null
}

function Get-BoabGlobalExcludesPath {
    <#
    .SYNOPSIS
    Port of ignore::gitignore::gitconfig_excludes_path.
    #>
    [CmdletBinding()]
    param()
    $home_ = Get-BoabHomeDirectory
    $rx = [regex]::new('(?im)^\s*excludesfile\s*=\s*"?\s*(\S+?)\s*"?\s*$')
    $xdg = [Environment]::GetEnvironmentVariable('XDG_CONFIG_HOME')
    $configDir = $null
    if ($xdg) { $configDir = $xdg } elseif ($home_) { $configDir = [System.IO.Path]::Combine($home_, '.config') }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($home_) { $candidates.Add([System.IO.Path]::Combine($home_, '.gitconfig')) }
    if ($configDir) { $candidates.Add([System.IO.Path]::Combine($configDir, 'git', 'config')) }
    foreach ($cfg in $candidates) {
        if (-not [System.IO.File]::Exists($cfg)) { continue }
        try { $text = [System.IO.File]::ReadAllText($cfg) } catch { continue }
        $m = $rx.Match($text)
        if ($m.Success) {
            $p = $m.Groups[1].Value
            if ($home_) { $p = $p.Replace('~', $home_) }
            return $p
        }
    }
    if ($configDir) { return [System.IO.Path]::Combine($configDir, 'git', 'ignore') }
    return $null
}

function Get-BoabGlobalIgnoreMatcher {
    [CmdletBinding()]
    param()
    $path = Get-BoabGlobalExcludesPath
    if ($null -eq $path -or -not [System.IO.File]::Exists($path)) { return $null }
    $cwd = (Get-Location -PSProvider FileSystem).ProviderPath
    return Read-BoabIgnoreFile -Root $cwd -File $path
}

function Get-BoabDirIgnoreLevel {
    <#
    .SYNOPSIS
    Build the per-directory ignore matchers (.ignore, .gitignore, .git/info/exclude).
    #>
    param([string] $Dir, $Options)
    $level = [pscustomobject]@{ Dir = $Dir; DotIgnore = $null; GitIgnore = $null; Exclude = $null }
    if ($Options.DotIgnore) {
        $level.DotIgnore = Read-BoabIgnoreFile -Root $Dir -File ([System.IO.Path]::Combine($Dir, '.ignore'))
    }
    if ($Options.GitIgnore) {
        $level.GitIgnore = Read-BoabIgnoreFile -Root $Dir -File ([System.IO.Path]::Combine($Dir, '.gitignore'))
    }
    if ($Options.GitExclude) {
        # With require_git(false) the Rust crate never resolves a `.git` *file*
        # (worktrees); it only reads <dir>/.git/info/exclude.
        $level.Exclude = Read-BoabIgnoreFile -Root $Dir -File ([System.IO.Path]::Combine($Dir, '.git', 'info', 'exclude'))
    }
    return $level
}

function Get-BoabIgnoreDecision {
    <#
    .SYNOPSIS
    Port of Ignore::matched_dir_entry. Returns $true when the entry must be skipped.
    #>
    param(
        [System.Collections.Generic.List[object]] $Chain,
        [string] $Path,
        [bool] $IsDir,
        [bool] $IsHidden,
        $Options,
        $GlobalMatcher
    )
    if ($null -ne $Options.Overrides) {
        $o = Test-BoabOverrideMatch -Matcher $Options.Overrides -Path $Path -IsDir $IsDir
        if ($o -eq 'ignore') { return $true }
        if ($o -eq 'whitelist') { return $false }
    }
    $mIgnore = $null; $mGi = $null; $mEx = $null
    foreach ($level in $Chain) {
        if ($null -eq $mIgnore -and $null -ne $level.DotIgnore) {
            $mIgnore = Test-BoabGitignoreMatch -Matcher $level.DotIgnore -Path $Path -IsDir $IsDir
        }
        if ($null -eq $mGi -and $null -ne $level.GitIgnore) {
            $mGi = Test-BoabGitignoreMatch -Matcher $level.GitIgnore -Path $Path -IsDir $IsDir
        }
        if ($null -eq $mEx -and $null -ne $level.Exclude) {
            $mEx = Test-BoabGitignoreMatch -Matcher $level.Exclude -Path $Path -IsDir $IsDir
        }
    }
    $mGlobal = $null
    if ($Options.GitGlobal -and $null -ne $GlobalMatcher) {
        $mGlobal = Test-BoabGitignoreMatch -Matcher $GlobalMatcher -Path $Path -IsDir $IsDir
    }
    $m = $mIgnore
    if ($null -eq $m) { $m = $mGi }
    if ($null -eq $m) { $m = $mEx }
    if ($null -eq $m) { $m = $mGlobal }
    if ($m -eq 'ignore') { return $true }
    if ($m -eq 'whitelist') { return $false }
    if ($Options.Hidden -and $IsHidden) { return $true }
    return $false
}

function Test-BoabHiddenEntry {
    param([System.IO.FileSystemInfo] $Info)
    if ($Info.Name.StartsWith('.')) { return $true }
    if ($IsWindows -and ($Info.Attributes -band [System.IO.FileAttributes]::Hidden)) { return $true }
    return $false
}

function Get-BoabEntryKind {
    <# 'dir', 'file', or 'other' (symlinks, devices, FIFOs, sockets). #>
    param([System.IO.FileSystemInfo] $Info)
    $isLink = $false
    try { $isLink = $null -ne $Info.LinkTarget } catch { $isLink = $false }
    if ($isLink) { return 'other' }
    if ($Info -is [System.IO.DirectoryInfo]) { return 'dir' }
    if (-not $IsWindows) {
        # Skip FIFOs, sockets and devices (Rust's `is_file()` is false for them,
        # and reading a FIFO would block). PowerShell's `UnixMode` string starts
        # with '-' for regular files.
        try {
            $um = $Info.PSObject.Properties['UnixMode']
            if ($null -ne $um -and $null -ne $um.Value -and ([string]$um.Value).Length -gt 0) {
                if (([string]$um.Value)[0] -ne [char]'-') { return 'other' }
            }
        }
        catch { $null = $_ }
    }
    return 'file'
}

function Get-BoabWalkFiles {
    <#
    .SYNOPSIS
    Walk -Root (an absolute, canonical path) and return the regular files that
    survive Boab's ignore rules, depth-first, entries in ordinal name order.
    .PARAMETER Options
    Hashtable: Hidden, DotIgnore, GitIgnore, GitExclude, GitGlobal, Parents
    (all bool) and Overrides (a matcher from New-BoabGitignoreMatcher, or $null).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [hashtable] $Options
    )
    $results = [System.Collections.Generic.List[string]]::new()
    if ([System.IO.File]::Exists($Root) -and -not [System.IO.Directory]::Exists($Root)) {
        # Depth-0 entries are never filtered.
        $results.Add($Root)
        return , $results
    }
    if (-not [System.IO.Directory]::Exists($Root)) { return , $results }

    $globalMatcher = $null
    if ($Options.GitGlobal) { $globalMatcher = Get-BoabGlobalIgnoreMatcher }

    # Ancestors of the root, closest first.
    $parentChain = [System.Collections.Generic.List[object]]::new()
    if ($Options.Parents) {
        $p = [System.IO.Path]::GetDirectoryName($Root)
        while (-not [string]::IsNullOrEmpty($p)) {
            $parentChain.Add((Get-BoabDirIgnoreLevel -Dir $p -Options $Options))
            $p = [System.IO.Path]::GetDirectoryName($p)
        }
    }

    $rootChain = [System.Collections.Generic.List[object]]::new()
    $rootChain.Add((Get-BoabDirIgnoreLevel -Dir $Root -Options $Options))
    $rootChain.AddRange($parentChain)

    $walkDir = $null
    $walkDir = {
        param([string] $Dir, [System.Collections.Generic.List[object]] $Chain)
        try {
            $infos = [System.IO.DirectoryInfo]::new($Dir).GetFileSystemInfos()
        }
        catch {
            return
        }
        $byName = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($i in $infos) { $byName[$i.Name] = $i }
        $names = [string[]]@($byName.Keys)
        [Array]::Sort($names, [System.StringComparer]::Ordinal)
        foreach ($name in $names) {
            $info = $byName[$name]
            $kind = Get-BoabEntryKind -Info $info
            $isDir = $kind -eq 'dir'
            $hidden = Test-BoabHiddenEntry -Info $info
            $skip = Get-BoabIgnoreDecision -Chain $Chain -Path $info.FullName -IsDir $isDir -IsHidden $hidden -Options $Options -GlobalMatcher $globalMatcher
            if ($skip) { continue }
            if ($isDir) {
                $child = [System.Collections.Generic.List[object]]::new()
                $child.Add((Get-BoabDirIgnoreLevel -Dir $info.FullName -Options $Options))
                $child.AddRange($Chain)
                & $walkDir $info.FullName $child
            }
            elseif ($kind -eq 'file') {
                $results.Add($info.FullName)
            }
        }
    }
    & $walkDir $Root $rootChain
    return , $results
}

# ----------------------------------------------------------------------------
# Codebase scanner
# ----------------------------------------------------------------------------

function Get-BoabDefaultExcludes {
    return @('node_modules', 'vendor', '.venv', 'venv', 'target', 'dist', 'build', '.git')
}

function Get-BoabCodebaseCertKeyExtensions {
    return @('pem', 'crt', 'cer', 'der', 'p7b', 'p12', 'pfx', 'jks', 'key')
}

function Get-BoabRelativePath {
    <# Port of `file.strip_prefix(root)` + display. #>
    param([string] $Root, [string] $File)
    if ($File -eq $Root) { return '' }
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $prefix = $Root
    if (-not $prefix.EndsWith($sep)) { $prefix = $prefix + $sep }
    if ($File.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
        return $File.Substring($prefix.Length)
    }
    return $File
}

function Split-BoabRustLines {
    <#
    .SYNOPSIS
    Port of Rust `str::lines()`: split on '\n', drop one '\r' before each '\n',
    no empty trailing line after a final '\n'.
    #>
    param([string] $Content)
    $out = [System.Collections.Generic.List[string]]::new()
    if ($Content.Length -eq 0) { return , $out }
    $parts = $Content.Split([char]10)
    $last = $parts.Length - 1
    for ($i = 0; $i -lt $parts.Length; $i++) {
        $part = $parts[$i]
        if ($i -eq $last) {
            # The unterminated tail; empty when the content ends with '\n'.
            if ($part.Length -gt 0) { $out.Add($part) }
        }
        else {
            if ($part.EndsWith("`r")) { $part = $part.Substring(0, $part.Length - 1) }
            $out.Add($part)
        }
    }
    return , $out
}

function Get-BoabLineAndSnippet {
    <#
    .SYNOPSIS
    Port of `line_and_snippet`: 1-based line of the match start, and the
    previous/current/next lines joined with '\n'.
    #>
    param(
        [int[]] $NewlineOffsets,
        [System.Collections.Generic.List[string]] $Lines,
        [int] $Start
    )
    # Number of '\n' strictly before $Start.
    $idx = [Array]::BinarySearch($NewlineOffsets, $Start)
    if ($idx -lt 0) { $idx = -bnot $idx }
    $lineNo = $idx + 1
    $li = $lineNo - 1
    $lo = [Math]::Max($li - 1, 0)
    $hi = [Math]::Min($li + 2, $Lines.Count)
    $snippet = ''
    if ($hi -gt $lo) {
        $snippet = [string]::Join("`n", [string[]]$Lines.GetRange($lo, $hi - $lo).ToArray())
    }
    return @($lineNo, $snippet)
}

function Get-BoabCodebaseFileFindings {
    <#
    .SYNOPSIS
    Port of `scan_file`. Returns a list of findings (possibly empty).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScanId,
        [Parameter(Mandatory)] [string] $File,
        [Parameter(Mandatory)] [string] $Root
    )
    $out = [System.Collections.Generic.List[object]]::new()
    $rel = Get-BoabRelativePath -Root $Root -File $File

    $ext = Get-BoabPathExtension -Path $File
    if ($null -ne $ext) {
        $extLower = $ext.ToLowerInvariant()
        if ((Get-BoabCodebaseCertKeyExtensions) -ccontains $extLower) {
            [long]$size = 0
            try { $size = ([System.IO.FileInfo]::new($File)).Length } catch { $size = 0 }
            $evidence = [ordered]@{
                kind       = 'cert_or_keystore_file'
                extension  = $extLower
                size_bytes = $size
            }
            $out.Add((New-BoabFinding -ScanId $ScanId -SourceType 'file' -SourceLocation $rel -Evidence $evidence -Confidence 'low'))
            return , $out
        }
    }

    # Skip files above 4 MiB to avoid memory spikes.
    $len = ([System.IO.FileInfo]::new($File)).Length
    if ($len -gt 4 * 1024 * 1024) { return , $out }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($File)
        # Strict UTF-8, BOM kept as U+FEFF (like Rust read_to_string).
        $content = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        return , $out # binary or non-UTF8
    }

    $language = Get-BoabLanguage -Path $File

    $nl = [System.Collections.Generic.List[int]]::new()
    $pos = $content.IndexOf([char]10)
    while ($pos -ge 0) {
        $nl.Add($pos)
        $pos = $content.IndexOf([char]10, $pos + 1)
    }
    $nlArr = $nl.ToArray()
    $lines = Split-BoabRustLines -Content $content

    foreach ($pat in (Get-BoabGenericPatterns)) {
        foreach ($m in $pat.Regex.Matches($content)) {
            $ls = Get-BoabLineAndSnippet -NewlineOffsets $nlArr -Lines $lines -Start $m.Index
            $params = [ordered]@{}
            if ($null -ne $pat.KeySizeBits) { $params['key_size_bits'] = [int]$pat.KeySizeBits }
            if ($null -ne $pat.Primitive) { $params['primitive'] = [string]$pat.Primitive }
            $evidence = [ordered]@{
                kind           = 'algorithm_match'
                algorithm_name = $pat.AlgorithmName
                pqc_status     = $pat.PqcStatus
                parameter_set  = $params
                language       = $language
                match          = $m.Value
                line           = [int]$ls[0]
                snippet        = [string]$ls[1]
            }
            $out.Add((New-BoabFinding -ScanId $ScanId -SourceType 'file' -SourceLocation "${rel}:$($ls[0])" -Evidence $evidence -Confidence $pat.Confidence))
        }
    }

    foreach ($pat in (Get-BoabLibraryPatterns)) {
        if ($pat.Language -cne $language) { continue }
        foreach ($m in $pat.Regex.Matches($content)) {
            $ls = Get-BoabLineAndSnippet -NewlineOffsets $nlArr -Lines $lines -Start $m.Index
            $evidence = [ordered]@{
                kind         = 'library_import'
                library_name = $pat.LibraryName
                language     = $language
                match        = $m.Value
                line         = [int]$ls[0]
                snippet      = [string]$ls[1]
            }
            $out.Add((New-BoabFinding -ScanId $ScanId -SourceType 'file' -SourceLocation "${rel}:$($ls[0])" -Evidence $evidence -Confidence $pat.Confidence))
        }
    }
    return , $out
}

function New-BoabCodebaseOverrides {
    <#
    .SYNOPSIS
    Build the override matcher exactly as `scan_path` does: for every default and
    user exclude add "!<ex>/" and "!**/<ex>/**", then every include glob.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [string[]] $Include = @(),
        [string[]] $Exclude = @()
    )
    $ov = New-BoabGitignoreMatcher -Root $Root
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($e in (Get-BoabDefaultExcludes)) { $all.Add($e) }
    foreach ($e in $Exclude) { $all.Add($e) }
    foreach ($ex in $all) {
        Add-BoabGitignoreLine -Matcher $ov -Line "!$ex/"
        Add-BoabGitignoreLine -Matcher $ov -Line "!**/$ex/**"
    }
    foreach ($inc in $Include) {
        Add-BoabGitignoreLine -Matcher $ov -Line $inc
    }
    return $ov
}

function Invoke-BoabCodebaseScan {
    <#
    .SYNOPSIS
    Scan a directory (or single file) for cryptographic usage. Port of
    `boab::scanners::codebase::scan_path`.
    .DESCRIPTION
    Returns one Scan ([ordered] hashtable). Throws "could not resolve scan path
    <path>" when the path does not exist, like the Rust scanner.

    Git URLs are not supported: the Rust CLI rejects `--git` with "git cloning
    is not yet implemented" before it reaches the scanner, so the scanner only
    takes local paths.
    .PARAMETER Include
    Extra include globs (CodebaseOptions.include). With any include present, only
    files matching an include are scanned. Includes override hidden-file and
    ignore-file rules.
    .PARAMETER Exclude
    Extra exclude names/globs (CodebaseOptions.exclude), applied like the defaults
    as "!<ex>/" and "!**/<ex>/**" overrides.
    .PARAMETER Name
    Scan name (CodebaseOptions.name). Defaults to "codebase:<canonical path>".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Path,
        [string[]] $Include = @(),
        [string[]] $Exclude = @(),
        [string] $Name
    )
    if ($null -eq $Include) { $Include = @() }
    if ($null -eq $Exclude) { $Exclude = @() }
    try {
        $root = Resolve-BoabCanonicalPath -Path $Path
    }
    catch {
        throw "could not resolve scan path ${Path}: $($_.Exception.Message)"
    }
    $display = Get-BoabPathDisplay -Path $root
    $scanName = if ($PSBoundParameters.ContainsKey('Name') -and $null -ne $Name) { $Name } else { "codebase:$display" }
    $scan = New-BoabScan -Name $scanName -ScanType 'codebase' -Target $display
    $scan.config = [ordered]@{
        include          = [object[]]@($Include)
        exclude          = [object[]]@($Exclude)
        default_excludes = [object[]]@(Get-BoabDefaultExcludes)
    }
    $scan.status = 'running'

    $options = @{
        Hidden     = $true
        DotIgnore  = $true
        GitIgnore  = $true
        GitExclude = $true
        GitGlobal  = $true
        Parents    = $true
        Overrides  = (New-BoabCodebaseOverrides -Root $root -Include $Include -Exclude $Exclude)
    }
    $files = Get-BoabWalkFiles -Root $root -Options $options
    foreach ($file in $files) {
        try {
            $found = Get-BoabCodebaseFileFindings -ScanId $scan.id -File $file -Root $root
            $scan.findings.AddRange($found)
        }
        catch {
            Write-Debug "skip ${file}: $($_.Exception.Message)"
        }
    }

    $scan.status = 'completed'
    $scan.completed_at = Get-BoabUtcNow
    return $scan
}
