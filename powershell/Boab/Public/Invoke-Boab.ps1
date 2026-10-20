function Invoke-Boab {
    <#
    .SYNOPSIS
    Run Boab with exactly the same command line as the Rust `boab` binary.

    .DESCRIPTION
    Accepts the same arguments as the native CLI (for example
    `Invoke-Boab init --force --yes` or `Invoke-Boab scan codebase ./src`) and
    produces the same stdout text, stderr text and exit code.

    Standard output is written to the pipeline one line per string (so it can be
    captured or piped), standard error is written to the console's error stream
    verbatim, and $LASTEXITCODE is set to the Rust exit code (0 success,
    1 runtime error, 2 usage error, 64 not implemented).

    This is intentionally a simple (non-advanced) function so that arguments such
    as `-o`, `-h` or `-V` are passed through to the Boab parser untouched. Use
    Invoke-BoabCli for structured results.

    .EXAMPLE
    Invoke-Boab --workspace ./demo init

    .EXAMPLE
    Invoke-Boab report --format md -o readiness.md; $LASTEXITCODE
    #>
    $argv = ConvertTo-BoabArgumentList -InputArguments $args
    $result = Invoke-BoabMain -Arguments $argv
    if ($result.StdErr) { [Console]::Error.Write($result.StdErr) }
    $global:LASTEXITCODE = $result.ExitCode
    if ($result.StdOut) {
        $text = $result.StdOut
        if ($text.EndsWith("`n")) { $text = $text.Substring(0, $text.Length - 1) }
        foreach ($line in $text.Split([char]10)) { $line }
    }
}

function Invoke-BoabCli {
    <#
    .SYNOPSIS
    Run a Boab command line and return its exit code and captured output.

    .DESCRIPTION
    Structured counterpart of Invoke-Boab. Returns an object with ExitCode, StdOut
    and StdErr (exact text, including trailing newlines). With -PassThru omitted the
    output is also streamed to the console as the Rust binary would print it.

    .PARAMETER ArgumentList
    The argv to parse, exactly as it would be passed to the `boab` binary.

    .PARAMETER PassThru
    Capture only: do not write anything to the console, just return the result.

    .EXAMPLE
    $r = Invoke-BoabCli -ArgumentList 'system', 'list' -PassThru; $r.StdOut
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList = @(),
        [switch]$PassThru
    )
    $result = Invoke-BoabMain -Arguments $ArgumentList -Stream:(-not $PassThru)
    $global:LASTEXITCODE = $result.ExitCode
    $result
}

function ConvertTo-BoabArgumentList {
    # Flatten PowerShell's $args into argv strings (arrays expand like for native commands).
    param([AllowNull()][object[]]$InputArguments)
    $out = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $InputArguments) { return , $out.ToArray() }
    foreach ($a in $InputArguments) {
        if ($null -eq $a) { continue }
        if ($a -is [string]) { $out.Add($a); continue }
        if ($a -is [System.Collections.IEnumerable] -and $a -isnot [System.Collections.IDictionary]) {
            foreach ($x in $a) { if ($null -ne $x) { $out.Add([string]$x) } }
            continue
        }
        if ($a -is [bool]) { $out.Add($(if ($a) { 'true' } else { 'false' })); continue }
        if ($a -is [double] -or $a -is [single] -or $a -is [decimal]) { $out.Add($a.ToString([System.Globalization.CultureInfo]::InvariantCulture)); continue }
        $out.Add([string]$a)
    }
    , $out.ToArray()
}
