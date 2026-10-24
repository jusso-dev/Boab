# Shared helpers for the Boab Pester suite. Dot-source from BeforeAll.

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).ProviderPath
$script:ModuleManifest = Join-Path $PSScriptRoot '..' 'Boab' 'Boab.psd1'
$script:FixtureRoot = Join-Path $PSScriptRoot 'fixtures'

function Import-BoabTestModule {
    Import-Module $script:ModuleManifest -Force
}

function New-BoabTestDirectory {
    $base = [System.IO.Path]::GetTempPath()
    $dir = Join-Path $base ('boab-pester-' + [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($dir)
    $dir
}

function Invoke-BoabTest {
    # Run a Boab command line in-process and capture its result. Deliberately a
    # simple function (no param block) so tokens like -V, -o or -x reach Boab.
    $argv = [string[]]@($args | ForEach-Object { [string]$_ })
    Invoke-BoabCli -ArgumentList $argv -PassThru
}

function Invoke-InBoabModule {
    param([scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
    $mod = Get-Module Boab
    & $mod $ScriptBlock @ArgumentList
}

function Install-BoabScannerStub {
    <#
    Replace the scanner entry points inside the module with stubs that replay
    scan JSON files queued with Add-BoabQueuedScan (crypto_asset_id links reset).
    This keeps these tests independent of the scanner implementation.
    #>
    $mod = Get-Module Boab
    & $mod ([scriptblock]::Create(@'
        if (-not (Get-Variable -Name BoabTestSavedScanners -Scope Script -ErrorAction SilentlyContinue)) {
            $script:BoabTestSavedScanners = @{}
            foreach ($n in 'Invoke-BoabCodebaseScan', 'Invoke-BoabCertStoreScan', 'Invoke-BoabTlsScan') {
                $existing = Get-Item -Path "function:$n" -ErrorAction SilentlyContinue
                $script:BoabTestSavedScanners[$n] = if ($existing) { $existing.ScriptBlock } else { $null }
            }
        }
        $script:BoabTestScanQueue = [System.Collections.Generic.Queue[string]]::new()
        $script:BoabTestScannerCalls = [System.Collections.Generic.List[object]]::new()
        function script:Get-BoabTestQueuedScan {
            param([hashtable]$Call)
            $script:BoabTestScannerCalls.Add($Call)
            if ($script:BoabTestScanQueue.Count -eq 0) { throw 'no queued scan fixture' }
            $file = $script:BoabTestScanQueue.Dequeue()
            $scan = Read-BoabJsonFile -Path $file -Converter 'ConvertTo-BoabScanFromJson'
            foreach ($f in $scan.findings) { $f.crypto_asset_id = $null }
            $scan
        }
        function script:Invoke-BoabCodebaseScan {
            param([string]$Path, [string[]]$Include, [string[]]$Exclude, [string]$Name)
            Get-BoabTestQueuedScan -Call @{ Scanner = 'codebase'; Bound = $PSBoundParameters }
        }
        function script:Invoke-BoabCertStoreScan {
            param([string]$Path, [string]$PasswordFile, [string]$Name)
            Get-BoabTestQueuedScan -Call @{ Scanner = 'certs'; Bound = $PSBoundParameters }
        }
        function script:Invoke-BoabTlsScan {
            param([string[]]$Targets, [string]$RateLimit, $TimeoutSeconds, [switch]$ProbeHsts, [string[]]$Exclude, [string]$Name, [switch]$AirGapped)
            $all = [System.Collections.Generic.List[object]]::new()
            foreach ($t in $Targets) {
                $all.Add((Get-BoabTestQueuedScan -Call @{ Scanner = 'tls'; Bound = $PSBoundParameters; Target = $t }))
            }
            $all.ToArray()
        }
'@))
}

function Uninstall-BoabScannerStub {
    $mod = Get-Module Boab
    if (-not $mod) { return }
    & $mod ([scriptblock]::Create(@'
        if (Get-Variable -Name BoabTestSavedScanners -Scope Script -ErrorAction SilentlyContinue) {
            foreach ($n in @($script:BoabTestSavedScanners.Keys)) {
                $sb = $script:BoabTestSavedScanners[$n]
                if ($null -ne $sb) { Set-Item -Path "function:script:$n" -Value $sb }
                else { Remove-Item -Path "function:$n" -ErrorAction SilentlyContinue }
            }
            Remove-Variable -Name BoabTestSavedScanners -Scope Script
        }
'@))
}

function Add-BoabQueuedScan {
    param([Parameter(Mandatory)][string[]]$Path)
    $mod = Get-Module Boab
    foreach ($p in $Path) {
        & $mod { param($x) $script:BoabTestScanQueue.Enqueue($x) } (Resolve-Path -LiteralPath $p).ProviderPath
    }
}

function Get-BoabFixtureScan {
    param([string]$Pattern = '*.json')
    @(Get-ChildItem -Path (Join-Path $script:FixtureRoot 'scans') -Filter $Pattern | Sort-Object Name | ForEach-Object FullName)
}

function ConvertTo-NormalizedText {
    <#
    Make two Boab outputs comparable: UUIDs are renamed in order of first
    appearance, RFC 3339 timestamps become <ts>, and optional literal paths are
    replaced. With -Table, runs of padding and border characters are collapsed
    so variable-width timestamps do not change column widths.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$Text,
        [hashtable]$Replace = @{},
        [switch]$Table
    )
    if ($null -eq $Text) { return '' }
    $t = $Text -replace "`r`n", "`n"
    foreach ($k in ($Replace.Keys | Sort-Object { $_.Length } -Descending)) { $t = $t.Replace([string]$k, [string]$Replace[$k]) }
    $map = @{}
    $t = [regex]::Replace($t, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', {
            param($m)
            $key = $m.Value
            if (-not $map.ContainsKey($key)) { $map[$key] = 'UUID{0:D4}-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -f ($map.Count + 1) }
            $map[$key]
        })
    $t = [regex]::Replace($t, '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})', '<ts>')
    # HTML reports show the same instants in readable form inside <time> elements.
    $t = [regex]::Replace($t, '<time datetime="<ts>">[^<]*</time>', '<time datetime="<ts>"><ts></time>')
    if ($Table) {
        $t = [regex]::Replace($t, ' {2,}', ' ')
        $t = [regex]::Replace($t, '─+', '─')
        $t = [regex]::Replace($t, '═+', '═')
        $t = [regex]::Replace($t, '╌+', '╌')
    }
    $t
}

function Read-TestText {
    param([string]$Path)
    [System.IO.File]::ReadAllText($Path)
}
