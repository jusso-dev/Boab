#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Live parity check: runs the same command sequence through the Rust `boab`
# binary and through Invoke-BoabCli in two temporary workspaces, then diffs
# stdout, stderr, exit codes and every workspace/report file after normalising
# UUIDs, timestamps and absolute paths.
#
# Scans: the Rust binary performs the real scans; the PowerShell side replays the
# exact scan JSON the Rust binary produced (via scanner stubs), so this compares
# everything downstream of the scanners (dedup, storage, scoring, plans, reports,
# console output).
#
# The Rust binary is located via $env:BOAB_RUST_BIN, then target/release/boab and
# target/debug/boab under the repository root. When none exists the tests are skipped.

BeforeDiscovery {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).ProviderPath
    $exe = if ($IsWindows) { 'boab.exe' } else { 'boab' }
    $script:RustBin = @($env:BOAB_RUST_BIN, (Join-Path $root 'target' 'release' $exe), (Join-Path $root 'target' 'debug' $exe)) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    Install-BoabScannerStub
    $exe = if ($IsWindows) { 'boab.exe' } else { 'boab' }
    $script:Bin = @($env:BOAB_RUST_BIN, (Join-Path $script:RepoRoot 'target' 'release' $exe), (Join-Path $script:RepoRoot 'target' 'debug' $exe)) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1

    function script:Invoke-RustBoab {
        param([string[]]$Argv)
        $psi = [System.Diagnostics.ProcessStartInfo]::new($script:Bin)
        foreach ($a in $Argv) { $psi.ArgumentList.Add($a) }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.WorkingDirectory = (Get-Location).ProviderPath
        $p = [System.Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $outTask.Result; StdErr = $errTask.Result }
    }

    function script:Get-SideToken {
        # Resolve {system0}, {asset0}, {plan2030} ... against one side's workspace.
        param([string]$Ws, [string]$Token)
        $dir = Join-Path $Ws '.boab'
        switch -Regex ($Token) {
            '^\{system(\d+)\}$' { return @(Get-Content -Raw (Join-Path $dir 'systems.json') | ConvertFrom-Json)[[int]$Matches[1]].id }
            '^\{asset(\d+)\}$' { return @(Get-Content -Raw (Join-Path $dir 'inventory.json') | ConvertFrom-Json)[[int]$Matches[1]].id }
            '^\{plan(\d{4})\}$' {
                foreach ($f in Get-ChildItem -LiteralPath (Join-Path $dir 'plans') -Filter '*.json') {
                    if ((Get-Content -Raw $f.FullName | ConvertFrom-Json).milestone -eq "y$($Matches[1])") { return $f.BaseName }
                }
                return 'missing-plan'
            }
            '^\{ws\}(.*)$' { return $Ws + $Matches[1] }
            '^\{repo\}(.*)$' { return $script:RepoRoot + $Matches[1] }
        }
        $Token
    }

    function script:Get-ScanFileSet {
        param([string]$Ws)
        $d = Join-Path $Ws '.boab' 'scans'
        if (-not (Test-Path -LiteralPath $d)) { return @() }
        @(Get-ChildItem -LiteralPath $d -Filter '*.json' | ForEach-Object Name)
    }

    function script:Invoke-ParityStep {
        param([string[]]$Argv, [switch]$Scan, [switch]$Table)
        $rustArgv = @('--workspace', $script:RustWs) + @($Argv | ForEach-Object { Get-SideToken -Ws $script:RustWs -Token $_ })
        $psArgv = @('--workspace', $script:PsWs) + @($Argv | ForEach-Object { Get-SideToken -Ws $script:PsWs -Token $_ })
        $before = Get-ScanFileSet -Ws $script:RustWs
        $rust = Invoke-RustBoab -Argv $rustArgv
        if ($Scan) {
            # Feed the scans the Rust binary just wrote to the PowerShell scanner stub.
            $new = @(Get-ScanFileSet -Ws $script:RustWs | Where-Object { $before -notcontains $_ })
            $files = @($new | ForEach-Object { Join-Path $script:RustWs '.boab' 'scans' $_ } |
                    Sort-Object { (Get-Content -Raw -LiteralPath $_ | ConvertFrom-Json -AsHashtable).started_at })
            if ($files.Count) { Add-BoabQueuedScan -Path $files }
        }
        $ps = Invoke-BoabCli -ArgumentList $psArgv -PassThru
        $label = $Argv -join ' '
        $ps.ExitCode | Should -Be $rust.ExitCode -Because "exit code of '$label'"
        $replace = Get-ParityReplacement
        $eOut = ConvertTo-NormalizedText -Text $rust.StdOut -Replace $replace -Table:$Table
        $aOut = ConvertTo-NormalizedText -Text $ps.StdOut -Replace $replace -Table:$Table
        $aOut | Should -BeExactly $eOut -Because "stdout of '$label'"
        $eErr = ConvertTo-NormalizedText -Text $rust.StdErr -Replace $replace
        $aErr = ConvertTo-NormalizedText -Text $ps.StdErr -Replace $replace
        $aErr | Should -BeExactly $eErr -Because "stderr of '$label'"
    }

    function script:Get-ParityReplacement {
        $r = @{}
        foreach ($p in @($script:RustWs, $script:PsWs, $script:RustWsCanonical, $script:PsWsCanonical)) { if ($p) { $r[$p] = '<ws>' } }
        $r[$script:RepoRoot] = '<repo>'
        $r
    }

    function script:Assert-ParityFile {
        param([string]$Relative)
        $e = Read-TestText (Join-Path $script:RustWs $Relative)
        $a = Read-TestText (Join-Path $script:PsWs $Relative)
        $replace = Get-ParityReplacement
        (ConvertTo-NormalizedText -Text $a -Replace $replace) | Should -BeExactly (ConvertTo-NormalizedText -Text $e -Replace $replace) -Because $Relative
    }

    if ($script:Bin) {
        $script:RustWs = New-BoabTestDirectory
        $script:PsWs = New-BoabTestDirectory
        $script:RustWsCanonical = InModuleScope Boab -Parameters @{ P = $script:RustWs } { param($P) Resolve-BoabCanonicalPath -Path $P }
        $script:PsWsCanonical = InModuleScope Boab -Parameters @{ P = $script:PsWs } { param($P) Resolve-BoabCanonicalPath -Path $P }
    }
}

AfterAll {
    Uninstall-BoabScannerStub
    foreach ($d in @($script:RustWs, $script:PsWs)) {
        if ($d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Rust binary vs PowerShell module' -Skip:(-not $script:RustBin) {
    It 'init / system management' {
        Invoke-ParityStep @('init')
        Invoke-ParityStep @('init')
        Invoke-ParityStep @('init', '--force')
        Invoke-ParityStep @('system', 'add', '--name', 'Demo Payments', '--classification', 'protected', '--criticality', 'mission_critical', '--soci', '--lifetime-years', '25')
        Invoke-ParityStep @('system', 'add', '--name', 'HR | People', '--description', 'a "quoted" thing', '--classification', 'official-sensitive', '--criticality', 'essential')
        Invoke-ParityStep @('system', 'list') -Table
        Invoke-ParityStep @('system', 'edit', '--id', '{system1}', '--soci', 'true', '--lifetime-years', '7')
        Invoke-ParityStep @('system', 'list') -Table
        Invoke-ParityStep @('system', 'add', '--name', 'x', '--classification', 'nope')
        Invoke-ParityStep @('system', 'delete', '00000000-0000-0000-0000-000000000000')
        Assert-ParityFile '.boab/systems.json'
    }

    It 'config' {
        Invoke-ParityStep @('config', 'get', 'scanner.air_gapped')
        Invoke-ParityStep @('config', 'set', 'scanner.default_rate_limit', 'a"b')
        Invoke-ParityStep @('config', 'get', 'scanner.default_rate_limit')
        Invoke-ParityStep @('config', 'set', 'scanner.tls_timeout_seconds', '30')
        Invoke-ParityStep @('config', 'set', 'scanner.air_gapped', 'maybe')
        Invoke-ParityStep @('config', 'get', 'nope')
        Assert-ParityFile '.boab/config.toml'
    }

    It 'scans, dedup and inventory' {
        Invoke-ParityStep @('scan', 'codebase', '{repo}/tests/fixtures/codebase') -Scan
        Invoke-ParityStep @('scan', 'certs', '{repo}/tests/fixtures/certs') -Scan
        Invoke-ParityStep @('scan', 'codebase', '{repo}/examples/demo/app') -Scan
        Invoke-ParityStep @('scan', 'certs', '{repo}/examples/demo/certs') -Scan
        Invoke-ParityStep @('scan', 'codebase', '{repo}/examples/demo/app') -Scan
        Invoke-ParityStep @('scan', 'codebase', '--git', 'https://example.com/x.git')
        Assert-ParityFile '.boab/inventory.json'
        foreach ($f in Get-ScanFileSet -Ws $script:RustWs) { Assert-ParityFile ".boab/scans/$f" }
        Invoke-ParityStep @('inventory', 'list') -Table
        Invoke-ParityStep @('inventory', 'list', '--tier', '3') -Table
        Invoke-ParityStep @('inventory', 'list', '--pqc-status', 'vulnerable', '--algorithm', 'rsa') -Table
        Invoke-ParityStep @('inventory', 'list', '--pqc-status', 'symmetricok') -Table
        Invoke-ParityStep @('inventory', 'list', '--system', '{system0}')
        Invoke-ParityStep @('inventory', 'show', '{asset0}')
        Invoke-ParityStep @('inventory', 'show', '{asset40}')
        Invoke-ParityStep @('inventory', 'show', '00000000-0000-0000-0000-000000000000')
    }

    It 'plans' {
        Invoke-ParityStep @('plan', 'list')
        Invoke-ParityStep @('plan', 'generate', '--milestone', '2030', '--name', 'Demo rollout')
        Invoke-ParityStep @('plan', 'generate', '--milestone', '2028')
        Invoke-ParityStep @('plan', 'generate', '--milestone', '2027')
        Invoke-ParityStep @('plan', 'list') -Table
        Invoke-ParityStep @('plan', 'show', '{plan2030}')
        foreach ($ws in $script:RustWs, $script:PsWs) {
            $file = Join-Path $ws '.boab' 'plans' ((Get-SideToken -Ws $ws -Token '{plan2030}') + '.json')
            $plan = InModuleScope Boab -Parameters @{ P = $file } { param($P) ConvertFrom-BoabJson -Json ([System.IO.File]::ReadAllText($P)) }
            $plan.items[0].assignee = 'payments-team'
            $plan.items[0].notes = 'Owned by Sue'
            $plan.items[1].status = 'deferred'
            $plan.items[1].target_date = '+002029-01-01T00:00:00.000000000Z'
            [System.IO.File]::WriteAllText($file, (ConvertTo-BoabJson -InputObject $plan))
        }
        Invoke-ParityStep @('plan', 'regenerate', '{plan2030}')
        Invoke-ParityStep @('plan', 'show', '{plan2030}')
        Invoke-ParityStep @('plan', 'show', '00000000-0000-0000-0000-000000000000')
        foreach ($m in '2028', '2030') {
            $rel = '.boab/plans/' + (Get-SideToken -Ws $script:RustWs -Token "{plan$m}") + '.json'
            $relPs = '.boab/plans/' + (Get-SideToken -Ws $script:PsWs -Token "{plan$m}") + '.json'
            $e = ConvertTo-NormalizedText -Text (Read-TestText (Join-Path $script:RustWs $rel))
            $a = ConvertTo-NormalizedText -Text (Read-TestText (Join-Path $script:PsWs $relPs))
            $a | Should -BeExactly $e -Because "plan $m"
        }
    }

    It 'vendors' {
        Invoke-ParityStep @('vendor', 'list') -Table
        Invoke-ParityStep @('vendor', 'search', 'azure') -Table
        Invoke-ParityStep @('vendor', 'add', '--vendor', 'Microsoft', '--product', 'Azure', '--pqc-status', 'resistant', '--target-date', '2026-Q4')
        Invoke-ParityStep @('vendor', 'add', '--vendor', 'Acme', '--product', 'Widget', '--pqc-status', 'HYBRID', '--source-url', 'https://example.com')
        Invoke-ParityStep @('vendor', 'search', 'a') -Table
        Invoke-ParityStep @('vendor', 'search', 'zzz')
        Assert-ParityFile '.boab/vendor-overrides.json'
    }

    It 'reports' {
        Invoke-ParityStep @('report', '--format', 'json')
        Invoke-ParityStep @('report', '--format', 'cbom')
        Invoke-ParityStep @('report', '--format', 'md')
        Invoke-ParityStep @('report', '--format', 'JSON', '-o', '{ws}/out.json')
        Invoke-ParityStep @('report', '--format', 'html')
        Assert-ParityFile '.boab/reports/report.json'
        Assert-ParityFile '.boab/reports/bom.cdx.json'
        Assert-ParityFile '.boab/reports/readiness.md'
        Assert-ParityFile 'out.json'
    }

    It 'help, version and usage errors' {
        Invoke-ParityStep @('--help')
        Invoke-ParityStep @('-V')
        Invoke-ParityStep @('system')
        Invoke-ParityStep @('scan', 'tls', '--help')
        Invoke-ParityStep @('help', 'vendor', 'add')
        Invoke-ParityStep @('frob')
        Invoke-ParityStep @('system', 'lst')
        Invoke-ParityStep @('system', 'add', '--nam', 'x')
        Invoke-ParityStep @('inventory', 'list', '--tier', '300')
        Invoke-ParityStep @('system', 'delete', 'not-a-uuid')
        Invoke-ParityStep @('--verbose', '--quiet', 'init')
    }
}
