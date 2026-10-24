#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Byte-level parity against outputs produced by the Rust implementation:
#  1. fixtures/golden/workspace - built by powershell/tools/golden-gen (Rust library)
#     from the scan JSON in fixtures/scans.
#  2. examples/demo - the committed demo run (reports/*.json|md|html and inventory.txt).
# UUIDs and timestamps are normalised before comparing; everything else must match.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    $script:GoldenWs = Join-Path $PSScriptRoot 'fixtures' 'golden' 'workspace'
    $script:DemoDir = Join-Path $script:RepoRoot 'examples' 'demo'

    function script:Assert-SameNormalized {
        param([string]$Expected, [string]$Actual, [string]$Label, [switch]$Table)
        $e = ConvertTo-NormalizedText -Text $Expected -Table:$Table
        $a = ConvertTo-NormalizedText -Text $Actual -Table:$Table
        if ($a -cne $e) {
            $el = $e.Split("`n"); $al = $a.Split("`n")
            $n = [math]::Max($el.Count, $al.Count)
            for ($i = 0; $i -lt $n; $i++) {
                $x = if ($i -lt $el.Count) { $el[$i] } else { '<eof>' }
                $y = if ($i -lt $al.Count) { $al[$i] } else { '<eof>' }
                if ($x -cne $y) { throw "$Label differs at line $($i + 1):`n  expected: $x`n  actual:   $y" }
            }
        }
    }
}

Describe 'Golden workspace built by the Rust library' {
    BeforeAll {
        $script:Ws = New-BoabTestDirectory
        Initialize-BoabWorkspace -Path $script:Ws | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:GoldenWs 'systems.json') -Destination (Join-Path $script:Ws '.boab' 'systems.json') -Force
        $scanFiles = Get-BoabFixtureScan
        InModuleScope Boab -Parameters @{ Root = $script:Ws; Scans = $scanFiles } {
            param($Root, $Scans)
            $ws = Open-BoabWorkspace -Root $Root
            foreach ($file in $Scans) {
                $scan = Read-BoabJsonFile -Path $file -Converter 'ConvertTo-BoabScanFromJson'
                foreach ($f in $scan.findings) { $f.crypto_asset_id = $null }
                [void](Invoke-BoabPromotion -Workspace $ws -Scan $scan)
                Save-BoabStoredScan -Workspace $ws -Scan $scan
            }
            # Same edits as golden-gen's workspace() function.
            $systems = Get-BoabStoredSystem -Workspace $ws
            $inv = Get-BoabStoredInventory -Workspace $ws
            $inv[0].system_id = $systems[0].id
            $inv[1].data_classification = 'secret'
            $inv[2].data_retention_horizon_year = [long]2060
            $inv[3].system_id = $systems[1].id
            $inv[4].data_retention_horizon_year = [long]2020
            $inv[5].migration_difficulty = 'hardware_locked'
            $inv[6].notes = 'Owned by | payments'
            Save-BoabStoredInventory -Workspace $ws -Inventory $inv

            [void](Add-BoabVendorOverrideEntry -Workspace $ws -Vendor 'Microsoft' -Product 'Azure' -PqcStatus 'resistant' -TargetDate '2026-Q4' -SourceNote 'override')
            [void](Add-BoabVendorOverrideEntry -Workspace $ws -Vendor 'Acme' -Product 'Widget' -PqcStatus 'hybrid' -SourceUrl 'https://example.com')
            $ov = Get-BoabStoredVendorOverride -Workspace $ws
            $ov.entries[1].last_verified_at = $null
            Save-BoabStoredVendorOverride -Workspace $ws -Registry $ov

            Save-BoabStoredPlan -Workspace $ws -Plan (New-BoabTransitionPlan -Workspace $ws -Milestone 'y2028' -Name $null)
            Start-Sleep -Milliseconds 5
            Save-BoabStoredPlan -Workspace $ws -Plan (New-BoabTransitionPlan -Workspace $ws -Milestone 'y2030' -Name 'Demo rollout')

            $reports = Get-BoabWorkspacePath -Workspace $ws -Kind Reports
            Export-BoabJsonReport -Workspace $ws -Path (Join-Path $reports 'report.json')
            Export-BoabCbomReport -Workspace $ws -Path (Join-Path $reports 'bom.cdx.json')
            Export-BoabMarkdownReport -Workspace $ws -Path (Join-Path $reports 'readiness.md')
            Export-BoabHtmlReport -Workspace $ws -Path (Join-Path $reports 'readiness.html')
        }
        $script:Ps = Join-Path $script:Ws '.boab'
    }
    AfterAll {
        Remove-Item -LiteralPath $script:Ws -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'inventory.json matches' {
        Assert-SameNormalized -Label 'inventory.json' -Expected (Read-TestText (Join-Path $script:GoldenWs 'inventory.json')) -Actual (Read-TestText (Join-Path $script:Ps 'inventory.json'))
    }

    It 'saved scan <_> matches (findings linked to assets)' -ForEach @(
        '5ba16e0d-4644-4332-8c39-c7fab7366600.json', '6d5042c7-58ba-47d2-b754-c50f25b30431.json',
        '798d1d4c-7a86-4d52-9104-f08c815cd3b9.json', 'ae9f5cee-e49c-4aa1-b22a-f4bffc2c5bcb.json'
    ) {
        Assert-SameNormalized -Label $_ -Expected (Read-TestText (Join-Path $script:GoldenWs 'scans' $_)) -Actual (Read-TestText (Join-Path $script:Ps 'scans' $_))
    }

    It 'vendor-overrides.json matches' {
        Assert-SameNormalized -Label 'vendor-overrides.json' -Expected (Read-TestText (Join-Path $script:GoldenWs 'vendor-overrides.json')) -Actual (Read-TestText (Join-Path $script:Ps 'vendor-overrides.json'))
    }

    It 'plans match' {
        $byMilestone = {
            param($dir)
            $h = @{}
            foreach ($f in Get-ChildItem -LiteralPath (Join-Path $dir 'plans') -Filter '*.json') {
                $text = Read-TestText $f.FullName
                $h[($text | ConvertFrom-Json).milestone] = $text
            }
            $h
        }
        $expected = & $byMilestone $script:GoldenWs
        $actual = & $byMilestone $script:Ps
        @($actual.Keys | Sort-Object) | Should -Be @($expected.Keys | Sort-Object)
        foreach ($k in $expected.Keys) { Assert-SameNormalized -Label "plan $k" -Expected $expected[$k] -Actual $actual[$k] }
    }

    It 'report <_> matches' -ForEach @('report.json', 'bom.cdx.json', 'readiness.md', 'readiness.html') {
        Assert-SameNormalized -Label $_ -Expected (Read-TestText (Join-Path $script:GoldenWs 'reports' $_)) -Actual (Read-TestText (Join-Path $script:Ps 'reports' $_))
    }
}

Describe 'Committed demo outputs (examples/demo)' {
    BeforeAll {
        $script:DemoWs = New-BoabTestDirectory
        Initialize-BoabWorkspace -Path $script:DemoWs | Out-Null
        $reportPath = Join-Path $script:DemoDir 'reports' 'inventory.json'
        # Rebuild the demo workspace state from the committed JSON report.
        InModuleScope Boab -Parameters @{ Root = $script:DemoWs; ReportPath = $reportPath } {
            param($Root, $ReportPath)
            $ws = Open-BoabWorkspace -Root $Root
            $report = ConvertFrom-BoabJson -Json ([System.IO.File]::ReadAllText($ReportPath))
            Save-BoabStoredSystem -Workspace $ws -Systems (ConvertTo-BoabRecordList -Parsed $report.systems -Converter 'ConvertTo-BoabSystemRecord')
            $inv = New-BoabList
            foreach ($a in $report.inventory) {
                $copy = [ordered]@{}
                foreach ($k in $a.Keys) { if ($k -cne 'risk_score') { $copy[$k] = $a[$k] } }
                $inv.Add((ConvertTo-BoabCryptoAssetRecord -InputObject $copy))
            }
            Save-BoabStoredInventory -Workspace $ws -Inventory $inv
            foreach ($p in $report.plans) { Save-BoabStoredPlan -Workspace $ws -Plan (ConvertTo-BoabPlanRecord -InputObject $p) }
            foreach ($s in $report.scans) {
                $findings = New-BoabList
                for ($i = 0; $i -lt $s.finding_count; $i++) {
                    $findings.Add([ordered]@{
                            id = New-BoabUuid; scan_id = $s.id; crypto_asset_id = $null; source_type = 'host'
                            source_location = $s.target; evidence = [ordered]@{}; confidence = 'low'; status = 'new'
                            discovered_at = $s.started_at
                        })
                }
                Save-BoabStoredScan -Workspace $ws -Scan ([ordered]@{
                        id = $s.id; name = $s.name; scan_type = $s.scan_type; status = $s.status; target = $s.target
                        config = [ordered]@{}; started_at = $s.started_at; completed_at = $null; findings = $findings; error_message = $null
                    })
            }
        }
    }
    AfterAll {
        Remove-Item -LiteralPath $script:DemoWs -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'regenerates reports/inventory.json' {
        $out = Join-Path $script:DemoWs 'inventory.json'
        (Invoke-BoabTest --workspace $script:DemoWs report --format json --output $out).ExitCode | Should -Be 0
        Assert-SameNormalized -Label 'inventory.json' -Expected (Read-TestText (Join-Path $script:DemoDir 'reports' 'inventory.json')) -Actual (Read-TestText $out)
    }

    It 'regenerates reports/cbom.cdx.json' {
        $out = Join-Path $script:DemoWs 'cbom.cdx.json'
        (Invoke-BoabTest --workspace $script:DemoWs report --format cbom --output $out).ExitCode | Should -Be 0
        Assert-SameNormalized -Label 'cbom.cdx.json' -Expected (Read-TestText (Join-Path $script:DemoDir 'reports' 'cbom.cdx.json')) -Actual (Read-TestText $out)
    }

    It 'regenerates reports/readiness.md' {
        $out = Join-Path $script:DemoWs 'readiness.md'
        (Invoke-BoabTest --workspace $script:DemoWs report --format md --output $out).ExitCode | Should -Be 0
        Assert-SameNormalized -Label 'readiness.md' -Expected (Read-TestText (Join-Path $script:DemoDir 'reports' 'readiness.md')) -Actual (Read-TestText $out)
    }

    It 'regenerates reports/readiness.html' {
        $out = Join-Path $script:DemoWs 'readiness.html'
        (Invoke-BoabTest --workspace $script:DemoWs report --format html --output $out).ExitCode | Should -Be 0
        Assert-SameNormalized -Label 'readiness.html' -Expected (Read-TestText (Join-Path $script:DemoDir 'reports' 'readiness.html')) -Actual (Read-TestText $out)
    }

    It 'reproduces inventory.txt (inventory list table) exactly' {
        $r = Invoke-BoabTest --workspace $script:DemoWs inventory list
        $r.ExitCode | Should -Be 0
        $expected = (Read-TestText (Join-Path $script:DemoDir 'inventory.txt')) -replace "`r`n", "`n"
        $r.StdOut | Should -BeExactly $expected
    }
}
