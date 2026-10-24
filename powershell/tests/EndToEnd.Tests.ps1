#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Ports of tests/end_to_end.rs, tests/plan_and_vendor.rs and tests/reports.rs.
# Scanners are replaced by stubs that replay scan JSON produced by the Rust
# binary (fixtures/scans), so these tests exercise everything downstream of the
# scanners: dedup, persistence, scoring, plans and reports.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    Install-BoabScannerStub
    $script:CodebaseFixture = Join-Path $script:RepoRoot 'tests' 'fixtures' 'codebase'
    $script:CertFixture = Join-Path $script:RepoRoot 'tests' 'fixtures' 'certs'

    function script:Initialize-ScannedWorkspace {
        param([string]$Milestone)
        $tmp = New-BoabTestDirectory
        (Invoke-BoabTest --workspace $tmp init).ExitCode | Should -Be 0
        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '01-codebase-fixtures.json')
        $r = Invoke-BoabTest --workspace $tmp scan codebase $script:CodebaseFixture
        $r.ExitCode | Should -Be 0
        if ($Milestone) {
            (Invoke-BoabTest --workspace $tmp plan generate --milestone $Milestone).ExitCode | Should -Be 0
        }
        $tmp
    }
}

AfterAll {
    Uninstall-BoabScannerStub
}

Describe 'end_to_end.rs' {
    It 'runs the full happy path' {
        $tmp = New-BoabTestDirectory
        (Invoke-BoabTest --workspace $tmp init).ExitCode | Should -Be 0
        (Invoke-BoabTest --workspace $tmp system add --name Payments --classification protected --criticality mission_critical --soci --lifetime-years 25).ExitCode | Should -Be 0

        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '01-codebase-fixtures.json')
        $r = Invoke-BoabTest --workspace $tmp scan codebase $script:CodebaseFixture
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match '^scan [0-9a-f-]{36} complete: 55 findings, inventory 40 entries\n$'

        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '02-certs-fixtures.json')
        $r = Invoke-BoabTest --workspace $tmp scan certs $script:CertFixture
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match '^cert scan [0-9a-f-]{36} complete: 1 findings, inventory 41 entries\n$'

        $r = Invoke-BoabTest --workspace $tmp plan generate --milestone 2028
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match '^plan [0-9a-f-]{36} generated for 2028: \d+ items\n$'

        foreach ($fmt in 'json', 'cbom', 'md') {
            (Invoke-BoabTest --workspace $tmp report --format $fmt).ExitCode | Should -Be 0
        }
        $reports = Join-Path $tmp '.boab' 'reports'
        Test-Path -LiteralPath (Join-Path $reports 'report.json') -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $reports 'bom.cdx.json') -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $reports 'readiness.md') -PathType Leaf | Should -BeTrue

        # Scans are persisted with findings linked to inventory assets.
        $scanFiles = @(Get-ChildItem -LiteralPath (Join-Path $tmp '.boab' 'scans') -Filter '*.json')
        $scanFiles.Count | Should -Be 2
        $inventoryIds = @((Get-Content -Raw (Join-Path $tmp '.boab' 'inventory.json') | ConvertFrom-Json) | ForEach-Object id)
        foreach ($f in $scanFiles) {
            $scan = Get-Content -Raw -LiteralPath $f.FullName | ConvertFrom-Json
            foreach ($finding in $scan.findings) { $inventoryIds | Should -Contain $finding.crypto_asset_id }
        }
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'does not duplicate inventory entries when the same scan is repeated' {
        $tmp = Initialize-ScannedWorkspace
        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '01-codebase-fixtures.json')
        $r = Invoke-BoabTest --workspace $tmp scan codebase $script:CodebaseFixture
        $r.StdOut | Should -Match 'complete: 55 findings, inventory 40 entries'
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'passes CLI options through to the scanners' {
        $tmp = New-BoabTestDirectory
        Invoke-BoabTest --workspace $tmp init | Out-Null
        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '01-codebase-fixtures.json')
        (Invoke-BoabTest --workspace $tmp scan codebase ./src --include '*.go' --include '*.rs' --exclude vendor --name my-scan).ExitCode | Should -Be 0
        $call = InModuleScope Boab { $script:BoabTestScannerCalls[$script:BoabTestScannerCalls.Count - 1] }
        $call.Scanner | Should -Be 'codebase'
        $call.Bound.Path | Should -BeExactly './src'
        @($call.Bound.Include) | Should -Be @('*.go', '*.rs')
        @($call.Bound.Exclude) | Should -Be @('vendor')
        $call.Bound.Name | Should -BeExactly 'my-scan'
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'runs TLS scans per target and reports the inventory size' {
        $tmp = New-BoabTestDirectory
        Invoke-BoabTest --workspace $tmp init | Out-Null
        $targets = Join-Path $tmp 'targets.txt'
        Set-Content -LiteralPath $targets -Value "# comment`n`nb.example:443`n" -NoNewline
        Add-BoabQueuedScan -Path (Get-BoabFixtureScan '02-certs-fixtures.json'), (Get-BoabFixtureScan '04-certs-demo.json')
        $r = Invoke-BoabTest --workspace $tmp scan tls a.example:443 --targets-file $targets --timeout-seconds 3
        $r.ExitCode | Should -Be 0
        $lines = $r.StdOut.TrimEnd("`n").Split("`n")
        $lines.Count | Should -Be 3
        $lines[0] | Should -Match '^tls scan [0-9a-f-]{36} target=\S+ status=Completed findings=1$'
        $lines[1] | Should -Match '^tls scan [0-9a-f-]{36} target=\S+ status=Completed findings=5$'
        $lines[2] | Should -BeExactly 'inventory now has 6 entries'
        $call = InModuleScope Boab { $script:BoabTestScannerCalls[$script:BoabTestScannerCalls.Count - 1] }
        @($call.Bound.Targets) | Should -Be @('a.example:443', 'b.example:443')
        $call.Bound.TimeoutSeconds | Should -Be 3
        [bool]$call.Bound.AirGapped | Should -BeTrue
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}

Describe 'plan_and_vendor.rs' {
    It 'plan generate 2028 contains only tier 1 and 2 items' {
        $tmp = Initialize-ScannedWorkspace -Milestone 2028
        $plans = @(Get-ChildItem -LiteralPath (Join-Path $tmp '.boab' 'plans') -Filter '*.json')
        $plans.Count | Should -Be 1
        $plan = Get-Content -Raw -LiteralPath $plans[0].FullName | ConvertFrom-Json
        $plan.milestone | Should -BeExactly 'y2028'
        foreach ($item in $plan.items) { $item.triage_tier | Should -BeLessOrEqual 2 }
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'plan generate 2030 includes lower tiers and appears in plan list' {
        $tmp = Initialize-ScannedWorkspace -Milestone 2030
        $r = Invoke-BoabTest --workspace $tmp plan list
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match '2030'
        $r.StdOut | Should -Match 'PQC transition plan 2030'
        $plan = Get-BoabPlan -Workspace $tmp
        @($plan.items | Where-Object { $_.triage_tier -ge 3 }).Count | Should -BeGreaterThan 0
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'plan items are ordered by priority desc, migration difficulty asc, then name' {
        $tmp = Initialize-ScannedWorkspace -Milestone 2030
        $plan = Get-BoabPlan -Workspace $tmp
        $inv = @{}
        foreach ($a in (Get-BoabInventory -Workspace $tmp)) { $inv[$a.id] = $a }
        $items = @($plan.items)
        for ($i = 1; $i -lt $items.Count; $i++) {
            $prev = $items[$i - 1]; $cur = $items[$i]
            [double]$prev.priority | Should -BeGreaterOrEqual ([double]$cur.priority)
            if ([double]$prev.priority -eq [double]$cur.priority) {
                $pm = $inv[$prev.crypto_asset_id].RiskScore.migration_difficulty
                $cm = $inv[$cur.crypto_asset_id].RiskScore.migration_difficulty
                $pm | Should -BeLessOrEqual $cm
                if ($pm -eq $cm) { [string]::CompareOrdinal($prev.asset_name, $cur.asset_name) | Should -BeLessOrEqual 0 }
            }
        }
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'plan regenerate preserves user edits' {
        $tmp = Initialize-ScannedWorkspace -Milestone 2030
        $planFile = @(Get-ChildItem -LiteralPath (Join-Path $tmp '.boab' 'plans') -Filter '*.json')[0].FullName
        $plan = InModuleScope Boab -Parameters @{ P = $planFile } { param($P) ConvertFrom-BoabJson -Json ([System.IO.File]::ReadAllText($P)) }
        $planId = $plan.id
        $plan.items[0].assignee = 'payments-team'
        $plan.items[0].notes = 'Owned by Sue'
        $plan.items[0].target_action = 'Custom action'
        $plan.items[0].status = 'in_progress'
        [System.IO.File]::WriteAllText($planFile, (ConvertTo-BoabJson -InputObject $plan))

        $r = Invoke-BoabTest --workspace $tmp plan regenerate $planId
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match "^plan $planId regenerated: \d+ items \(user edits preserved\)\n$"
        $updated = Get-Content -Raw -LiteralPath $planFile | ConvertFrom-Json
        $first = $updated.items[0]
        $first.assignee | Should -BeExactly 'payments-team'
        $first.notes | Should -BeExactly 'Owned by Sue'
        $first.target_action | Should -BeExactly 'Custom action'
        $first.status | Should -BeExactly 'in_progress'
        $updated.id | Should -BeExactly $planId
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'plan show prints the stored plan JSON' {
        $tmp = Initialize-ScannedWorkspace -Milestone 2028
        $planFile = @(Get-ChildItem -LiteralPath (Join-Path $tmp '.boab' 'plans') -Filter '*.json')[0]
        $r = Invoke-BoabTest --workspace $tmp plan show $planFile.BaseName
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly ([System.IO.File]::ReadAllText($planFile.FullName) + "`n")
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'vendor list shows bundled entries' {
        $tmp = New-BoabTestDirectory
        Invoke-BoabTest --workspace $tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $tmp vendor list
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match 'Microsoft'
        $r.StdOut | Should -Match '│ VENDOR'
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }

    It 'vendor override takes precedence' {
        $tmp = New-BoabTestDirectory
        Invoke-BoabTest --workspace $tmp init | Out-Null
        $r = Invoke-BoabTest --workspace $tmp vendor add --vendor Microsoft --product Azure --pqc-status resistant --target-date 2026-Q4
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly "vendor override saved`n"
        $r = Invoke-BoabTest --workspace $tmp vendor search Azure
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -Match 'resistant'
        $r.StdOut | Should -Match '2026-Q4'
        $azure = @(Get-BoabVendor -Search azure -Workspace $tmp)
        $azure.Count | Should -Be 1
        $azure[0].pqc_status | Should -BeExactly 'resistant'
        $azure[0].last_verified_at | Should -Match '^\d{4}-\d{2}-\d{2}T'
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}

Describe 'reports.rs' {
    BeforeAll {
        $script:ReportWs = Initialize-ScannedWorkspace -Milestone 2030
    }
    AfterAll {
        Remove-Item -LiteralPath $script:ReportWs -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'JSON report round-trips' {
        $out = Join-Path $script:ReportWs 'report.json'
        $r = Invoke-BoabTest --workspace $script:ReportWs report --format json -o $out
        $r.ExitCode | Should -Be 0
        $r.StdOut | Should -BeExactly "wrote json report to $out`n"
        $text = [System.IO.File]::ReadAllText($out)
        $text.EndsWith("`n") | Should -BeFalse
        $v = $text | ConvertFrom-Json
        $v.metadata.tool | Should -BeExactly 'boab'
        $v.metadata.version | Should -BeExactly '0.1.0'
        @($v.inventory).Count | Should -BeGreaterThan 5
        @($v.vendor_registry.entries).Count | Should -BeGreaterOrEqual 20
        @($v.inventory[0].PSObject.Properties.Name)[-1] | Should -BeExactly 'risk_score'
        $v.vendor_coverage.total | Should -Be @($v.vendor_registry.entries).Count
    }

    It 'CBOM validates against the CycloneDX 1.6 subset schema' {
        $out = Join-Path $script:ReportWs 'bom.cdx.json'
        (Invoke-BoabTest --workspace $script:ReportWs report --format cbom -o $out).ExitCode | Should -Be 0
        $bom = [System.IO.File]::ReadAllText($out)
        $obj = $bom | ConvertFrom-Json
        $obj.bomFormat | Should -BeExactly 'CycloneDX'
        $obj.specVersion | Should -BeExactly '1.6'
        $obj.serialNumber | Should -Match '^urn:uuid:[0-9a-f-]{36}$'
        $schemaText = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'tests' 'fixtures' 'cyclonedx-1.6.schema.json'))
        $schemaText = $schemaText -replace '"\$schema":\s*"[^"]*",', '' -replace '"\$id":\s*"[^"]*",', ''
        $errs = $null
        $valid = Test-Json -Json $bom -Schema $schemaText -ErrorAction SilentlyContinue -ErrorVariable errs
        $valid | Should -BeTrue -Because (($errs | ForEach-Object { $_.ToString() }) -join '; ')
    }

    It 'Markdown report contains the executive summary' {
        $out = Join-Path $script:ReportWs 'readiness.md'
        (Invoke-BoabTest --workspace $script:ReportWs report --format md -o $out).ExitCode | Should -Be 0
        $md = [System.IO.File]::ReadAllText($out)
        $md | Should -Match '# Boab PQC Readiness Report'
        $md | Should -Match 'Executive summary'
        $md | Should -Match 'ASD LATICE phase status'
        $md | Should -Match 'Methodology'
        $md.EndsWith("Generated by Boab 0.1.0.`n") | Should -BeTrue
    }

    It 'HTML report is self-contained and escapes workspace text' {
        (Invoke-BoabTest --workspace $script:ReportWs system add --name "<script>alert('x')</script> & Co" --classification official_sensitive --criticality essential).ExitCode | Should -Be 0
        (Invoke-BoabTest --workspace $script:ReportWs vendor add --vendor '<b>Evil</b>' --product 'X' --pqc-status unknown --source-url 'javascript:alert(1)').ExitCode | Should -Be 0
        $out = Join-Path $script:ReportWs 'readiness.html'
        (Invoke-BoabTest --workspace $script:ReportWs report --format html -o $out).ExitCode | Should -Be 0
        $bytes = [System.IO.File]::ReadAllBytes($out)
        $bytes[0] | Should -Be 0x3C -Because 'no UTF-8 BOM'
        $html = [System.Text.Encoding]::UTF8.GetString($bytes)
        $html | Should -Not -Match "`r"
        $html | Should -Match ([regex]::Escape("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; Co"))
        $html | Should -Match ([regex]::Escape('&lt;b&gt;Evil&lt;/b&gt;'))
        $html | Should -Not -Match 'href="javascript:'
        $html | Should -Match '<div class="marking">OFFICIAL: Sensitive</div>'
        # The readable timestamp must describe the same instant as the datetime attribute.
        $m = [regex]::Match($html, '<time datetime="([^"]+)">([^<]+)</time>')
        $m.Success | Should -BeTrue
        $instant = [DateTimeOffset]::Parse($m.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        $u = $instant.UtcDateTime
        $months = 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'
        $m.Groups[2].Value | Should -BeExactly ('{0} {1} {2}, {3:00}:{4:00} UTC' -f $u.Day, $months[$u.Month - 1], $u.Year, $u.Hour, $u.Minute)
        $html.StartsWith("<!DOCTYPE html>`n") | Should -BeTrue
        $html.EndsWith("</html>`n") | Should -BeTrue
        $html | Should -Match 'Executive summary'
        $html | Should -Match 'Highest-priority assets'
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '(src|href)="(?!https?://)[a-z]+:'
        $html | Should -Not -Match '<link'
    }

    It 'rejects an invalid format' {
        $r = Invoke-BoabTest --workspace $script:ReportWs report --format pdf
        $r.ExitCode | Should -Be 1
        $r.StdErr | Should -Match 'unknown report format'
    }

    It 'Export-BoabReport writes to the reports directory by default' {
        $f = Export-BoabReport -Format md -Workspace $script:ReportWs
        $f.Name | Should -BeExactly 'readiness.md'
        $f.Directory.Name | Should -BeExactly 'reports'
    }
}

Describe 'Public cmdlets' {
    It 'support the core workflow without Invoke-Boab' {
        $tmp = New-BoabTestDirectory
        $ws = Initialize-BoabWorkspace -Path $tmp
        $ws.Existed | Should -BeFalse
        (Initialize-BoabWorkspace -Path $tmp).Existed | Should -BeTrue
        $sys = Add-BoabSystem -Name Payments -Classification protected -Criticality mission_critical -Soci -LifetimeYears 25 -Workspace $tmp
        $sys.id | Should -Match '^[0-9a-f-]{36}$'
        Set-BoabSystem -SystemId $sys.id -Criticality essential -Workspace $tmp | Out-Null
        (Get-BoabSystem -Workspace $tmp).criticality | Should -BeExactly 'essential'
        $imported = Import-BoabScan -Path (Get-BoabFixtureScan '03-codebase-demo.json') -ResetAssetLinks -Workspace $tmp
        $imported.FindingCount | Should -Be 12
        @(Get-BoabInventory -Workspace $tmp).Count | Should -Be $imported.InventoryCount
        @(Get-BoabInventory -Workspace $tmp -PqcStatus vulnerable) | ForEach-Object { $_.pqc_status | Should -BeExactly 'vulnerable' }
        $plan = New-BoabPlan -Milestone 2030 -Workspace $tmp
        $plan.name | Should -BeExactly 'PQC transition plan 2030'
        (Update-BoabPlan -PlanId $plan.id -Workspace $tmp).id | Should -BeExactly $plan.id
        Set-BoabConfig -Key scanner.air_gapped -Value false -Workspace $tmp
        Get-BoabConfig -Key scanner.air_gapped -Workspace $tmp | Should -BeExactly 'false'
        Add-BoabVendor -Vendor Acme -Product Widget -PqcStatus hybrid -Workspace $tmp | Out-Null
        (Get-BoabVendor -Search widget -Workspace $tmp).pqc_status | Should -BeExactly 'hybrid'
        Remove-BoabSystem -SystemId $sys.id -Workspace $tmp -Confirm:$false
        @(Get-BoabSystem -Workspace $tmp).Count | Should -Be 0
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}
