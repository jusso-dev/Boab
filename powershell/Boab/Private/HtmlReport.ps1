# HTML readiness report. Port of src/report/html.rs: one self-contained file with
# inline CSS, an inline SVG logo, no scripts and no external requests. The output
# must match the Rust writer byte for byte, so all numbers use integer arithmetic
# or the shared f32 helpers.

$script:BoabReportThemePath = Join-Path (Split-Path -Parent $PSScriptRoot) (Join-Path 'Data' 'report-theme.css')
$script:BoabHtmlTopAssets = 25
$script:BoabHtmlStatusOrder = @('vulnerable', 'unknown', 'hybrid', 'resistant', 'symmetric_ok')
$script:BoabHtmlMilestones = @(
    @{ Year = 2026; Title = 'Refined transition plan'; Desc = 'Have a refined PQC transition plan in place by the end of 2026.' }
    @{ Year = 2028; Title = 'Implementation begins'; Desc = 'Begin migrating priority systems to post-quantum cryptography.' }
    @{ Year = 2030; Title = 'Implementation complete'; Desc = 'Retire quantum-vulnerable cryptography across the estate.' }
)
$script:BoabHtmlLogo = '<svg class="logo" viewBox="0 0 48 48" aria-hidden="true"><path fill="currentColor" d="M17 46c-4.5-8.5-4-17 1.5-23h11c5.5 6 6 14.5 1.5 23z"/><path fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" d="M20 24c-2.5-5-7-7.5-12-8.5M22.5 23c-.5-6-1-10.5-3.5-15M25.5 23c1-6 3-10 6.5-13.5M28 24c3-4.5 7.5-6.5 12-6.5"/><circle class="leaf" cx="7" cy="15" r="3"/><circle class="leaf" cx="18.5" cy="7" r="3"/><circle class="leaf" cx="32.5" cy="9" r="3"/><circle class="leaf" cx="41" cy="17.5" r="3"/></svg>'
$script:BoabMonthNames = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')

function ConvertTo-BoabHtmlEscaped {
    # Escape text for HTML element content and double-quoted attributes.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Format-BoabGrouped {
    # Thousands separators, for example 12,345.
    param([long]$Value)
    $Value.ToString('#,0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Format-BoabPercentTenths {
    # count * 100 / total rounded half up to one decimal, in integer arithmetic.
    param([long]$Count, [long]$Total)
    if ($Total -eq 0) { return '0.0' }
    $perMille = [long][System.Math]::Floor([decimal]($Count * 2000 + $Total) / [decimal](2 * $Total))
    '{0}.{1}' -f [long][System.Math]::Floor($perMille / 10), ($perMille % 10)
}

function Format-BoabCountNoun {
    param([long]$Count, [string]$One, [string]$Many)
    '{0} {1}' -f (Format-BoabGrouped $Count), $(if ($Count -eq 1) { $One } else { $Many })
}

function Join-BoabWithAnd {
    param([string[]]$Items)
    if ($Items.Count -eq 0) { return '' }
    if ($Items.Count -eq 1) { return $Items[0] }
    '{0} and {1}' -f ($Items[0..($Items.Count - 2)] -join ', '), $Items[-1]
}

function Get-BoabHtmlStatusLabel {
    param([string]$Status)
    switch -CaseSensitive ($Status) {
        'vulnerable' { return 'Quantum-vulnerable' }
        'unknown' { return 'Unknown' }
        'hybrid' { return 'PQ/T hybrid' }
        'resistant' { return 'Quantum-resistant' }
        'symmetric_ok' { return 'Symmetric (adequate)' }
    }
    $Status
}

function Get-BoabHtmlTierLabel {
    param([int]$Tier)
    switch ($Tier) {
        1 { return 'Tier 1: by 2028' }
        2 { return 'Tier 2: 2028 window' }
        3 { return 'Tier 3: 2029 to 2030' }
    }
    'Tier 4: monitor'
}

function Get-BoabHtmlAssetTypeLabel {
    param([string]$AssetType)
    switch -CaseSensitive ($AssetType) {
        'algorithm' { return 'Algorithm' }
        'certificate' { return 'Certificate' }
        'key' { return 'Key' }
        'protocol_endpoint' { return 'TLS endpoint' }
        'library_dependency' { return 'Library' }
    }
    $AssetType
}

function Get-BoabHtmlClassificationLabel {
    param([string]$Classification)
    switch -CaseSensitive ($Classification) {
        'unofficial' { return 'UNOFFICIAL' }
        'official' { return 'OFFICIAL' }
        'official_sensitive' { return 'OFFICIAL: Sensitive' }
        'protected' { return 'PROTECTED' }
        'secret' { return 'SECRET' }
        'top_secret' { return 'TOP SECRET' }
    }
    $Classification
}

function Get-BoabHtmlCriticalityLabel {
    param([string]$Criticality)
    switch -CaseSensitive ($Criticality) {
        'low' { return 'Low' }
        'standard' { return 'Standard' }
        'essential' { return 'Essential' }
        'mission_critical' { return 'Mission critical' }
    }
    $Criticality
}

function Get-BoabProtectiveMarking {
    # Highest classification of the systems in scope, or $null without systems.
    param($Systems)
    $order = @('unofficial', 'official', 'official_sensitive', 'protected', 'secret', 'top_secret')
    $best = -1
    foreach ($s in $Systems) {
        $rank = [array]::IndexOf($order, [string]$s.classification)
        if ($rank -gt $best) { $best = $rank }
    }
    if ($best -lt 0) { return $null }
    Get-BoabHtmlClassificationLabel $order[$best]
}

function Format-BoabHumanTimestamp {
    # For example "5 March 2026, 07:04 UTC".
    param([DateTimeOffset]$Value)
    $utc = $Value.UtcDateTime
    '{0} {1} {2}, {3:00}:{4:00} UTC' -f $utc.Day, $script:BoabMonthNames[$utc.Month - 1], $utc.Year, $utc.Hour, $utc.Minute
}

function Get-BoabHtmlPill {
    param([string]$Class, [string]$Label)
    '<span class="pill"><span class="swatch {0}"></span>{1}</span>' -f $Class, $Label
}

function Get-BoabHtmlSourceLink {
    param($Url)   # untyped: a [string] parameter would turn $null into ''
    if ($null -eq $Url) { return '-' }
    $Url = [string]$Url
    if ($Url.StartsWith('https://', [System.StringComparison]::Ordinal) -or $Url.StartsWith('http://', [System.StringComparison]::Ordinal)) {
        return ('<a href="{0}" rel="noopener noreferrer">Vendor statement</a>' -f (ConvertTo-BoabHtmlEscaped $Url))
    }
    ConvertTo-BoabHtmlEscaped $Url
}

function Test-BoabAtRisk {
    param([string]$Status)
    $Status -ceq 'vulnerable' -or $Status -ceq 'unknown'
}

function New-BoabHtmlReport {
    # report::html::write (content only).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $data = Get-BoabReadinessData -Workspace $Workspace
    $scored = $data.Scored
    $systems = $data.Systems
    $plans = $data.Plans
    $registry = $data.Registry
    $now = $data.Now
    $version = $script:BoabVersion

    $total = $scored.Count
    $vulnerable = Get-BoabReadinessVulnerableCount -Data $data
    $pctText = Format-BoabPercentTenths -Count $vulnerable -Total $total
    $tiers = @(0, 0, 0, 0)
    foreach ($e in $scored) {
        $t = [int]$e.Score.triage_tier
        if ($t -ge 1 -and $t -le 4) { $tiers[$t - 1]++ }
    }
    $statusCounts = @{}
    foreach ($st in $script:BoabHtmlStatusOrder) { $statusCounts[$st] = 0 }
    foreach ($e in $scored) { $k = [string]$e.Asset.pqc_status; if ($statusCounts.ContainsKey($k)) { $statusCounts[$k]++ } }
    $soci = 0
    foreach ($s in $systems) { if ($s.is_soci) { $soci++ } }
    $covered = 0
    foreach ($m in $script:BoabHtmlMilestones) { if (Test-BoabReadinessPlan -Data $data -Year $m.Year) { $covered++ } }
    $vendorUnknown = 0
    foreach ($e in $registry.entries) { if ($e.pqc_status -ceq 'unknown') { $vendorUnknown++ } }
    $rfc3339 = Format-BoabRfc3339 -Value $now.ToUniversalTime()
    $human = Format-BoabHumanTimestamp -Value $now
    $marking = Get-BoabProtectiveMarking -Systems $systems

    $h = [System.Text.StringBuilder]::new()
    $add = { param([string]$s) [void]$h.Append($s) }
    $line = { param([string]$s) [void]$h.Append($s).Append("`n") }

    & $add "<!DOCTYPE html>`n<html lang=`"en-AU`">`n<head>`n<meta charset=`"utf-8`">`n"
    & $add "<meta name=`"viewport`" content=`"width=device-width, initial-scale=1`">`n"
    & $add "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; style-src 'unsafe-inline'; img-src data:`">`n"
    & $line ('<meta name="generator" content="Boab {0}">' -f $version)
    & $add "<title>PQC Readiness Report | Boab</title>`n<style>`n"
    & $add ([System.IO.File]::ReadAllText($script:BoabReportThemePath))
    & $add "</style>`n"
    if ($null -ne $marking) {
        & $line ('<style>@media print {{ @page {{ @top-center {{ content: "{0}"; }} @bottom-center {{ content: "{0}"; }} }} }}</style>' -f $marking)
    }
    & $add "</head>`n<body>`n"
    if ($null -ne $marking) { & $line ('<div class="marking">{0}</div>' -f $marking) }

    # Masthead.
    & $add "<header class=`"masthead`">`n<div class=`"page`">`n"
    & $line $script:BoabHtmlLogo
    & $add "<div>`n<p class=`"eyebrow`">Post-quantum cryptography transition</p>`n"
    & $add "<h1>PQC Readiness Report</h1>`n"
    & $line ('<p class="meta"><span>Generated <time datetime="{0}">{1}</time></span><span>Boab {2}</span><span>ASD milestones 2026, 2028, 2030</span></p>' -f $rfc3339, $human, $version)
    & $add "</div>`n</div>`n</header>`n<main class=`"page`">`n"

    # Overall posture and key findings.
    if ($total -eq 0) {
        $postureClass = 'neutral'; $posture = 'Not yet assessed'
        $detail = 'No cryptographic assets are in the inventory yet. Run the codebase, TLS and certificate scanners to build it.'
    }
    elseif ($tiers[0] -gt 0) {
        $postureClass = 'critical'; $posture = 'Action required'
        $detail = '{0} must be migrated inside the 2028 milestone window.' -f (Format-BoabCountNoun $tiers[0] 'asset' 'assets')
    }
    elseif ($vulnerable -gt 0) {
        $postureClass = 'serious'; $posture = 'At risk'
        $detail = '{0} of {1} assets rely on cryptography a quantum computer is expected to break, or have an unknown status.' -f (Format-BoabGrouped $vulnerable), (Format-BoabGrouped $total)
    }
    else {
        $postureClass = 'good'; $posture = 'No exposure found'
        $detail = 'No quantum-vulnerable cryptography was found in the assets inventoried so far. Keep scan coverage and transition plans current.'
    }
    & $add "<section aria-labelledby=`"summary`">`n"
    & $add "<h2 id=`"summary`">Executive summary</h2>`n"
    & $add "<p class=`"lede`">Position of the inventoried cryptography against the ASD post-quantum transition milestones.</p>`n"
    & $line ('<div class="card posture posture-{0}">' -f $postureClass)
    & $line ('<div class="posture-badge"><p class="label">Overall posture</p><p class="value">{0}</p><p class="detail">{1}</p></div>' -f $posture, (ConvertTo-BoabHtmlEscaped $detail))
    & $add "<div class=`"findings`">`n<h3>Key findings</h3>`n<ul>`n"
    $findings = New-BoabList
    if ($total -gt 0) {
        $findings.Add(('{0} of {1} cryptographic assets ({2}%) are quantum-vulnerable or have an unknown status.' -f (Format-BoabGrouped $vulnerable), (Format-BoabGrouped $total), $pctText))
        if ($tiers[0] + $tiers[1] -gt 0) {
            $findings.Add(('{0} in tier 1 and {1} in tier 2 need migration inside the 2028 milestone window.' -f (Format-BoabGrouped $tiers[0]), (Format-BoabGrouped $tiers[1])))
        }
        else {
            $findings.Add('No inventoried assets fall in tiers 1 or 2, so none must be migrated inside the 2028 window.')
        }
    }
    else {
        $findings.Add('The cryptographic inventory is empty.')
    }
    $missing = @($script:BoabHtmlMilestones | Where-Object { -not (Test-BoabReadinessPlan -Data $data -Year $_.Year) } | ForEach-Object { [string]$_.Year })
    if ($missing.Count -eq 0) {
        $findings.Add('Transition plans are on file for all three ASD milestones.')
    }
    else {
        $findings.Add(('No transition plan is on file for the {0} {1}.' -f (Join-BoabWithAnd $missing), $(if ($missing.Count -eq 1) { 'milestone' } else { 'milestones' })))
    }
    $vendorCount = @($registry.entries).Count
    if ($vendorCount -gt 0) {
        $findings.Add(('{0} of {1} tracked vendor products have not published a post-quantum position.' -f (Format-BoabGrouped $vendorUnknown), (Format-BoabGrouped $vendorCount)))
    }
    if ($soci -gt 0) {
        $findings.Add(('{0} in scope {1} regulated under the SOCI Act.' -f (Format-BoabCountNoun $soci 'system' 'systems'), $(if ($soci -eq 1) { 'is' } else { 'are' })))
    }
    foreach ($f in $findings) { & $line ('<li>{0}</li>' -f (ConvertTo-BoabHtmlEscaped $f)) }
    & $add "</ul>`n</div>`n</div>`n"

    # Headline numbers.
    $kpi = {
        param([string]$Class, [string]$Label, [string]$Value, [string]$Sub)
        & $line ('<div class="kpi{0}"><p class="label">{1}</p><p class="value">{2}</p><p class="sub">{3}</p></div>' -f $Class, $Label, $Value, $Sub)
    }
    & $add "<div class=`"kpis`">`n"
    & $kpi '' 'Cryptographic assets' (Format-BoabGrouped $total) 'Deduplicated inventory'
    & $kpi $(if ($vulnerable -gt 0) { ' kpi-critical' } else { ' kpi-good' }) 'At-risk assets' (Format-BoabGrouped $vulnerable) ('{0}% vulnerable or unknown' -f $pctText)
    & $kpi $(if ($tiers[0] -gt 0) { ' kpi-critical' } else { ' kpi-good' }) 'Tier 1 (urgent)' (Format-BoabGrouped $tiers[0]) 'Migrate inside the 2028 window'
    & $kpi '' 'Systems in scope' (Format-BoabGrouped $systems.Count) ('{0} SOCI-regulated' -f (Format-BoabGrouped $soci))
    & $kpi $(if ($covered -eq 3) { ' kpi-good' } else { ' kpi-serious' }) 'Transition plans' (Format-BoabGrouped $plans.Count) ('{0} of 3 milestones covered' -f $covered)
    & $add "</div>`n</section>`n"

    # ASD milestones.
    & $add "<section aria-labelledby=`"milestones`">`n"
    & $add "<h2 id=`"milestones`">ASD transition milestones</h2>`n"
    & $add "<p class=`"lede`">Whether a Boab transition plan is on file for each milestone.</p>`n"
    & $add "<div class=`"card timeline`">`n"
    foreach ($m in $script:BoabHtmlMilestones) {
        $done = Test-BoabReadinessPlan -Data $data -Year $m.Year
        $pill = if ($done) { Get-BoabHtmlPill 's-resistant' 'Plan drafted' } else { Get-BoabHtmlPill 's-unknown' 'Plan outstanding' }
        & $line ('<div class="milestone {0}"><p class="year">{1}</p><p class="title">{2}</p><p class="desc">{3}</p>{4}</div>' -f $(if ($done) { 'done' } else { 'open' }), $m.Year, $m.Title, $m.Desc, $pill)
    }
    & $add "</div>`n</section>`n"

    # Distributions.
    $barRow = {
        param([string]$Class, [string]$Label, [long]$Count)
        $pct = Format-BoabPercentTenths -Count $Count -Total $total
        $g = Format-BoabGrouped $Count
        & $line ('<div class="bar-row" title="{0}: {1} ({2}%)"><span class="bar-label"><span class="swatch {3}"></span>{0}</span><div class="bar-track"><div class="bar-fill {3}{4}" style="width:{2}%"></div></div><span class="bar-value"><strong>{1}</strong> ({2}%)</span></div>' -f $Label, $g, $pct, $Class, $(if ($Count -gt 0) { ' nonzero' } else { '' }))
    }
    & $add "<section aria-labelledby=`"distribution`">`n"
    & $add "<h2 id=`"distribution`">Where the exposure sits</h2>`n"
    & $add "<p class=`"lede`">Inventory broken down by post-quantum status and by triage tier.</p>`n"
    & $add "<div class=`"charts`">`n<div class=`"card chart`">`n<h3>Assets by PQC status</h3>`n"
    foreach ($st in $script:BoabHtmlStatusOrder) { & $barRow ('s-' + $st) (Get-BoabHtmlStatusLabel $st) $statusCounts[$st] }
    & $add "</div>`n<div class=`"card chart`">`n<h3>Assets by triage tier</h3>`n"
    for ($i = 0; $i -lt 4; $i++) { & $barRow ('t-{0}' -f ($i + 1)) (Get-BoabHtmlTierLabel ($i + 1)) $tiers[$i] }
    & $add "</div>`n</div>`n</section>`n"

    # Priority assets.
    & $add "<section aria-labelledby=`"priority`">`n"
    & $add "<h2 id=`"priority`">Highest-priority assets</h2>`n"
    & $add "<p class=`"lede`">Ranked by the Boab priority score (0 to 10). Start migration work at the top of this list.</p>`n"
    if ($total -eq 0) {
        & $add "<div class=`"card`"><p class=`"empty`">No assets in the inventory yet.</p></div>`n"
    }
    else {
        & $add "<div class=`"card table-card`">`n<table>`n<thead><tr><th class=`"num`">#</th><th>Asset</th><th>Algorithm</th><th>PQC status</th><th>Priority</th><th>Tier</th><th>Recommended action</th></tr></thead>`n<tbody>`n"
        $n = [math]::Min($script:BoabHtmlTopAssets, $total)
        for ($i = 0; $i -lt $n; $i++) {
            $asset = $scored[$i].Asset; $score = $scored[$i].Score
            $tenths = [long][math]::Round((ConvertTo-BoabF32 ([double][single]$score.priority * 10.0)), [System.MidpointRounding]::AwayFromZero)
            $tenths = [math]::Max(0, [math]::Min(100, $tenths))
            & $line ('<tr><td class="num">{0}</td><td class="name">{1}<span class="kind">{2}</span></td><td class="algo"><code>{3}</code></td><td>{4}</td><td><div class="score"><div class="bar-track"><div class="bar-fill" style="width:{5}%"></div></div><b>{6}</b></div></td><td><span class="tier t-{7}">{7}</span></td><td>{8}</td></tr>' -f
                ($i + 1),
                (ConvertTo-BoabHtmlEscaped $asset.name),
                (Get-BoabHtmlAssetTypeLabel $asset.asset_type),
                (ConvertTo-BoabHtmlEscaped $asset.algorithm_name),
                (Get-BoabHtmlPill ('s-' + $asset.pqc_status) (Get-BoabHtmlStatusLabel $asset.pqc_status)),
                $tenths,
                (Format-BoabFixed -Value ([double]$score.priority) -Decimals 1),
                $score.triage_tier,
                (ConvertTo-BoabHtmlEscaped $score.recommended_action))
        }
        & $add "</tbody>`n</table>`n</div>`n"
        if ($total -gt $script:BoabHtmlTopAssets) {
            & $line ('<p class="note">Showing the top {0} of {1} assets. The full inventory is in the JSON and CycloneDX reports.</p>' -f $script:BoabHtmlTopAssets, (Format-BoabGrouped $total))
        }
    }
    & $add "</section>`n"

    # Systems.
    & $add "<section aria-labelledby=`"systems`">`n"
    & $add "<h2 id=`"systems`">Systems in scope</h2>`n"
    & $add "<p class=`"lede`">Business systems registered in the workspace and the cryptographic assets linked to each.</p>`n"
    $unassigned = 0; $unassignedRisk = 0
    foreach ($e in $scored) {
        if ($null -eq (Find-BoabSystemById -Systems $systems -Id $e.Asset.system_id)) {
            $unassigned++
            if (Test-BoabAtRisk $e.Asset.pqc_status) { $unassignedRisk++ }
        }
    }
    if ($systems.Count -eq 0 -and $unassigned -eq 0) {
        & $add "<div class=`"card`"><p class=`"empty`">No systems registered yet.</p></div>`n"
    }
    else {
        & $add "<div class=`"card table-card`">`n<table>`n<thead><tr><th>System</th><th>Classification</th><th>Criticality</th><th>SOCI</th><th class=`"num`">Data lifetime</th><th class=`"num`">Assets</th><th class=`"num`">At risk</th></tr></thead>`n<tbody>`n"
        foreach ($s in $systems) {
            $linked = 0; $risk = 0
            foreach ($e in $scored) {
                if ($null -ne $e.Asset.system_id -and $e.Asset.system_id -ceq $s.id) {
                    $linked++
                    if (Test-BoabAtRisk $e.Asset.pqc_status) { $risk++ }
                }
            }
            $lifetime = if ($null -ne $s.expected_data_lifetime_years) { '{0} years' -f $s.expected_data_lifetime_years } else { '-' }
            & $line ('<tr><td class="name">{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="num">{4}</td><td class="num">{5}</td><td class="num">{6}</td></tr>' -f
                (ConvertTo-BoabHtmlEscaped $s.name),
                (Get-BoabHtmlClassificationLabel $s.classification),
                (Get-BoabHtmlCriticalityLabel $s.criticality),
                $(if ($s.is_soci) { 'Yes' } else { 'No' }),
                $lifetime,
                (Format-BoabGrouped $linked),
                (Format-BoabGrouped $risk))
        }
        if ($unassigned -gt 0) {
            & $line ('<tr><td class="name">Not linked to a system</td><td>-</td><td>-</td><td>-</td><td class="num">-</td><td class="num">{0}</td><td class="num">{1}</td></tr>' -f (Format-BoabGrouped $unassigned), (Format-BoabGrouped $unassignedRisk))
        }
        & $add "</tbody>`n</table>`n</div>`n"
    }
    & $add "</section>`n"

    # Plans.
    & $add "<section aria-labelledby=`"plans`">`n"
    & $add "<h2 id=`"plans`">Transition plans on file</h2>`n"
    & $add "<p class=`"lede`">Transition plans generated by Boab and progress against each.</p>`n"
    if ($plans.Count -eq 0) {
        & $add "<div class=`"card`"><p class=`"empty`">No plans generated yet.</p></div>`n"
    }
    else {
        & $add "<div class=`"card table-card`">`n<table>`n<thead><tr><th>Plan</th><th class=`"num`">Milestone</th><th class=`"num`">Items</th><th>Progress</th><th>Generated</th></tr></thead>`n<tbody>`n"
        foreach ($p in $plans) {
            $items = @($p.items).Count
            $complete = 0
            foreach ($it in $p.items) { if ($it.status -ceq 'complete') { $complete++ } }
            $generated = [string]$p.generated_at
            $day = if ($generated.Length -ge 10) { $generated.Substring(0, 10) } else { '' }
            & $line ('<tr><td class="name">{0}</td><td class="num">{1}</td><td class="num">{2}</td><td><div class="progress"><div class="bar-track"><div class="bar-fill" style="width:{3}%"></div></div><span>{4} of {2} complete</span></div></td><td><time datetime="{5}">{6}</time></td></tr>' -f
                (ConvertTo-BoabHtmlEscaped $p.name),
                (Get-BoabMilestoneYear $p.milestone),
                (Format-BoabGrouped $items),
                (Format-BoabPercentTenths -Count $complete -Total $items),
                (Format-BoabGrouped $complete),
                $generated,
                $day)
        }
        & $add "</tbody>`n</table>`n</div>`n"
    }
    & $add "</section>`n"

    # Vendors.
    & $add "<section aria-labelledby=`"vendors`">`n"
    & $add "<h2 id=`"vendors`">Vendor PQC dependencies</h2>`n"
    & $add "<p class=`"lede`">Published post-quantum positions of the vendors tracked in the Boab registry, including workspace overrides.</p>`n"
    if ($vendorCount -eq 0) {
        & $add "<div class=`"card`"><p class=`"empty`">No vendors tracked.</p></div>`n"
    }
    else {
        & $add "<div class=`"card table-card`">`n<table>`n<thead><tr><th>Vendor</th><th>Product</th><th>PQC status</th><th>Target</th><th>Source</th></tr></thead>`n<tbody>`n"
        foreach ($e in $registry.entries) {
            $target = if ($null -ne $e.target_date) { $e.target_date } else { '-' }
            & $line ('<tr><td class="name">{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f
                (ConvertTo-BoabHtmlEscaped $e.vendor),
                (ConvertTo-BoabHtmlEscaped $e.product),
                (Get-BoabHtmlPill ('s-' + $e.pqc_status) (Get-BoabHtmlStatusLabel $e.pqc_status)),
                (ConvertTo-BoabHtmlEscaped $target),
                (Get-BoabHtmlSourceLink $e.source_url))
        }
        & $add "</tbody>`n</table>`n</div>`n"
    }
    & $add "</section>`n"

    # Methodology.
    & $add "<section aria-labelledby=`"method`">`n"
    & $add "<h2 id=`"method`">Methodology</h2>`n"
    & $add "<div class=`"card method`">`n"
    & $add "<p>Boab inventories cryptography in source code, TLS endpoints and certificate stores, deduplicates the findings and scores each asset on five axes aligned to the ASD LATICE approach.</p>`n"
    & $add "<p><code class=`"formula`">priority = round(algo_vuln &times; 0.30 + hndl &times; 0.30 + data_sens &times; 0.15 + sys_crit &times; 0.15 + mig_diff &times; 0.10, 1)</code></p>`n"
    & $add "<p><strong>Tier 1</strong> assets must be migrated inside the 2028 milestone window. <strong>Tier 2</strong> fits inside the 2028 milestone but is harder to migrate. <strong>Tier 3</strong> belongs in the 2029 to 2030 rollout window. <strong>Tier 4</strong> needs monitoring only.</p>`n"
    & $add "<p><strong>At-risk</strong> assets use algorithms a cryptographically relevant quantum computer is expected to break (RSA, ECDSA, ECDH, classic Diffie-Hellman, and broken legacy primitives), or have a status Boab could not determine. Data protected by them today can be harvested now and decrypted later.</p>`n"
    & $add "<p>Refer to the ASD Information Security Manual for control mappings. Boab does not map findings to specific ISM control IDs.</p>`n"
    & $add "</div>`n</section>`n"

    & $line ('<footer><p>Generated by Boab {0} at {1}. This report is self-contained and makes no network requests.</p><p>The protective marking shown is the highest classification of the systems in scope. Confirm it before release.</p></footer>' -f $version, $rfc3339)
    & $add "</main>`n"
    if ($null -ne $marking) { & $line ('<div class="marking">{0}</div>' -f $marking) }
    & $add "</body>`n</html>`n"
    $h.ToString()
}

function Export-BoabHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Path)
    $text = New-BoabHtmlReport -Workspace $Workspace
    Write-BoabReportFile -Path $Path -Content $text
}
