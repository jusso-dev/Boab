# HTML readiness report: a single self-contained page for executives and boards.
# Port of src/report/html.rs - the output must stay byte-for-byte identical, so
# keep the two in step. Output is ASCII apart from user data: typographic
# characters are written as HTML entities.

$script:BoabHtmlTopAssets = 10

# sha256 of $script:BoabHtmlPrintScript, allowed by the page's Content-Security-Policy.
$script:BoabHtmlPrintScriptHash = 'sha256-8U7RJlWgu7WepxDnJbVVXadHk7k8MSogCSxej3/N0oo='

# Appendices are written expanded so they still print without JavaScript; on
# screen this collapses them, and expands them again for printing or PDF.
$script:BoabHtmlPrintScript = 'document.querySelectorAll(''details[data-collapse]'').forEach(function(d){d.open=false;});window.addEventListener(''beforeprint'',function(){document.querySelectorAll(''details'').forEach(function(d){d.open=true;});});'

$script:BoabHtmlMonths = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')

# Status order used by the exposure bar, legend and inventory counts.
$script:BoabHtmlStatusOrder = @('vulnerable', 'unknown', 'hybrid', 'resistant', 'symmetric_ok')

$script:BoabHtmlLogo = '<svg class="logo" viewBox="0 0 32 36" width="30" height="34" aria-hidden="true"><path d="M16 1L30 6V17C30 26 24 32 16 35C8 32 2 26 2 17V6Z" fill="#2a78d6"/><path d="M16 1L30 6V17C30 26 24 32 16 35Z" fill="#d9622b"/><path d="M14.4 29C14 24 13.6 20.5 12.2 17.6C10.2 16.8 8.4 15.4 7.6 13.4C9.8 13.8 11.8 14.8 13.3 15.8C13.3 13.4 12.4 11.4 11 9.8C13.4 10.8 15 12.8 16 15.2C17 12.8 18.6 10.8 21 9.8C19.6 11.4 18.7 13.4 18.7 15.8C20.2 14.8 22.2 13.8 24.4 13.4C23.6 15.4 21.8 16.8 19.8 17.6C18.4 20.5 18 24 17.6 29Z" fill="#ffffff"/></svg>'

$script:BoabHtmlCss = @'
:root{color-scheme:light;--page:#f3f4f6;--surface:#ffffff;--ink:#101b2b;--ink-2:#46505e;--muted:#6b7482;--line:#e2e5e9;--track:#edf0f3;--brand:#13233a;--brand-2:#1d3a5f;--accent:#d9622b;--critical:#d03b3b;--serious:#ec835a;--warning:#fab219;--good:#0ca30c;--neutral:#8a94a6;--hybrid:#2a78d6;--symmetric:#1c5cab}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0e1319;--surface:#161d26;--ink:#edf1f5;--ink-2:#b9c1cc;--muted:#8d96a3;--line:#2a333e;--track:#232c37;--hybrid:#3987e5;--symmetric:#5598e7}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:0 28px}
code{font:0.88em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
a{color:var(--hybrid)}
.masthead{background:linear-gradient(135deg,var(--brand) 0%,var(--brand-2) 100%);color:#ffffff;padding:28px 0 30px;border-bottom:4px solid var(--accent)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.logo{flex:none}
.brand-name{font-weight:700;font-size:20px;letter-spacing:0.02em}
.brand-tag{font-size:12px;text-transform:uppercase;letter-spacing:0.12em;color:#c8d3e1;border-left:1px solid #4a6283;padding-left:10px}
.masthead h1{margin:0 0 8px;font-size:30px;line-height:1.2;font-weight:700;letter-spacing:-0.01em}
.masthead .meta{margin:2px 0 0;color:#c8d3e1;font-size:14px}
main{padding:28px 0 8px}
.card,.hero,.kpi{background:var(--surface);border:1px solid var(--line);border-radius:12px}
.card{padding:22px 24px;margin:0 0 20px}
.card h2{margin:0 0 4px;font-size:18px;line-height:1.3}
.sub{margin:0 0 16px;color:var(--muted);font-size:13px}
.empty{color:var(--muted);font-style:italic;margin:4px 0}
.hero{display:flex;gap:28px;align-items:center;justify-content:space-between;padding:26px 28px;margin:0 0 20px;border-left:8px solid var(--tone)}
.tone-critical{--tone:var(--critical)}
.tone-serious{--tone:var(--serious)}
.tone-warning{--tone:var(--warning)}
.tone-good{--tone:var(--good)}
.tone-neutral{--tone:var(--neutral)}
.eyebrow{margin:0;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.1em;font-weight:600}
.posture{margin:4px 0 8px;font-size:26px;font-weight:700;display:flex;align-items:center;gap:10px}
.posture .pip{width:14px;height:14px;border-radius:50%;background:var(--tone);flex:none}
.headline{margin:0;color:var(--ink-2);max-width:660px}
.hero-figure{flex:none;text-align:right;max-width:230px}
.hero-figure .big{display:block;font-size:56px;line-height:1;font-weight:700}
.hero-figure .cap{display:block;margin-top:8px;color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:0 0 20px}
.kpi{padding:16px 18px;display:flex;flex-direction:column;gap:4px}
.kl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.06em;font-weight:600}
.kv{font-size:30px;font-weight:700;line-height:1.1}
.ks{color:var(--ink-2);font-size:13px}
.actions{margin:8px 0 0;padding-left:22px}
.actions li{margin:0 0 8px;padding-left:4px}
.actions li::marker{color:var(--accent);font-weight:700}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
.stack{display:flex;gap:2px;height:22px;border-radius:6px;overflow:hidden;margin:0 0 16px;background:var(--track)}
.seg{display:block;min-width:4px}
.s-vulnerable{background:var(--critical)}
.s-unknown{background:var(--warning)}
.s-hybrid{background:var(--hybrid)}
.s-resistant{background:var(--good)}
.s-symmetric{background:var(--symmetric)}
.legend,.bars,.chips,.milestones{list-style:none;margin:0;padding:0}
.legend li{display:grid;grid-template-columns:14px 1fr auto;column-gap:10px;align-items:center;padding:6px 0;border-top:1px solid var(--line)}
.legend li:first-child{border-top:0}
.key{display:inline-block;width:12px;height:12px;border-radius:3px}
.lk{font-weight:600}
.lv{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.ld{grid-column:2 / 4;color:var(--muted);font-size:12px}
.bars li{display:grid;grid-template-columns:150px 1fr 44px;gap:12px;align-items:center;padding:8px 0}
.bl{display:flex;flex-direction:column;line-height:1.25}
.bl span{color:var(--muted);font-size:12px}
.track{display:block;height:18px;background:var(--track);border-radius:4px}
.fill{display:block;height:100%;border-radius:0 4px 4px 0;min-width:2px}
.mf{display:block;height:100%;background:var(--good)}
.t-1{background:var(--critical)}
.t-2{background:var(--serious)}
.t-3{background:var(--warning)}
.t-4{background:var(--neutral)}
.bv{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.milestones{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.milestones li{border:1px solid var(--line);border-top:4px solid var(--brand-2);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:6px;align-items:flex-start}
.year{font-size:26px;font-weight:700;line-height:1}
.mt{font-weight:600}
.md{color:var(--ink-2);font-size:13px;flex:1}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 9px 2px 7px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;background:var(--surface)}
.badge .pip{width:8px;height:8px;border-radius:50%;flex:none}
.b-vulnerable .pip,.b-t1 .pip{background:var(--critical)}
.b-unknown .pip,.b-warning .pip,.b-t3 .pip{background:var(--warning)}
.b-hybrid .pip{background:var(--hybrid)}
.b-resistant .pip,.b-good .pip{background:var(--good)}
.b-symmetric .pip{background:var(--symmetric)}
.b-t2 .pip{background:var(--serious)}
.b-t4 .pip,.b-neutral .pip{background:var(--neutral)}
.tag{display:inline-block;margin-left:6px;padding:0 6px;border-radius:4px;background:var(--brand-2);color:#ffffff;font-size:11px;font-weight:700;letter-spacing:0.04em;vertical-align:1px}
.tag-broken{background:var(--critical)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:0.05em;font-weight:600;padding:8px 10px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums}
.an{display:block;font-weight:600;overflow-wrap:anywhere}
.aa{display:block;color:var(--muted);font-size:12px}
.score{display:inline-flex;align-items:center;gap:8px;font-weight:700;font-variant-numeric:tabular-nums}
.meter{display:inline-block;width:56px;height:6px;background:var(--track);border-radius:3px;overflow:hidden;vertical-align:middle}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px}
.chips li{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid var(--line);border-radius:8px}
details{margin-top:4px}
summary{cursor:pointer;font-weight:600;color:var(--hybrid);padding:4px 0;margin-bottom:8px}
.method p,.method dd{color:var(--ink-2)}
.method dl{margin:0 0 12px}
.method dt{font-weight:600;margin-top:8px}
.method dd{margin:2px 0 0}
.formula{background:var(--track);border-radius:8px;padding:10px 14px}
footer{color:var(--muted);font-size:12.5px;padding-top:4px;padding-bottom:36px}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2,.milestones{grid-template-columns:1fr}.hero{flex-direction:column;align-items:flex-start}.hero-figure{text-align:left;max-width:none}}
@media print{:root{color-scheme:light;--page:#ffffff;--surface:#ffffff;--ink:#101b2b;--ink-2:#46505e;--muted:#5d6672;--line:#d9dde2;--track:#edf0f3;--hybrid:#2a78d6;--symmetric:#1c5cab}@page{size:A4;margin:14mm}body{font-size:12px;-webkit-print-color-adjust:exact;print-color-adjust:exact}.wrap{max-width:none;padding:0}.masthead{padding:18px 20px}main{padding-top:16px}.hero,.kpi,.grid2 .card,.milestones li,tr{break-inside:avoid}h2,.sub{break-after:avoid}.hero{flex-direction:row;align-items:center}.hero-figure{text-align:right;max-width:200px}.hero-figure .big{font-size:44px}.kv{font-size:24px}table{font-size:11px}th{font-size:9.5px}.badge{font-size:10px;white-space:normal}.assets{table-layout:fixed}.assets .an{overflow-wrap:break-word}.c-n{width:4%}.c-a{width:25%}.c-s{width:11%}.c-st{width:14%}.c-p{width:12%}.c-t{width:10%}.c-r{width:24%}.assets .meter{width:28px}.assets .score{gap:5px}.b-t1,.b-t2,.b-t3,.b-t4{white-space:nowrap}.kpis{grid-template-columns:repeat(5,minmax(0,1fr))}.grid2{grid-template-columns:repeat(2,minmax(0,1fr))}.milestones{grid-template-columns:repeat(3,minmax(0,1fr))}summary{display:none}.tw{overflow:visible}}
'@ + "`n"

function ConvertTo-BoabHtmlEscaped {
    # Escape text for HTML element content and quoted attribute values.
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Format-BoabHtmlGroup {
    # 1234567 -> 1,234,567
    [OutputType([string])]
    param([long]$Value)
    $digits = $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $digits.Length; $i++) {
        if ($i -gt 0 -and (($digits.Length - $i) % 3) -eq 0) { [void]$sb.Append(',') }
        [void]$sb.Append($digits[$i])
    }
    $sb.ToString()
}

function Format-BoabHtmlPlural {
    [OutputType([string])]
    param([long]$Count, [string]$One, [string]$Many)
    '{0} {1}' -f (Format-BoabHtmlGroup $Count), $(if ($Count -eq 1) { $One } else { $Many })
}

function Format-BoabHtmlDate {
    # "2026-10-04..." -> "4 October 2026"
    [OutputType([string])]
    param([int]$Year, [int]$Month, [int]$Day)
    '{0} {1} {2}' -f $Day, $script:BoabHtmlMonths[$Month - 1], $Year
}

function Format-BoabHtmlStoredDate {
    # Date part of a stored RFC 3339 timestamp, in the timestamp's own offset.
    [OutputType([string])]
    param([string]$Timestamp)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    Format-BoabHtmlDate -Year ([int]::Parse($Timestamp.Substring(0, 4), $inv)) -Month ([int]::Parse($Timestamp.Substring(5, 2), $inv)) -Day ([int]::Parse($Timestamp.Substring(8, 2), $inv))
}

function Test-BoabHtmlWebUrl {
    param([string]$Url)
    $lower = ConvertTo-BoabAsciiLower $Url
    $lower.StartsWith('https://', [System.StringComparison]::Ordinal) -or $lower.StartsWith('http://', [System.StringComparison]::Ordinal)
}

function Get-BoabHtmlStatusIndex {
    param([string]$Status)
    switch -CaseSensitive ($Status) {
        'vulnerable' { return 0 }
        'unknown' { return 1 }
        'hybrid' { return 2 }
        'resistant' { return 3 }
        'symmetric_ok' { return 4 }
    }
    1
}

function Get-BoabHtmlStatusKey {
    param([string]$Status)
    switch -CaseSensitive ($Status) {
        'vulnerable' { return 'vulnerable' }
        'unknown' { return 'unknown' }
        'hybrid' { return 'hybrid' }
        'resistant' { return 'resistant' }
        'symmetric_ok' { return 'symmetric' }
    }
    'unknown'
}

function Get-BoabHtmlStatusLabel {
    param([string]$Status)
    switch -CaseSensitive ($Status) {
        'vulnerable' { return 'Vulnerable' }
        'unknown' { return 'Unknown' }
        'hybrid' { return 'Hybrid PQ/T' }
        'resistant' { return 'Quantum-resistant' }
        'symmetric_ok' { return 'Symmetric OK' }
    }
    'Unknown'
}

function Get-BoabHtmlStatusBlurb {
    param([string]$Status)
    switch -CaseSensitive ($Status) {
        'vulnerable' { return 'Breakable by a quantum computer' }
        'unknown' { return 'Not yet classified' }
        'hybrid' { return 'Classical plus post-quantum' }
        'resistant' { return 'NIST post-quantum standard' }
        'symmetric_ok' { return 'Strong symmetric or hash' }
    }
    'Not yet classified'
}

function Get-BoabHtmlTierBlurb {
    param([int]$Tier)
    switch ($Tier) {
        1 { return 'Migrate before 2028' }
        2 { return 'Inside the 2028 window' }
        3 { return 'Replace 2029&ndash;2030' }
    }
    'Monitor'
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
    [string]$AssetType
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
    [string]$Classification
}

function Get-BoabHtmlCriticalityLabel {
    param([string]$Criticality)
    switch -CaseSensitive ($Criticality) {
        'low' { return 'Low' }
        'standard' { return 'Standard' }
        'essential' { return 'Essential' }
        'mission_critical' { return 'Mission critical' }
    }
    [string]$Criticality
}

function Get-BoabHtmlBadge {
    param([string]$Class, [string]$Label)
    '<span class="badge b-' + $Class + '"><span class="pip" aria-hidden="true"></span>' + $Label + '</span>'
}

function Get-BoabHtmlStatusBadge {
    param([string]$Status)
    Get-BoabHtmlBadge -Class (Get-BoabHtmlStatusKey $Status) -Label (Get-BoabHtmlStatusLabel $Status)
}

function Get-BoabHtmlTierBadge {
    param([int]$Tier)
    Get-BoabHtmlBadge -Class ('t{0}' -f $Tier) -Label ('Tier {0}' -f $Tier)
}

function Add-BoabHtmlKpi {
    param([System.Text.StringBuilder]$Sb, [string]$Label, [string]$Value, [string]$Sub)
    [void]$Sb.Append('<div class="kpi"><span class="kl">' + $Label + '</span><span class="kv">' + $Value + '</span><span class="ks">' + $Sub + "</span></div>`n")
}

function Add-BoabHtmlAssetTable {
    param([System.Text.StringBuilder]$Sb, [AllowEmptyCollection()]$Rows, $Systems, [string]$Empty)
    [void]$Sb.Append("<div class=`"tw`"><table class=`"assets`">`n<colgroup><col class=`"c-n`"><col class=`"c-a`"><col class=`"c-s`"><col class=`"c-st`"><col class=`"c-p`"><col class=`"c-t`"><col class=`"c-r`"></colgroup>`n<thead><tr><th class=`"num`">#</th><th>Asset</th><th>System</th><th>Status</th><th>Priority</th><th>Tier</th><th>Recommended action</th></tr></thead>`n<tbody>`n")
    $n = 0
    foreach ($row in $Rows) {
        $n++
        $asset = $row.Asset; $score = $row.Score
        $p = Format-BoabFixed -Value ([double]$score.priority) -Decimals 1
        $sys = Find-BoabSystemById -Systems $Systems -Id $asset.system_id
        $sysName = if ($null -ne $sys) { ConvertTo-BoabHtmlEscaped $sys.name } else { '&ndash;' }
        $display = Get-BoabHtmlDisplayName $asset.name
        $broken = [int]$score.algorithm_vulnerability -ge 10
        $brokenTag = if ($broken) { ' <span class="tag tag-broken">Broken today</span>' } else { '' }
        $subject = if ($null -ne $display.Subject) { ' &middot; ' + (ConvertTo-BoabHtmlEscaped $display.Subject) } else { '' }
        $action = if ($broken) { 'Replace now: already weak against conventional (non-quantum) attacks' } else { ConvertTo-BoabHtmlEscaped $score.recommended_action }
        [void]$Sb.Append('<tr><td class="num">' + $n + '</td><td><span class="an" title="' + (ConvertTo-BoabHtmlEscaped $asset.name) + '">' + (ConvertTo-BoabHtmlEscaped $display.Short) + $brokenTag +
            '</span><span class="aa">' + (Get-BoabHtmlAssetTypeLabel $asset.asset_type) + ' &middot; <code>' + (ConvertTo-BoabHtmlEscaped $asset.algorithm_name) +
            '</code>' + $subject + '</span></td><td>' + $sysName + '</td><td>' + (Get-BoabHtmlStatusBadge $asset.pqc_status) +
            '</td><td><span class="score"><span class="meter"><span class="mf t-' + $score.triage_tier + '" style="width:' + [int]::Parse($p.Replace('.', ''), [System.Globalization.CultureInfo]::InvariantCulture) +
            '%"></span></span>' + $p + '</span></td><td>' + (Get-BoabHtmlTierBadge $score.triage_tier) + '</td><td>' + $action + "</td></tr>`n")
    }
    if ($n -eq 0) {
        [void]$Sb.Append('<tr><td colspan="7" class="empty">' + $Empty + "</td></tr>`n")
    }
    [void]$Sb.Append("</tbody>`n</table></div>`n")
}

function Get-BoabHtmlDisplayName {
    # Scanner asset names often join a location and a subject, e.g.
    # "/abs/path/cert.pem|CN=example". Returns the part to headline (the file
    # name for absolute paths) and the subject, if any.
    param([string]$Name)
    $head = $Name; $subject = $null
    $bar = $Name.IndexOf('|')
    if ($bar -ge 0) { $head = $Name.Substring(0, $bar); $subject = $Name.Substring($bar + 1) }
    $isPath = $head.StartsWith('/', [System.StringComparison]::Ordinal) -or $head.StartsWith('\', [System.StringComparison]::Ordinal) -or
        ($head.Length -ge 3 -and [int]$head[0] -lt 128 -and [char]::IsLetter($head[0]) -and $head[1] -eq ':' -and ($head[2] -eq '\' -or $head[2] -eq '/'))
    $short = $head
    if ($isPath) {
        $base = $head.Substring($head.LastIndexOfAny([char[]]@('/', '\')) + 1)
        if ($base.Length -gt 0) { $short = $base }
    }
    @{ Short = $short; Subject = $subject }
}

function Add-BoabHtmlSystemRow {
    param([System.Text.StringBuilder]$Sb, [string]$Name, [string]$Classification, [string]$Criticality, [AllowEmptyCollection()]$Rows)
    $count = 0; $vulnerable = 0; $urgent = 0; $peak = $null
    foreach ($row in $Rows) {
        $count++
        if ($row.Asset.pqc_status -ceq 'vulnerable' -or $row.Asset.pqc_status -ceq 'unknown') { $vulnerable++ }
        if ([int]$row.Score.triage_tier -le 2) { $urgent++ }
        if ($null -eq $peak -or [double]$row.Score.priority -gt [double]$peak) { $peak = $row.Score.priority }
    }
    $peakText = if ($null -eq $peak) { '&ndash;' } else { Format-BoabFixed -Value ([double]$peak) -Decimals 1 }
    [void]$Sb.Append('<tr><td>' + $Name + '</td><td>' + $Classification + '</td><td>' + $Criticality + '</td><td class="num">' + (Format-BoabHtmlGroup $count) +
        '</td><td class="num">' + (Format-BoabHtmlGroup $vulnerable) + '</td><td class="num">' + (Format-BoabHtmlGroup $urgent) + '</td><td class="num">' + $peakText + "</td></tr>`n")
}

function New-BoabHtmlReport {
    # report::html::render
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $systems = Get-BoabStoredSystem -Workspace $Workspace
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $plans = Get-BoabStoredPlan -Workspace $Workspace
    $scans = Get-BoabStoredScan -Workspace $Workspace
    $registry = Get-BoabMergedVendorRegistry -Workspace $Workspace
    $now = Get-BoabNow
    $utc = $now.UtcDateTime
    $year = $utc.Year
    $version = $script:BoabVersion

    $scoredRaw = New-BoabList
    foreach ($a in $inventory) {
        $sys = Find-BoabSystemById -Systems $systems -Id $a.system_id
        $scoredRaw.Add(@{ Asset = $a; Score = (Get-BoabRiskScore -Asset $a -System $sys -CurrentYear $year) })
    }
    $scored = Sort-BoabStable -Items $scoredRaw -Compare {
        param($x, $y)
        ([double]$y.Score.priority).CompareTo([double]$x.Score.priority)
    }

    # Headline figures
    $total = $scored.Count
    $statusCounts = @(0, 0, 0, 0, 0)
    $tierCounts = @(0, 0, 0, 0)
    $broken = 0
    $unassigned = 0
    foreach ($e in $scored) {
        $statusCounts[(Get-BoabHtmlStatusIndex $e.Asset.pqc_status)]++
        $tier = [math]::Min(4, [math]::Max(1, [int]$e.Score.triage_tier))
        $tierCounts[$tier - 1]++
        if ([int]$e.Score.algorithm_vulnerability -ge 10) { $broken++ }
        if ($null -eq (Find-BoabSystemById -Systems $systems -Id $e.Asset.system_id)) { $unassigned++ }
    }
    $unknown = $statusCounts[1]
    $exposed = $statusCounts[0] + $unknown
    $exposedPct = 0.0
    if ($total -ne 0) {
        $exposedPct = ConvertTo-BoabF32 ((ConvertTo-BoabF32 ([double][single]$exposed * 100.0)) / [double][single]$total)
    }
    $pctText = Format-BoabFixed -Value $exposedPct -Decimals 1
    $t1 = $tierCounts[0]; $t2 = $tierCounts[1]; $t3 = $tierCounts[2]
    $planYears = @{}
    foreach ($p in $plans) { $planYears[(Get-BoabMilestoneYear $p.milestone)] = $true }
    # Any plan on file meets the 2026 "refined transition plan" milestone.
    $covered = 0
    if ($plans.Count -gt 0) { $covered++ }
    foreach ($y in @(2028, 2030)) { if ($planYears.ContainsKey($y)) { $covered++ } }
    $soci = 0
    foreach ($s in $systems) { if ($s.is_soci) { $soci++ } }

    $h = [System.Text.StringBuilder]::new()
    $add = { param([string]$s) [void]$h.Append($s) }

    # Document head
    & $add "<!DOCTYPE html>`n<html lang=`"en`">`n<head>`n<meta charset=`"utf-8`">`n"
    & $add "<meta name=`"viewport`" content=`"width=device-width, initial-scale=1`">`n"
    & $add ("<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; style-src 'unsafe-inline'; script-src '" + $script:BoabHtmlPrintScriptHash + "'; base-uri 'none'; form-action 'none'`">`n")
    & $add "<meta name=`"color-scheme`" content=`"light dark`">`n"
    & $add ("<meta name=`"generator`" content=`"Boab {0}`">`n" -f $version)
    & $add "<title>Post-Quantum Cryptography Readiness Report</title>`n"
    & $add "<style>`n"
    & $add $script:BoabHtmlCss
    & $add "</style>`n</head>`n<body>`n"

    # Masthead
    & $add "<header class=`"masthead`">`n<div class=`"wrap`">`n"
    & $add '<div class="brand">'
    & $add $script:BoabHtmlLogo
    & $add "<span class=`"brand-name`">Boab</span><span class=`"brand-tag`">Transitioning to post-quantum security</span></div>`n"
    & $add "<h1>Post-Quantum Cryptography Readiness Report</h1>`n"
    & $add ("<p class=`"meta`">Prepared {0} &middot; Boab {1} &middot; Aligned to the ASD 2026, 2028 and 2030 transition milestones</p>`n" -f (Format-BoabHtmlDate -Year $utc.Year -Month $utc.Month -Day $utc.Day), $version)
    $scanCounts = @(0, 0, 0)
    foreach ($s in $scans) {
        switch -CaseSensitive ($s.scan_type) {
            'codebase' { $scanCounts[0]++ }
            'tls_endpoint' { $scanCounts[1]++ }
            'certificate_store' { $scanCounts[2]++ }
        }
    }
    & $add ("<p class=`"meta`">Assessment scope: {0} &middot; {1} &middot; {2}</p>`n" -f (Format-BoabHtmlPlural $scanCounts[0] 'codebase scan' 'codebase scans'),
        (Format-BoabHtmlPlural $scanCounts[1] 'TLS endpoint scan' 'TLS endpoint scans'), (Format-BoabHtmlPlural $scanCounts[2] 'certificate store scan' 'certificate store scans'))
    & $add "</div>`n</header>`n<main class=`"wrap`">`n"

    # Overall posture
    if ($total -eq 0) { $tone = 'neutral'; $posture = 'Not yet assessed' }
    elseif ($t1 -gt 0) { $tone = 'critical'; $posture = 'Critical exposure' }
    elseif ($t2 -gt 0 -or $exposed * 2 -ge $total) { $tone = 'serious'; $posture = 'High exposure' }
    elseif ($exposed -gt 0) { $tone = 'warning'; $posture = 'Moderate exposure' }
    else { $tone = 'good'; $posture = 'Low exposure' }
    if ($total -eq 0) {
        $headline = 'No cryptographic assets have been inventoried yet. Run the Boab codebase, TLS and certificate scanners to establish a baseline before the end-of-2026 planning milestone.'
    }
    else {
        $headline = '{0} of {1} ({2}%) {3} on cryptography that a future quantum computer could break, or {4} not yet classified. ' -f (Format-BoabHtmlGroup $exposed),
        (Format-BoabHtmlPlural $total 'inventoried cryptographic asset' 'inventoried cryptographic assets'), $pctText,
        $(if ($exposed -eq 1) { 'relies' } else { 'rely' }), $(if ($exposed -eq 1) { 'is' } else { 'are' })
        if ($t1 + $t2 -gt 0) {
            $headline += '{0} {1} migration inside the 2028 implementation window.' -f (Format-BoabHtmlPlural ($t1 + $t2) 'asset' 'assets'), $(if ($t1 + $t2 -eq 1) { 'needs' } else { 'need' })
        }
        elseif ($exposed -gt 0) {
            $headline += 'None require migration inside the 2028 window; the remainder fall into the 2029&ndash;2030 rollout or monitoring.'
        }
        else {
            $headline += 'No quantum-vulnerable cryptography was found in scope.'
        }
    }
    & $add ("<section class=`"hero tone-{0}`" aria-label=`"Overall posture`">`n" -f $tone)
    & $add "<div class=`"hero-text`">`n<p class=`"eyebrow`">Overall posture</p>`n"
    & $add ("<p class=`"posture`"><span class=`"pip`" aria-hidden=`"true`"></span>{0}</p>`n" -f $posture)
    & $add ("<p class=`"headline`">{0}</p>`n</div>`n" -f $headline)
    & $add "<div class=`"hero-figure`">`n"
    & $add ("<span class=`"big`">{0}</span>`n" -f $(if ($total -eq 0) { '&ndash;' } else { $pctText + '%' }))
    & $add "<span class=`"cap`">of inventoried assets are quantum-vulnerable or unclassified</span>`n</div>`n</section>`n"

    # KPI tiles
    & $add "<section class=`"kpis`" aria-label=`"Key figures`">`n"
    $assetsSub = if ($unassigned -gt 0) { '{0} not linked to a system' -f (Format-BoabHtmlGroup $unassigned) } else { 'across {0}' -f (Format-BoabHtmlPlural $systems.Count 'system' 'systems') }
    Add-BoabHtmlKpi -Sb $h -Label 'Assets inventoried' -Value (Format-BoabHtmlGroup $total) -Sub $assetsSub
    Add-BoabHtmlKpi -Sb $h -Label 'Quantum-vulnerable' -Value (Format-BoabHtmlGroup $exposed) -Sub ('{0}% of inventory' -f $pctText)
    Add-BoabHtmlKpi -Sb $h -Label 'Migrate by 2028' -Value (Format-BoabHtmlGroup ($t1 + $t2)) -Sub ('Tier 1: {0} &middot; Tier 2: {1}' -f (Format-BoabHtmlGroup $t1), (Format-BoabHtmlGroup $t2))
    Add-BoabHtmlKpi -Sb $h -Label 'Classically broken' -Value (Format-BoabHtmlGroup $broken) -Sub 'weak even without a quantum computer'
    Add-BoabHtmlKpi -Sb $h -Label 'Plans on file' -Value (Format-BoabHtmlGroup $plans.Count) -Sub ('covering {0} of 3 ASD milestones' -f $covered)
    & $add "</section>`n"

    # Key actions
    $actions = New-BoabList
    if ($t1 -gt 0) {
        $actions.Add(('<strong>Migrate {0} now.</strong> {1} high quantum exposure with a practical migration path and should be completed before the 2028 milestone.' -f (Format-BoabHtmlPlural $t1 'Tier 1 asset' 'Tier 1 assets'), $(if ($t1 -eq 1) { 'It combines' } else { 'They combine' })))
    }
    if ($broken -gt 0) {
        $actions.Add(('<strong>Replace {0} using classically broken algorithms now</strong> (such as MD5, SHA-1, RSA-1024, 3DES and RC4). These are already weak against conventional attacks, whatever their quantum triage tier, and are marked <em>Broken today</em> below.' -f (Format-BoabHtmlPlural $broken 'asset' 'assets')))
    }
    if ($t2 -gt 0) {
        $actions.Add(('<strong>Schedule {0} inside the 2028 window</strong>, starting with hardware-locked and long-lived systems that take longest to change.' -f (Format-BoabHtmlPlural $t2 'Tier 2 asset' 'Tier 2 assets')))
    }
    if ($plans.Count -eq 0) {
        $actions.Add('<strong>Generate and agree a transition plan</strong> to meet the ASD end-of-2026 milestone for a refined plan (<code>boab plan generate --milestone 2030</code> covers every tier).')
    }
    if ($unknown -gt 0) {
        $actions.Add(('<strong>Classify {0} with unknown quantum status.</strong> Unknowns are scored conservatively until they are reviewed.' -f (Format-BoabHtmlPlural $unknown 'asset' 'assets')))
    }
    if ($unassigned -gt 0) {
        $actions.Add(('<strong>Link {0} to business systems</strong> so data classification, SOCI status and retention are weighted correctly.' -f (Format-BoabHtmlPlural $unassigned 'asset' 'assets')))
    }
    if ($t3 -gt 0) {
        $actions.Add(('<strong>Track {0}</strong> for replacement during the 2029&ndash;2030 rollout window.' -f (Format-BoabHtmlPlural $t3 'Tier 3 asset' 'Tier 3 assets')))
    }
    if ($actions.Count -eq 0) {
        $actions.Add('<strong>Maintain the inventory.</strong> Rescan after significant changes and keep monitoring vendor post-quantum roadmaps.')
    }
    & $add "<section class=`"card`">`n<h2>Recommended actions</h2>`n<ol class=`"actions`">`n"
    foreach ($a in $actions) { & $add ("<li>" + $a + "</li>`n") }
    & $add "</ol>`n</section>`n"

    # Charts
    & $add "<div class=`"grid2`">`n"
    & $add "<section class=`"card`">`n<h2>Quantum exposure</h2>`n<p class=`"sub`">Inventoried assets by post-quantum status</p>`n"
    if ($total -eq 0) {
        & $add "<p class=`"empty`">No assets inventoried yet.</p>`n"
    }
    else {
        & $add '<div class="stack" role="img" aria-label="'
        $aria = New-BoabList
        for ($i = 0; $i -lt 5; $i++) { $aria.Add(('{0} {1}' -f (Get-BoabHtmlStatusLabel $script:BoabHtmlStatusOrder[$i]), $statusCounts[$i])) }
        & $add ($aria -join ', ')
        & $add '">'
        for ($i = 0; $i -lt 5; $i++) {
            $st = $script:BoabHtmlStatusOrder[$i]
            if ($statusCounts[$i] -gt 0) {
                & $add ('<span class="seg s-{0}" style="flex-grow:{1}" title="{2}: {1}"></span>' -f (Get-BoabHtmlStatusKey $st), $statusCounts[$i], (Get-BoabHtmlStatusLabel $st))
            }
        }
        & $add "</div>`n"
    }
    & $add "<ul class=`"legend`">`n"
    for ($i = 0; $i -lt 5; $i++) {
        $st = $script:BoabHtmlStatusOrder[$i]
        & $add ("<li><span class=`"key s-{0}`" aria-hidden=`"true`"></span><span class=`"lk`">{1}</span><span class=`"lv`">{2}</span><span class=`"ld`">{3}</span></li>`n" -f (Get-BoabHtmlStatusKey $st),
            (Get-BoabHtmlStatusLabel $st), (Format-BoabHtmlGroup $statusCounts[$i]), (Get-BoabHtmlStatusBlurb $st))
    }
    & $add "</ul>`n</section>`n"

    & $add "<section class=`"card`">`n<h2>Migration priority</h2>`n<p class=`"sub`">Inventoried assets by triage tier</p>`n"
    $tierMax = 0
    foreach ($c in $tierCounts) { if ($c -gt $tierMax) { $tierMax = $c } }
    & $add "<ul class=`"bars`">`n"
    for ($i = 0; $i -lt 4; $i++) {
        $tier = $i + 1
        $count = $tierCounts[$i]
        $width = if ($tierMax -eq 0) { 0 } else { [long][math]::Floor(([long]$count * 1000) / $tierMax) }
        & $add ("<li><span class=`"bl`"><strong>Tier {0}</strong><span>{1}</span></span><span class=`"track`"><span class=`"fill t-{0}`" style=`"width:{2}.{3}%`" title=`"Tier {0}: {4}`"></span></span><span class=`"bv`">{5}</span></li>`n" -f $tier,
            (Get-BoabHtmlTierBlurb $tier), [long][math]::Floor($width / 10), ($width % 10), $count, (Format-BoabHtmlGroup $count))
    }
    & $add "</ul>`n</section>`n</div>`n"

    # Milestones
    & $add "<section class=`"card`">`n<h2>ASD transition milestones</h2>`n<p class=`"sub`">Australian Signals Directorate (ASD) guidance for post-quantum migration</p>`n<ol class=`"milestones`">`n"
    $milestones = @(
        @(2026, 'Refined transition plan', 'Cryptographic inventory complete and a prioritised, funded transition plan agreed.'),
        @(2028, 'Implementation begins', 'Tier 1 and Tier 2 assets migrated or actively in flight.'),
        @(2030, 'Implementation complete', 'Classical public-key cryptography retired from in-scope systems.')
    )
    foreach ($m in $milestones) {
        $items = 0; $done = 0
        foreach ($p in $plans) {
            if ((Get-BoabMilestoneYear $p.milestone) -ne $m[0]) { continue }
            foreach ($it in $p.items) { $items++; if ($it.status -ceq 'complete') { $done++ } }
        }
        if ($m[0] -eq 2026) {
            $badge = if ($plans.Count -eq 0) { Get-BoabHtmlBadge -Class 'warning' -Label 'Plan outstanding' } else { Get-BoabHtmlBadge -Class 'good' -Label 'Plan on file' }
        }
        elseif (-not $planYears.ContainsKey($m[0])) { $badge = Get-BoabHtmlBadge -Class 'warning' -Label 'Plan outstanding' }
        elseif ($items -eq 0) { $badge = Get-BoabHtmlBadge -Class 'neutral' -Label 'Plan on file &middot; no items' }
        elseif ($done -eq $items) { $badge = Get-BoabHtmlBadge -Class 'good' -Label 'All plan items complete' }
        else { $badge = Get-BoabHtmlBadge -Class 'neutral' -Label ('Plan on file &middot; {0}% complete' -f [long][math]::Floor(([long]$done * 100) / $items)) }
        & $add ("<li><span class=`"year`">{0}</span><span class=`"mt`">{1}</span><span class=`"md`">{2}</span>{3}</li>`n" -f $m[0], $m[1], $m[2], $badge)
    }
    & $add "</ol>`n</section>`n"

    # Top assets
    & $add ("<section class=`"card`">`n<h2>Highest-priority assets</h2>`n<p class=`"sub`">Top {0} by priority score (0&ndash;10)</p>`n" -f $script:BoabHtmlTopAssets)
    $top = New-BoabList
    for ($i = 0; $i -lt [math]::Min($script:BoabHtmlTopAssets, $total); $i++) { $top.Add($scored[$i]) }
    Add-BoabHtmlAssetTable -Sb $h -Rows $top -Systems $systems -Empty 'No assets inventoried yet.'
    & $add "</section>`n"

    # Systems
    & $add "<section class=`"card`">`n<h2>Exposure by business system</h2>`n"
    & $add ("<p class=`"sub`">{0} in scope, {1} SOCI-regulated</p>`n" -f (Format-BoabHtmlPlural $systems.Count 'system' 'systems'), (Format-BoabHtmlGroup $soci))
    if ($systems.Count -eq 0 -and $unassigned -eq 0) {
        & $add "<p class=`"empty`">No business systems recorded. Add them with <code>boab system add</code> so risk is weighted by classification and criticality.</p>`n"
    }
    else {
        & $add "<div class=`"tw`"><table>`n<thead><tr><th>System</th><th>Classification</th><th>Criticality</th><th class=`"num`">Assets</th><th class=`"num`">Vulnerable</th><th class=`"num`">Tier 1&ndash;2</th><th class=`"num`">Peak priority</th></tr></thead>`n<tbody>`n"
        foreach ($sys in $systems) {
            $mine = New-BoabList
            foreach ($e in $scored) { if ($null -ne $e.Asset.system_id -and $e.Asset.system_id -ceq $sys.id) { $mine.Add($e) } }
            $name = (ConvertTo-BoabHtmlEscaped $sys.name) + $(if ($sys.is_soci) { ' <span class="tag">SOCI</span>' } else { '' })
            Add-BoabHtmlSystemRow -Sb $h -Name $name -Classification (Get-BoabHtmlClassificationLabel $sys.classification) -Criticality (Get-BoabHtmlCriticalityLabel $sys.criticality) -Rows $mine
        }
        if ($unassigned -gt 0) {
            $mine = New-BoabList
            foreach ($e in $scored) { if ($null -eq (Find-BoabSystemById -Systems $systems -Id $e.Asset.system_id)) { $mine.Add($e) } }
            Add-BoabHtmlSystemRow -Sb $h -Name '<em>Not linked to a system</em>' -Classification '&ndash;' -Criticality '&ndash;' -Rows $mine
        }
        & $add "</tbody>`n</table></div>`n"
    }
    & $add "</section>`n"

    # Plans
    & $add "<section class=`"card`">`n<h2>Transition plans</h2>`n"
    if ($plans.Count -eq 0) {
        & $add "<p class=`"empty`">No transition plans generated yet. Create one with <code>boab plan generate --milestone 2028</code>.</p>`n"
    }
    else {
        & $add "<div class=`"tw`"><table>`n<thead><tr><th>Plan</th><th>Milestone</th><th class=`"num`">Items</th><th class=`"num`">In progress</th><th class=`"num`">Complete</th><th>Progress</th><th>Generated</th></tr></thead>`n<tbody>`n"
        foreach ($p in $plans) {
            $items = $p.items.Count
            $done = 0; $doing = 0
            foreach ($it in $p.items) {
                if ($it.status -ceq 'complete') { $done++ }
                elseif ($it.status -ceq 'in_progress') { $doing++ }
            }
            $pct = if ($items -eq 0) { 0 } else { [long][math]::Floor(([long]$done * 100) / $items) }
            & $add ("<tr><td>{0}</td><td>{1}</td><td class=`"num`">{2}</td><td class=`"num`">{3}</td><td class=`"num`">{4}</td><td><span class=`"meter`"><span class=`"mf`" style=`"width:{5}%`"></span></span> {5}%</td><td><time datetime=`"{6}`">{7}</time></td></tr>`n" -f (ConvertTo-BoabHtmlEscaped $p.name),
                (Get-BoabMilestoneYear $p.milestone), (Format-BoabHtmlGroup $items), (Format-BoabHtmlGroup $doing), (Format-BoabHtmlGroup $done), $pct, (ConvertTo-BoabHtmlEscaped $p.generated_at), (Format-BoabHtmlStoredDate $p.generated_at))
        }
        & $add "</tbody>`n</table></div>`n"
    }
    & $add "</section>`n"

    # Vendors
    $vendorCounts = @(0, 0, 0, 0, 0)
    foreach ($e in $registry.entries) { $vendorCounts[(Get-BoabHtmlStatusIndex $e.pqc_status)]++ }
    $vendorTotal = @($registry.entries).Count
    & $add "<section class=`"card`">`n<h2>Vendor PQC dependencies</h2>`n"
    & $add ("<p class=`"sub`">Post-quantum readiness of {0} in the vendor registry</p>`n" -f (Format-BoabHtmlPlural $vendorTotal 'tracked product' 'tracked products'))
    & $add "<ul class=`"chips`">`n"
    $chipOrder = @('resistant', 'hybrid', 'vulnerable', 'unknown', 'symmetric_ok')
    for ($i = 0; $i -lt 5; $i++) {
        $st = $chipOrder[$i]
        $n = $vendorCounts[(Get-BoabHtmlStatusIndex $st)]
        if ($n -gt 0 -or $i -lt 4) {
            & $add ("<li><span class=`"key s-{0}`" aria-hidden=`"true`"></span>{1} <strong>{2}</strong></li>`n" -f (Get-BoabHtmlStatusKey $st), (Get-BoabHtmlStatusLabel $st), (Format-BoabHtmlGroup $n))
        }
    }
    & $add "</ul>`n"
    if ($vendorTotal -gt 0) {
        & $add ("<details open data-collapse>`n<summary>View all {0} vendor products</summary>`n" -f (Format-BoabHtmlGroup $vendorTotal))
        & $add "<div class=`"tw`"><table>`n<thead><tr><th>Vendor</th><th>Product</th><th>Status</th><th>Target</th><th>Source</th></tr></thead>`n<tbody>`n"
        foreach ($e in $registry.entries) {
            if ($null -ne $e.source_url -and (Test-BoabHtmlWebUrl $e.source_url)) {
                $label = if ($null -ne $e.source_note) { $e.source_note } else { 'source' }
                $source = '<a href="' + (ConvertTo-BoabHtmlEscaped $e.source_url) + '" rel="noopener noreferrer">' + (ConvertTo-BoabHtmlEscaped $label) + '</a>'
            }
            elseif ($null -ne $e.source_note) { $source = ConvertTo-BoabHtmlEscaped $e.source_note }
            else { $source = '&ndash;' }
            $target = if ($null -ne $e.target_date) { ConvertTo-BoabHtmlEscaped $e.target_date } else { '&ndash;' }
            & $add ('<tr><td>' + (ConvertTo-BoabHtmlEscaped $e.vendor) + '</td><td>' + (ConvertTo-BoabHtmlEscaped $e.product) + '</td><td>' + (Get-BoabHtmlStatusBadge $e.pqc_status) +
                '</td><td>' + $target + '</td><td>' + $source + "</td></tr>`n")
        }
        & $add "</tbody>`n</table></div>`n</details>`n"
    }
    & $add "</section>`n"

    # Appendix: full inventory
    & $add "<section class=`"card`">`n<h2>Appendix A &middot; Full cryptographic inventory</h2>`n"
    & $add ("<p class=`"sub`">{0}, ranked by priority</p>`n" -f (Format-BoabHtmlPlural $total 'asset' 'assets'))
    if ($total -eq 0) {
        & $add "<p class=`"empty`">No assets inventoried yet.</p>`n"
    }
    else {
        & $add ("<details open data-collapse>`n<summary>View all {0}</summary>`n" -f (Format-BoabHtmlPlural $total 'asset' 'assets'))
        Add-BoabHtmlAssetTable -Sb $h -Rows $scored -Systems $systems -Empty ''
        & $add "</details>`n"
    }
    & $add "</section>`n"

    # Appendix: methodology
    & $add "<section class=`"card method`">`n<h2>Appendix B &middot; Methodology</h2>`n"
    & $add "<p>Each asset is scored with Boab&rsquo;s LATICE risk rubric, aligned to ASD guidance, on five axes, each from 0 to 10, and combined into a priority score:</p>`n"
    & $add "<p class=`"formula`"><code>priority = algo_vuln &times; 0.30 + hndl &times; 0.30 + data_sens &times; 0.15 + sys_crit &times; 0.15 + mig_diff &times; 0.10</code></p>`n"
    & $add "<dl>`n"
    & $add "<dt>Algorithm vulnerability</dt><dd>How exposed the algorithm is: 10 for classically broken primitives, 8&ndash;9 for RSA and elliptic-curve cryptography, 5 for PQ/T hybrids, 1 for ML-KEM, ML-DSA and SLH-DSA, 0 for strong symmetric cryptography. Unrecognised algorithms score 7 until they are classified.</dd>`n"
    & $add "<dt>Harvest now, decrypt later</dt><dd>How far the data&rsquo;s confidentiality horizon extends past the expected arrival of a cryptographically relevant quantum computer.</dd>`n"
    & $add "<dt>Data sensitivity and system criticality</dt><dd>Taken from the protective marking and criticality of the linked business system; SOCI-regulated systems score as mission critical.</dd>`n"
    & $add "<dt>Migration difficulty</dt><dd>Effort to replace the asset, from trivial configuration changes to hardware-locked devices.</dd>`n"
    & $add "</dl>`n"
    & $add "<p><strong>Triage tiers.</strong> Tier 1: priority &ge; 7 with a practical migration path, migrate before 2028. Tier 2: priority &ge; 6, or hardware-locked and clearly vulnerable, migrate inside the 2028 window. Tier 3: vulnerable algorithm, replace during 2029&ndash;2030. Tier 4: monitor. Assets using classically broken algorithms are marked <em>Broken today</em> and should be replaced now, whatever their tier.</p>`n"
    & $add "<p><strong>Overall posture.</strong> Critical when any Tier 1 asset exists; high when any Tier 2 asset exists or at least half of the inventory is quantum-vulnerable or unclassified; moderate when any vulnerable or unclassified asset remains; otherwise low.</p>`n"
    & $add "<p>Refer to the ASD Information Security Manual for control mappings. Boab does not map findings to specific ISM control IDs in this version.</p>`n"
    & $add "</section>`n</main>`n"

    # Footer
    $ts = Format-BoabRfc3339 -Value $now.ToUniversalTime()
    & $add ("<footer class=`"wrap`">Generated by Boab {0} at <time datetime=`"{1}`">{1}</time>. This report is self-contained and loads nothing from the network.</footer>`n" -f $version, $ts)
    & $add ('<script>' + $script:BoabHtmlPrintScript + "</script>`n")
    & $add "</body>`n</html>`n"
    $h.ToString()
}

function Export-BoabHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Path)
    $text = New-BoabHtmlReport -Workspace $Workspace
    Write-BoabReportFile -Path $Path -Content $text
}
