# Report writers: native JSON, CycloneDX 1.6 CBOM and Markdown (HTML lives in HtmlReport.ps1).
# Ports of src/report/json.rs, src/report/cbom.rs, src/report/markdown.rs and src/report/mod.rs.

$script:BoabVersion = '0.1.0'

function Write-BoabReportFile {
    param([string]$Path, [string]$Content)
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if ($parent) {
        try { [void][System.IO.Directory]::CreateDirectory($parent) } catch { Write-Debug "create_dir_all failed: $_" }
    }
    try {
        Write-BoabTextFile -Path $Path -Content $Content
    }
    catch {
        throw (New-BoabException ("write {0}: {1}" -f $Path, (Get-BoabIoErrorText -Exception $_ -Path $Path)))
    }
}

# --- JSON ----------------------------------------------------------------------------

function New-BoabJsonReport {
    # Build the report::json document (ordered structure).
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $systems = Get-BoabStoredSystem -Workspace $Workspace
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $scans = Get-BoabStoredScan -Workspace $Workspace
    $plans = Get-BoabStoredPlan -Workspace $Workspace
    $registry = Get-BoabMergedVendorRegistry -Workspace $Workspace
    $now = Get-BoabNow
    $year = $now.UtcDateTime.Year

    $scored = New-BoabList
    foreach ($a in $inventory) {
        $sys = Find-BoabSystemById -Systems $systems -Id $a.system_id
        $row = [ordered]@{}
        foreach ($k in $a.Keys) { $row[$k] = $a[$k] }
        $row['risk_score'] = Get-BoabRiskScore -Asset $a -System $sys -CurrentYear $year
        $scored.Add($row)
    }
    $summaries = New-BoabList
    foreach ($s in $scans) {
        $summaries.Add([ordered]@{
                id            = $s.id
                name          = $s.name
                scan_type     = $s.scan_type
                status        = $s.status
                target        = $s.target
                started_at    = $s.started_at
                finding_count = [long]@($s.findings).Count
            })
    }
    $byStatus = [ordered]@{}
    foreach ($e in $registry.entries) {
        $k = Get-BoabDebugLower $e.pqc_status
        if (-not $byStatus.Contains($k)) { $byStatus[$k] = [long]0 }
        $byStatus[$k] = [long]$byStatus[$k] + 1
    }
    [ordered]@{
        metadata        = [ordered]@{
            tool         = 'boab'
            version      = $script:BoabVersion
            generated_at = Format-BoabRfc3339 -Value $now.ToUniversalTime()
        }
        systems         = $systems
        inventory       = $scored
        scans           = $summaries
        plans           = $plans
        vendor_coverage = [ordered]@{
            total     = [long]$registry.entries.Count
            by_status = $byStatus
        }
        vendor_registry = $registry
    }
}

function Export-BoabJsonReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Path)
    $doc = New-BoabJsonReport -Workspace $Workspace
    Write-BoabReportFile -Path $Path -Content (ConvertTo-BoabJson -InputObject $doc)
}

# --- CBOM ----------------------------------------------------------------------------

function Get-BoabCbomPrimitive {
    param($Primitive)
    switch -CaseSensitive ([string]$Primitive) {
        'block_cipher' { return 'block-cipher' }
        'stream_cipher' { return 'stream-cipher' }
        'hash' { return 'hash' }
        'signature' { return 'signature' }
        'key_agreement' { return 'key-agree' }
        'kem' { return 'kem' }
        'pke' { return 'pke' }
        'mac' { return 'mac' }
        'drbg' { return 'drbg' }
    }
    'unknown'
}

function Get-BoabNistQuantumSecurityLevel {
    param([System.Collections.IDictionary]$Asset)
    if ($Asset.pqc_status -ceq 'vulnerable' -or $Asset.pqc_status -ceq 'unknown') { return [long]0 }
    $algo = ConvertTo-BoabAsciiLower $Asset.algorithm_name
    $has = { param($s) $algo.Contains($s) }
    if ((& $has 'ml-kem-512') -or (& $has 'mlkem-512') -or (& $has 'kyber512')) { return [long]1 }
    if ((& $has 'ml-kem-768') -or (& $has 'mlkem-768') -or (& $has 'kyber768')) { return [long]3 }
    if ((& $has 'ml-kem-1024') -or (& $has 'mlkem-1024') -or (& $has 'kyber1024')) { return [long]5 }
    if ((& $has 'ml-dsa-44') -or (& $has 'dilithium2')) { return [long]2 }
    if ((& $has 'ml-dsa-65') -or (& $has 'dilithium3')) { return [long]3 }
    if ((& $has 'ml-dsa-87') -or (& $has 'dilithium5')) { return [long]5 }
    if ($Asset.pqc_status -ceq 'symmetric_ok') { return [long]1 }
    if ($Asset.pqc_status -ceq 'resistant') { return [long]1 }
    [long]0
}

function Get-BoabCbomComponent {
    param([System.Collections.IDictionary]$Asset)
    $ps = $Asset.parameter_set
    $props = [ordered]@{}
    $algorithmProperties = {
        $paramSet = $Asset.algorithm_name
        if (Test-BoabJsonHasField $ps 'key_size_bits') {
            $paramSet = '{0} bits' -f (ConvertTo-BoabJson -InputObject (Get-BoabJsonField $ps 'key_size_bits') -Compress)
        }
        [ordered]@{
            primitive                = Get-BoabCbomPrimitive $Asset.primitive
            parameterSetIdentifier   = $paramSet
            executionEnvironment     = 'software-plain-ram'
            implementationPlatform   = 'generic'
            certificationLevel       = (New-BoabList @('none'))
            cryptoFunctions          = (New-BoabList @('generate', 'verify'))
            nistQuantumSecurityLevel = Get-BoabNistQuantumSecurityLevel $Asset
        }
    }
    switch -CaseSensitive ($Asset.asset_type) {
        'algorithm' {
            $props['assetType'] = 'algorithm'
            $props['algorithmProperties'] = & $algorithmProperties
        }
        'library_dependency' {
            $props['assetType'] = 'algorithm'
            $props['algorithmProperties'] = & $algorithmProperties
        }
        'certificate' {
            $subject = Get-BoabJsonStr (Get-BoabJsonField $ps 'subject')
            if ($null -eq $subject) { $subject = $Asset.name }
            $issuer = Get-BoabJsonStr (Get-BoabJsonField $ps 'issuer')
            if ($null -eq $issuer) { $issuer = '' }
            $nbf = ''
            $t = Get-BoabJsonI64 (Get-BoabJsonField $ps 'not_before_unix')
            if ($null -ne $t) { $f = Format-BoabUnixRfc3339 -Seconds $t; if ($null -ne $f) { $nbf = $f } }
            $naf = ''
            $t = Get-BoabJsonI64 (Get-BoabJsonField $ps 'not_after_unix')
            if ($null -ne $t) { $f = Format-BoabUnixRfc3339 -Seconds $t; if ($null -ne $f) { $naf = $f } }
            $props['assetType'] = 'certificate'
            $props['certificateProperties'] = [ordered]@{
                subjectName           = $subject
                issuerName            = $issuer
                notValidBefore        = $nbf
                notValidAfter         = $naf
                signatureAlgorithmRef = $Asset.algorithm_name
                certificateFormat     = 'X.509'
            }
        }
        'key' {
            $size = Get-BoabJsonU64 (Get-BoabJsonField $ps 'key_size_bits')
            if ($null -eq $size) { $size = [ulong]0 }
            $props['assetType'] = 'related-crypto-material'
            $props['relatedCryptoMaterialProperties'] = [ordered]@{
                type   = 'key'
                format = 'raw'
                size   = $size
            }
        }
        'protocol_endpoint' {
            $version = Get-BoabJsonStr (Get-BoabJsonField $ps 'tls_version')
            if ($null -eq $version) { $version = 'unknown' }
            $props['assetType'] = 'protocol'
            $props['protocolProperties'] = [ordered]@{
                type         = 'tls'
                version      = $version
                cipherSuites = (New-BoabList @([ordered]@{ name = $Asset.algorithm_name }))
            }
        }
    }
    $props['oid'] = if ($null -ne $Asset.algorithm_oid) { $Asset.algorithm_oid } else { '' }
    [ordered]@{
        'type'             = 'cryptographic-asset'
        'bom-ref'          = 'boab:' + $Asset.id
        'name'             = $Asset.name
        'description'      = $Asset.description
        'cryptoProperties' = $props
    }
}

function New-BoabCbom {
    # report::cbom::build_bom
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Inventory)
    $now = Format-BoabRfc3339 -Value (Get-BoabNow).ToUniversalTime()
    $components = New-BoabList
    foreach ($a in $Inventory) { $components.Add((Get-BoabCbomComponent -Asset $a)) }
    [ordered]@{
        bomFormat    = 'CycloneDX'
        specVersion  = '1.6'
        serialNumber = 'urn:uuid:' + (New-BoabUuid)
        version      = [long]1
        metadata     = [ordered]@{
            timestamp = $now
            tools     = [ordered]@{
                components = (New-BoabList @([ordered]@{
                            type    = 'application'
                            name    = 'boab'
                            version = $script:BoabVersion
                        }))
            }
        }
        components   = $components
    }
}

function Export-BoabCbomReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Path)
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $bom = New-BoabCbom -Inventory $inventory
    Write-BoabReportFile -Path $Path -Content (ConvertTo-BoabJson -InputObject $bom)
}

# --- Readiness data (shared by Markdown and HTML) -------------------------------------

function Get-BoabReadinessData {
    # report::Readiness::load. Every asset scored, sorted by descending priority (stable).
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $systems = Get-BoabStoredSystem -Workspace $Workspace
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $plans = Get-BoabStoredPlan -Workspace $Workspace
    $registry = Get-BoabMergedVendorRegistry -Workspace $Workspace
    $now = Get-BoabNow
    $year = $now.UtcDateTime.Year

    $scoredRaw = New-BoabList
    foreach ($a in $inventory) {
        $sys = Find-BoabSystemById -Systems $systems -Id $a.system_id
        $scoredRaw.Add(@{ Asset = $a; Score = (Get-BoabRiskScore -Asset $a -System $sys -CurrentYear $year) })
    }
    $scored = Sort-BoabStable -Items $scoredRaw -Compare {
        param($x, $y)
        ([double]$y.Score.priority).CompareTo([double]$x.Score.priority)
    }
    @{ Systems = $systems; Scored = $scored; Plans = $plans; Registry = $registry; Now = $now }
}

function Get-BoabReadinessVulnerableCount {
    param([hashtable]$Data)
    $n = 0
    foreach ($e in $Data.Scored) { if ($e.Asset.pqc_status -ceq 'vulnerable' -or $e.Asset.pqc_status -ceq 'unknown') { $n++ } }
    $n
}

function Get-BoabReadinessVulnerablePct {
    # f32 arithmetic, as in Readiness::vulnerable_pct.
    param([hashtable]$Data)
    $total = $Data.Scored.Count
    if ($total -eq 0) { return 0.0 }
    $vulnerable = Get-BoabReadinessVulnerableCount -Data $Data
    ConvertTo-BoabF32 ((ConvertTo-BoabF32 ([double][single]$vulnerable * 100.0)) / [double][single]$total)
}

function Test-BoabReadinessPlan {
    param([hashtable]$Data, [int]$Year)
    foreach ($p in $Data.Plans) { if ((Get-BoabMilestoneYear $p.milestone) -eq $Year) { return $true } }
    $false
}

# --- Markdown --------------------------------------------------------------------------

function ConvertTo-BoabMarkdownEscaped {
    param([AllowEmptyString()][string]$Text)
    $Text.Replace('|', '\|').Replace("`n", ' ')
}

function New-BoabMarkdownReport {
    # report::markdown::write (content only).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $data = Get-BoabReadinessData -Workspace $Workspace
    $systems = $data.Systems
    $scored = $data.Scored
    $plans = $data.Plans
    $registry = $data.Registry
    $now = $data.Now

    $total = $scored.Count
    $vulnerable = Get-BoabReadinessVulnerableCount -Data $data
    $pct = Get-BoabReadinessVulnerablePct -Data $data

    $tierCounts = [System.Collections.Generic.SortedDictionary[int, int]]::new()
    foreach ($e in $scored) {
        $t = [int]$e.Score.triage_tier
        if ($tierCounts.ContainsKey($t)) { $tierCounts[$t] = $tierCounts[$t] + 1 } else { $tierCounts[$t] = 1 }
    }
    $statusCounts = [System.Collections.Generic.SortedDictionary[string, int]]::new([System.StringComparer]::Ordinal)
    foreach ($e in $scored) {
        $k = [string]$e.Asset.pqc_status
        if ($statusCounts.ContainsKey($k)) { $statusCounts[$k] = $statusCounts[$k] + 1 } else { $statusCounts[$k] = 1 }
    }

    $md = [System.Text.StringBuilder]::new()
    $add = { param([string]$s) [void]$md.Append($s) }
    & $add "# Boab PQC Readiness Report`n`n"
    & $add ("Generated by Boab {0} at {1}.`n`n" -f $script:BoabVersion, (Format-BoabRfc3339 -Value $now.ToUniversalTime()))

    & $add "## Executive summary`n`n"
    & $add ("- Total inventory: **{0}** assets`n" -f $total)
    & $add ("- Quantum-vulnerable or unknown: **{0} ({1}%)**`n" -f $vulnerable, (Format-BoabFixed -Value $pct -Decimals 1))
    & $add ("- Systems in scope: **{0}**`n" -f $systems.Count)
    & $add ("- Plans on file: **{0}**`n`n" -f $plans.Count)

    $hasPlan = {
        param([int]$y)
        if (Test-BoabReadinessPlan -Data $data -Year $y) { 'plan drafted' } else { 'plan outstanding' }
    }
    & $add "## ASD LATICE phase status`n`n"
    & $add "| Milestone | Year | Status |`n"
    & $add "|-----------|------|--------|`n"
    & $add ("| Refined transition plan | 2026 | {0} |`n" -f (& $hasPlan 2026))
    & $add ("| Implementation begins | 2028 | {0} |`n" -f (& $hasPlan 2028))
    & $add ("| Implementation complete | 2030 | {0} |`n`n" -f (& $hasPlan 2030))

    & $add "## Top 25 priority assets`n`n"
    & $add "| # | Name | Algorithm | PQC | Priority | Tier | Recommended action |`n"
    & $add "|---|------|-----------|-----|----------|------|--------------------|`n"
    $n = [math]::Min(25, $scored.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $asset = $scored[$i].Asset; $score = $scored[$i].Score
        & $add ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |`n" -f ($i + 1),
            (ConvertTo-BoabMarkdownEscaped $asset.name),
            (ConvertTo-BoabMarkdownEscaped $asset.algorithm_name),
            $asset.pqc_status,
            (Format-BoabFixed -Value ([double]$score.priority) -Decimals 1),
            $score.triage_tier,
            (ConvertTo-BoabMarkdownEscaped $score.recommended_action))
    }
    & $add "`n"

    & $add "## Triage tier distribution`n`n"
    & $add "| Tier | Count |`n|------|-------|`n"
    foreach ($kv in $tierCounts.GetEnumerator()) { & $add ("| {0} | {1} |`n" -f $kv.Key, $kv.Value) }
    & $add "`n"

    & $add "## PQC status distribution`n`n"
    & $add "| Status | Count |`n|--------|-------|`n"
    foreach ($kv in $statusCounts.GetEnumerator()) { & $add ("| {0} | {1} |`n" -f $kv.Key, $kv.Value) }
    & $add "`n"

    & $add "## Vendor PQC dependency summary`n`n"
    & $add "| Vendor | Product | PQC | Target |`n"
    & $add "|--------|---------|-----|--------|`n"
    foreach ($e in $registry.entries) {
        $target = if ($null -ne $e.target_date) { $e.target_date } else { '-' }
        & $add ("| {0} | {1} | {2} | {3} |`n" -f (ConvertTo-BoabMarkdownEscaped $e.vendor), (ConvertTo-BoabMarkdownEscaped $e.product), $e.pqc_status, (ConvertTo-BoabMarkdownEscaped $target))
    }
    & $add "`n"

    & $add "## Plans on file`n`n"
    if ($plans.Count -eq 0) {
        & $add "(no plans generated yet)`n`n"
    }
    else {
        & $add "| Plan | Milestone | Items | Generated |`n"
        & $add "|------|-----------|-------|-----------|`n"
        foreach ($p in $plans) {
            & $add ("| {0} | {1} | {2} | {3} |`n" -f (ConvertTo-BoabMarkdownEscaped $p.name), (Get-BoabMilestoneYear $p.milestone), $p.items.Count, $p.generated_at)
        }
        & $add "`n"
    }

    & $add "## Methodology`n`n"
    & $add "Boab uses the ASD LATICE rubric. The priority score is computed as:`n`n"
    & $add "priority = round(algo_vuln * 0.30 + hndl * 0.30 + data_sens * 0.15 + sys_crit * 0.15 + mig_diff * 0.10, 1)`n`n"
    & $add "Triage tier 1 indicates an asset that must be migrated within the 2028 milestone window. Tier 2 fits comfortably inside the 2028 milestone, tier 3 within the 2029 to 2030 window, and tier 4 requires monitoring only.`n`n"
    & $add "Refer to the ASD Information Security Manual for control mappings. Boab does not map to specific ISM control IDs in v1; that work is on the v1.1 backlog.`n`n"
    & $add ("---`n`nGenerated by Boab {0}.`n" -f $script:BoabVersion)
    $md.ToString()
}

function Export-BoabMarkdownReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Path)
    $text = New-BoabMarkdownReport -Workspace $Workspace
    Write-BoabReportFile -Path $Path -Content $text
}
