# ASD LATICE scoring engine, port of src/scoring.rs. Pure functions, no I/O.
# Priority arithmetic is performed in IEEE single precision exactly like Rust's
# f32 maths (each operation rounded to f32) so scores and tiers are identical.

$script:BoabF32Weight30 = [double][single]::Parse('0.30', [System.Globalization.CultureInfo]::InvariantCulture)
$script:BoabF32Weight15 = [double][single]::Parse('0.15', [System.Globalization.CultureInfo]::InvariantCulture)
$script:BoabF32Weight10 = [double][single]::Parse('0.10', [System.Globalization.CultureInfo]::InvariantCulture)

function ConvertTo-BoabF32 {
    # Round a double to the nearest f32 and back (exact emulation of one f32 op
    # when the double result is exact or double rounding is innocuous).
    param([double]$Value)
    [double][single]$Value
}

function Get-BoabNormalisedAlgorithm {
    param([string]$Name)
    $s = ConvertTo-BoabAsciiLower $Name
    $s = $s.Replace(' ', '-').Replace('_', '-').Replace('/', '-')
    $s.Replace('--', '-')
}

function Get-BoabAssetKeySizeBits {
    # scoring::key_size_bits (`as u32` truncation preserved).
    param([System.Collections.IDictionary]$Asset)
    $ps = $Asset.parameter_set
    if (-not (Test-BoabJsonObjectLike $ps)) { return $null }
    $v = $null
    if (Test-BoabJsonHasField $ps 'key_size_bits') { $v = Get-BoabJsonField $ps 'key_size_bits' }
    elseif (Test-BoabJsonHasField $ps 'bits') { $v = Get-BoabJsonField $ps 'bits' }
    else { return $null }
    $u = Get-BoabJsonU64 $v
    if ($null -eq $u) { return $null }
    [long]([ulong]$u % [ulong]4294967296)
}

function Get-BoabAlgorithmVulnerabilityScore {
    # scoring::algo_vuln_score
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Asset)
    switch -CaseSensitive ($Asset.pqc_status) {
        'hybrid' { return 5 }
        'resistant' { return 1 }
        'symmetric_ok' { return 0 }
    }
    $algo = Get-BoabNormalisedAlgorithm -Name $Asset.algorithm_name
    $bits = Get-BoabAssetKeySizeBits -Asset $Asset
    $has = { param($s) $algo.Contains($s) }
    $starts = { param($s) $algo.StartsWith($s, [StringComparison]::Ordinal) }

    if ((& $has 'md5') -or (& $has 'md4') -or (& $has 'md2') -or (& $has 'sha-0') -or (& $has 'sha0') -or
        $algo -ceq 'sha1' -or (& $has 'sha-1') -or
        ((& $has 'rsa') -and $bits -eq 1024) -or
        ((& $has 'dsa') -and -not (& $has 'ecdsa') -and -not (& $has 'eddsa') -and $bits -eq 1024) -or
        (& $has 'rc4') -or (& $has '3des') -or (& $has 'des-') -or $algo -ceq 'des') {
        return 10
    }

    if (((& $has 'rsa') -and $bits -eq 2048) -or
        (& $has 'ecdsa-p256') -or (& $has 'ecdsa-p-256') -or $algo -ceq 'p-256' -or
        ((& $has 'ecdsa') -and (& $has '256')) -or
        ((& $has 'ecdh') -and (& $has '256')) -or
        ($algo -ceq 'dh' -and $bits -eq 2048) -or
        ((& $has 'dh-') -and $bits -eq 2048)) {
        return 9
    }

    if (((& $has 'rsa') -and ($bits -eq 3072 -or $bits -eq 4096 -or $bits -eq 8192)) -or
        (& $has 'p-384') -or (& $has 'p384') -or (& $has 'p-521') -or (& $has 'p521') -or
        ((& $has 'ecdsa') -and ((& $has '384') -or (& $has '521')))) {
        return 8
    }

    if ((& $starts 'ml-kem') -or (& $starts 'mlkem') -or (& $starts 'kyber') -or (& $starts 'ml-dsa') -or
        (& $starts 'mldsa') -or (& $starts 'dilithium') -or (& $starts 'slh-dsa') -or (& $starts 'slhdsa') -or
        (& $starts 'sphincs') -or (& $has 'falcon') -or (& $starts 'hqc')) {
        return 1
    }

    if ((& $has 'aes-256') -or $algo -ceq 'aes256' -or
        ((& $has 'aes') -and ((& $has 'gcm') -or (& $has 'ccm')) -and ($null -ne $bits -and $bits -ge 256)) -or
        (& $has 'sha-256') -or (& $has 'sha256') -or (& $has 'sha-384') -or (& $has 'sha384') -or
        (& $has 'sha-512') -or (& $has 'sha512') -or (& $has 'sha3-') -or (& $has 'shake') -or
        (& $has 'chacha20') -or (& $has 'poly1305') -or (& $has 'hmac-sha256') -or (& $has 'hmac-sha384') -or
        (& $has 'hmac-sha512')) {
        return 0
    }

    if ((& $has 'rsa') -or (& $has 'ecdsa') -or (& $has 'ecdh') -or (& $has 'dh') -or (& $has 'dsa') -or
        (& $has 'ed25519') -or (& $has 'ed448') -or (& $has 'x25519') -or (& $has 'x448')) {
        if ((& $has 'ed25519') -or (& $has 'x25519')) { return 8 }
        if ((& $has 'ed448') -or (& $has 'x448')) { return 8 }
        return 9
    }
    7
}

function Get-BoabDataSensitivityScore {
    # scoring::data_sens_score
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Asset)
    switch -CaseSensitive ([string]$Asset.data_classification) {
        'top_secret' { return 10 }
        'secret' { return 8 }
        'protected' { return 6 }
        'official_sensitive' { return 4 }
        'official' { return 2 }
    }
    0
}

function Get-BoabHndlScore {
    # scoring::hndl_score
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Asset,
        [Parameter(Mandatory)][int]$CurrentYear,
        [AllowNull()]$System
    )
    $years = $null
    if ($null -ne $Asset.data_retention_horizon_year) {
        $years = [math]::Max(0, [long]$Asset.data_retention_horizon_year - $CurrentYear)
    }
    elseif ($null -ne $System) {
        $years = $System.expected_data_lifetime_years
    }
    if ($null -eq $years) { return 5 }
    if ($years -ge 15) { return 10 }
    if ($years -ge 10) { return 8 }
    if ($years -ge 5) { return 6 }
    if ($years -ge 2) { return 3 }
    0
}

function Get-BoabSystemCriticalityScore {
    # scoring::system_crit_score
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()]$System)
    if ($null -eq $System) { return 4 }
    if ($System.criticality -ceq 'mission_critical' -or $System.is_soci) { return 10 }
    if ($System.criticality -ceq 'essential') { return 7 }
    if ($System.criticality -ceq 'standard') { return 4 }
    1
}

function Get-BoabMigrationDifficultyScore {
    # scoring::mig_diff_score
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Asset)
    switch -CaseSensitive ($Asset.migration_difficulty) {
        'hardware_locked' { return 10 }
        'high' { return 8 }
        'medium' { return 6 }
        'low' { return 3 }
    }
    1
}

function Get-BoabPriority {
    # scoring::priority, computed with f32 semantics. Returns [single].
    [CmdletBinding()]
    [OutputType([single])]
    param([int]$AlgoVuln, [int]$Hndl, [int]$DataSens, [int]$SysCrit, [int]$MigDiff)
    $t1 = ConvertTo-BoabF32 ($AlgoVuln * $script:BoabF32Weight30)
    $t2 = ConvertTo-BoabF32 ($Hndl * $script:BoabF32Weight30)
    $t3 = ConvertTo-BoabF32 ($DataSens * $script:BoabF32Weight15)
    $t4 = ConvertTo-BoabF32 ($SysCrit * $script:BoabF32Weight15)
    $t5 = ConvertTo-BoabF32 ($MigDiff * $script:BoabF32Weight10)
    $raw = ConvertTo-BoabF32 ($t1 + $t2)
    $raw = ConvertTo-BoabF32 ($raw + $t3)
    $raw = ConvertTo-BoabF32 ($raw + $t4)
    $raw = ConvertTo-BoabF32 ($raw + $t5)
    $scaled = ConvertTo-BoabF32 ($raw * 10.0)
    $rounded = [math]::Round($scaled, [System.MidpointRounding]::AwayFromZero)
    [single](ConvertTo-BoabF32 ($rounded / 10.0))
}

function Get-BoabTriageTier {
    # scoring::triage_tier
    [CmdletBinding()]
    [OutputType([int])]
    param([double]$Priority, [int]$MigDiff, [int]$AlgoVuln)
    if ($Priority -ge 7.0 -and $MigDiff -le 6) { return 1 }
    if ($Priority -ge 6.0 -or ($MigDiff -ge 7 -and $AlgoVuln -ge 8)) { return 2 }
    if ($AlgoVuln -ge 7) { return 3 }
    4
}

function Get-BoabRecommendedAction {
    # scoring::recommended_action
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Tier, [string]$AssetType)
    $table = @{
        '1|certificate'        = 'Reissue with ML-DSA-65 before end of 2028'
        '1|key'                = 'Rotate to ML-KEM-768 or ML-DSA-65 key material before end of 2028'
        '1|algorithm'          = 'Replace algorithm with NIST FIPS 203/204/205 equivalent before end of 2028'
        '1|protocol_endpoint'  = 'Migrate endpoint to TLS 1.3 with PQ hybrid KEM by end of 2028'
        '1|library_dependency' = 'Upgrade dependency to PQC-capable build immediately and pin version'
        '2|certificate'        = 'Plan certificate reissuance with ML-DSA before end of 2028'
        '2|key'                = 'Schedule key rotation to PQC equivalent inside the 2028 milestone'
        '2|algorithm'          = 'Schedule algorithm replacement inside the 2028 milestone window'
        '2|protocol_endpoint'  = 'Plan TLS 1.3 hybrid KEM rollout inside the 2028 milestone window'
        '2|library_dependency' = 'Upgrade to vendor PQC build when GA; verify roadmap'
        '3|certificate'        = 'Track certificate for replacement during the 2029 to 2030 rollout window'
        '3|key'                = 'Track key for rotation during the 2029 to 2030 rollout window'
        '3|algorithm'          = 'Plan replacement during the 2029 to 2030 rollout window'
        '3|protocol_endpoint'  = 'Plan TLS 1.3 hybrid KEM rollout for 2029-2030'
        '3|library_dependency' = 'Track vendor PQC roadmap; upgrade before 2030'
        '4|certificate'        = 'Monitor; reassess if classification or retention changes'
        '4|key'                = 'Monitor; reassess if classification or retention changes'
        '4|algorithm'          = 'Monitor; no immediate action required'
        '4|protocol_endpoint'  = 'Monitor; no immediate action required'
        '4|library_dependency' = 'Monitor vendor roadmap; no immediate action required'
    }
    $t = if ($Tier -ge 1 -and $Tier -le 3) { $Tier } else { 4 }
    $table["$t|$AssetType"]
}

function Get-BoabRiskScore {
    # scoring::score_asset. Returns an [ordered] RiskScore record.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Asset,
        [AllowNull()]$System,
        [int]$CurrentYear = (Get-BoabNow).UtcDateTime.Year
    )
    $algo = Get-BoabAlgorithmVulnerabilityScore -Asset $Asset
    $data = Get-BoabDataSensitivityScore -Asset $Asset
    $hndl = Get-BoabHndlScore -Asset $Asset -CurrentYear $CurrentYear -System $System
    $crit = Get-BoabSystemCriticalityScore -System $System
    $mig = Get-BoabMigrationDifficultyScore -Asset $Asset
    $priority = Get-BoabPriority -AlgoVuln $algo -Hndl $hndl -DataSens $data -SysCrit $crit -MigDiff $mig
    $tier = Get-BoabTriageTier -Priority $priority -MigDiff $mig -AlgoVuln $algo
    [ordered]@{
        algorithm_vulnerability   = $algo
        data_sensitivity          = $data
        harvest_now_decrypt_later = $hndl
        system_criticality        = $crit
        migration_difficulty      = $mig
        priority                  = $priority
        triage_tier               = $tier
        recommended_action        = Get-BoabRecommendedAction -Tier $tier -AssetType $Asset.asset_type
    }
}

function Find-BoabSystemById {
    param($Systems, $Id)
    if ($null -eq $Id) { return $null }
    foreach ($s in $Systems) { if ($s.id -ceq $Id) { return $s } }
    $null
}
