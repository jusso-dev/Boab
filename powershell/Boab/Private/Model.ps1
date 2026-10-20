# Data model (src/model/*). Records are [ordered] hashtables whose key order is
# the Rust struct field order, so ConvertTo-BoabJson output matches serde.
# Enum values are serde snake_case strings.

$script:BoabEnums = @{
    AssetType           = @('algorithm', 'certificate', 'key', 'protocol_endpoint', 'library_dependency')
    Primitive           = @('block_cipher', 'stream_cipher', 'hash', 'signature', 'key_agreement', 'kem', 'pke', 'mac', 'drbg')
    PqcStatus           = @('vulnerable', 'hybrid', 'resistant', 'symmetric_ok', 'unknown')
    MigrationDifficulty = @('trivial', 'low', 'medium', 'high', 'hardware_locked')
    MigrationStatus     = @('not_started', 'planned', 'in_progress', 'migrated', 'not_applicable')
    TargetMilestone     = @('y2026', 'y2028', 'y2030')
    Classification      = @('unofficial', 'official', 'official_sensitive', 'protected', 'secret', 'top_secret')
    Criticality         = @('low', 'standard', 'essential', 'mission_critical')
    SourceType          = @('file', 'url', 'cert_subject', 'host')
    Confidence          = @('low', 'medium', 'high')
    FindingStatus       = @('new', 'confirmed', 'false_positive', 'ignored')
    ScanType            = @('codebase', 'tls_endpoint', 'certificate_store')
    ScanStatus          = @('queued', 'running', 'completed', 'failed', 'cancelled')
    PlanItemStatus      = @('pending', 'in_progress', 'complete', 'deferred', 'not_applicable')
}

function Get-BoabDebugName {
    # Rust `format!("{:?}", variant)` for a unit enum: PascalCase variant name.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$SnakeValue)
    -join ($SnakeValue.Split('_') | ForEach-Object { if ($_.Length) { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) } })
}

function Get-BoabDebugLower {
    # `format!("{:?}", variant).to_ascii_lowercase()` e.g. symmetric_ok -> symmetricok.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$SnakeValue)
    $SnakeValue.Replace('_', '')
}

function ConvertFrom-BoabClassification {
    # Classification::parse
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    switch -CaseSensitive (ConvertTo-BoabAsciiLower $Value) {
        'unofficial' { return 'unofficial' }
        'official' { return 'official' }
        'official_sensitive' { return 'official_sensitive' }
        'official-sensitive' { return 'official_sensitive' }
        'protected' { return 'protected' }
        'secret' { return 'secret' }
        'top_secret' { return 'top_secret' }
        'top-secret' { return 'top_secret' }
    }
    $null
}

function ConvertFrom-BoabCriticality {
    # Criticality::parse
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    switch -CaseSensitive (ConvertTo-BoabAsciiLower $Value) {
        'low' { return 'low' }
        'standard' { return 'standard' }
        'essential' { return 'essential' }
        'mission_critical' { return 'mission_critical' }
        'mission-critical' { return 'mission_critical' }
    }
    $null
}

function ConvertFrom-BoabMilestone {
    # TargetMilestone::parse
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    switch -CaseSensitive ($Value.Trim()) {
        '2026' { return 'y2026' }
        '2028' { return 'y2028' }
        '2030' { return 'y2030' }
    }
    $null
}

function Get-BoabMilestoneYear {
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Milestone)
    [int]$Milestone.Substring(1)
}

# --- serde-like field readers -------------------------------------------------

function Get-BoabRequiredField {
    param($Object, [string]$Key)
    if (-not (Test-BoabJsonHasField $Object $Key)) { throw (New-BoabException ("missing field ``{0}``" -f $Key)) }
    , (Get-BoabJsonField $Object $Key)
}

function Read-BoabStringField {
    param($Object, [string]$Key, [switch]$Optional)
    if ($Optional -and -not (Test-BoabJsonHasField $Object $Key)) { return $null }
    $v = Get-BoabRequiredField $Object $Key
    if ($null -eq $v) {
        if ($Optional) { return $null }
        throw (New-BoabException 'invalid type: null, expected a string')
    }
    if ($v -isnot [string]) { throw (New-BoabException ("invalid type: {0}, expected a string" -f (Get-BoabSerdeTypeName $v))) }
    $v
}

function Read-BoabUuidField {
    param($Object, [string]$Key, [switch]$Optional)
    $v = Read-BoabStringField $Object $Key -Optional:$Optional
    if ($null -eq $v) { return $null }
    try { ConvertFrom-BoabUuidText -Text $v }
    catch { throw (New-BoabException ("UUID parsing failed: {0}" -f (Get-BoabErrorMessage $_))) }
}

function Read-BoabEnumField {
    param($Object, [string]$Key, [string]$EnumName, [switch]$Optional)
    $v = Read-BoabStringField $Object $Key -Optional:$Optional
    if ($null -eq $v) { return $null }
    $allowed = $script:BoabEnums[$EnumName]
    if ($allowed -cnotcontains $v) {
        throw (New-BoabException ("unknown variant ``{0}``, expected one of {1}" -f $v, (($allowed | ForEach-Object { '`' + $_ + '`' }) -join ', ')))
    }
    $v
}

function Read-BoabBoolField {
    param($Object, [string]$Key)
    $v = Get-BoabRequiredField $Object $Key
    if ($v -isnot [bool]) { throw (New-BoabException ("invalid type: {0}, expected a boolean" -f (Get-BoabSerdeTypeName $v))) }
    $v
}

function Read-BoabUIntField {
    param($Object, [string]$Key, [ulong]$Max, [switch]$Optional)
    if ($Optional -and -not (Test-BoabJsonHasField $Object $Key)) { return $null }
    $v = Get-BoabRequiredField $Object $Key
    if ($null -eq $v -and $Optional) { return $null }
    $u = Get-BoabJsonU64 $v
    if ($null -eq $u) { throw (New-BoabException ("invalid type: {0}, expected an unsigned integer" -f (Get-BoabSerdeTypeName $v))) }
    if ($u -gt $Max) { throw (New-BoabException ("invalid value: integer ``{0}``, expected u{1}" -f $u, $(if ($Max -eq 255) { 8 } elseif ($Max -eq 65535) { 16 } elseif ($Max -eq 4294967295) { 32 } else { 64 }))) }
    [long]$u
}

function Read-BoabF32Field {
    param($Object, [string]$Key)
    $v = Get-BoabRequiredField $Object $Key
    if ($v -is [single]) { return $v }
    if ($v -is [double] -or $v -is [long] -or $v -is [ulong] -or $v -is [int]) { return [single][double]$v }
    throw (New-BoabException ("invalid type: {0}, expected f32" -f (Get-BoabSerdeTypeName $v)))
}

function Read-BoabTimeField {
    param($Object, [string]$Key, [switch]$Optional, [switch]$Iso8601)
    $v = $null
    if ($Optional) {
        if (-not (Test-BoabJsonHasField $Object $Key)) { return $null }
        $v = Get-BoabJsonField $Object $Key
        if ($null -eq $v) { return $null }
    }
    else {
        $v = Get-BoabRequiredField $Object $Key
    }
    if ($v -isnot [string]) { throw (New-BoabException ("invalid type: {0}, expected a timestamp string" -f (Get-BoabSerdeTypeName $v))) }
    if ($Iso8601) { return ConvertTo-BoabCanonicalIso8601 -Text $v }
    ConvertTo-BoabCanonicalRfc3339 -Text $v
}

function Read-BoabValueField {
    # serde_json::Value field: a missing field deserialises as null.
    param($Object, [string]$Key)
    if (-not (Test-BoabJsonHasField $Object $Key)) { return $null }
    , (Copy-BoabJsonValue (Get-BoabJsonField $Object $Key))
}

function Read-BoabArrayField {
    param($Object, [string]$Key)
    $v = Get-BoabRequiredField $Object $Key
    if ($v -is [string] -or $v -isnot [System.Collections.IEnumerable] -or (Test-BoabJsonObjectLike $v)) {
        throw (New-BoabException ("invalid type: {0}, expected a sequence" -f (Get-BoabSerdeTypeName $v)))
    }
    , $v
}

function Get-BoabSerdeTypeName {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return ('boolean `{0}`' -f $(if ($Value) { 'true' } else { 'false' })) }
    if ($Value -is [string]) { return ('string "{0}"' -f $Value) }
    if ($Value -is [double]) { return ('floating point `{0}`' -f (Format-BoabF64 $Value)) }
    if ($Value -is [long] -and $Value -lt 0) { return ('integer `{0}`' -f $Value) }
    if ($Value -is [long] -or $Value -is [ulong] -or $Value -is [int]) { return ('integer `{0}`' -f $Value) }
    if (Test-BoabJsonObjectLike $Value) { return 'map' }
    'sequence'
}

# --- constructors -------------------------------------------------------------

function New-BoabSystemRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Description,
        [Parameter(Mandatory)][string]$Classification,
        [Parameter(Mandatory)][string]$Criticality,
        [bool]$IsSoci,
        [AllowNull()][Nullable[int]]$ExpectedDataLifetimeYears
    )
    $desc = if ($PSBoundParameters.ContainsKey('Description') -and $null -ne $Description) { $Description } else { $null }
    $life = if ($null -ne $ExpectedDataLifetimeYears) { [long]$ExpectedDataLifetimeYears } else { $null }
    [ordered]@{
        id                           = New-BoabUuid
        name                         = $Name
        description                  = $desc
        classification               = $Classification
        criticality                  = $Criticality
        is_soci                      = $IsSoci
        expected_data_lifetime_years = $life
        created_at                   = Get-BoabTimestamp
    }
}

function New-BoabCryptoAssetRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AssetType,
        [Parameter(Mandatory)][AllowEmptyString()][string]$AlgorithmName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][string]$PqcStatus,
        [bool]$QuantumVulnerable,
        [Parameter(Mandatory)][string]$MigrationDifficulty
    )
    $now = Get-BoabTimestamp
    [ordered]@{
        id                          = New-BoabUuid
        asset_type                  = $AssetType
        algorithm_name              = $AlgorithmName
        algorithm_oid               = $null
        primitive                   = $null
        parameter_set               = [ordered]@{}
        pqc_status                  = $PqcStatus
        quantum_vulnerable          = $QuantumVulnerable
        name                        = $Name
        description                 = $null
        system_id                   = $null
        data_classification         = $null
        data_retention_horizon_year = $null
        migration_difficulty        = $MigrationDifficulty
        migration_status            = 'not_started'
        target_milestone            = $null
        tags                        = (New-BoabList)
        first_seen_at               = $now
        last_seen_at                = $now
        notes                       = $null
    }
}

function New-BoabPlanRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Milestone)
    [ordered]@{
        id           = New-BoabUuid
        name         = $Name
        milestone    = $Milestone
        generated_at = Get-BoabTimestamp
        items        = (New-BoabList)
    }
}

# --- normalisers (deserialise into canonical records) ---------------------------

function ConvertTo-BoabSystemRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    [ordered]@{
        id                           = Read-BoabUuidField $o 'id'
        name                         = Read-BoabStringField $o 'name'
        description                  = Read-BoabStringField $o 'description' -Optional
        classification               = Read-BoabEnumField $o 'classification' 'Classification'
        criticality                  = Read-BoabEnumField $o 'criticality' 'Criticality'
        is_soci                      = Read-BoabBoolField $o 'is_soci'
        expected_data_lifetime_years = Read-BoabUIntField $o 'expected_data_lifetime_years' -Max 65535 -Optional
        created_at                   = Read-BoabTimeField $o 'created_at'
    }
}

function ConvertTo-BoabCryptoAssetRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    $tags = New-BoabList
    foreach ($t in (Read-BoabArrayField $o 'tags')) {
        if ($t -isnot [string]) { throw (New-BoabException ("invalid type: {0}, expected a string" -f (Get-BoabSerdeTypeName $t))) }
        $tags.Add($t)
    }
    [ordered]@{
        id                          = Read-BoabUuidField $o 'id'
        asset_type                  = Read-BoabEnumField $o 'asset_type' 'AssetType'
        algorithm_name              = Read-BoabStringField $o 'algorithm_name'
        algorithm_oid               = Read-BoabStringField $o 'algorithm_oid' -Optional
        primitive                   = Read-BoabEnumField $o 'primitive' 'Primitive' -Optional
        parameter_set               = Read-BoabValueField $o 'parameter_set'
        pqc_status                  = Read-BoabEnumField $o 'pqc_status' 'PqcStatus'
        quantum_vulnerable          = Read-BoabBoolField $o 'quantum_vulnerable'
        name                        = Read-BoabStringField $o 'name'
        description                 = Read-BoabStringField $o 'description' -Optional
        system_id                   = Read-BoabUuidField $o 'system_id' -Optional
        data_classification         = Read-BoabEnumField $o 'data_classification' 'Classification' -Optional
        data_retention_horizon_year = Read-BoabUIntField $o 'data_retention_horizon_year' -Max 65535 -Optional
        migration_difficulty        = Read-BoabEnumField $o 'migration_difficulty' 'MigrationDifficulty'
        migration_status            = Read-BoabEnumField $o 'migration_status' 'MigrationStatus'
        target_milestone            = Read-BoabEnumField $o 'target_milestone' 'TargetMilestone' -Optional
        tags                        = $tags
        first_seen_at               = Read-BoabTimeField $o 'first_seen_at'
        last_seen_at                = Read-BoabTimeField $o 'last_seen_at'
        notes                       = Read-BoabStringField $o 'notes' -Optional
    }
}

function ConvertTo-BoabFindingRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    [ordered]@{
        id              = Read-BoabUuidField $o 'id'
        scan_id         = Read-BoabUuidField $o 'scan_id'
        crypto_asset_id = Read-BoabUuidField $o 'crypto_asset_id' -Optional
        source_type     = Read-BoabEnumField $o 'source_type' 'SourceType'
        source_location = Read-BoabStringField $o 'source_location'
        evidence        = Read-BoabValueField $o 'evidence'
        confidence      = Read-BoabEnumField $o 'confidence' 'Confidence'
        status          = Read-BoabEnumField $o 'status' 'FindingStatus'
        discovered_at   = Read-BoabTimeField $o 'discovered_at'
    }
}

function ConvertTo-BoabScanRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    $findings = New-BoabList
    foreach ($f in (Read-BoabArrayField $o 'findings')) { $findings.Add((ConvertTo-BoabFindingRecord -InputObject $f)) }
    [ordered]@{
        id            = Read-BoabUuidField $o 'id'
        name          = Read-BoabStringField $o 'name'
        scan_type     = Read-BoabEnumField $o 'scan_type' 'ScanType'
        status        = Read-BoabEnumField $o 'status' 'ScanStatus'
        target        = Read-BoabStringField $o 'target'
        config        = Read-BoabValueField $o 'config'
        started_at    = Read-BoabTimeField $o 'started_at'
        completed_at  = Read-BoabTimeField $o 'completed_at' -Optional
        findings      = $findings
        error_message = Read-BoabStringField $o 'error_message' -Optional
    }
}

function ConvertTo-BoabPlanItemRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    [ordered]@{
        id              = Read-BoabUuidField $o 'id'
        crypto_asset_id = Read-BoabUuidField $o 'crypto_asset_id'
        asset_name      = Read-BoabStringField $o 'asset_name'
        algorithm_name  = Read-BoabStringField $o 'algorithm_name'
        triage_tier     = Read-BoabUIntField $o 'triage_tier' -Max 255
        priority        = Read-BoabF32Field $o 'priority'
        target_action   = Read-BoabStringField $o 'target_action'
        target_date     = Read-BoabTimeField $o 'target_date' -Optional -Iso8601
        assignee        = Read-BoabStringField $o 'assignee' -Optional
        notes           = Read-BoabStringField $o 'notes' -Optional
        status          = Read-BoabEnumField $o 'status' 'PlanItemStatus'
    }
}

function ConvertTo-BoabPlanRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    $items = New-BoabList
    foreach ($i in (Read-BoabArrayField $o 'items')) { $items.Add((ConvertTo-BoabPlanItemRecord -InputObject $i)) }
    [ordered]@{
        id           = Read-BoabUuidField $o 'id'
        name         = Read-BoabStringField $o 'name'
        milestone    = Read-BoabEnumField $o 'milestone' 'TargetMilestone'
        generated_at = Read-BoabTimeField $o 'generated_at'
        items        = $items
    }
}

function ConvertTo-BoabVendorEntryRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $o = $InputObject
    [ordered]@{
        vendor           = Read-BoabStringField $o 'vendor'
        product          = Read-BoabStringField $o 'product'
        pqc_status       = Read-BoabEnumField $o 'pqc_status' 'PqcStatus'
        target_date      = Read-BoabStringField $o 'target_date' -Optional
        source_url       = Read-BoabStringField $o 'source_url' -Optional
        source_note      = Read-BoabStringField $o 'source_note' -Optional
        last_verified_at = Read-BoabTimeField $o 'last_verified_at' -Optional
    }
}

function ConvertTo-BoabVendorRegistryRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject)
    $entries = New-BoabList
    foreach ($e in (Read-BoabArrayField $InputObject 'entries')) { $entries.Add((ConvertTo-BoabVendorEntryRecord -InputObject $e)) }
    [ordered]@{ entries = $entries }
}

function ConvertTo-BoabRecordList {
    # Deserialise a JSON array of records with the given converter.
    param($Parsed, [string]$Converter)
    if ($null -eq $Parsed -or $Parsed -is [string] -or (Test-BoabJsonObjectLike $Parsed) -or $Parsed -isnot [System.Collections.IEnumerable]) {
        throw (New-BoabException ("invalid type: {0}, expected a sequence" -f (Get-BoabSerdeTypeName $Parsed)))
    }
    $list = New-BoabList
    foreach ($item in $Parsed) { $list.Add((& $Converter -InputObject $item)) }
    , $list
}
