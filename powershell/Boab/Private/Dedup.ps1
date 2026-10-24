# Finding -> inventory promotion, port of src/dedup.rs.

function Get-BoabSourceRoot {
    # dedup::source_root_of
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$SourceLocation)
    $pathOnly = $SourceLocation
    $idx = $SourceLocation.LastIndexOf([char]':')
    if ($idx -ge 0) { $pathOnly = $SourceLocation.Substring(0, $idx) }
    $comp = Get-BoabFirstPathComponent -Path $pathOnly
    if ($null -eq $comp) { return $pathOnly }
    $comp
}

function ConvertFrom-BoabPrimitiveName {
    param($Value)
    if ($Value -is [string] -and $script:BoabEnums.Primitive -ccontains $Value) { return $Value }
    $null
}

function ConvertFrom-BoabPqcStatusValue {
    # dedup::parse_pqc_status
    param($Value)
    if ($Value -is [string] -and @('vulnerable', 'hybrid', 'resistant', 'symmetric_ok') -ccontains $Value) { return $Value }
    'unknown'
}

function Get-BoabFindingKey {
    # dedup::finding_dedup_key. Returns a hashtable describing the asset to create.
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Finding)
    $ev = $Finding.evidence
    $kind = Get-BoabJsonStr (Get-BoabJsonField $ev 'kind')
    if ($null -eq $kind) { $kind = '' }
    $sourceRoot = Get-BoabSourceRoot -SourceLocation $Finding.source_location
    $key = @{
        DedupKey = $null; AssetType = 'algorithm'; AlgorithmName = 'unknown'; PqcStatus = 'unknown'
        Primitive = $null; KeySizeBits = $null; SourceRoot = $sourceRoot; LibraryName = $null
    }
    switch -CaseSensitive ($kind) {
        'cert_or_keystore_file' {
            $path = Resolve-BoabFullPath -Path $Finding.source_location
            $bytes = [byte[]]@()
            try { $bytes = [System.IO.File]::ReadAllBytes($path) } catch { $bytes = [byte[]]@() }
            $key.DedupKey = 'cert:' + (Get-BoabSha256Hex -Bytes $bytes)
            $key.AssetType = 'certificate'
            $key.AlgorithmName = 'x509'
            return $key
        }
        'algorithm_match' {
            $algo = Get-BoabJsonStr (Get-BoabJsonField $ev 'algorithm_name')
            if ($null -eq $algo) { $algo = 'unknown' }
            $pqc = ConvertFrom-BoabPqcStatusValue (Get-BoabJsonField $ev 'pqc_status')
            $params = Get-BoabJsonField $ev 'parameter_set'
            if (-not (Test-BoabJsonHasField $ev 'parameter_set')) { $params = [ordered]@{} }
            $primitive = ConvertFrom-BoabPrimitiveName (Get-BoabJsonStr (Get-BoabJsonField $params 'primitive'))
            $bits = Get-BoabJsonU64 (Get-BoabJsonField $params 'key_size_bits')
            $bitsText = if ($null -ne $bits) { $bits.ToString([System.Globalization.CultureInfo]::InvariantCulture) } else { '_' }
            $key.DedupKey = 'algo:{0}:{1}:{2}' -f (ConvertTo-BoabAsciiLower $algo), $bitsText, $sourceRoot
            $key.AlgorithmName = $algo
            $key.PqcStatus = $pqc
            $key.Primitive = $primitive
            $key.KeySizeBits = $bits
            return $key
        }
        'library_import' {
            $lib = Get-BoabJsonStr (Get-BoabJsonField $ev 'library_name')
            if ($null -eq $lib) { $lib = 'unknown' }
            $key.DedupKey = 'lib:{0}:{1}' -f (ConvertTo-BoabAsciiLower $lib), $sourceRoot
            $key.AssetType = 'library_dependency'
            $key.AlgorithmName = $lib
            $key.LibraryName = $lib
            return $key
        }
        'tls_certificate' {
            $fp = Get-BoabJsonStr (Get-BoabJsonField $ev 'fingerprint_sha256')
            if ($null -eq $fp) { $fp = '' }
            $sig = Get-BoabJsonStr (Get-BoabJsonField $ev 'signature_algorithm')
            if ($null -eq $sig) { $sig = 'x509' }
            $key.DedupKey = 'cert:' + $fp
            $key.AssetType = 'certificate'
            $key.AlgorithmName = $sig
            $key.PqcStatus = ConvertFrom-BoabPqcStatusValue (Get-BoabJsonField $ev 'pqc_status')
            $key.Primitive = 'signature'
            $key.KeySizeBits = Get-BoabJsonU64 (Get-BoabJsonField $ev 'public_key_bits')
            return $key
        }
        'tls_endpoint' {
            $suite = Get-BoabJsonStr (Get-BoabJsonField $ev 'cipher_suite')
            if ($null -eq $suite) { $suite = 'unknown' }
            $key.DedupKey = 'tls_endpoint:{0}:{1}' -f $Finding.source_location, $suite
            $key.AssetType = 'protocol_endpoint'
            $key.AlgorithmName = $suite
            $key.PqcStatus = ConvertFrom-BoabPqcStatusValue (Get-BoabJsonField $ev 'pqc_status')
            return $key
        }
        'tls_supported_group' {
            $group = Get-BoabJsonStr (Get-BoabJsonField $ev 'group')
            if ($null -eq $group) { $group = 'unknown' }
            $key.DedupKey = 'tls_group:{0}:{1}' -f $Finding.source_location, $group
            $key.AssetType = 'protocol_endpoint'
            $key.AlgorithmName = $group
            $key.PqcStatus = ConvertFrom-BoabPqcStatusValue (Get-BoabJsonField $ev 'pqc_status')
            $key.Primitive = 'kem'
            return $key
        }
    }
    $key.DedupKey = 'other:' + $Finding.source_location
    $key
}

function Get-BoabAssetDedupKey {
    # dedup::asset_dedup_key (no source-root override).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Asset)
    $ps = $Asset.parameter_set
    $keySize = Get-BoabJsonU64 (Get-BoabJsonField $ps 'key_size_bits')
    $root = Get-BoabJsonStr (Get-BoabJsonField $ps 'source_root')
    if ($null -eq $root) { $root = '_' }
    switch -CaseSensitive ($Asset.asset_type) {
        'algorithm' {
            $ks = if ($null -ne $keySize) { $keySize.ToString([System.Globalization.CultureInfo]::InvariantCulture) } else { '_' }
            return ('algo:{0}:{1}:{2}' -f (ConvertTo-BoabAsciiLower $Asset.algorithm_name), $ks, $root)
        }
        'certificate' {
            $fp = Get-BoabJsonStr (Get-BoabJsonField $ps 'fingerprint_sha256')
            if ($null -eq $fp) { $fp = $Asset.name }
            return ('cert:' + $fp)
        }
        'library_dependency' {
            return ('lib:{0}:{1}' -f (ConvertTo-BoabAsciiLower $Asset.algorithm_name), $root)
        }
        'protocol_endpoint' {
            $kind = if ((Get-BoabJsonStr (Get-BoabJsonField $ps 'kind')) -ceq 'tls_supported_group') { 'tls_group' } else { 'tls_endpoint' }
            $target = Get-BoabJsonStr (Get-BoabJsonField $ps 'target')
            if ($null -eq $target) { $target = $Asset.name }
            return ('{0}:{1}:{2}' -f $kind, $target, $Asset.algorithm_name)
        }
        'key' { return ('key:' + $Asset.name) }
    }
    ''
}

function Get-BoabMigrationDifficultyFor {
    param([string]$AssetType, [string]$PqcStatus)
    switch -CaseSensitive ($AssetType) {
        'certificate' { return 'medium' }
        'key' { return 'medium' }
        'library_dependency' { return 'low' }
        'protocol_endpoint' { return 'medium' }
    }
    if ($PqcStatus -ceq 'symmetric_ok' -or $PqcStatus -ceq 'resistant') { return 'trivial' }
    'medium'
}

function New-BoabAssetFromFinding {
    # dedup::build_asset_from_finding
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        [Parameter(Mandatory)][hashtable]$Key
    )
    $quantumVulnerable = @('vulnerable', 'unknown', 'hybrid') -ccontains $Key.PqcStatus
    $mig = Get-BoabMigrationDifficultyFor -AssetType $Key.AssetType -PqcStatus $Key.PqcStatus
    switch -CaseSensitive ($Key.AssetType) {
        'library_dependency' { $display = if ($null -ne $Key.LibraryName) { $Key.LibraryName } else { $Key.AlgorithmName } }
        'certificate' { $display = $Finding.source_location }
        'protocol_endpoint' { $display = '{0}@{1}' -f $Key.AlgorithmName, $Key.SourceRoot }
        default { $display = $Key.AlgorithmName }
    }
    $params = [ordered]@{}
    if ($null -ne $Key.KeySizeBits) { $params['key_size_bits'] = $Key.KeySizeBits }
    if ($null -ne $Key.Primitive) { $params['primitive'] = Get-BoabDebugLower $Key.Primitive }
    $params['source_root'] = $Key.SourceRoot
    $ev = $Finding.evidence
    $extra = Get-BoabJsonField $ev 'parameter_set'
    if ($extra -is [System.Collections.IDictionary]) {
        foreach ($k in @($extra.Keys)) {
            if (-not $params.Contains($k)) { $params[$k] = Copy-BoabJsonValue $extra[$k] }
        }
    }
    $target = Get-BoabJsonStr (Get-BoabJsonField $ev 'target')
    if ($null -ne $target) { $params['target'] = $target }
    $fp = Get-BoabJsonStr (Get-BoabJsonField $ev 'fingerprint_sha256')
    if ($null -ne $fp) { $params['fingerprint_sha256'] = $fp }

    $asset = New-BoabCryptoAssetRecord -AssetType $Key.AssetType -AlgorithmName $Key.AlgorithmName -Name $display `
        -PqcStatus $Key.PqcStatus -QuantumVulnerable $quantumVulnerable -MigrationDifficulty $mig
    $asset.primitive = $Key.Primitive
    $asset.parameter_set = $params
    $now = Get-BoabTimestamp
    $asset.first_seen_at = $now
    $asset.last_seen_at = $now
    $asset
}

function Merge-BoabFindingIntoInventory {
    # dedup::promote_findings. Mutates the findings' crypto_asset_id and returns
    # the merged inventory list.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Scan,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Inventory
    )
    $now = Get-BoabTimestamp
    $inv = New-BoabList $Inventory
    # Case-sensitive, like Rust's BTreeMap<String, usize>.
    $index = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    for ($i = 0; $i -lt $inv.Count; $i++) { $index[(Get-BoabAssetDedupKey -Asset $inv[$i])] = $i }
    foreach ($finding in $Scan.findings) {
        $keyData = Get-BoabFindingKey -Finding $finding
        $k = $keyData.DedupKey
        if ($index.ContainsKey($k)) {
            $existing = $inv[$index[$k]]
            $existing.last_seen_at = $now
            $finding.crypto_asset_id = $existing.id
            continue
        }
        $asset = New-BoabAssetFromFinding -Finding $finding -Key $keyData
        $finding.crypto_asset_id = $asset.id
        $newKey = Get-BoabAssetDedupKey -Asset $asset
        $inv.Add($asset)
        $index[$newKey] = $inv.Count - 1
    }
    , $inv
}

function Invoke-BoabPromotion {
    # dedup::promote_into_workspace: load inventory, merge, persist.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Workspace,
        [Parameter(Mandatory)]$Scan
    )
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $updated = Merge-BoabFindingIntoInventory -Scan $Scan -Inventory $inventory
    Save-BoabStoredInventory -Workspace $Workspace -Inventory $updated
    , $updated
}
