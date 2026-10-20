# Vendor PQC registry (src/vendor.rs + src/model/vendor.rs).

$script:BoabBundledRegistryPath = Join-Path (Split-Path -Parent $PSScriptRoot) (Join-Path 'Data' 'vendor-pqc-registry.json')

function Get-BoabBundledVendorRegistry {
    # vendor::load_bundled
    [CmdletBinding()]
    param()
    try {
        $text = Read-BoabTextFile -Path $script:BoabBundledRegistryPath
        ConvertTo-BoabVendorRegistryRecord -InputObject (ConvertFrom-BoabJson -Json $text)
    }
    catch {
        throw (New-BoabException ("parse bundled vendor PQC registry: {0}" -f (Get-BoabErrorMessage $_)))
    }
}

function Get-BoabVendorKey {
    param([System.Collections.IDictionary]$Entry)
    (ConvertTo-BoabAsciiLower $Entry.vendor) + [char]0 + (ConvertTo-BoabAsciiLower $Entry.product)
}

function Merge-BoabVendorRegistry {
    # VendorRegistry::merge_overrides
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Base,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Overrides
    )
    $merged = New-BoabList $Base.entries
    foreach ($ov in $Overrides.entries) {
        $key = Get-BoabVendorKey $ov
        $found = $false
        for ($i = 0; $i -lt $merged.Count; $i++) {
            if ((Get-BoabVendorKey $merged[$i]) -ceq $key) { $merged[$i] = $ov; $found = $true; break }
        }
        if (-not $found) { $merged.Add($ov) }
    }
    $sorted = Sort-BoabStable -Items $merged -Compare {
        param($a, $b)
        $c = Compare-BoabOrdinal (ConvertTo-BoabAsciiLower $a.vendor) (ConvertTo-BoabAsciiLower $b.vendor)
        if ($c -ne 0) { return $c }
        Compare-BoabOrdinal (ConvertTo-BoabAsciiLower $a.product) (ConvertTo-BoabAsciiLower $b.product)
    }
    [ordered]@{ entries = $sorted }
}

function Get-BoabMergedVendorRegistry {
    # vendor::load_merged
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $bundled = Get-BoabBundledVendorRegistry
    $overrides = Get-BoabStoredVendorOverride -Workspace $Workspace
    Merge-BoabVendorRegistry -Base $bundled -Overrides $overrides
}

function Find-BoabVendorEntry {
    # VendorRegistry::search
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Registry, [Parameter(Mandatory)][AllowEmptyString()][string]$Term)
    $needle = ConvertTo-BoabAsciiLower $Term
    $out = New-BoabList
    foreach ($e in $Registry.entries) {
        if ((ConvertTo-BoabAsciiLower $e.vendor).Contains($needle) -or (ConvertTo-BoabAsciiLower $e.product).Contains($needle)) { $out.Add($e) }
    }
    , $out
}

function ConvertFrom-BoabPqcStatusArgument {
    # The `vendor add --pqc-status` parser in runner.rs.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    $lower = ConvertTo-BoabAsciiLower $Value
    if ($lower -cin @('vulnerable', 'hybrid', 'resistant', 'symmetric_ok', 'unknown')) { return $lower }
    throw (New-BoabException ("unknown pqc_status: {0} (expected vulnerable|hybrid|resistant|symmetric_ok|unknown)" -f $lower))
}

function Add-BoabVendorOverrideEntry {
    # The `vendor add` body in runner.rs: upsert into the workspace overrides file.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Workspace,
        [Parameter(Mandatory)][string]$Vendor,
        [Parameter(Mandatory)][string]$Product,
        [Parameter(Mandatory)][string]$PqcStatus,
        [AllowNull()]$TargetDate,
        [AllowNull()]$SourceUrl,
        [AllowNull()]$SourceNote
    )
    $status = ConvertFrom-BoabPqcStatusArgument -Value $PqcStatus
    $overrides = Get-BoabStoredVendorOverride -Workspace $Workspace
    $entry = [ordered]@{
        vendor           = $Vendor
        product          = $Product
        pqc_status       = $status
        target_date      = $(if ($PSBoundParameters.ContainsKey('TargetDate')) { $TargetDate } else { $null })
        source_url       = $(if ($PSBoundParameters.ContainsKey('SourceUrl')) { $SourceUrl } else { $null })
        source_note      = $(if ($PSBoundParameters.ContainsKey('SourceNote')) { $SourceNote } else { $null })
        last_verified_at = Get-BoabTimestamp
    }
    $key = Get-BoabVendorKey $entry
    $entries = New-BoabList $overrides.entries
    $found = $false
    for ($i = 0; $i -lt $entries.Count; $i++) {
        if ((Get-BoabVendorKey $entries[$i]) -ceq $key) { $entries[$i] = $entry; $found = $true; break }
    }
    if (-not $found) { $entries.Add($entry) }
    $overrides.entries = $entries
    Save-BoabStoredVendorOverride -Workspace $Workspace -Registry $overrides
    $entry
}
