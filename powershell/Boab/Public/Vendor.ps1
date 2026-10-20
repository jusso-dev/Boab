function Get-BoabVendor {
    <#
    .SYNOPSIS
    List or search the merged vendor PQC registry (bundled + workspace overrides) -
    equivalent of `boab vendor list` / `boab vendor search <term>`.

    .EXAMPLE
    Get-BoabVendor -Search azure
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Search,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $merged = Get-BoabMergedVendorRegistry -Workspace $ws
    $entries = if ($PSBoundParameters.ContainsKey('Search')) { Find-BoabVendorEntry -Registry $merged -Term $Search } else { $merged.entries }
    foreach ($e in $entries) { ConvertTo-BoabOutputObject $e }
}

function Add-BoabVendor {
    <#
    .SYNOPSIS
    Add or override a vendor registry entry for this workspace - equivalent of
    `boab vendor add`.

    .EXAMPLE
    Add-BoabVendor -Vendor Microsoft -Product Azure -PqcStatus resistant -TargetDate 2026-Q4
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Vendor,
        [Parameter(Mandatory)][string]$Product,
        [Parameter(Mandatory)][string]$PqcStatus,
        [string]$TargetDate,
        [string]$SourceUrl,
        [string]$SourceNote,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $null = ConvertFrom-BoabPqcStatusArgument -Value $PqcStatus
    $splat = @{ Workspace = $ws; Vendor = $Vendor; Product = $Product; PqcStatus = $PqcStatus }
    foreach ($k in 'TargetDate', 'SourceUrl', 'SourceNote') {
        if ($PSBoundParameters.ContainsKey($k)) { $splat[$k] = $PSBoundParameters[$k] }
    }
    if ($PSCmdlet.ShouldProcess("$Vendor $Product", 'Save vendor override')) {
        ConvertTo-BoabOutputObject (Add-BoabVendorOverrideEntry @splat)
    }
}
