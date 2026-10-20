function Get-BoabInventory {
    <#
    .SYNOPSIS
    Query the deduplicated cryptographic inventory - equivalent of
    `boab inventory list` / `boab inventory show`.

    .DESCRIPTION
    Returns one object per inventory asset with an added RiskScore property
    (the LATICE score computed exactly as the Rust tool does). Filters behave like
    the CLI: -PqcStatus matches the Rust Debug name case-insensitively
    (e.g. 'vulnerable', 'symmetricok'), -Algorithm is a case-insensitive substring.

    .EXAMPLE
    Get-BoabInventory -Tier 1 | Sort-Object { $_.RiskScore.priority } -Descending
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Id,
        [string]$PqcStatus,
        [ValidateRange(0, 255)][Nullable[int]]$Tier,
        [string]$SystemId,
        [string]$Algorithm,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $inventory = Get-BoabStoredInventory -Workspace $ws
    $systems = Get-BoabStoredSystem -Workspace $ws
    $year = (Get-BoabNow).UtcDateTime.Year
    if ($Id) {
        $uuid = ConvertFrom-BoabUuidText -Text $Id
        $found = $null
        foreach ($a in $inventory) { if ($a.id -ceq $uuid) { $found = $a; break } }
        if ($null -eq $found) { throw (New-BoabException ("no inventory entry with id {0}" -f $uuid)) }
        $sys = Find-BoabSystemById -Systems $systems -Id $found.system_id
        $o = ConvertTo-BoabOutputObject $found
        $o | Add-Member -NotePropertyName RiskScore -NotePropertyValue ([pscustomobject](Get-BoabRiskScore -Asset $found -System $sys -CurrentYear $year))
        return $o
    }
    $sysFilter = if ($SystemId) { ConvertFrom-BoabUuidText -Text $SystemId } else { $null }
    $pqc = if ($PSBoundParameters.ContainsKey('PqcStatus')) { $PqcStatus } else { $null }
    $alg = if ($PSBoundParameters.ContainsKey('Algorithm')) { $Algorithm } else { $null }
    $rows = Select-BoabInventoryRow -Inventory $inventory -Systems $systems -Year $year -PqcStatus $pqc -Tier $Tier -SystemId $sysFilter -Algorithm $alg
    foreach ($r in $rows) {
        $o = ConvertTo-BoabOutputObject $r.Asset
        $o | Add-Member -NotePropertyName RiskScore -NotePropertyValue ([pscustomobject]$r.Score)
        $o
    }
}
