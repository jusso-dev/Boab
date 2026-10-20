function ConvertTo-BoabOutputObject {
    # Present an internal [ordered] record as a PSCustomObject (top level only).
    param($Record)
    if ($null -eq $Record) { return $null }
    $o = [ordered]@{}
    foreach ($k in $Record.Keys) { $o[$k] = $Record[$k] }
    [pscustomobject]$o
}

function Add-BoabSystem {
    <#
    .SYNOPSIS
    Register a business system - equivalent of `boab system add`.

    .EXAMPLE
    Add-BoabSystem -Name Payments -Classification protected -Criticality mission_critical -Soci -LifetimeYears 25
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$Description,
        [string]$Classification = 'official',
        [string]$Criticality = 'standard',
        [switch]$Soci,
        [ValidateRange(0, 65535)][Nullable[int]]$LifetimeYears,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $class = ConvertFrom-BoabClassification -Value $Classification
    if ($null -eq $class) { throw (New-BoabException ("unknown classification: {0}" -f $Classification)) }
    $crit = ConvertFrom-BoabCriticality -Value $Criticality
    if ($null -eq $crit) { throw (New-BoabException ("unknown criticality: {0}" -f $Criticality)) }
    $desc = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $null }
    $systems = Get-BoabStoredSystem -Workspace $ws
    $sys = New-BoabSystemRecord -Name $Name -Description $desc -Classification $class -Criticality $crit -IsSoci ([bool]$Soci) -ExpectedDataLifetimeYears $LifetimeYears
    if ($PSCmdlet.ShouldProcess($Name, 'Add system')) {
        $systems.Add($sys)
        Save-BoabStoredSystem -Workspace $ws -Systems $systems
        ConvertTo-BoabOutputObject $sys
    }
}

function Get-BoabSystem {
    <#
    .SYNOPSIS
    List registered systems - equivalent of `boab system list`.

    .EXAMPLE
    Get-BoabSystem | Format-Table name, classification, criticality
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Id,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $systems = Get-BoabStoredSystem -Workspace $ws
    $wanted = if ($Id) { ConvertFrom-BoabUuidText -Text $Id } else { $null }
    foreach ($s in $systems) {
        if ($null -eq $wanted -or $s.id -ceq $wanted) { ConvertTo-BoabOutputObject $s }
    }
}

function Set-BoabSystem {
    <#
    .SYNOPSIS
    Edit an existing system - equivalent of `boab system edit`.

    .EXAMPLE
    Set-BoabSystem -Id 6f0c... -Criticality essential -Soci $false
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][Alias('id')][string]$SystemId,
        [string]$Name,
        [string]$Description,
        [string]$Classification,
        [string]$Criticality,
        [Nullable[bool]]$Soci,
        [ValidateRange(0, 65535)][Nullable[int]]$LifetimeYears,
        [string]$Workspace = '.'
    )
    process {
        $ws = Open-BoabWorkspace -Root $Workspace
        $uuid = ConvertFrom-BoabUuidText -Text $SystemId
        $systems = Get-BoabStoredSystem -Workspace $ws
        $s = Find-BoabSystemById -Systems $systems -Id $uuid
        if ($null -eq $s) { throw (New-BoabException ("no system with id {0}" -f $uuid)) }
        if ($PSBoundParameters.ContainsKey('Name')) { $s.name = $Name }
        if ($PSBoundParameters.ContainsKey('Description')) { $s.description = $Description }
        if ($PSBoundParameters.ContainsKey('Classification')) {
            $c = ConvertFrom-BoabClassification -Value $Classification
            if ($null -eq $c) { throw (New-BoabException ("unknown classification: {0}" -f $Classification)) }
            $s.classification = $c
        }
        if ($PSBoundParameters.ContainsKey('Criticality')) {
            $c = ConvertFrom-BoabCriticality -Value $Criticality
            if ($null -eq $c) { throw (New-BoabException ("unknown criticality: {0}" -f $Criticality)) }
            $s.criticality = $c
        }
        if ($null -ne $Soci) { $s.is_soci = [bool]$Soci }
        if ($null -ne $LifetimeYears) { $s.expected_data_lifetime_years = [long]$LifetimeYears }
        if ($PSCmdlet.ShouldProcess($uuid, 'Update system')) {
            Save-BoabStoredSystem -Workspace $ws -Systems $systems
            ConvertTo-BoabOutputObject $s
        }
    }
}

function Remove-BoabSystem {
    <#
    .SYNOPSIS
    Delete a system by id - equivalent of `boab system delete`.

    .EXAMPLE
    Get-BoabSystem | Where-Object name -eq 'Legacy' | Remove-BoabSystem -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][Alias('id')][string]$SystemId,
        [string]$Workspace = '.'
    )
    process {
        $ws = Open-BoabWorkspace -Root $Workspace
        $uuid = ConvertFrom-BoabUuidText -Text $SystemId
        $systems = Get-BoabStoredSystem -Workspace $ws
        $kept = New-BoabList
        foreach ($s in $systems) { if ($s.id -cne $uuid) { $kept.Add($s) } }
        if ($kept.Count -eq $systems.Count) { throw (New-BoabException ("no system with id {0}" -f $uuid)) }
        if ($PSCmdlet.ShouldProcess($uuid, 'Delete system')) {
            Save-BoabStoredSystem -Workspace $ws -Systems $kept
        }
    }
}
