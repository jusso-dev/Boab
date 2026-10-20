function New-BoabPlan {
    <#
    .SYNOPSIS
    Generate a transition plan for an ASD milestone - equivalent of
    `boab plan generate --milestone <year>`.

    .EXAMPLE
    New-BoabPlan -Milestone 2030 -Name 'Demo rollout'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)][ValidateSet('2026', '2028', '2030')][string]$Milestone,
        [string]$Name,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $ms = ConvertFrom-BoabMilestone -Value $Milestone
    $planName = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { $null }
    $plan = New-BoabTransitionPlan -Workspace $ws -Milestone $ms -Name $planName
    if ($PSCmdlet.ShouldProcess($plan.name, 'Save plan')) {
        Save-BoabStoredPlan -Workspace $ws -Plan $plan
        ConvertTo-BoabOutputObject $plan
    }
}

function Get-BoabPlan {
    <#
    .SYNOPSIS
    List plans, or show one by id - equivalent of `boab plan list` / `boab plan show`.

    .EXAMPLE
    Get-BoabPlan | Select-Object id, name, milestone
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)][string]$Id,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    if ($Id) {
        $uuid = ConvertFrom-BoabUuidText -Text $Id
        return (ConvertTo-BoabOutputObject (Get-BoabStoredPlan -Workspace $ws -Id $uuid))
    }
    foreach ($p in (Get-BoabStoredPlan -Workspace $ws)) { ConvertTo-BoabOutputObject $p }
}

function Update-BoabPlan {
    <#
    .SYNOPSIS
    Regenerate a plan, preserving user edits - equivalent of `boab plan regenerate <id>`.

    .EXAMPLE
    Get-BoabPlan | Update-BoabPlan
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)][Alias('id')][string]$PlanId,
        [string]$Workspace = '.'
    )
    process {
        $ws = Open-BoabWorkspace -Root $Workspace
        $uuid = ConvertFrom-BoabUuidText -Text $PlanId
        $plan = Update-BoabTransitionPlan -Workspace $ws -Id $uuid
        if ($PSCmdlet.ShouldProcess($uuid, 'Regenerate plan')) {
            Save-BoabStoredPlan -Workspace $ws -Plan $plan
            ConvertTo-BoabOutputObject $plan
        }
    }
}
