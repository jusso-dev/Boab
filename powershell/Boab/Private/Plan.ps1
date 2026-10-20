# Transition plan generation, port of src/plan.rs and model::plan helpers.

function Get-BoabMilestoneForTier {
    param([int]$Tier)
    if ($Tier -le 2) { return 'y2028' }
    'y2030'
}

function Get-BoabFrontLoadedTargetDate {
    # model::plan::front_loaded_target_date at 00:00:00 UTC, iso8601-serialised.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Milestone, [int]$Tier)
    $month = switch ($Tier) { 1 { 3 } 2 { 6 } 3 { 9 } default { 12 } }
    Format-BoabIso8601Parts -Parts @{
        Year = (Get-BoabMilestoneYear $Milestone); Month = $month; Day = 1
        Hour = 0; Minute = 0; Second = 0; Nanosecond = 0; OffsetMinutes = 0
    }
}

function New-BoabTransitionPlan {
    # plan::generate
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Workspace,
        [Parameter(Mandatory)][string]$Milestone,
        [AllowNull()]$Name
    )
    $inventory = Get-BoabStoredInventory -Workspace $Workspace
    $systems = Get-BoabStoredSystem -Workspace $Workspace
    $year = (Get-BoabNow).UtcDateTime.Year
    $milestoneYear = Get-BoabMilestoneYear $Milestone

    $scored = New-BoabList
    foreach ($a in $inventory) {
        $sys = Find-BoabSystemById -Systems $systems -Id $a.system_id
        $s = Get-BoabRiskScore -Asset $a -System $sys -CurrentYear $year
        $ms = Get-BoabMilestoneForTier -Tier $s.triage_tier
        if ((Get-BoabMilestoneYear $ms) -le $milestoneYear) {
            $scored.Add(@{ Asset = $a; Score = $s })
        }
    }
    $sorted = Sort-BoabStable -Items $scored -Compare {
        param($x, $y)
        $c = ([double]$y.Score.priority).CompareTo([double]$x.Score.priority)
        if ($c -ne 0) { return $c }
        $c = ([int]$x.Score.migration_difficulty).CompareTo([int]$y.Score.migration_difficulty)
        if ($c -ne 0) { return $c }
        Compare-BoabOrdinal $x.Asset.name $y.Asset.name
    }
    $planName = if ($null -ne $Name) { [string]$Name } else { 'PQC transition plan {0}' -f $milestoneYear }
    $plan = New-BoabPlanRecord -Name $planName -Milestone $Milestone
    foreach ($entry in $sorted) {
        $asset = $entry.Asset; $score = $entry.Score
        $plan.items.Add([ordered]@{
                id              = New-BoabUuid
                crypto_asset_id = $asset.id
                asset_name      = $asset.name
                algorithm_name  = $asset.algorithm_name
                triage_tier     = $score.triage_tier
                priority        = $score.priority
                target_action   = $score.recommended_action
                target_date     = Get-BoabFrontLoadedTargetDate -Milestone $Milestone -Tier $score.triage_tier
                assignee        = $null
                notes           = $null
                status          = 'pending'
            })
    }
    $plan
}

function Update-BoabTransitionPlan {
    # plan::regenerate: regenerate preserving user edits for unchanged assets.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][string]$Id)
    $existing = Get-BoabStoredPlan -Workspace $Workspace -Id $Id
    $edits = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($i in $existing.items) { $edits[$i.crypto_asset_id] = $i }
    $regenerated = New-BoabTransitionPlan -Workspace $Workspace -Milestone $existing.milestone -Name $existing.name
    $regenerated.id = $existing.id
    foreach ($item in $regenerated.items) {
        if (-not $edits.ContainsKey($item.crypto_asset_id)) { continue }
        $prev = $edits[$item.crypto_asset_id]
        if ($prev.target_action -cne $item.target_action) { $item.target_action = $prev.target_action }
        if ($null -ne $prev.target_date) {
            $same = $null -ne $item.target_date -and (Get-BoabIso8601Key $prev.target_date) -eq (Get-BoabIso8601Key $item.target_date)
            if (-not $same) { $item.target_date = $prev.target_date }
        }
        if ($null -ne $prev.assignee) { $item.assignee = $prev.assignee }
        if ($null -ne $prev.notes) { $item.notes = $prev.notes }
        if ($prev.status -cne 'pending') { $item.status = $prev.status }
    }
    $regenerated
}
