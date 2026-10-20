function Initialize-BoabWorkspace {
    <#
    .SYNOPSIS
    Create a Boab workspace (.boab/) - equivalent of `boab init`.

    .DESCRIPTION
    Creates .boab/ with config.toml, systems.json, inventory.json,
    vendor-overrides.json and the scans/, plans/ and reports/ directories.
    Re-running on an existing workspace is a no-op. -Force removes and recreates
    the workspace (the Rust CLI requires --force --yes; here -Force asks for
    confirmation unless -Confirm:$false is supplied).

    .EXAMPLE
    Initialize-BoabWorkspace -Path ./demo
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)]
        [string]$Path = '.',
        [switch]$Force
    )
    if ($Force) {
        $target = Join-Path $Path '.boab'
        if (-not $PSCmdlet.ShouldProcess($target, 'Remove and recreate Boab workspace')) { return }
    }
    $result = Initialize-BoabWorkspaceLayout -Root $Path -Force:$Force
    [pscustomobject]@{
        Path    = Get-BoabWorkspacePath -Workspace $result.Workspace -Kind Dir
        Existed = [bool]($result.Existed -and -not $Force)
    }
}

function Get-BoabConfig {
    <#
    .SYNOPSIS
    Read workspace configuration (config.toml) - equivalent of `boab config get`.

    .PARAMETER Key
    Dotted key, e.g. scanner.air_gapped. Without -Key the whole configuration is returned.

    .EXAMPLE
    Get-BoabConfig -Key scanner.tls_timeout_seconds
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Key,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $cfg = Read-BoabConfig -Workspace $ws
    if (-not $Key) {
        return [pscustomobject]@{
            schema_version = $cfg.schema_version
            scanner        = [pscustomobject]$cfg.scanner
            reporting      = [pscustomobject]$cfg.reporting
        }
    }
    $value = Get-BoabConfigValue -Config $cfg -Key $Key
    if ($null -eq $value) { throw (New-BoabException ("unknown config key: {0}" -f $Key)) }
    $value
}

function Set-BoabConfig {
    <#
    .SYNOPSIS
    Set a workspace configuration value - equivalent of `boab config set`.

    .EXAMPLE
    Set-BoabConfig -Key scanner.air_gapped -Value false
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Key,
        [Parameter(Mandatory, Position = 1)][AllowEmptyString()][string]$Value,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $cfg = Read-BoabConfig -Workspace $ws
    Set-BoabConfigValue -Config $cfg -Key $Key -Value $Value
    if ($PSCmdlet.ShouldProcess($Key, "Set to '$Value'")) {
        Save-BoabConfig -Workspace $ws -Config $cfg
    }
}
