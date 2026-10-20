function Complete-BoabScanImport {
    # Promote a scan's findings into the inventory and persist the scan record.
    param([hashtable]$Workspace, $Scan)
    $inventory = Invoke-BoabPromotion -Workspace $Workspace -Scan $Scan
    Save-BoabStoredScan -Workspace $Workspace -Scan $Scan
    [pscustomobject]@{
        ScanId         = $Scan.id
        Name           = $Scan.name
        ScanType       = $Scan.scan_type
        Status         = $Scan.status
        Target         = $Scan.target
        FindingCount   = @($Scan.findings).Count
        InventoryCount = $inventory.Count
        Scan           = $Scan
    }
}

function Start-BoabCodebaseScan {
    <#
    .SYNOPSIS
    Scan a source tree and fold the findings into the inventory - equivalent of
    `boab scan codebase <path>`.

    .EXAMPLE
    Start-BoabCodebaseScan -Path ./src -Exclude 'vendor/**'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [string[]]$Include,
        [string[]]$Exclude,
        [string]$Name,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabCodebaseScan'
    $splat = @{ Path = $Path }
    if ($Include) { $splat.Include = $Include }
    if ($Exclude) { $splat.Exclude = $Exclude }
    if ($Name) { $splat.Name = $Name }
    if ($PSCmdlet.ShouldProcess($Path, 'Scan codebase')) {
        $scan = & $scanner @splat
        Complete-BoabScanImport -Workspace $ws -Scan $scan
    }
}

function Start-BoabTlsScan {
    <#
    .SYNOPSIS
    Probe TLS endpoints and fold the findings into the inventory - equivalent of
    `boab scan tls host:port ...`.

    .EXAMPLE
    Start-BoabTlsScan -Target example.com:443 -TimeoutSeconds 5
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position = 0)][string[]]$Target = @(),
        [string]$TargetsFile,
        [string]$RateLimit,
        [ValidateRange(0, [long]::MaxValue)][long]$TimeoutSeconds = 10,
        [switch]$ProbeHsts,
        [string[]]$Exclude,
        [string]$Name,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $cfg = Read-BoabConfig -Workspace $ws
    $targets = New-BoabList $Target
    if ($TargetsFile) {
        $file = Resolve-BoabFullPath -Path $TargetsFile
        $raw = Read-BoabTextFile -Path $file
        foreach ($line in ($raw -split "`n")) {
            $l = $line.Trim()
            if ($l.Length -gt 0 -and -not $l.StartsWith('#')) { $targets.Add($l) }
        }
    }
    if ($targets.Count -eq 0) { throw (New-BoabException 'no TLS targets specified; pass host:port or --targets-file') }
    $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabTlsScan'
    $splat = @{ Targets = [string[]]$targets; TimeoutSeconds = $TimeoutSeconds; ProbeHsts = [bool]$ProbeHsts; AirGapped = [bool]$cfg.scanner.air_gapped }
    if ($RateLimit) { $splat.RateLimit = $RateLimit }
    if ($Exclude) { $splat.Exclude = $Exclude }
    if ($Name) { $splat.Name = $Name }
    if ($PSCmdlet.ShouldProcess(($targets -join ', '), 'Scan TLS endpoints')) {
        foreach ($scan in @(& $scanner @splat)) {
            Complete-BoabScanImport -Workspace $ws -Scan $scan
        }
    }
}

function Start-BoabCertificateScan {
    <#
    .SYNOPSIS
    Scan a directory of certificate / keystore files - equivalent of
    `boab scan certs <path>`.

    .EXAMPLE
    Start-BoabCertificateScan -Path ./certs
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [string]$PasswordFile,
        [string]$Name,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $scanner = Get-BoabScannerCommand -Name 'Invoke-BoabCertStoreScan'
    $splat = @{ Path = $Path }
    if ($PasswordFile) { $splat.PasswordFile = $PasswordFile }
    if ($Name) { $splat.Name = $Name }
    if ($PSCmdlet.ShouldProcess($Path, 'Scan certificate store')) {
        $scan = & $scanner @splat
        Complete-BoabScanImport -Workspace $ws -Scan $scan
    }
}

function Import-BoabScan {
    <#
    .SYNOPSIS
    Import an existing scan JSON file (e.g. one written by the Rust binary) into
    the workspace: findings are deduplicated into the inventory exactly as the
    scan commands do, and the scan record is saved under .boab/scans/.

    .EXAMPLE
    Get-ChildItem ../other/.boab/scans/*.json | Import-BoabScan
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][Alias('FullName')][string]$Path,
        [switch]$ResetAssetLinks,
        [string]$Workspace = '.'
    )
    begin { $ws = Open-BoabWorkspace -Root $Workspace }
    process {
        $full = Resolve-BoabFullPath -Path $Path
        $scan = Read-BoabJsonFile -Path $full -Converter 'ConvertTo-BoabScanFromJson'
        if ($ResetAssetLinks) { foreach ($f in $scan.findings) { $f.crypto_asset_id = $null } }
        if ($PSCmdlet.ShouldProcess($Path, 'Import scan')) {
            Complete-BoabScanImport -Workspace $ws -Scan $scan
        }
    }
}
