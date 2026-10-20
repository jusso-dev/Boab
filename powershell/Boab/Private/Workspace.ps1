# Workspace layout (.boab/) and JSON storage. Ports src/workspace.rs and src/storage.rs.

$script:BoabWorkspaceDir = '.boab'
$script:BoabDefaultConfigText = "# Boab configuration`n`nschema_version = 1`n`n[scanner]`ndefault_rate_limit = `"1/second`"`ntls_timeout_seconds = 10`nair_gapped = true`n`n[reporting]`ndefault_format = `"md`"`n"

function Get-BoabWorkspacePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Workspace,
        [Parameter(Mandatory)][ValidateSet('Dir', 'Config', 'Systems', 'Inventory', 'Scans', 'Plans', 'Reports', 'VendorOverrides')][string]$Kind
    )
    $dir = Join-BoabPath $Workspace.Root $script:BoabWorkspaceDir
    switch ($Kind) {
        'Dir' { return $dir }
        'Config' { return (Join-BoabPath $dir 'config.toml') }
        'Systems' { return (Join-BoabPath $dir 'systems.json') }
        'Inventory' { return (Join-BoabPath $dir 'inventory.json') }
        'Scans' { return (Join-BoabPath $dir 'scans') }
        'Plans' { return (Join-BoabPath $dir 'plans') }
        'Reports' { return (Join-BoabPath $dir 'reports') }
        'VendorOverrides' { return (Join-BoabPath $dir 'vendor-overrides.json') }
    }
}

function Test-BoabPathExists {
    param([string]$Path)
    [System.IO.Directory]::Exists($Path) -or [System.IO.File]::Exists($Path)
}

function Resolve-BoabWorkspaceRoot {
    param([string]$Root)
    try {
        Resolve-BoabCanonicalPath -Path $Root
    }
    catch {
        throw (New-BoabException ("could not resolve workspace path {0}: {1}" -f $Root, (Get-BoabErrorMessage $_)))
    }
}

function Open-BoabWorkspace {
    # Workspace::open
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Root)
    $canonical = Resolve-BoabWorkspaceRoot -Root $Root
    $ws = @{ Root = $canonical }
    $dir = Get-BoabWorkspacePath -Workspace $ws -Kind Dir
    if (-not (Test-BoabPathExists $dir)) {
        throw (New-BoabException ("workspace not initialised: {0} is missing. Run ``boab init`` first." -f $dir))
    }
    if (-not [System.IO.Directory]::Exists($dir)) {
        throw (New-BoabException ("{0} exists but is not a directory" -f $dir))
    }
    if (-not (Test-BoabPathExists (Get-BoabWorkspacePath -Workspace $ws -Kind Config))) {
        throw (New-BoabException ("workspace at {0} is malformed: missing config.toml" -f $dir))
    }
    $ws
}

function Initialize-BoabWorkspaceLayout {
    # Workspace::init. Returns @{ Workspace = ...; Existed = [bool] }.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Root, [switch]$Force)
    $canonical = Resolve-BoabWorkspaceRoot -Root $Root
    $ws = @{ Root = $canonical }
    $dir = Get-BoabWorkspacePath -Workspace $ws -Kind Dir
    if (Test-BoabPathExists $dir) {
        if ($Force) {
            try {
                if ([System.IO.Directory]::Exists($dir) -and -not ([System.IO.DirectoryInfo]::new($dir).LinkTarget)) {
                    [System.IO.Directory]::Delete($dir, $true)
                }
                else {
                    throw [System.IO.IOException]::new('Not a directory (os error 20)')
                }
            }
            catch {
                throw (New-BoabException ("could not remove existing {0}: {1}" -f $dir, (Get-BoabIoErrorText -Exception $_ -Path $dir)))
            }
        }
        else {
            if (Test-BoabPathExists (Get-BoabWorkspacePath -Workspace $ws -Kind Config)) {
                return @{ Workspace = $ws; Existed = $true }
            }
            throw (New-BoabException ("{0} exists but is malformed (no config.toml). Use ``boab init --force --yes`` to recreate." -f $dir))
        }
    }
    try {
        [void][System.IO.Directory]::CreateDirectory($dir)
    }
    catch {
        throw (New-BoabException ("create {0}: {1}" -f $dir, (Get-BoabIoErrorText -Exception $_ -Path $dir)))
    }
    try {
        [void][System.IO.Directory]::CreateDirectory((Get-BoabWorkspacePath -Workspace $ws -Kind Scans))
        [void][System.IO.Directory]::CreateDirectory((Get-BoabWorkspacePath -Workspace $ws -Kind Plans))
        [void][System.IO.Directory]::CreateDirectory((Get-BoabWorkspacePath -Workspace $ws -Kind Reports))
        Write-BoabTextFile -Path (Get-BoabWorkspacePath -Workspace $ws -Kind Config) -Content $script:BoabDefaultConfigText
        Write-BoabTextFile -Path (Get-BoabWorkspacePath -Workspace $ws -Kind Systems) -Content "[]`n"
        Write-BoabTextFile -Path (Get-BoabWorkspacePath -Workspace $ws -Kind Inventory) -Content "[]`n"
        Write-BoabTextFile -Path (Get-BoabWorkspacePath -Workspace $ws -Kind VendorOverrides) -Content "{`"entries`":[]}`n"
    }
    catch {
        throw (New-BoabException (Get-BoabIoErrorText -Exception $_))
    }
    @{ Workspace = $ws; Existed = $false }
}

# --- storage ---------------------------------------------------------------------

function Read-BoabJsonFile {
    # storage::read_json (parse only; callers convert into typed records).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Converter)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    }
    catch {
        throw (New-BoabException ("read {0}: {1}" -f $Path, (Get-BoabIoErrorText -Exception $_ -Path $Path)))
    }
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { throw (New-BoabException 'expected value at line 1 column 1') }
        $parsed = ConvertFrom-BoabJson -Json $text
        if ($Converter) {
            return , (& $Converter $parsed)
        }
        , $parsed
    }
    catch {
        throw (New-BoabException ("parse JSON from {0}: {1}" -f $Path, (Get-BoabErrorMessage $_)))
    }
}

function Write-BoabJsonFile {
    # storage::write_json: pretty JSON, no trailing newline, parent dirs created.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Value)
    $text = ConvertTo-BoabJson -InputObject $Value
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if ($parent) {
        try { [void][System.IO.Directory]::CreateDirectory($parent) } catch { Write-Debug "create_dir_all failed: $_" }
    }
    try {
        Write-BoabTextFile -Path $Path -Content $text
    }
    catch {
        throw (New-BoabException ("write {0}: {1}" -f $Path, (Get-BoabIoErrorText -Exception $_ -Path $Path)))
    }
}

function ConvertTo-BoabSystemList { param($Parsed) , (ConvertTo-BoabRecordList -Parsed $Parsed -Converter 'ConvertTo-BoabSystemRecord') }
function ConvertTo-BoabInventoryList { param($Parsed) , (ConvertTo-BoabRecordList -Parsed $Parsed -Converter 'ConvertTo-BoabCryptoAssetRecord') }
function ConvertTo-BoabScanFromJson { param($Parsed) ConvertTo-BoabScanRecord -InputObject $Parsed }
function ConvertTo-BoabPlanFromJson { param($Parsed) ConvertTo-BoabPlanRecord -InputObject $Parsed }
function ConvertTo-BoabVendorRegistryFromJson { param($Parsed) ConvertTo-BoabVendorRegistryRecord -InputObject $Parsed }

function Get-BoabStoredSystem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $path = Get-BoabWorkspacePath -Workspace $Workspace -Kind Systems
    if (-not (Test-BoabPathExists $path)) { return , (New-BoabList) }
    , (Read-BoabJsonFile -Path $path -Converter 'ConvertTo-BoabSystemList')
}

function Save-BoabStoredSystem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][AllowEmptyCollection()]$Systems)
    Write-BoabJsonFile -Path (Get-BoabWorkspacePath -Workspace $Workspace -Kind Systems) -Value $Systems
}

function Get-BoabStoredInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $path = Get-BoabWorkspacePath -Workspace $Workspace -Kind Inventory
    if (-not (Test-BoabPathExists $path)) { return , (New-BoabList) }
    , (Read-BoabJsonFile -Path $path -Converter 'ConvertTo-BoabInventoryList')
}

function Save-BoabStoredInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][AllowEmptyCollection()]$Inventory)
    Write-BoabJsonFile -Path (Get-BoabWorkspacePath -Workspace $Workspace -Kind Inventory) -Value $Inventory
}

function Save-BoabStoredScan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)]$Scan)
    $path = Join-BoabPath (Get-BoabWorkspacePath -Workspace $Workspace -Kind Scans) ("{0}.json" -f $Scan.id)
    Write-BoabJsonFile -Path $path -Value $Scan
}

function Get-BoabJsonFilesInDirectory {
    param([string]$Dir)
    $files = New-BoabList
    try {
        foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($Dir)) {
            if ((Get-BoabPathExtension -Path $entry) -ceq 'json') { $files.Add($entry) }
        }
    }
    catch {
        throw (New-BoabException (Get-BoabIoErrorText -Exception $_ -Path $Dir))
    }
    , $files
}

function Get-BoabStoredScan {
    # storage::list_scans (sorted by started_at, stable) or load_scan when -Id given.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [string]$Id)
    $dir = Get-BoabWorkspacePath -Workspace $Workspace -Kind Scans
    if ($Id) {
        return (Read-BoabJsonFile -Path (Join-BoabPath $dir ("{0}.json" -f $Id)) -Converter 'ConvertTo-BoabScanFromJson')
    }
    if (-not (Test-BoabPathExists $dir)) { return , (New-BoabList) }
    $scans = New-BoabList
    foreach ($f in (Get-BoabJsonFilesInDirectory -Dir $dir)) {
        $scan = Read-BoabJsonFile -Path $f -Converter 'ConvertTo-BoabScanFromJson'
        $scan['__sort'] = Get-BoabRfc3339Key -Text $scan.started_at
        $scans.Add($scan)
    }
    $sorted = Sort-BoabStable -Items $scans -Compare { param($a, $b) $a['__sort'].CompareTo($b['__sort']) }
    foreach ($s in $sorted) { $s.Remove('__sort') }
    , $sorted
}

function Save-BoabStoredPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][System.Collections.IDictionary]$Plan)
    $path = Join-BoabPath (Get-BoabWorkspacePath -Workspace $Workspace -Kind Plans) ("{0}.json" -f $Plan.id)
    Write-BoabJsonFile -Path $path -Value $Plan
}

function Get-BoabStoredPlan {
    # storage::list_plans (sorted by generated_at) or load_plan when -Id given.
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [string]$Id)
    $dir = Get-BoabWorkspacePath -Workspace $Workspace -Kind Plans
    if ($Id) {
        return (Read-BoabJsonFile -Path (Join-BoabPath $dir ("{0}.json" -f $Id)) -Converter 'ConvertTo-BoabPlanFromJson')
    }
    if (-not (Test-BoabPathExists $dir)) { return , (New-BoabList) }
    $plans = New-BoabList
    foreach ($f in (Get-BoabJsonFilesInDirectory -Dir $dir)) {
        $plan = Read-BoabJsonFile -Path $f -Converter 'ConvertTo-BoabPlanFromJson'
        $plan['__sort'] = Get-BoabRfc3339Key -Text $plan.generated_at
        $plans.Add($plan)
    }
    $sorted = Sort-BoabStable -Items $plans -Compare { param($a, $b) $a['__sort'].CompareTo($b['__sort']) }
    foreach ($p in $sorted) { $p.Remove('__sort') }
    , $sorted
}

function Get-BoabStoredVendorOverride {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace)
    $path = Get-BoabWorkspacePath -Workspace $Workspace -Kind VendorOverrides
    if (-not (Test-BoabPathExists $path)) { return [ordered]@{ entries = (New-BoabList) } }
    Read-BoabJsonFile -Path $path -Converter 'ConvertTo-BoabVendorRegistryFromJson'
}

function Save-BoabStoredVendorOverride {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Workspace, [Parameter(Mandatory)][System.Collections.IDictionary]$Registry)
    Write-BoabJsonFile -Path (Get-BoabWorkspacePath -Workspace $Workspace -Kind VendorOverrides) -Value $Registry
}
