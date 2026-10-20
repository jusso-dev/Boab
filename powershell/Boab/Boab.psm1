# Boab PowerShell module: a port of the Boab Rust CLI (PQC readiness tooling for
# ASD LATICE transition planning) that produces the same workspace files, JSON,
# CycloneDX CBOM, Markdown, console output and exit codes.

Set-StrictMode -Version Latest

$privateRoot = Join-Path $PSScriptRoot 'Private'
$publicRoot = Join-Path $PSScriptRoot 'Public'

# Private helpers first: top-level files, then nested folders (e.g. Private/Scanners).
$privateFiles = @(Get-ChildItem -Path $privateRoot -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
$nestedFiles = @(Get-ChildItem -Path $privateRoot -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -ne (Get-Item -LiteralPath $privateRoot).FullName } | Sort-Object FullName)
$publicFiles = @(Get-ChildItem -Path $publicRoot -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)

foreach ($file in @($privateFiles) + @($nestedFiles) + @($publicFiles)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load $($file.FullName): $_"
    }
}

$exported = @(
    'Invoke-Boab'
    'Invoke-BoabCli'
    'Initialize-BoabWorkspace'
    'Get-BoabConfig'
    'Set-BoabConfig'
    'Add-BoabSystem'
    'Get-BoabSystem'
    'Set-BoabSystem'
    'Remove-BoabSystem'
    'Get-BoabInventory'
    'Start-BoabCodebaseScan'
    'Start-BoabTlsScan'
    'Start-BoabCertificateScan'
    'Import-BoabScan'
    'New-BoabPlan'
    'Get-BoabPlan'
    'Update-BoabPlan'
    'Get-BoabVendor'
    'Add-BoabVendor'
    'Export-BoabReport'
    'ConvertTo-BoabJson'
)
Export-ModuleMember -Function $exported
