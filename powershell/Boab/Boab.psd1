@{
    RootModule           = 'Boab.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6b0f3f8e-5a4f-4c43-9d55-4b1f1d0c2a7e'
    Author               = 'Boab contributors'
    CompanyName          = 'Boab contributors'
    Copyright            = '(c) Boab contributors. Licensed under MIT OR Apache-2.0.'
    Description          = 'PQC readiness tooling that helps Australian organisations meet ASD post-quantum cryptography transition obligations. PowerShell port of the Boab Rust CLI with identical workspace files, reports and console output.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
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
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    FileList             = @('Data/vendor-pqc-registry.json')
    PrivateData          = @{
        PSData = @{
            Tags         = @('pqc', 'cryptography', 'security', 'cbom', 'cyclonedx', 'asd', 'PSEdition_Core', 'Windows', 'Linux', 'MacOS')
            LicenseUri   = 'https://github.com/jusso-dev/Boab/blob/main/LICENSE-MIT'
            ProjectUri   = 'https://github.com/jusso-dev/Boab'
            ReleaseNotes = 'Initial PowerShell port of Boab 0.1.0.'
        }
    }
}
