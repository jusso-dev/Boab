function Export-BoabReport {
    <#
    .SYNOPSIS
    Export the workspace as native JSON, CycloneDX 1.6 CBOM, Markdown or a
    self-contained HTML readiness report -
    equivalent of `boab report --format <fmt> [-o <path>]`.

    .DESCRIPTION
    Output is byte-for-byte the same shape as the Rust tool (serde_json pretty
    printing, same key order, same float formatting). Without -OutputPath the file
    is written to .boab/reports/ (report.json, bom.cdx.json, readiness.md or
    readiness.html).

    .EXAMPLE
    Export-BoabReport -Format cbom -OutputPath ./bom.cdx.json

    .EXAMPLE
    Export-BoabReport -Format html -OutputPath ./readiness.html
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, Position = 0)][ValidateSet('json', 'cbom', 'md', 'html')][string]$Format,
        [Alias('Output')][string]$OutputPath,
        [string]$Workspace = '.'
    )
    $ws = Open-BoabWorkspace -Root $Workspace
    $display = if ($OutputPath) { $OutputPath } else { 'reports/' + (Get-BoabReportDefaultName -Format (ConvertTo-BoabAsciiLower $Format)) }
    if ($PSCmdlet.ShouldProcess($display, "Write $Format report")) {
        $r = Export-BoabReportFile -Workspace $ws -Format $Format -OutputPath $OutputPath
        Get-Item -LiteralPath $r.FullPath
    }
}
