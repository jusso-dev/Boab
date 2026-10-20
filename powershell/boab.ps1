#!/usr/bin/env pwsh
# Thin CLI wrapper around the Boab PowerShell module. Accepts the same arguments as
# the Rust `boab` binary and exits with the same code, e.g.
#   pwsh ./powershell/boab.ps1 init
#   pwsh ./powershell/boab.ps1 scan tls example.com:443
# This script intentionally has no param() block so every argument (including
# -o, -h and -V) reaches the Boab parser unchanged.

$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8

Import-Module (Join-Path $PSScriptRoot 'Boab') -Force
$boabModule = Get-Module Boab
$argv = & $boabModule { param($a) ConvertTo-BoabArgumentList -InputArguments $a } $args
$result = Invoke-BoabCli -ArgumentList $argv
exit $result.ExitCode
