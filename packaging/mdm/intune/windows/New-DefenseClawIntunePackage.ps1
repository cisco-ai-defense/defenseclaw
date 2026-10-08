# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 7.4
<#
.SYNOPSIS
    Builds the Intune Win32 app content for the DefenseClaw standalone
    deployment and prints the values to enter in the Intune admin center.

.DESCRIPTION
    Run on an administrator workstation. Verifies DefenseClawSetup-Enterprise-Standalone-x64.exe
    (hash-pinned against -Sha256, which you take from the release's
    cosign-verified checksums.txt, and/or Authenticode against
    -AllowedSigners), copies it with config.yaml and Install-DefenseClawIntune.ps1
    into a content folder, writes intune-package.json with the SHA-256 pins
    the launcher re-checks on the device, and, when -IntuneWinAppUtil is
    given, wraps the folder into a .intunewin.

    Never put credentials in config.yaml: the Win32 app content is not secret
    storage. Deliver the AI Defense key separately (see the Intune on Windows page in the docs).

.EXAMPLE
    ./New-DefenseClawIntunePackage.ps1 -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe -Sha256 <pin> `
        -ConfigPath .\config.yaml -OutputDirectory .\out -IntuneWinAppUtil C:\Tools\IntuneWinAppUtil.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SetupPath,
    [string]$Sha256 = '',
    [ValidateSet('HashPinned', 'Authenticode')][string]$TrustMode = 'HashPinned',
    [string[]]$AllowedSigners = @(),
    [string]$ConfigPath = '',
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$IntuneWinAppUtil = '',
    [string]$ProductVersion = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path (Get-Location).ProviderPath $OutputDirectory
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

$setup = (Resolve-Path -LiteralPath $SetupPath).ProviderPath
$pin = $Sha256.Trim().ToLowerInvariant()
$actual = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
if ($TrustMode -eq 'HashPinned' -and -not $pin) { throw 'hash-pinned trust requires -Sha256 (from the cosign-verified checksums.txt)' }
if ($pin -and $pin -ne $actual) { throw "Setup SHA-256 $actual does not match -Sha256 $pin" }
$signers = @($AllowedSigners | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
if ($TrustMode -eq 'Authenticode') {
    if ($signers.Count -eq 0) { throw 'Authenticode trust requires -AllowedSigners (SHA-256 thumbprints of the signer certificate)' }
    $signature = Get-AuthenticodeSignature -LiteralPath $setup
    if ($signature.Status -ne 'Valid') { throw "Setup Authenticode status is $($signature.Status)" }
    $thumbprint = ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($signature.SignerCertificate.RawData))).ToLowerInvariant()
    if ($signers -notcontains $thumbprint) { throw "Setup is signed by certificate $thumbprint, which is not in -AllowedSigners" }
}

$content = Join-Path $OutputDirectory 'content'
if (Test-Path -LiteralPath $content) { throw "$content already exists; use an empty -OutputDirectory" }
New-Item -ItemType Directory -Path $content -Force | Out-Null
Copy-Item -LiteralPath $setup -Destination (Join-Path $content 'DefenseClawSetup-Enterprise-Standalone-x64.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-DefenseClawIntune.ps1') -Destination $content
$configPin = ''
if ($ConfigPath) {
    $configText = Get-Content -LiteralPath $ConfigPath -Raw
    if ($configText -match '(?im)^\s*api_key\s*:\s*\S') { throw 'config.yaml contains an inline api_key; the standalone profile rejects it and the package must not carry credentials' }
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $content 'config.yaml')
    $configPin = (Get-FileHash -LiteralPath (Join-Path $content 'config.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
}
$pins = [ordered]@{
    schema_version  = 1
    setup_sha256    = $actual
    config_sha256   = $configPin
    trust_mode      = $(if ($TrustMode -eq 'Authenticode') { 'authenticode' } else { 'hash_pinned' })
    allowed_signers = $signers
    product_version = $ProductVersion
}
[IO.File]::WriteAllText((Join-Path $content 'intune-package.json'), ($pins | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))

if ($IntuneWinAppUtil) {
    & $IntuneWinAppUtil -c $content -s 'Install-DefenseClawIntune.ps1' -o $OutputDirectory -q
    if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil exited $LASTEXITCODE" }
}

$version = if ($ProductVersion) { $ProductVersion } else { '<the release version>' }
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
Uninstall command: DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall JSON=1
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later; dependency: PowerShell 7.4+ (x64 MSI) Win32 app
Detection rule:    Registry, HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise, value ProductVersion,
                   Version comparison, Greater than or equal to $version, 32-bit app on 64-bit clients: No
"@
