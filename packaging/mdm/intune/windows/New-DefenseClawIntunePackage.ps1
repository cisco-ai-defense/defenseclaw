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
    -AllowedSigners), copies it with either config.yaml or a signed policy
    bundle and optional trust anchors into a content folder, writes intune-package.json with the SHA-256 pins
    the launcher re-checks on the device, and, when -IntuneWinAppUtil is
    given, wraps the folder into a .intunewin.

    Never put credentials in config.yaml: the Win32 app content is not secret
    storage. Deliver the AI Defense key separately (see the Intune on Windows page in the docs).
    A bundle package needs an installed base deployment. Verify the bundle offline
    with defenseclaw-gateway enterprise bundle verify before packaging it.

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
    [string]$BundlePath = '',
    [string]$TrustAnchorPath = '',
    [string]$RequireBundle = '',
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

if ($BundlePath -and $ConfigPath) { throw '-BundlePath cannot be combined with -ConfigPath: the signed bundle carries the config. Build the first-install (base) package with -ConfigPath, and each bundle package with -BundlePath as an Intune dependency of the base app' }
if ($TrustAnchorPath -and -not $BundlePath) { throw '-TrustAnchorPath needs -BundlePath: the kit installs trust anchors together with a signed bundle' }
if ($BundlePath -and -not $RequireBundle) { throw '-RequireBundle is required with -BundlePath for the bundle app detection rule' }
if ($RequireBundle -and -not $BundlePath) { throw '-RequireBundle needs -BundlePath' }
if ($RequireBundle -and $RequireBundle -cnotmatch '^(?:[1-9][0-9]{0,18}|b-[0-9A-HJKMNP-TV-Z]{26})$') { throw '-RequireBundle must be a positive version number or bundle id' }
if ($ProductVersion -and $ProductVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$') { throw '-ProductVersion must be a valid version' }
if ($BundlePath) {
    $BundlePath = (Resolve-Path -LiteralPath $BundlePath).ProviderPath
    $bundleItem = Get-Item -LiteralPath $BundlePath -Force
    if (-not ($bundleItem -is [IO.FileInfo]) -or ($bundleItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '-BundlePath must be a regular file' }
    if ($bundleItem.Length -lt 1 -or $bundleItem.Length -gt 4MB) { throw '-BundlePath must contain 1 to 4194304 bytes' }
}
if ($TrustAnchorPath) {
    $TrustAnchorPath = (Resolve-Path -LiteralPath $TrustAnchorPath).ProviderPath
    $anchorItem = Get-Item -LiteralPath $TrustAnchorPath -Force
    if (-not ($anchorItem -is [IO.FileInfo]) -or ($anchorItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '-TrustAnchorPath must be a regular file' }
    if ($anchorItem.Length -gt 64KB) { throw '-TrustAnchorPath exceeds 65536 bytes' }
    $anchorText = Get-Content -LiteralPath $TrustAnchorPath -Raw
    if ($anchorText -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') { throw '-TrustAnchorPath contains a private key' }
    try { $anchorJson = $anchorText | ConvertFrom-Json -ErrorAction Stop } catch { throw '-TrustAnchorPath must contain a JSON object with schema_version 1' }
    if ($null -eq $anchorJson -or $anchorJson -isnot [pscustomobject] -or $null -eq $anchorJson.PSObject.Properties['schema_version'] -or $anchorJson.schema_version -isnot [long] -or $anchorJson.schema_version -ne 1) { throw '-TrustAnchorPath must contain a JSON object with schema_version 1' }
}

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

$configText = ''
if ($ConfigPath) {
    $configText = Get-Content -LiteralPath $ConfigPath -Raw
    if ($configText -match '(?im)^\s*api_key\s*:\s*\S') { throw 'config.yaml contains an inline api_key; the standalone profile rejects it and the package must not carry credentials' }
}

$content = Join-Path $OutputDirectory 'content'
if (Test-Path -LiteralPath $content) { throw "$content already exists; use an empty -OutputDirectory" }
New-Item -ItemType Directory -Path $content -Force | Out-Null
Copy-Item -LiteralPath $setup -Destination (Join-Path $content 'DefenseClawSetup-Enterprise-Standalone-x64.exe')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-DefenseClawIntune.ps1') -Destination $content
$configPin = ''
if ($ConfigPath) {
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $content 'config.yaml')
    $configPin = (Get-FileHash -LiteralPath (Join-Path $content 'config.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
}
$bundlePin = ''
$anchorPin = ''
if ($BundlePath) {
    Copy-Item -LiteralPath $BundlePath -Destination (Join-Path $content 'policy.dcbundle')
    $bundlePin = (Get-FileHash -LiteralPath (Join-Path $content 'policy.dcbundle') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($TrustAnchorPath) {
        Copy-Item -LiteralPath $TrustAnchorPath -Destination (Join-Path $content 'bundle-anchors.json')
        $anchorPin = (Get-FileHash -LiteralPath (Join-Path $content 'bundle-anchors.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$pins = [ordered]@{
    schema_version  = 1
    setup_sha256    = $actual
    config_sha256   = $configPin
    bundle_sha256   = $bundlePin
    trust_anchors_sha256 = $anchorPin
    trust_mode      = $(if ($TrustMode -eq 'Authenticode') { 'authenticode' } else { 'hash_pinned' })
    allowed_signers = $signers
    product_version = $ProductVersion
}
[IO.File]::WriteAllText((Join-Path $content 'intune-package.json'), ($pins | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))

if ($BundlePath) {
    $detectSource = Join-Path $PSScriptRoot '..\..\windows\detect.ps1'
    if (-not (Test-Path -LiteralPath $detectSource -PathType Leaf)) { throw 'packaging/mdm/windows/detect.ps1 not found next to the kit' }
    $detectText = Get-Content -LiteralPath $detectSource -Raw
    $bundleDefault = "[string]`$RequireBundle = ''"
    if (([regex]::Matches($detectText, [regex]::Escape($bundleDefault))).Count -ne 1) { throw 'detect.ps1 changed; update the packager' }
    $detectText = $detectText.Replace($bundleDefault, "[string]`$RequireBundle = '$RequireBundle'")
    if ($ProductVersion) {
        $versionDefault = "[string]`$MinimumVersion = ''"
        if (([regex]::Matches($detectText, [regex]::Escape($versionDefault))).Count -ne 1) { throw 'detect.ps1 changed; update the packager' }
        $detectText = $detectText.Replace($versionDefault, "[string]`$MinimumVersion = '$ProductVersion'")
    }
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'detect-bundle.ps1'), $detectText, [Text.UTF8Encoding]::new($false))
}

if ($IntuneWinAppUtil) {
    & $IntuneWinAppUtil -c $content -s 'Install-DefenseClawIntune.ps1' -o $OutputDirectory -q
    if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil exited $LASTEXITCODE" }
}

$version = if ($ProductVersion) { $ProductVersion } else { '<the release version>' }
if ($BundlePath) {
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
Uninstall command: cmd.exe /c exit 0
                   (a policy bundle is not uninstalled: roll back with a new, higher signed version; remove DefenseClaw with the base app's uninstall)
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later
Dependency:        the DefenseClaw base app (built with -ConfigPath), Automatically install: Yes. Setup cannot take a bundle on the first install.
Supersedence:      supersede the previous bundle app; Uninstall previous version: No
Detection rule:    Custom script $(Join-Path $OutputDirectory 'detect-bundle.ps1'), Run script as 32-bit process on 64-bit clients: No
Pins:              policy.dcbundle sha256 $bundlePin; bundle-anchors.json sha256 $(if ($anchorPin) { $anchorPin } else { 'none' })
Setup:             build each bundle package with the Setup of the release the devices run (an older Setup is refused: downgrade_refused)
"@
    return
}
@"
Win32 app content: $content
Install command:   %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
Uninstall command: DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall JSON=1
Install behavior:  System
Return codes:      0 Success, 1707 Success, 3010 Soft reboot, 1641 Hard reboot, 1618 Retry (defaults; 1603 and 1639 report Failed)
Requirements:      x64 only; Windows 10 22H2 or later; dependency: PowerShell 7.4+ (x64 MSI) Win32 app
Detection rule:    Registry, HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise, value ProductVersion,
                   Version comparison, Greater than or equal to $version, 32-bit app on 64-bit clients: No
Purge twin:        DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall PURGE=1 JSON=1 (assign as Uninstall when purging)
Bundle mode:       once a device takes signed bundles, do not assign a package built with -ConfigPath to it again (Setup refuses it with bundle_required); build upgrade packages without -ConfigPath.
"@
