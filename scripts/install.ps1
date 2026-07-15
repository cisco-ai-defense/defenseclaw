# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Authenticated bootstrap for the native DefenseClaw Windows installer.

.DESCRIPTION
    This script is retained for compatibility with older PowerShell install
    commands. It does not install Python, uv, wheels, or individual gateway
    artifacts. It authenticates the release metadata and the native
    DefenseClawSetup-x64.exe, then delegates the complete install transaction
    to that executable.

    Remote mode downloads only fixed release assets from GitHub and a pinned
    Cosign verifier. Local mode performs no downloads and expects a complete
    release bundle plus a pinned Cosign executable.

.EXAMPLE
    $Version = "0.8.3"
    $InstallUrl = "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/$Version/scripts/install.ps1"
    & ([scriptblock]::Create((irm $InstallUrl))) -Version $Version

.EXAMPLE
    .\install.ps1 -Version 0.8.3 -Connector codex -Yes -Quickstart

.EXAMPLE
    .\install.ps1 -Local .\release -CosignPath .\tools\cosign-windows-amd64.exe -Yes
#>

[CmdletBinding()]
param(
    [string]$Connector = "",
    [string]$Version = "",
    [string]$Local = "",
    [string]$CosignPath = "",
    [ValidateSet("observe", "action", "")]
    [string]$QuickstartMode = "",
    [switch]$Quickstart,
    [switch]$NoOpenclaw,
    [switch]$NoPersistPath,
    [switch]$Yes,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # PowerShell editions that do not expose this legacy property already use
    # the operating system TLS policy.
}

$Repo = "cisco-ai-defense/defenseclaw"
$SetupAsset = "DefenseClawSetup-x64.exe"
$ProvenanceAsset = "$SetupAsset.provenance.json"
$UpgradeManifestAsset = "upgrade-manifest.json"
$ChecksumsAsset = "checksums.txt"
$ChecksumsSignatureAsset = "checksums.txt.sig"
$ChecksumsCertificateAsset = "checksums.txt.pem"
$ChecksumsBundleAsset = "checksums.txt.bundle"
$ExpectedPublisher = "Cisco Systems, Inc."
$SigstoreOIDCIssuer = "https://token.actions.githubusercontent.com"
$CosignVersion = "2.6.2"
$CosignAsset = "cosign-windows-amd64.exe"
$CosignSha256 = "DD6C61E510DA627BCAED4CD9DB844EC11CACD09826D814D89F7F68D40FEB07BE"
$CosignUrl = "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignAsset"
$ConnectorChoices = @(
    "codex",
    "claudecode",
    "none"
)
$HookConnectors = @()

function Write-Ok    { param([string]$Message) Write-Host "  + $Message" -ForegroundColor Green }
function Write-Warn2 { param([string]$Message) Write-Host "  ! $Message" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Message) Write-Host "  x $Message" -ForegroundColor Red }
function Write-Step  { param([string]$Message) Write-Host "`n--- $Message" -ForegroundColor Cyan }
function Die         { param([string]$Message) throw $Message }

function Show-Help {
    @"

DefenseClaw native Windows bootstrap

Usage:
  `$Version = "0.8.3"
  `$InstallUrl = "https://raw.githubusercontent.com/$Repo/`$Version/scripts/install.ps1"
  & ([scriptblock]::Create((irm `$InstallUrl))) -Version `$Version
  .\install.ps1 -Version 0.8.3 -Connector codex -Yes -Quickstart
  .\install.ps1 -Local .\release -CosignPath .\cosign-windows-amd64.exe

Options:
  -Connector <name>    Configure a connector ($($ConnectorChoices -join '|'))
  -NoOpenclaw          Legacy alias for -Connector none
  -Version <x.y.z>     Install one exact release (latest when omitted remotely)
  -Local <dir>         Use a complete local release bundle without network access
  -CosignPath <file>   Pinned Cosign binary for -Local (or place it in <dir>)
  -Quickstart          Configure the selected connector and start the gateway
  -QuickstartMode <m>  Quickstart policy mode (observe|action)
  -Yes                 Run native Setup silently without confirmation prompts
  -Help                Show this help

Local bundle requirements:
  $SetupAsset, $ProvenanceAsset, $UpgradeManifestAsset, $ChecksumsAsset,
  $ChecksumsSignatureAsset, $ChecksumsCertificateAsset, $ChecksumsBundleAsset,
  and a pinned Cosign binary.

Compatibility notes:
  -NoPersistPath is no longer supported because native Setup owns PATH lifecycle.
  A non-default DEFENSECLAW_HOME is not supported by the per-user native layout.

"@ | Write-Host
}

function Test-ReleaseVersion {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value -match '^\d+\.\d+\.\d+$'
}

function Assert-NativeWindowsX64 {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Die "scripts/install.ps1 supports native Windows only. Use scripts/install.sh on macOS or Linux."
    }
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if (-not [string]::Equals($architecture, "X64", [StringComparison]::OrdinalIgnoreCase)) {
        switch ($architecture.ToUpperInvariant()) {
            "ARM64" { Die "Windows ARM64 is not certified, including x64 emulation; use native Windows x64 (amd64)." }
            "X86"   { Die "32-bit Windows is not supported; use native Windows x64 (amd64)." }
            default { Die "Unsupported native Windows architecture: $architecture" }
        }
    }
}

function Assert-CompatibleLayoutRequest {
    if ($NoPersistPath) {
        Die "-NoPersistPath has no safe native Setup equivalent. Native Setup must own the user PATH entry so repair and uninstall remain consistent."
    }
    if (-not [string]::IsNullOrWhiteSpace($env:DEFENSECLAW_HOME)) {
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        $nativeHome = [IO.Path]::GetFullPath((Join-Path $profile ".defenseclaw")).TrimEnd('\')
        $requestedHome = [IO.Path]::GetFullPath($env:DEFENSECLAW_HOME).TrimEnd('\')
        if (-not $requestedHome.Equals($nativeHome, [StringComparison]::OrdinalIgnoreCase)) {
            Die "Native Windows Setup uses $nativeHome; custom DEFENSECLAW_HOME '$requestedHome' is not supported by this compatibility bootstrap."
        }
    }
}

function Set-PrivateDirectoryProtection {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "Bootstrap staging root must be a regular directory: $Path"
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) { Die "Current Windows identity has no user SID" }
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($identity.User)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($identity.User, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    if ($null -ne $item.PSObject.Methods["SetAccessControl"]) {
        $item.SetAccessControl($security)
    } else {
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.DirectoryInfo]$item,
            [Security.AccessControl.DirectorySecurity]$security
        )
    }
}

function New-PrivateStageRoot {
    $root = Join-Path ([IO.Path]::GetTempPath()) (
        ".defenseclaw-bootstrap-" + [guid]::NewGuid().ToString("N")
    )
    [IO.Directory]::CreateDirectory($root) | Out-Null
    try {
        Set-PrivateDirectoryProtection -Path $root
    } catch {
        Remove-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
        throw
    }
    return [IO.Path]::GetFullPath($root)
}

function Remove-PrivateStageRoot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if (-not ([IO.Path]::GetDirectoryName($full)).Equals(
            $temp, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -notmatch '^\.defenseclaw-bootstrap-[0-9a-f]{32}$') {
        Die "Refusing to clean an unexpected bootstrap staging path: $full"
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        [IO.Directory]::Delete($full)
        return
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
}

function Assert-RegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 0
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0) {
        Die "$Label must be a non-empty regular file: $Path"
    }
    if ($MaximumBytes -gt 0 -and $item.Length -gt $MaximumBytes) {
        Die "$Label exceeds its $MaximumBytes-byte limit: $Path"
    }
}

function Copy-RegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 0
    )

    Assert-RegularFile -Path $Source -Label $Label -MaximumBytes $MaximumBytes
    $inputStream = [IO.File]::Open(
        $Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $outputStream = [IO.File]::Open(
            $Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        try {
            $inputStream.CopyTo($outputStream)
            $outputStream.Flush($true)
        } finally {
            $outputStream.Dispose()
        }
    } finally {
        $inputStream.Dispose()
    }
    Assert-RegularFile -Path $Destination -Label $Label -MaximumBytes $MaximumBytes
}

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 0
    )

    try {
        Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing
    } catch {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        Die "Could not download required $Label from ${Uri}: $($_.Exception.Message)"
    }
    Assert-RegularFile -Path $Destination -Label $Label -MaximumBytes $MaximumBytes
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "")
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-ByteSha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') {
        Die "Expected SHA-256 for $Label is malformed"
    }
    $actual = Get-Sha256Hex -Path $Path
    if (-not $actual.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) {
        Die "SHA-256 mismatch for ${Label}: expected $Expected, got $actual"
    }
}

function Get-AuthenticatedChecksum {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')][string]$ChecksumsPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'Content')][string]$ChecksumsContent,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    $found = @()
    $lines = if ($PSCmdlet.ParameterSetName -eq 'Content') {
        $ChecksumsContent -split '\r?\n'
    } else {
        [IO.File]::ReadAllLines($ChecksumsPath)
    }
    foreach ($line in $lines) {
        if ($line -match '^([0-9a-fA-F]{64})[ \t]+\*?(.+?)[ \t]*$') {
            $listedName = $Matches[2].Trim().Replace('\', '/')
            if ($listedName.StartsWith('./', [StringComparison]::Ordinal)) {
                $listedName = $listedName.Substring(2)
            }
            if ($listedName.Equals($FileName, [StringComparison]::Ordinal)) {
                $found += $Matches[1]
            }
        }
    }
    if ($found.Count -ne 1) {
        Die "Authenticated $ChecksumsAsset contains $($found.Count) entries for $FileName; expected exactly one"
    }
    return $found[0]
}

function Invoke-CosignVerification {
    param(
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$ChecksumsPath,
        [Parameter(Mandatory = $true)][string]$SignaturePath,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$BundlePath,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion
    )

    Assert-Sha256 -Path $Verifier -Expected $CosignSha256 -Label "pinned Cosign verifier"
    $before = @{}
    foreach ($path in @(
        $Verifier, $ChecksumsPath, $SignaturePath, $CertificatePath, $BundlePath
    )) {
        $before[$path] = Get-Sha256Hex -Path $path
    }
    # Release candidates are signed before tag creation by the protected main
    # workflow.  Do not accept a tag-ref identity: it is not the reviewed
    # signing path and would broaden the offline trust policy unnecessarily.
    $identity = "^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$"
    $previousErrorActionPreference = $ErrorActionPreference
    $output = @()
    $exitCode = 1
    $verifyArguments = @(
        "verify-blob",
        "--certificate", $CertificatePath,
        "--signature", $SignaturePath,
        "--bundle", $BundlePath,
        "--offline",
        "--certificate-identity-regexp", $identity,
        "--certificate-oidc-issuer", $SigstoreOIDCIssuer,
        $ChecksumsPath
    )
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& $Verifier @verifyArguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        Die "Release checksum signature verification failed (exit $exitCode): $(($output -join ' ').Trim())"
    }
    foreach ($path in $before.Keys) {
        $after = Get-Sha256Hex -Path $path
        if (-not $after.Equals($before[$path], [StringComparison]::OrdinalIgnoreCase)) {
            Die "Release verification input changed while Cosign was running: $path"
        }
    }
    $authenticatedBytes = [IO.File]::ReadAllBytes($ChecksumsPath)
    $authenticatedHash = Get-ByteSha256Hex -Bytes $authenticatedBytes
    if (-not $authenticatedHash.Equals(
        $before[$ChecksumsPath], [StringComparison]::OrdinalIgnoreCase)) {
        Die "Release checksum content changed after Cosign verification: $ChecksumsPath"
    }
    try {
        $authenticatedContent = [Text.UTF8Encoding]::new($false, $true).GetString($authenticatedBytes)
    } catch {
        Die "Authenticated $ChecksumsAsset is not valid UTF-8: $($_.Exception.Message)"
    }
    Write-Ok "Release checksum signature verified (Sigstore)"
    return $authenticatedContent
}

function Assert-UpgradeManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion
    )

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Die "Could not parse authenticated ${UpgradeManifestAsset}: $($_.Exception.Message)"
    }
    if ([int]$manifest.schema_version -ne 1 -or
        -not ([string]$manifest.release_version).Equals($ReleaseVersion, [StringComparison]::Ordinal)) {
        Die "Authenticated upgrade manifest does not describe DefenseClaw $ReleaseVersion"
    }
    $installer = $manifest.windows_installer
    if ($null -eq $installer -or
        -not ([string]$installer.asset).Equals($SetupAsset, [StringComparison]::Ordinal)) {
        Die "Authenticated upgrade manifest does not select $SetupAsset"
    }
    $architectures = @($installer.architectures)
    if ($architectures.Count -ne 1 -or
        -not ([string]$architectures[0]).Equals("amd64", [StringComparison]::Ordinal)) {
        Die "Authenticated upgrade manifest does not describe the exact native Windows amd64 surface"
    }
    if ($null -eq $installer.authenticode -or
        $installer.authenticode.required -ne $true -or
        -not ([string]$installer.authenticode.publisher).Equals(
            $ExpectedPublisher, [StringComparison]::Ordinal)) {
        Die "Authenticated upgrade manifest does not require the pinned DefenseClaw publisher"
    }
    if (-not ([string]$installer.managed_policy).Equals("respect", [StringComparison]::Ordinal)) {
        Die "Authenticated upgrade manifest has an unsupported Windows managed-policy contract"
    }
}

function Assert-SetupProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$SetupSha256
    )

    try {
        $provenance = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Die "Could not parse authenticated ${ProvenanceAsset}: $($_.Exception.Message)"
    }
    if ([int]$provenance.schema_version -ne 1 -or
        -not ([string]$provenance.artifact).Equals($SetupAsset, [StringComparison]::Ordinal) -or
        -not ([string]$provenance.version).Equals($ReleaseVersion, [StringComparison]::Ordinal) -or
        -not ([string]$provenance.distribution_flavor).Equals("oss", [StringComparison]::Ordinal)) {
        Die "Authenticated Setup provenance does not describe the exact DefenseClaw $ReleaseVersion OSS artifact"
    }
    if ($provenance.unsigned -isnot [bool] -or $provenance.unsigned) {
        Die "Authenticated Setup provenance does not describe a signed release artifact"
    }
    if ([string]$provenance.source_commit -notmatch '^[0-9a-fA-F]{40}$') {
        Die "Authenticated Setup provenance has an invalid source commit"
    }
    $claimedSha256 = [string]$provenance.artifact_sha256
    if ($claimedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        -not $claimedSha256.Equals($SetupSha256, [StringComparison]::OrdinalIgnoreCase)) {
        Die "Authenticated Setup provenance does not match the exact signed checksum for $SetupAsset"
    }
}

function Assert-SetupAuthenticode {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [string]::IsNullOrWhiteSpace($Local)) {
        $exitCode = Invoke-BoundedNativeProcess -FilePath $Path `
            -Arguments @('/verify') -TimeoutSeconds 120 -Hidden
        if ($exitCode -ne 0) {
            Die "Setup offline Authenticode verification failed (exit $exitCode)"
        }
        Write-Ok "Setup Authenticode signature verified offline ($ExpectedPublisher)"
        return
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $publisher = ""
    if ($null -ne $signature.SignerCertificate) {
        $publisher = $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    }
    if ([string]$signature.Status -ne "Valid" -or
        -not $publisher.Equals($ExpectedPublisher, [StringComparison]::Ordinal)) {
        Die "Setup Authenticode signature is not trusted: status='$($signature.Status)', publisher='$publisher'"
    }
    Write-Ok "Setup Authenticode signature verified ($ExpectedPublisher)"
}

function Resolve-RemoteVersion {
    if (-not [string]::IsNullOrWhiteSpace($Version)) {
        if (-not (Test-ReleaseVersion -Value $Version)) {
            Die "Invalid -Version '$Version'; expected x.y.z"
        }
        return $Version
    }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{
            "User-Agent" = "defenseclaw-native-bootstrap"
        }
    } catch {
        Die "Failed to resolve the latest release. Use -Version x.y.z or -Local <dir>."
    }
    $tag = [string]$release.tag_name
    if (-not (Test-ReleaseVersion -Value $tag)) {
        Die "Could not parse an exact release version from tag '$tag'"
    }
    return $tag
}

function Resolve-LocalCosignSource {
    param([Parameter(Mandatory = $true)][string]$LocalRoot)

    if (-not [string]::IsNullOrWhiteSpace($CosignPath)) {
        return (Resolve-Path -LiteralPath $CosignPath -ErrorAction Stop).Path
    }
    foreach ($candidate in @(
        (Join-Path $LocalRoot $CosignAsset),
        (Join-Path $LocalRoot "cosign.exe")
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $command = Get-Command cosign.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $command) { return $command.Source }
    Die "Local/offline mode requires pinned Cosign $CosignVersion. Supply -CosignPath or place $CosignAsset in '$LocalRoot'."
}

function Read-LocalManifestVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $value = [string]$manifest.release_version
    } catch {
        Die "Could not read local ${UpgradeManifestAsset}: $($_.Exception.Message)"
    }
    if (-not (Test-ReleaseVersion -Value $value)) {
        Die "Local upgrade manifest has an invalid release_version '$value'"
    }
    return $value
}

function Invoke-StagedChecksumVerification {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$Verifier
    )

    $checksums = Join-Path $StageRoot $ChecksumsAsset
    $signature = Join-Path $StageRoot $ChecksumsSignatureAsset
    $certificate = Join-Path $StageRoot $ChecksumsCertificateAsset
    $sigstoreBundle = Join-Path $StageRoot $ChecksumsBundleAsset

    return Invoke-CosignVerification -Verifier $Verifier -ChecksumsPath $checksums `
        -SignaturePath $signature -CertificatePath $certificate -BundlePath $sigstoreBundle `
        -ReleaseVersion $ReleaseVersion
}

function Complete-StagedBundleVerification {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$ChecksumsContent
    )

    $setup = Join-Path $StageRoot $SetupAsset
    $setupSha = Get-AuthenticatedChecksum -ChecksumsContent $ChecksumsContent -FileName $SetupAsset
    Assert-StagedUpgradeManifest -StageRoot $StageRoot -ReleaseVersion $ReleaseVersion `
        -ChecksumsContent $ChecksumsContent
    Assert-StagedSetupProvenance -StageRoot $StageRoot -ReleaseVersion $ReleaseVersion `
        -SetupSha256 $setupSha -ChecksumsContent $ChecksumsContent
    Assert-Sha256 -Path $setup -Expected $setupSha -Label $SetupAsset
    Assert-SetupAuthenticode -Path $setup

    return [pscustomobject]@{
        Root = $StageRoot
        Setup = $setup
        SetupSha256 = $setupSha
        Version = $ReleaseVersion
    }
}

function Assert-StagedUpgradeManifest {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$ChecksumsContent
    )

    $manifest = Join-Path $StageRoot $UpgradeManifestAsset
    $manifestSha = Get-AuthenticatedChecksum -ChecksumsContent $ChecksumsContent `
        -FileName $UpgradeManifestAsset
    Assert-Sha256 -Path $manifest -Expected $manifestSha -Label $UpgradeManifestAsset
    Assert-UpgradeManifest -Path $manifest -ReleaseVersion $ReleaseVersion
}

function Assert-StagedSetupProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$SetupSha256,
        [Parameter(Mandatory = $true)][string]$ChecksumsContent
    )

    $provenance = Join-Path $StageRoot $ProvenanceAsset
    $provenanceSha = Get-AuthenticatedChecksum -ChecksumsContent $ChecksumsContent `
        -FileName $ProvenanceAsset
    Assert-Sha256 -Path $provenance -Expected $provenanceSha -Label $ProvenanceAsset
    Assert-SetupProvenance -Path $provenance -ReleaseVersion $ReleaseVersion `
        -SetupSha256 $SetupSha256
}

function Stage-RemoteBundle {
    param([Parameter(Mandatory = $true)][string]$ReleaseVersion)

    $stage = New-PrivateStageRoot
    try {
        $releaseBase = "https://github.com/$Repo/releases/download/$ReleaseVersion"
        $cosign = Join-Path $stage $CosignAsset
        Invoke-DownloadFile -Uri $CosignUrl -Destination $cosign -Label "pinned Cosign verifier" -MaximumBytes 104857600
        Assert-Sha256 -Path $cosign -Expected $CosignSha256 -Label "pinned Cosign verifier"
        # Authenticate the release root before downloading the large executable
        # or any metadata that will influence the handoff.
        foreach ($asset in @(
            @{ Name = $ChecksumsAsset; Maximum = 16777216 },
            @{ Name = $ChecksumsSignatureAsset; Maximum = 1048576 },
            @{ Name = $ChecksumsCertificateAsset; Maximum = 1048576 },
            @{ Name = $ChecksumsBundleAsset; Maximum = 16777216 }
        )) {
            Invoke-DownloadFile -Uri "$releaseBase/$($asset.Name)" `
                -Destination (Join-Path $stage $asset.Name) -Label $asset.Name `
                -MaximumBytes $asset.Maximum
        }
        $authenticatedChecksums = Invoke-StagedChecksumVerification -StageRoot $stage `
            -ReleaseVersion $ReleaseVersion -Verifier $cosign
        Invoke-DownloadFile -Uri "$releaseBase/$UpgradeManifestAsset" `
            -Destination (Join-Path $stage $UpgradeManifestAsset) `
            -Label $UpgradeManifestAsset -MaximumBytes 1048576
        Assert-StagedUpgradeManifest -StageRoot $stage -ReleaseVersion $ReleaseVersion `
            -ChecksumsContent $authenticatedChecksums
        Invoke-DownloadFile -Uri "$releaseBase/$ProvenanceAsset" `
            -Destination (Join-Path $stage $ProvenanceAsset) `
            -Label $ProvenanceAsset -MaximumBytes 1048576
        $setupSha = Get-AuthenticatedChecksum `
            -ChecksumsContent $authenticatedChecksums -FileName $SetupAsset
        Assert-StagedSetupProvenance -StageRoot $stage -ReleaseVersion $ReleaseVersion `
            -SetupSha256 $setupSha -ChecksumsContent $authenticatedChecksums
        Invoke-DownloadFile -Uri "$releaseBase/$SetupAsset" `
            -Destination (Join-Path $stage $SetupAsset) `
            -Label $SetupAsset -MaximumBytes 2147483648
        return Complete-StagedBundleVerification -StageRoot $stage `
            -ReleaseVersion $ReleaseVersion -ChecksumsContent $authenticatedChecksums
    } catch {
        Remove-PrivateStageRoot -Path $stage
        throw
    }
}

function Stage-LocalBundle {
    $resolved = Resolve-Path -LiteralPath $Local -ErrorAction Stop
    $localRoot = [IO.Path]::GetFullPath($resolved.Path)
    $rootItem = Get-Item -LiteralPath $localRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "-Local must name a regular release directory: $localRoot"
    }

    $stage = New-PrivateStageRoot
    try {
        foreach ($asset in @(
            @{ Name = $ChecksumsAsset; Maximum = 16777216 },
            @{ Name = $ChecksumsSignatureAsset; Maximum = 1048576 },
            @{ Name = $ChecksumsCertificateAsset; Maximum = 1048576 },
            @{ Name = $ChecksumsBundleAsset; Maximum = 16777216 },
            @{ Name = $UpgradeManifestAsset; Maximum = 1048576 },
            @{ Name = $ProvenanceAsset; Maximum = 1048576 }
        )) {
            Copy-RegularFile -Source (Join-Path $localRoot $asset.Name) `
                -Destination (Join-Path $stage $asset.Name) -Label $asset.Name `
                -MaximumBytes $asset.Maximum
        }
        $releaseVersion = if ([string]::IsNullOrWhiteSpace($Version)) {
            Read-LocalManifestVersion -Path (Join-Path $stage $UpgradeManifestAsset)
        } else {
            if (-not (Test-ReleaseVersion -Value $Version)) {
                Die "Invalid -Version '$Version'; expected x.y.z"
            }
            $Version
        }
        $cosignSource = Resolve-LocalCosignSource -LocalRoot $localRoot
        $cosign = Join-Path $stage $CosignAsset
        Copy-RegularFile -Source $cosignSource -Destination $cosign `
            -Label "pinned Cosign verifier" -MaximumBytes 104857600
        Assert-Sha256 -Path $cosign -Expected $CosignSha256 -Label "pinned Cosign verifier"
        $authenticatedChecksums = Invoke-StagedChecksumVerification -StageRoot $stage `
            -ReleaseVersion $releaseVersion -Verifier $cosign
        Assert-StagedUpgradeManifest -StageRoot $stage -ReleaseVersion $releaseVersion `
            -ChecksumsContent $authenticatedChecksums
        $setupSha = Get-AuthenticatedChecksum `
            -ChecksumsContent $authenticatedChecksums -FileName $SetupAsset
        Assert-StagedSetupProvenance -StageRoot $stage -ReleaseVersion $releaseVersion `
            -SetupSha256 $setupSha -ChecksumsContent $authenticatedChecksums
        Copy-RegularFile -Source (Join-Path $localRoot $SetupAsset) `
            -Destination (Join-Path $stage $SetupAsset) -Label $SetupAsset `
            -MaximumBytes 2147483648
        return Complete-StagedBundleVerification -StageRoot $stage `
            -ReleaseVersion $releaseVersion -ChecksumsContent $authenticatedChecksums
    } catch {
        Remove-PrivateStageRoot -Path $stage
        throw
    }
}

function Resolve-SelectedConnector {
    $selected = $Connector.Trim().ToLowerInvariant()
    switch ($selected) {
        "claude"      { $selected = "claudecode" }
        "claude-code" { $selected = "claudecode" }
    }
    if ($NoOpenclaw -and [string]::IsNullOrWhiteSpace($selected)) {
        $selected = "none"
    }
    if (-not [string]::IsNullOrWhiteSpace($selected) -and
        $ConnectorChoices -notcontains $selected) {
        Die "Invalid -Connector '$Connector'. Choices: $($ConnectorChoices -join ', ')"
    }
    return $selected
}

function New-SetupArgumentList {
    param([string]$SelectedConnector)

    $arguments = @("/norestart", "INSTALLSCOPE=user")
    if ($Yes) { $arguments = @("/quiet") + $arguments }
    if ($Yes -and [string]::IsNullOrWhiteSpace($SelectedConnector)) {
        $SelectedConnector = "none"
    }
    if (-not [string]::IsNullOrWhiteSpace($SelectedConnector)) {
        $arguments += "CONNECTOR=$SelectedConnector"
    }
    if ($Quickstart) {
        $mode = if ([string]::IsNullOrWhiteSpace($QuickstartMode)) { "observe" } else { $QuickstartMode }
        if (-not ($Yes -and $SelectedConnector -eq "none")) {
            $arguments += "MODE=$mode"
        }
        if (-not [string]::IsNullOrWhiteSpace($SelectedConnector) -and
            $SelectedConnector -ne "none") {
            $arguments += "STARTGATEWAY=1"
        } elseif ($SelectedConnector -eq "none" -or $Yes) {
            $arguments += "STARTGATEWAY=0"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($QuickstartMode)) {
        Write-Warn2 "-QuickstartMode is ignored unless -Quickstart is specified"
    }
    return [string[]]$arguments
}

function Invoke-BoundedNativeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [switch]$Hidden
    )

    $start = @{
        FilePath = $FilePath
        PassThru = $true
    }
    if ($Arguments.Count -gt 0) { $start['ArgumentList'] = $Arguments }
    if ($Hidden) { $start['WindowStyle'] = 'Hidden' }
    $process = Start-Process @start
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $treeKillError = $null
            try {
                $process.Kill($true)
            } catch {
                $treeKillError = $_.Exception.Message
                $systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
                $taskkillPath = Join-Path $systemDirectory 'taskkill.exe'
                $taskkill = Start-Process -FilePath $taskkillPath `
                    -ArgumentList @('/PID', [string]$process.Id, '/T', '/F') `
                    -PassThru -WindowStyle Hidden
                try {
                    if (-not $taskkill.WaitForExit(10000)) {
                        try { $taskkill.Kill() } catch {}
                        throw "Timed out while terminating native process tree: $FilePath"
                    }
                } finally {
                    $taskkill.Dispose()
                }
            }
            if (-not $process.WaitForExit(10000)) {
                throw "Native process timed out and cleanup did not complete: $FilePath"
            }
            if ($treeKillError) {
                Write-Warn2 "Used taskkill fallback for timed-out native process tree: $treeKillError"
            }
            throw "Native process timed out after $TimeoutSeconds seconds: $FilePath"
        }
        return [int]$process.ExitCode
    } finally {
        $process.Dispose()
    }
}

function Invoke-NativeSetup {
    param(
        [Parameter(Mandatory = $true)][string]$SetupPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    # Repeat both independent checks immediately before execution. The setup
    # file lives in a private directory, but this also detects same-user or
    # security-product replacement between initial verification and handoff.
    Assert-Sha256 -Path $SetupPath -Expected $ExpectedSha256 -Label $SetupAsset
    Assert-SetupAuthenticode -Path $SetupPath
    Write-Step "Starting authenticated native Setup"
    return Invoke-BoundedNativeProcess -FilePath $SetupPath -Arguments $Arguments `
        -TimeoutSeconds 3600
}

function Main {
    if ($Help) { Show-Help; return 0 }
    Assert-NativeWindowsX64
    Assert-CompatibleLayoutRequest

    Write-Host ""
    Write-Host "  DefenseClaw native Windows bootstrap" -ForegroundColor White
    Write-Host "  Authenticated handoff to $SetupAsset" -ForegroundColor DarkGray

    $selectedConnector = Resolve-SelectedConnector
    $arguments = New-SetupArgumentList -SelectedConnector $selectedConnector
    $bundle = $null
    try {
        if ([string]::IsNullOrWhiteSpace($Local)) {
            $releaseVersion = Resolve-RemoteVersion
            Write-Step "Authenticating DefenseClaw $releaseVersion release assets"
            $bundle = Stage-RemoteBundle -ReleaseVersion $releaseVersion
        } else {
            Write-Step "Authenticating local/offline release assets"
            $bundle = Stage-LocalBundle
        }
        Write-Ok "Authenticated $SetupAsset for DefenseClaw $($bundle.Version)"
        $exitCode = Invoke-NativeSetup -SetupPath $bundle.Setup `
            -ExpectedSha256 $bundle.SetupSha256 -Arguments $arguments
        if ($exitCode -eq 0) {
            Write-Ok "Native DefenseClaw Setup completed successfully"
        } else {
            Write-Err2 "Native DefenseClaw Setup exited with code $exitCode"
        }
        return $exitCode
    } finally {
        if ($null -ne $bundle -and -not [string]::IsNullOrWhiteSpace($bundle.Root)) {
            Remove-PrivateStageRoot -Path $bundle.Root
        }
    }
}

# Dot-sourcing exposes the small verification and argument-building seams to
# regression tests without initiating downloads or installation. -File and the
# documented in-memory scriptblock invocation both execute Main.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Main
        if ([int]$result -ne 0) {
            if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
                throw "Native DefenseClaw Setup exited with code $result"
            }
            exit [int]$result
        }
        # A script downloaded and invoked as an in-memory ScriptBlock runs in
        # the caller's PowerShell process. Returning here keeps that terminal
        # open; -File invocations still receive an exact process exit code.
        if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) { exit 0 }
    } catch {
        Write-Err2 $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { throw }
        exit 1
    }
}
