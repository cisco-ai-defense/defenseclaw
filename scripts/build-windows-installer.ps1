# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Build the native offline Windows setup executable.

.DESCRIPTION
    Produces DefenseClawSetup-x64.exe from already-built release artifacts:
    the GoReleaser-shaped Windows gateway zip and the DefenseClaw Python wheel.
    The output is a native Windows executable that embeds a complete offline
    payload: gateway zip, wheel, CPython embeddable runtime, locked
    site-packages tree, and a small native CLI launcher.

    Local/PR builds are unsigned and clearly marked. Production release signing
    is enabled only when real Authenticode credentials are provided via
    WINDOWS_SIGNING_CERT_BASE64 and WINDOWS_SIGNING_CERT_PASSWORD.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DistRoot,
    [string]$OutRoot = $DistRoot,
    [string]$Version = "",
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) "defenseclaw-windows-installer-build"),
    [ValidateSet('oss', 'managed-enterprise')][string]$DistributionFlavor = 'oss',
    [switch]$SkipSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PythonVersion = "3.12.10"
$PythonEmbedName = "python-$PythonVersion-embed-amd64.zip"
$PythonEmbedUrl = "https://www.python.org/ftp/python/$PythonVersion/$PythonEmbedName"
$PythonEmbedSha256 = "4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3"
$WinUnicodeSourceName = 'win_unicode_console-0.5.zip'
$WinUnicodeSourceUrl = 'https://files.pythonhosted.org/packages/89/8d/7aad74930380c8972ab282304a2ff45f3d4927108bb6693cabcc9fc6a099/win_unicode_console-0.5.zip'
$WinUnicodeSourceSha256 = 'D4142D4D56D46F449D6F00536A73625A871CBA040F0BC1A2E305A04578F07D1E'
$CosignVersion = '2.6.2'
$CosignName = 'cosign-windows-amd64.exe'
$CosignUrl = "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignName"
$CosignSha256 = 'DD6C61E510DA627BCAED4CD9DB844EC11CACD09826D814D89F7F68D40FEB07BE'

function Resolve-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path)
}

function Test-PathWithin([string]$Path, [string]$Root) {
    $candidate = Resolve-FullPath $Path
    $parent = (Resolve-FullPath $Root).TrimEnd('\')
    return $candidate.Equals($parent, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Remove-SafeTree([string]$Path, [string]$Root) {
    $full = Resolve-FullPath $Path
    if (-not (Test-PathWithin $full $Root)) {
        throw "Refusing to remove path outside build root: $full"
    }
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    }
}

function Invoke-CheckedProcess([string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory = (Get-Location).Path) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($arg in $ArgumentList) { [void]$start.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::Start($start)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stdout) { Write-Host $stdout.TrimEnd() }
    if ($stderr) { Write-Host $stderr.TrimEnd() }
    if ($process.ExitCode -ne 0) {
        throw "$FilePath exited $($process.ExitCode)"
    }
}

function Get-ProjectVersion {
    $text = Get-Content -LiteralPath "pyproject.toml" -Raw -Encoding UTF8
    if ($text -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw "Could not resolve project version from pyproject.toml"
    }
    return $Matches[1]
}

function Get-GitSourceCommit([string]$RepositoryRoot) {
    $git = (Get-Command 'git.exe' -ErrorAction Stop).Source
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $git
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-C', $RepositoryRoot, 'rev-parse', '--verify', 'HEAD')) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Could not resolve the installer source commit: $($stderr.Trim())"
        }
    } finally {
        $process.Dispose()
    }
    $commit = $stdout.Trim().ToLowerInvariant()
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw "Git returned an invalid installer source commit: $commit"
    }
    return $commit
}

function Copy-RequiredFile([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Missing required file: $Source"
    }
    if ((Resolve-FullPath $Source).Equals((Resolve-FullPath $Destination), [StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Destination)) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Write-ZipFromDirectory([string]$Source, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
    $items = @(Get-ChildItem -LiteralPath $Source -Force)
    if (-not $items) {
        throw "Cannot zip empty directory: $Source"
    }
    Compress-Archive -LiteralPath ($items | ForEach-Object { $_.FullName }) -DestinationPath $Destination -Force
}

function Get-FileHashHex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Protect-SensitiveDirectory([string]$Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-TrustedTimestampUrl {
    $value = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_TIMESTAMP_URL')
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = 'https://timestamp.digicert.com'
    }
    $uri = $null
    if (-not [Uri]::TryCreate($value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or
        $uri.UserInfo -or
        $uri.Host -notin @('timestamp.digicert.com', 'timestamp.sectigo.com')) {
        throw 'WINDOWS_SIGNING_TIMESTAMP_URL must be an allowlisted HTTPS timestamp service.'
    }
    return $uri.AbsoluteUri
}

function Sign-SetupIfConfigured([string]$SetupPath, [string]$BuildRoot) {
    if ($SkipSigning) {
        Write-Warning "Skipping Authenticode signing by request; artifact is unsigned."
        return $false
    }
    $cert64 = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")
    $certPassword = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD")
    if ([string]::IsNullOrWhiteSpace($cert64) -or [string]::IsNullOrWhiteSpace($certPassword)) {
        Write-Warning "No real Authenticode credentials provided; artifact is an unsigned local/PR build."
        return $false
    }
    $signtool = (Get-Command 'signtool.exe' -ErrorAction Stop).Source
    $signingRoot = Join-Path $BuildRoot 'signing-private'
    Remove-SafeTree $signingRoot $BuildRoot
    Protect-SensitiveDirectory $signingRoot
    $pfx = Join-Path $signingRoot 'authenticode.pfx'
    $imported = @()
    try {
        [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($cert64))
        $securePassword = ConvertTo-SecureString $certPassword -AsPlainText -Force
        $probe = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfx,
            $certPassword,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        try { $thumbprint = $probe.Thumbprint } finally { $probe.Dispose() }
        if (Test-Path -LiteralPath "Cert:\CurrentUser\My\$thumbprint") {
            throw "Refusing to replace an existing signing certificate in the current-user store: $thumbprint"
        }
        $imported = @(Import-PfxCertificate -FilePath $pfx -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Password $securePassword -Exportable:$false)
        $signer = @($imported | Where-Object { $_.Thumbprint -eq $thumbprint })
        if ($signer.Count -ne 1 -or -not $signer[0].HasPrivateKey) {
            throw 'The imported Authenticode certificate did not expose exactly one signing private key.'
        }
        Invoke-CheckedProcess $signtool @(
            'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', (Get-TrustedTimestampUrl),
            '/s', 'My', '/sha1', $thumbprint, $SetupPath
        )
        $signature = Get-AuthenticodeSignature -LiteralPath $SetupPath
        $publisher = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.GetNameInfo(
                [Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
            )
        } else { '' }
        if ($signature.Status -ne 'Valid' -or $publisher -ne 'Cisco Systems, Inc.') {
            throw "Authenticode signature validation failed: status=$($signature.Status), publisher=$publisher"
        }
        return $true
    } finally {
        foreach ($certificate in $imported) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
        }
        Remove-SafeTree $signingRoot $BuildRoot
    }
}

if (-not $IsWindows) {
    throw "The native Windows installer must be built on a native Windows runner."
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw "The native Windows installer build supports only Windows x64."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

if ($DistributionFlavor -eq 'managed-enterprise') {
    throw @'
The public Windows installer builder cannot produce a managed-enterprise artifact. A managed Windows release requires the private CMID provider overlay, its pinned private module version, and authorized dependency credentials; only the macOS bundle pipeline currently implements that overlay contract. Refusing to compile the public cmid-tagged stub.
'@
}
$sourceCommit = Get-GitSourceCommit $repoRoot

$dist = Resolve-FullPath $DistRoot
$out = Resolve-FullPath $OutRoot
$state = Resolve-FullPath $StateRoot
[IO.Directory]::CreateDirectory($dist) | Out-Null
[IO.Directory]::CreateDirectory($out) | Out-Null
[IO.Directory]::CreateDirectory($state) | Out-Null

if (-not $Version) { $Version = Get-ProjectVersion }
if ($Version -notmatch '^\d+\.\d+\.\d+(-[A-Za-z0-9_.-]+)?$') {
    throw "Invalid version for installer payload: $Version"
}
$willSign = -not $SkipSigning -and
    -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")) -and
    -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD"))

$gatewayZip = Join-Path $dist "defenseclaw_${Version}_windows_amd64.zip"
$wheel = Join-Path $dist "defenseclaw-$Version-py3-none-any.whl"
$upgradeManifest = Join-Path $dist 'upgrade-manifest.json'
Copy-RequiredFile $gatewayZip $gatewayZip
Copy-RequiredFile $wheel $wheel
Copy-RequiredFile $upgradeManifest $upgradeManifest

Add-Type -AssemblyName System.IO.Compression.FileSystem
$wheelArchive = [IO.Compression.ZipFile]::OpenRead($wheel)
try {
    $metadataEntries = @($wheelArchive.Entries | Where-Object { $_.FullName -match '\.dist-info/METADATA$' })
    if ($metadataEntries.Count -ne 1) { throw 'DefenseClaw wheel must contain exactly one METADATA file.' }
    $reader = [IO.StreamReader]::new($metadataEntries[0].Open(), [Text.Encoding]::UTF8)
    try { $metadata = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $versionMatch = [regex]::Match($metadata, '(?m)^Version:[ \t]*([^\r\n]+)')
    if (-not $versionMatch.Success -or $versionMatch.Groups[1].Value.Trim() -ne $Version) {
        throw "DefenseClaw wheel metadata does not match installer version $Version."
    }
} finally { $wheelArchive.Dispose() }

$gatewayArchive = [IO.Compression.ZipFile]::OpenRead($gatewayZip)
try {
    $entryNames = @($gatewayArchive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
    foreach ($required in @('defenseclaw.exe', 'defenseclaw-hook.exe')) {
        if ($required -notin $entryNames) { throw "Gateway archive is missing $required." }
    }
} finally { $gatewayArchive.Dispose() }

$upgradePolicy = Get-Content -LiteralPath $upgradeManifest -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$upgradePolicy.release_version -ne $Version -or
    [string]$upgradePolicy.windows_installer.asset -ne 'DefenseClawSetup-x64.exe' -or
    $upgradePolicy.windows_installer.authenticode.required -ne $true -or
    [string]$upgradePolicy.windows_installer.authenticode.publisher -ne 'Cisco Systems, Inc.') {
    throw 'Upgrade manifest does not match the setup version and pinned Authenticode policy.'
}

$build = Join-Path $state "build"
Remove-SafeTree $build $state
[IO.Directory]::CreateDirectory($build) | Out-Null
$payload = Join-Path $build "payload"
[IO.Directory]::CreateDirectory($payload) | Out-Null

$downloadDir = Join-Path $state "downloads"
[IO.Directory]::CreateDirectory($downloadDir) | Out-Null
$pythonZip = Join-Path $downloadDir $PythonEmbedName
if (-not (Test-Path -LiteralPath $pythonZip)) {
    Invoke-WebRequest -Uri $PythonEmbedUrl -OutFile $pythonZip
}
if ((Get-FileHash -LiteralPath $pythonZip -Algorithm SHA256).Hash -ne $PythonEmbedSha256) {
    throw "Pinned CPython embeddable runtime hash mismatch for $PythonEmbedName"
}
$winUnicodeSource = Join-Path $downloadDir $WinUnicodeSourceName
if (-not (Test-Path -LiteralPath $winUnicodeSource)) {
    Invoke-WebRequest -Uri $WinUnicodeSourceUrl -OutFile $winUnicodeSource
}
if ((Get-FileHash -LiteralPath $winUnicodeSource -Algorithm SHA256).Hash -ne $WinUnicodeSourceSha256) {
    throw "Pinned source hash mismatch for $WinUnicodeSourceName"
}
$cosignVerifier = Join-Path $downloadDir $CosignName
if (-not (Test-Path -LiteralPath $cosignVerifier)) {
    Invoke-WebRequest -Uri $CosignUrl -OutFile $cosignVerifier
}
if ((Get-FileHash -LiteralPath $cosignVerifier -Algorithm SHA256).Hash -ne $CosignSha256) {
    throw "Pinned Sigstore verifier hash mismatch for $CosignName"
}

$requirements = Join-Path $build "requirements-release.txt"
Invoke-CheckedProcess "uv" @(
    "export", "--frozen", "--no-dev", "--no-emit-project", "--no-header",
    "--no-emit-package", "win-unicode-console",
    "--format", "requirements.txt", "--output-file", $requirements
)

$sitePackages = Join-Path $build "site-packages"
[IO.Directory]::CreateDirectory($sitePackages) | Out-Null
Invoke-CheckedProcess "uv" @(
    "pip", "sync", "--target", $sitePackages,
    "--python-version", "3.12", "--python-platform", "windows",
    "--only-binary", ":all:", "--require-hashes", $requirements
)
$winUnicodeExtract = Join-Path $build 'win-unicode-console-source'
$sourceArchive = [IO.Compression.ZipFile]::OpenRead($winUnicodeSource)
try {
    foreach ($entry in $sourceArchive.Entries) {
        $normalized = $entry.FullName.Replace('\', '/')
        if ([IO.Path]::IsPathRooted($normalized) -or
            $normalized -eq '..' -or $normalized.StartsWith('../') -or
            $normalized.Contains('/../')) {
            throw "Unsafe path in pinned source archive: $normalized"
        }
    }
} finally { $sourceArchive.Dispose() }
[IO.Compression.ZipFile]::ExtractToDirectory($winUnicodeSource, $winUnicodeExtract)
$winUnicodeRoot = Join-Path $winUnicodeExtract 'win_unicode_console-0.5'
foreach ($name in @('win_unicode_console', 'win_unicode_console.egg-info')) {
    $sourcePath = Join-Path $winUnicodeRoot $name
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        throw "Pinned source archive is missing $name"
    }
    Copy-Item -LiteralPath $sourcePath -Destination $sitePackages -Recurse -Force
}
Invoke-CheckedProcess "uv" @(
    "pip", "install", "--target", $sitePackages,
    "--python-version", "3.12", "--python-platform", "windows",
    "--only-binary", ":all:", "--no-deps", "--strict", $wheel
)

$validationRuntime = Join-Path $build 'validation-runtime'
Expand-Archive -LiteralPath $pythonZip -DestinationPath $validationRuntime -Force
$pth = @(Get-ChildItem -LiteralPath $validationRuntime -Filter 'python*._pth' -File)
if ($pth.Count -ne 1) { throw 'Pinned CPython runtime did not contain exactly one _pth file.' }
$stdlibZip = [IO.Path]::GetFileNameWithoutExtension($pth[0].Name) + '.zip'
"$stdlibZip`r`n.`r`nLib\site-packages`r`nimport site`r`n" |
    Set-Content -LiteralPath $pth[0].FullName -Encoding ascii -NoNewline
$validationSite = Join-Path $validationRuntime 'Lib\site-packages'
[IO.Directory]::CreateDirectory($validationSite) | Out-Null
foreach ($item in Get-ChildItem -LiteralPath $sitePackages -Force) {
    Copy-Item -LiteralPath $item.FullName -Destination $validationSite -Recurse -Force
}
$dependencyCheck = @'
import importlib.metadata as metadata
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

installed = {canonicalize_name(dist.metadata['Name']): dist.version for dist in metadata.distributions() if dist.metadata.get('Name')}
problems = []
for dist in metadata.distributions():
    for raw in dist.requires or ():
        requirement = Requirement(raw)
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
            continue
        key = canonicalize_name(requirement.name)
        version = installed.get(key)
        if version is None:
            problems.append(f'{dist.metadata.get("Name")}: missing {requirement.name}')
        elif requirement.specifier and not requirement.specifier.contains(version, prereleases=True):
            problems.append(f'{dist.metadata.get("Name")}: {requirement.name} {version} violates {requirement.specifier}')
if problems:
    raise SystemExit('\n'.join(problems))
for module in ('defenseclaw', 'skill_scanner', 'mcpscanner'):
    __import__(module)
print(f'validated {len(installed)} embedded distributions')
'@
Invoke-CheckedProcess (Join-Path $validationRuntime 'python.exe') @('-I', '-c', $dependencyCheck)

$siteZip = Join-Path $payload "site-packages.zip"
Write-ZipFromDirectory $sitePackages $siteZip

$launcher = Join-Path $payload "defenseclaw-launcher.exe"
Invoke-CheckedProcess "go" @(
    "build", "-ldflags", "-s -w", "-o", $launcher, "./cmd/defenseclaw-launcher"
)

Copy-RequiredFile $gatewayZip (Join-Path $payload (Split-Path -Leaf $gatewayZip))
Copy-RequiredFile $wheel (Join-Path $payload (Split-Path -Leaf $wheel))
Copy-RequiredFile $pythonZip (Join-Path $payload $PythonEmbedName)
Copy-RequiredFile $cosignVerifier (Join-Path $payload 'cosign.exe')
Copy-RequiredFile $requirements (Join-Path $payload "requirements-release.txt")
Copy-RequiredFile $upgradeManifest (Join-Path $payload 'upgrade-manifest.json')

$files = [ordered]@{}
foreach ($file in Get-ChildItem -LiteralPath $payload -File | Sort-Object Name) {
    if ($file.Name -eq "manifest.json") { continue }
    $files[$file.Name] = Get-FileHashHex $file.FullName
}

$manifest = [ordered]@{
    schema_version = 1
    version = $Version
    source_commit = $sourceCommit
    distribution_flavor = $DistributionFlavor
    python_version = $PythonVersion
    gateway_archive = (Split-Path -Leaf $gatewayZip)
    wheel = (Split-Path -Leaf $wheel)
    python_embed = $PythonEmbedName
    upgrade_manifest = 'upgrade-manifest.json'
    site_packages = "site-packages.zip"
    launcher = "defenseclaw-launcher.exe"
    cosign_verifier = 'cosign.exe'
    unsigned = -not $willSign
    toolchain = [ordered]@{
        go = (& go version)
        uv = (& uv --version)
        python_embed_url = $PythonEmbedUrl
        python_embed_sha256 = $PythonEmbedSha256.ToLowerInvariant()
        win_unicode_console_source_url = $WinUnicodeSourceUrl
        win_unicode_console_source_sha256 = $WinUnicodeSourceSha256.ToLowerInvariant()
        cosign_version = $CosignVersion
        cosign_url = $CosignUrl
        cosign_sha256 = $CosignSha256.ToLowerInvariant()
    }
    files = $files
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $payload "manifest.json") -Encoding UTF8

$embeddedPayload = Join-Path $repoRoot "cmd\defenseclaw-setup\payload\installer-payload.zip"
Write-ZipFromDirectory $payload $embeddedPayload

$setupPath = Join-Path $out "DefenseClawSetup-x64.exe"
try {
    Invoke-CheckedProcess "go" @(
        "build", "-ldflags", "-s -w -H=windowsgui", "-o", $setupPath, "./cmd/defenseclaw-setup"
    )
} finally {
    Remove-Item -LiteralPath $embeddedPayload -Force -ErrorAction SilentlyContinue
}

$signed = Sign-SetupIfConfigured $setupPath $build

$shaPath = "$setupPath.sha256"
"$(Get-FileHashHex $setupPath)  $(Split-Path -Leaf $setupPath)" |
    Set-Content -LiteralPath $shaPath -Encoding ascii

$provenance = [ordered]@{
    schema_version = 1
    artifact = (Split-Path -Leaf $setupPath)
    version = $Version
    source_commit = $sourceCommit
    distribution_flavor = $DistributionFlavor
    built_at_utc = [DateTime]::UtcNow.ToString("o")
    unsigned = -not $signed
    inputs = [ordered]@{
        gateway_archive = (Split-Path -Leaf $gatewayZip)
        gateway_archive_sha256 = Get-FileHashHex $gatewayZip
        wheel = (Split-Path -Leaf $wheel)
        wheel_sha256 = Get-FileHashHex $wheel
        python_embed = $PythonEmbedName
        python_embed_sha256 = $PythonEmbedSha256.ToLowerInvariant()
    }
    toolchain = $manifest.toolchain
}
$provenancePath = Join-Path $out "DefenseClawSetup-x64.exe.provenance.json"
$provenance | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $provenancePath -Encoding UTF8

$syft = Get-Command "syft" -ErrorAction SilentlyContinue
if ($syft) {
    Invoke-CheckedProcess $syft.Source @(
        "scan", $setupPath, "-o", "spdx-json=$setupPath.sbom.json"
    )
} else {
    Write-Warning "syft not found; setup SBOM generation skipped for local build."
}

$artifact = Get-Item -LiteralPath $setupPath
Write-Host "Built $($artifact.FullName)"
Write-Host "Size $($artifact.Length) bytes"
Write-Host "Signature status: $(if ($signed) { 'Authenticode signed' } else { 'unsigned local/PR artifact' })"
