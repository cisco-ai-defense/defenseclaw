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

$PythonVersion = "3.14.6"
$PythonTargetVersion = "3.14"
$PythonEmbedName = "python-$PythonVersion-embed-amd64.zip"
$PythonEmbedUrl = "https://www.python.org/ftp/python/$PythonVersion/$PythonEmbedName"
$PythonEmbedSha256 = "DF901E84A896FF1EE720AD03377E0C8D8C2244FDA79808AEEAFF6316DF1CB75C"
# Force the runtime owner to review the pinned binary at least quarterly. A
# release after this deadline must deliberately move the deadline (and normally
# the version/hash) after checking Python's current security release line.
$PythonRuntimeReviewDeadlineUTC = [DateTimeOffset]::Parse('2026-09-10T00:00:00Z')
$WinUnicodeSourceName = 'win_unicode_console-0.5.zip'
$WinUnicodeSourceUrl = 'https://files.pythonhosted.org/packages/89/8d/7aad74930380c8972ab282304a2ff45f3d4927108bb6693cabcc9fc6a099/win_unicode_console-0.5.zip'
$WinUnicodeSourceSha256 = 'D4142D4D56D46F449D6F00536A73625A871CBA040F0BC1A2E305A04578F07D1E'
$CosignVersion = '2.6.2'
$CosignName = 'cosign-windows-amd64.exe'
$CosignUrl = "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignName"
$CosignSha256 = 'DD6C61E510DA627BCAED4CD9DB844EC11CACD09826D814D89F7F68D40FEB07BE'
$WindowsArtifactHelper = Join-Path $PSScriptRoot 'windows_installer_artifacts.py'
$WindowsAuthenticodeHelper = Join-Path $PSScriptRoot 'windows-authenticode.ps1'
$WindowsBinaryIdentityHelper = Join-Path $PSScriptRoot 'windows-binary-identity.ps1'

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

function Get-GitSourceEpoch([string]$RepositoryRoot, [string]$Commit) {
    $git = (Get-Command 'git.exe' -ErrorAction Stop).Source
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $git
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('-C', $RepositoryRoot, 'show', '-s', '--format=%ct', $Commit)) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Could not resolve the installer source timestamp: $($stderr.Trim())"
        }
    } finally {
        $process.Dispose()
    }
    $epoch = $stdout.Trim()
    if ($epoch -notmatch '^\d{9,}$') {
        throw "Git returned an invalid installer source timestamp: $epoch"
    }
    return $epoch
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

function Write-ZipFromDirectory(
    [string]$Source,
    [string]$Destination,
    [string]$PythonExecutable,
    [string]$Epoch,
    [string]$VerificationRoot,
    [switch]$IncludeSourceDirectory
) {
    foreach ($required in @($WindowsArtifactHelper, $PythonExecutable)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Deterministic ZIP dependency is missing: $required"
        }
    }
    if ($Epoch -notmatch '^\d{9,}$') {
        throw "Invalid deterministic ZIP epoch: $Epoch"
    }
    [IO.Directory]::CreateDirectory($VerificationRoot) | Out-Null
    $verification = Join-Path $VerificationRoot "$(Split-Path -Leaf $Destination).verify.zip"
    $arguments = @(
        $WindowsArtifactHelper, 'zip', '--source', $Source,
        '--output', $Destination, '--epoch', $Epoch
    )
    if ($IncludeSourceDirectory) {
        $arguments += '--include-root'
    }
    Invoke-CheckedProcess $PythonExecutable $arguments
    $verificationArguments = @($arguments)
    $outputIndex = [Array]::IndexOf($verificationArguments, '--output') + 1
    $verificationArguments[$outputIndex] = $verification
    try {
        Invoke-CheckedProcess $PythonExecutable $verificationArguments
        $primaryHash = Get-FileHashHex $Destination
        $verificationHash = Get-FileHashHex $verification
        if ($primaryHash -ne $verificationHash) {
            throw "Deterministic ZIP self-check failed for $(Split-Path -Leaf $Destination): $primaryHash != $verificationHash"
        }
    } finally {
        Remove-Item -LiteralPath $verification -Force -ErrorAction SilentlyContinue
    }
}

function Build-VerifiedGoBinary(
    [string]$Output,
    [string]$Package,
    [string]$LdFlags,
    [string]$VerificationRoot
) {
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Output)) | Out-Null
    [IO.Directory]::CreateDirectory($VerificationRoot) | Out-Null
    $verification = Join-Path $VerificationRoot "$(Split-Path -Leaf $Output).verify.exe"
    $go = (Get-Command 'go.exe' -ErrorAction Stop).Source
    $savedCgo = [Environment]::GetEnvironmentVariable('CGO_ENABLED')
    try {
        [Environment]::SetEnvironmentVariable('CGO_ENABLED', '0')
        $hashes = @()
        # Build the disposable comparison first and the artifact second. Hash
        # each immediately so endpoint scanners cannot turn a successful,
        # byte-identical build into a misleading comparison race.
        foreach ($target in @($verification, $Output)) {
            Invoke-CheckedProcess $go @(
                'build', '-trimpath', '-buildvcs=false', '-ldflags', $LdFlags,
                '-o', $target, $Package
            )
            $hashes += Get-FileHashHex $target
        }
        $verificationHash = $hashes[0]
        $primaryHash = $hashes[1]
        if ($primaryHash -ne $verificationHash) {
            throw "Reproducible Go build self-check failed for $(Split-Path -Leaf $Output): $primaryHash != $verificationHash"
        }
    } finally {
        [Environment]::SetEnvironmentVariable('CGO_ENABLED', $savedCgo)
        Remove-Item -LiteralPath $verification -Force -ErrorAction SilentlyContinue
    }
}

function Get-FileHashHex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Set-WindowsExecutableResource(
    [string]$Executable,
    [ValidateSet('gateway', 'hook', 'launcher', 'startup', 'setup')][string]$Component,
    [switch]$VerifyOnly
) {
    $arguments = @(
        'run', './internal/tools/windowsresources',
        '-target', 'windows_amd64',
        '-executable', $Executable,
        '-component', $Component,
        '-version', $Version,
        '-icon', $resourceIcon
    )
    if ($VerifyOnly) { $arguments += '-verify-only' }
    Invoke-CheckedProcess 'go' $arguments $repoRoot

    # Exercise the same Win32 version API used by Explorer in addition to the
    # tool's exact PE-resource parser.
    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo([IO.Path]::GetFullPath($Executable))
    if ($versionInfo.CompanyName -ne 'Cisco Systems, Inc.' -or
        $versionInfo.ProductName -ne 'Cisco DefenseClaw' -or
        $versionInfo.FileVersion -ne $Version -or
        $versionInfo.ProductVersion -ne $Version) {
        throw "Windows VERSIONINFO API returned unexpected metadata for ${Executable}: company='$($versionInfo.CompanyName)' product='$($versionInfo.ProductName)' file='$($versionInfo.FileVersion)' version='$($versionInfo.ProductVersion)'"
    }
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

function Set-FileSignaturesIfConfigured([string[]]$Paths, [string]$BuildRoot) {
    if (-not $Paths -or $Paths.Count -eq 0) {
        throw 'Authenticode signing requires at least one file.'
    }
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Authenticode signing input is missing: $path"
        }
    }
    if ($SkipSigning) {
        Write-Warning "Skipping Authenticode signing by request; product executables are unsigned."
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
        $timestampUrl = Get-TrustedTimestampUrl
        foreach ($path in $Paths) {
            Invoke-CheckedProcess $signtool @(
                'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $timestampUrl,
                '/s', 'My', '/sha1', $thumbprint, $path
            )
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            $publisher = if ($signature.SignerCertificate) {
                $signature.SignerCertificate.GetNameInfo(
                    [Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false
                )
            } else { '' }
            if ($signature.Status -ne 'Valid' -or $publisher -ne 'Cisco Systems, Inc.') {
                throw "Authenticode signature validation failed for ${path}: status=$($signature.Status), publisher=$publisher"
            }
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
if ([DateTimeOffset]::UtcNow -ge $PythonRuntimeReviewDeadlineUTC) {
    throw "Pinned CPython $PythonVersion security review expired at $($PythonRuntimeReviewDeadlineUTC.ToString('o')); review the current Python 3.14 Windows release and update the pin."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot
$resourceIcon = Join-Path $repoRoot 'macos\DefenseClawMac\DefenseClawMac\Assets.xcassets\AppIcon.appiconset\icon_256.png'
foreach ($requiredSetupInput in @(
    $resourceIcon, $WindowsArtifactHelper, $WindowsAuthenticodeHelper,
    $WindowsBinaryIdentityHelper
)) {
    if (-not (Test-Path -LiteralPath $requiredSetupInput -PathType Leaf)) {
        throw "Required Windows installer input is missing: $requiredSetupInput"
    }
}
. $WindowsAuthenticodeHelper

if ($DistributionFlavor -eq 'managed-enterprise') {
    throw @'
The public Windows installer builder cannot produce a managed-enterprise artifact. A managed Windows release requires the private CMID provider overlay, its pinned private module version, and authorized dependency credentials; only the macOS bundle pipeline currently implements that overlay contract. Refusing to compile the public cmid-tagged stub.
'@
}
$sourceCommit = Get-GitSourceCommit $repoRoot
$sourceDateEpoch = Get-GitSourceEpoch $repoRoot $sourceCommit

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
$reproducibilityRoot = Join-Path $build 'reproducibility-checks'
[IO.Directory]::CreateDirectory($reproducibilityRoot) | Out-Null
$payload = Join-Path $build "payload"
[IO.Directory]::CreateDirectory($payload) | Out-Null

# yara-python's last published Windows wheel targets CPython 3.13. Build the
# repository-owned, pure-Python MCP Scanner compatibility adapter twice from
# clean copies. SOURCE_DATE_EPOCH plus byte-for-byte equality makes a
# non-reproducible adapter wheel a hard release failure. Runtime dependencies
# still enter site-packages exclusively as hash-verified binary wheels.
$yaraCompatSource = Join-Path $repoRoot 'packages\yara-python-compat'
if (-not (Test-Path -LiteralPath (Join-Path $yaraCompatSource 'src\yara\__init__.py') -PathType Leaf)) {
    throw 'Windows Python 3.14 YARA compatibility source is missing.'
}
$yaraCompatHashes = @()
$yaraCompatWheels = @()
$savedSourceDateEpoch = [Environment]::GetEnvironmentVariable('SOURCE_DATE_EPOCH')
try {
    [Environment]::SetEnvironmentVariable('SOURCE_DATE_EPOCH', $sourceDateEpoch)
    foreach ($attempt in @('a', 'b')) {
        $sourceCopy = Join-Path $build "yara-python-compat-source-$attempt"
        $wheelRoot = Join-Path $build "yara-python-compat-wheel-$attempt"
        Copy-Item -LiteralPath $yaraCompatSource -Destination $sourceCopy -Recurse -Force
        [IO.Directory]::CreateDirectory($wheelRoot) | Out-Null
        Invoke-CheckedProcess 'uv' @('build', '--wheel', $sourceCopy, '--out-dir', $wheelRoot)
        $builtWheels = @(Get-ChildItem -LiteralPath $wheelRoot -Filter 'yara_python-4.5.4.post1-py3-none-any.whl' -File)
        if ($builtWheels.Count -ne 1) {
            throw "YARA compatibility build $attempt did not produce exactly one expected wheel."
        }
        $yaraCompatWheels += $builtWheels[0].FullName
        $yaraCompatHashes += Get-FileHashHex $builtWheels[0].FullName
    }
} finally {
    [Environment]::SetEnvironmentVariable('SOURCE_DATE_EPOCH', $savedSourceDateEpoch)
}
if ($yaraCompatHashes[0] -ne $yaraCompatHashes[1]) {
    throw 'Windows Python 3.14 YARA compatibility wheel is not reproducible.'
}
$yaraCompatWheel = $yaraCompatWheels[0]
$yaraCompatSha256 = $yaraCompatHashes[0]

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
    "--no-emit-package", "yara-python",
    "--format", "requirements.txt", "--output-file", $requirements
)

$yaraCompatRequirements = Join-Path $build 'requirements-yara-compat.txt'
$yaraCompatUri = ([Uri]$yaraCompatWheel).AbsoluteUri
"yara-python @ $yaraCompatUri --hash=sha256:$yaraCompatSha256`r`n" |
    Set-Content -LiteralPath $yaraCompatRequirements -Encoding ascii -NoNewline

$sitePackages = Join-Path $build "site-packages"
[IO.Directory]::CreateDirectory($sitePackages) | Out-Null
Invoke-CheckedProcess "uv" @(
    "pip", "sync", "--target", $sitePackages,
    "--python-version", $PythonTargetVersion, "--python-platform", "windows",
    "--only-binary", ":all:", "--require-hashes", $requirements
)
Invoke-CheckedProcess "uv" @(
    "pip", "install", "--target", $sitePackages,
    "--python-version", $PythonTargetVersion, "--python-platform", "windows",
    "--only-binary", ":all:", "--require-hashes", "--no-deps",
    "--requirements", $yaraCompatRequirements
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
    "--python-version", $PythonTargetVersion, "--python-platform", "windows",
    "--only-binary", ":all:", "--no-deps", "--strict", $wheel
)

$validationRuntime = Join-Path $build 'validation-runtime'
Expand-Archive -LiteralPath $pythonZip -DestinationPath $validationRuntime -Force
$pth = @(Get-ChildItem -LiteralPath $validationRuntime -Filter 'python*._pth' -File)
if ($pth.Count -ne 1) { throw 'Pinned CPython runtime did not contain exactly one _pth file.' }
$stdlibZip = [IO.Path]::GetFileNameWithoutExtension($pth[0].Name) + '.zip'
"$stdlibZip`r`n.`r`nLib\site-packages`r`nimport site`r`n" |
    Set-Content -LiteralPath $pth[0].FullName -Encoding ascii -NoNewline
$validationPython = Join-Path $validationRuntime 'python.exe'
# uv targets can inherit bytecode from a shared cache and PEP 610 file://
# origins for locally supplied wheels. Both encode host-specific absolute
# paths. Remove those optional artifacts and repair RECORD before validating
# or archiving the runtime; exact input hashes remain in manifest/provenance.
Invoke-CheckedProcess $validationPython @(
    '-I', $WindowsArtifactHelper, 'normalize-site', '--root', $sitePackages
)
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
for module in ('defenseclaw', 'skill_scanner', 'mcpscanner', 'yara'):
    __import__(module)
import asyncio
import yara
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
if not getattr(yara, '__defenseclaw_yarax_compat__', False):
    raise SystemExit('Windows CPython 3.14 payload did not select the YARA-X compatibility adapter')
findings = asyncio.run(YaraAnalyzer().analyze('os.system("calc.exe")', {'tool_name': 'release-probe'}))
if not findings or not any(finding.analyzer == 'YARA' for finding in findings):
    raise SystemExit('MCP Scanner YARA compatibility probe did not return the expected finding')
print(f'validated {len(installed)} embedded distributions')
'@
Invoke-CheckedProcess $validationPython @('-I', '-c', $dependencyCheck)

$siteZip = Join-Path $payload "site-packages.zip"
Write-ZipFromDirectory $sitePackages $siteZip $validationPython $sourceDateEpoch $reproducibilityRoot

$launcher = Join-Path $payload "defenseclaw-launcher.exe"
Build-VerifiedGoBinary $launcher './cmd/defenseclaw-launcher' "-s -w -buildid=defenseclaw-launcher-$sourceCommit" $reproducibilityRoot
Set-WindowsExecutableResource $launcher 'launcher'
$startupLauncher = Join-Path $payload "defenseclaw-startup.exe"
Build-VerifiedGoBinary $startupLauncher './cmd/defenseclaw-startup' "-s -w -buildid=defenseclaw-startup-$sourceCommit -H=windowsgui" $reproducibilityRoot
Set-WindowsExecutableResource $startupLauncher 'startup'

$gatewayPayloadDir = Join-Path $build 'gateway-payload'
Remove-SafeTree $gatewayPayloadDir $build
[IO.Directory]::CreateDirectory($gatewayPayloadDir) | Out-Null
Expand-Archive -LiteralPath $gatewayZip -DestinationPath $gatewayPayloadDir -Force
$gatewayBinary = Join-Path $gatewayPayloadDir 'defenseclaw.exe'
$hookBinary = Join-Path $gatewayPayloadDir 'defenseclaw-hook.exe'
Set-WindowsExecutableResource $gatewayBinary 'gateway' -VerifyOnly
Set-WindowsExecutableResource $hookBinary 'hook' -VerifyOnly
. $WindowsBinaryIdentityHelper
Assert-DefenseClawBinaryIdentity `
    -Path $gatewayBinary -ExpectedName 'defenseclaw-gateway' `
    -ExpectedVersion $Version -ExpectedCommit $sourceCommit | Out-Null
Assert-DefenseClawBinaryIdentity `
    -Path $hookBinary -ExpectedName 'defenseclaw-hook' `
    -ExpectedVersion $Version -ExpectedCommit $sourceCommit | Out-Null
$payloadSigned = Set-FileSignaturesIfConfigured @($launcher, $startupLauncher, $gatewayBinary, $hookBinary) $build
foreach ($resourceContract in @(
    [pscustomobject]@{ Path = $launcher; Component = 'launcher' },
    [pscustomobject]@{ Path = $startupLauncher; Component = 'startup' },
    [pscustomobject]@{ Path = $gatewayBinary; Component = 'gateway' },
    [pscustomobject]@{ Path = $hookBinary; Component = 'hook' }
)) {
    Set-WindowsExecutableResource $resourceContract.Path $resourceContract.Component -VerifyOnly
}

$payloadAuthenticodeFiles = [ordered]@{}
function Add-PayloadAuthenticodeEvidence(
    [string]$InstalledPath,
    [string]$SourcePath,
    [string]$SbomFileName,
    [switch]$DefenseClawProduct,
    [switch]$DigestOnlyUpstream
) {
    $normalizedInstalledPath = $InstalledPath.Replace('\', '/')
    if ($payloadAuthenticodeFiles.Contains($normalizedInstalledPath)) {
        throw "Duplicate installed Authenticode identity: $normalizedInstalledPath"
    }
    $arguments = @{
        Path = $SourcePath
        InstalledPath = $normalizedInstalledPath
        SbomFileName = $SbomFileName.Replace('\', '/')
    }
    if ($DefenseClawProduct) {
        $arguments.Policy = 'defenseclaw-product-publisher'
        $arguments.ExpectedStatus = if ($payloadSigned) { 'Valid' } else { 'NotSigned' }
        $arguments.ExpectedPublisher = if ($payloadSigned) { 'Cisco Systems, Inc.' } else { '' }
        $arguments.TimestampRequired = [bool]$payloadSigned
    } elseif ($DigestOnlyUpstream) {
        $arguments.Policy = 'digest-only-upstream'
        $arguments.ExpectedStatus = 'NotSigned'
        $arguments.ExpectedPublisher = ''
        $arguments.TimestampRequired = $false
    }
    $payloadAuthenticodeFiles[$normalizedInstalledPath] = Get-DefenseClawAuthenticodeEvidence @arguments
}

foreach ($mapping in @(
    [pscustomobject]@{ Installed = 'bin/defenseclaw.exe'; Source = $launcher; Sbom = './payload/defenseclaw-launcher.exe' },
    [pscustomobject]@{ Installed = 'bin/skill-scanner.exe'; Source = $launcher; Sbom = './payload/defenseclaw-launcher.exe' },
    [pscustomobject]@{ Installed = 'bin/mcp-scanner.exe'; Source = $launcher; Sbom = './payload/defenseclaw-launcher.exe' },
    [pscustomobject]@{ Installed = 'bin/defenseclaw-observability.exe'; Source = $launcher; Sbom = './payload/defenseclaw-launcher.exe' },
    [pscustomobject]@{ Installed = 'bin/defenseclaw-startup.exe'; Source = $startupLauncher; Sbom = './payload/defenseclaw-startup.exe' },
    [pscustomobject]@{ Installed = 'bin/defenseclaw-gateway.exe'; Source = $gatewayBinary; Sbom = './expanded/gateway/defenseclaw.exe' },
    [pscustomobject]@{ Installed = 'bin/defenseclaw-hook.exe'; Source = $hookBinary; Sbom = './expanded/gateway/defenseclaw-hook.exe' }
)) {
    Add-PayloadAuthenticodeEvidence $mapping.Installed $mapping.Source $mapping.Sbom -DefenseClawProduct
}

# Inventory every third-party PE that Setup installs. Pinned archive digests
# remain the supply-chain root; this evidence also binds the observed Windows
# publisher/certificate/timestamp state to the manifest and final SBOM.
foreach ($file in Get-ChildItem -LiteralPath $validationRuntime -File -Recurse | Sort-Object FullName) {
    if (Test-PathWithin $file.FullName $validationSite) { continue }
    if (-not (Test-DefenseClawPortableExecutable $file.FullName)) { continue }
    $relative = [IO.Path]::GetRelativePath($validationRuntime, $file.FullName).Replace('\', '/')
    Add-PayloadAuthenticodeEvidence "runtime/python/$relative" $file.FullName "./expanded/python/$relative"
}
foreach ($file in Get-ChildItem -LiteralPath $sitePackages -File -Recurse | Sort-Object FullName) {
    if (-not (Test-DefenseClawPortableExecutable $file.FullName)) { continue }
    $relative = [IO.Path]::GetRelativePath($sitePackages, $file.FullName).Replace('\', '/')
    Add-PayloadAuthenticodeEvidence `
        "runtime/python/Lib/site-packages/$relative" `
        $file.FullName `
        "./expanded/site-packages/$relative"
}
# The exact pinned Cosign 2.6.2 Windows release is not Authenticode-signed.
Add-PayloadAuthenticodeEvidence `
    'runtime/tools/cosign.exe' $cosignVerifier './payload/cosign.exe' -DigestOnlyUpstream
$embeddedGatewayZip = Join-Path $payload (Split-Path -Leaf $gatewayZip)
Write-ZipFromDirectory $gatewayPayloadDir $embeddedGatewayZip $validationPython $sourceDateEpoch $reproducibilityRoot

Copy-RequiredFile $wheel (Join-Path $payload (Split-Path -Leaf $wheel))
Copy-RequiredFile $pythonZip (Join-Path $payload $PythonEmbedName)
Copy-RequiredFile $cosignVerifier (Join-Path $payload 'cosign.exe')
Copy-RequiredFile $requirements (Join-Path $payload "requirements-release.txt")
Copy-RequiredFile $yaraCompatWheel (Join-Path $payload (Split-Path -Leaf $yaraCompatWheel))
Copy-RequiredFile $upgradeManifest (Join-Path $payload 'upgrade-manifest.json')

$files = [ordered]@{}
foreach ($file in Get-ChildItem -LiteralPath $payload -File | Sort-Object Name) {
    if ($file.Name -eq "manifest.json") { continue }
    $files[$file.Name] = Get-FileHashHex $file.FullName
}

$manifest = [ordered]@{
    schema_version = 2
    version = $Version
    source_commit = $sourceCommit
    distribution_flavor = $DistributionFlavor
    python_version = $PythonVersion
    gateway_archive = (Split-Path -Leaf $gatewayZip)
    wheel = (Split-Path -Leaf $wheel)
    python_embed = $PythonEmbedName
    yara_compat_wheel = (Split-Path -Leaf $yaraCompatWheel)
    upgrade_manifest = 'upgrade-manifest.json'
    site_packages = "site-packages.zip"
    launcher = "defenseclaw-launcher.exe"
    startup_launcher = "defenseclaw-startup.exe"
    cosign_verifier = 'cosign.exe'
    unsigned = -not $payloadSigned
    authenticode = [ordered]@{
        schema_version = 1
        files = $payloadAuthenticodeFiles
    }
    toolchain = [ordered]@{
        go = (& go version)
        uv = (& uv --version)
        python_embed_url = $PythonEmbedUrl
        python_embed_sha256 = $PythonEmbedSha256.ToLowerInvariant()
        python_runtime_review_deadline_utc = $PythonRuntimeReviewDeadlineUTC.ToString('o')
        yara_compat_sha256 = $yaraCompatSha256
        win_unicode_console_source_url = $WinUnicodeSourceUrl
        win_unicode_console_source_sha256 = $WinUnicodeSourceSha256.ToLowerInvariant()
        cosign_version = $CosignVersion
        cosign_url = $CosignUrl
        cosign_sha256 = $CosignSha256.ToLowerInvariant()
    }
    files = $files
}
$manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $payload "manifest.json") -Encoding UTF8

$embeddedPayload = Join-Path $repoRoot "cmd\defenseclaw-setup\payload\installer-payload.zip"
# loadPayload deliberately extracts into a private parent and resolves the
# manifest below a single payload/ directory. Preserve that root in the ZIP;
# the other archives built above intentionally contain only their children.
Write-ZipFromDirectory $payload $embeddedPayload $validationPython $sourceDateEpoch $reproducibilityRoot -IncludeSourceDirectory
$embeddedArchive = [IO.Compression.ZipFile]::OpenRead($embeddedPayload)
try {
    $embeddedEntryNames = @($embeddedArchive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
    if ('payload/manifest.json' -notin $embeddedEntryNames) {
        throw 'Embedded setup payload is missing payload/manifest.json.'
    }
} finally {
    $embeddedArchive.Dispose()
}

$setupPath = Join-Path $out "DefenseClawSetup-x64.exe"
$shaPath = "$setupPath.sha256"
$provenancePath = Join-Path $out "DefenseClawSetup-x64.exe.provenance.json"
$sbomPath = "$setupPath.sbom.json"
$setupVerification = Join-Path $reproducibilityRoot 'DefenseClawSetup-x64.exe.manifest.verify.exe'
try {
    Build-VerifiedGoBinary $setupPath './cmd/defenseclaw-setup' "-s -w -buildid=defenseclaw-setup-$sourceCommit -H=windowsgui" $reproducibilityRoot
    Copy-RequiredFile $setupPath $setupVerification
    # Resource mutation is the last PE-writing step before Authenticode. Apply
    # the deterministic manifest, icon, and VERSIONINFO contract to both
    # byte-identical builds and compare the complete unsigned executables.
    Set-WindowsExecutableResource $setupPath 'setup'
    Set-WindowsExecutableResource $setupVerification 'setup'
    $setupPreSignHash = Get-FileHashHex $setupPath
    $setupVerificationHash = Get-FileHashHex $setupVerification
    if ($setupPreSignHash -ne $setupVerificationHash) {
        throw "Deterministic setup resource self-check failed: $setupPreSignHash != $setupVerificationHash"
    }
    Remove-Item -LiteralPath $setupVerification -Force

    # Signing order is security-sensitive: all inner executable bytes and the
    # deterministic embedded payload are finalized before the outer Setup EXE
    # is signed. The merged SBOM is generated only after this signature, so
    # its top-level checksum names the exact artifact accepted by lifecycle CI.
    $setupSigned = Set-FileSignaturesIfConfigured @($setupPath) $build
    Set-WindowsExecutableResource $setupPath 'setup' -VerifyOnly
    $signed = $setupSigned -and $payloadSigned

    $setupSha256 = Get-FileHashHex $setupPath
    "$setupSha256  $(Split-Path -Leaf $setupPath)" |
        Set-Content -LiteralPath $shaPath -Encoding ascii

    $goInventoryPath = Join-Path $build 'go-component-inventory.json'
    $goExecutable = (Get-Command 'go.exe' -ErrorAction Stop).Source
    Invoke-CheckedProcess $validationPython @(
        '-I', $WindowsArtifactHelper, 'go-inventory',
        '--go', $goExecutable,
        '--output', $goInventoryPath,
        '--component', "setup=$setupPath",
        '--component', "gateway=$gatewayBinary",
        '--component', "hook=$hookBinary",
        '--component', "launcher=$launcher",
        '--component', "startup-launcher=$startupLauncher",
        '--component', "cosign=$(Join-Path $payload 'cosign.exe')"
    )

    $reproducibleBuiltAt = [DateTimeOffset]::FromUnixTimeSeconds([long]$sourceDateEpoch).UtcDateTime.ToString('o')
    $releaseAuthenticodeFiles = [ordered]@{
        'DefenseClawSetup-x64.exe' = Get-DefenseClawAuthenticodeEvidence `
            -Path $setupPath `
            -InstalledPath 'DefenseClawSetup-x64.exe' `
            -SbomFileName './DefenseClawSetup-x64.exe' `
            -Policy 'defenseclaw-product-publisher' `
            -ExpectedStatus $(if ($setupSigned) { 'Valid' } else { 'NotSigned' }) `
            -ExpectedPublisher $(if ($setupSigned) { 'Cisco Systems, Inc.' } else { '' }) `
            -TimestampRequired ([bool]$setupSigned)
    }
    foreach ($entry in $payloadAuthenticodeFiles.GetEnumerator()) {
        $releaseAuthenticodeFiles[$entry.Key] = $entry.Value
    }
    $releaseAuthenticode = [ordered]@{
        schema_version = 1
        files = $releaseAuthenticodeFiles
    }
    $authenticodeInventoryPath = Join-Path $build 'authenticode-inventory.json'
    $releaseAuthenticode | ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath $authenticodeInventoryPath -Encoding UTF8

    $provenance = [ordered]@{
        schema_version = 1
        artifact = (Split-Path -Leaf $setupPath)
        artifact_sha256 = $setupSha256
        version = $Version
        source_commit = $sourceCommit
        distribution_flavor = $DistributionFlavor
        built_at_utc = if ($signed) { [DateTime]::UtcNow.ToString('o') } else { $reproducibleBuiltAt }
        unsigned = -not $signed
        authenticode = $releaseAuthenticode
        inputs = [ordered]@{
            gateway_archive = (Split-Path -Leaf $gatewayZip)
            gateway_archive_sha256 = Get-FileHashHex $gatewayZip
            embedded_gateway_archive_sha256 = Get-FileHashHex $embeddedGatewayZip
            embedded_payload_sha256 = Get-FileHashHex $embeddedPayload
            product_executables_authenticode_signed = $payloadSigned
            wheel = (Split-Path -Leaf $wheel)
            wheel_sha256 = Get-FileHashHex $wheel
            python_embed = $PythonEmbedName
            python_embed_sha256 = $PythonEmbedSha256.ToLowerInvariant()
            site_packages_sha256 = Get-FileHashHex $siteZip
            yara_compat_wheel = (Split-Path -Leaf $yaraCompatWheel)
            yara_compat_wheel_sha256 = $yaraCompatSha256
            cosign_sha256 = Get-FileHashHex (Join-Path $payload 'cosign.exe')
            payload_manifest_sha256 = Get-FileHashHex (Join-Path $payload 'manifest.json')
            go_component_inventory_sha256 = Get-FileHashHex $goInventoryPath
            payload_files = $files
            windows_resource_policy = 'internal/windowsresources'
            windows_resource_icon = 'macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png'
            windows_resource_icon_sha256 = Get-FileHashHex $resourceIcon
        }
        toolchain = $manifest.toolchain
    }
    $provenance | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $provenancePath -Encoding UTF8

    Invoke-CheckedProcess $validationPython @(
        $WindowsArtifactHelper, 'sbom',
        '--setup', $setupPath,
        '--payload-root', $payload,
        '--embedded-payload', $embeddedPayload,
        '--output', $sbomPath,
        '--version', $Version,
        '--source-commit', $sourceCommit,
        '--source-epoch', $sourceDateEpoch,
        '--python-version', $PythonVersion,
        '--cosign-version', $CosignVersion,
        '--go-inventory', $goInventoryPath,
        '--authenticode-inventory', $authenticodeInventoryPath
    )
    $sbom = Get-Content -LiteralPath $sbomPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$sbom.spdxVersion -ne 'SPDX-2.3' -or
        [string]$sbom.dataLicense -ne 'CC0-1.0' -or
        @($sbom.documentDescribes).Count -ne 1) {
        throw 'Merged Windows installer SBOM failed the release validity gate.'
    }
} catch {
    # Never leave a setup-named executable or incomplete sidecars in an
    # otherwise valid-looking output directory.
    foreach ($incomplete in @($setupPath, $shaPath, $provenancePath, $sbomPath)) {
        Remove-Item -LiteralPath $incomplete -Force -ErrorAction SilentlyContinue
    }
    throw
} finally {
    Remove-Item -LiteralPath $setupVerification -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $embeddedPayload -Force -ErrorAction SilentlyContinue
}

$artifact = Get-Item -LiteralPath $setupPath
Write-Host "Built $($artifact.FullName)"
Write-Host "Size $($artifact.Length) bytes"
Write-Host "Signature status: $(if ($signed) { 'Authenticode signed' } else { 'unsigned local/PR artifact' })"
