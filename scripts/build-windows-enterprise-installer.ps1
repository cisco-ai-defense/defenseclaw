# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

<#
.SYNOPSIS
Build the self-contained managed-enterprise Windows x64 Setup executable.

.DESCRIPTION
Consumes the CMID-enabled gateway archive produced by
packaging/scripts/build-managed-windows-bundle.sh and embeds the gateway,
hook, CLI, install-enterprise.ps1, and DefenseClawEnterprise.psm1 into
DefenseClawSetup-Enterprise-x64.exe.

This builder is intentionally separate from build-windows-installer.ps1. The
latter produces the non-elevating per-user product and must never be relabeled
or repurposed as the machine-wide service installer.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DistRoot,
    [string]$OutRoot = $DistRoot,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) 'defenseclaw-windows-enterprise-installer-build'),
    [Parameter(Mandatory = $true)][string]$Version,
    [switch]$SkipSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ArtifactName = 'DefenseClawSetup-Enterprise-x64.exe'
$ExpectedPublisher = 'Cisco Systems, Inc.'
$PayloadNames = @(
    'DefenseClawEnterprise.psm1',
    'defenseclaw-gateway.exe',
    'defenseclaw-hook.exe',
    'defenseclaw.exe',
    'install-enterprise.ps1'
)

function Resolve-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path)
}

function Get-FileHashHex([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$WorkingDirectory = ''
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $start.WorkingDirectory = $WorkingDirectory
    }
    foreach ($argument in $Arguments) {
        [void]$start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    if ($null -eq $process) {
        throw "could not start $FilePath"
    }
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(1800000)) {
            try { $process.Kill($true) } catch { $process.Kill() }
            [void]$process.WaitForExit(30000)
            throw "$FilePath exceeded the bounded 30-minute build timeout"
        }
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr))
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$FilePath exited $($process.ExitCode): $($err.Trim())"
        }
        if (-not [string]::IsNullOrWhiteSpace($out)) {
            Microsoft.PowerShell.Utility\Write-Host $out.TrimEnd()
        }
    } finally {
        $process.Dispose()
    }
}

function Remove-BuildTree {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot
    )
    $full = Resolve-FullPath $Path
    $root = (Resolve-FullPath $AllowedRoot).TrimEnd('\')
    if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to remove build path outside its exact root: $full"
    }
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force
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

function Copy-ZipEntry {
    param(
        [Parameter(Mandatory)]$Archive,
        [Parameter(Mandatory)][string]$EntryName,
        [Parameter(Mandatory)][string]$Destination
    )
    $matches = @($Archive.Entries | Where-Object {
        $_.FullName.Replace('\', '/') -ceq $EntryName
    })
    if ($matches.Count -ne 1 -or $matches[0].Length -le 0) {
        throw "managed gateway archive must contain exactly one non-empty $EntryName"
    }
    $input = $matches[0].Open()
    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $input.CopyTo($output)
        $output.Flush($true)
    } finally {
        $output.Dispose()
        $input.Dispose()
    }
}

function Assert-CiscoSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $publisher = if ($signature.SignerCertificate) {
        $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    } else { '' }
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $publisher -cne $ExpectedPublisher) {
        throw "Authenticode verification failed for $Path`: status=$($signature.Status), publisher=$publisher"
    }
}

function Get-SigningContext([string]$BuildRoot) {
    $encoded = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_CERT_BASE64')
    $password = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_CERT_PASSWORD')
    $timestamp = [Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_TIMESTAMP_URL')
    if ([string]::IsNullOrWhiteSpace($encoded) -or
        [string]::IsNullOrWhiteSpace($password) -or
        [string]::IsNullOrWhiteSpace($timestamp)) {
        throw 'signed enterprise Setup requires WINDOWS_SIGNING_CERT_BASE64, WINDOWS_SIGNING_CERT_PASSWORD, and WINDOWS_SIGNING_TIMESTAMP_URL'
    }
    $timestampUri = [Uri]$timestamp
    if (-not $timestampUri.IsAbsoluteUri -or $timestampUri.Scheme -cne 'https' -or
        -not [string]::IsNullOrWhiteSpace($timestampUri.UserInfo) -or
        $timestampUri.Host -notin @('timestamp.digicert.com', 'timestamp.sectigo.com')) {
        throw 'WINDOWS_SIGNING_TIMESTAMP_URL must use an allowlisted HTTPS timestamp service'
    }
    $signTool = (Get-Command signtool.exe -ErrorAction Stop).Source
    $signingRoot = Join-Path $BuildRoot 'signing-private'
    if (Test-Path -LiteralPath $signingRoot) {
        throw "refusing to reuse the enterprise signing directory: $signingRoot"
    }
    Protect-SensitiveDirectory $signingRoot
    $pfx = Join-Path $signingRoot 'authenticode.pfx'
    $imported = @()
    try {
        [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($encoded))
        $probe = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfx,
            $password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        try { $thumbprint = $probe.Thumbprint } finally { $probe.Dispose() }
        if (Test-Path -LiteralPath "Cert:\CurrentUser\My\$thumbprint") {
            throw "refusing to replace an existing signing certificate: $thumbprint"
        }
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $imported = @(Import-PfxCertificate -FilePath $pfx `
            -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword `
            -Exportable:$false)
        $signer = @($imported | Where-Object { $_.Thumbprint -eq $thumbprint })
        if ($signer.Count -ne 1 -or -not $signer[0].HasPrivateKey) {
            throw 'Windows signing certificate import did not expose exactly one signing private key'
        }
        return [pscustomobject]@{
            Certificate = $signer[0]
            ImportedCertificates = $imported
            SignTool = $signTool
            Timestamp = $timestampUri.AbsoluteUri
            SigningRoot = $signingRoot
        }
    }
    catch {
        foreach ($certificate in $imported) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" `
                -Force -ErrorAction SilentlyContinue
        }
        Remove-BuildTree -Path $signingRoot -AllowedRoot $BuildRoot
        throw
    }
}

function Sign-PortableExecutable {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Path
    )
    Invoke-CheckedProcess -FilePath $Context.SignTool -Arguments @(
        'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $Context.Timestamp,
        '/s', 'My', '/sha1', $Context.Certificate.Thumbprint, $Path
    )
    Assert-CiscoSignature $Path
}

function Sign-PowerShellSource {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Path
    )
    $result = Set-AuthenticodeSignature -FilePath $Path -Certificate $Context.Certificate `
        -HashAlgorithm SHA256 -TimestampServer $Context.Timestamp
    if ($result.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "PowerShell Authenticode signing failed for $Path`: $($result.StatusMessage)"
    }
    Assert-CiscoSignature $Path
}

if (-not $IsWindows -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw 'the enterprise Windows Setup must be built on native Windows x64'
}
if ($Version -cnotmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9_.-]+)?$') {
    throw "invalid enterprise Setup version: $Version"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dist = Resolve-FullPath $DistRoot
$out = Resolve-FullPath $OutRoot
$state = Resolve-FullPath $StateRoot
[IO.Directory]::CreateDirectory($dist) | Out-Null
[IO.Directory]::CreateDirectory($out) | Out-Null
[IO.Directory]::CreateDirectory($state) | Out-Null

$git = (Get-Command git.exe -ErrorAction Stop).Source
$go = (Get-Command go.exe -ErrorAction Stop).Source
$sourceCommit = (& $git -C $repoRoot rev-parse --verify HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'could not resolve the DefenseClaw source commit'
}
$commitSidecar = Join-Path $dist 'gateway-source-commit.txt'
if (-not (Test-Path -LiteralPath $commitSidecar -PathType Leaf)) {
    throw 'managed enterprise input is missing gateway-source-commit.txt'
}
$gatewayCommit = (Get-Content -LiteralPath $commitSidecar -Raw -Encoding UTF8).Trim().ToLowerInvariant()
if ($gatewayCommit -cne $sourceCommit) {
    throw "managed gateway commit $gatewayCommit does not match checkout $sourceCommit"
}
$gatewayArchivePath = Join-Path $dist "defenseclaw_${Version}_windows_amd64.zip"
if (-not (Test-Path -LiteralPath $gatewayArchivePath -PathType Leaf)) {
    throw "managed enterprise input is missing $(Split-Path -Leaf $gatewayArchivePath)"
}

$build = Join-Path $state 'enterprise-setup-build'
Remove-BuildTree -Path $build -AllowedRoot $state
[IO.Directory]::CreateDirectory($build) | Out-Null
$payloadStage = Join-Path $build 'payload'
[IO.Directory]::CreateDirectory($payloadStage) | Out-Null
$embedRoot = Join-Path $repoRoot 'cmd\defenseclaw-enterprise-setup\payload'
$generatedEmbedPaths = [Collections.Generic.List[string]]::new()
$signing = $null

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($gatewayArchivePath)
    try {
        Copy-ZipEntry -Archive $archive -EntryName 'defenseclaw.exe' `
            -Destination (Join-Path $payloadStage 'defenseclaw-gateway.exe')
        Copy-ZipEntry -Archive $archive -EntryName 'defenseclaw-hook.exe' `
            -Destination (Join-Path $payloadStage 'defenseclaw-hook.exe')
    } finally {
        $archive.Dispose()
    }
    Copy-Item -LiteralPath (Join-Path $payloadStage 'defenseclaw-gateway.exe') `
        -Destination (Join-Path $payloadStage 'defenseclaw.exe')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'packaging\windows\install-enterprise.ps1') `
        -Destination (Join-Path $payloadStage 'install-enterprise.ps1')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'packaging\windows\DefenseClawEnterprise.psm1') `
        -Destination (Join-Path $payloadStage 'DefenseClawEnterprise.psm1')

    . (Join-Path $repoRoot 'scripts\windows-binary-identity.ps1')
    Assert-DefenseClawBinaryIdentity `
        -Path (Join-Path $payloadStage 'defenseclaw-gateway.exe') `
        -ExpectedName 'defenseclaw-gateway' -ExpectedVersion $Version `
        -ExpectedCommit $sourceCommit | Out-Null
    Assert-DefenseClawBinaryIdentity `
        -Path (Join-Path $payloadStage 'defenseclaw-hook.exe') `
        -ExpectedName 'defenseclaw-hook' -ExpectedVersion $Version `
        -ExpectedCommit $sourceCommit | Out-Null

    if (-not $SkipSigning) {
        $signing = Get-SigningContext $build
        foreach ($name in @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe', 'defenseclaw.exe')) {
            Sign-PortableExecutable -Context $signing -Path (Join-Path $payloadStage $name)
        }
        foreach ($name in @('install-enterprise.ps1', 'DefenseClawEnterprise.psm1')) {
            Sign-PowerShellSource -Context $signing -Path (Join-Path $payloadStage $name)
        }
    }

    $files = [ordered]@{}
    foreach ($name in $PayloadNames | Sort-Object) {
        $path = Join-Path $payloadStage $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "enterprise payload is missing $name"
        }
        $files[$name] = Get-FileHashHex $path
    }
    $manifest = [ordered]@{
        schema_version = 1
        version = $Version
        source_commit = $sourceCommit
        distribution_flavor = 'managed-enterprise'
        unsigned = [bool]$SkipSigning
        files = $files
    }
    $manifestPath = Join-Path $payloadStage 'manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

    foreach ($name in @($PayloadNames + 'manifest.json')) {
        $destination = Join-Path $embedRoot $name
        if (Test-Path -LiteralPath $destination) {
            throw "refusing to overwrite an existing generated embed input: $destination"
        }
        Copy-Item -LiteralPath (Join-Path $payloadStage $name) -Destination $destination
        $generatedEmbedPaths.Add($destination)
    }

    $setupPath = Join-Path $out $ArtifactName
    $verificationPath = Join-Path $build "$ArtifactName.verify.exe"
    $ldflags = "-s -w -buildid=defenseclaw-enterprise-setup-$sourceCommit"
    foreach ($target in @($setupPath, $verificationPath)) {
        Invoke-CheckedProcess -FilePath $go -WorkingDirectory $repoRoot -Arguments @(
            'build', '-trimpath', '-buildvcs=false', '-ldflags', $ldflags,
            '-o', $target, './cmd/defenseclaw-enterprise-setup'
        )
        Invoke-CheckedProcess -FilePath $go -WorkingDirectory $repoRoot -Arguments @(
            'run', './internal/tools/windowsresources',
            '-target', 'windows_amd64', '-executable', $target,
            '-component', 'enterprise-setup', '-version', $Version,
            '-icon', (Join-Path $repoRoot 'macos\DefenseClawMac\DefenseClawMac\Assets.xcassets\AppIcon.appiconset\icon_256.png')
        )
    }
    $firstHash = Get-FileHashHex $setupPath
    $secondHash = Get-FileHashHex $verificationPath
    if ($firstHash -cne $secondHash) {
        throw "enterprise Setup reproducibility check failed: $firstHash != $secondHash"
    }
    Remove-Item -LiteralPath $verificationPath -Force
    if (-not $SkipSigning) {
        Sign-PortableExecutable -Context $signing -Path $setupPath
    }

    $setupHash = Get-FileHashHex $setupPath
    "$setupHash *$ArtifactName" | Set-Content -LiteralPath "$setupPath.sha256" -Encoding ascii
    $provenance = [ordered]@{
        schema_version = 1
        artifact = $ArtifactName
        version = $Version
        source_commit = $sourceCommit
        distribution_flavor = 'managed-enterprise'
        unsigned = [bool]$SkipSigning
        setup_sha256 = $setupHash
        payload = $files
    }
    $provenance | ConvertTo-Json -Depth 8 | Set-Content `
        -LiteralPath "$setupPath.provenance.json" -Encoding utf8NoBOM

    Microsoft.PowerShell.Utility\Write-Host "Enterprise Setup: $setupPath"
    Microsoft.PowerShell.Utility\Write-Host "SHA-256:         $setupHash"
    Microsoft.PowerShell.Utility\Write-Host "Source commit:   $sourceCommit"
    Microsoft.PowerShell.Utility\Write-Host "Unsigned:        $([bool]$SkipSigning)"
} finally {
    foreach ($path in $generatedEmbedPaths) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $signing) {
        foreach ($certificate in $signing.ImportedCertificates) {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" `
                -Force -ErrorAction SilentlyContinue
        }
        Remove-BuildTree -Path $signing.SigningRoot -AllowedRoot $build
    }
}
