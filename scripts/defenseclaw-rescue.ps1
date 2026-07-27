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
    Authenticated external rescue entry point for native Windows x64.

.DESCRIPTION
    Authenticates the mutable stable-channel pointer at one exact Git commit,
    verifies its signed fixed-schema manifest, downloads the immutable
    install.ps1 selected by that manifest, verifies its digest, and delegates
    repair or installation to that authenticated installer.

    The stable channel owns the target version. This script intentionally has
    no version selection, local-artifact, verifier, or unverified mode.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Connector = "",
    [ValidateSet("observe", "action", "")]
    [string]$QuickstartMode = "",
    [switch]$Quickstart,
    [switch]$NoOpenclaw,
    [switch]$Yes,
    [switch]$Help,

    # These parameters exist only so unsafe requests fail with a stable,
    # explicit refusal instead of being reinterpreted as installer arguments.
    [string]$Version = "",
    [string]$Local = "",
    [string]$CosignPath = "",
    [switch]$AllowUnverified,
    [switch]$NoPersistPath,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Microsoft.PowerShell.Utility\Get-Variable `
        -Name PSNativeCommandUseErrorActionPreference `
        -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # PowerShell editions that do not expose this legacy property already use
    # the operating system TLS policy.
}

$Repository = "cisco-ai-defense/defenseclaw"
$ChannelRefUrl = "https://api.github.com/repos/$Repository/git/ref/heads/release-channel"
$ChannelRawBaseUrl = "https://raw.githubusercontent.com/$Repository"
$ReleaseWorkflowIdentity =
    "https://github.com/$Repository/.github/workflows/release.yaml@refs/heads/main"
$SigstoreOIDCIssuer = "https://token.actions.githubusercontent.com"
$ChannelSchema = "defenseclaw-release-channel-v1"
$ChannelName = "stable"
$ResolverName = "defenseclaw-upgrade.sh"
$PosixInstallerName = "install.sh"
$WindowsInstallerName = "install.ps1"

$CosignVersion = "2.6.3"
$CosignAsset = "cosign-windows-amd64.exe"
$CosignSha256 = "2264ea5867077b9e070161648e8c18544decac351f5f3a7edaea43c233ce2e36"
$CosignUrl =
    "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignAsset"

$MaximumChannelRefBytes = 65536
$MaximumChannelBytes = 16384
$MaximumChannelBundleBytes = 1048576
$MaximumInstallerBytes = 4194304
$MaximumCosignBytes = 209715200
$DownloadTransferTimeoutSeconds = 300

$ChannelFields = @(
    "schema",
    "channel",
    "repository",
    "target_version",
    "target_tag",
    "target_ref",
    "target_commit",
    "resolver_name",
    "resolver_url",
    "resolver_sha256",
    "posix_installer_name",
    "posix_installer_url",
    "posix_installer_sha256",
    "windows_installer_name",
    "windows_installer_url",
    "windows_installer_sha256"
)

function Die {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "DefenseClaw rescue failed: $Message"
}

function ConvertTo-RescueExitCode {
    param([AllowNull()][object]$ExitCode)

    if ($null -eq $ExitCode) {
        return 1
    }
    return [int]$ExitCode
}

function Show-RescueHelp {
    @"

DefenseClaw authenticated Windows rescue

Usage:
  pwsh -NoLogo -NoProfile -File .\defenseclaw-rescue.ps1 [-Yes] [installer options]

Safe installer options:
  -Connector <name>    Configure a connector
  -Quickstart          Configure the connector and start the gateway
  -QuickstartMode <m>  Quickstart policy mode (observe|action)
  -NoOpenclaw          Legacy alias for -Connector none
  -Yes                 Run native Setup silently
  -Help                Show this help

The authenticated stable channel owns the exact target version and installer.
-Version, -Local, -CosignPath, and -AllowUnverified are always refused.
Unsupported compatibility switches are also refused rather than forwarded.

"@ | Microsoft.PowerShell.Utility\Write-Host
}

function Assert-NativeWindowsX64 {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Die "this entry point supports native Windows only; use defenseclaw-rescue.sh on macOS or Linux"
    }
    $architecture =
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if (-not $architecture.Equals("X64", [StringComparison]::OrdinalIgnoreCase)) {
        Die "native Windows x64 (amd64) is required; found $architecture"
    }
}

function Assert-RegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 0
    )

    $item = [IO.FileInfo]::new([IO.Path]::GetFullPath($Path))
    $item.Refresh()
    if (-not $item.Exists -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0) {
        Die "$Label must be a non-empty regular file: $Path"
    }
    if ($MaximumBytes -gt 0 -and $item.Length -gt $MaximumBytes) {
        Die "$Label exceeds its $MaximumBytes-byte limit"
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString(
                $sha256.ComputeHash($stream)
            )).Replace("-", "").ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Expected -notmatch '^[0-9a-f]{64}$') {
        Die "authenticated SHA-256 for $Label is not canonical"
    }
    $actual = Get-Sha256Hex -Path $Path
    if (-not $actual.Equals($Expected, [StringComparison]::Ordinal)) {
        Die "SHA-256 mismatch for ${Label}: expected $Expected, got $actual"
    }
}

function Set-PrivateDirectoryProtection {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
    $item.Refresh()
    if (-not $item.Exists -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Die "rescue staging root must be a regular directory: $Path"
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        Die "current Windows identity has no user SID"
    }
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
            $item,
            [Security.AccessControl.DirectorySecurity]$security
        )
    }
}

function New-PrivateStageRoot {
    $root = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        ".defenseclaw-rescue-" + [guid]::NewGuid().ToString("N")
    )
    [IO.Directory]::CreateDirectory($root) | Out-Null
    try {
        Set-PrivateDirectoryProtection -Path $root
    } catch {
        $hardeningException = $_.Exception
        try {
            [IO.Directory]::Delete($root, $true)
        } catch {
            # Cleanup is best effort; never replace the ACL hardening failure
            # that explains why this staging root was rejected.
        }
        throw $hardeningException
    }
    return [IO.Path]::GetFullPath($root)
}

function Remove-PrivateStageRoot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $expectedParent = [IO.Path]::GetDirectoryName($full)
    $expectedName = [IO.Path]::GetFileName($full)
    if (-not $expectedParent.Equals(
            $temp,
            [StringComparison]::OrdinalIgnoreCase
        ) -or $expectedName -notmatch '^\.defenseclaw-rescue-[0-9a-f]{32}$') {
        Die "refusing to clean an unexpected rescue staging path: $full"
    }

    $item = [IO.DirectoryInfo]::new($full)
    $item.Refresh()
    if (-not $item.Exists) {
        return
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        [IO.Directory]::Delete($full)
        return
    }
    [IO.Directory]::Delete($full, $true)
}

function Copy-RegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes
    )

    Assert-RegularFile -Path $Source -Label $Label -MaximumBytes $MaximumBytes
    $inputStream = [IO.File]::Open(
        $Source,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $outputStream = [IO.File]::Open(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
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

function New-HttpClient {
    Microsoft.PowerShell.Utility\Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $handler.MaxAutomaticRedirections = 8
    $client = [Net.Http.HttpClient]::new($handler, $true)
    # Invoke-SingleBoundedDownload owns one deadline spanning response headers
    # and the complete streamed body. Disable HttpClient's independent timer so
    # every blocking transfer operation observes that same cancellation token.
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $client.DefaultRequestHeaders.UserAgent.ParseAdd(
        "defenseclaw-windows-rescue/1"
    )
    $client.DefaultRequestHeaders.CacheControl =
        [Net.Http.Headers.CacheControlHeaderValue]::new()
    $client.DefaultRequestHeaders.CacheControl.NoCache = $true
    $client.DefaultRequestHeaders.Pragma.ParseAdd("no-cache")
    return $client
}

function Invoke-SingleBoundedDownload {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][uri]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    if (-not $Uri.Scheme.Equals("https", [StringComparison]::OrdinalIgnoreCase)) {
        Die "$Label URL must use HTTPS"
    }

    $response = $null
    $inputStream = $null
    $outputStream = $null
    $transferCancellation = [Threading.CancellationTokenSource]::new()
    try {
        $transferCancellation.CancelAfter(
            [TimeSpan]::FromSeconds($DownloadTransferTimeoutSeconds)
        )
        $transferToken = $transferCancellation.Token
        $response = $Client.GetAsync(
            $Uri,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $transferToken
        ).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "HTTP $([int]$response.StatusCode)"
        }
        $finalUri = $response.RequestMessage.RequestUri
        if ($null -eq $finalUri -or
            -not $finalUri.Scheme.Equals(
                "https",
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "redirected outside HTTPS"
        }

        $declaredLength = $response.Content.Headers.ContentLength
        if ($null -ne $declaredLength -and
            ($declaredLength -le 0 -or $declaredLength -gt $MaximumBytes)) {
            throw "declared size is outside the 1..$MaximumBytes byte bound"
        }

        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [IO.File]::Open(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $buffer = [byte[]]::new(131072)
        [long]$total = 0
        while (($read = $inputStream.ReadAsync(
                    $buffer,
                    0,
                    $buffer.Length,
                    $transferToken
                ).GetAwaiter().GetResult()) -gt 0) {
            $total += $read
            if ($total -gt $MaximumBytes) {
                throw "download exceeded its $MaximumBytes-byte limit"
            }
            $outputStream.Write($buffer, 0, $read)
        }
        if ($total -le 0) {
            throw "download was empty"
        }
        $outputStream.Flush($true)
    } finally {
        if ($null -ne $outputStream) {
            $outputStream.Dispose()
        }
        if ($null -ne $inputStream) {
            $inputStream.Dispose()
        }
        if ($null -ne $response) {
            $response.Dispose()
        }
        $transferCancellation.Dispose()
    }

    Assert-RegularFile `
        -Path $Destination `
        -Label $Label `
        -MaximumBytes $MaximumBytes
}

function Invoke-BoundedDownload {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $lastFailure = ""
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if ([IO.File]::Exists($Destination)) {
            [IO.File]::Delete($Destination)
        }
        try {
            Invoke-SingleBoundedDownload `
                -Client $Client `
                -Uri ([uri]$Uri) `
                -Destination $Destination `
                -Label $Label `
                -MaximumBytes $MaximumBytes
            return
        } catch {
            $lastFailure = $_.Exception.Message
            if ([IO.File]::Exists($Destination)) {
                [IO.File]::Delete($Destination)
            }
            if ($attempt -lt 3) {
                [Threading.Thread]::Sleep(1000)
            }
        }
    }
    Die "could not download $Label from ${Uri}: $lastFailure"
}

function Get-ReleaseChannelCommit {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $decoder = [Text.UTF8Encoding]::new($false, $true)
    try {
        $json = $decoder.GetString($bytes)
        $document = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $json
    } catch {
        Die "release-channel ref response is not canonical UTF-8 JSON"
    }
    if (@($document).Count -ne 1 -or $document -isnot [pscustomobject]) {
        Die "release-channel ref response must contain exactly one object"
    }
    $objectProperty = $document.PSObject.Properties["object"]
    if ($null -eq $objectProperty -or
        $null -eq $objectProperty.Value -or
        $objectProperty.Value -isnot [pscustomobject]) {
        Die "release-channel ref response must contain exactly one object"
    }
    $refProperty = $document.PSObject.Properties["ref"]
    if ($null -eq $refProperty -or
        $refProperty.Value -isnot [string] -or
        -not ([string]$refProperty.Value).Equals(
            "refs/heads/release-channel",
            [StringComparison]::Ordinal
        )) {
        Die "release-channel ref response names an unexpected ref"
    }
    $target = $objectProperty.Value
    $typeProperty = $target.PSObject.Properties["type"]
    if ($null -eq $typeProperty -or
        $typeProperty.Value -isnot [string] -or
        -not ([string]$typeProperty.Value).Equals(
            "commit",
            [StringComparison]::Ordinal
        )) {
        Die "release-channel ref does not resolve to a commit"
    }
    $shaProperty = $target.PSObject.Properties["sha"]
    if ($null -eq $shaProperty -or
        $shaProperty.Value -isnot [string] -or
        ([string]$shaProperty.Value) -notmatch '^[0-9a-f]{40}$') {
        Die "release-channel ref response has an invalid commit ID"
    }
    return [string]$shaProperty.Value
}

function Clear-UntrustedEnvironment {
    $exact = @(
        "BASH_ENV",
        "ENV",
        "VERSION",
        "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "GODEBUG"
    )
    foreach ($name in $exact) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $null,
            [EnvironmentVariableTarget]::Process
        )
    }

    foreach ($entry in [Environment]::GetEnvironmentVariables().Keys) {
        $name = [string]$entry
        if ($name -match '^(COSIGN|SIGSTORE|TUF)_') {
            [Environment]::SetEnvironmentVariable(
                $name,
                $null,
                [EnvironmentVariableTarget]::Process
            )
        }
    }
}

function Resolve-AuthenticatedCosign {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [string]$Candidate
    )

    $verifier = [IO.Path]::Combine($StageRoot, $CosignAsset)
    if (-not [string]::IsNullOrWhiteSpace($Candidate)) {
        try {
            Copy-RegularFile `
                -Source $Candidate `
                -Destination $verifier `
                -Label "ambient Cosign candidate" `
                -MaximumBytes $MaximumCosignBytes
            Assert-Sha256 `
                -Path $verifier `
                -Expected $CosignSha256 `
                -Label "Cosign $CosignVersion"
        } catch {
            if ([IO.File]::Exists($verifier)) {
                [IO.File]::Delete($verifier)
            }
        }
    }

    if (-not [IO.File]::Exists($verifier)) {
        Invoke-BoundedDownload `
            -Client $Client `
            -Uri $CosignUrl `
            -Destination $verifier `
            -Label "Cosign $CosignVersion" `
            -MaximumBytes $MaximumCosignBytes
        Assert-Sha256 `
            -Path $verifier `
            -Expected $CosignSha256 `
            -Label "Cosign $CosignVersion"
    }
    return $verifier
}

function Invoke-CosignChannelVerification {
    param(
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$ChannelPath,
        [Parameter(Mandatory = $true)][string]$BundlePath,
        [Parameter(Mandatory = $true)][string]$CosignHome
    )

    $temporaryNames = @(
        "HOME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "TEMP",
        "TMP",
        "PATH"
    )
    $saved = @{}
    foreach ($name in $temporaryNames) {
        $saved[$name] = [Environment]::GetEnvironmentVariable(
            $name,
            [EnvironmentVariableTarget]::Process
        )
    }
    try {
        foreach ($name in @(
                "HOME",
                "USERPROFILE",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "TEMP",
                "TMP"
            )) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $CosignHome,
                [EnvironmentVariableTarget]::Process
            )
        }
        [Environment]::SetEnvironmentVariable(
            "PATH",
            [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::System
            ),
            [EnvironmentVariableTarget]::Process
        )
        Clear-UntrustedEnvironment
        $previousErrorActionPreference = $ErrorActionPreference
        $output = @()
        $exitCode = 1
        try {
            # Windows PowerShell 5.1 promotes redirected native stderr to
            # NativeCommandError. Capture Cosign's complete diagnostic and
            # decide success exclusively from its native exit status.
            $ErrorActionPreference = "Continue"
            $output = @(
                & $Verifier verify-blob `
                    --bundle $BundlePath `
                    --certificate-identity $ReleaseWorkflowIdentity `
                    --certificate-oidc-issuer $SigstoreOIDCIssuer `
                    $ChannelPath 2>&1
            )
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($exitCode -ne 0) {
            throw "Cosign exited ${exitCode}: $($output -join ' ')"
        }
    } finally {
        foreach ($name in $temporaryNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $saved[$name],
                [EnvironmentVariableTarget]::Process
            )
        }
    }
}

function Read-CanonicalChannel {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -le 0 -or $bytes.Length -gt $MaximumChannelBytes) {
        Die "authenticated channel size is invalid"
    }
    foreach ($value in $bytes) {
        if ($value -eq 0 -or $value -eq 13 -or $value -gt 127) {
            Die "authenticated channel must be canonical ASCII with LF line endings"
        }
    }
    if ($bytes[$bytes.Length - 1] -ne 10) {
        Die "authenticated channel must end with one LF"
    }

    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $lines = $text.Split([char]10)
    if ($lines[$lines.Length - 1] -ne "") {
        Die "authenticated channel line termination is invalid"
    }
    if (($lines.Length - 1) -ne $ChannelFields.Count) {
        Die "authenticated channel must contain exactly $($ChannelFields.Count) canonical fields"
    }

    $record = [ordered]@{}
    for ($index = 0; $index -lt $ChannelFields.Count; $index++) {
        $field = $ChannelFields[$index]
        $prefix = "$field="
        $line = $lines[$index]
        if (-not $line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            Die "authenticated channel field $($index + 1) must be $field"
        }
        $value = $line.Substring($prefix.Length)
        if ([string]::IsNullOrEmpty($value)) {
            Die "authenticated channel field $field is empty"
        }
        $record[$field] = $value
    }

    $canonical = (($ChannelFields | ForEach-Object {
        "$_=$($record[$_])"
    }) -join "`n") + "`n"
    $canonicalBytes = [Text.Encoding]::ASCII.GetBytes($canonical)
    if ($canonicalBytes.Length -ne $bytes.Length) {
        Die "authenticated channel encoding is not canonical"
    }
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($bytes[$index] -ne $canonicalBytes[$index]) {
            Die "authenticated channel encoding is not canonical"
        }
    }
    return $record
}

function Assert-ChannelBindings {
    param([Parameter(Mandatory = $true)][Collections.IDictionary]$Record)

    if (-not $Record.schema.Equals($ChannelSchema, [StringComparison]::Ordinal)) {
        Die "unsupported channel schema"
    }
    if (-not $Record.channel.Equals($ChannelName, [StringComparison]::Ordinal)) {
        Die "unexpected release channel"
    }
    if (-not $Record.repository.Equals($Repository, [StringComparison]::Ordinal)) {
        Die "channel repository mismatch"
    }
    if ($Record.target_version -notmatch
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        Die "channel target version is not canonical"
    }
    if (-not $Record.target_tag.Equals(
            $Record.target_version,
            [StringComparison]::Ordinal
        )) {
        Die "channel tag/version mismatch"
    }
    if (-not $Record.target_ref.Equals(
            "refs/tags/$($Record.target_version)",
            [StringComparison]::Ordinal
        )) {
        Die "channel ref is not the exact target tag"
    }
    if ($Record.target_commit -notmatch '^[0-9a-f]{40}$') {
        Die "channel target commit is invalid"
    }

    if (-not $Record.resolver_name.Equals(
            $ResolverName,
            [StringComparison]::Ordinal
        )) {
        Die "channel resolver name mismatch"
    }
    $releaseBase =
        "https://github.com/$Repository/releases/download/$($Record.target_version)"
    if (-not $Record.resolver_url.Equals(
            "$releaseBase/$ResolverName",
            [StringComparison]::Ordinal
        ) -or $Record.resolver_sha256 -notmatch '^[0-9a-f]{64}$') {
        Die "channel resolver binding is not derived from its immutable tag"
    }

    if (-not $Record.posix_installer_name.Equals(
            $PosixInstallerName,
            [StringComparison]::Ordinal
        ) -or
        -not $Record.posix_installer_url.Equals(
            "$releaseBase/$PosixInstallerName",
            [StringComparison]::Ordinal
        ) -or
        $Record.posix_installer_sha256 -notmatch '^[0-9a-f]{64}$') {
        Die "channel POSIX installer binding is not derived from its immutable tag"
    }

    if (-not $Record.windows_installer_name.Equals(
            $WindowsInstallerName,
            [StringComparison]::Ordinal
        ) -or
        -not $Record.windows_installer_url.Equals(
            "$releaseBase/$WindowsInstallerName",
            [StringComparison]::Ordinal
        ) -or
        $Record.windows_installer_sha256 -notmatch '^[0-9a-f]{64}$') {
        Die "channel Windows installer binding is not derived from its immutable tag"
    }
}

function Assert-PowerShellSyntax {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null
    if (@($errors).Count -ne 0) {
        Die "authenticated install.ps1 has invalid PowerShell syntax: $($errors -join '; ')"
    }
}

function Resolve-TrustedPowerShell {
    $name = if ($PSVersionTable.PSEdition -eq "Core") {
        "pwsh.exe"
    } else {
        "powershell.exe"
    }
    $path = [IO.Path]::Combine($PSHOME, $name)
    Assert-RegularFile -Path $path -Label "trusted PowerShell"
    return [pscustomobject]@{
        Path = [IO.Path]::GetFullPath($path)
        Sha256 = Get-Sha256Hex -Path $path
    }
}

function Assert-TrustedPowerShellStable {
    param([Parameter(Mandatory = $true)]$Identity)

    Assert-RegularFile -Path $Identity.Path -Label "trusted PowerShell"
    $actual = Get-Sha256Hex -Path $Identity.Path
    if (-not $actual.Equals($Identity.Sha256, [StringComparison]::Ordinal)) {
        Die "trusted PowerShell changed before installer execution"
    }
}

function Assert-SafeConnectorName {
    param([AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return
    }
    if ($Name.StartsWith("-", [StringComparison]::Ordinal) -or
        $Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        Die (
            "invalid -Connector value; connector names must start with an " +
            "alphanumeric character and contain only letters, digits, '.', '_', or '-'"
        )
    }
}

foreach ($unsafeName in @(
        "Version",
        "Local",
        "CosignPath",
        "AllowUnverified",
        "NoPersistPath"
    )) {
    if ($PSBoundParameters.ContainsKey($unsafeName)) {
        [Console]::Error.WriteLine(
            "DefenseClaw rescue failed: -$unsafeName is not permitted; " +
            "the authenticated stable channel owns the rescue target and verifier"
        )
        exit 1
    }
}
if (@($RemainingArguments).Count -ne 0) {
    [Console]::Error.WriteLine(
        "DefenseClaw rescue failed: unsupported rescue arguments: " +
        ($RemainingArguments -join " ")
    )
    exit 1
}
try {
    Assert-SafeConnectorName -Name $Connector
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
if ($Help) {
    Show-RescueHelp
    exit 0
}

$stageRoot = ""
$httpClient = $null
$finalExitCode = 1
try {
    Assert-NativeWindowsX64
    $trustedPowerShell = Resolve-TrustedPowerShell

    $ambientCosign = ""
    $cosignCommand = Microsoft.PowerShell.Core\Get-Command `
        -Name "cosign.exe" `
        -CommandType Application `
        -ErrorAction SilentlyContinue |
        Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($null -ne $cosignCommand) {
        $ambientCosign = [string]$cosignCommand.Source
    }
    Clear-UntrustedEnvironment

    $stageRoot = New-PrivateStageRoot
    $cosignHome = [IO.Path]::Combine($stageRoot, "cosign-home")
    [IO.Directory]::CreateDirectory($cosignHome) | Out-Null
    $httpClient = New-HttpClient
    $cosign = Resolve-AuthenticatedCosign `
        -Client $httpClient `
        -StageRoot $stageRoot `
        -Candidate $ambientCosign

    $channelPath = ""
    for ($channelAttempt = 1; $channelAttempt -le 3; $channelAttempt++) {
        $attemptRoot = [IO.Path]::Combine(
            $stageRoot,
            "channel-attempt-$channelAttempt"
        )
        [IO.Directory]::CreateDirectory($attemptRoot) | Out-Null
        $refPath = [IO.Path]::Combine($attemptRoot, "release-channel-ref.json")
        $candidatePath = [IO.Path]::Combine($attemptRoot, "stable.txt")
        $bundlePath = "$candidatePath.bundle"

        try {
            Invoke-BoundedDownload `
                -Client $httpClient `
                -Uri $ChannelRefUrl `
                -Destination $refPath `
                -Label "release-channel branch ref" `
                -MaximumBytes $MaximumChannelRefBytes
            $channelCommit = Get-ReleaseChannelCommit -Path $refPath
            $commitBase = "$ChannelRawBaseUrl/$channelCommit"
            if (($channelAttempt % 2) -eq 1) {
                Invoke-BoundedDownload `
                    -Client $httpClient `
                    -Uri "$commitBase/stable.txt" `
                    -Destination $candidatePath `
                    -Label "stable channel manifest" `
                    -MaximumBytes $MaximumChannelBytes
                Invoke-BoundedDownload `
                    -Client $httpClient `
                    -Uri "$commitBase/stable.txt.bundle" `
                    -Destination $bundlePath `
                    -Label "stable channel Sigstore bundle" `
                    -MaximumBytes $MaximumChannelBundleBytes
            } else {
                Invoke-BoundedDownload `
                    -Client $httpClient `
                    -Uri "$commitBase/stable.txt.bundle" `
                    -Destination $bundlePath `
                    -Label "stable channel Sigstore bundle" `
                    -MaximumBytes $MaximumChannelBundleBytes
                Invoke-BoundedDownload `
                    -Client $httpClient `
                    -Uri "$commitBase/stable.txt" `
                    -Destination $candidatePath `
                    -Label "stable channel manifest" `
                    -MaximumBytes $MaximumChannelBytes
            }

            Invoke-CosignChannelVerification `
                -Verifier $cosign `
                -ChannelPath $candidatePath `
                -BundlePath $bundlePath `
                -CosignHome $cosignHome
            $channelPath = $candidatePath
            break
        } catch {
            if ($channelAttempt -eq 3) {
                throw
            }
        }
    }
    if ([string]::IsNullOrEmpty($channelPath)) {
        Die "stable channel proof did not authenticate after 3 bounded generations"
    }

    $channel = Read-CanonicalChannel -Path $channelPath
    Assert-ChannelBindings -Record $channel

    $installer = [IO.Path]::Combine($stageRoot, $WindowsInstallerName)
    Invoke-BoundedDownload `
        -Client $httpClient `
        -Uri $channel.windows_installer_url `
        -Destination $installer `
        -Label $WindowsInstallerName `
        -MaximumBytes $MaximumInstallerBytes
    Assert-Sha256 `
        -Path $installer `
        -Expected $channel.windows_installer_sha256 `
        -Label $WindowsInstallerName
    Assert-PowerShellSyntax -Path $installer
    Assert-TrustedPowerShellStable -Identity $trustedPowerShell

    $installerArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $installer,
        "-Version",
        $channel.target_version
    )
    if (-not [string]::IsNullOrWhiteSpace($Connector)) {
        $installerArguments += @("-Connector", $Connector)
    }
    if (-not [string]::IsNullOrWhiteSpace($QuickstartMode)) {
        $installerArguments += @("-QuickstartMode", $QuickstartMode)
    }
    if ($Quickstart) {
        $installerArguments += "-Quickstart"
    }
    if ($NoOpenclaw) {
        $installerArguments += "-NoOpenclaw"
    }
    if ($Yes) {
        $installerArguments += "-Yes"
    }

    Microsoft.PowerShell.Utility\Write-Host (
        "Authenticated stable Windows installer {0} ({1}); starting repair controller." -f
        $channel.target_version,
        $channel.target_commit
    )
    Clear-UntrustedEnvironment
    & $trustedPowerShell.Path @installerArguments
    $finalExitCode = ConvertTo-RescueExitCode -ExitCode $LASTEXITCODE
    if ($finalExitCode -ne 0) {
        [Console]::Error.WriteLine(
            "Authenticated install.ps1 exited with status $finalExitCode"
        )
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $finalExitCode = 1
} finally {
    if ($null -ne $httpClient) {
        $httpClient.Dispose()
    }
    if (-not [string]::IsNullOrEmpty($stageRoot)) {
        try {
            Remove-PrivateStageRoot -Path $stageRoot
        } catch {
            Microsoft.PowerShell.Utility\Write-Warning (
                "Could not remove private rescue staging directory: " +
                $_.Exception.Message
            )
        }
    }
}
exit $finalExitCode
# DefenseClaw Windows rescue bootstrap complete v1
