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
    Manifest-aware DefenseClaw upgrade resolver for Windows.
.DESCRIPTION
    Verifies signed release contracts before changing installed state. Explicit
    hard-cut requests never bridge implicitly. Latest mode bridges only sources
    named by auto_bridge_from, proves the bridge healthy, retains authenticated
    rollback artifacts privately, and invokes a fresh bridge controller. The
    bridge hop has its own exact source-state rollback before phase two begins;
    a durable private journal makes that rollback resume on the next invocation
    after abrupt process or machine termination.
    cosign must be available on PATH; authenticated release verification is a
    pre-mutation requirement and cannot be bypassed.
#>

[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$Yes,
    [ValidateRange(1, 600)][int]$HealthTimeout = 60,
    [string]$ReleaseBaseUrl = "https://github.com/cisco-ai-defense/defenseclaw/releases/download",
    [Parameter(DontShow = $true)][string]$LatestVersionOverride = "",
    [Parameter(DontShow = $true)][switch]$TestMode,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneFailureAfterMutation,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneCrashAfterMutation,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneCrashDuringRecovery,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneCrashAfterJournalClose,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneStopFailure,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneNonQuiescentStop,
    [Parameter(DontShow = $true)][switch]$InjectProtectedMaterializationCollision,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneOwnedMutationTemporaries,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneFailureAfterFreshMutation,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneConcurrentEditAfterActiveSeal,
    [Parameter(DontShow = $true)][switch]$InjectPhaseOneConcurrentFileAfterActiveSeal,
    [switch]$KeepStaging,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:Repo = "cisco-ai-defense/defenseclaw"
$script:ResolverProtocol = 2
$script:VersionPattern = '^\d+\.\d+\.\d+$'
$script:ExplicitTarget = -not [string]::IsNullOrWhiteSpace($Version)
$script:WorkRoot = ""
$script:RetainedSourceDirectory = ""
$script:PreserveWorkRoot = $false
$script:ReceiptBaseline = @{}
$script:RecoveringPhaseOneJournal = $false
$script:ControllerHome = ""
$script:RuntimePaths = $null

function Info { param([string]$Message) Write-Host "  > $Message" -ForegroundColor Cyan }
function Ok { param([string]$Message) Write-Host "  + $Message" -ForegroundColor Green }
function Warn { param([string]$Message) Write-Host "  ! $Message" -ForegroundColor Yellow }
function Step { param([string]$Message) Write-Host ""; Write-Host "--- $Message" -ForegroundColor Cyan }
function Fail { param([string]$Message) throw $Message }

function Show-Usage {
    @"
DefenseClaw Upgrade Resolver (Windows)
Usage:
  .\scripts\upgrade.ps1 [-Yes]
  .\scripts\upgrade.ps1 -Version X.Y.Z [-Yes]
Without -Version, a manifest-declared bridge may run. Explicit requests that
skip a required bridge are refused before any installed-state change.
Requires cosign on PATH to verify the exact protected release workflow identity.
"@ | Write-Host
}

function Assert-Version {
    param([string]$Value, [string]$Label)
    if ($Value -notmatch $script:VersionPattern) { Fail "$Label must be canonical X.Y.Z; got '$Value'." }
}
function Compare-Version {
    param([string]$Left, [string]$Right)
    Assert-Version $Left "left version"; Assert-Version $Right "right version"
    return ([version]$Left).CompareTo([version]$Right)
}
function Test-Integer {
    param([object]$Value)
    return $Value -is [sbyte] -or $Value -is [byte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}
function Get-Home {
    if ($env:DEFENSECLAW_HOME) { return [IO.Path]::GetFullPath($env:DEFENSECLAW_HOME) }
    return Join-Path $env:USERPROFILE ".defenseclaw"
}
function Get-ControllerHome {
    if($script:ControllerHome){return $script:ControllerHome}
    $candidate=if($env:DEFENSECLAW_HOME -and -not [string]::IsNullOrWhiteSpace($env:DEFENSECLAW_HOME)){$env:DEFENSECLAW_HOME}else{Join-Path $env:USERPROFILE ".defenseclaw"}
    if(-not [IO.Path]::IsPathRooted($candidate)){Fail "Managed controller home must be an absolute path; no installed state changed."}
    $candidate=[IO.Path]::GetFullPath($candidate)
    $item=Get-Item -LiteralPath $candidate -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Managed controller home must be a stable real directory; no installed state changed."}
    $script:ControllerHome=$candidate
    return $script:ControllerHome
}
function Assert-StableRuntimeDirectory {
    param([string]$Path,[string]$Label)
    if(-not [IO.Path]::IsPathRooted($Path)){Fail "$Label must be absolute; no installed state changed."}
    $full=[IO.Path]::GetFullPath($Path);$item=Get-Item -LiteralPath $full -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "$Label must be a stable real directory; no installed state changed."}
    return $full
}
function Resolve-InstalledRuntimePaths {
    $controllerHome=Assert-StableRuntimeDirectory -Path (Get-ControllerHome) -Label "Managed controller home"
    $configWasExplicit=$env:DEFENSECLAW_CONFIG -and -not [string]::IsNullOrWhiteSpace($env:DEFENSECLAW_CONFIG)
    if($configWasExplicit -and -not [IO.Path]::IsPathRooted($env:DEFENSECLAW_CONFIG)){Fail "Explicit DEFENSECLAW_CONFIG must be absolute; no installed state changed."}
    $configPath=if($configWasExplicit){[IO.Path]::GetFullPath($env:DEFENSECLAW_CONFIG)}else{[IO.Path]::GetFullPath((Join-Path $controllerHome "config.yaml"))}
    Assert-RealFile $configPath "Active source configuration"
    $configItem=Get-Item -LiteralPath $configPath -Force
    if($configItem.Length -le 0 -or $configItem.Length -gt 4194304){Fail "Active source configuration has an unsafe size; no installed state changed."}
    [void](Assert-StableRuntimeDirectory -Path (Split-Path -Parent $configPath) -Label "Active config parent")
    $openClawWasExplicit=$env:OPENCLAW_HOME -and -not [string]::IsNullOrWhiteSpace($env:OPENCLAW_HOME)
    if($openClawWasExplicit -and -not [IO.Path]::IsPathRooted($env:OPENCLAW_HOME)){Fail "Explicit OPENCLAW_HOME must be absolute; no installed state changed."}
    $requestedOpenClaw=if($openClawWasExplicit){[IO.Path]::GetFullPath($env:OPENCLAW_HOME)}else{"__DEFENSECLAW_UNSET__"}
    $resolver=@'
import json
import os
import sys

from defenseclaw.config import load

controller_home, config_path, openclaw_explicit, requested_openclaw = sys.argv[1:]
cfg = load(data_dir=controller_home)
configured_data_dir = os.path.expanduser(cfg.data_dir or controller_home)
if not os.path.isabs(configured_data_dir):
    raise RuntimeError("configured data_dir must be absolute for a staged upgrade")
data_dir = os.path.abspath(configured_data_dir)
openclaw_home = os.path.abspath(os.path.expanduser(requested_openclaw if openclaw_explicit == "1" else cfg.claw.home_dir))
for label, value in (("data_dir", data_dir), ("config_path", config_path), ("openclaw_home", openclaw_home)):
    if any(character in value for character in ("\n", "\r", "\t")):
        raise RuntimeError(f"{label} contains an unsafe control character")
print(json.dumps({"data_dir": data_dir, "config_path": os.path.abspath(config_path), "openclaw_home": openclaw_home}, separators=(",", ":")))
'@
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    $openClawFlag=if($openClawWasExplicit){"1"}else{"0"}
    try{
        $env:DEFENSECLAW_HOME=$controllerHome;$env:DEFENSECLAW_CONFIG=$configPath
        $output=@(& (Get-Python) -I -c $resolver $controllerHome $configPath $openClawFlag $requestedOpenClaw 2>&1)
        $contracts=@($output|Where-Object{[string]$_ -match '^\{"data_dir":"'})
        if($LASTEXITCODE -ne 0 -or $contracts.Count -ne 1){Fail "Could not resolve a stable controller-home/data-dir/config-path split from the installed source controller. No changes were made. $($output -join ' ')"}
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
    try{$resolved=[string]$contracts[0]|ConvertFrom-Json}catch{Fail "Installed source returned an invalid runtime path contract; no changes were made."}
    Assert-ExactJsonKeys $resolved @("data_dir","config_path","openclaw_home") "Installed runtime path contract"
    $resolvedConfig=[IO.Path]::GetFullPath([string]$resolved.config_path)
    if(-not $resolvedConfig.Equals($configPath,[StringComparison]::OrdinalIgnoreCase)){Fail "Installed source changed the active config path while resolving runtime state; no changes were made."}
    $dataDir=Assert-StableRuntimeDirectory -Path ([string]$resolved.data_dir) -Label "Configured data_dir"
    $openClawHome=[IO.Path]::GetFullPath([string]$resolved.openclaw_home)
    [void](Assert-StableRuntimeDirectory -Path (Split-Path -Parent $openClawHome) -Label "Resolved OpenClaw parent")
    $openClawItem=Get-Item -LiteralPath $openClawHome -Force -ErrorAction SilentlyContinue
    if($null -ne $openClawItem){$openClawHome=Assert-StableRuntimeDirectory -Path $openClawHome -Label "Resolved OpenClaw home"}
    return [pscustomobject]@{ControllerHome=$controllerHome;DataDir=$dataDir;ConfigPath=$configPath;OpenClawHome=$openClawHome;OpenClawExisted=($null -ne $openClawItem);ConfigWasExplicit=[bool]$configWasExplicit;OpenClawWasExplicit=[bool]$openClawWasExplicit}
}
function Get-OpenClawHome {
    if($env:OPENCLAW_HOME -and -not [string]::IsNullOrWhiteSpace($env:OPENCLAW_HOME)){
        if(-not [IO.Path]::IsPathRooted($env:OPENCLAW_HOME)){Fail "Explicit OPENCLAW_HOME must be an absolute path before rollback custody is prepared."}
        return [IO.Path]::GetFullPath($env:OPENCLAW_HOME)
    }
    $python=Get-Python
    $resolved=@(& $python -I -c "import os; from defenseclaw.config import load; print(os.path.abspath(os.path.expanduser(load().claw.home_dir)))" 2>$null)
    if($LASTEXITCODE -ne 0 -or $resolved.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$resolved[0]) -or -not [IO.Path]::IsPathRooted([string]$resolved[0])){
        Fail "Could not resolve the configured OpenClaw home before preparing rollback custody."
    }
    return [IO.Path]::GetFullPath([string]$resolved[0])
}
function Get-Cli {
    $path = Join-Path (Join-Path (Join-Path (Get-ControllerHome) ".venv") "Scripts") "defenseclaw.exe"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Managed CLI not found at $path." }
    return $path
}
function Get-Python {
    $path = Join-Path (Join-Path (Join-Path (Get-ControllerHome) ".venv") "Scripts") "python.exe"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Managed Python not found at $path." }
    return $path
}
function Get-Gateway {
    $path = Get-GatewayPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Gateway not found at $path." }
    return $path
}
function Get-GatewayPath {
    return Join-Path (Join-Path $env:USERPROFILE ".local\bin") "defenseclaw-gateway.exe"
}
function Enter-UpgradeMutex {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $homeBytes = [Text.Encoding]::UTF8.GetBytes((Get-ControllerHome).ToLowerInvariant())
        $homeHash = [BitConverter]::ToString($sha.ComputeHash($homeBytes)).Replace("-", "").Substring(0, 32)
    } finally { $sha.Dispose() }
    $mutex = New-Object Threading.Mutex($false, "Local\DefenseClawUpgrade-$homeHash")
    try {
        try { $acquired = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { Fail "Another DefenseClaw upgrade resolver is active; no installed state changed." }
        return $mutex
    } catch {
        $mutex.Dispose()
        throw
    }
}
function Exit-UpgradeMutex {
    param([object]$Mutex)
    if (-not $Mutex) { return }
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}
function Get-InstalledVersion {
    $cli=Get-Cli
    return (Get-CanonicalVersionOutput -Command $cli -Label "installed CLI")
}
function Get-CanonicalVersionOutput {
    param([string]$Command,[string]$Label)
    $output=(& $Command --version 2>&1|Out-String)
    $exitCode=$LASTEXITCODE
    $versionMatches=[regex]::Matches(
        $output,
        '(?<![0-9A-Za-z.])((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?![0-9A-Za-z.])'
    )
    if($exitCode -ne 0 -or $versionMatches.Count -ne 1){Fail "Could not determine $Label version."}
    return [string]$versionMatches[0].Groups[1].Value
}
function Fail-InstalledSourceCoherence {
    param([string]$Message)
    Fail "Installed source coherence check failed: $Message No changes were made: no target release was downloaded, no service was stopped, and no installed artifact was changed. Restore or reinstall the current release with the release-owned installer; do not copy a wheel or gateway over an existing installation."
}
function Assert-InstalledSourceCoherence {
    param([string]$InstalledVersion)
    $gatewayPath=Get-GatewayPath
    try{Assert-RealFile $gatewayPath "Installed gateway"}catch{Fail-InstalledSourceCoherence "The canonical gateway is missing or is not a real file."}
    try{$gatewayVersion=Get-CanonicalVersionOutput -Command $gatewayPath -Label "installed gateway"}catch{Fail-InstalledSourceCoherence "The canonical gateway version is unverifiable."}
    if($gatewayVersion -ne $InstalledVersion){
        Fail-InstalledSourceCoherence "CLI=$InstalledVersion and gateway=$gatewayVersion do not match."
    }
    if((Compare-Version $InstalledVersion "0.8.5")-lt 0){return}

    $configPath=if($env:DEFENSECLAW_CONFIG){[IO.Path]::GetFullPath($env:DEFENSECLAW_CONFIG)}else{Join-Path (Get-Home) "config.yaml"}
    try{
        Assert-RealFile $configPath "Installed configuration"
        $configItem=Get-Item -LiteralPath $configPath -Force
        if($configItem.Length -le 0 -or $configItem.Length -gt 1048576){throw "unsafe configuration size"}
        $configText=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8
        $configMatches=[regex]::Matches($configText,'(?m)^[ \t]*config_version[ \t]*:[ \t]*([0-9]+)[ \t]*(?:#.*)?$')
    }catch{Fail-InstalledSourceCoherence "The installed configuration schema is unreadable."}
    if($configMatches.Count -ne 1 -or [int64]$configMatches[0].Groups[1].Value -ne 8){
        Fail-InstalledSourceCoherence "DefenseClaw $InstalledVersion does not have exactly one config_version: 8 discriminator."
    }

    $cursorPath=Join-Path (Get-Home) ".migration_state.json"
    try{
        Assert-RealFile $cursorPath "Migration cursor"
        $cursorItem=Get-Item -LiteralPath $cursorPath -Force
        if($cursorItem.Length -le 0 -or $cursorItem.Length -gt 65536){throw "unsafe cursor size"}
        $cursor=Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8|ConvertFrom-Json
    }catch{Fail-InstalledSourceCoherence "The migration cursor is missing or unreadable."}
    $schemaProperty=Property $cursor "schema";$appliedProperty=Property $cursor "applied"
    if(-not $schemaProperty -or -not(Test-Integer $schemaProperty.Value) -or [int64]$schemaProperty.Value -ne 1 -or -not $appliedProperty -or $appliedProperty.Value -isnot [System.Array] -or @($appliedProperty.Value)-notcontains "0.8.5"){
        Fail-InstalledSourceCoherence "DefenseClaw $InstalledVersion lacks the applied 0.8.5 migration cursor."
    }
}
function Get-Arch {
    $raw = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($raw.ToUpperInvariant()) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Fail "Unsupported Windows architecture: $raw" }
    }
}
function Resolve-Target {
    if ($script:ExplicitTarget) { Assert-Version $Version "-Version"; return $Version }
    if ($LatestVersionOverride) {
        if (-not $TestMode) { Fail "LatestVersionOverride requires TestMode." }
        Assert-Version $LatestVersionOverride "LatestVersionOverride"; return $LatestVersionOverride
    }
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$($script:Repo)/releases/latest" -Headers @{ "User-Agent" = "defenseclaw-windows-upgrade" }
    } catch { Fail "Could not resolve latest release." }
    $resolved = [string]$response.tag_name
    if ($resolved.StartsWith("v")) { $resolved = $resolved.Substring(1) }
    Assert-Version $resolved "latest release"; return $resolved
}

function New-PrivateDirectoryAcl {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($current); $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($current, $system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}
function Assert-PrivateDirectoryAcl {
    param([string]$Path, [Security.AccessControl.DirectorySecurity]$Expected)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail "Private path must be a real directory: $Path"
    }
    $verified = Get-Acl -LiteralPath $Path
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $verifiedOwner = $verified.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $section = [Security.AccessControl.AccessControlSections]::Access
    $expectedDacl = $Expected.GetSecurityDescriptorSddlForm($section)
    $actualDacl = $verified.GetSecurityDescriptorSddlForm($section)
    if (-not $verified.AreAccessRulesProtected -or $verifiedOwner -ne $current.Value -or $actualDacl -ne $expectedDacl) {
        Fail "Private DACL verification failed."
    }
}
function Set-PrivateDirectoryAcl {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail "Private path must be a real directory: $Path"
    }
    $acl = New-PrivateDirectoryAcl
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-PrivateDirectoryAcl -Path $Path -Expected $acl
}
function New-PrivateDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { Fail "Private path already exists: $Path" }
    $acl = New-PrivateDirectoryAcl
    try {
        if ($PSVersionTable.PSEdition -eq "Core") {
            $directory = New-Object IO.DirectoryInfo($Path)
            [IO.FileSystemAclExtensions]::Create($directory, $acl)
        } else {
            # Windows PowerShell 5.1 exposes the equivalent atomic ACL-aware
            # overload on Directory rather than FileSystemAclExtensions.
            [void][IO.Directory]::CreateDirectory($Path, $acl)
        }
        Assert-PrivateDirectoryAcl -Path $Path -Expected $acl
        if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
            Fail "Private directory was not empty immediately after creation."
        }
    } catch {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    return [IO.Path]::GetFullPath($Path)
}
function Get-UpgradeRecoveryRoot {
    param([switch]$Create)
    $controllerHome=Get-ControllerHome
    if(-not(Test-Path -LiteralPath $controllerHome -PathType Container)){Fail "DefenseClaw controller home is missing: $controllerHome"}
    $homeItem=Get-Item -LiteralPath $controllerHome -Force
    if($homeItem.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "DefenseClaw controller home must not be a reparse point during recovery: $controllerHome"}
    $root=Join-Path $controllerHome ".upgrade-recovery"
    if(Test-Path -LiteralPath $root){Assert-PrivateDirectoryAcl -Path $root -Expected (New-PrivateDirectoryAcl)}
    elseif($Create){$root=New-PrivateDirectory $root}
    else{return $null}
    return [IO.Path]::GetFullPath($root)
}
function Get-PhaseOneRecoveryRoot {
    param([switch]$Create)
    $controllerHome=Get-ControllerHome
    $root=Join-Path $controllerHome ".upgrade-recovery"
    if(Test-Path -LiteralPath $root){Assert-PrivateDirectoryAcl -Path $root -Expected (New-PrivateDirectoryAcl)}
    elseif($Create){$root=New-PrivateDirectory $root}
    else{return $null}
    return [IO.Path]::GetFullPath($root)
}

function Release-Url {
    param([string]$ReleaseVersion, [string]$Name)
    return "$($ReleaseBaseUrl.TrimEnd('/'))/$ReleaseVersion/$Name"
}
function Download {
    param([string]$ReleaseVersion, [string]$Name, [string]$Destination)
    $url = Release-Url $ReleaseVersion $Name
    try { Invoke-WebRequest -Uri $url -OutFile $Destination -UseBasicParsing | Out-Null } catch { Fail "Failed to download $url" }
}
function Read-Checksums {
    param([string]$Path)
    $result = @{}
    foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        if ($line -notmatch '^([0-9A-Fa-f]{64})\s+(.+)$') { Fail "Invalid checksums.txt line." }
        $digest = $Matches[1].ToLowerInvariant(); $name = $Matches[2].Trim()
        if ($name.StartsWith("*")) { $name = $name.Substring(1) }
        if ($name.StartsWith("./")) { $name = $name.Substring(2) }
        if (-not $name -or $name -in @(".", "..") -or [IO.Path]::GetFileName($name) -ne $name -or $result.ContainsKey($name)) { Fail "Invalid checksum artifact name." }
        $result[$name] = $digest
    }
    if ($result.Count -eq 0) { Fail "checksums.txt has no valid entries." }
    return $result
}
function Assert-Hash {
    param([string]$Path, [string]$Name, [hashtable]$Checksums)
    if (-not $Checksums.ContainsKey($Name)) { Fail "Signed checksums do not cover $Name." }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Checksums[$Name]) { Fail "Checksum mismatch for $Name." }
}
function Assert-SinglePemCertificate {
    param([string]$Text,[string]$Label)
    $match=[regex]::Match($Text,'\A-----BEGIN CERTIFICATE-----\r?\n(?<body>(?:[A-Za-z0-9+/=]+\r?\n)+)-----END CERTIFICATE-----\r?\n?\z')
    if(-not $match.Success){Fail "$Label is not exactly one bounded PEM certificate."}
    $body=($match.Groups["body"].Value -replace '\s','')
    if($body -notmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'){Fail "$Label has invalid PEM base64."}
    try{$der=[Convert]::FromBase64String($body);$certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)}catch{Fail "$Label does not contain a valid X.509 certificate."}
    try{if([Convert]::ToBase64String($certificate.RawData)-ne [Convert]::ToBase64String($der)){Fail "$Label X.509 bytes are ambiguous."}}finally{$certificate.Dispose()}
}
function Normalize-ReleaseCertificate {
    param([string]$ReleaseVersion,[string]$Path,[string]$Directory)
    Assert-RealFile $Path "Release certificate"
    $item=Get-Item -LiteralPath $Path -Force
    if($item.Length -le 0 -or $item.Length -gt 65536){Fail "Release certificate has invalid size."}
    try{$bytes=[IO.File]::ReadAllBytes($Path);$text=(New-Object Text.UTF8Encoding($false,$true)).GetString($bytes)}catch{Fail "Release certificate is not strict UTF-8."}
    if($text.StartsWith("-----BEGIN CERTIFICATE-----")){
        Assert-SinglePemCertificate $text "Release certificate"
        return $Path
    }
    if((Compare-Version $ReleaseVersion "0.8.4")-ge 0){Fail "Modern release certificate must be raw PEM; refusing legacy normalization."}
    $encoded=$text.Trim()
    if($encoded -notmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'){Fail "Legacy release certificate is not strict base64."}
    try{$decoded=(New-Object Text.UTF8Encoding($false,$true)).GetString([Convert]::FromBase64String($encoded))}catch{Fail "Legacy release certificate base64 is invalid."}
    Assert-SinglePemCertificate $decoded "Decoded legacy release certificate"
    $normalized=Join-Path $Directory "checksums.txt.normalized.pem"
    Write-PrivateUtf8File -Path $normalized -Content $decoded
    return $normalized
}
function Verify-Signature {
    param([string]$ReleaseVersion, [string]$Checksums, [string]$Signature, [string]$Certificate)
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if (-not $cosign) {
        Fail "cosign is required to authenticate bridge and hard-cut release checksums; no installed state changed."
    }
    $identityArguments = @(
        "--certificate-identity",
        "https://github.com/$($script:Repo)/.github/workflows/release.yaml@refs/heads/main"
    )
    $cosignArguments = @("verify-blob", "--certificate", $Certificate, "--signature", $Signature) + $identityArguments + @("--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", $Checksums)
    & $cosign.Source @cosignArguments *> $null
    if ($LASTEXITCODE -ne 0) { Fail "Sigstore verification failed." }
}
function Property {
    param([object]$Object, [string]$Name)
    return $Object.PSObject.Properties[$Name]
}

function Validate-Manifest {
    param([object]$Raw, [string]$ReleaseVersion)
    $schema = Property $Raw "schema_version"; $release = Property $Raw "release_version"
    $expectedSchema = if ((Compare-Version $ReleaseVersion "0.8.4") -ge 0) { 2 } else { 1 }
    if (-not $schema -or -not (Test-Integer $schema.Value) -or [int64]$schema.Value -ne $expectedSchema) {
        Fail "Unsupported manifest schema."
    }
    if (-not $release -or $release.Value -isnot [string] -or [string]$release.Value -ne $ReleaseVersion) {
        Fail "Manifest release mismatch."
    }
    $minProperty = Property $Raw "min_upgrade_protocol"
    if ($minProperty -and -not (Test-Integer $minProperty.Value)) { Fail "min_upgrade_protocol must be an integer." }
    $minProtocol = if ($minProperty) { [int64]$minProperty.Value } else { 1 }
    if ($minProtocol -lt 1 -or $minProtocol -gt $script:ResolverProtocol) { Fail "Unsupported protocol $minProtocol." }
    $controllerProperty = Property $Raw "controller_upgrade_protocol"
    if ($controllerProperty -and -not (Test-Integer $controllerProperty.Value)) { Fail "controller_upgrade_protocol must be an integer." }
    $controllerProtocol = if ($controllerProperty) { [int64]$controllerProperty.Value } else { $minProtocol }
    if ($controllerProtocol -lt 1 -or $controllerProtocol -lt $minProtocol) { Fail "Invalid controller protocol." }

    $policyProperty = Property $Raw "migration_failure_policy"
    if (-not $policyProperty -or $policyProperty.Value -isnot [string]) { Fail "migration_failure_policy must be present as a string." }
    $policy = [string]$policyProperty.Value
    if ($policy -notin @("warn", "fail")) { Fail "Invalid migration_failure_policy." }
    $requiredProperty = Property $Raw "required_cli_migrations"
    if (-not $requiredProperty -or $requiredProperty.Value -isnot [System.Array]) {
        Fail "required_cli_migrations must be an array."
    }
    $required = @(); $requiredSeen = @{}
    foreach ($item in @($requiredProperty.Value)) {
        if ($item -isnot [string]) { Fail "required_cli_migrations must contain canonical versions." }
        $migration = [string]$item
        Assert-Version $migration "required_cli_migrations entry"
        if ($requiredSeen.ContainsKey($migration)) { Fail "required_cli_migrations contains duplicates." }
        $requiredSeen[$migration] = $true
        $required += $migration
    }

    $tested = @(); $windowsTested = @()
    $testedProperty = Property $Raw "tested_source_versions"
    $platformTestedProperty = Property $Raw "platform_tested_source_versions"
    $runtimeConfigProperty = Property $Raw "runtime_config_version"
    $releaseArtifactsProperty = Property $Raw "release_artifacts"
    $wheelArtifact="";$gatewayArtifacts=@{}
    if ($expectedSchema -eq 2) {
        if (-not $testedProperty -or $testedProperty.Value -isnot [System.Array]) {
            Fail "Schema-2 manifest requires tested_source_versions."
        }
        if (-not $platformTestedProperty -or $null -eq $platformTestedProperty.Value) {
            Fail "Schema-2 manifest requires platform_tested_source_versions."
        }
        $platformNames = @($platformTestedProperty.Value.PSObject.Properties.Name)
        $windowsProperty = Property $platformTestedProperty.Value "windows"
        if ($platformNames.Count -ne 1 -or $platformNames -notcontains "windows" -or -not $windowsProperty -or $windowsProperty.Value -isnot [System.Array]) {
            Fail "platform_tested_source_versions must contain exactly the Windows source list."
        }
        $testedSeen = @{}; $previous = ""
        foreach ($item in @($testedProperty.Value)) {
            if ($item -isnot [string]) { Fail "tested_source_versions must contain canonical versions." }
            $source = [string]$item; Assert-Version $source "tested_source_versions entry"
            if ($testedSeen.ContainsKey($source)) { Fail "tested_source_versions contains duplicates." }
            if ($previous -and (Compare-Version $previous $source) -le 0) { Fail "tested_source_versions must be strictly descending." }
            if ((Compare-Version $source $ReleaseVersion) -ge 0) { Fail "tested_source_versions must contain only older releases." }
            $testedSeen[$source] = $true; $tested += $source; $previous = $source
        }
        if ($tested.Count -eq 0) { Fail "tested_source_versions must not be empty." }
        $windowsSeen = @{}; $previous = ""
        foreach ($item in @($windowsProperty.Value)) {
            if ($item -isnot [string]) { Fail "Windows tested sources must contain canonical versions." }
            $source = [string]$item; Assert-Version $source "Windows tested-source entry"
            if ($windowsSeen.ContainsKey($source)) { Fail "Windows tested sources contain duplicates." }
            if ($previous -and (Compare-Version $previous $source) -le 0) { Fail "Windows tested sources must be strictly descending." }
            if ($tested -notcontains $source) { Fail "Windows tested sources must be a subset of tested_source_versions." }
            $windowsSeen[$source] = $true; $windowsTested += $source; $previous = $source
        }
        if ($windowsTested.Count -eq 0) { Fail "Windows tested-source list must not be empty." }
        $expectedRuntimeConfig=if($ReleaseVersion -eq "0.8.4"){7}else{8}
        if(-not $runtimeConfigProperty -or -not(Test-Integer $runtimeConfigProperty.Value) -or [int64]$runtimeConfigProperty.Value -ne $expectedRuntimeConfig){
            Fail "Schema-2 manifest runtime_config_version does not match its release boundary."
        }
        if(-not $releaseArtifactsProperty -or $null -eq $releaseArtifactsProperty.Value){Fail "Schema-2 manifest requires release_artifacts."}
        $artifactNames=@($releaseArtifactsProperty.Value.PSObject.Properties.Name)
        $wheelProperty=Property $releaseArtifactsProperty.Value "wheel"
        $gatewaysProperty=Property $releaseArtifactsProperty.Value "gateways"
        if($artifactNames.Count -ne 2 -or $artifactNames -cnotcontains "wheel" -or $artifactNames -cnotcontains "gateways" -or -not $wheelProperty -or $wheelProperty.Value -isnot [string] -or -not $gatewaysProperty){
            Fail "release_artifacts must contain exactly wheel and gateways."
        }
        $wheelArtifact=[string]$wheelProperty.Value
        $expectedWheel="defenseclaw-$ReleaseVersion-2-py3-none-any.dcwheel"
        if($wheelArtifact -cne $expectedWheel -or [IO.Path]::GetFileName($wheelArtifact) -cne $wheelArtifact){Fail "release_artifacts wheel is not the protected candidate wheel."}
        $platformArtifactNames=@($gatewaysProperty.Value.PSObject.Properties.Name)
        $missingPlatforms=@(@("darwin","linux","windows")|Where-Object{$platformArtifactNames -cnotcontains $_})
        if($platformArtifactNames.Count -ne 3 -or $missingPlatforms.Count -ne 0){Fail "release_artifacts gateways must contain exact platform maps."}
        $allProtected=@($wheelArtifact)
        foreach($platformName in @("darwin","linux","windows")){
            $platformProperty=Property $gatewaysProperty.Value $platformName
            if(-not $platformProperty){Fail "release_artifacts lacks $platformName gateways."}
            $archNames=@($platformProperty.Value.PSObject.Properties.Name)
            if($archNames.Count -ne 2 -or $archNames -cnotcontains "amd64" -or $archNames -cnotcontains "arm64"){Fail "release_artifacts $platformName gateways must contain amd64 and arm64."}
            foreach($artifactArch in @("amd64","arm64")){
                $artifactProperty=Property $platformProperty.Value $artifactArch
                if(-not $artifactProperty -or $artifactProperty.Value -isnot [string]){Fail "release_artifacts gateway name is invalid."}
                $artifactName=[string]$artifactProperty.Value
                $expectedName="defenseclaw_$($ReleaseVersion)_protocol2_$($platformName)_$artifactArch.dcgateway"
                if($artifactName -cne $expectedName -or [IO.Path]::GetFileName($artifactName) -cne $artifactName){Fail "release_artifacts gateway is not the protected candidate artifact."}
                $allProtected += $artifactName
                if($platformName -eq "windows"){$gatewayArtifacts[$artifactArch]=$artifactName}
            }
        }
        if(@($allProtected|Select-Object -Unique).Count -ne $allProtected.Count){Fail "release_artifacts names must be unique."}
    } elseif ($testedProperty -or $platformTestedProperty -or $runtimeConfigProperty -or $releaseArtifactsProperty) {
        Fail "Schema-1 manifest must not declare schema-2 policy."
    }

    $names = @("minimum_source_version", "required_bridge_version", "auto_bridge_from")
    $properties = @($names | ForEach-Object { Property $Raw $_ })
    $count = @($properties | Where-Object { $_ }).Count
    if ($count -ne 0 -and $count -ne 3) { Fail "Incomplete bridge contract." }
    $minimum = ""; $bridge = ""; $automatic = @()
    if ($count -eq 3) {
        if ($properties[0].Value -isnot [string] -or $properties[1].Value -isnot [string] -or $properties[2].Value -isnot [System.Array]) {
            Fail "Bridge contract fields have invalid types."
        }
        $minimum = [string]$properties[0].Value; $bridge = [string]$properties[1].Value; $automatic = @($properties[2].Value)
        Assert-Version $minimum "minimum_source_version"; Assert-Version $bridge "required_bridge_version"
        if ((Compare-Version $minimum $ReleaseVersion) -gt 0) { Fail "Minimum source exceeds target." }
        if ($bridge -ne $minimum) { Fail "required_bridge_version must equal minimum_source_version." }
        $seen = @{}
        foreach ($item in $automatic) {
            if ($item -isnot [string]) { Fail "auto_bridge_from must contain canonical versions." }
            $source = [string]$item; Assert-Version $source "auto_bridge_from"
            if ($seen.ContainsKey($source) -or (Compare-Version $source $minimum) -ge 0) { Fail "Invalid auto_bridge_from." }
            $seen[$source] = $true
        }
        if($tested -notcontains $bridge -or $windowsTested -notcontains $bridge){
            Fail "Required bridge is absent from a signed tested-source matrix."
        }
    }
    if ($minProtocol -gt 1 -and $count -ne 3) { Fail "Protocol-2 release lacks a complete bridge contract." }
    if ((Compare-Version $ReleaseVersion "0.8.5") -ge 0) {
        if ($minProtocol -lt 2 -or $count -ne 3 -or $policy -ne "fail" -or $automatic.Count -eq 0) {
            Fail "Hard-cut release lacks its fail-closed protocol-2 bridge contract."
        }
        if ($required -notcontains "0.8.5") { Fail "Hard-cut manifest lacks the observability-v8 migration." }
    } elseif ($count -ne 0) {
        Fail "Pre-hard-cut release must not declare a bridge contract."
    }
    if ($ReleaseVersion -eq "0.8.4" -and $controllerProtocol -lt 2) {
        Fail "Release 0.8.4 does not install the protocol-2 bridge controller."
    }
    return [pscustomobject]@{
        Raw = $Raw
        SchemaVersion = $expectedSchema
        MinimumProtocol = $minProtocol
        ControllerProtocol = $controllerProtocol
        MigrationFailurePolicy = $policy
        RequiredMigrations = $required
        TestedSources = $tested
        WindowsTestedSources = $windowsTested
        RuntimeConfigVersion = if($runtimeConfigProperty){[int64]$runtimeConfigProperty.Value}else{0}
        WheelArtifact = $wheelArtifact
        GatewayArtifacts = $gatewayArtifacts
        HasBridge = ($count -eq 3)
        MinimumSource = $minimum
        RequiredBridge = $bridge
        AutoBridgeFrom = $automatic
    }
}

function Assert-SafeZip {
    param([string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $found = $false
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\', '/'); $segments = @($name.Split('/'))
            if (-not $name -or $name.StartsWith("/") -or [IO.Path]::IsPathRooted($name) -or $segments -contains "..") { Fail "Unsafe gateway ZIP." }
            if ([IO.Path]::GetFileName($name) -eq "defenseclaw.exe") { $found = $true }
        }
        if (-not $found) { Fail "Gateway ZIP lacks defenseclaw.exe." }
    } finally { $zip.Dispose() }
}
function Assert-SafeWheel {
    param([string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip=[IO.Compression.ZipFile]::OpenRead($Path)
    try{
        $foundPackage=$false;$foundMetadata=$false
        foreach($entry in $zip.Entries){
            $name=$entry.FullName.Replace('\','/');$segments=@($name.Split('/'))
            if(-not $name -or $name.StartsWith('/') -or [IO.Path]::IsPathRooted($name) -or $segments -contains '..'){Fail "Unsafe wheel ZIP."}
            if($name -eq 'defenseclaw/__init__.py'){$foundPackage=$true}
            if($name -match '^defenseclaw-[^/]+\.dist-info/WHEEL$'){$foundMetadata=$true}
        }
        if(-not $foundPackage -or -not $foundMetadata){Fail "Materialized wheel lacks DefenseClaw package metadata."}
    }finally{$zip.Dispose()}
}
function Assert-CanonicalRefusalEnvelope {
    param([string]$Path,[string]$ReleaseVersion,[string]$Label)
    Assert-RealFile $Path "Canonical $Label refusal envelope"
    $boundary=if($ReleaseVersion -eq "0.8.4"){"DefenseClaw 0.8.4 must be installed by the release-owned staged upgrade resolver.`n"}else{"DefenseClaw $ReleaseVersion requires the 0.8.4 upgrade bridge.`n"}
    $expected=(New-Object Text.UTF8Encoding($false,$true)).GetBytes($boundary+"No changes were made. Run the release-owned upgrade resolver without a version.`n")
    $actual=[IO.File]::ReadAllBytes($Path)
    if($actual.Length -ne $expected.Length){Fail "Canonical $Label refusal envelope has an invalid size."}
    for($index=0;$index -lt $expected.Length;$index++){if($actual[$index] -ne $expected[$index]){Fail "Canonical $Label refusal envelope changed."}}
}
function Stage-Release {
    param([string]$ReleaseVersion, [string]$Purpose)
    $directory = New-PrivateDirectory (Join-Path $script:WorkRoot "$Purpose-$ReleaseVersion")
    foreach ($name in @("checksums.txt","checksums.txt.sig","checksums.txt.pem")) { Download $ReleaseVersion $name (Join-Path $directory $name) }
    $certificate=Normalize-ReleaseCertificate $ReleaseVersion (Join-Path $directory "checksums.txt.pem") $directory
    Verify-Signature $ReleaseVersion (Join-Path $directory "checksums.txt") (Join-Path $directory "checksums.txt.sig") $certificate
    $checksums = Read-Checksums (Join-Path $directory "checksums.txt")
    $manifestPath = Join-Path $directory "upgrade-manifest.json"; Download $ReleaseVersion "upgrade-manifest.json" $manifestPath; Assert-Hash $manifestPath "upgrade-manifest.json" $checksums
    try { $raw = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Fail "Invalid manifest JSON." }
    $manifest = Validate-Manifest $raw $ReleaseVersion
    $archValue = Get-Arch
    $protectedWheel = if($manifest.SchemaVersion -eq 2){$manifest.WheelArtifact}else{"defenseclaw-$ReleaseVersion-py3-none-any.whl"}
    $protectedGateway = if($manifest.SchemaVersion -eq 2){[string]$manifest.GatewayArtifacts[$archValue]}else{"defenseclaw_$($ReleaseVersion)_windows_$archValue.zip"}
    $refusalWheel="defenseclaw-$ReleaseVersion-py3-none-any.whl";$refusalGateway="defenseclaw_$($ReleaseVersion)_windows_$archValue.zip"
    $downloadNames=if($manifest.SchemaVersion -eq 2){@($protectedWheel,$protectedGateway,$refusalWheel,$refusalGateway)}else{@($protectedWheel,$protectedGateway)}
    foreach ($name in @($downloadNames|Select-Object -Unique)) { $path=Join-Path $directory $name; Download $ReleaseVersion $name $path; Assert-Hash $path $name $checksums }
    if($manifest.SchemaVersion -eq 2){
        Assert-CanonicalRefusalEnvelope -Path (Join-Path $directory $refusalWheel) -ReleaseVersion $ReleaseVersion -Label "wheel"
        Assert-CanonicalRefusalEnvelope -Path (Join-Path $directory $refusalGateway) -ReleaseVersion $ReleaseVersion -Label "gateway"
        $materializedDirectory=New-PrivateDirectory (Join-Path $directory "materialized")
        $wheel=Join-Path "materialized" $refusalWheel
        $gateway=Join-Path "materialized" $refusalGateway
        if($InjectProtectedMaterializationCollision -and $Purpose -eq "final"){Write-PrivateUtf8File -Path (Join-Path $directory $wheel) -Content "protected-materialization-collision-sentinel`n"}
        [void](New-AuthenticatedMaterializedFile -Source (Join-Path $directory $protectedWheel) -Destination (Join-Path $directory $wheel) -Label "wheel" -ExpectedOuterSha256 $checksums[$protectedWheel])
        [void](New-AuthenticatedMaterializedFile -Source (Join-Path $directory $protectedGateway) -Destination (Join-Path $directory $gateway) -Label "gateway" -ExpectedOuterSha256 $checksums[$protectedGateway])
        Assert-SafeWheel (Join-Path $directory $wheel)
        Assert-SafeZip (Join-Path $directory $gateway)
    }else{
        $wheel=$protectedWheel;$gateway=$protectedGateway
        Assert-SafeZip (Join-Path $directory $gateway)
    }
    Ok "$Purpose $ReleaseVersion verified"
    return [pscustomobject]@{ Version=$ReleaseVersion; Directory=$directory; Manifest=$manifest; Wheel=$wheel; Gateway=$gateway; ProtectedWheel=$protectedWheel; ProtectedGateway=$protectedGateway; RefusalWheel=$refusalWheel; RefusalGateway=$refusalGateway }
}

function Get-OwnerDaclSddl {
    param([string]$Path)
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    return (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($sections)
}
function New-FileAclFromSddl {
    param([string]$Sddl)
    $security = New-Object Security.AccessControl.FileSecurity
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $security.SetSecurityDescriptorSddlForm($Sddl, $sections)
    return $security
}
function New-DirectoryAclFromSddl {
    param([string]$Sddl)
    $security = New-Object Security.AccessControl.DirectorySecurity
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $security.SetSecurityDescriptorSddlForm($Sddl, $sections)
    return $security
}
function New-PrivateFileAcl {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetOwner($current); $security.SetAccessRuleProtection($true, $false)
    foreach($sid in @($current,$system,$administrators)){
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    return $security
}
function Get-PrivateFileSddl {
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    return (New-PrivateFileAcl).GetSecurityDescriptorSddlForm($sections)
}
function Assert-PrivateFileAcl {
    param([string]$Path)
    Assert-RealFile $Path "Private file"
    if((Get-OwnerDaclSddl $Path)-ne (Get-PrivateFileSddl)){Fail "Private file DACL verification failed: $Path"}
}
function Set-PrivateFileAcl {
    param([string]$Path)
    Assert-RealFile $Path "Private file"
    $security=New-PrivateFileAcl;Set-Acl -LiteralPath $Path -AclObject $security
    Assert-PrivateFileAcl $Path
}
function Assert-RealFile {
    param([string]$Path,[string]$Label)
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "$Label must be a real file: $Path"}
}
function New-PrivateFileStream {
    param([string]$Path)
    $private=New-PrivateFileAcl
    if($PSVersionTable.PSEdition -eq "Core"){
        $info=New-Object IO.FileInfo($Path)
        return [IO.FileSystemAclExtensions]::Create($info,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,65536,[IO.FileOptions]::WriteThrough,$private)
    }
    return New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,65536,[IO.FileOptions]::WriteThrough,$private)
}
function Write-PrivateUtf8File {
    param([string]$Path,[string]$Content)
    if(Test-Path -LiteralPath $Path){Fail "Private file already exists: $Path"}
    $stream=New-PrivateFileStream $Path
    try{
        $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Content)
        $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
    }finally{$stream.Dispose()}
    Assert-PrivateFileAcl $Path
}
function Write-SecuredRestoreCandidate {
    param([string]$Source,[string]$Destination,[string]$FinalSddl)
    if(Test-Path -LiteralPath $Destination){Fail "Restore candidate already exists: $Destination"}
    Assert-RealFile $Source "Rollback source"
    $stream=New-PrivateFileStream $Destination
    try{
        $sourceStream=[IO.File]::OpenRead($Source)
        try{$sourceStream.CopyTo($stream)}finally{$sourceStream.Dispose()}
        $stream.Flush($true)
    }finally{$stream.Dispose()}
    $final=New-FileAclFromSddl $FinalSddl;Set-Acl -LiteralPath $Destination -AclObject $final
    if((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash){Fail "Staged rollback digest mismatch"}
    if((Get-OwnerDaclSddl $Destination)-ne $FinalSddl){Fail "Staged rollback owner/DACL mismatch"}
}
function New-AuthenticatedMaterializedFile {
    param([string]$Source,[string]$Destination,[string]$Label,[string]$ExpectedOuterSha256)
    Assert-RealFile $Source "Authenticated protected $Label artifact"
    if(Test-Path -LiteralPath $Destination){Fail "Authenticated $Label materialization destination already exists; refusing to overwrite: $Destination"}
    $sourceItem=Get-Item -LiteralPath $Source -Force
    $magic=(New-Object Text.UTF8Encoding($false,$true)).GetBytes("DEFENSECLAW-PROTECTED-ARTIFACT-V1`n")
    $ExpectedOuterSha256=([string]$ExpectedOuterSha256).ToLowerInvariant()
    if($ExpectedOuterSha256 -notmatch '^[0-9a-f]{64}$'){Fail "Authenticated protected $Label artifact lacks a signed outer digest."}
    if($sourceItem.Length -le $magic.Length -or $sourceItem.Length -gt 4294967296){Fail "Authenticated protected $Label envelope has an invalid size."}
    $destinationStream=$null;$sourceStream=$null;$innerHash=$null;$outerHash=$null;$created=$false
    try{
        $destinationStream=New-PrivateFileStream $Destination;$created=$true
        $sourceStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $observed=New-Object byte[] $magic.Length;$offset=0
        while($offset -lt $observed.Length){$count=$sourceStream.Read($observed,$offset,$observed.Length-$offset);if($count -le 0){Fail "Authenticated protected $Label envelope is truncated."};$offset += $count}
        for($index=0;$index -lt $magic.Length;$index++){if($observed[$index] -ne $magic[$index]){Fail "Authenticated protected $Label envelope has invalid magic."}}
        $outerHash=[Security.Cryptography.SHA256]::Create()
        [void]$outerHash.TransformBlock($observed,0,$observed.Length,$observed,0)
        $innerHash=[Security.Cryptography.SHA256]::Create()
        $encoded=New-Object byte[] 1048576;$decoded=New-Object byte[] 1048576;$decodedBytes=[int64]0
        while(($count=$sourceStream.Read($encoded,0,$encoded.Length)) -gt 0){
            [void]$outerHash.TransformBlock($encoded,0,$count,$encoded,0)
            for($index=0;$index -lt $count;$index++){$decoded[$index]=[byte]($encoded[$index] -bxor 0xA5)}
            $destinationStream.Write($decoded,0,$count)
            [void]$innerHash.TransformBlock($decoded,0,$count,$decoded,0)
            $decodedBytes += $count
        }
        if($decodedBytes -le 0){Fail "Authenticated protected $Label envelope has no payload."}
        [void]$outerHash.TransformFinalBlock((New-Object byte[] 0),0,0)
        $observedOuterDigest=[BitConverter]::ToString($outerHash.Hash).Replace('-','').ToLowerInvariant()
        if($observedOuterDigest -ne $ExpectedOuterSha256){Fail "Authenticated protected $Label artifact changed after checksum authentication."}
        [void]$innerHash.TransformFinalBlock((New-Object byte[] 0),0,0)
        $expectedDigest=[BitConverter]::ToString($innerHash.Hash).Replace('-','').ToLowerInvariant()
        $destinationStream.Flush($true)
    }catch{
        if($sourceStream){$sourceStream.Dispose();$sourceStream=$null}
        if($destinationStream){$destinationStream.Dispose();$destinationStream=$null}
        if($innerHash){$innerHash.Dispose();$innerHash=$null}
        if($outerHash){$outerHash.Dispose();$outerHash=$null}
        if($created){Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue}
        throw
    }finally{
        if($sourceStream){$sourceStream.Dispose()}
        if($destinationStream){$destinationStream.Dispose()}
        if($innerHash){$innerHash.Dispose()}
        if($outerHash){$outerHash.Dispose()}
    }
    Assert-PrivateFileAcl $Destination
    $destinationDigest=(Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if($destinationDigest -ne $expectedDigest){
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        Fail "Authenticated $Label materialization digest changed; refusing the release."
    }
    return [IO.Path]::GetFullPath($Destination)
}
function Get-PhaseOneStateTargets {
    param([string]$DataDir,[string]$OpenClawHome,[string]$ConfigPath)
    $dataHome=[IO.Path]::GetFullPath($DataDir)
    $openHome=[IO.Path]::GetFullPath($OpenClawHome)
    if(-not $ConfigPath){Fail "Phase-one state custody requires the actual source config path"}
    $config=[IO.Path]::GetFullPath($ConfigPath)
    $targets=@(
        [pscustomobject]@{Key="config";Active=$config},
        [pscustomobject]@{Key="config/pre-observability-migration-backup";Active=($config+".pre-observability-migration.bak")},
        [pscustomobject]@{Key="config/lock";Active=($config+".lock")},
        [pscustomobject]@{Key="config/fixed-temp";Active=($config+".tmp-f3395")}
    )
    foreach($name in @(
        ".env",".migration_state.json","guardrail_runtime.json",
        "device.key","active_connector.json","codex_backup.json",
        "claudecode_backup.json","zeptoclaw_backup.json","codex_config_backup.json",
        "codex_env.sh","codex.env","policies","connector_backups",
        "hooks",".upgrade-shims","observability-stack"
    )){
        $targets += [pscustomobject]@{Key="data/$name";Active=[IO.Path]::GetFullPath((Join-Path $dataHome $name))}
    }
    foreach($name in @("openclaw.json","openclaw.json.pre-0.3.0-migration")){
        $targets += [pscustomobject]@{Key="openclaw/$name";Active=[IO.Path]::GetFullPath((Join-Path $openHome $name))}
    }
    for($left=0;$left -lt $targets.Count;$left++){
        for($right=$left+1;$right -lt $targets.Count;$right++){
            $leftPath=[string]$targets[$left].Active;$rightPath=[string]$targets[$right].Active
            $leftPrefix=$leftPath.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))+[IO.Path]::DirectorySeparatorChar
            $rightPrefix=$rightPath.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))+[IO.Path]::DirectorySeparatorChar
            if($leftPath.Equals($rightPath,[StringComparison]::OrdinalIgnoreCase) -or $leftPath.StartsWith($rightPrefix,[StringComparison]::OrdinalIgnoreCase) -or $rightPath.StartsWith($leftPrefix,[StringComparison]::OrdinalIgnoreCase)){
                Fail "Phase-one managed state targets overlap: $leftPath and $rightPath"
            }
        }
    }
    return @($targets)
}
function Get-PhaseOneItem {
    param([string]$Path)
    try{return Get-Item -LiteralPath $Path -Force -ErrorAction Stop}catch [System.Management.Automation.ItemNotFoundException]{return $null}
}
function Get-PhaseOnePathInventory {
    param([string]$Path)
    $rootItem=Get-PhaseOneItem $Path
    if($null -eq $rootItem){return @()}
    $pending=New-Object Collections.Stack
    $pending.Push([pscustomobject]@{Path=[IO.Path]::GetFullPath($Path);Relative="."})
    $inventory=New-Object Collections.Generic.List[object]
    while($pending.Count -gt 0){
        $current=$pending.Pop();$item=Get-PhaseOneItem $current.Path
        if($null -eq $item){Fail "Phase-one state changed while it was inventoried: $($current.Path)"}
        $attributes=[int64]$item.Attributes
        $isReparse=($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        $linkTypeProperty=$item.PSObject.Properties["LinkType"]
        $linkType=if($linkTypeProperty){[string]$linkTypeProperty.Value}else{""}
        if(-not $isReparse -and $linkType){Fail "Phase-one state contains an unsupported hard link: $($current.Path)"}
        if($isReparse){
            if($linkType -notin @("SymbolicLink","Junction")){Fail "Phase-one state contains an unsupported reparse point: $($current.Path)"}
            $targetProperty=$item.PSObject.Properties["Target"]
            $targets=@(if($targetProperty){@($targetProperty.Value)}else{@()})
            if($targets.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$targets[0])){Fail "Phase-one reparse target is unavailable: $($current.Path)"}
            if(-not(Test-Path -LiteralPath $current.Path)){Fail "Broken phase-one reparse points are not rollback-safe: $($current.Path)"}
            [void]$inventory.Add([pscustomobject][ordered]@{
                relative=$current.Relative;kind=$linkType.ToLowerInvariant();attributes=$attributes
                sddl="";length=[int64]0;sha256="";blob="";link_type=$linkType
                link_target=[string]$targets[0];link_is_directory=[bool]$item.PSIsContainer
            })
            continue
        }
        if($item.PSIsContainer){
            [void]$inventory.Add([pscustomobject][ordered]@{
                relative=$current.Relative;kind="directory";attributes=$attributes
                sddl=(Get-OwnerDaclSddl $current.Path);length=[int64]0;sha256="";blob=""
                link_type="";link_target="";link_is_directory=$false
            })
            $children=@(Get-ChildItem -LiteralPath $current.Path -Force|Sort-Object Name -Descending)
            foreach($child in $children){
                $relative=if($current.Relative -eq "."){$child.Name}else{$current.Relative+"/"+$child.Name}
                $pending.Push([pscustomobject]@{Path=$child.FullName;Relative=$relative})
            }
            continue
        }
        Assert-RealFile $current.Path "Phase-one state"
        [void]$inventory.Add([pscustomobject][ordered]@{
            relative=$current.Relative;kind="file";attributes=$attributes
            sddl=(Get-OwnerDaclSddl $current.Path);length=[int64]$item.Length
            sha256=(Get-FileHash -LiteralPath $current.Path -Algorithm SHA256).Hash.ToLowerInvariant()
            blob="";link_type="";link_target="";link_is_directory=$false
        })
    }
    if($inventory.Count -gt 16384){Fail "Phase-one state inventory exceeds its entry bound"}
    $total=[int64]0;foreach($node in $inventory){if($node.kind -eq "file"){$total += [int64]$node.length}}
    if($total -gt 1073741824){Fail "Phase-one state inventory exceeds its byte bound"}
    return @($inventory|ForEach-Object{$_})
}
function Get-PhaseOneInventoryIdentity {
    param([object[]]$Inventory)
    $identity=@($Inventory|ForEach-Object{[ordered]@{
        relative=[string]$_.relative;kind=[string]$_.kind;attributes=[int64]$_.attributes
        sddl=[string]$_.sddl;length=[int64]$_.length;sha256=[string]$_.sha256
        link_type=[string]$_.link_type;link_target=[string]$_.link_target
        link_is_directory=[bool]$_.link_is_directory
    }})
    return ConvertTo-Json -InputObject $identity -Depth 8 -Compress
}
function Resolve-PhaseOneInventoryPath {
    param([string]$Root,[string]$Relative)
    $rootFull=[IO.Path]::GetFullPath($Root)
    if($Relative -eq "."){return $rootFull}
    if(-not $Relative -or $Relative.StartsWith("/") -or $Relative.Split('/') -contains ".." -or $Relative.Split('/') -contains "."){Fail "Invalid phase-one inventory relative path"}
    $native=$Relative.Replace('/',[IO.Path]::DirectorySeparatorChar)
    $full=[IO.Path]::GetFullPath((Join-Path $rootFull $native))
    $prefix=$rootFull.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar))+[IO.Path]::DirectorySeparatorChar
    if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one inventory path escaped its target"}
    return $full
}
function Remove-PhaseOneManagedPath {
    param([string]$Path)
    $item=Get-PhaseOneItem $Path
    if($null -eq $item){return}
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){
        if($item.PSIsContainer){[IO.Directory]::Delete($Path)}else{[IO.File]::Delete($Path)}
        if($null -ne (Get-PhaseOneItem $Path)){Fail "Phase-one reparse point was not removed: $Path"}
        return
    }
    if($item.PSIsContainer){
        foreach($child in @(Get-ChildItem -LiteralPath $Path -Force)){Remove-PhaseOneManagedPath $child.FullName}
        Set-PrivateDirectoryAcl $Path
        [IO.File]::SetAttributes($Path,[IO.FileAttributes]::Directory)
        [IO.Directory]::Delete($Path)
    }else{
        Assert-RealFile $Path "Phase-one removal target"
        Set-PrivateFileAcl $Path
        [IO.File]::SetAttributes($Path,[IO.FileAttributes]::Normal)
        [IO.File]::Delete($Path)
    }
    if($null -ne (Get-PhaseOneItem $Path)){Fail "Phase-one managed state was not removed: $Path"}
}
function New-PhaseOneStateSnapshot {
    param([string]$StateRoot,[string]$DataDir,[string]$OpenClawHome,[string]$ConfigPath)
    $targets=@(Get-PhaseOneStateTargets -DataDir $DataDir -OpenClawHome $OpenClawHome -ConfigPath $ConfigPath)
    $entries=@();$blobNames=@{};$totalNodes=[int64]0;$totalBytes=[int64]0
    for($targetIndex=0;$targetIndex -lt $targets.Count;$targetIndex++){
        $target=$targets[$targetIndex];$item=Get-PhaseOneItem $target.Active
        $inventory=@(if($null -eq $item){@()}else{@(Get-PhaseOnePathInventory $target.Active)})
        $totalNodes += $inventory.Count
        foreach($inventoryNode in $inventory){if($inventoryNode.kind -eq "file"){$totalBytes += [int64]$inventoryNode.length}}
        if($totalNodes -gt 16384){Fail "Phase-one state snapshot exceeds its total entry bound"}
        if($totalBytes -gt 1073741824){Fail "Phase-one state snapshot exceeds its total byte bound"}
        for($nodeIndex=0;$nodeIndex -lt $inventory.Count;$nodeIndex++){
            $node=$inventory[$nodeIndex]
            if($node.kind -ne "file"){continue}
            $blobName=("item-{0:D2}-file-{1:D5}.source" -f $targetIndex,$nodeIndex)
            $blob=Join-Path $StateRoot $blobName
            $source=Resolve-PhaseOneInventoryPath -Root $target.Active -Relative ([string]$node.relative)
            Write-SecuredRestoreCandidate -Source $source -Destination $blob -FinalSddl (Get-PrivateFileSddl)
            if((Get-FileHash -LiteralPath $blob -Algorithm SHA256).Hash.ToLowerInvariant()-ne [string]$node.sha256){Fail "Phase-one state blob digest mismatch"}
            $node.blob=$blobName;$blobNames[$blobName]=$true
        }
        if($null -ne $item){
            $current=@(Get-PhaseOnePathInventory $target.Active)
            if((Get-PhaseOneInventoryIdentity $inventory)-ne (Get-PhaseOneInventoryIdentity $current)){Fail "Phase-one state changed while it was snapshotted: $($target.Active)"}
        }
        $entries += [pscustomobject][ordered]@{key=$target.Key;target=$target.Active;existed=($null -ne $item);inventory=$inventory}
    }
    $roots=@()
    foreach($root in @(
        [pscustomobject]@{Key="data";Path=[IO.Path]::GetFullPath($DataDir)},
        [pscustomobject]@{Key="openclaw";Path=[IO.Path]::GetFullPath($OpenClawHome)}
    )){
        $item=Get-PhaseOneItem $root.Path
        if($null -ne $item -and (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))){Fail "Phase-one managed root must be a real directory: $($root.Path)"}
        $roots += [pscustomobject][ordered]@{
            key=$root.Key;target=$root.Path;existed=($null -ne $item)
            attributes=if($null -ne $item){[int64]$item.Attributes}else{[int64]0}
            sddl=if($null -ne $item){Get-OwnerDaclSddl $root.Path}else{""}
        }
    }
    $manifest=Join-Path $StateRoot "manifest.json"
    $document=[ordered]@{schema_version=1;entries=$entries;roots=$roots}
    Write-PrivateUtf8File -Path $manifest -Content ((ConvertTo-Json -InputObject $document -Depth 12 -Compress)+"`n")
    $digest=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{Manifest=$manifest;ManifestSha256=$digest;Entries=$entries;Roots=$roots;BlobNames=$blobNames}
}
function Read-PhaseOneStateSnapshot {
    param([string]$StateRoot,[string]$ExpectedDigest,[string]$DataDir,[string]$OpenClawHome,[string]$ConfigPath,[switch]$AllowActiveManifest)
    $manifest=Join-Path $StateRoot "manifest.json";Assert-PrivateFileAcl $manifest
    $manifestItem=Get-Item -LiteralPath $manifest -Force
    if($manifestItem.Length -le 0 -or $manifestItem.Length -gt 4194304){Fail "Phase-one state manifest has invalid size"}
    if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()-ne $ExpectedDigest){Fail "Phase-one state manifest digest changed"}
    try{$raw=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one state manifest is invalid JSON"}
    Assert-ExactJsonKeys $raw @("schema_version","entries","roots") "Phase-one state manifest"
    if(-not(Test-Integer $raw.schema_version) -or [int64]$raw.schema_version -ne 1){Fail "Unsupported phase-one state manifest schema"}
    $expectedTargets=@(Get-PhaseOneStateTargets -DataDir $DataDir -OpenClawHome $OpenClawHome -ConfigPath $ConfigPath)
    $entries=@($raw.entries)
    if($entries.Count -ne $expectedTargets.Count){Fail "Phase-one state target count changed"}
    $expectedBlobs=@{};$parsed=@();$totalNodes=[int64]0;$totalBytes=[int64]0
    for($entryIndex=0;$entryIndex -lt $entries.Count;$entryIndex++){
        $entry=$entries[$entryIndex];$expected=$expectedTargets[$entryIndex]
        Assert-ExactJsonKeys $entry @("key","target","existed","inventory") "Phase-one state entry"
        if([string]$entry.key -ne $expected.Key -or -not ([IO.Path]::GetFullPath([string]$entry.target)).Equals($expected.Active,[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one state target set changed"}
        if($entry.existed -isnot [bool]){Fail "Phase-one state existed flag is invalid"}
        $nodes=@($entry.inventory);$seen=@{}
        if(-not $entry.existed -and $nodes.Count -ne 0){Fail "Absent phase-one state has an inventory"}
        if($entry.existed -and ($nodes.Count -eq 0 -or [string]$nodes[0].relative -ne ".")){Fail "Existing phase-one state lacks a root inventory entry"}
        foreach($node in $nodes){
            $totalNodes++
            if($totalNodes -gt 16384){Fail "Phase-one state manifest exceeds its total entry bound"}
            Assert-ExactJsonKeys $node @("relative","kind","attributes","sddl","length","sha256","blob","link_type","link_target","link_is_directory") "Phase-one inventory node"
            $relative=[string]$node.relative
            [void](Resolve-PhaseOneInventoryPath -Root $expected.Active -Relative $relative)
            if($seen.ContainsKey($relative)){Fail "Phase-one inventory contains duplicate paths"};$seen[$relative]=$true
            if(-not(Test-Integer $node.attributes) -or -not(Test-Integer $node.length) -or $node.link_is_directory -isnot [bool]){Fail "Phase-one inventory metadata type is invalid"}
            $kind=[string]$node.kind
            $isReparse=([int64]$node.attributes -band [int64][IO.FileAttributes]::ReparsePoint) -ne 0
            if(($kind -in @("symboliclink","junction")) -ne $isReparse){Fail "Phase-one inventory reparse metadata is inconsistent"}
            if($kind -in @("file","directory")){
                if(-not [string]$node.sddl){Fail "Phase-one real state lacks owner/DACL metadata"}
                try{if($kind -eq "file"){[void](New-FileAclFromSddl ([string]$node.sddl))}else{[void](New-DirectoryAclFromSddl ([string]$node.sddl))}}catch{Fail "Phase-one owner/DACL metadata is invalid"}
            }
            if($kind -eq "file"){
                $blob=[string]$node.blob;$sha=[string]$node.sha256
                if($blob -notmatch '^item-\d{2}-file-\d{5}\.source$' -or $expectedBlobs.ContainsKey($blob) -or $sha -notmatch '^[0-9a-f]{64}$' -or [int64]$node.length -lt 0 -or [string]$node.link_type -or [string]$node.link_target -or [bool]$node.link_is_directory){Fail "Phase-one file inventory is invalid"}
                $totalBytes += [int64]$node.length
                if($totalBytes -gt 1073741824){Fail "Phase-one state manifest exceeds its total byte bound"}
                $expectedBlobs[$blob]=$true;$blobPath=Join-Path $StateRoot $blob;Assert-PrivateFileAcl $blobPath
                if((Get-FileHash -LiteralPath $blobPath -Algorithm SHA256).Hash.ToLowerInvariant()-ne $sha -or (Get-Item -LiteralPath $blobPath -Force).Length -ne [int64]$node.length){Fail "Phase-one state blob changed"}
            }elseif($kind -eq "directory"){
                if([string]$node.blob -or [string]$node.sha256 -or [int64]$node.length -ne 0 -or [string]$node.link_type -or [string]$node.link_target -or [bool]$node.link_is_directory){Fail "Phase-one directory inventory is invalid"}
            }elseif($kind -in @("symboliclink","junction")){
                if([string]$node.sddl -or [string]$node.blob -or [string]$node.sha256 -or [int64]$node.length -ne 0 -or [string]::IsNullOrWhiteSpace([string]$node.link_target)){Fail "Phase-one reparse inventory is invalid"}
                if(($kind -eq "symboliclink" -and [string]$node.link_type -ne "SymbolicLink") -or ($kind -eq "junction" -and [string]$node.link_type -ne "Junction")){Fail "Phase-one reparse kind changed"}
                if($kind -eq "junction" -and -not [bool]$node.link_is_directory){Fail "Phase-one junction inventory is not directory-shaped"}
            }else{Fail "Phase-one inventory kind is unsupported"}
            if($relative -ne "."){
                $slash=$relative.LastIndexOf('/');$parent=if($slash -lt 0){"."}else{$relative.Substring(0,$slash)}
                if(-not $seen.ContainsKey($parent)){Fail "Phase-one inventory parent ordering is invalid"}
            }
        }
        $parsed += [pscustomobject]@{Key=$expected.Key;Active=$expected.Active;Existed=[bool]$entry.existed;Inventory=$nodes}
    }
    $roots=@($raw.roots)
    if($roots.Count -ne 2){Fail "Phase-one root metadata count changed"}
    $expectedRoots=@([IO.Path]::GetFullPath($DataDir),[IO.Path]::GetFullPath($OpenClawHome));$parsedRoots=@()
    for($index=0;$index -lt 2;$index++){
        $root=$roots[$index];Assert-ExactJsonKeys $root @("key","target","existed","attributes","sddl") "Phase-one root metadata"
        if([string]$root.key -ne @("data","openclaw")[$index] -or -not ([IO.Path]::GetFullPath([string]$root.target)).Equals($expectedRoots[$index],[StringComparison]::OrdinalIgnoreCase) -or $root.existed -isnot [bool] -or -not(Test-Integer $root.attributes)){Fail "Phase-one root metadata is invalid"}
        if($root.existed){try{[void](New-DirectoryAclFromSddl ([string]$root.sddl))}catch{Fail "Phase-one root owner/DACL is invalid"}}elseif([string]$root.sddl -or [int64]$root.attributes -ne 0){Fail "Absent phase-one root has unexpected metadata"}
        $parsedRoots += [pscustomobject]@{Key=[string]$root.key;Active=$expectedRoots[$index];Existed=[bool]$root.existed;Attributes=[int64]$root.attributes;Sddl=[string]$root.sddl}
    }
    foreach($child in @(Get-ChildItem -LiteralPath $StateRoot -Force)){
        if($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one state custody contains an unsupported member"}
        if($child.Name -ne "manifest.json" -and -not($AllowActiveManifest -and $child.Name -eq "active-manifest.json") -and -not $expectedBlobs.ContainsKey($child.Name)){Fail "Phase-one state custody contains an unexpected blob"}
    }
    return [pscustomobject]@{Manifest=$manifest;ManifestSha256=$ExpectedDigest;Entries=$parsed;Roots=$parsedRoots;BlobNames=$expectedBlobs}
}
function Get-PhaseOneRootState {
    param([string]$Key,[string]$Path,[string]$Python)
    $full=[IO.Path]::GetFullPath($Path);$item=Get-PhaseOneItem $full
    if($null -eq $item){return [pscustomobject]@{Key=$Key;Active=$full;Existed=$false;Attributes=[int64]0;Sddl="";Device="";Inode=""}}
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one managed root must be a real directory: $full"}
    $identity=Get-PhaseOneDirectoryIdentity -Path $full -Python $Python
    return [pscustomobject]@{
        Key=$Key;Active=$full;Existed=$true;Attributes=[int64]$item.Attributes
        Sddl=(Get-OwnerDaclSddl $full);Device=[string]$identity.device;Inode=[string]$identity.inode
    }
}
function Test-PhaseOneEntryMatches {
    param([string]$Path,[object]$Entry)
    $item=Get-PhaseOneItem $Path
    if(($null -ne $item) -ne [bool]$Entry.Existed){return $false}
    if($null -eq $item){return $true}
    $current=@(Get-PhaseOnePathInventory $Path)
    return (Get-PhaseOneInventoryIdentity -Inventory @($Entry.Inventory)) -eq (Get-PhaseOneInventoryIdentity -Inventory $current)
}
function Test-PhaseOneRootMatches {
    param([object]$Expected,[string]$Python)
    $current=Get-PhaseOneRootState -Key ([string]$Expected.Key) -Path ([string]$Expected.Active) -Python $Python
    if([bool]$current.Existed -ne [bool]$Expected.Existed){return $false}
    if(-not [bool]$Expected.Existed){return $true}
    if([int64]$current.Attributes -ne [int64]$Expected.Attributes -or [string]$current.Sddl -ne [string]$Expected.Sddl){return $false}
    $deviceProperty=Property $Expected "Device";$inodeProperty=Property $Expected "Inode"
    if($deviceProperty -and $inodeProperty -and ([string]$deviceProperty.Value -or [string]$inodeProperty.Value)){
        return [string]$current.Device -eq [string]$deviceProperty.Value -and [string]$current.Inode -eq [string]$inodeProperty.Value
    }
    return $true
}
function New-PhaseOneActiveStateSnapshot {
    param([object]$Plan)
    $manifest=Join-Path $Plan.StateRoot "active-manifest.json"
    if($null -ne (Get-PhaseOneItem $manifest)){Fail "Phase-one active state manifest already exists"}
    $targets=@(Get-PhaseOneStateTargets -DataDir $Plan.DataDir -OpenClawHome $Plan.OpenClawHome -ConfigPath $Plan.ConfigPath)
    $entries=@();$totalNodes=[int64]0;$totalBytes=[int64]0
    foreach($target in $targets){
        $item=Get-PhaseOneItem $target.Active
        $inventory=@(if($null -eq $item){@()}else{@(Get-PhaseOnePathInventory $target.Active)})
        $totalNodes += $inventory.Count
        foreach($node in $inventory){if([string]$node.kind -eq "file"){$totalBytes += [int64]$node.length}}
        if($totalNodes -gt 16384 -or $totalBytes -gt 1073741824){Fail "Phase-one active state inventory exceeds its bound"}
        $entries += [pscustomobject][ordered]@{key=$target.Key;target=$target.Active;existed=($null -ne $item);inventory=$inventory}
    }
    $rootRecords=@(
        Get-PhaseOneRootState -Key "data" -Path $Plan.DataDir -Python $Plan.BasePython
        Get-PhaseOneRootState -Key "openclaw" -Path $Plan.OpenClawHome -Python $Plan.BasePython
    )
    $roots=@($rootRecords|ForEach-Object{[pscustomobject][ordered]@{
        key=$_.Key;target=$_.Active;existed=[bool]$_.Existed;attributes=[int64]$_.Attributes
        sddl=$_.Sddl;device=$_.Device;inode=$_.Inode
    }})
    $document=[ordered]@{schema_version=1;plan_id=$Plan.PlanId;entries=$entries;roots=$roots}
    $content=(ConvertTo-Json -InputObject $document -Depth 12 -Compress)+"`n"
    if((New-Object Text.UTF8Encoding($false)).GetByteCount($content) -gt 4194304){Fail "Phase-one active state manifest exceeds its size bound"}
    try{
        Write-PrivateUtf8File -Path $manifest -Content $content
        $digest=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
        $snapshot=Read-PhaseOneActiveStateSnapshot -StateRoot $Plan.StateRoot -ExpectedDigest $digest -PlanId $Plan.PlanId -DataDir $Plan.DataDir -OpenClawHome $Plan.OpenClawHome -ConfigPath $Plan.ConfigPath
        foreach($entry in $snapshot.Entries){if(-not(Test-PhaseOneEntryMatches -Path $entry.Active -Entry $entry)){Fail "Phase-one state changed while its active inventory was sealed: $($entry.Active)"}}
        foreach($root in $snapshot.Roots){if(-not(Test-PhaseOneRootMatches -Expected $root -Python $Plan.BasePython)){Fail "Phase-one managed root changed while its active inventory was sealed: $($root.Active)"}}
        return $snapshot
    }catch{
        if($null -ne (Get-PhaseOneItem $manifest)){try{Set-PrivateFileAcl $manifest;Remove-Item -LiteralPath $manifest -Force -ErrorAction Stop}catch{Warn "Unsealed phase-one active manifest remains in private custody: $manifest"}}
        throw
    }
}
function Read-PhaseOneActiveStateSnapshot {
    param([string]$StateRoot,[string]$ExpectedDigest,[string]$PlanId,[string]$DataDir,[string]$OpenClawHome,[string]$ConfigPath)
    $manifest=Join-Path $StateRoot "active-manifest.json";Assert-PrivateFileAcl $manifest
    $manifestItem=Get-Item -LiteralPath $manifest -Force
    if($manifestItem.Length -le 0 -or $manifestItem.Length -gt 4194304){Fail "Phase-one active state manifest has invalid size"}
    if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()-ne $ExpectedDigest){Fail "Phase-one active state manifest digest changed"}
    try{$raw=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one active state manifest is invalid JSON"}
    Assert-ExactJsonKeys $raw @("schema_version","plan_id","entries","roots") "Phase-one active state manifest"
    if(-not(Test-Integer $raw.schema_version) -or [int64]$raw.schema_version -ne 1 -or [string]$raw.plan_id -ne $PlanId){Fail "Unsupported phase-one active state manifest"}
    $expectedTargets=@(Get-PhaseOneStateTargets -DataDir $DataDir -OpenClawHome $OpenClawHome -ConfigPath $ConfigPath)
    $entries=@($raw.entries);$parsed=@();$totalNodes=[int64]0;$totalBytes=[int64]0
    if($entries.Count -ne $expectedTargets.Count){Fail "Phase-one active state target count changed"}
    for($entryIndex=0;$entryIndex -lt $entries.Count;$entryIndex++){
        $entry=$entries[$entryIndex];$expected=$expectedTargets[$entryIndex]
        Assert-ExactJsonKeys $entry @("key","target","existed","inventory") "Phase-one active state entry"
        if([string]$entry.key -ne $expected.Key -or -not ([IO.Path]::GetFullPath([string]$entry.target)).Equals($expected.Active,[StringComparison]::OrdinalIgnoreCase) -or $entry.existed -isnot [bool]){Fail "Phase-one active state target set changed"}
        $nodes=@($entry.inventory);$seen=@{}
        if(-not [bool]$entry.existed -and $nodes.Count -ne 0){Fail "Absent phase-one active state has an inventory"}
        if([bool]$entry.existed -and ($nodes.Count -eq 0 -or [string]$nodes[0].relative -ne ".")){Fail "Existing phase-one active state lacks a root inventory entry"}
        foreach($node in $nodes){
            $totalNodes++;if($totalNodes -gt 16384){Fail "Phase-one active state manifest exceeds its total entry bound"}
            Assert-ExactJsonKeys $node @("relative","kind","attributes","sddl","length","sha256","blob","link_type","link_target","link_is_directory") "Phase-one active inventory node"
            $relative=[string]$node.relative;[void](Resolve-PhaseOneInventoryPath -Root $expected.Active -Relative $relative)
            if($seen.ContainsKey($relative)){Fail "Phase-one active inventory contains duplicate paths"};$seen[$relative]=$true
            if(-not(Test-Integer $node.attributes) -or -not(Test-Integer $node.length) -or $node.link_is_directory -isnot [bool] -or [string]$node.blob){Fail "Phase-one active inventory metadata type is invalid"}
            $kind=[string]$node.kind;$isReparse=([int64]$node.attributes -band [int64][IO.FileAttributes]::ReparsePoint) -ne 0
            if(($kind -in @("symboliclink","junction")) -ne $isReparse){Fail "Phase-one active inventory reparse metadata is inconsistent"}
            if($kind -in @("file","directory")){
                if(-not [string]$node.sddl){Fail "Phase-one active real state lacks owner/DACL metadata"}
                try{if($kind -eq "file"){[void](New-FileAclFromSddl ([string]$node.sddl))}else{[void](New-DirectoryAclFromSddl ([string]$node.sddl))}}catch{Fail "Phase-one active owner/DACL metadata is invalid"}
            }
            if($kind -eq "file"){
                if([string]$node.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64]$node.length -lt 0 -or [string]$node.link_type -or [string]$node.link_target -or [bool]$node.link_is_directory){Fail "Phase-one active file inventory is invalid"}
                $totalBytes += [int64]$node.length;if($totalBytes -gt 1073741824){Fail "Phase-one active state manifest exceeds its total byte bound"}
            }elseif($kind -eq "directory"){
                if([string]$node.sha256 -or [int64]$node.length -ne 0 -or [string]$node.link_type -or [string]$node.link_target -or [bool]$node.link_is_directory){Fail "Phase-one active directory inventory is invalid"}
            }elseif($kind -in @("symboliclink","junction")){
                if([string]$node.sddl -or [string]$node.sha256 -or [int64]$node.length -ne 0 -or [string]::IsNullOrWhiteSpace([string]$node.link_target)){Fail "Phase-one active reparse inventory is invalid"}
                if(($kind -eq "symboliclink" -and [string]$node.link_type -ne "SymbolicLink") -or ($kind -eq "junction" -and [string]$node.link_type -ne "Junction") -or ($kind -eq "junction" -and -not [bool]$node.link_is_directory)){Fail "Phase-one active reparse kind changed"}
            }else{Fail "Phase-one active inventory kind is unsupported"}
            if($relative -ne "."){$slash=$relative.LastIndexOf('/');$parent=if($slash -lt 0){"."}else{$relative.Substring(0,$slash)};if(-not $seen.ContainsKey($parent)){Fail "Phase-one active inventory parent ordering is invalid"}}
        }
        $parsed += [pscustomobject]@{Key=$expected.Key;Active=$expected.Active;Existed=[bool]$entry.existed;Inventory=$nodes}
    }
    $roots=@($raw.roots);$parsedRoots=@();$expectedRoots=@([IO.Path]::GetFullPath($DataDir),[IO.Path]::GetFullPath($OpenClawHome))
    if($roots.Count -ne 2){Fail "Phase-one active root metadata count changed"}
    for($index=0;$index -lt 2;$index++){
        $root=$roots[$index];Assert-ExactJsonKeys $root @("key","target","existed","attributes","sddl","device","inode") "Phase-one active root metadata"
        if([string]$root.key -ne @("data","openclaw")[$index] -or -not ([IO.Path]::GetFullPath([string]$root.target)).Equals($expectedRoots[$index],[StringComparison]::OrdinalIgnoreCase) -or $root.existed -isnot [bool] -or -not(Test-Integer $root.attributes)){Fail "Phase-one active root metadata is invalid"}
        if([bool]$root.existed){
            try{[void](New-DirectoryAclFromSddl ([string]$root.sddl))}catch{Fail "Phase-one active root owner/DACL is invalid"}
            if([string]$root.device -notmatch '^\d+$' -or [string]$root.inode -notmatch '^\d+$'){Fail "Phase-one active root identity is invalid"}
        }elseif([string]$root.sddl -or [int64]$root.attributes -ne 0 -or [string]$root.device -or [string]$root.inode){Fail "Absent phase-one active root has unexpected metadata"}
        $parsedRoots += [pscustomobject]@{Key=[string]$root.key;Active=$expectedRoots[$index];Existed=[bool]$root.existed;Attributes=[int64]$root.attributes;Sddl=[string]$root.sddl;Device=[string]$root.device;Inode=[string]$root.inode}
    }
    return [pscustomobject]@{Manifest=$manifest;ManifestSha256=$ExpectedDigest;Entries=$parsed;Roots=$parsedRoots}
}
function Restore-PhaseOneReparsePoint {
    param([string]$Path,[object]$Node)
    $kind=[string]$Node.kind;$target=[string]$Node.link_target
    if($kind -eq "junction"){
        [void](New-Item -ItemType Junction -Path $Path -Target $target -ErrorAction Stop)
    }elseif($PSVersionTable.PSEdition -eq "Core"){
        if([bool]$Node.link_is_directory){[void][IO.Directory]::CreateSymbolicLink($Path,$target)}else{[void][IO.File]::CreateSymbolicLink($Path,$target)}
    }else{
        [void](New-Item -ItemType SymbolicLink -Path $Path -Target $target -ErrorAction Stop)
    }
    $item=Get-PhaseOneItem $Path
    if($null -eq $item -or -not($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one reparse point was not restored"}
}
function Get-PhaseOneStateQuarantinePath {
    param([object]$Entry,[string]$PlanId,[int]$Index)
    if($PlanId -notmatch '^phase-one-[0-9a-f]{32}$'){Fail "Phase-one state quarantine has an invalid plan identity"}
    $token=$PlanId.Substring("phase-one-".Length);$parent=Split-Path -Parent $Entry.Active;$name=Split-Path -Leaf $Entry.Active
    return Join-Path $parent ("."+$name+".phase-one-quarantine-"+$token+("-{0:D2}" -f $Index))
}
function Get-PhaseOneStateRestoreCandidatePath {
    param([object]$Entry,[string]$PlanId,[int]$Index)
    if($PlanId -notmatch '^phase-one-[0-9a-f]{32}$'){Fail "Phase-one state restore candidate has an invalid plan identity"}
    $token=$PlanId.Substring("phase-one-".Length);$parent=Split-Path -Parent $Entry.Active;$name=Split-Path -Leaf $Entry.Active
    return Join-Path $parent ("."+$name+".phase-one-restore-"+$token+("-{0:D2}" -f $Index))
}
function Move-PhaseOnePathNoReplace {
    param([string]$Source,[string]$Destination)
    $sourceItem=Get-PhaseOneItem $Source
    if($null -eq $sourceItem){Fail "Phase-one no-replace source is missing: $Source"}
    if($null -ne (Get-PhaseOneItem $Destination)){Fail "Phase-one no-replace destination appeared concurrently: $Destination"}
    try{
        if($sourceItem.PSIsContainer){[IO.Directory]::Move($Source,$Destination)}else{[IO.File]::Move($Source,$Destination)}
    }catch{Fail "Phase-one no-replace move failed without overwriting its destination: $Destination. $($_.Exception.Message)"}
    if($null -ne (Get-PhaseOneItem $Source) -or $null -eq (Get-PhaseOneItem $Destination)){Fail "Phase-one no-replace move did not commit exactly once: $Destination"}
}
function Assert-PhaseOneStateRollbackCas {
    param([object]$Snapshot,[object]$ActiveSnapshot,[string]$PlanId,[string]$Python)
    $expected=if($null -ne $ActiveSnapshot){$ActiveSnapshot}else{$Snapshot}
    if(@($expected.Entries).Count -ne @($Snapshot.Entries).Count){Fail "Phase-one active/source state target counts differ"}
    foreach($root in @($expected.Roots)){
        if(-not(Test-PhaseOneRootMatches -Expected $root -Python $Python)){Fail "Phase-one state root diverged after migration; preserved without overwrite: $($root.Active)"}
    }
    for($index=0;$index -lt @($Snapshot.Entries).Count;$index++){
        $sourceEntry=$Snapshot.Entries[$index];$activeEntry=$expected.Entries[$index]
        if(-not ([IO.Path]::GetFullPath([string]$sourceEntry.Active)).Equals([IO.Path]::GetFullPath([string]$activeEntry.Active),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one active/source state target order differs"}
        $quarantine=Get-PhaseOneStateQuarantinePath -Entry $sourceEntry -PlanId $PlanId -Index $index
        if($null -ne (Get-PhaseOneItem $quarantine)){
            if(-not(Test-PhaseOneEntryMatches -Path $quarantine -Entry $activeEntry)){Fail "Phase-one state quarantine diverged; preserved for inspection: $quarantine"}
            if($null -ne (Get-PhaseOneItem $sourceEntry.Active) -and -not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $sourceEntry)){Fail "Phase-one state target reappeared during rollback; preserved without overwrite: $($sourceEntry.Active)"}
            continue
        }
        if(-not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $activeEntry) -and -not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $sourceEntry)){
            Fail "Phase-one state diverged after migration; preserved without overwrite: $($sourceEntry.Active)"
        }
    }
}
function New-PhaseOneStateRestoreCandidate {
    param([object]$Entry,[string]$StateRoot,[string]$Candidate)
    if(-not [bool]$Entry.Existed){Fail "Cannot construct a restore candidate for absent source state"}
    if($null -ne (Get-PhaseOneItem $Candidate)){
        if(Test-PhaseOneEntryMatches -Path $Candidate -Entry $Entry){return}
        Fail "Phase-one restore candidate diverged; preserved for inspection: $Candidate"
    }
    $parent=Split-Path -Parent $Candidate;$parentItem=Get-PhaseOneItem $parent
    if($null -eq $parentItem -or -not $parentItem.PSIsContainer -or ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one restore candidate parent is unsafe"}
    $nodes=@($Entry.Inventory|Sort-Object @{Expression={if([string]$_.relative -eq "."){0}else{@(([string]$_.relative).Split('/')).Count}}},relative)
    foreach($node in @($nodes|Where-Object{$_.kind -eq "directory"})){
        $destination=Resolve-PhaseOneInventoryPath -Root $Candidate -Relative ([string]$node.relative)
        [void](New-PrivateDirectory $destination)
    }
    foreach($node in @($nodes|Where-Object{$_.kind -eq "file"})){
        $destination=Resolve-PhaseOneInventoryPath -Root $Candidate -Relative ([string]$node.relative)
        $fileParent=Split-Path -Parent $destination;$fileParentItem=Get-PhaseOneItem $fileParent
        if($null -eq $fileParentItem -or -not $fileParentItem.PSIsContainer -or ($fileParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one file restore candidate parent is unsafe"}
        Write-SecuredRestoreCandidate -Source (Join-Path $StateRoot ([string]$node.blob)) -Destination $destination -FinalSddl ([string]$node.sddl)
        [IO.File]::SetAttributes($destination,[IO.FileAttributes][int64]$node.attributes)
    }
    foreach($node in @($nodes|Where-Object{$_.kind -in @("symboliclink","junction")})){
        $destination=Resolve-PhaseOneInventoryPath -Root $Candidate -Relative ([string]$node.relative)
        $linkParent=Split-Path -Parent $destination;$linkParentItem=Get-PhaseOneItem $linkParent
        if($null -eq $linkParentItem -or -not $linkParentItem.PSIsContainer -or ($linkParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one reparse restore candidate parent is unsafe"}
        Restore-PhaseOneReparsePoint -Path $destination -Node $node
    }
    $directories=@($Entry.Inventory|Where-Object{$_.kind -eq "directory"}|Sort-Object @{Expression={if([string]$_.relative -eq "."){0}else{@(([string]$_.relative).Split('/')).Count}}} -Descending)
    foreach($node in $directories){
        $destination=Resolve-PhaseOneInventoryPath -Root $Candidate -Relative ([string]$node.relative)
        $security=New-DirectoryAclFromSddl ([string]$node.sddl);Set-Acl -LiteralPath $destination -AclObject $security
        if((Get-OwnerDaclSddl $destination)-ne [string]$node.sddl){Fail "Phase-one restore candidate directory owner/DACL mismatch"}
        [IO.File]::SetAttributes($destination,[IO.FileAttributes][int64]$node.attributes)
    }
    if(-not(Test-PhaseOneEntryMatches -Path $Candidate -Entry $Entry)){Fail "Phase-one restore candidate does not match exact source custody: $Candidate"}
}
function Restore-PhaseOneStateSnapshot {
    param([object]$Snapshot,[object]$ActiveSnapshot,[string]$StateRoot,[string]$PlanId,[string]$Python)
    Assert-PhaseOneStateRollbackCas -Snapshot $Snapshot -ActiveSnapshot $ActiveSnapshot -PlanId $PlanId -Python $Python
    $expected=if($null -ne $ActiveSnapshot){$ActiveSnapshot}else{$Snapshot}
    for($index=0;$index -lt @($Snapshot.Entries).Count;$index++){
        $sourceEntry=$Snapshot.Entries[$index];$activeEntry=$expected.Entries[$index]
        $quarantine=Get-PhaseOneStateQuarantinePath -Entry $sourceEntry -PlanId $PlanId -Index $index
        if($null -eq (Get-PhaseOneItem $quarantine) -and (Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $activeEntry) -and -not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $sourceEntry)){
            Move-PhaseOnePathNoReplace -Source $sourceEntry.Active -Destination $quarantine
            if(-not(Test-PhaseOneEntryMatches -Path $quarantine -Entry $activeEntry)){Fail "Phase-one state changed while entering quarantine: $($sourceEntry.Active)"}
        }
        if($null -ne (Get-PhaseOneItem $sourceEntry.Active) -and -not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $sourceEntry)){Fail "Phase-one state target appeared during rollback; preserved without overwrite: $($sourceEntry.Active)"}
    }
    $restoredEntries=0
    for($index=0;$index -lt @($Snapshot.Entries).Count;$index++){
        $entry=$Snapshot.Entries[$index]
        if([bool]$entry.Existed -and $null -eq (Get-PhaseOneItem $entry.Active)){
            $candidate=Get-PhaseOneStateRestoreCandidatePath -Entry $entry -PlanId $PlanId -Index $index
            New-PhaseOneStateRestoreCandidate -Entry $entry -StateRoot $StateRoot -Candidate $candidate
            Move-PhaseOnePathNoReplace -Source $candidate -Destination $entry.Active
        }
        if(-not(Test-PhaseOneEntryMatches -Path $entry.Active -Entry $entry)){Fail "Restored phase-one state does not match its exact inventory: $($entry.Active)"}
        $restoredEntries++
        if($script:RecoveringPhaseOneJournal -and $InjectPhaseOneCrashDuringRecovery -and $restoredEntries -eq 1){Invoke-TestHardCrash "mid phase-one journal recovery"}
    }
    for($index=0;$index -lt @($Snapshot.Entries).Count;$index++){
        $sourceEntry=$Snapshot.Entries[$index];$activeEntry=$expected.Entries[$index]
        $quarantine=Get-PhaseOneStateQuarantinePath -Entry $sourceEntry -PlanId $PlanId -Index $index
        if($null -eq (Get-PhaseOneItem $quarantine)){continue}
        if(-not(Test-PhaseOneEntryMatches -Path $sourceEntry.Active -Entry $sourceEntry) -or -not(Test-PhaseOneEntryMatches -Path $quarantine -Entry $activeEntry)){Fail "Phase-one state changed before quarantine cleanup: $($sourceEntry.Active)"}
        Remove-PhaseOneManagedPath $quarantine
    }
    foreach($root in @($Snapshot.Roots|Sort-Object @{Expression={if($_.Key -eq "openclaw"){0}else{1}}})){
        $item=Get-PhaseOneItem $root.Active
        if([bool]$root.Existed){
            if($null -eq $item -or -not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one managed root was not restored as a real directory"}
            $security=New-DirectoryAclFromSddl $root.Sddl;Set-Acl -LiteralPath $root.Active -AclObject $security
            if((Get-OwnerDaclSddl $root.Active)-ne $root.Sddl){Fail "Restored phase-one root owner/DACL mismatch"}
            [IO.File]::SetAttributes($root.Active,[IO.FileAttributes]$root.Attributes)
        }elseif($null -ne $item){
            if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @(Get-ChildItem -LiteralPath $root.Active -Force).Count -ne 0){Fail "Bridge-created managed root diverged; preserved without overwrite: $($root.Active)"}
            Remove-PhaseOneManagedPath $root.Active
        }
    }
}
function Publish-PhaseOneSnapshot {
    param([object]$Snapshot)
    Remove-PhaseOneQuarantines $Snapshot
    if(-not $Snapshot.Existed){
        if(-not(Test-Path -LiteralPath $Snapshot.Active)){return}
        Assert-RealFile $Snapshot.Active "Rollback-created state"
        Set-PrivateFileAcl $Snapshot.Active
        $createdParent=Split-Path -Parent $Snapshot.Active;$createdName=Split-Path -Leaf $Snapshot.Active
        $createdQuarantine=Join-Path $createdParent ("."+$createdName+".phase-one-created-"+[guid]::NewGuid().ToString("N"))
        [IO.File]::Move($Snapshot.Active,$createdQuarantine)
        if(Test-Path -LiteralPath $Snapshot.Active){Fail "Rollback-created state was not removed"}
        try{Remove-Item -LiteralPath $createdQuarantine -Force -ErrorAction Stop}catch{Warn "Kept private rollback quarantine: $createdQuarantine"}
        Remove-PhaseOneQuarantines $Snapshot
        return
    }
    if(-not(Test-Path -LiteralPath $Snapshot.Backup -PathType Leaf)){Fail "Rollback backup is missing"}
    if((Get-FileHash -LiteralPath $Snapshot.Backup -Algorithm SHA256).Hash.ToLowerInvariant()-ne $Snapshot.Sha256){Fail "Rollback backup changed"}
    $parent=Split-Path -Parent $Snapshot.Active;$name=Split-Path -Leaf $Snapshot.Active
    $candidate=Join-Path $parent ("."+$name+".phase-one-restore-"+[guid]::NewGuid().ToString("N"))
    # Both rename endpoints must stay on the target volume. WorkRoot may be on
    # a redirected TEMP volume, where File.Move cannot provide this swap.
    $displaced=Join-Path $parent ("."+$name+".phase-one-displaced-"+[guid]::NewGuid().ToString("N"))
    Write-SecuredRestoreCandidate -Source $Snapshot.Backup -Destination $candidate -FinalSddl $Snapshot.Sddl
    $hadActive=Test-Path -LiteralPath $Snapshot.Active
    $activeSha=""
    if($hadActive){
        Assert-RealFile $Snapshot.Active "Rollback target"
        $activeSha=(Get-FileHash -LiteralPath $Snapshot.Active -Algorithm SHA256).Hash.ToLowerInvariant()
        $allowedProperty=Property $Snapshot "AllowedActiveSha256"
        if($allowedProperty){
            if(@($allowedProperty.Value)-notcontains $activeSha){
                Fail "Refusing to displace an unrecognized phase-one activation at $($Snapshot.Active)"
            }
        }
        [IO.File]::Move($Snapshot.Active,$displaced)
        if((Get-FileHash -LiteralPath $displaced -Algorithm SHA256).Hash.ToLowerInvariant()-ne $activeSha){
            if(-not(Test-Path -LiteralPath $Snapshot.Active)){[IO.File]::Move($displaced,$Snapshot.Active)}
            Fail "Phase-one activation changed while it was quarantined."
        }
    }
    try{[IO.File]::Move($candidate,$Snapshot.Active)}catch{if($hadActive -and -not(Test-Path -LiteralPath $Snapshot.Active) -and (Test-Path -LiteralPath $displaced)){[IO.File]::Move($displaced,$Snapshot.Active)};throw}
    if((Get-FileHash -LiteralPath $Snapshot.Active -Algorithm SHA256).Hash.ToLowerInvariant()-ne $Snapshot.Sha256 -or (Get-OwnerDaclSddl $Snapshot.Active)-ne $Snapshot.Sddl){Fail "Restored phase-one bytes or owner/DACL mismatch: $($Snapshot.Active)"}
    if(Test-Path -LiteralPath $displaced){
        if((Get-FileHash -LiteralPath $displaced -Algorithm SHA256).Hash.ToLowerInvariant()-ne $activeSha){Fail "Phase-one activation quarantine changed before cleanup."}
        Set-PrivateFileAcl $displaced
        try{Remove-Item -LiteralPath $displaced -Force -ErrorAction Stop}catch{Warn "Kept private rollback quarantine: $displaced"}
    }
    Remove-PhaseOneQuarantines $Snapshot
}
function Get-PhaseOneGatewayPidRecord {
    param([string]$DataDir)
    if(-not $DataDir){$DataDir=Get-Home}
    $path=Join-Path ([IO.Path]::GetFullPath($DataDir)) "gateway.pid"
    $item=Get-PhaseOneItem $path
    if($null -eq $item){return [pscustomobject]@{Exists=$false;Path=$path;Pid=0;Sha256=""}}
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 4096){Fail "Gateway PID custody is unsafe"}
    $sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $raw=(Get-Content -LiteralPath $path -Raw -Encoding UTF8).Trim()
    $pidValue=$null
    if($raw -match '^[1-9]\d*$'){
        $pidValue=$raw
    }else{
        try{$payload=$raw|ConvertFrom-Json}catch{Fail "Gateway PID custody is malformed"}
        $pidProperty=Property $payload "pid"
        if(-not $pidProperty -or -not(Test-Integer $pidProperty.Value)) {Fail "Gateway PID custody is malformed"}
        $pidValue=$pidProperty.Value
    }
    try{$processId=[int]$pidValue}catch{Fail "Gateway PID custody is outside the supported process range"}
    if($processId -le 0){Fail "Gateway PID custody is outside the supported process range"}
    return [pscustomobject]@{Exists=$true;Path=$path;Pid=$processId;Sha256=$sha256}
}
function Get-PhaseOneGatewayProcesses {
    param([string]$Gateway)
    $expected=[IO.Path]::GetFullPath($Gateway);$gatewayProcesses=@()
    foreach($process in @(Get-Process -ErrorAction Stop)){
        try{$candidate=[string]$process.Path}catch{continue}
        if($candidate -and ([IO.Path]::GetFullPath($candidate)).Equals($expected,[StringComparison]::OrdinalIgnoreCase)){$gatewayProcesses += $process}
    }
    return @($gatewayProcesses)
}
function Assert-PhaseOnePidRecordUnchanged {
    param([object]$Before,[object]$After)
    if([bool]$Before.Exists -ne [bool]$After.Exists -or [int]$Before.Pid -ne [int]$After.Pid -or [string]$Before.Sha256 -ne [string]$After.Sha256){Fail "Gateway PID custody changed during a read-only state probe"}
}
function Get-PhaseOneSourceRunningState {
    param([string]$Gateway,[string]$ControllerHome,[string]$DataDir,[string]$ConfigPath,[string]$ExpectedVersion)
    if(-not $DataDir){$DataDir=Get-Home};if(-not $ConfigPath){$ConfigPath=if($env:DEFENSECLAW_CONFIG){$env:DEFENSECLAW_CONFIG}else{Join-Path $DataDir "config.yaml"}}
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process");$savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=[IO.Path]::GetFullPath($DataDir);$env:DEFENSECLAW_CONFIG=[IO.Path]::GetFullPath($ConfigPath)
        $before=Get-PhaseOneGatewayPidRecord -DataDir $DataDir
        $processesBefore=@(Get-PhaseOneGatewayProcesses $Gateway)
        & $Gateway status *> $null;$statusResponding=$LASTEXITCODE -eq 0
        $after=Get-PhaseOneGatewayPidRecord -DataDir $DataDir
        $processesAfter=@(Get-PhaseOneGatewayProcesses $Gateway)
        Assert-PhaseOnePidRecordUnchanged -Before $before -After $after
        $beforeIds=@($processesBefore|ForEach-Object{[int]$_.Id}|Sort-Object)
        $afterIds=@($processesAfter|ForEach-Object{[int]$_.Id}|Sort-Object)
        if(($beforeIds -join ',') -ne ($afterIds -join ',')){Fail "Gateway process state changed during the pre-stop probe"}
        if(-not $after.Exists){
            if($statusResponding -or $processesAfter.Count -ne 0){Fail "Gateway is live without verifiable PID custody before phase-one stop"}
            return $false
        }
        $recordedProcess=Get-Process -Id $after.Pid -ErrorAction SilentlyContinue
        if($null -eq $recordedProcess){
            if($statusResponding -or $processesAfter.Count -ne 0){Fail "Gateway process and PID custody are inconsistent before phase-one stop"}
            return $false
        }
        try{$recordedPath=[IO.Path]::GetFullPath([string]$recordedProcess.Path)}catch{Fail "Gateway PID custody cannot be bound to its managed executable"}
        if(-not $recordedPath.Equals([IO.Path]::GetFullPath($Gateway),[StringComparison]::OrdinalIgnoreCase)){Fail "Gateway PID custody points at an unexpected live process"}
        if(-not(Test-VersionBoundGatewayHealth -ControllerHome $ControllerHome -DataDir $DataDir -ConfigPath $ConfigPath -ExpectedVersion $ExpectedVersion -TimeoutSeconds $HealthTimeout)){Fail "The live source gateway is not healthy enough for an exact phase-one rollback"}
        return $true
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
}
function Assert-PhaseOneGatewayStopped {
    param([string]$Gateway,[string]$DataDir,[string]$ConfigPath)
    if(-not $DataDir){$DataDir=Get-Home};if(-not $ConfigPath){$ConfigPath=if($env:DEFENSECLAW_CONFIG){$env:DEFENSECLAW_CONFIG}else{Join-Path $DataDir "config.yaml"}}
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process");$savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=[IO.Path]::GetFullPath($DataDir);$env:DEFENSECLAW_CONFIG=[IO.Path]::GetFullPath($ConfigPath)
        $before=Get-PhaseOneGatewayPidRecord -DataDir $DataDir
        $processesBefore=@(Get-PhaseOneGatewayProcesses $Gateway)
        & $Gateway status *> $null;$statusHealthy=$LASTEXITCODE -eq 0
        $after=Get-PhaseOneGatewayPidRecord -DataDir $DataDir
        $processesAfter=@(Get-PhaseOneGatewayProcesses $Gateway)
        Assert-PhaseOnePidRecordUnchanged -Before $before -After $after
        if($statusHealthy -or $processesBefore.Count -ne 0 -or $processesAfter.Count -ne 0){Fail "Gateway remains live after phase-one stop"}
        if($after.Exists -and (Get-Process -Id $after.Pid -ErrorAction SilentlyContinue)){Fail "Gateway PID custody remains live after phase-one stop"}
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
}
function Get-PhaseOneVenvIdentity {
    param([string]$Path)
    $root=Get-Item -LiteralPath $Path -Force
    if(-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one venv identity root must be a real directory."}
    $entries=@(Get-ChildItem -LiteralPath $Path -Force -Recurse|Sort-Object FullName)
    if($entries.Count -gt 65536){Fail "Phase-one venv identity exceeds its entry bound."}
    $prefix=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\'
    $total=[int64]0
    $builder=New-Object Text.StringBuilder
    [void]$builder.Append("root|").Append([int64]$root.Attributes).Append("`n")
    foreach($entry in $entries){
        if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "Phase-one venv identity contains a reparse point: $($entry.FullName)"}
        $full=[IO.Path]::GetFullPath($entry.FullName)
        if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one venv identity escaped its root."}
        $relative=$full.Substring($prefix.Length).Replace('\','/')
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($relative))
        if($entry.PSIsContainer){
            [void]$builder.Append("d|").Append($encoded).Append('|').Append([int64]$entry.Attributes).Append("`n")
        }else{
            Assert-RealFile $entry.FullName "Phase-one venv member"
            $total+=[int64]$entry.Length
            if($total -gt 4294967296){Fail "Phase-one venv identity exceeds its byte bound."}
            $digest=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            [void]$builder.Append("f|").Append($encoded).Append('|').Append([int64]$entry.Attributes).Append('|').Append([int64]$entry.Length).Append('|').Append($digest).Append("`n")
        }
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($builder.ToString()))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Get-PhaseOneDirectoryIdentity {
    param([string]$Path,[string]$Python)
    $identity=@'
import json
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
info = os.lstat(path)
if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or not stat.S_ISDIR(info.st_mode):
    raise RuntimeError("phase-one identity root is unsafe")
print(json.dumps({"device": str(info.st_dev), "inode": str(info.st_ino)}, separators=(",", ":")))
'@
    $output=@(& $Python -I -c $identity $Path 2>&1)
    if($LASTEXITCODE -ne 0 -or $output.Count -ne 1){Fail "Could not bind phase-one directory identity for $Path; no installed state changed. $($output -join ' ')"}
    try{$resolved=[string]$output[0]|ConvertFrom-Json}catch{Fail "Phase-one directory identity is invalid for $Path."}
    Assert-ExactJsonKeys $resolved @("device","inode") "Phase-one directory identity"
    if([string]$resolved.device -notmatch '^\d+$' -or [string]$resolved.inode -notmatch '^\d+$'){Fail "Phase-one directory identity is invalid for $Path."}
    return [pscustomobject][ordered]@{device=[string]$resolved.device;inode=[string]$resolved.inode}
}
function Get-PhaseOneOpenClawIdentity {
    param([string]$Path,[string]$Python)
    $full=[IO.Path]::GetFullPath($Path);$parent=Split-Path -Parent $full
    $parentIdentity=Get-PhaseOneDirectoryIdentity -Path $parent -Python $Python
    $item=Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if($null -eq $item){return [pscustomobject][ordered]@{existed=$false;device="";inode="";parent_device=$parentIdentity.device;parent_inode=$parentIdentity.inode}}
    $identity=Get-PhaseOneDirectoryIdentity -Path $full -Python $Python
    return [pscustomobject][ordered]@{existed=$true;device=$identity.device;inode=$identity.inode;parent_device=$parentIdentity.device;parent_inode=$parentIdentity.inode}
}
function New-PhaseOnePathIdentities {
    param([string]$ControllerHome,[string]$DataDir,[string]$ConfigPath,[string]$OpenClawHome,[string]$Python)
    return [pscustomobject][ordered]@{
        controller_home=(Get-PhaseOneDirectoryIdentity -Path $ControllerHome -Python $Python)
        data_dir=(Get-PhaseOneDirectoryIdentity -Path $DataDir -Python $Python)
        openclaw_home=(Get-PhaseOneOpenClawIdentity -Path $OpenClawHome -Python $Python)
        config_parent=(Get-PhaseOneDirectoryIdentity -Path (Split-Path -Parent $ConfigPath) -Python $Python)
    }
}
function Assert-PhaseOnePathIdentities {
    param([object]$Identities,[string]$ControllerHome,[string]$DataDir,[string]$ConfigPath,[string]$OpenClawHome,[string]$Python,[switch]$AllowCreatedOpenClaw)
    Assert-ExactJsonKeys $Identities @("controller_home","data_dir","openclaw_home","config_parent") "Phase-one path identities"
    $paths=[ordered]@{controller_home=$ControllerHome;data_dir=$DataDir;config_parent=(Split-Path -Parent $ConfigPath)}
    foreach($name in $paths.Keys){
        $recorded=Property $Identities $name
        if(-not $recorded){Fail "Phase-one path identity set lacks $name."}
        Assert-ExactJsonKeys $recorded.Value @("device","inode") "Phase-one $name identity"
        $current=Get-PhaseOneDirectoryIdentity -Path ([string]$paths[$name]) -Python $Python
        if([string]$recorded.Value.device -ne [string]$current.device -or [string]$recorded.Value.inode -ne [string]$current.inode){Fail "Phase-one $name identity changed before recovery; journal custody remains intact."}
    }
    $openProperty=Property $Identities "openclaw_home"
    if(-not $openProperty){Fail "Phase-one path identity set lacks openclaw_home."}
    $recordedOpen=$openProperty.Value
    Assert-ExactJsonKeys $recordedOpen @("existed","device","inode","parent_device","parent_inode") "Phase-one OpenClaw identity"
    if($recordedOpen.existed -isnot [bool] -or [string]$recordedOpen.parent_device -notmatch '^\d+$' -or [string]$recordedOpen.parent_inode -notmatch '^\d+$'){Fail "Phase-one OpenClaw identity is invalid."}
    if([bool]$recordedOpen.existed -and ([string]$recordedOpen.device -notmatch '^\d+$' -or [string]$recordedOpen.inode -notmatch '^\d+$')){Fail "Phase-one OpenClaw identity is invalid."}
    if(-not [bool]$recordedOpen.existed -and ([string]$recordedOpen.device -or [string]$recordedOpen.inode)){Fail "Absent phase-one OpenClaw identity unexpectedly binds a directory."}
    $currentOpen=Get-PhaseOneOpenClawIdentity -Path $OpenClawHome -Python $Python
    if([string]$recordedOpen.parent_device -ne [string]$currentOpen.parent_device -or [string]$recordedOpen.parent_inode -ne [string]$currentOpen.parent_inode){Fail "Phase-one OpenClaw parent identity changed; journal custody remains intact."}
    if([bool]$recordedOpen.existed){
        if(-not [bool]$currentOpen.existed -or [string]$recordedOpen.device -ne [string]$currentOpen.device -or [string]$recordedOpen.inode -ne [string]$currentOpen.inode){Fail "Phase-one OpenClaw home identity changed; journal custody remains intact."}
    }elseif([bool]$currentOpen.existed -and -not $AllowCreatedOpenClaw){Fail "Phase-one OpenClaw home appeared before an owned state mutation."}
}
function Get-PhaseOneMutatorLeasePath {
    param([string]$RecoveryRoot)
    return Join-Path $RecoveryRoot "phase-one-mutator.lease"
}
function Initialize-PhaseOneMutatorLease {
    param([string]$RecoveryRoot)
    $path=Get-PhaseOneMutatorLeasePath $RecoveryRoot
    if(Test-Path -LiteralPath $path){
        $stream=$null
        try{
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            Assert-PrivateFileAcl $path
        }catch [IO.IOException]{
            Fail "A surviving phase-one mutation child still holds the recovery lease; no installed state changed."
        }finally{if($stream){$stream.Dispose()}}
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    }
    Write-PrivateUtf8File -Path $path -Content "phase-one-mutator-lease-v1`n"
    Assert-PrivateFileAcl $path
    return $path
}
function Enter-PhaseOneMutatorLease {
    param([string]$RecoveryRoot)
    $path=Get-PhaseOneMutatorLeasePath $RecoveryRoot
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){Fail "Phase-one recovery journal lacks its private mutator lease."}
    $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max($HealthTimeout,1))
    while($true){
        try{
            $lease=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        }catch [IO.IOException]{
            if([DateTime]::UtcNow -ge $deadline){Fail "A phase-one mutation child is still active; recovery did not race it and the journal remains intact."}
            Start-Sleep -Milliseconds 100
            continue
        }
        try{Assert-PrivateFileAcl $path;return $lease}catch{$lease.Dispose();throw}
    }
}
function Invoke-PhaseOneLeasedCommand {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][string[]]$Command,
        [switch]$InheritLeaseHandle
    )
    if($Command.Count -eq 0){Fail "Phase-one leased command is empty."}
    Assert-PrivateFileAcl $Plan.MutatorLease
    Assert-RealFile $Plan.BasePython "Phase-one external lease controller"
    $leaseWrapper=@'
import ctypes
import os
import subprocess
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
create_file = kernel32.CreateFileW
create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
create_file.restype = ctypes.c_void_p
close_handle = kernel32.CloseHandle
close_handle.argtypes = [ctypes.c_void_p]
close_handle.restype = ctypes.c_int
invalid = ctypes.c_void_p(-1).value
deadline = time.monotonic() + max(float(sys.argv[2]), 1.0)
while True:
    handle = create_file(sys.argv[1], 0xC0000000 | 0x00020000, 0, None, 3, 0x00200000 | 0x80000000, None)
    if handle != invalid:
        break
    error = ctypes.get_last_error()
    if error not in (32, 33):
        raise ctypes.WinError(error)
    if time.monotonic() >= deadline:
        raise TimeoutError("phase-one mutator lease remained held")
    time.sleep(0.05)
inherit = sys.argv[3] == "inherit"
try:
    if inherit:
        os.set_handle_inheritable(handle, True)
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {"handle_list": [handle]}
        try:
            child = subprocess.Popen(sys.argv[4:], close_fds=True, startupinfo=startup)
        finally:
            os.set_handle_inheritable(handle, False)
    else:
        child = subprocess.Popen(sys.argv[4:])
    raise SystemExit(child.wait())
finally:
    close_handle(handle)
'@
    $mode=if($InheritLeaseHandle){"inherit"}else{"wrapper"}
    $output=@(& $Plan.BasePython -I -c $leaseWrapper $Plan.MutatorLease ([string]$HealthTimeout) $mode @Command 2>&1)
    return [pscustomobject]@{ExitCode=[int]$LASTEXITCODE;Output=$output}
}
function Sync-PhaseOneBridgeVenv {
    param([object]$Plan)
    Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv
    $sync=@'
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
root_info = root.lstat()
if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
    raise RuntimeError("phase-one bridge venv durability root is unsafe")
count = 0
total = 0
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    for name in directories:
        info = (Path(current) / name).lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("phase-one bridge venv contains an unsafe directory")
    for name in files:
        path = Path(current) / name
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("phase-one bridge venv contains an unsafe file")
        count += 1
        total += info.st_size
        if count > 65536 or total > 4294967296:
            raise RuntimeError("phase-one bridge venv exceeds its durability bound")
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
print(count)
'@
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.BasePython,"-I","-c",$sync,$Plan.ActiveVenv) -InheritLeaseHandle
    if($execution.ExitCode -ne 0){Fail "Could not durably flush the healthy bridge controller: $($execution.Output -join ' ')"}
    if($execution.Output.Count -ne 1 -or [string]$execution.Output[0] -notmatch '^\d+$'){Fail "Bridge controller durability flush returned an invalid contract."}
    Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv
}
function New-PhaseOneRollbackPlan {
    param([object]$SourceRelease,[string]$SourceVersion,[object]$Bridge)
    $uv=Get-Command uv -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not $uv){Fail "uv is required for bridge rollback; no installed state changed."}
    $recoveryRoot=Get-PhaseOneRecoveryRoot -Create
    $planId="phase-one-"+[guid]::NewGuid().ToString("N")
    $root=New-PrivateDirectory (Join-Path $recoveryRoot $planId)
    $mutatorLease=""
    try{
        $mutatorLease=Initialize-PhaseOneMutatorLease $recoveryRoot
        $state=New-PrivateDirectory (Join-Path $root "state")
        if($null -eq $script:RuntimePaths){Fail "Phase-one runtime paths were not resolved before rollback planning; no installed state changed."}
        $controllerHome=[IO.Path]::GetFullPath([string]$script:RuntimePaths.ControllerHome)
        $dataDir=[IO.Path]::GetFullPath([string]$script:RuntimePaths.DataDir)
        $configPath=[IO.Path]::GetFullPath([string]$script:RuntimePaths.ConfigPath)
        $openClawHome=[IO.Path]::GetFullPath([string]$script:RuntimePaths.OpenClawHome)
        $openClawExisted=[bool]$script:RuntimePaths.OpenClawExisted
        $configOverride=if([bool]$script:RuntimePaths.ConfigWasExplicit){$configPath}else{""}
        $activeVenv=Join-Path $controllerHome ".venv"
        $activeVenvItem=Get-Item -LiteralPath $activeVenv -Force
        if(-not $activeVenvItem.PSIsContainer -or ($activeVenvItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Installed source venv must be a real directory; no state changed."}
        $venvSddl=Get-OwnerDaclSddl $activeVenv
        $baseOutput=@(& (Get-Python) -I -c 'import os,sys; print(os.path.realpath(getattr(sys,"_base_executable","") or sys.executable))' 2>$null)
        if($LASTEXITCODE -ne 0 -or $baseOutput.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$baseOutput[0]) -or -not [IO.Path]::IsPathRooted([string]$baseOutput[0])){Fail "Could not resolve an external base Python for bridge activation; no state changed."}
        $basePython=[IO.Path]::GetFullPath([string]$baseOutput[0])
        Assert-RealFile $basePython "Bridge base Python"
        $venvPrefix=$activeVenv.TrimEnd('\')+'\'
        if($basePython.StartsWith($venvPrefix,[StringComparison]::OrdinalIgnoreCase)){Fail "Bridge base Python is inside the source venv; no state changed."}
        $pathIdentities=New-PhaseOnePathIdentities -ControllerHome $controllerHome -DataDir $dataDir -ConfigPath $configPath -OpenClawHome $openClawHome -Python $basePython

        $sourceWheelPath=Join-Path $SourceRelease.Directory $SourceRelease.Wheel
        Assert-RealFile $sourceWheelPath "Authenticated source wheel"
        $wheel=Join-Path $root "source.whl";Write-SecuredRestoreCandidate -Source $sourceWheelPath -Destination $wheel -FinalSddl (Get-PrivateFileSddl)
        $wheelSha=(Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash.ToLowerInvariant()
        $bridgeWheelPath=Join-Path $Bridge.Directory $Bridge.Wheel
        Assert-RealFile $bridgeWheelPath "Authenticated bridge wheel"
        $bridgeWheel=Join-Path $root "bridge.whl";Write-SecuredRestoreCandidate -Source $bridgeWheelPath -Destination $bridgeWheel -FinalSddl (Get-PrivateFileSddl)
        $bridgeWheelSha=(Get-FileHash -LiteralPath $bridgeWheel -Algorithm SHA256).Hash.ToLowerInvariant()
        $gateway=Get-Gateway;Assert-RealFile $gateway "Installed source gateway"
        $gatewayStage=New-PrivateDirectory (Join-Path $root "gateway")
        Expand-Archive -LiteralPath (Join-Path $SourceRelease.Directory $SourceRelease.Gateway) -DestinationPath $gatewayStage
        $candidates=@(Get-ChildItem -LiteralPath $gatewayStage -Filter "defenseclaw.exe" -File -Recurse)
        if($candidates.Count -ne 1){Fail "Authenticated source gateway archive is invalid"}
        $sourceGateway=Join-Path $root "source-gateway.exe";Write-SecuredRestoreCandidate -Source $candidates[0].FullName -Destination $sourceGateway -FinalSddl (Get-PrivateFileSddl)
        Remove-Item -LiteralPath $gatewayStage -Recurse -Force
        $gatewaySha=(Get-FileHash -LiteralPath $sourceGateway -Algorithm SHA256).Hash.ToLowerInvariant()
        if($gatewaySha -ne (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash.ToLowerInvariant()){Fail "Installed gateway does not match authenticated source release; no state changed."}
        $bridgeGatewayStage=New-PrivateDirectory (Join-Path $root "bridge-gateway-stage")
        Expand-Archive -LiteralPath (Join-Path $Bridge.Directory $Bridge.Gateway) -DestinationPath $bridgeGatewayStage
        $bridgeCandidates=@(Get-ChildItem -LiteralPath $bridgeGatewayStage -Filter "defenseclaw.exe" -File -Recurse)
        if($bridgeCandidates.Count -ne 1){Fail "Authenticated bridge gateway archive is invalid"}
        $bridgeGateway=Join-Path $root "bridge-gateway.exe";Write-SecuredRestoreCandidate -Source $bridgeCandidates[0].FullName -Destination $bridgeGateway -FinalSddl (Get-PrivateFileSddl)
        Remove-Item -LiteralPath $bridgeGatewayStage -Recurse -Force
        $bridgeGatewaySha=(Get-FileHash -LiteralPath $bridgeGateway -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-VersionOutput $bridgeGateway $Bridge.Version "authenticated bridge gateway"
        & $uv.Source --no-config pip check --python (Get-Python) *> $null
        if($LASTEXITCODE -ne 0){Fail "The source Python environment is already inconsistent; exact bridge activation is unavailable. No state changed."}
        $preflight=Join-Path $root "bridge-preflight"
        & $uv.Source --no-config venv $preflight --python $basePython --no-python-downloads --quiet *> $null
        if($LASTEXITCODE -ne 0){Fail "Could not create the bridge dependency preflight environment; no state changed."}
        $preflightPython=Join-Path (Join-Path $preflight "Scripts") "python.exe"
        & $uv.Source --no-config pip install --python $preflightPython --quiet $bridgeWheel *> $null
        if($LASTEXITCODE -ne 0){Fail "Could not resolve and install bridge dependencies before stopping services; no state changed."}
        & $uv.Source --no-config pip check --python $preflightPython *> $null
        if($LASTEXITCODE -ne 0){Fail "The resolved bridge dependency environment is inconsistent; no state changed."}
        $preflightVersion=@(& $preflightPython -I -c 'from defenseclaw import __version__; print(__version__)' 2>$null)
        if($LASTEXITCODE -ne 0 -or $preflightVersion.Count -ne 1 -or [string]$preflightVersion[0] -ne $Bridge.Version){Fail "Bridge CLI dependency preflight installed the wrong version; no state changed."}
        Remove-Item -LiteralPath $preflight -Recurse -Force
        Assert-VersionOutput (Get-Cli) $SourceVersion "source CLI"
        $sourceWasRunning=Get-PhaseOneSourceRunningState -Gateway $gateway -ControllerHome $controllerHome -DataDir $dataDir -ConfigPath $configPath -ExpectedVersion $SourceVersion
        $venvIdentity=Get-PhaseOneVenvIdentity $activeVenv
        $gatewaySddl=Get-OwnerDaclSddl $gateway
        return [pscustomobject]@{PlanId=$planId;RecoveryRoot=$recoveryRoot;Root=$root;ControllerHome=$controllerHome;DataDir=$dataDir;ConfigPath=$configPath;PathIdentities=$pathIdentities;SourceVersion=$SourceVersion;SourceWasRunning=[bool]$sourceWasRunning;Wheel=$wheel;WheelSha256=$wheelSha;BridgeVersion=$Bridge.Version;BridgeWheel=$bridgeWheel;BridgeWheelSha256=$bridgeWheelSha;Gateway=$sourceGateway;BridgeGateway=$bridgeGateway;BridgeGatewaySha256=$bridgeGatewaySha;GatewaySnapshot=[pscustomobject]@{Active=$gateway;Backup=$sourceGateway;Existed=$true;Sha256=$gatewaySha;Sddl=$gatewaySddl;AllowedActiveSha256=@($gatewaySha,$bridgeGatewaySha)};State=$null;StateRoot=$state;StateSnapshotReady=$false;ActiveState=$null;ActiveStateSnapshotReady=$false;OpenClawHome=$openClawHome;OpenClawExisted=$openClawExisted;ConfigOverride=$configOverride;Uv=[string]$uv.Source;BasePython=$basePython;ActiveVenv=$activeVenv;SourceVenv=(Join-Path $root "source-venv");VenvSddl=$venvSddl;VenvIdentitySha256=$venvIdentity;Journal=(Join-Path $recoveryRoot "phase-one-active.json");MutatorLease=$mutatorLease}
    }catch{
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        if($mutatorLease -and -not(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-active.json"))){Remove-Item -LiteralPath $mutatorLease -Force -ErrorAction SilentlyContinue}
        throw
    }
}
function Get-PhaseOneJournalValue {
    param([object]$Object,[string]$Name)
    $property=Property $Object $Name
    if(-not $property){Fail "Phase-one recovery journal lacks $Name."}
    return $property.Value
}
function Read-PhaseOneJournal {
    $recoveryRoot=Get-PhaseOneRecoveryRoot
    if(-not $recoveryRoot){return $null}
    $journal=Join-Path $recoveryRoot "phase-one-active.json"
    if(-not(Test-Path -LiteralPath $journal)){return $null}
    Assert-PrivateFileAcl $journal
    try{$raw=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one recovery journal is invalid JSON."}
    $schema=Get-PhaseOneJournalValue $raw "schema_version"
    if(-not(Test-Integer $schema) -or [int64]$schema -ne 4){Fail "Unsupported phase-one recovery journal schema."}
    Assert-ExactJsonKeys $raw @("schema_version","kind","plan_id","controller_home","data_dir","config_path","path_identities","source_version","source_was_running","wheel_sha256","gateway_sha256","gateway_sddl","bridge_version","bridge_wheel_sha256","bridge_gateway_sha256","venv_sddl","venv_identity_sha256","base_python","state_snapshot_ready","state_manifest_sha256","active_snapshot_ready","active_manifest_sha256","openclaw_home","openclaw_home_existed","config_override") "Phase-one recovery journal"
    if([string](Get-PhaseOneJournalValue $raw "kind") -ne "defenseclaw-phase-one-recovery"){Fail "Invalid phase-one recovery journal kind."}
    $planId=[string](Get-PhaseOneJournalValue $raw "plan_id")
    if($planId -notmatch '^phase-one-[0-9a-f]{32}$'){Fail "Invalid phase-one recovery plan identifier."}
    $sourceVersion=[string](Get-PhaseOneJournalValue $raw "source_version");Assert-Version $sourceVersion "phase-one recovery source_version"
    $bridgeVersion=[string](Get-PhaseOneJournalValue $raw "bridge_version");Assert-Version $bridgeVersion "phase-one recovery bridge_version"
    if((Compare-Version $sourceVersion $bridgeVersion)-ge 0){Fail "Phase-one recovery bridge version is not newer than its source."}
    $sourceWasRunning=Get-PhaseOneJournalValue $raw "source_was_running"
    if($sourceWasRunning -isnot [bool]){Fail "Phase-one recovery source running state is invalid."}
    $wheelSha=[string](Get-PhaseOneJournalValue $raw "wheel_sha256")
    $gatewaySha=[string](Get-PhaseOneJournalValue $raw "gateway_sha256")
    $bridgeWheelSha=[string](Get-PhaseOneJournalValue $raw "bridge_wheel_sha256")
    $bridgeGatewaySha=[string](Get-PhaseOneJournalValue $raw "bridge_gateway_sha256")
    if($wheelSha -notmatch '^[0-9a-f]{64}$' -or $gatewaySha -notmatch '^[0-9a-f]{64}$' -or $bridgeWheelSha -notmatch '^[0-9a-f]{64}$' -or $bridgeGatewaySha -notmatch '^[0-9a-f]{64}$'){Fail "Phase-one recovery custody digest is invalid."}
    $gatewaySddl=[string](Get-PhaseOneJournalValue $raw "gateway_sddl")
    if(-not $gatewaySddl){Fail "Phase-one recovery journal lacks gateway owner/DACL."}
    try{[void](New-FileAclFromSddl $gatewaySddl)}catch{Fail "Phase-one recovery gateway owner/DACL is invalid."}
    $venvSddl=[string](Get-PhaseOneJournalValue $raw "venv_sddl")
    if(-not $venvSddl){Fail "Phase-one recovery journal lacks source venv owner/DACL."}
    try{[void](New-DirectoryAclFromSddl $venvSddl)}catch{Fail "Phase-one recovery source venv owner/DACL is invalid."}
    $venvIdentity=[string](Get-PhaseOneJournalValue $raw "venv_identity_sha256")
    if($venvIdentity -notmatch '^[0-9a-f]{64}$'){Fail "Phase-one recovery source venv identity is invalid."}
    $basePython=[string](Get-PhaseOneJournalValue $raw "base_python")
    if(-not [IO.Path]::IsPathRooted($basePython)){Fail "Phase-one recovery base Python is invalid."};$basePython=[IO.Path]::GetFullPath($basePython)
    Assert-RealFile $basePython "Phase-one recovery base Python"
    $controllerHome=[string](Get-PhaseOneJournalValue $raw "controller_home")
    $dataDir=[string](Get-PhaseOneJournalValue $raw "data_dir")
    $configPath=[string](Get-PhaseOneJournalValue $raw "config_path")
    if(-not [IO.Path]::IsPathRooted($controllerHome) -or -not [IO.Path]::IsPathRooted($dataDir) -or -not [IO.Path]::IsPathRooted($configPath)){Fail "Phase-one recovery runtime paths are invalid."}
    $controllerHome=[IO.Path]::GetFullPath($controllerHome);$dataDir=[IO.Path]::GetFullPath($dataDir);$configPath=[IO.Path]::GetFullPath($configPath)
    if(-not $controllerHome.Equals((Get-ControllerHome),[StringComparison]::OrdinalIgnoreCase) -or -not $recoveryRoot.Equals((Join-Path $controllerHome ".upgrade-recovery"),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one recovery journal targets a different controller home."}
    $root=Join-Path $recoveryRoot $planId
    Assert-PrivateDirectoryAcl -Path $root -Expected (New-PrivateDirectoryAcl)
    $wheel=Join-Path $root "source.whl";$sourceGateway=Join-Path $root "source-gateway.exe";$bridgeWheel=Join-Path $root "bridge.whl";$bridgeGateway=Join-Path $root "bridge-gateway.exe"
    foreach($custody in @(@($wheel,$wheelSha),@($sourceGateway,$gatewaySha),@($bridgeWheel,$bridgeWheelSha),@($bridgeGateway,$bridgeGatewaySha))){
        Assert-PrivateFileAcl $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $custody[1]){Fail "Phase-one recovery custody digest changed: $($custody[0])"}
    }
    $stateRoot=Join-Path $root "state";Assert-PrivateDirectoryAcl -Path $stateRoot -Expected (New-PrivateDirectoryAcl)
    $stateReady=Get-PhaseOneJournalValue $raw "state_snapshot_ready"
    if($stateReady -isnot [bool]){Fail "Phase-one recovery state snapshot flag is invalid."}
    $stateManifestRaw=Get-PhaseOneJournalValue $raw "state_manifest_sha256"
    $stateManifestSha=if($null -eq $stateManifestRaw){""}else{[string]$stateManifestRaw}
    if(($stateReady -and $stateManifestSha -notmatch '^[0-9a-f]{64}$') -or (-not $stateReady -and $stateManifestSha)){Fail "Phase-one recovery state manifest digest is invalid."}
    $activeReady=Get-PhaseOneJournalValue $raw "active_snapshot_ready"
    if($activeReady -isnot [bool]){Fail "Phase-one recovery active snapshot flag is invalid."}
    $activeManifestRaw=Get-PhaseOneJournalValue $raw "active_manifest_sha256"
    $activeManifestSha=if($null -eq $activeManifestRaw){""}else{[string]$activeManifestRaw}
    if(($activeReady -and (-not $stateReady -or $activeManifestSha -notmatch '^[0-9a-f]{64}$')) -or (-not $activeReady -and $activeManifestSha)){Fail "Phase-one recovery active manifest digest is invalid."}
    $openClawHome=[string](Get-PhaseOneJournalValue $raw "openclaw_home")
    if(-not [IO.Path]::IsPathRooted($openClawHome)){Fail "Phase-one recovery OpenClaw home is invalid."};$openClawHome=[IO.Path]::GetFullPath($openClawHome)
    $openClawExisted=Get-PhaseOneJournalValue $raw "openclaw_home_existed"
    if($openClawExisted -isnot [bool]){Fail "Phase-one recovery OpenClaw existence flag is invalid."}
    $configRaw=Get-PhaseOneJournalValue $raw "config_override"
    $configOverride=if($null -eq $configRaw){""}else{[string]$configRaw}
    if($configOverride -and -not [IO.Path]::IsPathRooted($configOverride)){Fail "Phase-one recovery config override is invalid."}
    if($configOverride){$configOverride=[IO.Path]::GetFullPath($configOverride)}
    $expectedConfig=if($configOverride){$configOverride}else{Join-Path $controllerHome "config.yaml"}
    if(-not $configPath.Equals([IO.Path]::GetFullPath($expectedConfig),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one recovery config path is inconsistent with its recorded source."}
    if($null -ne $script:RuntimePaths){
        foreach($binding in @(@("ControllerHome",$controllerHome),@("DataDir",$dataDir),@("ConfigPath",$configPath),@("OpenClawHome",$openClawHome))){
            $runtimeProperty=Property $script:RuntimePaths ([string]$binding[0])
            if(-not $runtimeProperty -or -not ([IO.Path]::GetFullPath([string]$runtimeProperty.Value)).Equals([string]$binding[1],[StringComparison]::OrdinalIgnoreCase)){Fail "Active runtime paths differ from the phase-one journal."}
        }
    }else{
        if($env:DEFENSECLAW_HOME -and -not ([IO.Path]::GetFullPath($env:DEFENSECLAW_HOME)).Equals($controllerHome,[StringComparison]::OrdinalIgnoreCase)){Fail "Ambient DEFENSECLAW_HOME differs from the interrupted phase-one controller home."}
        if($env:DEFENSECLAW_CONFIG -and -not ([IO.Path]::GetFullPath($env:DEFENSECLAW_CONFIG)).Equals($configPath,[StringComparison]::OrdinalIgnoreCase)){Fail "Ambient DEFENSECLAW_CONFIG differs from the interrupted phase-one config path."}
        if($env:OPENCLAW_HOME -and -not ([IO.Path]::GetFullPath($env:OPENCLAW_HOME)).Equals($openClawHome,[StringComparison]::OrdinalIgnoreCase)){Fail "Ambient OPENCLAW_HOME differs from the interrupted phase-one OpenClaw home."}
    }
    $pathIdentities=Get-PhaseOneJournalValue $raw "path_identities"
    $openIdentity=(Property $pathIdentities "openclaw_home").Value
    if([bool]$openIdentity.existed -ne [bool]$openClawExisted){Fail "Phase-one OpenClaw existence contract is inconsistent."}
    Assert-PhaseOnePathIdentities -Identities $pathIdentities -ControllerHome $controllerHome -DataDir $dataDir -ConfigPath $configPath -OpenClawHome $openClawHome -Python $basePython -AllowCreatedOpenClaw
    $stateSnapshot=if($stateReady){Read-PhaseOneStateSnapshot -StateRoot $stateRoot -ExpectedDigest $stateManifestSha -DataDir $dataDir -OpenClawHome $openClawHome -ConfigPath $configPath -AllowActiveManifest:$activeReady}else{$null}
    $activeSnapshot=if($activeReady){Read-PhaseOneActiveStateSnapshot -StateRoot $stateRoot -ExpectedDigest $activeManifestSha -PlanId $planId -DataDir $dataDir -OpenClawHome $openClawHome -ConfigPath $configPath}else{$null}
    $activeVenv=Join-Path $controllerHome ".venv"
    $venvPrefix=$activeVenv.TrimEnd('\')+'\'
    if($basePython.StartsWith($venvPrefix,[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-one recovery base Python resolves inside the active venv."}
    $identityPath=if(Test-Path -LiteralPath (Join-Path $root "source-venv")){Join-Path $root "source-venv"}else{$activeVenv}
    if((Get-PhaseOneVenvIdentity $identityPath)-ne $venvIdentity){Fail "Phase-one recovery source venv identity changed."}
    $mutatorLease=Get-PhaseOneMutatorLeasePath $recoveryRoot
    Assert-PrivateFileAcl $mutatorLease
    return [pscustomobject]@{PlanId=$planId;RecoveryRoot=$recoveryRoot;Root=$root;ControllerHome=$controllerHome;DataDir=$dataDir;ConfigPath=$configPath;PathIdentities=$pathIdentities;SourceVersion=$sourceVersion;SourceWasRunning=[bool]$sourceWasRunning;Wheel=$wheel;WheelSha256=$wheelSha;BridgeVersion=$bridgeVersion;BridgeWheel=$bridgeWheel;BridgeWheelSha256=$bridgeWheelSha;Gateway=$sourceGateway;BridgeGateway=$bridgeGateway;BridgeGatewaySha256=$bridgeGatewaySha;GatewaySnapshot=[pscustomobject]@{Active=(Get-GatewayPath);Backup=$sourceGateway;Existed=$true;Sha256=$gatewaySha;Sddl=$gatewaySddl;AllowedActiveSha256=@($gatewaySha,$bridgeGatewaySha)};State=$stateSnapshot;StateRoot=$stateRoot;StateSnapshotReady=[bool]$stateReady;ActiveState=$activeSnapshot;ActiveStateSnapshotReady=[bool]$activeReady;OpenClawHome=$openClawHome;OpenClawExisted=[bool]$openClawExisted;ConfigOverride=$configOverride;Uv="";BasePython=$basePython;ActiveVenv=$activeVenv;SourceVenv=(Join-Path $root "source-venv");VenvSddl=$venvSddl;VenvIdentitySha256=$venvIdentity;Journal=$journal;MutatorLease=$mutatorLease}
}
function Register-PhaseOneJournal {
    param([object]$Plan)
    if(Test-Path -LiteralPath $Plan.Journal){Fail "Another phase-one recovery journal is active; no installed state changed."}
    $document=[ordered]@{schema_version=4;kind="defenseclaw-phase-one-recovery";plan_id=$Plan.PlanId;controller_home=$Plan.ControllerHome;data_dir=$Plan.DataDir;config_path=$Plan.ConfigPath;path_identities=$Plan.PathIdentities;source_version=$Plan.SourceVersion;source_was_running=[bool]$Plan.SourceWasRunning;wheel_sha256=$Plan.WheelSha256;gateway_sha256=$Plan.GatewaySnapshot.Sha256;gateway_sddl=$Plan.GatewaySnapshot.Sddl;bridge_version=$Plan.BridgeVersion;bridge_wheel_sha256=$Plan.BridgeWheelSha256;bridge_gateway_sha256=$Plan.BridgeGatewaySha256;venv_sddl=$Plan.VenvSddl;venv_identity_sha256=$Plan.VenvIdentitySha256;base_python=$Plan.BasePython;state_snapshot_ready=$false;state_manifest_sha256=$null;active_snapshot_ready=$false;active_manifest_sha256=$null;openclaw_home=$Plan.OpenClawHome;openclaw_home_existed=[bool]$Plan.OpenClawExisted;config_override=if($Plan.ConfigOverride){$Plan.ConfigOverride}else{$null}}
    $candidate=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".tmp"
    try{
        Write-PrivateUtf8File -Path $candidate -Content (($document|ConvertTo-Json -Depth 6 -Compress)+"`n")
        [IO.File]::Move($candidate,$Plan.Journal)
        Assert-PrivateFileAcl $Plan.Journal
        $loaded=Read-PhaseOneJournal
        if(-not $loaded -or $loaded.PlanId -ne $Plan.PlanId){Fail "Phase-one recovery journal readback failed."}
    }catch{Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue;throw}
}
function Seal-PhaseOneStateSnapshot {
    param([object]$Plan)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython
    Assert-PrivateFileAcl $Plan.Journal
    try{$raw=Get-Content -LiteralPath $Plan.Journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Cannot seal invalid phase-one recovery journal."}
    if([string](Get-PhaseOneJournalValue $raw "plan_id")-ne $Plan.PlanId -or (Get-PhaseOneJournalValue $raw "state_snapshot_ready") -isnot [bool] -or [bool](Get-PhaseOneJournalValue $raw "state_snapshot_ready") -or $null -ne (Get-PhaseOneJournalValue $raw "state_manifest_sha256")){Fail "Phase-one recovery journal changed before state sealing."}
    $snapshot=New-PhaseOneStateSnapshot -StateRoot $Plan.StateRoot -DataDir $Plan.DataDir -OpenClawHome $Plan.OpenClawHome -ConfigPath $Plan.ConfigPath
    Assert-PhaseOneGatewayStopped -Gateway $Plan.GatewaySnapshot.Active -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
    $raw.state_snapshot_ready=$true;$raw.state_manifest_sha256=$snapshot.ManifestSha256
    $candidate=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".state.tmp"
    $displaced=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".state.previous"
    try{
        Write-PrivateUtf8File -Path $candidate -Content ((ConvertTo-Json -InputObject $raw -Depth 8 -Compress)+"`n")
        [IO.File]::Replace($candidate,$Plan.Journal,$displaced,$true)
        Assert-PrivateFileAcl $Plan.Journal
        $loaded=Read-PhaseOneJournal
        if(-not $loaded -or $loaded.PlanId -ne $Plan.PlanId -or -not $loaded.StateSnapshotReady -or $loaded.State.ManifestSha256 -ne $snapshot.ManifestSha256){Fail "Phase-one state journal seal readback failed."}
        $Plan.State=$snapshot;$Plan.StateSnapshotReady=$true
        if(Test-Path -LiteralPath $displaced){Set-PrivateFileAcl $displaced;Remove-Item -LiteralPath $displaced -Force -ErrorAction Stop}
    }catch{
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if(Test-Path -LiteralPath $displaced){Set-PrivateFileAcl $displaced;Remove-Item -LiteralPath $displaced -Force -ErrorAction SilentlyContinue}
        throw
    }
}
function Seal-PhaseOneActiveStateSnapshot {
    param([object]$Plan)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython -AllowCreatedOpenClaw
    Assert-PrivateFileAcl $Plan.Journal
    try{$raw=Get-Content -LiteralPath $Plan.Journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Cannot seal invalid phase-one active-state journal."}
    if([string](Get-PhaseOneJournalValue $raw "plan_id")-ne $Plan.PlanId -or (Get-PhaseOneJournalValue $raw "state_snapshot_ready") -isnot [bool] -or -not [bool](Get-PhaseOneJournalValue $raw "state_snapshot_ready") -or (Get-PhaseOneJournalValue $raw "active_snapshot_ready") -isnot [bool] -or [bool](Get-PhaseOneJournalValue $raw "active_snapshot_ready") -or $null -ne (Get-PhaseOneJournalValue $raw "active_manifest_sha256")){Fail "Phase-one recovery journal changed before active-state sealing."}
    $snapshot=New-PhaseOneActiveStateSnapshot -Plan $Plan
    Assert-PhaseOneGatewayStopped -Gateway $Plan.GatewaySnapshot.Active -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
    $raw.active_snapshot_ready=$true;$raw.active_manifest_sha256=$snapshot.ManifestSha256
    $candidate=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".active.tmp"
    $displaced=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".active.previous"
    $replaced=$false
    try{
        Write-PrivateUtf8File -Path $candidate -Content ((ConvertTo-Json -InputObject $raw -Depth 8 -Compress)+"`n")
        [IO.File]::Replace($candidate,$Plan.Journal,$displaced,$true);$replaced=$true
        Assert-PrivateFileAcl $Plan.Journal
        $loaded=Read-PhaseOneJournal
        if(-not $loaded -or $loaded.PlanId -ne $Plan.PlanId -or -not $loaded.ActiveStateSnapshotReady -or $loaded.ActiveState.ManifestSha256 -ne $snapshot.ManifestSha256){Fail "Phase-one active-state journal seal readback failed."}
        $Plan.ActiveState=$snapshot;$Plan.ActiveStateSnapshotReady=$true
        if(Test-Path -LiteralPath $displaced){Set-PrivateFileAcl $displaced;Remove-Item -LiteralPath $displaced -Force -ErrorAction Stop}
    }catch{
        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if(-not $replaced -and $null -ne (Get-PhaseOneItem $snapshot.Manifest)){Set-PrivateFileAcl $snapshot.Manifest;Remove-Item -LiteralPath $snapshot.Manifest -Force -ErrorAction SilentlyContinue}
        if(Test-Path -LiteralPath $displaced){Set-PrivateFileAcl $displaced;Remove-Item -LiteralPath $displaced -Force -ErrorAction SilentlyContinue}
        throw
    }
}
function Complete-PhaseOneJournal {
    param([object]$Plan)
    Assert-PrivateFileAcl $Plan.Journal
    try{$raw=Get-Content -LiteralPath $Plan.Journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Cannot clear invalid phase-one recovery journal."}
    if([string](Get-PhaseOneJournalValue $raw "plan_id") -ne $Plan.PlanId){Fail "Refusing to clear a different phase-one recovery journal."}
    Remove-Item -LiteralPath $Plan.Journal -Force -ErrorAction Stop
    $marker=Get-PhaseOneVenvMarkerPath $Plan.ActiveVenv
    if(Test-Path -LiteralPath $marker){
        try{Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv;Remove-Item -LiteralPath $marker -Force -ErrorAction Stop}catch{Warn "Healthy bridge venv retained its harmless phase-one ownership marker."}
    }
    try{Remove-Item -LiteralPath $Plan.Root -Recurse -Force -ErrorAction Stop}catch{Warn "Healthy phase-one recovery custody remains at $($Plan.Root)"}
    if(Test-Path -LiteralPath $Plan.MutatorLease){
        try{
            $lease=[IO.File]::Open($Plan.MutatorLease,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try{Assert-PrivateFileAcl $Plan.MutatorLease}finally{$lease.Dispose()}
            Remove-Item -LiteralPath $Plan.MutatorLease -Force -ErrorAction Stop
        }catch{Warn "Completed phase one retained its inactive mutator lease at $($Plan.MutatorLease)."}
    }
}
function Remove-PhaseOneQuarantines {
    param([object]$Snapshot)
    $parent=Split-Path -Parent $Snapshot.Active;$name=Split-Path -Leaf $Snapshot.Active
    if(-not(Test-Path -LiteralPath $parent -PathType Container)){return}
    $pattern='^\.'+[regex]::Escape($name)+'\.phase-one-(created|displaced|restore)-[0-9a-f]{32}$'
    foreach($item in Get-ChildItem -LiteralPath $parent -File -Force){
        if($item.Name -notmatch $pattern){continue}
        try{Set-PrivateFileAcl $item.FullName;Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop}catch{Warn "Kept private rollback quarantine: $($item.FullName)"}
    }
}
function Remove-PhaseOneOwnedMutationTemporaries {
    param([object]$Plan)
    if([string]$Plan.PlanId -notmatch '^phase-one-[0-9a-f]{32}$'){Fail "Phase-one mutation cleanup has an invalid plan identity."}
    Assert-PrivateFileAcl $Plan.Journal
    try{$journal=Get-Content -LiteralPath $Plan.Journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one mutation cleanup cannot authenticate its journal."}
    if(-not(Test-Integer $journal.schema_version) -or [int64]$journal.schema_version -ne 4 -or [string]$journal.plan_id -ne [string]$Plan.PlanId){Fail "Phase-one mutation cleanup journal identity changed."}
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython -AllowCreatedOpenClaw
    $token=([string]$Plan.PlanId).Substring("phase-one-".Length)
    $escaped=[regex]::Escape($token)
    $generic=[regex]::new('^\.tmp\.upgrade-'+$escaped+'\.')
    $cursor=[regex]::new('^\.migration_state\.upgrade-'+$escaped+'\..*\.tmp$')
    $tagged=[regex]::new('^\..+\.upgrade-'+$escaped+'\.[A-Za-z0-9_-]+\.tmp$')
    $roots=@([IO.Path]::GetFullPath($Plan.DataDir),[IO.Path]::GetFullPath((Split-Path -Parent $Plan.ConfigPath)))
    $openClawItem=Get-Item -LiteralPath $Plan.OpenClawHome -Force -ErrorAction SilentlyContinue
    if($null -ne $openClawItem){
        if(-not $openClawItem.PSIsContainer -or ($openClawItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one mutation cleanup OpenClaw root is unsafe."}
        $roots += [IO.Path]::GetFullPath($Plan.OpenClawHome)
    }
    $seen=@{};$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach($root in $roots){
        $key=$root.ToLowerInvariant()
        if($seen.ContainsKey($key)){continue};$seen[$key]=$true
        $rootItem=Get-Item -LiteralPath $root -Force
        if(-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one mutation cleanup root is unsafe: $root"}
        $members=@(Get-ChildItem -LiteralPath $root -Force)
        if($members.Count -gt 100000){Fail "Phase-one mutation cleanup exceeded its scan bound."}
        foreach($member in $members){
            $owned=$generic.IsMatch($member.Name) -or $cursor.IsMatch($member.Name) -or $tagged.IsMatch($member.Name)
            if(-not $owned){continue}
            if($member.PSIsContainer -or ($member.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one owned mutation temporary has an unsafe identity: $($member.FullName)"}
            Assert-RealFile $member.FullName "Phase-one owned mutation temporary"
            $owner=(Get-Acl -LiteralPath $member.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
            if($owner -ne $currentSid){Fail "Phase-one owned mutation temporary is not owned by the current user: $($member.FullName)"}
            Remove-Item -LiteralPath $member.FullName -Force -ErrorAction Stop
        }
    }
}
function New-TestPhaseOneOwnedMutationTemporaries {
    param([object]$Plan)
    if(-not $TestMode){Fail "Phase-one owned-temporary injection requires TestMode."}
    $token=([string]$Plan.PlanId).Substring("phase-one-".Length)
    $openClawItem=Get-Item -LiteralPath $Plan.OpenClawHome -Force -ErrorAction SilentlyContinue
    if($null -eq $openClawItem){[void](New-PrivateDirectory $Plan.OpenClawHome)}
    $configLeaf=Split-Path -Leaf $Plan.ConfigPath
    $paths=@(
        (Join-Path (Split-Path -Parent $Plan.ConfigPath) ("."+$configLeaf+".upgrade-"+$token+".abc.tmp")),
        (Join-Path $Plan.DataDir (".migration_state.upgrade-"+$token+".abc.tmp")),
        (Join-Path $Plan.OpenClawHome (".tmp.upgrade-"+$token+".abcopenclaw.json"))
    )
    foreach($path in $paths){Write-PrivateUtf8File -Path $path -Content ("phase-one-owned-temporary:"+$token+"`n")}
}
function Invoke-TestHardCrash {
    param([string]$Label)
    if(-not $TestMode){Fail "Hard-crash injection requires TestMode."}
    Write-Host "  ! Injecting abrupt process termination: $Label" -ForegroundColor Yellow
    [Diagnostics.Process]::GetCurrentProcess().Kill()
    [Threading.Thread]::Sleep([Timeout]::Infinite)
}
function Get-PhaseOneVenvMarkerPath {
    param([string]$Venv)
    return Join-Path $Venv ".defenseclaw-phase-one-owner.json"
}
function Assert-PhaseOneOwnedBridgeVenv {
    param([object]$Plan,[string]$Venv)
    $item=Get-Item -LiteralPath $Venv -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one bridge venv is not a real directory."}
    Assert-PrivateDirectoryAcl -Path $Venv -Expected (New-PrivateDirectoryAcl)
    $marker=Get-PhaseOneVenvMarkerPath $Venv
    Assert-PrivateFileAcl $marker
    $markerItem=Get-Item -LiteralPath $marker -Force
    if($markerItem.Length -le 0 -or $markerItem.Length -gt 4096){Fail "Phase-one bridge venv ownership marker has invalid size."}
    try{$payload=Get-Content -LiteralPath $marker -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one bridge venv ownership marker is invalid JSON."}
    Assert-ExactJsonKeys $payload @("schema_version","kind","plan_id","bridge_wheel_sha256") "Phase-one bridge venv ownership marker"
    if(-not(Test-Integer $payload.schema_version) -or [int64]$payload.schema_version -ne 1 -or [string]$payload.kind -ne "defenseclaw-phase-one-bridge-venv" -or [string]$payload.plan_id -ne $Plan.PlanId -or [string]$payload.bridge_wheel_sha256 -ne $Plan.BridgeWheelSha256){Fail "Phase-one bridge venv ownership marker does not match the active recovery plan."}
}
function New-PhaseOneOwnedBridgeVenvSeed {
    param([object]$Plan)
    $seed=New-PrivateDirectory (Join-Path $Plan.Root ("bridge-venv-seed-"+[guid]::NewGuid().ToString("N")))
    $document=[ordered]@{schema_version=1;kind="defenseclaw-phase-one-bridge-venv";plan_id=$Plan.PlanId;bridge_wheel_sha256=$Plan.BridgeWheelSha256}
    Write-PrivateUtf8File -Path (Get-PhaseOneVenvMarkerPath $seed) -Content (($document|ConvertTo-Json -Compress)+"`n")
    Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $seed
    return $seed
}
function Restore-PhaseOneSourceVenv {
    param([object]$Plan)
    if(Test-Path -LiteralPath $Plan.SourceVenv){
        $sourceItem=Get-Item -LiteralPath $Plan.SourceVenv -Force
        if(-not $sourceItem.PSIsContainer -or ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Phase-one source venv custody is unsafe."}
        if((Get-OwnerDaclSddl $Plan.SourceVenv)-ne $Plan.VenvSddl){Fail "Phase-one source venv custody owner/DACL changed."}
        if((Get-PhaseOneVenvIdentity $Plan.SourceVenv)-ne $Plan.VenvIdentitySha256){Fail "Phase-one source venv custody contents changed."}
        if(Test-Path -LiteralPath $Plan.ActiveVenv){
            Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv
            $quarantine=Join-Path $Plan.Root ("failed-bridge-venv-"+[guid]::NewGuid().ToString("N"))
            [IO.Directory]::Move($Plan.ActiveVenv,$quarantine)
        }
        if(Test-Path -LiteralPath $Plan.ActiveVenv){Fail "Phase-one active venv remained occupied during source restoration."}
        [IO.Directory]::Move($Plan.SourceVenv,$Plan.ActiveVenv)
    }
    $activeItem=Get-Item -LiteralPath $Plan.ActiveVenv -Force
    if(-not $activeItem.PSIsContainer -or ($activeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-OwnerDaclSddl $Plan.ActiveVenv)-ne $Plan.VenvSddl -or (Get-PhaseOneVenvIdentity $Plan.ActiveVenv)-ne $Plan.VenvIdentitySha256){Fail "Restored source venv does not match its exact bytes and root owner/DACL."}
}
function Publish-PhaseOneBridgeGateway {
    param([object]$Plan)
    $snapshot=[pscustomobject]@{Active=$Plan.GatewaySnapshot.Active;Backup=$Plan.BridgeGateway;Existed=$true;Sha256=$Plan.BridgeGatewaySha256;Sddl=$Plan.GatewaySnapshot.Sddl;AllowedActiveSha256=@($Plan.GatewaySnapshot.Sha256)}
    Publish-PhaseOneSnapshot -Snapshot $snapshot
    Assert-VersionOutput $snapshot.Active $Plan.BridgeVersion "activated bridge gateway"
}
function Install-PhaseOneBridgeArtifacts {
    param([object]$Plan)
    if(-not $Plan.Uv){Fail "Bridge activation lacks its preflighted uv executable."}
    $seed=New-PhaseOneOwnedBridgeVenvSeed $Plan
    if(Test-Path -LiteralPath $Plan.SourceVenv){Fail "Phase-one source venv custody path is already occupied."}
    $activeItem=Get-Item -LiteralPath $Plan.ActiveVenv -Force
    if(-not $activeItem.PSIsContainer -or ($activeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-OwnerDaclSddl $Plan.ActiveVenv)-ne $Plan.VenvSddl){Fail "Source venv identity changed before bridge activation."}
    [IO.Directory]::Move($Plan.ActiveVenv,$Plan.SourceVenv)
    if((Get-PhaseOneVenvIdentity $Plan.SourceVenv)-ne $Plan.VenvIdentitySha256){Fail "Source venv changed while entering rollback custody."}
    [IO.Directory]::Move($seed,$Plan.ActiveVenv)
    Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.Uv,"--no-config","venv",$Plan.ActiveVenv,"--allow-existing","--python",$Plan.BasePython,"--no-python-downloads","--quiet") -InheritLeaseHandle
    if($execution.ExitCode -ne 0){Fail "Could not create the resolver-owned bridge venv: $($execution.Output -join ' ')"}
    Assert-PhaseOneOwnedBridgeVenv -Plan $Plan -Venv $Plan.ActiveVenv
    $bridgePython=Join-Path (Join-Path $Plan.ActiveVenv "Scripts") "python.exe"
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.Uv,"--no-config","pip","install","--python",$bridgePython,"--quiet","--offline",$Plan.BridgeWheel) -InheritLeaseHandle
    if($execution.ExitCode -ne 0){Fail "Could not install the preflighted bridge dependency set from local custody: $($execution.Output -join ' ')"}
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.Uv,"--no-config","pip","check","--python",$bridgePython) -InheritLeaseHandle
    if($execution.ExitCode -ne 0){Fail "The activated bridge dependency environment is inconsistent: $($execution.Output -join ' ')"}
    Assert-VersionOutput (Get-Cli) $Plan.BridgeVersion "activated bridge CLI"
    Publish-PhaseOneBridgeGateway $Plan
}
function Invoke-FreshBridgeActivation {
    param([object]$Plan,[object]$Manifest)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process");$savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process");$savedOpenClaw=[Environment]::GetEnvironmentVariable("OPENCLAW_HOME","Process");$savedMutationToken=[Environment]::GetEnvironmentVariable("DEFENSECLAW_UPGRADE_MUTATION_TOKEN","Process")
    try{
    $env:DEFENSECLAW_HOME=$Plan.DataDir;$env:DEFENSECLAW_CONFIG=$Plan.ConfigPath;$env:OPENCLAW_HOME=$Plan.OpenClawHome;$env:DEFENSECLAW_UPGRADE_MUTATION_TOKEN=([string]$Plan.PlanId).Substring("phase-one-".Length)
    $requiredJson=ConvertTo-Json -InputObject @($Manifest.RequiredMigrations) -Compress
    $activation=@'
import inspect
import json
import sys

from defenseclaw import migration_state
from defenseclaw.migrations import run_migrations

source, target, openclaw_home, data_dir, required_json = sys.argv[1:]
kwargs = {}
parameter = inspect.signature(run_migrations).parameters.get("upgrade_handles_local_bundle")
if parameter is not None and parameter.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
    kwargs["upgrade_handles_local_bundle"] = True
count = run_migrations(source, target, openclaw_home, data_dir, **kwargs)
state = migration_state.load(data_dir)
required = json.loads(required_json)
if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
    raise RuntimeError("invalid resolver-owned required migration set")
if any(not migration_state.is_applied(state, item) for item in required):
    raise RuntimeError("fresh bridge controller did not apply every required migration")
print(json.dumps({"count": count}, separators=(",", ":")))
'@
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @((Get-Python),"-I","-c",$activation,$Plan.SourceVersion,$Plan.BridgeVersion,$Plan.OpenClawHome,$Plan.DataDir,$requiredJson) -InheritLeaseHandle
    $result=@($execution.Output)
    if($execution.ExitCode -ne 0){Fail "Fresh bridge controller migration process failed: $($result -join ' ')"}
    $contracts=@($result|Where-Object{[string]$_ -match '^\{"count":\d+\}$'})
    if($contracts.Count -ne 1){Fail "Fresh bridge controller returned an invalid migration contract."}
    $migrationContract=$contracts[0]|ConvertFrom-Json
    Remove-PhaseOneOwnedMutationTemporaries $Plan
    Seal-PhaseOneActiveStateSnapshot $Plan
    if($InjectPhaseOneConcurrentEditAfterActiveSeal){
        $stream=[IO.File]::Open($Plan.ConfigPath,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes("phase-one-concurrent-config-edit`n");$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
    if($InjectPhaseOneConcurrentFileAfterActiveSeal){
        $policies=Join-Path $Plan.DataDir "policies";$policiesItem=Get-PhaseOneItem $policies
        if($null -eq $policiesItem -or -not $policiesItem.PSIsContainer -or ($policiesItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "Concurrent-file injection requires a real managed policies directory."}
        Write-PrivateUtf8File -Path (Join-Path $policies "phase-one-concurrent-new.txt") -Content "phase-one-concurrent-new-state`n"
    }
    if($InjectPhaseOneConcurrentEditAfterActiveSeal -or $InjectPhaseOneConcurrentFileAfterActiveSeal){Fail "Injected phase-one target failure after active-state divergence"}
    $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @((Get-Gateway),"start")
    if($execution.ExitCode -ne 0){Fail "Fresh bridge gateway failed to start: $($execution.Output -join ' ')"}
    Assert-VersionOutput (Get-Cli) $Plan.BridgeVersion "fresh bridge CLI"
    Assert-VersionOutput (Get-Gateway) $Plan.BridgeVersion "fresh bridge gateway"
    if(-not(Test-VersionBoundGatewayHealth -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -ExpectedVersion $Plan.BridgeVersion -TimeoutSeconds $HealthTimeout)){Fail "Fresh bridge gateway failed its version-bound post-migration health check."}
    return [int]$migrationContract.count
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process");[Environment]::SetEnvironmentVariable("OPENCLAW_HOME",$savedOpenClaw,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_UPGRADE_MUTATION_TOKEN",$savedMutationToken,"Process")
    }
}
function Write-PhaseOneBridgeSuccessReceipt {
    param([object]$Plan,[int]$MigrationCount)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython -AllowCreatedOpenClaw
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process");$savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process");$savedOpenClaw=[Environment]::GetEnvironmentVariable("OPENCLAW_HOME","Process")
    try{
    $env:DEFENSECLAW_HOME=$Plan.DataDir;$env:DEFENSECLAW_CONFIG=$Plan.ConfigPath;$env:OPENCLAW_HOME=$Plan.OpenClawHome
    Set-ReceiptBaseline
    $receipt=@'
import sys
from defenseclaw.upgrade_receipt import begin_upgrade_receipt, complete_upgrade_receipt, record_upgrade_migrations

path = begin_upgrade_receipt(sys.argv[1], from_version=sys.argv[2], target_version=sys.argv[3], artifacts_verified=True)
record_upgrade_migrations(path, migration_count=int(sys.argv[4]), degraded=False)
complete_upgrade_receipt(path, status="succeeded")
'@
    & (Get-Python) -I -c $receipt $Plan.DataDir $Plan.SourceVersion $Plan.BridgeVersion ([string]$MigrationCount)
    if($LASTEXITCODE -ne 0){Fail "Fresh bridge controller could not commit its health-proven receipt."}
    [void](Success-Receipt $Plan.BridgeVersion)
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process");[Environment]::SetEnvironmentVariable("OPENCLAW_HOME",$savedOpenClaw,"Process")
    }
}
function Restore-PhaseOneSource {
    param([object]$Plan)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython -AllowCreatedOpenClaw
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedOpenClaw=[Environment]::GetEnvironmentVariable("OPENCLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=$Plan.DataDir;$env:DEFENSECLAW_CONFIG=$Plan.ConfigPath;$env:OPENCLAW_HOME=$Plan.OpenClawHome
        if($Plan.StateSnapshotReady){Assert-PhaseOneStateRollbackCas -Snapshot $Plan.State -ActiveSnapshot $Plan.ActiveState -PlanId $Plan.PlanId -Python $Plan.BasePython}
        if(Test-Path -LiteralPath $Plan.GatewaySnapshot.Active -PathType Leaf){
            Assert-RealFile $Plan.GatewaySnapshot.Active "Phase-one active gateway"
            $activeGatewaySha=(Get-FileHash -LiteralPath $Plan.GatewaySnapshot.Active -Algorithm SHA256).Hash.ToLowerInvariant()
            if(@($Plan.GatewaySnapshot.AllowedActiveSha256)-notcontains $activeGatewaySha){Fail "Refusing to execute or overwrite an unrecognized phase-one gateway activation."}
            if(-not $Plan.StateSnapshotReady -and -not $Plan.SourceWasRunning){
                Assert-PhaseOneGatewayStopped -Gateway $Plan.GatewaySnapshot.Active -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
            }else{
                $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.GatewaySnapshot.Active,"stop")
                if($execution.ExitCode -ne 0){Fail "Could not stop the phase-one target gateway before rollback: $($execution.Output -join ' ')"}
                Assert-PhaseOneGatewayStopped -Gateway $Plan.GatewaySnapshot.Active -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
            }
        }
        Restore-PhaseOneSourceVenv $Plan
        Remove-PhaseOneOwnedMutationTemporaries $Plan
        if($Plan.StateSnapshotReady){Restore-PhaseOneStateSnapshot -Snapshot $Plan.State -ActiveSnapshot $Plan.ActiveState -StateRoot $Plan.StateRoot -PlanId $Plan.PlanId -Python $Plan.BasePython}
        Publish-PhaseOneSnapshot -Snapshot $Plan.GatewaySnapshot
        Assert-VersionOutput (Get-Cli) $Plan.SourceVersion "restored CLI"
        Assert-VersionOutput (Get-Gateway) $Plan.SourceVersion "restored gateway"
        if($Plan.SourceWasRunning){
            $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @((Get-Gateway),"start")
            if($execution.ExitCode -ne 0){Fail "Restored source gateway did not start: $($execution.Output -join ' ')"}
            if(-not(Test-VersionBoundGatewayHealth -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -ExpectedVersion $Plan.SourceVersion -TimeoutSeconds $HealthTimeout)){Fail "Restored source gateway is not healthy at the authenticated source version"}
        }else{
            Assert-PhaseOneGatewayStopped -Gateway (Get-Gateway) -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
        }
        return $true
    }catch{Warn "Phase-one automatic rollback failed: $($_.Exception.Message)";$script:PreserveWorkRoot=$true;return $false}
    finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("OPENCLAW_HOME",$savedOpenClaw,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
}
function Recover-InterruptedPhaseOne {
    $recoveryRoot=Get-PhaseOneRecoveryRoot
    if(-not $recoveryRoot -or -not(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-active.json"))){return $false}
    $lease=Enter-PhaseOneMutatorLease $recoveryRoot
    try{$plan=Read-PhaseOneJournal}finally{$lease.Dispose()}
    if(-not $plan){return $false}
    Warn "Found interrupted phase-one upgrade; restoring authenticated DefenseClaw $($plan.SourceVersion) before reading installed versions."
    $script:RecoveringPhaseOneJournal=$true
    try{
        if(-not(Restore-PhaseOneSource $plan)){Fail "Interrupted phase-one recovery is incomplete. Private custody: $($plan.Root)"}
        Complete-PhaseOneJournal $plan
        Ok "Recovered interrupted phase-one upgrade to healthy DefenseClaw $($plan.SourceVersion)"
        return $true
    }finally{$script:RecoveringPhaseOneJournal=$false}
}
function Assert-ExactJsonKeys {
    param([object]$Object,[string[]]$Names,[string]$Label)
    $actual=@($Object.PSObject.Properties.Name|Sort-Object);$expected=@($Names|Sort-Object)
    if(($actual -join "`n") -ne ($expected -join "`n")){Fail "$Label has an unexpected schema."}
}
function Resolve-ContainedPath {
    param([string]$Path,[string]$Root,[string]$Label)
    try{$full=[IO.Path]::GetFullPath($Path);$rootFull=[IO.Path]::GetFullPath($Root)}catch{Fail "$Label path is invalid."}
    $trimChars=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $prefix=$rootFull.TrimEnd($trimChars)+[IO.Path]::DirectorySeparatorChar
    if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Fail "$Label escapes private recovery custody."}
    return $full
}
function Assert-RealDirectory {
    param([string]$Path,[string]$Label)
    $item=Get-Item -LiteralPath $Path -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){Fail "$Label must be a real directory: $Path"}
}
function Get-PhaseTwoBootstrapPlan {
    $recoveryRoot=Get-UpgradeRecoveryRoot
    if(-not $recoveryRoot){return $null}
    $journal=Join-Path $recoveryRoot "phase-two-active.json"
    if(-not(Test-Path -LiteralPath $journal)){return $null}
    Assert-PrivateFileAcl $journal
    try{$raw=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two recovery journal is invalid JSON."}
    $keys=@("schema_version","source_version","source_gateway_was_running","local_bundle_mutation_intent","target_version","os_name","recovery_home","data_dir","backup_dir","receipt_path","rollback_wheel_path","rollback_wheel_sha256","rollback_gateway_path","rollback_gateway_sha256","active_gateway_path","gateway_snapshot","state_files","backup_root_snapshot")
    Assert-ExactJsonKeys -Object $raw -Names $keys -Label "Phase-two recovery journal"
    if(-not(Test-Integer $raw.schema_version) -or [int64]$raw.schema_version -ne 3){Fail "Unsupported phase-two recovery journal schema."}
    if($raw.source_gateway_was_running -isnot [bool]){Fail "Phase-two recovery journal lacks source gateway state."}
    if($raw.local_bundle_mutation_intent -isnot [bool]){Fail "Phase-two recovery journal lacks bundle mutation intent."}
    $sourceWasRunning=[bool]$raw.source_gateway_was_running
    $sourceVersion=[string]$raw.source_version;$targetVersion=[string]$raw.target_version
    Assert-Version $sourceVersion "phase-two recovery source_version";Assert-Version $targetVersion "phase-two recovery target_version"
    if([string]$raw.os_name -ne "windows"){Fail "Phase-two recovery journal is not for Windows."}
    if(-not [IO.Path]::IsPathRooted([string]$raw.recovery_home) -or -not [IO.Path]::IsPathRooted([string]$raw.data_dir)){Fail "Phase-two recovery journal has non-absolute controller or data paths."}
    $recoveryHome=[IO.Path]::GetFullPath([string]$raw.recovery_home)
    if(-not $recoveryHome.Equals([IO.Path]::GetFullPath((Get-ControllerHome)),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two recovery journal targets a different controller home."}
    $dataDir=[IO.Path]::GetFullPath([string]$raw.data_dir)
    $backupsRoot=Join-Path $dataDir "backups";Assert-RealDirectory $backupsRoot "Phase-two backups root"
    $backupDir=Resolve-ContainedPath -Path ([string]$raw.backup_dir) -Root $backupsRoot -Label "Phase-two backup"
    Assert-PrivateDirectoryAcl -Path $backupDir -Expected (New-PrivateDirectoryAcl)
    $rollbackRoot=Join-Path $backupDir "hard-cut-rollback";Assert-PrivateDirectoryAcl -Path $rollbackRoot -Expected (New-PrivateDirectoryAcl)
    $wheel=Resolve-ContainedPath -Path ([string]$raw.rollback_wheel_path) -Root $rollbackRoot -Label "Phase-two rollback wheel"
    $gateway=Resolve-ContainedPath -Path ([string]$raw.rollback_gateway_path) -Root $rollbackRoot -Label "Phase-two rollback gateway"
    $wheelSha=[string]$raw.rollback_wheel_sha256;$gatewaySha=[string]$raw.rollback_gateway_sha256
    if($wheelSha -notmatch '^[0-9a-f]{64}$' -or $gatewaySha -notmatch '^[0-9a-f]{64}$'){Fail "Phase-two recovery custody digest is invalid."}
    foreach($custody in @(@($wheel,$wheelSha),@($gateway,$gatewaySha))){
        Assert-PrivateFileAcl $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $custody[1]){Fail "Phase-two recovery custody digest changed: $($custody[0])"}
    }
    $receiptRoot=Join-Path $dataDir ".upgrade-receipts";Assert-RealDirectory $receiptRoot "Upgrade receipt root"
    $receipt=Resolve-ContainedPath -Path ([string]$raw.receipt_path) -Root $receiptRoot -Label "Phase-two receipt"
    if(-not ([IO.Path]::GetFullPath([string]$raw.active_gateway_path)).Equals([IO.Path]::GetFullPath((Get-GatewayPath)),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two journal targets a different active gateway."}
    Assert-RealFile $receipt "Phase-two receipt"
    try{$receiptPayload=Get-Content -LiteralPath $receipt -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two recovery receipt is invalid JSON."}
    if([string]$receiptPayload.from_version -ne $sourceVersion -or [string]$receiptPayload.target_version -ne $targetVersion){Fail "Phase-two recovery receipt does not match the journal."}
    $status=[string]$receiptPayload.status
    if($status -notin @("pending","succeeded","rolled_back")){Fail "Phase-two recovery receipt has unsafe status '$status'."}
    $stateFiles=@($raw.state_files)
    if($raw.state_files -isnot [System.Array] -or $stateFiles.Count -ne 7){Fail "Phase-two recovery journal has an invalid exact state inventory."}
    $snapshotKeys=@("active_path","backup_path","existed","sha256","mode","windows_security")
    foreach($snapshot in $stateFiles){Assert-ExactJsonKeys -Object $snapshot -Names $snapshotKeys -Label "Phase-two state snapshot"}
    $configRaw=[string]$stateFiles[0].active_path
    if(-not [IO.Path]::IsPathRooted($configRaw)){Fail "Phase-two recovery journal has a non-absolute config path."}
    $configPath=[IO.Path]::GetFullPath($configRaw)
    $expectedStatePaths=@(
        $configPath,
        ($configPath+".pre-observability-migration.bak"),
        ($configPath+".lock"),
        ($configPath+".tmp-f3395"),
        [IO.Path]::GetFullPath((Join-Path $dataDir ".env")),
        [IO.Path]::GetFullPath((Join-Path $dataDir ".env.lock")),
        [IO.Path]::GetFullPath((Join-Path $dataDir ".migration_state.json"))
    )
    for($index=0;$index -lt $stateFiles.Count;$index++){
        $activeRaw=[string]$stateFiles[$index].active_path
        if(-not [IO.Path]::IsPathRooted($activeRaw)){Fail "Phase-two recovery state inventory contains a non-absolute path."}
        $active=[IO.Path]::GetFullPath($activeRaw)
        if(-not $active.Equals($expectedStatePaths[$index],[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two recovery state inventory is inconsistent."}
    }
    $directorySnapshotKeys=@("active_path","device","inode","mode","preexisting_recovery_entries","windows_security")
    Assert-ExactJsonKeys -Object $raw.backup_root_snapshot -Names $directorySnapshotKeys -Label "Phase-two backup-root snapshot"
    $snapshotRoot=[IO.Path]::GetFullPath([string]$raw.backup_root_snapshot.active_path)
    if(-not $snapshotRoot.Equals([IO.Path]::GetFullPath($backupsRoot),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two backup-root snapshot targets another directory."}
    if(-not(Test-Integer $raw.backup_root_snapshot.device) -or [int64]$raw.backup_root_snapshot.device -lt 0 -or -not(Test-Integer $raw.backup_root_snapshot.inode) -or [int64]$raw.backup_root_snapshot.inode -le 0 -or -not(Test-Integer $raw.backup_root_snapshot.mode)){Fail "Phase-two backup-root identity is invalid."}
    $preexisting=@($raw.backup_root_snapshot.preexisting_recovery_entries)
    if($raw.backup_root_snapshot.preexisting_recovery_entries -isnot [System.Array] -or $preexisting.Count -gt 256){Fail "Phase-two backup-root recovery inventory is invalid."}
    $previousName=$null
    foreach($entry in $preexisting){
        Assert-ExactJsonKeys -Object $entry -Names @("name","device","inode") -Label "Phase-two backup-root recovery entry"
        $name=[string]$entry.name
        if($name -notmatch '^observability-v8-[0-9a-f]{32}$' -or -not(Test-Integer $entry.device) -or [int64]$entry.device -lt 0 -or -not(Test-Integer $entry.inode) -or [int64]$entry.inode -le 0){Fail "Phase-two backup-root recovery inventory is invalid."}
        if($null -ne $previousName -and [string]::CompareOrdinal($previousName,$name) -ge 0){Fail "Phase-two backup-root recovery inventory is not canonical."}
        $previousName=$name
    }
    return [pscustomobject]@{Journal=$journal;RecoveryHome=$recoveryHome;DataDir=$dataDir;ConfigPath=$configPath;SourceVersion=$sourceVersion;SourceWasRunning=$sourceWasRunning;TargetVersion=$targetVersion;Wheel=$wheel;Receipt=$receipt;Status=$status}
}
function Test-VersionBoundGatewayHealth {
    param(
        [string]$ControllerHome,
        [string]$DataDir,
        [string]$ConfigPath,
        [string]$ExpectedVersion,
        [int]$TimeoutSeconds=$HealthTimeout
    )
    Assert-Version $ExpectedVersion "expected gateway health version"
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=[IO.Path]::GetFullPath($ControllerHome)
        $env:DEFENSECLAW_CONFIG=[IO.Path]::GetFullPath($ConfigPath)
        $probe=@'
import http.client
import ipaddress
import json
import sys
import time

from defenseclaw import config as config_module

data_dir, timeout_text, expected_version = sys.argv[1:]
timeout_seconds = max(int(timeout_text), 1)
config_module._load_dotenv_into_os(data_dir)
cfg = config_module.load()
bind = getattr(cfg.gateway, "api_bind", "") or ""
if not bind:
    openshell = getattr(cfg, "openshell", None)
    guardrail = getattr(cfg, "guardrail", None)
    guardrail_host = getattr(guardrail, "host", "") if guardrail is not None else ""
    is_standalone = bool(openshell is not None and openshell.is_standalone())
    bind = (
        guardrail_host
        if is_standalone and guardrail_host not in ("", "localhost", "127.0.0.1")
        else "127.0.0.1"
    )
connection_host = bind[1:-1] if bind.startswith("[") and bind.endswith("]") else bind
try:
    loopback = ipaddress.ip_address(connection_host.split("%", 1)[0]).is_loopback
except ValueError:
    loopback = connection_host.lower() == "localhost"
token = cfg.gateway.resolved_token() if loopback else ""
port = int(getattr(cfg.gateway, "api_port", 18970))
deadline = time.monotonic() + timeout_seconds
while time.monotonic() < deadline:
    connection = None
    try:
        remaining = max(deadline - time.monotonic(), 0.1)
        connection = http.client.HTTPConnection(
            connection_host,
            port,
            timeout=min(2.0, remaining),
        )
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection.request("GET", "/health", headers=headers)
        response = connection.getresponse()
        body = response.read((1 << 20) + 1)
        if response.status == 200 and len(body) <= (1 << 20):
            payload = json.loads(body.decode("utf-8"))
            gateway = payload.get("gateway") if isinstance(payload, dict) else None
            provenance = payload.get("provenance") if isinstance(payload, dict) else None
            if (
                isinstance(gateway, dict)
                and gateway.get("state") == "running"
                and isinstance(provenance, dict)
                and provenance.get("binary_version") == expected_version
            ):
                raise SystemExit(0)
    except (OSError, ValueError, json.JSONDecodeError, http.client.HTTPException):
        pass
    finally:
        if connection is not None:
            connection.close()
    time.sleep(min(0.25, max(deadline - time.monotonic(), 0.0)))
raise SystemExit(1)
'@
        & (Get-Python) -I -c $probe $DataDir ([string][Math]::Max($TimeoutSeconds,1)) $ExpectedVersion *> $null
        return $LASTEXITCODE -eq 0
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
}
function Assert-PhaseTwoGatewayStopped {
    param([string]$DataDir,[string]$ConfigPath)
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=$DataDir;$env:DEFENSECLAW_CONFIG=$ConfigPath
        Assert-PhaseOneGatewayStopped -Gateway (Get-Gateway) -DataDir $DataDir -ConfigPath $ConfigPath
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
}
function Enter-PhaseTwoMutatorLease {
    param([string]$RecoveryRoot)
    $leasePath=Join-Path $RecoveryRoot "phase-two-mutator.lease"
    if(-not(Test-Path -LiteralPath $leasePath -PathType Leaf)){Fail "Phase-two recovery journal lacks its private mutator lease."}
    $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max($HealthTimeout,1))
    while($true){
        try{
            $lease=[IO.File]::Open($leasePath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        }catch [IO.IOException]{
            if([DateTime]::UtcNow -ge $deadline){Fail "A phase-two mutator is still active; recovery did not race it and the journal remains intact."}
            Start-Sleep -Milliseconds 100;continue
        }
        try{Assert-PrivateFileAcl $leasePath;return $lease}catch{$lease.Dispose();throw}
    }
}
function Invoke-PhaseTwoBootstrapWheelInstall {
    param([string]$RecoveryRoot,[string]$Uv,[string]$Wheel)
    $leasePath=Join-Path $RecoveryRoot "phase-two-mutator.lease"
    $leaseWrapper=@'
import ctypes
import os
import subprocess
import sys
import time

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
create_file = kernel32.CreateFileW
create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
create_file.restype = ctypes.c_void_p
close_handle = kernel32.CloseHandle
close_handle.argtypes = [ctypes.c_void_p]
close_handle.restype = ctypes.c_int
invalid = ctypes.c_void_p(-1).value
deadline = time.monotonic() + max(float(sys.argv[2]), 1.0)
while True:
    handle = create_file(sys.argv[1], 0xC0000000 | 0x00020000, 0, None, 3, 0x00200000 | 0x80000000, None)
    if handle != invalid:
        break
    error = ctypes.get_last_error()
    if error not in (32, 33):
        raise ctypes.WinError(error)
    if time.monotonic() >= deadline:
        raise TimeoutError("phase-two mutator lease remained held")
    time.sleep(0.05)
os.set_handle_inheritable(handle, True)
startup = subprocess.STARTUPINFO()
startup.lpAttributeList = {"handle_list": [handle]}
try:
    child = subprocess.Popen(sys.argv[3:], close_fds=True, startupinfo=startup)
finally:
    os.set_handle_inheritable(handle, False)
try:
    raise SystemExit(child.wait())
finally:
    close_handle(handle)
'@
    & (Get-Python) -I -c $leaseWrapper $leasePath ([string]$HealthTimeout) $Uv pip install --python (Get-Python) --quiet --offline --no-deps --reinstall $Wheel *> $null
    if($LASTEXITCODE -ne 0){Fail "Could not reinstall the retained bridge recovery wheel; phase-two journal remains active."}
}
function Recover-InterruptedPhaseTwo {
    $recoveryRoot=Get-UpgradeRecoveryRoot
    if(-not $recoveryRoot -or -not(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-two-active.json"))){return $false}
    $lease=Enter-PhaseTwoMutatorLease $recoveryRoot;$plan=$null
    try{
        $plan=Get-PhaseTwoBootstrapPlan
        if(-not $plan){return $false}
        if($plan.Status -in @("succeeded","rolled_back")){
            $expected=if($plan.Status -eq "succeeded"){$plan.TargetVersion}else{$plan.SourceVersion}
            Assert-VersionOutput (Get-Cli) $expected "terminal phase-two CLI";Assert-VersionOutput (Get-Gateway) $expected "terminal phase-two gateway"
            if($plan.Status -eq "succeeded" -or $plan.SourceWasRunning){
                if(-not(Test-VersionBoundGatewayHealth -ControllerHome $plan.RecoveryHome -DataDir $plan.DataDir -ConfigPath $plan.ConfigPath -ExpectedVersion $expected -TimeoutSeconds $HealthTimeout)){Fail "Terminal phase-two journal cannot be cleared before exact health succeeds."}
            }else{Assert-PhaseTwoGatewayStopped -DataDir $plan.DataDir -ConfigPath $plan.ConfigPath}
            Remove-Item -LiteralPath $plan.Journal -Force -ErrorAction Stop
            Ok "Cleared terminal phase-two recovery journal ($($plan.Status))"
            return $true
        }
        Warn "Found interrupted phase-two hard cut; bootstrapping authenticated bridge recovery before reading installed versions."
        $uv=Get-Command uv -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
        if(-not $uv){Fail "uv is required to bootstrap phase-two recovery; private custody was preserved."}
    }finally{$lease.Dispose()}
    Invoke-PhaseTwoBootstrapWheelInstall -RecoveryRoot $recoveryRoot -Uv ([string]$uv.Source) -Wheel $plan.Wheel
    Assert-VersionOutput (Get-Cli) $plan.SourceVersion "recovery bridge CLI"
    $recoveryCode='from defenseclaw.commands.cmd_upgrade import _recover_interrupted_hard_cut; raise SystemExit(0 if _recover_interrupted_hard_cut() else 1)'
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=$plan.RecoveryHome;$env:DEFENSECLAW_CONFIG=$plan.ConfigPath
        & (Get-Python) -I -c $recoveryCode
        $recoveryExitCode=$LASTEXITCODE
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
    }
    if($recoveryExitCode -ne 0){Fail "Bridge recovery entrypoint could not complete interrupted phase two; journal remains active."}
    if(Test-Path -LiteralPath $plan.Journal){Fail "Bridge recovery returned success without clearing the phase-two journal."}
    Assert-VersionOutput (Get-Cli) $plan.SourceVersion "recovered bridge CLI";Assert-VersionOutput (Get-Gateway) $plan.SourceVersion "recovered bridge gateway"
    if($plan.SourceWasRunning){
        if(-not(Test-VersionBoundGatewayHealth -ControllerHome $plan.RecoveryHome -DataDir $plan.DataDir -ConfigPath $plan.ConfigPath -ExpectedVersion $plan.SourceVersion -TimeoutSeconds $HealthTimeout)){Fail "Recovered phase-two bridge is unhealthy or reports the wrong version."}
        Ok "Recovered interrupted phase-two hard cut to healthy DefenseClaw $($plan.SourceVersion)"
    }else{
        Assert-PhaseTwoGatewayStopped -DataDir $plan.DataDir -ConfigPath $plan.ConfigPath
        Ok "Recovered interrupted phase-two hard cut to stopped DefenseClaw $($plan.SourceVersion)"
    }
    return $true
}

function Confirm-Plan {
    param([string]$Plan)
    if ($Yes) { return }
    Write-Host ""; Write-Host "  Verified plan: $Plan"
    if ((Read-Host "  Proceed? [y/N]") -notmatch '^[Yy]$') { Info "Aborted; no installed change."; exit 0 }
}
function Set-TestEndpoint {
    if (-not $TestMode) { return }
    $uri = [Uri]$ReleaseBaseUrl
    if ($uri.Scheme -notin @("http","https") -or $uri.Host -notin @("127.0.0.1","localhost","::1")) { Fail "Test endpoint must be loopback." }
    $module = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Get-ControllerHome) ".venv") "Lib") "site-packages") "defenseclaw\commands") "cmd_upgrade.py"
    $source = Get-Content -LiteralPath $module -Raw -Encoding UTF8
    if ($source -notmatch '(?m)^GITHUB_DL\s*=') { Fail "Controller download constant missing." }
    $updated = [regex]::Replace($source, '(?m)^GITHUB_DL\s*=.*$', ('GITHUB_DL = "'+$ReleaseBaseUrl.TrimEnd('/')+'"'), 1)
    [IO.File]::WriteAllText($module, $updated, (New-Object Text.UTF8Encoding($false)))
}
function Invoke-Controller {
    param([string]$Target)
    Set-ReceiptBaseline
    Set-TestEndpoint
    & (Get-Cli) upgrade --yes --version $Target --health-timeout $HealthTimeout
    if ($LASTEXITCODE -ne 0) { Fail "Controller failed upgrading to $Target." }
}
function Assert-VersionOutput {
    param([string]$Command,[string]$Expected,[string]$Label)
    $output=(& $Command --version 2>&1|Out-String)
    $token = '(?<![\d.])' + [regex]::Escape($Expected) + '(?![\d.])'
    if ($LASTEXITCODE -ne 0 -or $output -notmatch $token) { Fail "$Label does not report $Expected." }
}
function Set-ReceiptBaseline {
    $script:ReceiptBaseline=@{};$root=Join-Path (Get-Home) ".upgrade-receipts"
    if(Test-Path -LiteralPath $root){foreach($file in Get-ChildItem -LiteralPath $root -Filter "*.json" -File){$script:ReceiptBaseline[$file.Name]=$true}}
}
function Success-Receipt {
    param([string]$Target)
    $root=Join-Path (Get-Home) ".upgrade-receipts"; $receiptMatches=@()
    if(Test-Path -LiteralPath $root){
        foreach($file in Get-ChildItem -LiteralPath $root -Filter "*.json" -File){
            try{$receipt=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8|ConvertFrom-Json}catch{continue}
            if(-not $script:ReceiptBaseline.ContainsKey($file.Name) -and [string]$receipt.target_version -eq $Target -and [string]$receipt.status -eq "succeeded"){$receiptMatches += [pscustomobject]@{File=$file;Receipt=$receipt}}
        }
    }
    if($receiptMatches.Count -eq 0){Fail "No new succeeded receipt for $Target."}
    return $receiptMatches|Sort-Object {$_.File.LastWriteTimeUtc} -Descending|Select-Object -First 1
}
function Assert-Healthy {
    param([string]$Expected,[object]$Manifest,[switch]$RequireV8)
    Assert-VersionOutput (Get-Cli) $Expected "CLI"; Assert-VersionOutput (Get-Gateway) $Expected "Gateway"
    if(-not(Test-VersionBoundGatewayHealth -ControllerHome $script:RuntimePaths.ControllerHome -DataDir $script:RuntimePaths.DataDir -ConfigPath $script:RuntimePaths.ConfigPath -ExpectedVersion $Expected -TimeoutSeconds $HealthTimeout)){Fail "Gateway unhealthy or reporting the wrong version after $Expected."}
    [void](Success-Receipt $Expected)
    if($RequireV8){
        $config=Get-Content -LiteralPath $script:RuntimePaths.ConfigPath -Raw -Encoding UTF8
        if($config -notmatch '(?m)^\s*config_version:\s*8\s*$'){Fail "config_version is not 8."}
        $cursor=Get-Content -LiteralPath (Join-Path $script:RuntimePaths.DataDir ".migration_state.json") -Raw -Encoding UTF8|ConvertFrom-Json
        foreach($migration in @($Manifest.RequiredMigrations)){if(@($cursor.applied) -notcontains [string]$migration){Fail "Cursor missing $migration."}}
    }
}
function Assert-RunningComponents {
    param([string]$Expected)
    Assert-VersionOutput (Get-Cli) $Expected "CLI"
    Assert-VersionOutput (Get-Gateway) $Expected "Gateway"
    if(-not(Test-VersionBoundGatewayHealth -ControllerHome $script:RuntimePaths.ControllerHome -DataDir $script:RuntimePaths.DataDir -ConfigPath $script:RuntimePaths.ConfigPath -ExpectedVersion $Expected -TimeoutSeconds $HealthTimeout)){Fail "Gateway unhealthy or reporting the wrong version after initial bridge install $Expected."}
}
function Retain-Source {
    param([object]$Release)
    $root=Join-Path (Get-Home) "backups"
    if(-not(Test-Path -LiteralPath $root)){[void](New-PrivateDirectory $root)}else{Set-PrivateDirectoryAcl $root}
    $destination=New-PrivateDirectory (Join-Path $root ("staged-bridge-"+[guid]::NewGuid().ToString("N")))
    foreach($file in Get-ChildItem -LiteralPath $Release.Directory -File){Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $destination $file.Name)}
    $required=@("checksums.txt","checksums.txt.sig","checksums.txt.pem","upgrade-manifest.json",$Release.ProtectedWheel,$Release.ProtectedGateway,$Release.RefusalWheel,$Release.RefusalGateway)
    foreach($name in @($required|Select-Object -Unique)){if(-not(Test-Path -LiteralPath (Join-Path $destination $name)-PathType Leaf)){Fail "Retained set lacks $name."}}
    $script:RetainedSourceDirectory=$destination; return $destination
}
function Assert-RollbackCallSites {
    $module=Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Get-ControllerHome) ".venv") "Lib") "site-packages") "defenseclaw\commands") "cmd_upgrade.py"
    $source=Get-Content -LiteralPath $module -Raw -Encoding UTF8
    $prepare=[regex]::Matches($source,'_prepare_hard_cut_rollback_plan\s*\(').Count
    $execute=[regex]::Matches($source,'_execute_hard_cut_rollback\s*\(').Count
    if($prepare -lt 2 -or $execute -lt 2 -or $source -notmatch 'DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR'){Fail "Fresh controller lacks live rollback call sites; healthy source remains installed."}
}
function Invoke-FreshHardCut {
    param([string]$Source,[string]$Target,[string]$Artifacts)
    Assert-RollbackCallSites; Set-ReceiptBaseline; Set-TestEndpoint
    $names=@("DEFENSECLAW_STAGED_UPGRADE","DEFENSECLAW_STAGED_BRIDGE_VERSION","DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR");$saved=@{}
    foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,"Process")}
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    try{
        $env:DEFENSECLAW_HOME=$script:RuntimePaths.ControllerHome;$env:DEFENSECLAW_CONFIG=$script:RuntimePaths.ConfigPath
        $env:DEFENSECLAW_STAGED_UPGRADE="1";$env:DEFENSECLAW_STAGED_BRIDGE_VERSION=$Source;$env:DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR=$Artifacts
        & (Get-Python) -I -m defenseclaw.main upgrade --yes --version $Target --health-timeout $HealthTimeout
        if($LASTEXITCODE -ne 0){Fail "Fresh controller failed upgrading to $Target."}
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process")
        foreach($name in $names){if($null -eq $saved[$name]){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}else{Set-Item "Env:$name" $saved[$name]}}
    }
}

function Stop-PhaseOneSourceForSnapshot {
    param([object]$Plan)
    Assert-PhaseOnePathIdentities -Identities $Plan.PathIdentities -ControllerHome $Plan.ControllerHome -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath -OpenClawHome $Plan.OpenClawHome -Python $Plan.BasePython
    $savedHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process");$savedConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process");$savedOpenClaw=[Environment]::GetEnvironmentVariable("OPENCLAW_HOME","Process")
    try{
    $env:DEFENSECLAW_HOME=$Plan.DataDir;$env:DEFENSECLAW_CONFIG=$Plan.ConfigPath;$env:OPENCLAW_HOME=$Plan.OpenClawHome
    Assert-RealFile $Plan.GatewaySnapshot.Active "Phase-one source gateway"
    $activeSha=(Get-FileHash -LiteralPath $Plan.GatewaySnapshot.Active -Algorithm SHA256).Hash.ToLowerInvariant()
    if($activeSha -ne $Plan.GatewaySnapshot.Sha256){Fail "Source gateway identity changed before phase-one stop; no unrecognized executable was invoked."}
    if($Plan.SourceWasRunning){
        $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.GatewaySnapshot.Active,"stop")
        $stopExitCode=$execution.ExitCode
        if($InjectPhaseOneStopFailure){$stopExitCode=86}
        if($stopExitCode -ne 0){Fail "Gateway stop command failed before phase-one state capture: $($execution.Output -join ' ')"}
        if($InjectPhaseOneNonQuiescentStop){
            $execution=Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @($Plan.GatewaySnapshot.Active,"start")
            if($execution.ExitCode -ne 0){Fail "Could not arrange the non-quiescent phase-one test state: $($execution.Output -join ' ')"}
        }
    }
    Assert-PhaseOneGatewayStopped -Gateway $Plan.GatewaySnapshot.Active -DataDir $Plan.DataDir -ConfigPath $Plan.ConfigPath
    }finally{
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedHome,"Process");[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedConfig,"Process");[Environment]::SetEnvironmentVariable("OPENCLAW_HOME",$savedOpenClaw,"Process")
    }
}

function Invoke-BridgeTransaction {
    param([string]$SourceVersion,[object]$Bridge,[object]$SourceRelease)
    $plan=New-PhaseOneRollbackPlan -SourceRelease $SourceRelease -SourceVersion $SourceVersion -Bridge $Bridge
    try{Register-PhaseOneJournal $plan}catch{Remove-Item -LiteralPath $plan.Root -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $plan.MutatorLease -Force -ErrorAction SilentlyContinue;throw}
    $committed=$false
    try{
        Step "Quiescing source state for exact rollback";Stop-PhaseOneSourceForSnapshot $plan;Seal-PhaseOneStateSnapshot $plan
        Step "Installing verified bridge under resolver custody";Install-PhaseOneBridgeArtifacts $plan
        if($InjectPhaseOneCrashAfterMutation){Invoke-TestHardCrash "after phase-one bridge mutation"}
        if($InjectPhaseOneFailureAfterMutation){Fail "Injected phase-one failure after bridge mutation"}
        Step "Launching fresh bridge controller migration and health process";$migrationCount=Invoke-FreshBridgeActivation -Plan $plan -Manifest $Bridge.Manifest
        if($InjectPhaseOneOwnedMutationTemporaries -or $InjectPhaseOneFailureAfterFreshMutation){New-TestPhaseOneOwnedMutationTemporaries $plan}
        if($InjectPhaseOneFailureAfterFreshMutation){Fail "Injected phase-one failure after fresh mutation temporaries"}
        Remove-PhaseOneOwnedMutationTemporaries $plan
        Sync-PhaseOneBridgeVenv $plan
        Complete-PhaseOneJournal $plan
        $committed=$true
        if($InjectPhaseOneCrashAfterJournalClose){Invoke-TestHardCrash "after healthy phase-one journal close and before terminal receipt"}
        Write-PhaseOneBridgeSuccessReceipt -Plan $plan -MigrationCount $migrationCount
    }catch{
        $original=$_.Exception.Message
        if($committed){Fail "Healthy bridge was durably committed, but its terminal receipt step failed; re-run the resolver. Original failure: $original"}
        if(Restore-PhaseOneSource $plan){Complete-PhaseOneJournal $plan;Fail "Bridge phase failed; restored healthy DefenseClaw $SourceVersion. Original failure: $original"}
        Fail "Bridge phase failed and automatic source restoration was incomplete. Recovery artifacts: $($plan.Root). Original failure: $original"
    }
}

function Main {
    if($Help){Show-Usage;return}
    if($TestMode -and -not $script:ExplicitTarget -and -not $LatestVersionOverride){Fail "TestMode latest path needs LatestVersionOverride."}
    if(($InjectPhaseOneFailureAfterMutation -or $InjectPhaseOneCrashAfterMutation -or $InjectPhaseOneCrashDuringRecovery -or $InjectPhaseOneCrashAfterJournalClose -or $InjectPhaseOneStopFailure -or $InjectPhaseOneNonQuiescentStop -or $InjectProtectedMaterializationCollision -or $InjectPhaseOneOwnedMutationTemporaries -or $InjectPhaseOneFailureAfterFreshMutation -or $InjectPhaseOneConcurrentEditAfterActiveSeal -or $InjectPhaseOneConcurrentFileAfterActiveSeal) -and -not $TestMode){Fail "Upgrade fault injection requires TestMode."}
    $savedRuntimeHome=[Environment]::GetEnvironmentVariable("DEFENSECLAW_HOME","Process")
    $savedRuntimeConfig=[Environment]::GetEnvironmentVariable("DEFENSECLAW_CONFIG","Process")
    $savedRuntimeOpenClaw=[Environment]::GetEnvironmentVariable("OPENCLAW_HOME","Process")
    [void](Get-ControllerHome)
    $upgradeMutex=Enter-UpgradeMutex
    try{
    $phaseOneRecoveryRoot=Get-PhaseOneRecoveryRoot;$phaseTwoRecoveryRoot=Get-UpgradeRecoveryRoot
    if($phaseOneRecoveryRoot -and $phaseTwoRecoveryRoot -and (Test-Path -LiteralPath (Join-Path $phaseOneRecoveryRoot "phase-one-active.json")) -and (Test-Path -LiteralPath (Join-Path $phaseTwoRecoveryRoot "phase-two-active.json"))){Fail "Conflicting phase-one and phase-two recovery journals require manual inspection; no version was trusted."}
    [void](Recover-InterruptedPhaseOne)
    if($InjectPhaseOneCrashDuringRecovery){Fail "Phase-one recovery crash injection requires an active journal."}
    [void](Recover-InterruptedPhaseTwo)
    $script:RuntimePaths=Resolve-InstalledRuntimePaths
    $env:DEFENSECLAW_HOME=$script:RuntimePaths.DataDir;$env:DEFENSECLAW_CONFIG=$script:RuntimePaths.ConfigPath;$env:OPENCLAW_HOME=$script:RuntimePaths.OpenClawHome
    $installed=Get-InstalledVersion;Assert-InstalledSourceCoherence $installed;$target=Resolve-Target
    if((Compare-Version $target $installed)-lt 0){Fail "Downgrades unsupported."}
    Info "Installed: $installed";Info "Target:    $target"
    $workName = "defenseclaw-upgrade-" + [guid]::NewGuid().ToString("N")
    $script:WorkRoot=New-PrivateDirectory (Join-Path ([IO.Path]::GetTempPath()) $workName)
    try{
        Step "Verifying final release";$final=Stage-Release $target "final";$sourceVersion=$installed;$sourceRelease=$null;$finalHandled=$false
        if($target -eq $installed){
            Step "Version already verified"
            Ok "Authenticated the $target release contract; installed version $installed is already current. No backup, receipt, service stop, artifact install, or migration was performed."
            return
        }
        if($final.Manifest.SchemaVersion -eq 2 -and (Compare-Version $installed $target)-lt 0 -and @($final.Manifest.WindowsTestedSources)-notcontains $installed){
            $supported=@($final.Manifest.WindowsTestedSources)
            Fail "Installed version $installed is outside the tested Windows source matrix for $target. No installed state changed. Supported Windows sources: $($supported -join ', '). No tested in-place path exists from this version; remain on it and contact support for a state-aware recovery plan."
        }
        if($final.Manifest.HasBridge -and (Compare-Version $installed $final.Manifest.MinimumSource)-lt 0){
            if($script:ExplicitTarget){Fail "$target requires bridge $($final.Manifest.RequiredBridge). No installed state changed; run without -Version."}
            if(@($final.Manifest.AutoBridgeFrom)-notcontains $installed){
                $supported=@($final.Manifest.AutoBridgeFrom)
                Fail "$installed is outside auto_bridge_from. No installed state changed. Supported staged sources: $($supported -join ', '). Do not force $($final.Manifest.RequiredBridge) or infer an intermediate hop from another source's path. Remain on $installed and contact DefenseClaw support for a validated state-aware recovery path."
            }
            $bridgeVersion=$final.Manifest.RequiredBridge;Step "Verifying bridge";$bridge=Stage-Release $bridgeVersion "bridge"
            if(@($bridge.Manifest.WindowsTestedSources)-notcontains $installed){Fail "Bridge $bridgeVersion does not declare $installed in its tested Windows source matrix. No installed state changed."}
            if($bridge.Manifest.MinimumProtocol -gt 1){Fail "Bridge not protocol-1 reachable."}
            if($bridge.Manifest.ControllerProtocol -lt $final.Manifest.MinimumProtocol){Fail "Bridge cannot control target protocol."}
            Step "Verifying phase-one rollback source";$phaseOneSource=Stage-Release $installed "phase-one-source"
            Confirm-Plan "$installed -> $bridgeVersion -> fresh controller -> $target"
            Invoke-BridgeTransaction -SourceVersion $installed -Bridge $bridge -SourceRelease $phaseOneSource
            $sourceVersion=$bridgeVersion;$sourceRelease=$bridge;[void](Success-Receipt $bridgeVersion)
        }else{
            if($target -eq "0.8.4" -and (Compare-Version $installed $target)-lt 0){
                Step "Verifying phase-one rollback source";$phaseOneSource=Stage-Release $installed "phase-one-source"
                Confirm-Plan "$installed -> $target -> fresh controller"
                Invoke-BridgeTransaction -SourceVersion $installed -Bridge $final -SourceRelease $phaseOneSource
                $finalHandled=$true
            }else{
                Confirm-Plan "$installed -> $target"
                if($final.Manifest.HasBridge){Step "Verifying rollback source";$sourceRelease=Stage-Release $installed "source";if($sourceRelease.Manifest.ControllerProtocol -lt $final.Manifest.MinimumProtocol){Fail "Source cannot control target protocol."}}
            }
        }
        if($final.Manifest.HasBridge){
            if(-not $sourceRelease){Fail "Hard-cut source artifacts not staged."}
            $retained=Retain-Source $sourceRelease;Step "Fresh-controller handoff";Invoke-FreshHardCut $sourceVersion $target $retained
        }elseif(-not $finalHandled){Step "Running installed controller";Invoke-Controller $target}
        Assert-Healthy $target $final.Manifest -RequireV8:$final.Manifest.HasBridge
        Step "Upgrade complete";Ok "DefenseClaw upgraded: $installed -> $target";if($script:RetainedSourceDirectory){Info "Rollback source: $($script:RetainedSourceDirectory)"}
    }finally{
        if($script:WorkRoot -and (Test-Path -LiteralPath $script:WorkRoot)){if($KeepStaging -or $script:PreserveWorkRoot){Warn "Kept staging: $($script:WorkRoot)"}else{Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction SilentlyContinue}}
    }
    }finally{
        $script:RuntimePaths=$null
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_HOME",$savedRuntimeHome,"Process")
        [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG",$savedRuntimeConfig,"Process")
        [Environment]::SetEnvironmentVariable("OPENCLAW_HOME",$savedRuntimeOpenClaw,"Process")
        Exit-UpgradeMutex $upgradeMutex
    }
}

try{Main}catch{Write-Host "";Write-Host "Upgrade resolver stopped: $($_.Exception.Message)" -ForegroundColor Red;exit 1}
# DefenseClaw upgrade resolver complete v1
