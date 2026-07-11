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
function Get-Cli {
    $path = Join-Path (Join-Path (Join-Path (Get-Home) ".venv") "Scripts") "defenseclaw.exe"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Managed CLI not found at $path." }
    return $path
}
function Get-Python {
    $path = Join-Path (Join-Path (Join-Path (Get-Home) ".venv") "Scripts") "python.exe"
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
        $homeBytes = [Text.Encoding]::UTF8.GetBytes((Get-Home).ToLowerInvariant())
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
    $output = (& (Get-Cli) --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $output -notmatch '(?<!\d)(\d+\.\d+\.\d+)(?!\d)') { Fail "Could not determine installed version." }
    return $Matches[1]
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
    $defenseClawHome=Get-Home
    if(-not(Test-Path -LiteralPath $defenseClawHome -PathType Container)){Fail "DefenseClaw home is missing: $defenseClawHome"}
    $homeItem=Get-Item -LiteralPath $defenseClawHome -Force
    if($homeItem.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "DefenseClaw home must not be a reparse point during recovery: $defenseClawHome"}
    $root=Join-Path $defenseClawHome ".upgrade-recovery"
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
function Verify-Signature {
    param([string]$ReleaseVersion, [string]$Checksums, [string]$Signature, [string]$Certificate)
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if (-not $cosign) {
        Fail "cosign is required to authenticate bridge and hard-cut release checksums; no installed state changed."
    }
    if ((Compare-Version $ReleaseVersion "0.8.4") -ge 0) {
        $identityArguments = @(
            "--certificate-identity",
            "https://github.com/$($script:Repo)/.github/workflows/release.yaml@refs/heads/main"
        )
    } else {
        $identityArguments = @(
            "--certificate-identity-regexp",
            '^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/(main|release/.+)$'
        )
    }
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
    if (-not $schema -or -not (Test-Integer $schema.Value) -or [int64]$schema.Value -ne 1) {
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
        MinimumProtocol = $minProtocol
        ControllerProtocol = $controllerProtocol
        MigrationFailurePolicy = $policy
        RequiredMigrations = $required
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
function Stage-Release {
    param([string]$ReleaseVersion, [string]$Purpose)
    $directory = New-PrivateDirectory (Join-Path $script:WorkRoot "$Purpose-$ReleaseVersion")
    foreach ($name in @("checksums.txt","checksums.txt.sig","checksums.txt.pem")) { Download $ReleaseVersion $name (Join-Path $directory $name) }
    Verify-Signature $ReleaseVersion (Join-Path $directory "checksums.txt") (Join-Path $directory "checksums.txt.sig") (Join-Path $directory "checksums.txt.pem")
    $checksums = Read-Checksums (Join-Path $directory "checksums.txt")
    $manifestPath = Join-Path $directory "upgrade-manifest.json"; Download $ReleaseVersion "upgrade-manifest.json" $manifestPath; Assert-Hash $manifestPath "upgrade-manifest.json" $checksums
    try { $raw = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Fail "Invalid manifest JSON." }
    $manifest = Validate-Manifest $raw $ReleaseVersion
    $archValue = Get-Arch
    $wheel = "defenseclaw-$ReleaseVersion-py3-none-any.whl"
    $gateway = "defenseclaw_$($ReleaseVersion)_windows_$archValue.zip"
    foreach ($name in @($wheel,$gateway)) { $path=Join-Path $directory $name; Download $ReleaseVersion $name $path; Assert-Hash $path $name $checksums }
    Assert-SafeZip (Join-Path $directory $gateway)
    Ok "$Purpose $ReleaseVersion verified"
    return [pscustomobject]@{ Version=$ReleaseVersion; Directory=$directory; Manifest=$manifest; Wheel=$wheel; Gateway=$gateway }
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
    if($hadActive){Assert-RealFile $Snapshot.Active "Rollback target";Set-PrivateFileAcl $Snapshot.Active;[IO.File]::Move($Snapshot.Active,$displaced)}
    try{[IO.File]::Move($candidate,$Snapshot.Active)}catch{if($hadActive -and -not(Test-Path -LiteralPath $Snapshot.Active) -and (Test-Path -LiteralPath $displaced)){[IO.File]::Move($displaced,$Snapshot.Active)};throw}
    if((Get-FileHash -LiteralPath $Snapshot.Active -Algorithm SHA256).Hash.ToLowerInvariant()-ne $Snapshot.Sha256 -or (Get-OwnerDaclSddl $Snapshot.Active)-ne $Snapshot.Sddl){Fail "Restored phase-one bytes or owner/DACL mismatch: $($Snapshot.Active)"}
    if(Test-Path -LiteralPath $displaced){Set-PrivateFileAcl $displaced;try{Remove-Item -LiteralPath $displaced -Force -ErrorAction Stop}catch{Warn "Kept private rollback quarantine: $displaced"}}
    Remove-PhaseOneQuarantines $Snapshot
}
function New-PhaseOneRollbackPlan {
    param([object]$SourceRelease,[string]$SourceVersion)
    $uv=Get-Command uv -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not $uv){Fail "uv is required for bridge rollback; no installed state changed."}
    $recoveryRoot=Get-UpgradeRecoveryRoot -Create
    $planId="phase-one-"+[guid]::NewGuid().ToString("N")
    $root=New-PrivateDirectory (Join-Path $recoveryRoot $planId)
    try{
        $state=New-PrivateDirectory (Join-Path $root "state")
        $records=@()
        foreach($name in @("config.yaml",".env",".migration_state.json")){
            $active=Join-Path (Get-Home) $name;$backup=Join-Path $state ($name.TrimStart('.')+".source")
            if(Test-Path -LiteralPath $active){
                Assert-RealFile $active "Phase-one state"
                Write-SecuredRestoreCandidate -Source $active -Destination $backup -FinalSddl (Get-PrivateFileSddl)
                $records += [pscustomobject]@{Name=$name;Active=$active;Backup=$backup;Existed=$true;Sha256=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant();Sddl=(Get-OwnerDaclSddl $active)}
            }else{$records += [pscustomobject]@{Name=$name;Active=$active;Backup=$backup;Existed=$false;Sha256="";Sddl=""}}
        }
        $sourceWheelPath=Join-Path $SourceRelease.Directory $SourceRelease.Wheel
        Assert-RealFile $sourceWheelPath "Authenticated source wheel"
        $wheel=Join-Path $root "source.whl";Write-SecuredRestoreCandidate -Source $sourceWheelPath -Destination $wheel -FinalSddl (Get-PrivateFileSddl)
        $wheelSha=(Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash.ToLowerInvariant()
        $gateway=Get-Gateway;Assert-RealFile $gateway "Installed source gateway"
        $gatewayStage=New-PrivateDirectory (Join-Path $root "gateway")
        Expand-Archive -LiteralPath (Join-Path $SourceRelease.Directory $SourceRelease.Gateway) -DestinationPath $gatewayStage
        $candidates=@(Get-ChildItem -LiteralPath $gatewayStage -Filter "defenseclaw.exe" -File -Recurse)
        if($candidates.Count -ne 1){Fail "Authenticated source gateway archive is invalid"}
        $sourceGateway=Join-Path $root "source-gateway.exe";Write-SecuredRestoreCandidate -Source $candidates[0].FullName -Destination $sourceGateway -FinalSddl (Get-PrivateFileSddl)
        Remove-Item -LiteralPath $gatewayStage -Recurse -Force
        $gatewaySha=(Get-FileHash -LiteralPath $sourceGateway -Algorithm SHA256).Hash.ToLowerInvariant()
        if($gatewaySha -ne (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash.ToLowerInvariant()){Fail "Installed gateway does not match authenticated source release; no state changed."}
        Assert-VersionOutput (Get-Cli) $SourceVersion "source CLI"
        return [pscustomobject]@{PlanId=$planId;RecoveryRoot=$recoveryRoot;Root=$root;SourceVersion=$SourceVersion;Wheel=$wheel;WheelSha256=$wheelSha;Gateway=$sourceGateway;GatewaySnapshot=[pscustomobject]@{Active=$gateway;Backup=$sourceGateway;Existed=$true;Sha256=$gatewaySha;Sddl=(Get-OwnerDaclSddl $gateway)};State=$records;Uv=[string]$uv.Source;Journal=(Join-Path $recoveryRoot "phase-one-active.json")}
    }catch{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue;throw}
}
function Get-PhaseOneJournalValue {
    param([object]$Object,[string]$Name)
    $property=Property $Object $Name
    if(-not $property){Fail "Phase-one recovery journal lacks $Name."}
    return $property.Value
}
function Read-PhaseOneJournal {
    $recoveryRoot=Get-UpgradeRecoveryRoot
    if(-not $recoveryRoot){return $null}
    $journal=Join-Path $recoveryRoot "phase-one-active.json"
    if(-not(Test-Path -LiteralPath $journal)){return $null}
    Assert-PrivateFileAcl $journal
    try{$raw=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one recovery journal is invalid JSON."}
    $schema=Get-PhaseOneJournalValue $raw "schema_version"
    if(-not(Test-Integer $schema) -or [int64]$schema -ne 1){Fail "Unsupported phase-one recovery journal schema."}
    if([string](Get-PhaseOneJournalValue $raw "kind") -ne "defenseclaw-phase-one-recovery"){Fail "Invalid phase-one recovery journal kind."}
    $planId=[string](Get-PhaseOneJournalValue $raw "plan_id")
    if($planId -notmatch '^phase-one-[0-9a-f]{32}$'){Fail "Invalid phase-one recovery plan identifier."}
    $sourceVersion=[string](Get-PhaseOneJournalValue $raw "source_version");Assert-Version $sourceVersion "phase-one recovery source_version"
    $wheelSha=[string](Get-PhaseOneJournalValue $raw "wheel_sha256")
    $gatewaySha=[string](Get-PhaseOneJournalValue $raw "gateway_sha256")
    if($wheelSha -notmatch '^[0-9a-f]{64}$' -or $gatewaySha -notmatch '^[0-9a-f]{64}$'){Fail "Phase-one recovery custody digest is invalid."}
    $gatewaySddl=[string](Get-PhaseOneJournalValue $raw "gateway_sddl")
    if(-not $gatewaySddl){Fail "Phase-one recovery journal lacks gateway owner/DACL."}
    try{[void](New-FileAclFromSddl $gatewaySddl)}catch{Fail "Phase-one recovery gateway owner/DACL is invalid."}
    $root=Join-Path $recoveryRoot $planId
    Assert-PrivateDirectoryAcl -Path $root -Expected (New-PrivateDirectoryAcl)
    $wheel=Join-Path $root "source.whl";$sourceGateway=Join-Path $root "source-gateway.exe"
    foreach($custody in @(@($wheel,$wheelSha),@($sourceGateway,$gatewaySha))){
        Assert-PrivateFileAcl $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $custody[1]){Fail "Phase-one recovery custody digest changed: $($custody[0])"}
    }
    $stateRoot=Join-Path $root "state";Assert-PrivateDirectoryAcl -Path $stateRoot -Expected (New-PrivateDirectoryAcl)
    $allowed=@{"config.yaml"=$true;".env"=$true;".migration_state.json"=$true};$seen=@{};$records=@()
    $journalState=@(Get-PhaseOneJournalValue $raw "state")
    if($journalState.Count -ne 3){Fail "Phase-one recovery journal must describe exactly three state paths."}
    foreach($record in $journalState){
        $name=[string](Get-PhaseOneJournalValue $record "name")
        if(-not $allowed.ContainsKey($name) -or $seen.ContainsKey($name)){Fail "Invalid phase-one recovery state name."};$seen[$name]=$true
        $existed=Get-PhaseOneJournalValue $record "existed";if($existed -isnot [bool]){Fail "Phase-one recovery existed flag must be boolean."}
        $sha256=[string](Get-PhaseOneJournalValue $record "sha256");$sddl=[string](Get-PhaseOneJournalValue $record "sddl")
        $active=Join-Path (Get-Home) $name;$backup=Join-Path $stateRoot ($name.TrimStart('.')+".source")
        if($existed){
            if($sha256 -notmatch '^[0-9a-f]{64}$' -or -not $sddl){Fail "Phase-one recovery state metadata is incomplete: $name"}
            try{[void](New-FileAclFromSddl $sddl)}catch{Fail "Phase-one recovery owner/DACL is invalid: $name"}
            Assert-PrivateFileAcl $backup
            if((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha256){Fail "Phase-one recovery state digest changed: $name"}
        }elseif($sha256 -or $sddl -or (Test-Path -LiteralPath $backup)){Fail "Absent phase-one recovery state has unexpected custody: $name"}
        $records += [pscustomobject]@{Name=$name;Active=$active;Backup=$backup;Existed=$existed;Sha256=$sha256;Sddl=$sddl}
    }
    $uv=Get-Command uv -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
    if(-not $uv){Fail "uv is required to resume phase-one recovery; custody was preserved."}
    return [pscustomobject]@{PlanId=$planId;RecoveryRoot=$recoveryRoot;Root=$root;SourceVersion=$sourceVersion;Wheel=$wheel;WheelSha256=$wheelSha;Gateway=$sourceGateway;GatewaySnapshot=[pscustomobject]@{Active=(Get-GatewayPath);Backup=$sourceGateway;Existed=$true;Sha256=$gatewaySha;Sddl=$gatewaySddl};State=$records;Uv=[string]$uv.Source;Journal=$journal}
}
function Register-PhaseOneJournal {
    param([object]$Plan)
    if(Test-Path -LiteralPath $Plan.Journal){Fail "Another phase-one recovery journal is active; no installed state changed."}
    $journalState=@($Plan.State|ForEach-Object{[ordered]@{name=$_.Name;existed=$_.Existed;sha256=$_.Sha256;sddl=$_.Sddl}})
    $document=[ordered]@{schema_version=1;kind="defenseclaw-phase-one-recovery";plan_id=$Plan.PlanId;source_version=$Plan.SourceVersion;wheel_sha256=$Plan.WheelSha256;gateway_sha256=$Plan.GatewaySnapshot.Sha256;gateway_sddl=$Plan.GatewaySnapshot.Sddl;state=$journalState}
    $candidate=$Plan.Journal+"."+[guid]::NewGuid().ToString("N")+".tmp"
    try{
        Write-PrivateUtf8File -Path $candidate -Content (($document|ConvertTo-Json -Depth 6 -Compress)+"`n")
        [IO.File]::Move($candidate,$Plan.Journal)
        Assert-PrivateFileAcl $Plan.Journal
        $loaded=Read-PhaseOneJournal
        if(-not $loaded -or $loaded.PlanId -ne $Plan.PlanId){Fail "Phase-one recovery journal readback failed."}
    }catch{Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue;throw}
}
function Complete-PhaseOneJournal {
    param([object]$Plan)
    Assert-PrivateFileAcl $Plan.Journal
    try{$raw=Get-Content -LiteralPath $Plan.Journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Cannot clear invalid phase-one recovery journal."}
    if([string](Get-PhaseOneJournalValue $raw "plan_id") -ne $Plan.PlanId){Fail "Refusing to clear a different phase-one recovery journal."}
    Remove-Item -LiteralPath $Plan.Journal -Force -ErrorAction Stop
    try{Remove-Item -LiteralPath $Plan.Root -Recurse -Force -ErrorAction Stop}catch{Warn "Healthy phase-one recovery custody remains at $($Plan.Root)"}
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
function Invoke-TestHardCrash {
    param([string]$Label)
    if(-not $TestMode){Fail "Hard-crash injection requires TestMode."}
    Write-Host "  ! Injecting abrupt process termination: $Label" -ForegroundColor Yellow
    [Diagnostics.Process]::GetCurrentProcess().Kill()
    [Threading.Thread]::Sleep([Timeout]::Infinite)
}
function Restore-PhaseOneSource {
    param([object]$Plan)
    try{
        if(Test-Path -LiteralPath $Plan.GatewaySnapshot.Active -PathType Leaf){& $Plan.GatewaySnapshot.Active stop *> $null}
        & $Plan.Uv pip install --python (Get-Python) --quiet --no-deps --reinstall $Plan.Wheel *> $null
        if($LASTEXITCODE -ne 0){Fail "Could not restore source controller wheel"}
        $restoredStateCount=0
        foreach($snapshot in $Plan.State){
            Publish-PhaseOneSnapshot -Snapshot $snapshot;$restoredStateCount++
            if($script:RecoveringPhaseOneJournal -and $InjectPhaseOneCrashDuringRecovery -and $restoredStateCount -eq 1){Invoke-TestHardCrash "mid phase-one journal recovery"}
        }
        Publish-PhaseOneSnapshot -Snapshot $Plan.GatewaySnapshot
        Assert-VersionOutput (Get-Cli) $Plan.SourceVersion "restored CLI"
        Assert-VersionOutput (Get-Gateway) $Plan.SourceVersion "restored gateway"
        & (Get-Gateway) start *> $null;if($LASTEXITCODE -ne 0){Fail "Restored source gateway did not start"}
        & (Get-Gateway) status *> $null;if($LASTEXITCODE -ne 0){Fail "Restored source gateway is unhealthy"}
        return $true
    }catch{Warn "Phase-one automatic rollback failed: $($_.Exception.Message)";$script:PreserveWorkRoot=$true;return $false}
}
function Recover-InterruptedPhaseOne {
    $plan=Read-PhaseOneJournal
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
    $keys=@("schema_version","source_version","target_version","os_name","data_dir","backup_dir","receipt_path","rollback_wheel_path","rollback_wheel_sha256","rollback_gateway_path","rollback_gateway_sha256","active_gateway_path","gateway_snapshot","state_files")
    Assert-ExactJsonKeys -Object $raw -Names $keys -Label "Phase-two recovery journal"
    if(-not(Test-Integer $raw.schema_version) -or [int64]$raw.schema_version -ne 1){Fail "Unsupported phase-two recovery journal schema."}
    $sourceVersion=[string]$raw.source_version;$targetVersion=[string]$raw.target_version
    Assert-Version $sourceVersion "phase-two recovery source_version";Assert-Version $targetVersion "phase-two recovery target_version"
    if([string]$raw.os_name -ne "windows"){Fail "Phase-two recovery journal is not for Windows."}
    $dataDir=[IO.Path]::GetFullPath([string]$raw.data_dir)
    if(-not $dataDir.Equals([IO.Path]::GetFullPath((Get-Home)),[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two recovery journal targets a different DefenseClaw home."}
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
    return [pscustomobject]@{Journal=$journal;SourceVersion=$sourceVersion;TargetVersion=$targetVersion;Wheel=$wheel;Receipt=$receipt;Status=$status}
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
    & (Get-Python) -I -c $leaseWrapper $leasePath ([string]$HealthTimeout) $Uv pip install --python (Get-Python) --quiet --no-deps --reinstall $Wheel *> $null
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
            & (Get-Gateway) status *> $null;if($LASTEXITCODE -ne 0){Fail "Terminal phase-two journal cannot be cleared before exact health succeeds."}
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
    & (Get-Python) -I -c $recoveryCode
    if($LASTEXITCODE -ne 0){Fail "Bridge recovery entrypoint could not complete interrupted phase two; journal remains active."}
    if(Test-Path -LiteralPath $plan.Journal){Fail "Bridge recovery returned success without clearing the phase-two journal."}
    Assert-VersionOutput (Get-Cli) $plan.SourceVersion "recovered bridge CLI";Assert-VersionOutput (Get-Gateway) $plan.SourceVersion "recovered bridge gateway"
    & (Get-Gateway) status *> $null;if($LASTEXITCODE -ne 0){Fail "Recovered phase-two bridge is unhealthy."}
    Ok "Recovered interrupted phase-two hard cut to healthy DefenseClaw $($plan.SourceVersion)"
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
    $module = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Get-Home) ".venv") "Lib") "site-packages") "defenseclaw\commands") "cmd_upgrade.py"
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
    & (Get-Gateway) status *> $null
    if($LASTEXITCODE -ne 0){Fail "Gateway unhealthy after $Expected."}
    [void](Success-Receipt $Expected)
    if($RequireV8){
        $config=Get-Content -LiteralPath (Join-Path (Get-Home) "config.yaml") -Raw -Encoding UTF8
        if($config -notmatch '(?m)^\s*config_version:\s*8\s*$'){Fail "config_version is not 8."}
        $cursor=Get-Content -LiteralPath (Join-Path (Get-Home) ".migration_state.json") -Raw -Encoding UTF8|ConvertFrom-Json
        foreach($migration in @($Manifest.RequiredMigrations)){if(@($cursor.applied) -notcontains [string]$migration){Fail "Cursor missing $migration."}}
    }
}
function Assert-RunningComponents {
    param([string]$Expected)
    Assert-VersionOutput (Get-Cli) $Expected "CLI"
    Assert-VersionOutput (Get-Gateway) $Expected "Gateway"
    & (Get-Gateway) status *> $null
    if($LASTEXITCODE -ne 0){Fail "Gateway unhealthy after initial bridge install $Expected."}
}
function Retain-Source {
    param([object]$Release)
    $root=Join-Path (Get-Home) "backups"
    if(-not(Test-Path -LiteralPath $root)){[void](New-PrivateDirectory $root)}else{Set-PrivateDirectoryAcl $root}
    $destination=New-PrivateDirectory (Join-Path $root ("staged-bridge-"+[guid]::NewGuid().ToString("N")))
    foreach($file in Get-ChildItem -LiteralPath $Release.Directory -File){Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $destination $file.Name)}
    foreach($name in @("checksums.txt","checksums.txt.sig","checksums.txt.pem","upgrade-manifest.json",$Release.Wheel,$Release.Gateway)){if(-not(Test-Path -LiteralPath (Join-Path $destination $name)-PathType Leaf)){Fail "Retained set lacks $name."}}
    $script:RetainedSourceDirectory=$destination; return $destination
}
function Assert-RollbackCallSites {
    $module=Join-Path (Join-Path (Join-Path (Join-Path (Join-Path (Get-Home) ".venv") "Lib") "site-packages") "defenseclaw\commands") "cmd_upgrade.py"
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
    try{
        $env:DEFENSECLAW_STAGED_UPGRADE="1";$env:DEFENSECLAW_STAGED_BRIDGE_VERSION=$Source;$env:DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR=$Artifacts
        & (Get-Python) -I -m defenseclaw.main upgrade --yes --version $Target --health-timeout $HealthTimeout
        if($LASTEXITCODE -ne 0){Fail "Fresh controller failed upgrading to $Target."}
    }finally{
        foreach($name in $names){if($null -eq $saved[$name]){Remove-Item "Env:$name" -ErrorAction SilentlyContinue}else{Set-Item "Env:$name" $saved[$name]}}
    }
}

function Invoke-BridgeTransaction {
    param([string]$SourceVersion,[object]$Bridge,[object]$SourceRelease)
    $plan=New-PhaseOneRollbackPlan -SourceRelease $SourceRelease -SourceVersion $SourceVersion
    try{Register-PhaseOneJournal $plan}catch{Remove-Item -LiteralPath $plan.Root -Recurse -Force -ErrorAction SilentlyContinue;throw}
    try{
        Step "Installing bridge";Invoke-Controller $Bridge.Version;Assert-RunningComponents $Bridge.Version
        if($InjectPhaseOneCrashAfterMutation){Invoke-TestHardCrash "after phase-one bridge mutation"}
        if($InjectPhaseOneFailureAfterMutation){Fail "Injected phase-one failure after bridge mutation"}
        Step "Revalidating bridge with its fresh controller";Invoke-Controller $Bridge.Version;Assert-Healthy $Bridge.Version $Bridge.Manifest
        Complete-PhaseOneJournal $plan
    }catch{
        $original=$_.Exception.Message
        if(Restore-PhaseOneSource $plan){Complete-PhaseOneJournal $plan;Fail "Bridge phase failed; restored healthy DefenseClaw $SourceVersion. Original failure: $original"}
        Fail "Bridge phase failed and automatic source restoration was incomplete. Recovery artifacts: $($plan.Root). Original failure: $original"
    }
}

function Main {
    if($Help){Show-Usage;return}
    if($TestMode -and -not $script:ExplicitTarget -and -not $LatestVersionOverride){Fail "TestMode latest path needs LatestVersionOverride."}
    if(($InjectPhaseOneFailureAfterMutation -or $InjectPhaseOneCrashAfterMutation -or $InjectPhaseOneCrashDuringRecovery) -and -not $TestMode){Fail "Phase-one fault injection requires TestMode."}
    $upgradeMutex=Enter-UpgradeMutex
    try{
    $activeRecoveryRoot=Get-UpgradeRecoveryRoot
    if($activeRecoveryRoot -and (Test-Path -LiteralPath (Join-Path $activeRecoveryRoot "phase-one-active.json")) -and (Test-Path -LiteralPath (Join-Path $activeRecoveryRoot "phase-two-active.json"))){Fail "Conflicting phase-one and phase-two recovery journals require manual inspection; no version was trusted."}
    [void](Recover-InterruptedPhaseOne)
    [void](Recover-InterruptedPhaseTwo)
    if($InjectPhaseOneCrashDuringRecovery){Fail "Phase-one recovery crash injection requires an active journal."}
    $installed=Get-InstalledVersion;$target=Resolve-Target
    if((Compare-Version $target $installed)-lt 0){Fail "Downgrades unsupported."}
    Info "Installed: $installed";Info "Target:    $target"
    $workName = "defenseclaw-upgrade-" + [guid]::NewGuid().ToString("N")
    $script:WorkRoot=New-PrivateDirectory (Join-Path ([IO.Path]::GetTempPath()) $workName)
    try{
        Step "Verifying final release";$final=Stage-Release $target "final";$sourceVersion=$installed;$sourceRelease=$null;$finalHandled=$false
        if($final.Manifest.HasBridge -and (Compare-Version $installed $final.Manifest.MinimumSource)-lt 0){
            if($script:ExplicitTarget){Fail "$target requires bridge $($final.Manifest.RequiredBridge). No installed state changed; run without -Version."}
            if(@($final.Manifest.AutoBridgeFrom)-notcontains $installed){Fail "$installed is outside auto_bridge_from. No installed state changed."}
            $bridgeVersion=$final.Manifest.RequiredBridge;Step "Verifying bridge";$bridge=Stage-Release $bridgeVersion "bridge"
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
    }finally{Exit-UpgradeMutex $upgradeMutex}
}

try{Main}catch{Write-Host "";Write-Host "Upgrade resolver stopped: $($_.Exception.Message)" -ForegroundColor Red;exit 1}
