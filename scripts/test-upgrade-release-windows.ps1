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
    Native Windows release gate for the manifest-driven upgrade path.
.DESCRIPTION
    Builds an isolated release server from a sealed candidate and real
    published Windows releases.  For a hard-cut candidate it proves that an
    explicit published-source -> target request is side-effect free, injects a
    post-mutation bridge failure, kills bridge/recovery processes twice to prove
    journaled re-entry, and proves exact healthy source restoration. It then
    proves both the automatic source -> 0.8.4 -> target route and the direct
    0.8.4 -> target route plus phase-two rollback. The bridge is never
    synthesized from source.

    A 0.8.4 bridge candidate is handled as the release immediately before the
    hard cut: the gate proves the fresh-install guard and a real published-
    source -> candidate upgrade. Once 0.8.4 is published, a 0.8.5+ candidate
    takes the full hard-cut branch automatically from its signed manifest.
.PARAMETER ReleaseDir
    Flat sealed candidate directory (normally release-candidate/dist).
.PARAMETER TargetVersion
    Canonical candidate release version, X.Y.Z.
.PARAMETER SourceVersion
    Exact published pre-bridge baseline to exercise. The version must be listed
    in release/upgrade-baselines.json. If omitted, the newest published
    pre-bridge baseline is used for local compatibility; release CI should pass
    every pre-bridge baseline through a job matrix.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseDir,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')]
    [string]$TargetVersion,

    [ValidatePattern('^$|^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')]
    [string]$SourceVersion = "",

    [ValidateRange(1, 600)]
    [int]$HealthTimeout = 60,

    [switch]$KeepWorkDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Repository = "cisco-ai-defense/defenseclaw"
$script:OldBaseline = ""
$script:BridgeVersion = "0.8.4"
$script:HardCutVersion = "0.8.5"
$script:PublishedBaselines = @()
$script:PublishedPreBridgeBaselines = @()
$script:PublishedWindowsBaselines = @()
$script:BaselineConfigVersions = @{}
$script:SourceVersionSpecified = $PSBoundParameters.ContainsKey("SourceVersion")
$script:WorkRoot = ""
$script:ReleaseRoot = ""
$script:ServerProcess = $null
$script:ServerBaseUrl = ""
$script:Cases = New-Object System.Collections.Generic.List[object]
$script:Sentinels = New-Object System.Collections.Generic.List[object]
$script:SavedEnvironment = @{}
$script:SavedUserPath = $null
$script:SavedUserPathCaptured = $false

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "OK: $Message" -ForegroundColor Green
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Compare-Version {
    param([string]$Left, [string]$Right)
    return ([version]$Left).CompareTo([version]$Right)
}

function Test-Integer {
    param([object]$Value)
    return $Value -is [sbyte] -or $Value -is [byte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
}

function Get-Property {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    return $Object.PSObject.Properties[$Name]
}

function Read-UpgradeBaselinePolicy {
    $path = Join-Path (Join-Path $PSScriptRoot "..") "release\upgrade-baselines.json"
    try {
        $policy = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Fail "Could not read the release upgrade-baseline policy: $path"
    }
    $schema = Get-Property $policy "schema_version"
    $published = Get-Property $policy "published_baselines"
    $configVersions = Get-Property $policy "published_baseline_config_versions"
    $platforms = Get-Property $policy "platform_published_baselines"
    $policyNames = @($policy.PSObject.Properties.Name)
    $expectedPolicyNames = @(
        "schema_version",
        "published_baselines",
        "published_baseline_config_versions",
        "platform_published_baselines"
    )
    if ((@($policyNames | Sort-Object) -join "`n") -ne (@($expectedPolicyNames | Sort-Object) -join "`n") -or
        -not $schema -or -not (Test-Integer $schema.Value) -or [int64]$schema.Value -ne 2 -or
        -not $published -or -not $configVersions -or -not $platforms) {
        Fail "Upgrade baseline policy must be a schema_version 2 object"
    }
    $values = @($published.Value)
    if ($values.Count -eq 0) { Fail "Upgrade baseline policy is empty" }
    foreach ($value in $values) {
        if ($value -isnot [string] -or $value -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
            Fail "Upgrade baseline policy contains a non-canonical version"
        }
    }
    if (@($values | Sort-Object -Unique).Count -ne $values.Count) {
        Fail "Upgrade baseline policy contains duplicate versions"
    }
    $configProperties = @($configVersions.Value.PSObject.Properties)
    if ($configProperties.Count -ne $values.Count) {
        Fail "Published baseline config-version keys must exactly match published_baselines"
    }
    $script:BaselineConfigVersions = @{}
    foreach ($value in $values) {
        $property = Get-Property $configVersions.Value ([string]$value)
        if (-not $property -or -not (Test-Integer $property.Value)) {
            Fail "Published baseline $value has no reviewed config version in {5,6,7}"
        }
        $configVersion = [int64]$property.Value
        if ($configVersion -notin @(5, 6, 7)) {
            Fail "Published baseline $value has no reviewed config version in {5,6,7}"
        }
        $expectedConfigVersion = if ((Compare-Version ([string]$value) "0.8.3") -ge 0) {
            7
        } elseif ((Compare-Version ([string]$value) "0.7.1") -ge 0) {
            6
        } else {
            5
        }
        if ($configVersion -ne $expectedConfigVersion) {
            Fail "Published baseline $value must seed historical config version $expectedConfigVersion"
        }
        $script:BaselineConfigVersions[[string]$value] = $configVersion
    }
    foreach ($property in $configProperties) {
        if ($values -notcontains [string]$property.Name) {
            Fail "Published baseline config-version policy contains an unknown version"
        }
    }
    if ($script:BaselineConfigVersions.ContainsKey($script:BridgeVersion) -and
        [int]$script:BaselineConfigVersions[$script:BridgeVersion] -ne 7) {
        Fail "Published bridge $($script:BridgeVersion) must use config version 7"
    }
    $platformNames = @($platforms.Value.PSObject.Properties.Name)
    $windowsProperty = Get-Property $platforms.Value "windows"
    if ($platformNames.Count -ne 1 -or $platformNames -notcontains "windows" -or -not $windowsProperty) {
        Fail "Upgrade baseline policy must contain exactly the reviewed Windows subset"
    }
    $windowsValues = @($windowsProperty.Value)
    if ($windowsValues.Count -eq 0 -or @($windowsValues | Sort-Object -Unique).Count -ne $windowsValues.Count) {
        Fail "Reviewed Windows baseline policy is empty or contains duplicates"
    }
    foreach ($value in $windowsValues) {
        if ($value -isnot [string] -or $values -notcontains ([string]$value)) {
            Fail "Reviewed Windows baseline policy must be a canonical subset of published_baselines"
        }
    }
    $globalEligible = @(
        $values |
            Where-Object { (Compare-Version ([string]$_) $script:BridgeVersion) -lt 0 } |
            Sort-Object { [version]$_ } -Descending
    )
    $windowsEligible = @(
        $windowsValues |
            Where-Object { (Compare-Version ([string]$_) $script:BridgeVersion) -lt 0 } |
            Sort-Object { [version]$_ } -Descending
    )
    if ($globalEligible.Count -eq 0 -or $windowsEligible.Count -eq 0) {
        Fail "Upgrade baseline policy has no published global/Windows pre-bridge source"
    }
    $script:PublishedBaselines = @($values | ForEach-Object { [string]$_ })
    $script:PublishedPreBridgeBaselines = @($globalEligible | ForEach-Object { [string]$_ })
    $script:PublishedWindowsBaselines = @($windowsValues | ForEach-Object { [string]$_ })
    if ($script:SourceVersionSpecified -and -not $SourceVersion) {
        Fail "SourceVersion cannot be empty when explicitly supplied"
    }
    if ($SourceVersion) {
        if ($windowsValues -notcontains $SourceVersion) {
            Fail "SourceVersion $SourceVersion is not in the reviewed Windows published-baseline policy"
        }
        if ((Compare-Version $SourceVersion $script:BridgeVersion) -ge 0) {
            Fail "SourceVersion must be a pre-bridge release older than $($script:BridgeVersion)"
        }
        $script:OldBaseline = $SourceVersion
    } else {
        $script:OldBaseline = [string]$windowsEligible[0]
    }
}

function Get-PublishedBaselineConfigVersion {
    param([Parameter(Mandatory = $true)][string]$Version)
    if ($null -eq $script:BaselineConfigVersions -or -not $script:BaselineConfigVersions.ContainsKey($Version)) {
        Fail "No reviewed config version exists for published baseline $Version"
    }
    return [int]$script:BaselineConfigVersions[$Version]
}

function Get-CurrentSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User
}

function Set-PrivatePathAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    $owner = Get-CurrentSid
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    if ($Directory) {
        $security = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $security = New-Object Security.AccessControl.FileSecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $security.SetOwner($owner)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner, $system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $owner = (Get-CurrentSid).Value
    $actualOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or $actualOwner -ne $owner) {
        Fail "Directory is not owner-controlled with a protected DACL: $Path"
    }
    $allowed = @{}
    foreach ($sidValue in @($owner, "S-1-5-18", "S-1-5-32-544")) {
        $allowed[$sidValue] = $true
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            Fail "Private directory contains a non-allow ACE: $Path"
        }
        if (-not $allowed.ContainsKey($sid)) {
            Fail "Private directory grants access to an unexpected SID ($sid): $Path"
        }
    }
}
function Assert-PrivateFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        Fail "Private custody is not a real file: $Path"
    }
    $acl=Get-Acl -LiteralPath $Path
    $owner=(Get-CurrentSid).Value
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner){
        Fail "File is not owner-controlled with a protected DACL: $Path"
    }
    $allowed=@{$owner=$true;"S-1-5-18"=$true;"S-1-5-32-544"=$true}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not $allowed.ContainsKey($rule.IdentityReference.Value)){
            Fail "Private file grants unexpected access: $Path"
        }
    }
}

function New-PrivateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Fail "Refusing to reuse private test path: $Path"
    }
    New-Item -ItemType Directory -Path $Path | Out-Null
    try {
        Set-PrivatePathAcl -Path $Path -Directory
        Assert-PrivateDirectoryAcl -Path $Path
    } catch {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    return [IO.Path]::GetFullPath($Path)
}
function New-PrivateDecodedArtifact {
    param([Parameter(Mandatory = $true)][string]$Source,[Parameter(Mandatory = $true)][string]$Destination)

    if(Test-Path -LiteralPath $Destination){Fail "Protected-artifact test destination already exists: $Destination"}
    $magic=(New-Object Text.UTF8Encoding($false,$true)).GetBytes("DEFENSECLAW-PROTECTED-ARTIFACT-V1`n")
    $sourceItem=Get-Item -LiteralPath $Source -Force
    if($sourceItem.PSIsContainer -or ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $sourceItem.Length -le $magic.Length -or $sourceItem.Length -gt 4294967296){Fail "Protected artifact envelope has an invalid identity or size: $Source"}
    $sourceStream=$null;$destinationStream=$null;$hash=$null;$created=$false
    try{
        $sourceStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $destinationStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$created=$true
        $observed=New-Object byte[] $magic.Length;$offset=0
        while($offset -lt $observed.Length){$count=$sourceStream.Read($observed,$offset,$observed.Length-$offset);if($count -le 0){Fail "Protected artifact envelope is truncated"};$offset += $count}
        for($index=0;$index -lt $magic.Length;$index++){if($observed[$index] -ne $magic[$index]){Fail "Protected artifact envelope magic changed"}}
        $hash=[Security.Cryptography.SHA256]::Create();$encoded=New-Object byte[] 1048576;$decoded=New-Object byte[] 1048576;$total=[int64]0
        while(($count=$sourceStream.Read($encoded,0,$encoded.Length)) -gt 0){
            for($index=0;$index -lt $count;$index++){$decoded[$index]=[byte]($encoded[$index] -bxor 0xA5)}
            $destinationStream.Write($decoded,0,$count);[void]$hash.TransformBlock($decoded,0,$count,$decoded,0);$total += $count
        }
        if($total -le 0){Fail "Protected artifact envelope has no decoded payload"}
        [void]$hash.TransformFinalBlock((New-Object byte[] 0),0,0)
        $expected=[BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
        $destinationStream.Flush($true)
    }catch{
        if($destinationStream){$destinationStream.Dispose();$destinationStream=$null}
        if($sourceStream){$sourceStream.Dispose();$sourceStream=$null}
        if($hash){$hash.Dispose();$hash=$null}
        if($created){Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue}
        throw
    }finally{
        if($destinationStream){$destinationStream.Dispose()};if($sourceStream){$sourceStream.Dispose()};if($hash){$hash.Dispose()}
    }
    Set-PrivatePathAcl -Path $Destination;Assert-PrivateFileAcl -Path $Destination
    if((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){Fail "Decoded protected artifact digest changed"}
    return [IO.Path]::GetFullPath($Destination)
}

function Assert-RequiredCommands {
    if ($env:OS -ne "Windows_NT") {
        Fail "This release gate must run on native Windows."
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Fail "The native release gate currently requires a 64-bit Windows runner."
    }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) {
        $env:PROCESSOR_ARCHITEW6432
    } else {
        $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]$architecture -ne "AMD64") {
        Fail "This gate verifies the required windows_amd64 release artifacts; runner architecture is $architecture"
    }
    foreach ($name in @("pwsh", "python", "uv", "cosign")) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $command) { Fail "Required release-gate command is unavailable: $name" }
        Set-Variable -Scope Script -Name ("Command" + $name) -Value ([string]$command.Source)
    }
    $curl = Get-Command "curl.exe" -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $curl) { Fail "Required release-gate command is unavailable: curl.exe" }
    $script:Commandcurl = [string]$curl.Source
}

function Save-ProcessEnvironment {
    $names = @(
        "USERPROFILE", "HOME", "DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG",
        "OPENCLAW_HOME", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
        "PATH", "TEMP", "TMP", "PYTHONDONTWRITEBYTECODE",
        "PYTHONUTF8", "UV_NO_CONFIG", "NO_COLOR",
        "DEFENSECLAW_UPGRADE_TEST_MODE", "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "DEFENSECLAW_STAGED_UPGRADE", "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR", "DEFENSECLAW_STAGED_BRIDGE_BACKUP",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "DEFENSECLAW_TEST_TARGET_WHEEL",
        "DEFENSECLAW_TEST_WHEEL_CRASH_MARKER", "DEFENSECLAW_TEST_PACKAGE_DIR",
        "DEFENSECLAW_TEST_CLI_EXE", "DEFENSECLAW_TEST_WHEEL_RELEASE",
        "DEFENSECLAW_TEST_WHEEL_CONSUMED", "DEFENSECLAW_TEST_PHASE1_MARKER",
        "DEFENSECLAW_TEST_PHASE1_RELEASE", "DEFENSECLAW_TEST_PHASE1_CONSUMED",
        "DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER", "GITHUB_TOKEN", "GH_TOKEN"
    )
    foreach ($name in $names) {
        $script:SavedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    $script:SavedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $script:SavedUserPathCaptured = $true
}

function Restore-ProcessEnvironment {
    foreach ($name in $script:SavedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name], "Process")
    }
    if ($script:SavedUserPathCaptured) {
        $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentUserPath -ne $script:SavedUserPath) {
            [Environment]::SetEnvironmentVariable("Path", $script:SavedUserPath, "User")
        }
    }
}

function Clear-UpgradeTestEnvironment {
    foreach ($name in @(
        "DEFENSECLAW_UPGRADE_TEST_MODE", "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "DEFENSECLAW_STAGED_UPGRADE", "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR", "DEFENSECLAW_STAGED_BRIDGE_BACKUP",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "DEFENSECLAW_TEST_TARGET_WHEEL",
        "DEFENSECLAW_TEST_WHEEL_CRASH_MARKER", "DEFENSECLAW_TEST_PACKAGE_DIR",
        "DEFENSECLAW_TEST_CLI_EXE", "DEFENSECLAW_TEST_WHEEL_RELEASE",
        "DEFENSECLAW_TEST_WHEEL_CONSUMED", "DEFENSECLAW_TEST_PHASE1_MARKER",
        "DEFENSECLAW_TEST_PHASE1_RELEASE", "DEFENSECLAW_TEST_PHASE1_CONSUMED",
        "DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER", "GITHUB_TOKEN", "GH_TOKEN"
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}

function Set-CaseEnvironment {
    param([Parameter(Mandatory = $true)][object]$Case)

    $env:USERPROFILE = $Case.Home
    $env:HOME = $Case.Home
    $env:DEFENSECLAW_HOME = $Case.Controller
    if($Case.ConfigExplicit){$env:DEFENSECLAW_CONFIG=$Case.ConfigPath}else{[Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG", $null, "Process")}
    $env:OPENCLAW_HOME = $Case.OpenClawHome
    $env:APPDATA = $Case.AppData
    $env:LOCALAPPDATA = $Case.LocalAppData
    $env:XDG_CONFIG_HOME = $Case.XdgConfig
    $originalPath = [string]$script:SavedEnvironment["PATH"]
    $env:PATH = $Case.Bin + [IO.Path]::PathSeparator + $originalPath
    $env:TEMP = $Case.Temp
    $env:TMP = $Case.Temp
    $env:PYTHONDONTWRITEBYTECODE = "1"
    $env:PYTHONUTF8 = "1"
    $env:UV_NO_CONFIG = "1"
    $env:NO_COLOR = "1"
    Clear-UpgradeTestEnvironment
}

function Get-ReleasePayloadNamesFromManifest {
    param([string]$ManifestPath,[string]$Version)
    try{$manifest=Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Invalid release manifest"}
    if([string]$manifest.release_version -ne $Version){Fail "Release manifest version mismatch"}
    if((Compare-Version $Version $script:BridgeVersion)-lt 0){
        return @("defenseclaw-$Version-py3-none-any.whl","defenseclaw_${Version}_windows_amd64.zip")
    }
    if([int]$manifest.schema_version -ne 2){Fail "Modern release manifest must use schema 2"}
    $wheel=[string]$manifest.release_artifacts.wheel
    $gateway=[string]$manifest.release_artifacts.gateways.windows.amd64
    if($wheel -ne "defenseclaw-$Version-2-py3-none-any.dcwheel" -or $gateway -ne "defenseclaw_$($Version)_protocol2_windows_amd64.dcgateway"){
        Fail "Modern release manifest does not bind protected Windows artifacts"
    }
    return @(
        $wheel,
        $gateway,
        "defenseclaw-$Version-py3-none-any.whl",
        "defenseclaw_${Version}_windows_amd64.zip"
    )
}

function Assert-ReleaseSet {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $fixedNames = @(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json"
    )
    if((Compare-Version $Version $script:HardCutVersion)-ge 0){$fixedNames += "release-provenance.json"}
    foreach ($name in $fixedNames) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
            Fail "Release $Version is missing $name"
        }
    }

    $payloadNames=@(Get-ReleasePayloadNamesFromManifest -ManifestPath (Join-Path $Directory "upgrade-manifest.json") -Version $Version)
    foreach($name in $payloadNames){
        if(-not(Test-Path -LiteralPath (Join-Path $Directory $name)-PathType Leaf)){Fail "Release $Version is missing $name"}
    }
    $authenticator = Join-Path $PSScriptRoot "historical_release_auth.py"
    $pinPolicy = Join-Path (Join-Path $PSScriptRoot "..") "release\historical-artifact-digests.json"
    $authenticationArguments = @(
        $authenticator,
        "--version", $Version,
        "--release-dir", $Directory,
        "--cosign", $script:Commandcosign,
        "--pin-policy", $pinPolicy
    )
    $authenticatedNames=@("upgrade-manifest.json")+$payloadNames
    if((Compare-Version $Version $script:HardCutVersion)-ge 0){$authenticatedNames += "release-provenance.json"}
    foreach ($name in $authenticatedNames) {
        $authenticationArguments += @("--asset", $name)
    }
    $authenticationOutput = @(& $script:Commandpython @authenticationArguments 2>&1)
    $authenticationStatus = $LASTEXITCODE
    foreach ($line in $authenticationOutput) { Write-Host ([string]$line) }
    if ($authenticationStatus -ne 0) {
        Fail "Signed release authentication failed for $Version"
    }
    if((Compare-Version $Version $script:BridgeVersion)-ge 0){
        [void](Add-Type -AssemblyName System.IO.Compression.FileSystem)
        $protectedWheel=Join-Path $Directory "defenseclaw-$Version-2-py3-none-any.dcwheel"
        $protectedGateway=Join-Path $Directory "defenseclaw_$($Version)_protocol2_windows_amd64.dcgateway"
        foreach($path in @($protectedWheel,$protectedGateway)){
            try{
                $sentinel=[IO.Compression.ZipFile]::OpenRead($path)
                $sentinel.Dispose()
                Fail "Protected release artifact remained directly ZIP-consumable: $path"
            }catch [IO.InvalidDataException]{}
        }
        & $script:Commanduv --no-config pip install --dry-run --system --python $script:Commandpython --no-python-downloads $protectedWheel *> $null
        if($LASTEXITCODE -eq 0){Fail "Protected .dcwheel remained directly installable by uv/pip"}
        $expandDestination=Join-Path $script:WorkRoot ("protected-expand-refusal-"+[guid]::NewGuid().ToString("N"))
        try{
            $expanded=$false
            try{[void](Expand-Archive -LiteralPath $protectedGateway -DestinationPath $expandDestination -ErrorAction Stop);$expanded=$true}catch{}
            if($expanded){Fail "Protected .dcgateway remained directly consumable by Expand-Archive"}
        }finally{Remove-Item -LiteralPath $expandDestination -Recurse -Force -ErrorAction SilentlyContinue}
        foreach($name in @("defenseclaw-$Version-py3-none-any.whl","defenseclaw_${Version}_windows_amd64.zip")){
            try{
                $sentinel=[IO.Compression.ZipFile]::OpenRead((Join-Path $Directory $name))
                $sentinel.Dispose()
                Fail "Canonical refusal envelope became installable: $name"
            }catch [IO.InvalidDataException]{}
        }
    }
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $Directory "upgrade-manifest.json") `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Fail "Release $Version has invalid upgrade-manifest.json"
    }
    $schema = Get-Property $manifest "schema_version"
    $release = Get-Property $manifest "release_version"
    $expectedSchema = if ((Compare-Version $Version $script:BridgeVersion) -ge 0) { 2 } else { 1 }
    if (-not $schema -or [int]$schema.Value -ne $expectedSchema -or -not $release -or [string]$release.Value -ne $Version) {
        Fail "Release $Version has a mismatched upgrade manifest"
    }
    return $manifest
}

function Assert-SealedCandidateResolver {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $resolver = Join-Path $Directory "defenseclaw-upgrade.ps1"
    if (-not (Test-Path -LiteralPath $resolver -PathType Leaf)) {
        Fail "Sealed candidate PowerShell resolver is missing: $resolver"
    }
    Assert-PrivateFileAcl -Path $resolver
    $pattern = '^([0-9a-f]{64})  defenseclaw-upgrade\.ps1$'
    $entries = @(
        Get-Content -LiteralPath (Join-Path $Directory "checksums.txt") -Encoding UTF8 |
            ForEach-Object {
                $match = [regex]::Match([string]$_, $pattern)
                if ($match.Success) { $match.Groups[1].Value }
            }
    )
    if ($entries.Count -ne 1) {
        Fail "Sealed checksums.txt must bind defenseclaw-upgrade.ps1 exactly once"
    }
    $actual = (Get-FileHash -LiteralPath $resolver -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne [string]$entries[0]) {
        Fail "Sealed candidate PowerShell resolver digest changed"
    }
    try {
        $content = [IO.File]::ReadAllText($resolver, (New-Object Text.UTF8Encoding($false, $true)))
    } catch {
        Fail "Sealed candidate PowerShell resolver is not strict UTF-8"
    }
    if ($content.TrimEnd([char[]]"`r`n").EndsWith("# DefenseClaw upgrade resolver complete v1") -ne $true) {
        Fail "Sealed candidate PowerShell resolver is incomplete"
    }
    return $resolver
}

function Copy-CandidateRelease {
    $resolved = (Resolve-Path -LiteralPath $ReleaseDir).Path
    $destination = New-PrivateDirectory -Path (Join-Path $script:ReleaseRoot $TargetVersion)
    $fixed=@(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json",
        "defenseclaw-upgrade.ps1"
    )
    if((Compare-Version $TargetVersion $script:HardCutVersion)-ge 0){$fixed += "release-provenance.json"}
    $payload=@(Get-ReleasePayloadNamesFromManifest -ManifestPath (Join-Path $resolved "upgrade-manifest.json") -Version $TargetVersion)
    foreach ($name in $fixed+$payload) {
        $source = Join-Path $resolved $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            Fail "Sealed candidate is missing $name in $resolved"
        }
        $copied = Join-Path $destination $name
        Copy-Item -LiteralPath $source -Destination $copied
        if ($name -eq "defenseclaw-upgrade.ps1") {
            Set-PrivatePathAcl -Path $copied
        }
    }
    [void](Assert-ReleaseSet -Directory $destination -Version $TargetVersion)
    [void](Assert-SealedCandidateResolver -Directory $destination)
}

function Get-PublishedAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $maximumBytes = switch ($Name) {
        "checksums.txt" { 8MB; break }
        "checksums.txt.sig" { 16KB; break }
        "checksums.txt.pem" { 64KB; break }
        "upgrade-manifest.json" { 1MB; break }
        "release-provenance.json" { 16KB; break }
        default { 512MB; break }
    }
    $url = "https://github.com/$($script:Repository)/releases/download/$Version/$Name"
    $temporary = "$Destination.$([guid]::NewGuid().ToString('N')).part"
    try {
        & $script:Commandcurl @(
            "--fail", "--show-error", "--location", "--max-redirs", "5",
            "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
            "--max-filesize", [string]$maximumBytes,
            "--output", $temporary, $url
        )
        if($LASTEXITCODE -ne 0){throw "curl failed with status $LASTEXITCODE"}
        $item=Get-Item -LiteralPath $temporary -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt $maximumBytes){
            throw "downloaded asset has an invalid type or size"
        }
        Set-PrivatePathAcl -Path $temporary
        [IO.File]::Move($temporary,$Destination)
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Fail "Published release asset is unavailable: $url"
    }
}

function Ensure-PublishedRelease {
    param([Parameter(Mandatory = $true)][string]$Version)

    $directory = Join-Path $script:ReleaseRoot $Version
    if (Test-Path -LiteralPath $directory -PathType Container) {
        [void](Assert-ReleaseSet -Directory $directory -Version $Version)
        return $directory
    }
    $directory = New-PrivateDirectory -Path $directory
    $fixed=@(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json"
    )
    if((Compare-Version $Version $script:HardCutVersion)-ge 0){$fixed += "release-provenance.json"}
    foreach($name in $fixed){
        Get-PublishedAsset -Version $Version -Name $name -Destination (Join-Path $directory $name)
    }
    $payload=@(Get-ReleasePayloadNamesFromManifest -ManifestPath (Join-Path $directory "upgrade-manifest.json") -Version $Version)
    foreach($name in $payload){Get-PublishedAsset -Version $Version -Name $name -Destination (Join-Path $directory $name)}
    [void](Assert-ReleaseSet -Directory $directory -Version $Version)
    Write-Ok "Authenticated published Windows release $Version"
    return $directory
}

function Get-FreeTcpPort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains('"')) { Fail "Process argument contains an unsupported quote" }
    return '"' + $Value + '"'
}

function Start-ReleaseServer {
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $port = Get-FreeTcpPort
        $stdout = Join-Path $script:WorkRoot "release-server.out.log"
        $stderr = Join-Path $script:WorkRoot "release-server.err.log"
        $process = Start-Process -FilePath $script:Commandpython `
            -ArgumentList @("-m", "http.server", [string]$port, "--bind", "127.0.0.1") `
            -WorkingDirectory $script:ReleaseRoot -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $ready = $false
        for ($probe = 0; $probe -lt 50; $probe++) {
            if ($process.HasExited) { break }
            try {
                Invoke-WebRequest -Uri "http://127.0.0.1:$port/$TargetVersion/checksums.txt" `
                    -Method Head -UseBasicParsing -TimeoutSec 2 | Out-Null
                $ready = $true
                break
            } catch {
                Start-Sleep -Milliseconds 200
            }
        }
        if ($ready) {
            $script:ServerProcess = $process
            $script:ServerBaseUrl = "http://127.0.0.1:$port"
            Write-Ok "Loopback release server is ready on port $port"
            return
        }
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Fail "Could not start the loopback release server"
}

function Invoke-ExternalLogged {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    & $Command @Arguments *> $LogPath
    return $LASTEXITCODE
}

function Show-LogTail {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Write-Host "--- tail: $Path ---" -ForegroundColor Yellow
        Get-Content -LiteralPath $Path -Tail 100 | Write-Host
    }
}

function Assert-CommandVersion {
    param([string]$Command, [string]$Expected, [string]$Label)
    $output = (& $Command --version 2>&1 | Out-String).Trim()
    $versions = @(
        [regex]::Matches($output, '(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])') |
            ForEach-Object { $_.Groups[1].Value }
    )
    if ($LASTEXITCODE -ne 0 -or $versions.Count -ne 1 -or [string]$versions[0] -cne $Expected) {
        Fail "$Label did not report $Expected (output: $output)"
    }
}

function Get-CandidateResolverPath {
    return Assert-SealedCandidateResolver -Directory (Join-Path $script:ReleaseRoot $TargetVersion)
}

function Assert-CaseConfigVersion {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][int]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $text = Get-Content -LiteralPath $Case.ConfigPath -Raw -Encoding UTF8
    $matches = @([regex]::Matches($text, '(?m)^\s*config_version:\s*([0-9]+)\s*(?:#.*)?$'))
    if ($matches.Count -ne 1 -or [int]$matches[0].Groups[1].Value -ne $Expected) {
        Fail "$Label did not contain exact config_version $Expected"
    }
}

function New-UpgradeCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$BaselineVersion,
        [switch]$SplitDataDir,
        [switch]$ExternalConfig,
        [switch]$NoOpenClaw
    )

    Write-Step "Seeding isolated $BaselineVersion Windows installation ($Name)"
    $root = New-PrivateDirectory -Path (Join-Path $script:WorkRoot $Name)
    $caseHome = New-PrivateDirectory -Path (Join-Path $root "profile")
    $controller = New-PrivateDirectory -Path (Join-Path $caseHome ".defenseclaw")
    $useSplitData=[bool]($SplitDataDir -or $ExternalConfig)
    $data = if($useSplitData){New-PrivateDirectory -Path (Join-Path $root "runtime-data")}else{$controller}
    if($ExternalConfig){
        $configRoot=New-PrivateDirectory -Path (Join-Path $root "external-config")
        $configPath=Join-Path $configRoot "defenseclaw.yaml"
    }else{$configPath=Join-Path $controller "config.yaml"}
    $openClawHomePath=Join-Path $caseHome ".openclaw"
    $local = New-PrivateDirectory -Path (Join-Path $caseHome ".local")
    $bin = New-PrivateDirectory -Path (Join-Path $local "bin")
    $appDataRoot = New-PrivateDirectory -Path (Join-Path $caseHome "AppData")
    $appData = New-PrivateDirectory -Path (Join-Path $appDataRoot "Roaming")
    $localAppData = New-PrivateDirectory -Path (Join-Path $appDataRoot "Local")
    $xdgConfig = New-PrivateDirectory -Path (Join-Path $caseHome ".config")
    $temp = New-PrivateDirectory -Path (Join-Path $root "temp")
    $port = Get-FreeTcpPort
    $sourceConfigVersion = Get-PublishedBaselineConfigVersion -Version $BaselineVersion
    $case = [pscustomobject]@{
        Name = $Name
        BaselineVersion = $BaselineVersion
        SourceConfigVersion = $sourceConfigVersion
        Root = $root
        Home = $caseHome
        Controller = $controller
        Data = $data
        ConfigPath = $configPath
        ConfigExplicit = [bool]$ExternalConfig
        OpenClawHome = $openClawHomePath
        OpenClawExisted = (-not [bool]$NoOpenClaw)
        Bin = $bin
        AppData = $appData
        LocalAppData = $localAppData
        XdgConfig = $xdgConfig
        Temp = $temp
        GatewayPort = $port
        Venv = Join-Path $controller ".venv"
        Python = Join-Path (Join-Path (Join-Path $controller ".venv") "Scripts") "python.exe"
        Cli = Join-Path (Join-Path (Join-Path $controller ".venv") "Scripts") "defenseclaw.exe"
        Gateway = Join-Path $bin "defenseclaw-gateway.exe"
        ExternalPolicy = ""
        ExternalPolicyFile = ""
        ExternalPolicySha256 = ""
    }
    Set-CaseEnvironment -Case $case

    $venvLog = Join-Path $root "seed-venv.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @("--no-config", "venv", $case.Venv, "--python", $script:Commandpython, "--quiet") `
        -LogPath $venvLog
    if ($status -ne 0) { Show-LogTail $venvLog; Fail "Could not create isolated venv for $Name" }

    # Install the target first to resolve the candidate dependency graph, then
    # replace only the DefenseClaw package with the real published baseline.
    # This is the same seed strategy used by the cross-platform release gate;
    # neither the controller nor gateway is synthesized from this checkout.
    $targetDirectory = Join-Path $script:ReleaseRoot $TargetVersion
    $targetPayload = @(
        Get-ReleasePayloadNamesFromManifest `
            -ManifestPath (Join-Path $targetDirectory "upgrade-manifest.json") `
            -Version $TargetVersion
    )
    $targetProtectedWheel = Join-Path $targetDirectory $targetPayload[0]
    $targetWheel=New-PrivateDecodedArtifact -Source $targetProtectedWheel -Destination (Join-Path $root "defenseclaw-$TargetVersion-2-py3-none-any.whl")
    $depsLog = Join-Path $root "seed-target-dependencies.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @("--no-config", "pip", "install", "--python", $case.Python, "--quiet", $targetWheel) `
        -LogPath $depsLog
    if ($status -ne 0) { Show-LogTail $depsLog; Fail "Could not install candidate dependency graph" }

    $baselineDirectory = Join-Path $script:ReleaseRoot $BaselineVersion
    $baselinePayload=@(Get-ReleasePayloadNamesFromManifest -ManifestPath (Join-Path $baselineDirectory "upgrade-manifest.json") -Version $BaselineVersion)
    $baselineWheel=if((Compare-Version $BaselineVersion $script:BridgeVersion)-ge 0){
        New-PrivateDecodedArtifact -Source (Join-Path $baselineDirectory $baselinePayload[0]) -Destination (Join-Path $root "defenseclaw-$BaselineVersion-2-py3-none-any.whl")
    }else{Join-Path $baselineDirectory $baselinePayload[0]}
    $baselineLog = Join-Path $root "seed-$BaselineVersion.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @(
            "--no-config", "pip", "install", "--python", $case.Python,
            "--quiet", "--no-deps", "--reinstall", $baselineWheel
        ) -LogPath $baselineLog
    if ($status -ne 0) { Show-LogTail $baselineLog; Fail "Could not install published CLI $BaselineVersion" }

    $gatewayStage = New-PrivateDirectory -Path (Join-Path $root "gateway-stage")
    $gatewayArchive=if((Compare-Version $BaselineVersion $script:BridgeVersion)-ge 0){
        New-PrivateDecodedArtifact -Source (Join-Path $baselineDirectory $baselinePayload[1]) -Destination (Join-Path $root "seed-baseline-gateway.zip")
    }else{Join-Path $baselineDirectory $baselinePayload[1]}
    Expand-Archive -LiteralPath $gatewayArchive -DestinationPath $gatewayStage -Force
    $gatewayCandidates = @(
        Get-ChildItem -LiteralPath $gatewayStage -Filter "defenseclaw.exe" -File -Recurse
    )
    if ($gatewayCandidates.Count -ne 1) {
        Fail "Published gateway archive $BaselineVersion did not contain one defenseclaw.exe"
    }
    Copy-Item -LiteralPath $gatewayCandidates[0].FullName -Destination $case.Gateway
    Set-PrivatePathAcl -Path $case.Gateway

    $shim = Join-Path $bin "defenseclaw.cmd"
    [IO.File]::WriteAllText(
        $shim,
        "@echo off`r`n`"$($case.Cli)`" %*`r`n",
        [Text.Encoding]::ASCII
    )
    Set-PrivatePathAcl -Path $shim
    if(-not $NoOpenClaw){
        $openClawShim = Join-Path $bin "openclaw.cmd"
        [IO.File]::WriteAllText($openClawShim, "@echo off`r`nexit /b 127`r`n", [Text.Encoding]::ASCII)
        Set-PrivatePathAcl -Path $openClawShim
    }
    Remove-Item -LiteralPath $gatewayStage -Recurse -Force

    $yamlData = $data.Replace("'", "''")
    $config = @"
config_version: $sourceConfigVersion
data_dir: '$yamlData'
gateway:
  api_bind: 127.0.0.1
  api_port: $port
guardrail:
  enabled: false
notifications:
  enabled: false
"@
    [IO.File]::WriteAllText($configPath, $config.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $configPath
    Assert-CaseConfigVersion -Case $case -Expected $sourceConfigVersion -Label "published source fixture"
    $environmentPath = Join-Path $data ".env"
    [IO.File]::WriteAllText(
        $environmentPath,
        "WINDOWS_UPGRADE_SMOKE=preserved`n",
        (New-Object Text.UTF8Encoding($false))
    )
    Set-PrivatePathAcl -Path $environmentPath

    $runtimePath=Join-Path $data "guardrail_runtime.json"
    [IO.File]::WriteAllText($runtimePath,"{`"source`":`"preserved`"}`n",(New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $runtimePath
    $legacyEnv=Join-Path $data "codex_env.sh"
    [IO.File]::WriteAllText($legacyEnv,"export SOURCE_ONLY=1`n",(New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $legacyEnv
    $policies=New-PrivateDirectory -Path (Join-Path $data "policies")
    $policyFile=Join-Path $policies "operator.rego"
    [IO.File]::WriteAllText($policyFile,"package operator`n",(New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $policyFile
    $externalPolicy=New-PrivateDirectory -Path (Join-Path $root "linked-policy-source")
    $externalPolicyFile=Join-Path $externalPolicy "linked.rego"
    [IO.File]::WriteAllText($externalPolicyFile,"package linked`n",(New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $externalPolicyFile
    $case.ExternalPolicy=$externalPolicy
    $case.ExternalPolicyFile=$externalPolicyFile
    $case.ExternalPolicySha256=(Get-FileHash -LiteralPath $externalPolicyFile -Algorithm SHA256).Hash.ToLowerInvariant()
    [void](New-Item -ItemType Junction -Path (Join-Path $policies "linked") -Target $externalPolicy -ErrorAction Stop)
    [void][IO.File]::CreateSymbolicLink((Join-Path $policies "linked-file.rego"),$externalPolicyFile)
    $connectorBackups=New-PrivateDirectory -Path (Join-Path $data "connector_backups")
    $connectorBackup=Join-Path $connectorBackups "source.json"
    [IO.File]::WriteAllText($connectorBackup,"{`"source`":true}`n",(New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $connectorBackup
    if(-not $NoOpenClaw){
        $openClawHome=New-PrivateDirectory -Path $openClawHomePath
        $openClawConfig=Join-Path $openClawHome "openclaw.json"
        [IO.File]::WriteAllText($openClawConfig,"{`"source`":`"preserved`"}`n",(New-Object Text.UTF8Encoding($false)))
        Set-PrivatePathAcl -Path $openClawConfig
    }elseif(Test-Path -LiteralPath $openClawHomePath){Fail "No-OpenClaw case unexpectedly created its home during seed"}

    Assert-CommandVersion -Command $case.Cli -Expected $BaselineVersion -Label "published CLI"
    Assert-CommandVersion -Command $case.Gateway -Expected $BaselineVersion -Label "published gateway"
    [void]$script:Cases.Add($case)
    Write-Ok "Seeded real published $BaselineVersion wheel and Windows gateway"
    return $case
}

function Add-SnapshotPath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path)
    if ($Seen.ContainsKey($full)) { return }
    $Seen[$full] = $true
    $item = Get-Item -LiteralPath $full -Force
    $acl = if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){$null}else{Get-Acl -LiteralPath $full}
    $relative = [IO.Path]::GetRelativePath($Case.Root, $full).Replace('\', '/')
    $row = [ordered]@{
        path = $relative
        kind = if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { "reparse" } elseif ($item.PSIsContainer) { "directory" } else { "file" }
        attributes = [string]$item.Attributes
        dacl_sddl = if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){$null}else{$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)}
        owner_sid = if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){$null}else{$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value}
        length = $null
        sha256 = $null
        link_type = $null
        link_target = $null
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $linkType=$item.PSObject.Properties["LinkType"];$target=$item.PSObject.Properties["Target"]
        $row.link_type=if($linkType){[string]$linkType.Value}else{""}
        $row.link_target=if($target){(@($target.Value)|ForEach-Object{[string]$_}) -join "`n"}else{""}
    } elseif (-not $item.PSIsContainer) {
        $row.length = $item.Length
        $row.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [void]$Rows.Add([pscustomobject]$row)
}

function Add-SnapshotTree {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    Add-SnapshotPath -Rows $Rows -Seen $Seen -Case $Case -Path $Path
    $root=Get-Item -LiteralPath $Path -Force
    if(-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)){return}
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force|Sort-Object Name) {
        Add-SnapshotTree -Rows $Rows -Seen $Seen -Case $Case -Path $item.FullName
    }
}

function Write-InstalledStateSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Output
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Controller
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Data
    foreach ($top in Get-ChildItem -LiteralPath $Case.Data -Force) {
        if ($top.Name -ne ".venv") {
            Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $top.FullName
        }
    }
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $Case.ConfigPath
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $Case.OpenClawHome
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $Case.Home ".local")

    # Installed package/controller state is the part of the venv an upgrade
    # replaces.  Snapshot it in full without hashing unrelated dependency
    # caches, standard-library files, or the interpreter itself.
    $sitePackages = Join-Path (Join-Path $Case.Venv "Lib") "site-packages"
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $sitePackages "defenseclaw")
    foreach ($distInfo in Get-ChildItem -LiteralPath $sitePackages -Directory -Filter "defenseclaw-*.dist-info") {
        Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $distInfo.FullName
    }
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Cli

    $ordered = @($rows | Sort-Object path)
    [IO.File]::WriteAllText(
        $Output,
        (($ordered | ConvertTo-Json -Depth 6 -Compress) + "`n"),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Assert-SnapshotsEqual {
    param([string]$Before, [string]$After, [string]$Label)
    $beforeHash = (Get-FileHash -LiteralPath $Before -Algorithm SHA256).Hash
    $afterHash = (Get-FileHash -LiteralPath $After -Algorithm SHA256).Hash
    if ($beforeHash -ne $afterHash) {
        Fail "$Label changed installed bytes, ACLs, configuration, cursor, receipts, or artifacts"
    }
}

function Assert-NoSucceededReceipt {
    param([object]$Case)
    $root = Join-Path $Case.Data ".upgrade-receipts"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }
    foreach ($path in Get-ChildItem -LiteralPath $root -Filter "*.json" -File) {
        try { $receipt = Get-Content -LiteralPath $path.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        if ([string]$receipt.status -in @("succeeded", "partial")) {
            Fail "A refused operation wrote a success receipt: $($path.FullName)"
        }
    }
}

function Write-TransactionalStateSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Output
    )

    $rows=New-Object System.Collections.Generic.List[object];$seen=@{}
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Controller
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Data
    foreach($name in @(
        "config.yaml",".env",".migration_state.json","guardrail_runtime.json",
        "device.key","active_connector.json","codex_backup.json",
        "claudecode_backup.json","zeptoclaw_backup.json","codex_config_backup.json",
        "codex_env.sh","codex.env","policies","connector_backups",
        "hooks",".upgrade-shims","observability-stack"
    )){Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $Case.Data $name)}
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $Case.ConfigPath
    $openClawHome=$Case.OpenClawHome
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $openClawHome
    foreach($name in @("openclaw.json","openclaw.json.pre-0.3.0-migration")){Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $openClawHome $name)}
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $Case.Venv
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Gateway
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $Case.ExternalPolicy
    $records=@($rows|Sort-Object path)
    [IO.File]::WriteAllText(
        $Output,
        (($records | ConvertTo-Json -Depth 4 -Compress) + "`n"),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Assert-ExternalPolicyTargetPreserved {
    param([Parameter(Mandatory = $true)][object]$Case)
    if(-not(Test-Path -LiteralPath $Case.ExternalPolicyFile -PathType Leaf)){Fail "Phase-one rollback followed a managed reparse point and removed its external target"}
    if((Get-FileHash -LiteralPath $Case.ExternalPolicyFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$Case.ExternalPolicySha256){Fail "Phase-one rollback changed the external reparse target"}
}

function Test-InstallerExistingInstallRefusal {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving install.ps1 -Local cannot overwrite an existing installation"
    Set-CaseEnvironment -Case $Case
    $before = Join-Path $Case.Root "installer-refusal.before.json"
    $after = Join-Path $Case.Root "installer-refusal.after.json"
    $log = Join-Path $Case.Root "installer-refusal.log"
    $userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")
    Write-InstalledStateSnapshot -Case $Case -Output $before
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Join-Path $PSScriptRoot "install.ps1"),
        "-Local", (Resolve-Path -LiteralPath $ReleaseDir).Path,
        "-Connector", "none", "-Yes"
    )
    $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if ($status -eq 0) { Show-LogTail $log; Fail "install.ps1 unexpectedly overwrote an existing installation" }
    Write-InstalledStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "install.ps1 refusal"
    if ([Environment]::GetEnvironmentVariable("Path", "User") -ne $userPathBefore) {
        Fail "install.ps1 refusal changed the persistent user PATH"
    }
    $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
    if ($text -notmatch '(?i)existing DefenseClaw installation' -or $text -notmatch '(?i)No changes were made') {
        Show-LogTail $log
        Fail "install.ps1 refusal did not explain the fresh-install boundary"
    }
    Write-Ok "install.ps1 refused the existing installation without mutation"
}

function Start-RefusalSentinel {
    param([Parameter(Mandatory = $true)][object]$Case)

    $sentinel = Start-Process -FilePath $script:Commandpwsh `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-Command", 'while ($true) { Start-Sleep -Seconds 30 }') `
        -WindowStyle Hidden -PassThru
    [void]$script:Sentinels.Add($sentinel)
    $pidPath = Join-Path $Case.Data "gateway.pid"
    [IO.File]::WriteAllText($pidPath, ([string]$sentinel.Id + "`n"), [Text.Encoding]::ASCII)
    Set-PrivatePathAcl -Path $pidPath
    return $sentinel
}

function Stop-RefusalSentinel {
    param([object]$Case, [object]$Sentinel)
    Remove-Item -LiteralPath (Join-Path $Case.Data "gateway.pid") -Force -ErrorAction SilentlyContinue
    if ($Sentinel -and -not $Sentinel.HasExited) {
        Stop-Process -Id $Sentinel.Id -Force -ErrorAction SilentlyContinue
        $Sentinel.WaitForExit(5000) | Out-Null
    }
}

function Test-HardCutExplicitRefusal {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving explicit $($Case.Name): $($script:OldBaseline) -> $TargetVersion refuses pre-mutation"
    Set-CaseEnvironment -Case $Case
    $sentinel = Start-RefusalSentinel -Case $Case
    $before = Join-Path $Case.Root "resolver-refusal.before.json"
    $after = Join-Path $Case.Root "resolver-refusal.after.json"
    $log = Join-Path $Case.Root "resolver-refusal.log"
    $userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")
    try {
        Write-InstalledStateSnapshot -Case $Case -Output $before
        $arguments = @(
            "-NoProfile", "-NonInteractive", "-File", (Get-CandidateResolverPath),
            "-Version", $TargetVersion, "-Yes", "-HealthTimeout", [string]$HealthTimeout,
            "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
        )
        $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if ($status -eq 0) { Show-LogTail $log; Fail "Explicit hard-cut request unexpectedly succeeded" }
        if ($sentinel.HasExited -or -not (Get-Process -Id $sentinel.Id -ErrorAction SilentlyContinue)) {
            Fail "Explicit hard-cut refusal crossed the service-stop boundary"
        }
        $pidText = (Get-Content -LiteralPath (Join-Path $Case.Data "gateway.pid") -Raw).Trim()
        if ($pidText -ne [string]$sentinel.Id) { Fail "Explicit refusal changed gateway.pid" }
        Write-InstalledStateSnapshot -Case $Case -Output $after
        Assert-SnapshotsEqual -Before $before -After $after -Label "explicit hard-cut refusal"
        if ([Environment]::GetEnvironmentVariable("Path", "User") -ne $userPathBefore) {
            Fail "Explicit hard-cut refusal changed the persistent user PATH"
        }
        Assert-NoSucceededReceipt -Case $Case
        Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "refused CLI"
        Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "refused gateway"
        $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if ($text -notmatch '(?i)requires bridge' -or $text -notmatch '(?i)No installed state changed') {
            Show-LogTail $log
            Fail "Explicit refusal did not explain the signed bridge requirement"
        }
    } finally {
        Stop-RefusalSentinel -Case $Case -Sentinel $sentinel
    }
    Write-Ok "Explicit hard-cut request left PID, service, config, cursor, ACLs, CLI, and gateway unchanged"
}

function Test-ProtectedMaterializationCollision {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving authenticated materialization refuses a preexisting private destination before stop"
    Start-CaseGateway -Case $Case
    $before=Join-Path $Case.Root "materialization-collision.before.json";$after=Join-Path $Case.Root "materialization-collision.after.json";$log=Join-Path $Case.Root "materialization-collision.log"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $staging=""
    try{
        $arguments=@(
            "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
            "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
            "-TestMode","-LatestVersionOverride",$TargetVersion,"-InjectProtectedMaterializationCollision","-KeepStaging"
        )
        $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if($status -eq 0){Show-LogTail $log;Fail "Protected materialization collision unexpectedly succeeded"}
        $text=Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if($text -notmatch 'Authenticated wheel materialization destination already exists; refusing to overwrite' -or $text -notmatch 'Kept staging:\s*([^\r\n]+)'){Show-LogTail $log;Fail "Materialization collision did not report its create-new refusal and retained custody"}
        $staging=[string]$Matches[1].Trim()
        $sentinel=Join-Path (Join-Path (Join-Path $staging "final-$TargetVersion") "materialized") "defenseclaw-$TargetVersion-py3-none-any.whl"
        Assert-PrivateFileAcl -Path $sentinel
        if((Get-Content -LiteralPath $sentinel -Raw -Encoding UTF8) -ne "protected-materialization-collision-sentinel`n"){Fail "Create-new refusal overwrote the preexisting authenticated materialization destination"}
        Write-TransactionalStateSnapshot -Case $Case -Output $after
        Assert-SnapshotsEqual -Before $before -After $after -Label "protected materialization collision"
        Assert-CaseGatewayRunning -Case $Case -Label "materialization-refusal source gateway"
        Assert-NoSucceededReceipt -Case $Case
    }finally{
        if($staging -and (Test-Path -LiteralPath $staging)){Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue}
    }
    Write-Ok "Preexisting private materialization destination was preserved and services stayed running"
}

function Invoke-ResolverUpgrade {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [switch]$Latest,
        [switch]$Explicit,
        [string[]]$AdditionalArguments=@()
    )

    Set-CaseEnvironment -Case $Case
    $log = Join-Path $Case.Root "upgrade.log"
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Get-CandidateResolverPath),
        "-Yes", "-HealthTimeout", [string]$HealthTimeout,
        "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
    )
    if ($Latest) { $arguments += @("-LatestVersionOverride", $TargetVersion) }
    if ($Explicit) { $arguments += @("-Version", $TargetVersion) }
    $arguments += @($AdditionalArguments)
    $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if ($status -ne 0) {
        Show-LogTail $log
        Fail "Production Windows resolver failed for case $($Case.Name)"
    }
}

function Assert-CaseGatewayRunning {
    param([Parameter(Mandatory = $true)][object]$Case,[string]$Expected="",[string]$Label="source gateway")
    if(-not $Expected){$Expected=[string]$Case.BaselineVersion}
    $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Min($HealthTimeout,30))
    while([DateTime]::UtcNow -lt $deadline){
        try{
            $health=Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2
            $gateway=Get-Property $health "gateway";$provenance=Get-Property $health "provenance"
            $state=if($gateway){Get-Property $gateway.Value "state"}else{$null}
            $version=if($provenance){Get-Property $provenance.Value "binary_version"}else{$null}
            if($state -and [string]$state.Value -eq "running" -and $version -and [string]$version.Value -eq $Expected){return}
        }catch{}
        Start-Sleep -Milliseconds 250
    }
    Fail "$Label is not healthy, running, and reporting $Expected"
}

function Assert-CaseGatewayStopped {
    param([Parameter(Mandatory = $true)][object]$Case,[string]$Label="source gateway")
    & $Case.Gateway status *> $null
    if($LASTEXITCODE -eq 0){Fail "$Label was unexpectedly running"}
    $pidPath=Join-Path $Case.Data "gateway.pid"
    if(Test-Path -LiteralPath $pidPath){
        $raw=(Get-Content -LiteralPath $pidPath -Raw -Encoding UTF8).Trim();$pidValue=$null
        if($raw -match '^[1-9]\d*$'){$pidValue=$raw}else{try{$pidValue=(ConvertFrom-Json $raw).pid}catch{Fail "$Label left malformed PID custody"}}
        try{$processId=[int]$pidValue}catch{Fail "$Label left malformed PID custody"}
        if($processId -gt 0 -and (Get-Process -Id $processId -ErrorAction SilentlyContinue)){Fail "$Label left a live PID while stopped"}
    }
}

function Start-CaseGateway {
    param([Parameter(Mandatory = $true)][object]$Case)
    Set-CaseEnvironment -Case $Case
    & $Case.Gateway status *> $null
    if($LASTEXITCODE -eq 0){return}
    & $Case.Gateway start *> $null
    if($LASTEXITCODE -ne 0){Fail "Could not start the isolated source gateway"}
    Assert-CaseGatewayRunning -Case $Case
}

function Get-PhaseOneMutationTemporaryPaths {
    param([Parameter(Mandatory = $true)][object]$Case,[Parameter(Mandatory = $true)][string]$Token)
    if($Token -notmatch '^[0-9a-f]{32}$'){Fail "Mutation-temporary test token is invalid"}
    $configLeaf=Split-Path -Leaf $Case.ConfigPath
    return @(
        (Join-Path (Split-Path -Parent $Case.ConfigPath) ("."+$configLeaf+".upgrade-"+$Token+".abc.tmp")),
        (Join-Path $Case.Data (".migration_state.upgrade-"+$Token+".abc.tmp")),
        (Join-Path $Case.OpenClawHome (".tmp.upgrade-"+$Token+".abcopenclaw.json"))
    )
}

function New-ForeignPhaseOneMutationTemporaries {
    param([Parameter(Mandatory = $true)][object]$Case)
    if(-not(Test-Path -LiteralPath $Case.OpenClawHome -PathType Container)){Fail "Foreign temporary test requires an existing OpenClaw home"}
    $token="11111111111111111111111111111111";$records=@()
    foreach($path in @(Get-PhaseOneMutationTemporaryPaths -Case $Case -Token $token)){
        if(Test-Path -LiteralPath $path){Fail "Foreign mutation-temporary path already exists: $path"}
        [IO.File]::WriteAllText($path,("foreign-phase-one-temporary:"+$token+"`n"),(New-Object Text.UTF8Encoding($false)))
        Set-PrivatePathAcl -Path $path;Assert-PrivateFileAcl -Path $path
        $records += [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    return @($records)
}

function Assert-PhaseOneMutationTemporaries {
    param([Parameter(Mandatory = $true)][object]$Case,[object[]]$ForeignRecords=@())
    $foreignToken="11111111111111111111111111111111"
    $roots=@($Case.Data,(Split-Path -Parent $Case.ConfigPath))
    if(Test-Path -LiteralPath $Case.OpenClawHome -PathType Container){$roots += $Case.OpenClawHome}
    foreach($root in @($roots|Sort-Object -Unique)){
        foreach($member in @(Get-ChildItem -LiteralPath $root -File -Force)){
            $match=[regex]::Match($member.Name,'\.upgrade-(?<token>[0-9a-f]{32})\.')
            if($match.Success -and $match.Groups["token"].Value -ne $foreignToken){Fail "Current-attempt phase-one mutation temporary survived cleanup: $($member.FullName)"}
        }
    }
    foreach($record in @($ForeignRecords)){
        Assert-PrivateFileAcl -Path ([string]$record.Path)
        if((Get-FileHash -LiteralPath ([string]$record.Path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$record.Sha256){Fail "Foreign-token phase-one temporary was changed or removed"}
    }
}

function Test-PhaseOneOwnedTemporaryRollback {
    param([Parameter(Mandatory = $true)][object]$Case,[switch]$SeedForeign)
    Write-Step "Injecting current-token mutation temporaries and proving authenticated rollback cleanup"
    Set-CaseEnvironment -Case $Case;Start-CaseGateway -Case $Case
    $foreign=@(if($SeedForeign){@(New-ForeignPhaseOneMutationTemporaries -Case $Case)}else{@()})
    $before=Join-Path $Case.Root "owned-temporary.before.json";$after=Join-Path $Case.Root "owned-temporary.after.json";$log=Join-Path $Case.Root "owned-temporary-rollback.log"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneFailureAfterFreshMutation"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if($status -eq 0){Show-LogTail $log;Fail "Owned-temporary rollback injection unexpectedly succeeded"}
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "owned mutation-temporary rollback"
    Assert-PhaseOneMutationTemporaries -Case $Case -ForeignRecords $foreign
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "owned-temporary restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "owned-temporary restored gateway"
    Assert-CaseGatewayRunning -Case $Case -Label "owned-temporary restored source gateway"
    $text=Get-Content -LiteralPath $log -Raw -Encoding UTF8
    if($text -notmatch 'Injected phase-one failure after fresh mutation temporaries' -or $text -notmatch '(?i)restored healthy DefenseClaw'){Show-LogTail $log;Fail "Owned-temporary failure did not complete authenticated rollback"}
    return @($foreign)
}

function Test-PhaseOneStopFailures {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving failed and non-quiescent phase-one stops restore the running source"
    Start-CaseGateway -Case $Case
    $before=Join-Path $Case.Root "phase-one-stop.before.json"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    foreach($fault in @(
        [pscustomobject]@{Switch="-InjectPhaseOneStopFailure";Pattern='Gateway stop command failed'},
        [pscustomobject]@{Switch="-InjectPhaseOneNonQuiescentStop";Pattern='Gateway remains live'}
    )){
        $log=Join-Path $Case.Root (([string]$fault.Switch).TrimStart('-')+".log")
        $after=Join-Path $Case.Root (([string]$fault.Switch).TrimStart('-')+".after.json")
        $arguments=@(
            "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
            "-Yes","-HealthTimeout",[string]$HealthTimeout,
            "-ReleaseBaseUrl",$script:ServerBaseUrl,"-TestMode",
            "-LatestVersionOverride",$TargetVersion,[string]$fault.Switch
        )
        $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if($status -eq 0){Show-LogTail $log;Fail "Injected phase-one stop fault unexpectedly succeeded"}
        Write-TransactionalStateSnapshot -Case $Case -Output $after
        Assert-SnapshotsEqual -Before $before -After $after -Label ([string]$fault.Switch)
        Assert-ExternalPolicyTargetPreserved -Case $Case
        Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "stop-fault restored CLI"
        Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "stop-fault restored gateway"
        Assert-CaseGatewayRunning -Case $Case -Label "stop-fault restored source gateway"
        if(Test-Path -LiteralPath (Join-Path (Join-Path $Case.Controller ".upgrade-recovery") "phase-one-active.json")){Fail "Stop-fault rollback left an active phase-one journal"}
        $text=Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if($text -notmatch [string]$fault.Pattern -or $text -notmatch '(?i)restored healthy DefenseClaw'){Show-LogTail $log;Fail "Stop-fault rollback did not report the fail-closed recovery"}
    }
    Write-Ok "Failed and non-quiescent stops remained fail-closed and restored the running source"
}

function Test-PhaseOneRollback {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Injecting failure after bridge mutation and proving exact source rollback"
    Set-CaseEnvironment -Case $Case
    $before=Join-Path $Case.Root "phase-one-state.before.json"
    $after=Join-Path $Case.Root "phase-one-state.after.json"
    $log=Join-Path $Case.Root "phase-one-rollback.log"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,
        "-ReleaseBaseUrl",$script:ServerBaseUrl,"-TestMode",
        "-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneFailureAfterMutation"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if($status -eq 0){Show-LogTail $log;Fail "Injected phase-one failure unexpectedly succeeded"}
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "phase-one bridge rollback"
    Assert-ExternalPolicyTargetPreserved -Case $Case
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "phase-one restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "phase-one restored gateway"
    Assert-CaseGatewayStopped -Case $Case -Label "phase-one restored stopped source gateway"
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Phase-one rollback changed persistent user PATH"}
    foreach($receipt in @(Get-UpgradeReceipts -Case $Case)){
        if([string]$receipt.target_version -eq $TargetVersion -and [string]$receipt.status -in @("succeeded","partial")){Fail "Phase-one rollback left a successful hard-cut receipt"}
    }
    $text=Get-Content -LiteralPath $log -Raw -Encoding UTF8
    if($text -notmatch '(?i)restored healthy DefenseClaw'){Show-LogTail $log;Fail "Phase-one failure did not report healthy source restoration"}
    Write-Ok "Phase-one failure restored exact source state, owner/DACL, CLI, gateway, and stopped service state"
}

function Test-PhaseOneConcurrentDivergence {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Injecting post-seal concurrent state and proving rollback fails closed without data loss"
    Set-CaseEnvironment -Case $Case;Start-CaseGateway -Case $Case
    $firstLog=Join-Path $Case.Root "phase-one-concurrent-divergence.log"
    $retryLog=Join-Path $Case.Root "phase-one-concurrent-divergence-retry.log"
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion,
        "-InjectPhaseOneConcurrentEditAfterActiveSeal","-InjectPhaseOneConcurrentFileAfterActiveSeal"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $firstLog
    if($status -eq 0){Show-LogTail $firstLog;Fail "Post-seal concurrent-divergence injection unexpectedly succeeded"}
    $newFile=Join-Path (Join-Path $Case.Data "policies") "phase-one-concurrent-new.txt"
    $expectedConfig=[Convert]::ToBase64String((New-Object Text.UTF8Encoding($false)).GetBytes("phase-one-concurrent-config-edit`n"))
    $expectedNew=[Convert]::ToBase64String((New-Object Text.UTF8Encoding($false)).GetBytes("phase-one-concurrent-new-state`n"))
    if(-not(Test-Path -LiteralPath $Case.ConfigPath -PathType Leaf) -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($Case.ConfigPath)) -ne $expectedConfig){Fail "Rollback overwrote the concurrent config edit"}
    if(-not(Test-Path -LiteralPath $newFile -PathType Leaf) -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($newFile)) -ne $expectedNew){Fail "Rollback removed or changed the concurrent managed-tree file"}
    Assert-PrivateFileAcl -Path $newFile
    $planId=Assert-PhaseOneJournalCustody -Case $Case
    $journal=Join-Path (Join-Path $Case.Controller ".upgrade-recovery") "phase-one-active.json"
    $payload=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json
    if(-not [bool]$payload.active_snapshot_ready){Fail "Concurrent-divergence rollback journal lacks its durable post-migration active-state seal"}
    $journalSha=(Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-CommandVersion -Command $Case.Cli -Expected $script:BridgeVersion -Label "divergence-preserved bridge CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:BridgeVersion -Label "divergence-preserved bridge gateway"
    Assert-CaseGatewayStopped -Case $Case -Label "divergence-preserved bridge gateway"
    $text=Get-Content -LiteralPath $firstLog -Raw -Encoding UTF8
    if($text -notmatch 'Injected phase-one target failure after active-state divergence' -or $text -notmatch 'state diverged after migration; preserved without overwrite'){
        Show-LogTail $firstLog;Fail "Concurrent-divergence failure did not report its fail-closed CAS refusal"
    }

    $retryArguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $retryArguments -LogPath $retryLog
    if($status -eq 0){Show-LogTail $retryLog;Fail "Recovery overwrote divergent state on retry"}
    if((Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash.ToLowerInvariant() -ne $journalSha){Fail "Fail-closed recovery rewrote its active rollback journal"}
    if((Assert-PhaseOneJournalCustody -Case $Case) -ne $planId){Fail "Fail-closed recovery replaced its active rollback plan"}
    if([Convert]::ToBase64String([IO.File]::ReadAllBytes($Case.ConfigPath)) -ne $expectedConfig -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($newFile)) -ne $expectedNew){Fail "Recovery retry changed concurrent state bytes"}
    $retryText=Get-Content -LiteralPath $retryLog -Raw -Encoding UTF8
    if($retryText -notmatch 'state diverged after migration; preserved without overwrite'){Show-LogTail $retryLog;Fail "Recovery retry did not fail closed on the same state divergence"}
    Write-Ok "Concurrent edit and new managed-tree file survived initial rollback and retry; schema-4 custody remained active"
}

function Assert-PhaseOneJournalCustody {
    param([Parameter(Mandatory = $true)][object]$Case)

    $recoveryRoot=Join-Path $Case.Controller ".upgrade-recovery"
    $journal=Join-Path $recoveryRoot "phase-one-active.json"
    Assert-PrivateDirectoryAcl -Path $recoveryRoot
    Assert-PrivateFileAcl -Path $journal
    Assert-PrivateFileAcl -Path (Join-Path $recoveryRoot "phase-one-mutator.lease")
    try{$payload=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one active journal is not valid JSON"}
    $expectedJournalKeys=@(
        "schema_version","kind","plan_id","controller_home","data_dir","config_path","path_identities",
        "source_version","source_was_running",
        "wheel_sha256","gateway_sha256","gateway_sddl","bridge_version",
        "bridge_wheel_sha256","bridge_gateway_sha256","venv_sddl",
        "venv_identity_sha256","base_python","state_snapshot_ready",
        "state_manifest_sha256","active_snapshot_ready","active_manifest_sha256",
        "openclaw_home","openclaw_home_existed","config_override"
    )
    $actualJournalKeys=@($payload.PSObject.Properties.Name)
    if(($actualJournalKeys -join "`n") -ne ($expectedJournalKeys -join "`n")){
        Fail "Phase-one active journal fields differ from the exact schema-4 contract"
    }
    if([int]$payload.schema_version -ne 4 -or [string]$payload.kind -ne "defenseclaw-phase-one-recovery" -or [string]$payload.plan_id -notmatch '^phase-one-[0-9a-f]{32}$' -or [string]$payload.source_version -ne $script:OldBaseline -or [string]$payload.bridge_version -ne $script:BridgeVersion -or $payload.source_was_running -isnot [bool] -or -not [bool]$payload.source_was_running -or $payload.state_snapshot_ready -isnot [bool] -or -not [bool]$payload.state_snapshot_ready -or $payload.active_snapshot_ready -isnot [bool]){
        Fail "Phase-one active journal contract is invalid"
    }
    if(([bool]$payload.active_snapshot_ready -and [string]$payload.active_manifest_sha256 -notmatch '^[0-9a-f]{64}$') -or (-not [bool]$payload.active_snapshot_ready -and $null -ne $payload.active_manifest_sha256)){Fail "Phase-one active-state seal contract is invalid"}
    foreach($name in @("wheel_sha256","gateway_sha256","bridge_wheel_sha256","bridge_gateway_sha256","venv_identity_sha256")){
        if([string]$payload.$name -notmatch '^[0-9a-f]{64}$'){Fail "Phase-one active journal has invalid custody digest: $name"}
    }
    foreach($record in @(
        @([string]$payload.gateway_sddl,"Security.AccessControl.FileSecurity"),
        @([string]$payload.venv_sddl,"Security.AccessControl.DirectorySecurity")
    )){
        if(-not [string]$record[0]){Fail "Phase-one active journal lacks owner/DACL custody"}
        try{
            $security=New-Object -TypeName ([string]$record[1])
            $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
            $security.SetSecurityDescriptorSddlForm([string]$record[0],$sections)
        }catch{Fail "Phase-one active journal contains invalid owner/DACL custody"}
    }
    if(-not [IO.Path]::IsPathRooted([string]$payload.base_python) -or -not(Test-Path -LiteralPath ([string]$payload.base_python) -PathType Leaf)){
        Fail "Phase-one active journal does not bind a real external base Python"
    }
    $venvPrefix=$Case.Venv.TrimEnd('\')+'\'
    if(([IO.Path]::GetFullPath([string]$payload.base_python)).StartsWith($venvPrefix,[StringComparison]::OrdinalIgnoreCase)){
        Fail "Phase-one active journal base Python is inside the replaceable source venv"
    }
    $expectedOverride=if($Case.ConfigExplicit){[IO.Path]::GetFullPath($Case.ConfigPath)}else{$null}
    if(-not ([IO.Path]::GetFullPath([string]$payload.controller_home)).Equals([IO.Path]::GetFullPath($Case.Controller),[StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$payload.data_dir)).Equals([IO.Path]::GetFullPath($Case.Data),[StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$payload.config_path)).Equals([IO.Path]::GetFullPath($Case.ConfigPath),[StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$payload.openclaw_home)).Equals([IO.Path]::GetFullPath($Case.OpenClawHome),[StringComparison]::OrdinalIgnoreCase) -or
        [bool]$payload.openclaw_home_existed -ne [bool]$Case.OpenClawExisted -or
        [string]$payload.config_override -ne [string]$expectedOverride){
        Fail "Phase-one active journal changed its managed home/config identity"
    }
    $identityNames=@($payload.path_identities.PSObject.Properties.Name)
    if(($identityNames -join "`n") -ne (@("controller_home","data_dir","openclaw_home","config_parent") -join "`n")){Fail "Phase-one journal path identity set changed"}
    foreach($identity in @($payload.path_identities.controller_home,$payload.path_identities.data_dir,$payload.path_identities.config_parent)){
        if(($identity.PSObject.Properties.Name -join "`n") -ne (@("device","inode") -join "`n") -or [string]$identity.device -notmatch '^\d+$' -or [string]$identity.inode -notmatch '^\d+$'){Fail "Phase-one journal path identity is invalid"}
    }
    $openIdentity=$payload.path_identities.openclaw_home
    if(($openIdentity.PSObject.Properties.Name -join "`n") -ne (@("existed","device","inode","parent_device","parent_inode") -join "`n") -or $openIdentity.existed -isnot [bool] -or [bool]$openIdentity.existed -ne [bool]$Case.OpenClawExisted -or [string]$openIdentity.parent_device -notmatch '^\d+$' -or [string]$openIdentity.parent_inode -notmatch '^\d+$'){Fail "Phase-one journal OpenClaw identity is invalid"}
    if([bool]$openIdentity.existed -and ([string]$openIdentity.device -notmatch '^\d+$' -or [string]$openIdentity.inode -notmatch '^\d+$')){Fail "Existing phase-one OpenClaw identity lacks its directory identity"}
    if(-not [bool]$openIdentity.existed -and ([string]$openIdentity.device -or [string]$openIdentity.inode)){Fail "Absent phase-one OpenClaw identity unexpectedly binds a directory"}
    $planRoot=Join-Path $recoveryRoot ([string]$payload.plan_id)
    Assert-PrivateDirectoryAcl -Path $planRoot
    foreach($custody in @(
        @((Join-Path $planRoot "defenseclaw-$([string]$payload.source_version)-py3-none-any.whl"),[string]$payload.wheel_sha256),
        @((Join-Path $planRoot "source-gateway.exe"),[string]$payload.gateway_sha256),
        @((Join-Path $planRoot "defenseclaw-$([string]$payload.bridge_version)-py3-none-any.whl"),[string]$payload.bridge_wheel_sha256),
        @((Join-Path $planRoot "bridge-gateway.exe"),[string]$payload.bridge_gateway_sha256)
    )){
        Assert-PrivateFileAcl -Path $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$custody[1]){Fail "Phase-one source/bridge custody digest changed"}
    }
    $sourceVenv=Join-Path $planRoot "source-venv"
    Assert-PrivateDirectoryAcl -Path $sourceVenv
    $sourceVenvSddl=(Get-Acl -LiteralPath $sourceVenv).GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    )
    if($sourceVenvSddl -ne [string]$payload.venv_sddl){Fail "Phase-one source venv custody owner/DACL changed"}
    $bridgeMarker=Join-Path $Case.Venv ".defenseclaw-phase-one-owner.json"
    Assert-PrivateFileAcl -Path $bridgeMarker
    try{$marker=Get-Content -LiteralPath $bridgeMarker -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one bridge venv ownership marker is invalid JSON"}
    $markerKeys=@($marker.PSObject.Properties.Name)
    if(($markerKeys -join "`n") -ne (@("schema_version","kind","plan_id","bridge_wheel_sha256") -join "`n") -or [int]$marker.schema_version -ne 1 -or [string]$marker.kind -ne "defenseclaw-phase-one-bridge-venv" -or [string]$marker.plan_id -ne [string]$payload.plan_id -or [string]$marker.bridge_wheel_sha256 -ne [string]$payload.bridge_wheel_sha256){
        Fail "Phase-one bridge venv ownership marker does not bind the active plan"
    }
    $stateRoot=Join-Path $planRoot "state";Assert-PrivateDirectoryAcl -Path $stateRoot
    $manifestPath=Join-Path $stateRoot "manifest.json";Assert-PrivateFileAcl -Path $manifestPath
    if((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$payload.state_manifest_sha256){Fail "Phase-one state manifest digest changed"}
    try{$manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one state manifest is invalid JSON"}
    $expectedKeys=@(
        "config","config/pre-observability-migration-backup","config/lock","config/fixed-temp",
        "data/.env","data/.migration_state.json","data/guardrail_runtime.json",
        "data/device.key","data/active_connector.json","data/codex_backup.json",
        "data/claudecode_backup.json","data/zeptoclaw_backup.json","data/codex_config_backup.json",
        "data/codex_env.sh","data/codex.env","data/policies","data/connector_backups",
        "data/hooks","data/.upgrade-shims","data/observability-stack",
        "openclaw/openclaw.json","openclaw/openclaw.json.pre-0.3.0-migration"
    )
    $actualKeys=@($manifest.entries|ForEach-Object{[string]$_.key})
    if([int]$manifest.schema_version -ne 1 -or ($actualKeys -join "`n") -ne ($expectedKeys -join "`n")){Fail "Phase-one state manifest does not cover the complete managed set"}
    $kinds=@{}
    foreach($record in @($manifest.entries)){
        foreach($node in @($record.inventory)){
            $kinds[[string]$node.kind]=$true
            if([string]$node.kind -eq "file"){
                $blob=Join-Path $stateRoot ([string]$node.blob);Assert-PrivateFileAcl -Path $blob
                if((Get-FileHash -LiteralPath $blob -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$node.sha256){Fail "Phase-one state blob digest changed"}
            }
        }
    }
    if(-not $kinds.ContainsKey("directory") -or -not $kinds.ContainsKey("junction") -or -not $kinds.ContainsKey("symboliclink")){Fail "Phase-one state custody did not preserve directory/reparse metadata"}
    if([bool]$payload.active_snapshot_ready){
        $activeManifestPath=Join-Path $stateRoot "active-manifest.json";Assert-PrivateFileAcl -Path $activeManifestPath
        if((Get-FileHash -LiteralPath $activeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$payload.active_manifest_sha256){Fail "Phase-one active-state manifest digest changed"}
        try{$activeManifest=Get-Content -LiteralPath $activeManifestPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one active-state manifest is invalid JSON"}
        if([int]$activeManifest.schema_version -ne 1 -or [string]$activeManifest.plan_id -ne [string]$payload.plan_id -or @($activeManifest.entries).Count -ne $expectedKeys.Count){Fail "Phase-one active-state manifest contract is invalid"}
    }
    return [string]$payload.plan_id
}

function Test-PhaseOneCrashRecovery {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Killing phase one twice and proving journaled next-invocation recovery"
    Start-CaseGateway -Case $Case
    $before=Join-Path $Case.Root "phase-one-crash.before.json"
    $after=Join-Path $Case.Root "phase-one-crash.after.json"
    $firstLog=Join-Path $Case.Root "phase-one-crash-first.log"
    $secondLog=Join-Path $Case.Root "phase-one-crash-recovery.log"
    $finalLog=Join-Path $Case.Root "phase-one-crash-final.log"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $baseArguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,
        "-ReleaseBaseUrl",$script:ServerBaseUrl,"-TestMode"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneCrashAfterMutation")) -LogPath $firstLog
    if($status -eq 0){Show-LogTail $firstLog;Fail "First phase-one hard crash unexpectedly returned success"}
    $planId=Assert-PhaseOneJournalCustody -Case $Case

    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneCrashDuringRecovery")) -LogPath $secondLog
    if($status -eq 0){Show-LogTail $secondLog;Fail "Repeated phase-one recovery crash unexpectedly returned success"}
    $reloadedPlanId=Assert-PhaseOneJournalCustody -Case $Case
    if($reloadedPlanId -ne $planId){Fail "Repeated crash replaced the active recovery custody"}

    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-Version",$TargetVersion)) -LogPath $finalLog
    if($status -eq 0){Show-LogTail $finalLog;Fail "Post-recovery explicit hard cut unexpectedly succeeded"}
    $journal=Join-Path (Join-Path $Case.Controller ".upgrade-recovery") "phase-one-active.json"
    if(Test-Path -LiteralPath $journal){Fail "Successful next-invocation recovery left an active phase-one journal"}
    if(Test-Path -LiteralPath (Join-Path (Join-Path $Case.Controller ".upgrade-recovery") $planId)){Fail "Successful next-invocation recovery left active phase-one custody"}
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "repeat-crash phase-one recovery"
    Assert-ExternalPolicyTargetPreserved -Case $Case
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "repeat-crash restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "repeat-crash restored gateway"
    & $Case.Gateway status *> $null;if($LASTEXITCODE -ne 0){Fail "Repeat-crash recovery did not restore a healthy source gateway"}
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Repeat-crash phase-one recovery changed persistent user PATH"}
    $text=Get-Content -LiteralPath $finalLog -Raw -Encoding UTF8
    if($text -notmatch '(?i)Recovered interrupted phase-one upgrade' -or $text -notmatch '(?i)requires bridge'){
        Show-LogTail $finalLog;Fail "Next resolver invocation did not recover before evaluating the explicit hard cut"
    }
    Write-Ok "Two abrupt phase-one deaths recovered from one durable private journal to exact healthy source state"
}

function Start-ResolverAndKillDuringPhaseOneMutator {
    param([Parameter(Mandatory = $true)][object]$Case)

    Set-CaseEnvironment -Case $Case
    $uvShim=Join-Path $Case.Bin "uv.cmd"
    $marker=Join-Path $Case.Root "phase-one-mutator.blocked"
    $release=Join-Path $Case.Root "phase-one-mutator.release"
    $consumed=Join-Path $Case.Root "phase-one-mutator.consumed"
    $activeMarker=Join-Path $Case.Venv ".defenseclaw-phase-one-owner.json"
    $stdout=Join-Path $Case.Root "phase-one-mutator-crash.stdout.log"
    $stderr=Join-Path $Case.Root "phase-one-mutator-crash.stderr.log"
    $env:DEFENSECLAW_TEST_PHASE1_MARKER=$marker
    $env:DEFENSECLAW_TEST_PHASE1_RELEASE=$release
    $env:DEFENSECLAW_TEST_PHASE1_CONSUMED=$consumed
    $env:DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER=$activeMarker
    $batch=@"
@echo off
setlocal
if "%DEFENSECLAW_TEST_PHASE1_MARKER%"=="" goto delegate
if not exist "%DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER%" goto delegate
if exist "%DEFENSECLAW_TEST_PHASE1_CONSUMED%" goto delegate
>"%DEFENSECLAW_TEST_PHASE1_MARKER%" echo phase-one child holds the mutation lease
:blocked
if exist "%DEFENSECLAW_TEST_PHASE1_RELEASE%" goto released
ping.exe -n 2 127.0.0.1 >nul
goto blocked
:released
>"%DEFENSECLAW_TEST_PHASE1_CONSUMED%" echo orphan phase-one mutator lease released
exit /b 86
:delegate
"$($script:Commanduv)" %*
exit /b %ERRORLEVEL%
"@
    [IO.File]::WriteAllText($uvShim,$batch.Replace("`n","`r`n"),[Text.Encoding]::ASCII)
    Set-PrivatePathAcl -Path $uvShim
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $process=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [void]$script:Sentinels.Add($process)
    try{
        $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max($HealthTimeout*3,120))
        while([DateTime]::UtcNow -lt $deadline -and -not $process.HasExited -and -not(Test-Path -LiteralPath $marker)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $marker)){Fail "Phase-one activation child did not reach its mutator lease barrier"}
        [void](Assert-PhaseOneJournalCustody -Case $Case)
        Stop-Process -Id $process.Id -Force
        [void]$process.WaitForExit(30000)
        if(-not $process.HasExited){Fail "Phase-one resolver parent survived forced termination"}
    }catch{
        if(-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue;[void]$process.WaitForExit(10000)}
        if((Test-Path -LiteralPath $marker) -and -not(Test-Path -LiteralPath $release)){[IO.File]::WriteAllText($release,"release`n",[Text.Encoding]::ASCII)}
        Remove-Item -LiteralPath $uvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_PHASE1_MARKER","DEFENSECLAW_TEST_PHASE1_RELEASE","DEFENSECLAW_TEST_PHASE1_CONSUMED","DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
        throw
    }
    return [pscustomobject]@{Process=$process;Stdout=$stdout;Stderr=$stderr;UvShim=$uvShim;Marker=$marker;Release=$release;Consumed=$consumed;ActiveMarker=$activeMarker}
}

function Test-PhaseOneParentDeathLeaseRecovery {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Killing only the phase-one resolver parent while its mutation child survives"
    Start-CaseGateway -Case $Case
    $before=Join-Path $Case.Root "phase-one-parent-death.before.json"
    $after=Join-Path $Case.Root "phase-one-parent-death.after.json"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $crash=Start-ResolverAndKillDuringPhaseOneMutator -Case $Case
    $recoveryStdout=Join-Path $Case.Root "phase-one-parent-death-recovery.stdout.log"
    $recoveryStderr=Join-Path $Case.Root "phase-one-parent-death-recovery.stderr.log"
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-Version",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $recovery=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $recoveryStdout -RedirectStandardError $recoveryStderr
    [void]$script:Sentinels.Add($recovery)
    try{
        Start-Sleep -Seconds 2
        if($recovery.HasExited){Fail "Phase-one recovery exited instead of waiting on the orphan phase-one mutator lease"}
        if(-not(Test-Path -LiteralPath $crash.ActiveMarker -PathType Leaf)){Fail "Recovery mutated the active bridge venv before the orphan phase-one mutator lease released"}
        [IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII);Set-PrivatePathAcl -Path $crash.Release
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while([DateTime]::UtcNow -lt $deadline -and -not(Test-Path -LiteralPath $crash.Consumed)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $crash.Consumed)){Fail "Orphan phase-one child did not release its mutator lease"}
        [void]$recovery.WaitForExit([Math]::Max($HealthTimeout*5000,300000))
        if(-not $recovery.HasExited -or $recovery.ExitCode -eq 0){Fail "Phase-one recovery did not restore source before the expected explicit hard-cut refusal"}
    }finally{
        if(-not(Test-Path -LiteralPath $crash.Release)){[IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII)}
        if(-not $recovery.HasExited){& (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $recovery.Id /T /F *> $null;[void]$recovery.WaitForExit(10000)}
        Remove-Item -LiteralPath $crash.UvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_PHASE1_MARKER","DEFENSECLAW_TEST_PHASE1_RELEASE","DEFENSECLAW_TEST_PHASE1_CONSUMED","DEFENSECLAW_TEST_PHASE1_ACTIVE_MARKER")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
    }
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "phase-one parent-death lease recovery"
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "parent-death restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "parent-death restored gateway"
    Assert-CaseGatewayRunning -Case $Case -Label "parent-death restored source gateway"
    $recoveryRoot=Join-Path $Case.Controller ".upgrade-recovery"
    if(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-active.json")){Fail "Parent-death recovery left its phase-one journal"}
    if(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-mutator.lease")){Fail "Parent-death recovery left its phase-one mutator lease"}
    Write-Ok "Recovery waited for the surviving child lease, then restored exact healthy source state"
}

function Test-PhaseOneJournalCloseReceiptOrdering {
    param([Parameter(Mandatory = $true)][object]$Case,[Parameter(Mandatory = $true)][object]$Manifest)

    Write-Step "Killing phase one after durable journal close but before its terminal receipt"
    Set-CaseEnvironment -Case $Case
    $log=Join-Path $Case.Root "phase-one-post-close-crash.log"
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneCrashAfterJournalClose"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if($status -eq 0){Show-LogTail $log;Fail "Post-journal-close phase-one crash unexpectedly returned success"}
    Assert-CommandVersion -Command $Case.Cli -Expected $script:BridgeVersion -Label "post-close bridge CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:BridgeVersion -Label "post-close bridge gateway"
    Assert-CaseGatewayRunning -Case $Case -Expected $script:BridgeVersion -Label "post-close bridge gateway"
    $recoveryRoot=Join-Path $Case.Controller ".upgrade-recovery"
    if(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-active.json")){Fail "Post-close crash retained rollback authority over a healthy bridge"}
    if(Test-Path -LiteralPath (Join-Path $recoveryRoot "phase-one-mutator.lease")){Fail "Post-close crash retained an inactive phase-one lease"}
    foreach($receipt in @(Get-UpgradeReceipts -Case $Case)){
        if([string]$receipt.from_version -eq $script:OldBaseline -and [string]$receipt.target_version -eq $script:BridgeVersion -and [string]$receipt.status -eq "succeeded"){Fail "Terminal bridge receipt was committed before phase-one journal closure"}
    }
    Invoke-ResolverUpgrade -Case $Case -Latest
    Assert-UpgradeSucceeded -Case $Case -Manifest $Manifest -RequireV8 -RequireRetainedBridge
    Write-Ok "Healthy bridge survived the receipt-boundary crash and the retry completed the hard cut"
}

function Assert-PhaseTwoJournalCustody {
    param([Parameter(Mandatory = $true)][object]$Case)

    $recoveryRoot=Join-Path $Case.Controller ".upgrade-recovery";$journal=Join-Path $recoveryRoot "phase-two-active.json"
    Assert-PrivateDirectoryAcl -Path $recoveryRoot;Assert-PrivateFileAcl -Path $journal
    Assert-PrivateFileAcl -Path (Join-Path $recoveryRoot "phase-two-mutator.lease")
    try{$payload=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two active journal is not valid JSON"}
    $expectedJournalKeys=@(
        "active_gateway_path","backup_dir","backup_root_snapshot","data_dir","gateway_snapshot",
        "local_bundle_mutation_intent","os_name","receipt_path","receipt_provenance_binding_sha256",
        "recovery_home","release_provenance","release_provenance_sha256",
        "rollback_gateway_path","rollback_gateway_sha256","rollback_wheel_path",
        "rollback_wheel_sha256","schema_version","source_gateway_was_running",
        "source_version","state_files","target_version"
    )
    $actualJournalKeys=@($payload.PSObject.Properties.Name|Sort-Object)
    if(($actualJournalKeys -join "`n") -ne ($expectedJournalKeys -join "`n")){
        Fail "Phase-two active journal fields differ from the exact schema-4 contract"
    }
    if([int]$payload.schema_version -ne 4 -or $payload.source_gateway_was_running -isnot [bool] -or -not [bool]$payload.source_gateway_was_running -or $payload.local_bundle_mutation_intent -isnot [bool] -or [string]$payload.source_version -ne $script:BridgeVersion -or [string]$payload.target_version -ne $TargetVersion -or [string]$payload.os_name -ne "windows"){
        Fail "Phase-two active journal identity is invalid"
    }
    $provenanceKeys=@($payload.release_provenance.PSObject.Properties.Name|Sort-Object)
    $expectedProvenanceKeys=@("bridge","policy_commit","policy_tree","release_source_map_sha256","release_version","schema_version","source_commit","source_install_identity","source_tree")
    if(($provenanceKeys -join "`n") -ne ($expectedProvenanceKeys -join "`n") -or [int]$payload.release_provenance.schema_version -ne 1 -or [string]$payload.release_provenance.release_version -ne $TargetVersion -or [string]$payload.release_provenance.bridge.version -ne $script:BridgeVersion -or [string]$payload.release_provenance.source_install_identity.source_release -ne $TargetVersion -or [int]$payload.release_provenance.source_install_identity.source_install_compatibility_epoch -ne 2 -or [int]$payload.release_provenance.source_install_identity.runtime_config_version -ne 8){
        Fail "Phase-two active release provenance identity is invalid"
    }
    if([string]$payload.release_provenance_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$payload.receipt_provenance_binding_sha256 -cnotmatch '^[0-9a-f]{64}$' -or [string]$payload.release_provenance.bridge.checksums_sha256 -cnotmatch '^[0-9a-f]{64}$'){
        Fail "Phase-two active release provenance digest identity is invalid"
    }
    if([IO.Path]::GetFullPath([string]$payload.recovery_home) -ne [IO.Path]::GetFullPath([string]$Case.Controller) -or [IO.Path]::GetFullPath([string]$payload.data_dir) -ne [IO.Path]::GetFullPath([string]$Case.Data)){
        Fail "Phase-two active journal targets a different controller recovery home"
    }
    $expectedStatePaths=@(
        [IO.Path]::GetFullPath($Case.ConfigPath),
        [IO.Path]::GetFullPath($Case.ConfigPath+".pre-observability-migration.bak"),
        [IO.Path]::GetFullPath($Case.ConfigPath+".lock"),
        [IO.Path]::GetFullPath($Case.ConfigPath+".tmp-f3395"),
        [IO.Path]::GetFullPath((Join-Path $Case.Data ".env")),
        [IO.Path]::GetFullPath((Join-Path $Case.Data ".env.lock")),
        [IO.Path]::GetFullPath((Join-Path $Case.Data ".migration_state.json"))
    )
    $stateFiles=@($payload.state_files)
    if($stateFiles.Count -ne $expectedStatePaths.Count){Fail "Phase-two active journal lacks its exact seven-state inventory"}
    for($index=0;$index -lt $stateFiles.Count;$index++){
        if(-not ([IO.Path]::GetFullPath([string]$stateFiles[$index].active_path)).Equals($expectedStatePaths[$index],[StringComparison]::OrdinalIgnoreCase)){Fail "Phase-two active journal state inventory changed at index $index"}
    }
    $backupDir=[IO.Path]::GetFullPath([string]$payload.backup_dir);Assert-PrivateDirectoryAcl -Path $backupDir
    $rollbackRoot=Join-Path $backupDir "hard-cut-rollback";Assert-PrivateDirectoryAcl -Path $rollbackRoot
    foreach($custody in @(
        @([string]$payload.rollback_wheel_path,[string]$payload.rollback_wheel_sha256),
        @([string]$payload.rollback_gateway_path,[string]$payload.rollback_gateway_sha256)
    )){
        Assert-PrivateFileAcl -Path $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $custody[1]){Fail "Phase-two active custody digest changed"}
    }
    $receiptPath=[IO.Path]::GetFullPath([string]$payload.receipt_path)
    try{$receipt=Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two active receipt is invalid JSON"}
    if([string]$receipt.from_version -ne $script:BridgeVersion -or [string]$receipt.target_version -ne $TargetVersion -or [string]$receipt.status -ne "pending"){
        Fail "Phase-two active receipt is not the pending hard cut"
    }
    $bindingJson="{`"receipt_id`":`"$([string]$receipt.receipt_id)`",`"release_provenance_sha256`":`"$([string]$payload.release_provenance_sha256)`",`"schema_version`":1,`"source_version`":`"$script:BridgeVersion`",`"target_version`":`"$TargetVersion`"}"
    $bindingAlgorithm=[Security.Cryptography.SHA256]::Create()
    try{$expectedBinding=([BitConverter]::ToString($bindingAlgorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($bindingJson)))).Replace("-","").ToLowerInvariant()}finally{$bindingAlgorithm.Dispose()}
    if($expectedBinding -cne [string]$payload.receipt_provenance_binding_sha256){Fail "Phase-two active receipt provenance binding changed"}
    return $receiptPath
}

function Start-ResolverAndKillDuringTargetWheel {
    param([Parameter(Mandatory = $true)][object]$Case)

    Set-CaseEnvironment -Case $Case
    $uvShim=Join-Path $Case.Bin "uv.cmd";$marker=Join-Path $Case.Root "target-wheel-install.blocked"
    $release=Join-Path $Case.Root "target-wheel-install.release";$consumed=Join-Path $Case.Root "target-wheel-install.consumed"
    $stdout=Join-Path $Case.Root "target-wheel-crash.stdout.log";$stderr=Join-Path $Case.Root "target-wheel-crash.stderr.log"
    $log=Join-Path $Case.Root "target-wheel-crash.log"
    $env:DEFENSECLAW_TEST_TARGET_WHEEL="defenseclaw-$TargetVersion-py3-none-any.whl"
    $env:DEFENSECLAW_TEST_WHEEL_CRASH_MARKER=$marker
    $env:DEFENSECLAW_TEST_PACKAGE_DIR=Join-Path (Join-Path $Case.Venv "Lib\site-packages") "defenseclaw"
    $env:DEFENSECLAW_TEST_CLI_EXE=$Case.Cli
    $env:DEFENSECLAW_TEST_WHEEL_RELEASE=$release
    $env:DEFENSECLAW_TEST_WHEEL_CONSUMED=$consumed
    $batch=@"
@echo off
setlocal
echo(%*| findstr.exe /L /C:"%DEFENSECLAW_TEST_TARGET_WHEEL%" >nul
if errorlevel 1 goto delegate
if "%DEFENSECLAW_TEST_WHEEL_CRASH_MARKER%"=="" goto delegate
if exist "%DEFENSECLAW_TEST_WHEEL_CONSUMED%" goto delegate
if exist "%DEFENSECLAW_TEST_PACKAGE_DIR%" rmdir /s /q "%DEFENSECLAW_TEST_PACKAGE_DIR%"
if exist "%DEFENSECLAW_TEST_CLI_EXE%" del /f /q "%DEFENSECLAW_TEST_CLI_EXE%"
>"%DEFENSECLAW_TEST_WHEEL_CRASH_MARKER%" echo target wheel install made the CLI unimportable
:blocked
if exist "%DEFENSECLAW_TEST_WHEEL_RELEASE%" goto released
ping.exe -n 2 127.0.0.1 >nul
goto blocked
:released
>"%DEFENSECLAW_TEST_WHEEL_CONSUMED%" echo orphan mutator released
exit /b 86
:delegate
"$($script:Commanduv)" %*
exit /b %ERRORLEVEL%
"@
    [IO.File]::WriteAllText($uvShim,$batch.Replace("`n","`r`n"),[Text.Encoding]::ASCII);Set-PrivatePathAcl -Path $uvShim
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $process=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [void]$script:Sentinels.Add($process)
    try{
        $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max($HealthTimeout*3,120))
        while([DateTime]::UtcNow -lt $deadline -and -not $process.HasExited -and -not(Test-Path -LiteralPath $marker)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $marker)){Fail "Target wheel install did not reach the unimportable-CLI crash barrier"}
        $controllers=@(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)"|Where-Object{$_.Name -ieq "python.exe" -and [string]$_.CommandLine -match 'defenseclaw\.main'})
        if($controllers.Count -ne 1){Fail "Could not identify exactly one live phase-two controller child"}
        Stop-Process -Id ([int]$controllers[0].ProcessId) -Force
        [void]$process.WaitForExit(30000)
        if(-not $process.HasExited){Fail "Resolver parent did not exit after its controller was killed"}
    }catch{
        if(-not $process.HasExited){& (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $process.Id /T /F *> $null;[void]$process.WaitForExit(10000)}
        if((Test-Path -LiteralPath $marker) -and -not(Test-Path -LiteralPath $release)){[IO.File]::WriteAllText($release,"release`n",[Text.Encoding]::ASCII)}
        Remove-Item -LiteralPath $uvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
        throw
    }
    if(Test-Path -LiteralPath $Case.Cli){
        & $Case.Cli --version *> $null
        if($LASTEXITCODE -eq 0){Fail "Crash barrier did not make the canonical CLI unimportable"}
    }
    return [pscustomobject]@{Log=$log;Stdout=$stdout;Stderr=$stderr;UvShim=$uvShim;Release=$release;Consumed=$consumed}
}

function Test-PhaseTwoWheelInstallCrashRecovery {
    param([Parameter(Mandatory = $true)][object]$Case,[Parameter(Mandatory = $true)][object]$Manifest)

    Write-Step "Killing the hard cut during target wheel install with an unimportable CLI"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    $crash=Start-ResolverAndKillDuringTargetWheel -Case $Case
    try{
    $receiptPath=Assert-PhaseTwoJournalCustody -Case $Case
    if(Test-Path -LiteralPath $Case.Cli){Fail "Target wheel crash left a callable canonical CLI instead of exercising bootstrap recovery"}
    $recoveryStdout=Join-Path $Case.Root "phase-two-lease-recovery.stdout.log";$recoveryStderr=Join-Path $Case.Root "phase-two-lease-recovery.stderr.log"
    $recoveryLog=Join-Path $Case.Root "upgrade.log"
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Get-CandidateResolverPath),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $recovery=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $recoveryStdout -RedirectStandardError $recoveryStderr
    [void]$script:Sentinels.Add($recovery)
    try{
        Start-Sleep -Seconds 2
        if($recovery.HasExited){Fail "Recovery resolver exited instead of waiting on the orphan mutator lease"}
        if(Test-Path -LiteralPath $Case.Cli){Fail "Recovery mutated the CLI before the orphan mutator lease was released"}
        [IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII);Set-PrivatePathAcl -Path $crash.Release
        $releaseDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while([DateTime]::UtcNow -lt $releaseDeadline -and -not(Test-Path -LiteralPath $crash.Consumed)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $crash.Consumed)){Fail "Orphan target-wheel mutator did not release its lease"}
        [void]$recovery.WaitForExit([Math]::Max($HealthTimeout*5000,300000))
        if(-not $recovery.HasExited -or $recovery.ExitCode -ne 0){Fail "Resolver re-entry failed after the orphan mutator lease released"}
    }finally{
        if(-not(Test-Path -LiteralPath $crash.Release)){[IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII)}
        if(-not $recovery.HasExited){& (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $recovery.Id /T /F *> $null;[void]$recovery.WaitForExit(10000)}
        Start-Sleep -Milliseconds 250
        $crashOutput="";if(Test-Path -LiteralPath $crash.Stdout){$crashOutput+=(Get-Content -LiteralPath $crash.Stdout -Raw -Encoding UTF8)};if(Test-Path -LiteralPath $crash.Stderr){$crashOutput+=(Get-Content -LiteralPath $crash.Stderr -Raw -Encoding UTF8)}
        [IO.File]::WriteAllText($crash.Log,$crashOutput,(New-Object Text.UTF8Encoding($false)))
        $recoveryOutput="";if(Test-Path -LiteralPath $recoveryStdout){$recoveryOutput+=(Get-Content -LiteralPath $recoveryStdout -Raw -Encoding UTF8)};if(Test-Path -LiteralPath $recoveryStderr){$recoveryOutput+=(Get-Content -LiteralPath $recoveryStderr -Raw -Encoding UTF8)}
        [IO.File]::WriteAllText($recoveryLog,$recoveryOutput,(New-Object Text.UTF8Encoding($false)))
        Remove-Item -LiteralPath $crash.UvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
    }
    $journal=Join-Path (Join-Path $Case.Controller ".upgrade-recovery") "phase-two-active.json"
    if(Test-Path -LiteralPath $journal){Fail "Successful resolver re-entry left the phase-two journal active"}
    if(Test-Path -LiteralPath $receiptPath){
        $interrupted=Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8|ConvertFrom-Json
        if([string]$interrupted.status -ne "rolled_back" -or [string]$interrupted.failure_code -ne "interrupted"){
            Show-LogTail $crash.Log;Fail "Wheel-install crash receipt was not completed as rolled_back/interrupted"
        }
    }else{
        Assert-CanonicalUpgradeOutcome -Case $Case -From $script:BridgeVersion -Target $TargetVersion -Status "rolled_back" -FailureCode "interrupted"
    }
    $text=Get-Content -LiteralPath $recoveryLog -Raw -Encoding UTF8
    if($text -notmatch '(?i)Recovered interrupted phase-two hard cut'){Show-LogTail $recoveryLog;Fail "Resolver did not report phase-two bootstrap recovery before continuing"}
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Phase-two bootstrap recovery changed persistent user PATH"}
    Assert-UpgradeSucceeded -Case $Case -Manifest $Manifest -RequireV8 -RequireRetainedBridge
    Write-Ok "Unimportable target-wheel crash bootstrapped the retained bridge, rolled back, and safely continued"
    }finally{
        if(-not(Test-Path -LiteralPath $crash.Release)){[IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII)}
        Remove-Item -LiteralPath $crash.UvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
    }
}

function Start-PostPublishPortBlocker {
    param([Parameter(Mandatory = $true)][object]$Case)

    $monitorPath = Join-Path $Case.Root "post-v8-port-blocker.py"
    $markerPath = Join-Path $Case.Root "post-v8-port-blocker.bound"
    $source = @'
import pathlib
import re
import socket
import struct
import sys
import time

config = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])
marker = pathlib.Path(sys.argv[3])
deadline = time.monotonic() + 180
listener = None
saw_v8 = False
published = re.compile(rb"(?m)^\s*config_version:\s*8\s*$")
while time.monotonic() < deadline:
    try:
        payload = config.read_bytes()
    except OSError:
        time.sleep(0.002)
        continue
    is_v8 = bool(published.search(payload))
    if is_v8 and listener is None:
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            candidate.bind(("127.0.0.1", port))
            candidate.listen(32)
            candidate.settimeout(0.01)
            listener = candidate
        except OSError:
            candidate.close()
    if listener is not None and is_v8 and not saw_v8:
        saw_v8 = True
        try:
            marker.write_text("bound-after-v8-publish\n", encoding="ascii")
        except OSError:
            listener.close()
            raise
    if listener is not None:
        if saw_v8 and not is_v8:
            listener.close()
            raise SystemExit(0)
        try:
            connection, _ = listener.accept()
        except (TimeoutError, socket.timeout):
            pass
        else:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
            connection.close()
    time.sleep(0.002)
if listener is not None:
    listener.close()
raise SystemExit(2)
'@
    [IO.File]::WriteAllText($monitorPath, $source, (New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $monitorPath
    $stdout = Join-Path $Case.Root "post-v8-port-blocker.out.log"
    $stderr = Join-Path $Case.Root "post-v8-port-blocker.err.log"
    $process = Start-Process -FilePath $script:Commandpython `
        -ArgumentList @(
            (Quote-ProcessArgument $monitorPath),
            (Quote-ProcessArgument $Case.ConfigPath),
            [string]$Case.GatewayPort,
            (Quote-ProcessArgument $markerPath)
        ) `
        -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return [pscustomobject]@{ Process = $process; Marker = $markerPath; ErrorLog = $stderr }
}

function Assert-RolledBackReceipt {
    param([Parameter(Mandatory = $true)][object]$Case)
    $receiptMatches = @(
        (Get-UpgradeReceipts -Case $Case) | Where-Object {
            [string]$_.from_version -eq $script:BridgeVersion -and
            [string]$_.target_version -eq $TargetVersion -and
            [string]$_.status -eq "rolled_back" -and
            [string]$_.failure_code -eq "health_check_failed" -and
            $_.artifacts_verified -eq $true
        }
    )
    if ($receiptMatches.Count -eq 0) {
        # A healthy restored bridge may asynchronously admit the terminal
        # receipt before this assertion runs. In that case require the exact
        # canonical event rather than weakening the rollback outcome check.
        Assert-CanonicalUpgradeOutcome -Case $Case -From $script:BridgeVersion -Target $TargetVersion `
            -Status "rolled_back" -FailureCode "health_check_failed"
    }
}

function Assert-BridgeRollbackState {
    param([Parameter(Mandatory = $true)][object]$Case)

    Assert-CaseConfigVersion -Case $Case -Expected 7 -Label "rolled-back bridge state"
    $backupRoot = Join-Path $Case.Data "backups"
    $stateDirectories = @(
        Get-ChildItem -LiteralPath $backupRoot -Directory -Filter "upgrade-*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $candidate = Join-Path (Join-Path $_.FullName "hard-cut-rollback") "state"
                if (Test-Path -LiteralPath $candidate -PathType Container) {
                    Get-Item -LiteralPath $candidate
                }
            } |
            Sort-Object LastWriteTimeUtc -Descending
    )
    if ($stateDirectories.Count -ne 1) {
        Fail "Expected exactly one retained pre-v8 bridge-state snapshot, got $($stateDirectories.Count)"
    }
    $stateDirectory = $stateDirectories[0].FullName
    Assert-PrivateDirectoryAcl -Path $stateDirectory
    $pairs = @(
        [pscustomobject]@{ Active = $Case.ConfigPath; Backup = Join-Path $stateDirectory "config.yaml"; Label = "config" },
        [pscustomobject]@{ Active = Join-Path $Case.Data ".env"; Backup = Join-Path $stateDirectory "environment"; Label = "environment" },
        [pscustomobject]@{ Active = Join-Path $Case.Data ".migration_state.json"; Backup = Join-Path $stateDirectory "migration-state.json"; Label = "migration cursor" }
    )
    foreach ($pair in $pairs) {
        if (-not (Test-Path -LiteralPath $pair.Active -PathType Leaf) -or
            -not (Test-Path -LiteralPath $pair.Backup -PathType Leaf)) {
            Fail "Bridge rollback lacks exact $($pair.Label) custody"
        }
        Assert-PrivateFileAcl -Path $pair.Active
        Assert-PrivateFileAcl -Path $pair.Backup
        $activeHash = (Get-FileHash -LiteralPath $pair.Active -Algorithm SHA256).Hash
        $backupHash = (Get-FileHash -LiteralPath $pair.Backup -Algorithm SHA256).Hash
        if ($activeHash -cne $backupHash) {
            Fail "Rolled-back $($pair.Label) differs from the exact pre-v8 bridge snapshot"
        }
    }

    $cursor = Get-Content -LiteralPath (Join-Path $Case.Data ".migration_state.json") -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $bridgeManifest = Get-Content -LiteralPath (
        Join-Path (Join-Path $script:ReleaseRoot $script:BridgeVersion) "upgrade-manifest.json"
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
    $targetManifest = Get-Content -LiteralPath (
        Join-Path (Join-Path $script:ReleaseRoot $TargetVersion) "upgrade-manifest.json"
    ) -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($migration in @($bridgeManifest.required_cli_migrations)) {
        if (@($cursor.applied) -notcontains [string]$migration) {
            Fail "Rolled-back bridge cursor is missing required migration $migration"
        }
    }
    foreach ($migration in @($targetManifest.required_cli_migrations)) {
        if (@($bridgeManifest.required_cli_migrations) -notcontains [string]$migration -and
            @($cursor.applied) -contains [string]$migration) {
            Fail "Rolled-back bridge cursor retained target-only migration $migration"
        }
    }

    foreach ($journalName in @("phase-one-active.json", "phase-two-active.json")) {
        $journal = Join-Path (Join-Path $Case.Controller ".upgrade-recovery") $journalName
        if (Test-Path -LiteralPath $journal) {
            Fail "Rolled-back bridge retained active recovery journal $journalName"
        }
    }
    $invalidTargetReceipts = @(
        Get-UpgradeReceipts -Case $Case | Where-Object {
            [string]$_.target_version -eq $TargetVersion -and
            [string]$_.status -in @("pending", "partial", "succeeded")
        }
    )
    if ($invalidTargetReceipts.Count -ne 0) {
        Fail "Rolled-back hard cut retained a pending, partial, or succeeded target receipt"
    }
    if ((Compare-Version ([string]$Case.BaselineVersion) $script:BridgeVersion) -lt 0) {
        foreach ($transition in @(
            @([string]$Case.BaselineVersion, [string]$script:BridgeVersion),
            @([string]$script:BridgeVersion, [string]$script:BridgeVersion)
        )) {
            $matches = @(
                Get-UpgradeReceipts -Case $Case | Where-Object {
                    [string]$_.from_version -eq $transition[0] -and
                    [string]$_.target_version -eq $transition[1] -and
                    [string]$_.status -eq "succeeded" -and
                    [string]$_.migration_status -eq "completed" -and
                    $_.artifacts_verified -eq $true -and
                    [string]::IsNullOrEmpty([string]$_.failure_code)
                }
            )
            if ($matches.Count -gt 1) {
                Fail "Bridge phase retained duplicate succeeded evidence for $($transition[0]) -> $($transition[1])"
            }
            if ($matches.Count -eq 0) {
                # A target process may have admitted the terminal queue file
                # before the injected health failure. In that case the exact
                # canonical row is the durable evidence; otherwise the
                # restored bridge retains the verified queue file.
                Assert-CanonicalUpgradeEvent -Case $Case -From $transition[0] -Target $transition[1]
            }
        }
    }
}

function Test-PostPublishRollback {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Injecting target health failure after v8 publication and proving exact bridge rollback"
    Set-CaseEnvironment -Case $Case
    Assert-CaseConfigVersion -Case $Case -Expected $Case.SourceConfigVersion -Label "post-publish source fixture"
    $stagedFromHistoricalSource = (Compare-Version ([string]$Case.BaselineVersion) $script:BridgeVersion) -lt 0
    $before = Join-Path $Case.Root "phase-two-state.before.json"
    $after = Join-Path $Case.Root "phase-two-state.after.json"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $blocker = Start-PostPublishPortBlocker -Case $Case
    $log = Join-Path $Case.Root "rollback-injection.log"
    $injectedTimeout = [Math]::Min($HealthTimeout, 15)
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Get-CandidateResolverPath),
        "-Yes", "-HealthTimeout", [string]$injectedTimeout,
        "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
    )
    if ($stagedFromHistoricalSource) {
        $arguments += @("-LatestVersionOverride", $TargetVersion)
    } else {
        $arguments += @("-Version", $TargetVersion)
    }
    try {
        $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if ($status -eq 0) {
            Show-LogTail $log
            Fail "Injected post-publish target health failure unexpectedly succeeded"
        }
        if (-not (Test-Path -LiteralPath $blocker.Marker -PathType Leaf)) {
            Show-LogTail $blocker.ErrorLog
            Show-LogTail $log
            Fail "Failure injector never observed v8 publication or could not reserve the gateway port"
        }
        if (-not $blocker.Process.HasExited) {
            $blocker.Process.WaitForExit(20000) | Out-Null
        }
        if (-not $blocker.Process.HasExited) {
            Fail "Post-publish port blocker did not observe rollback to the bridge configuration"
        }
        if ($blocker.Process.ExitCode -ne 0) {
            Show-LogTail $blocker.ErrorLog
            Fail "Post-publish port blocker exited without observing the v7 rollback"
        }
        Write-TransactionalStateSnapshot -Case $Case -Output $after
        if ($stagedFromHistoricalSource) {
            Assert-BridgeRollbackState -Case $Case
        } else {
            Assert-SnapshotsEqual -Before $before -After $after -Label "hard-cut rollback transaction"
        }
        Assert-CommandVersion -Command $Case.Cli -Expected $script:BridgeVersion -Label "rolled-back CLI"
        Assert-CommandVersion -Command $Case.Gateway -Expected $script:BridgeVersion -Label "rolled-back gateway"
        $health=$null;$deadline=[DateTime]::UtcNow.AddSeconds([Math]::Min($HealthTimeout,30))
        while([DateTime]::UtcNow -lt $deadline){
            try{
                $candidate=Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2
                $gateway=Get-Property $candidate "gateway";$provenance=Get-Property $candidate "provenance"
                $state=if($gateway){Get-Property $gateway.Value "state"}else{$null}
                $version=if($provenance){Get-Property $provenance.Value "binary_version"}else{$null}
                if($state -and [string]$state.Value -eq "running" -and $version -and [string]$version.Value -eq $script:BridgeVersion){$health=$candidate;break}
            }catch{}
            Start-Sleep -Milliseconds 250
        }
        if($null -eq $health){Fail "Rolled-back bridge did not report running at $($script:BridgeVersion)"}
        Assert-RolledBackReceipt -Case $Case
        Assert-RetainedBridgeArtifacts -Case $Case
        $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if ($text -notmatch '(?i)rolled back|rollback') {
            Show-LogTail $log
            Fail "Injected failure log did not report rollback"
        }
    } finally {
        if ($blocker -and -not $blocker.Process.HasExited) {
            Stop-Process -Id $blocker.Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Ok "Post-v8 failure restored exact config/.env/cursor bytes and owner/DACL, then recovered healthy 0.8.4"
}

function Get-UpgradeReceipts {
    param([Parameter(Mandatory = $true)][object]$Case)
    $root = Join-Path $Case.Data ".upgrade-receipts"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $receipts = @()
    foreach ($path in Get-ChildItem -LiteralPath $root -Filter "*.json" -File) {
        try {
            $payload = Get-Content -LiteralPath $path.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $receipts += $payload
        } catch {
            if (-not (Test-Path -LiteralPath $path.FullName)) { continue }
            Fail "Malformed upgrade receipt: $($path.FullName)"
        }
    }
    return $receipts
}

function Assert-SucceededReceipt {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][object[]]$Receipts,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target
    )
    $nonterminal = @(
        $Receipts | Where-Object {
            [string]$_.status -in @("pending", "partial")
        }
    )
    if ($nonterminal.Count -ne 0) {
        Fail "Successful staged upgrade left a pending or partial receipt"
    }
    $targetReceipts = @(
        $Receipts | Where-Object { [string]$_.target_version -eq $Target }
    )
    if ($targetReceipts.Count -gt 1) {
        Fail "Successful staged upgrade left more than one terminal target receipt"
    }
    $receiptMatches = @(
        $Receipts | Where-Object {
            [string]$_.from_version -eq $From -and
            [string]$_.target_version -eq $Target -and
            [string]$_.status -eq "succeeded" -and
            [string]$_.migration_status -eq "completed" -and
            $_.artifacts_verified -eq $true -and
            [string]::IsNullOrEmpty([string]$_.failure_code)
        }
    )
    if ($receiptMatches.Count -gt 1) {
        Fail "Successful staged upgrade left duplicate succeeded receipts"
    }
    if ($targetReceipts.Count -eq 1 -and $receiptMatches.Count -eq 0) {
        Fail "Successful staged upgrade left an invalid terminal target receipt"
    }
    if ($targetReceipts.Count -eq 0) {
        # A healthy v8 gateway acknowledges terminal handoff files after
        # canonical audit persistence.  Accept that durable row if the queue
        # file was consumed after the production resolver verified it.
        Assert-CanonicalUpgradeOutcome -Case $Case -From $From -Target $Target `
            -Status "succeeded" -FailureCode ""
    }
}

function Assert-CanonicalUpgradeOutcome {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FailureCode
    )

    $database = Join-Path $Case.Data "audit.db"
    if (-not (Test-Path -LiteralPath $database -PathType Leaf)) {
        Fail "Canonical audit database is missing after the hard cut"
    }
    $probe = @'
import sqlite3
import sys
import time
from pathlib import Path

database, source, target, status, failure_code = sys.argv[1:]
if failure_code == "__DEFENSECLAW_EMPTY_FAILURE__":
    failure_code = ""
identity = f"status={status} from_version={source} target_version={target}"
failure = f"failure_code={failure_code}"
verified = "artifacts_verified=true"
deadline = time.monotonic() + 10
database_uri = Path(database).resolve().as_uri() + "?mode=ro"
while True:
    try:
        connection = sqlite3.connect(database_uri, uri=True, timeout=1)
        try:
            rows = connection.execute(
                "SELECT details FROM audit_events WHERE action = 'upgrade'"
            ).fetchall()
        finally:
            connection.close()
        if any(
            identity in str(row[0]) and failure in str(row[0]) and verified in str(row[0])
            for row in rows
        ):
            raise SystemExit(0)
    except sqlite3.Error:
        pass
    if time.monotonic() >= deadline:
        raise SystemExit(1)
    time.sleep(0.25)
'@
    $failureArgument = if ($FailureCode) { $FailureCode } else { "__DEFENSECLAW_EMPTY_FAILURE__" }
    $probe | & $Case.Python - $database $From $Target $Status $failureArgument
    if ($LASTEXITCODE -ne 0) {
        Fail "Canonical audit does not contain $Status event $From -> $Target with failure_code=$FailureCode"
    }
}

function Assert-CanonicalUpgradeEvent {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target
    )
    Assert-CanonicalUpgradeOutcome -Case $Case -From $From -Target $Target `
        -Status "succeeded" -FailureCode ""
}

function Assert-RetainedBridgeArtifacts {
    param([Parameter(Mandatory = $true)][object]$Case)

    $backupRoot = Join-Path $Case.Data "backups"
    $retained = @(
        Get-ChildItem -LiteralPath $backupRoot -Directory -Filter "staged-bridge-*" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
    )
    if ($retained.Count -eq 0) { Fail "No retained bridge release was found" }
    $directory = $retained[0].FullName
    Assert-PrivateDirectoryAcl -Path $directory
    foreach ($name in @(
        "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "upgrade-manifest.json",
        "defenseclaw-$($script:BridgeVersion)-2-py3-none-any.dcwheel",
        "defenseclaw_$($script:BridgeVersion)_protocol2_windows_amd64.dcgateway",
        "defenseclaw-$($script:BridgeVersion)-py3-none-any.whl",
        "defenseclaw_$($script:BridgeVersion)_windows_amd64.zip"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $directory $name) -PathType Leaf)) {
            Fail "Retained bridge directory is incomplete: $name"
        }
    }
    [void](Assert-ReleaseSet -Directory $directory -Version $script:BridgeVersion)
    Write-Ok "Retained bridge artifacts are signed, complete, and protected by a private DACL"
}

function Assert-UpgradeSucceeded {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][object]$Manifest,
        [switch]$RequireV8,
        [switch]$RequireAutoBridge,
        [switch]$RequireRetainedBridge
    )

    Set-CaseEnvironment -Case $Case
    Assert-CommandVersion -Command $Case.Cli -Expected $TargetVersion -Label "upgraded CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $TargetVersion -Label "upgraded gateway"
    & $Case.Gateway status *> $null
    if ($LASTEXITCODE -ne 0) { Fail "Target gateway status failed for $($Case.Name)" }
    $health = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeout)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $candidate = Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2
            $gateway=Get-Property $candidate "gateway";$provenance=Get-Property $candidate "provenance"
            $state=if($gateway){Get-Property $gateway.Value "state"}else{$null}
            $version=if($provenance){Get-Property $provenance.Value "binary_version"}else{$null}
            if($state -and [string]$state.Value -eq "running" -and $version -and [string]$version.Value -eq $TargetVersion){$health=$candidate;break}
        } catch {
        }
        Start-Sleep -Milliseconds 250
    }
    if ($null -eq $health) { Fail "Target gateway did not report running at $TargetVersion for $($Case.Name)" }

    if ($RequireV8) {
        Assert-CaseConfigVersion -Case $Case -Expected 8 -Label "hard-cut target"
    } elseif ($TargetVersion -eq $script:BridgeVersion) {
        Assert-CaseConfigVersion -Case $Case -Expected 7 -Label "published bridge target"
    }
    $cursorPath = Join-Path $Case.Data ".migration_state.json"
    if (-not (Test-Path -LiteralPath $cursorPath -PathType Leaf)) {
        Fail "Successful upgrade did not write a migration cursor"
    }
    $cursor = Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $required = Get-Property $Manifest "required_cli_migrations"
    if ($required) {
        foreach ($migration in @($required.Value)) {
            if (@($cursor.applied) -notcontains [string]$migration) {
                Fail "Migration cursor does not contain required migration $migration"
            }
        }
    }

    $receipts = @(Get-UpgradeReceipts -Case $Case)
    if ($RequireAutoBridge) {
        # Starting the hard-cut gateway admits and removes already-terminal
        # bridge queue files.  Their canonical v8 audit rows (rather than a
        # now-consumed handoff file) prove resolver-direct bridge activation
        # plus the fresh 0.8.4 migration/health process. Same-version resolver
        # calls are separately verified as no-ops and do not create these rows.
        Assert-CanonicalUpgradeEvent -Case $Case -From $script:OldBaseline -Target $script:BridgeVersion
        Assert-CanonicalUpgradeEvent -Case $Case -From $script:BridgeVersion -Target $script:BridgeVersion
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:BridgeVersion -Target $TargetVersion
    } elseif ($RequireV8) {
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:BridgeVersion -Target $TargetVersion
    } else {
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:OldBaseline -Target $TargetVersion
    }
    if ($RequireRetainedBridge) { Assert-RetainedBridgeArtifacts -Case $Case }
    Write-Ok "Healthy $TargetVersion CLI/gateway, required cursor, and succeeded receipts verified"
}

function Stop-CaseGateway {
    param([Parameter(Mandatory = $true)][object]$Case)
    try {
        Set-CaseEnvironment -Case $Case
        if (Test-Path -LiteralPath $Case.Gateway -PathType Leaf) {
            & $Case.Gateway stop *> $null
        }
    } catch {
        # Cleanup remains best-effort; the case root is isolated and is removed
        # after all child processes have been terminated.
    }
}

function Assert-CandidatePolicy {
    param([Parameter(Mandatory = $true)][object]$Manifest)

    $minProtocolProperty = Get-Property $Manifest "min_upgrade_protocol"
    $controllerProperty = Get-Property $Manifest "controller_upgrade_protocol"
    $minimumProperty = Get-Property $Manifest "minimum_source_version"
    $bridgeProperty = Get-Property $Manifest "required_bridge_version"
    $automaticProperty = Get-Property $Manifest "auto_bridge_from"
    $testedProperty = Get-Property $Manifest "tested_source_versions"
    $platformTestedProperty = Get-Property $Manifest "platform_tested_source_versions"
    $minProtocol = if ($minProtocolProperty) { [int]$minProtocolProperty.Value } else { 1 }
    $controllerProtocol = if ($controllerProperty) { [int]$controllerProperty.Value } else { $minProtocol }
    $hasBridge = $null -ne $minimumProperty -or $null -ne $bridgeProperty -or $null -ne $automaticProperty

    if (-not $testedProperty -or -not $platformTestedProperty) {
        Fail "Schema-2 candidate lacks its signed tested-source policy"
    }
    $expectedTested = @(
        $script:PublishedBaselines |
            Where-Object { (Compare-Version ([string]$_) $TargetVersion) -lt 0 }
    )
    $tested = @($testedProperty.Value)
    if (($tested -join "`n") -ne ($expectedTested -join "`n")) {
        Fail "Candidate tested_source_versions does not match the reviewed global matrix"
    }
    $platformNames = @($platformTestedProperty.Value.PSObject.Properties.Name)
    $windowsProperty = Get-Property $platformTestedProperty.Value "windows"
    $expectedWindows = @(
        $script:PublishedWindowsBaselines |
            Where-Object { (Compare-Version ([string]$_) $TargetVersion) -lt 0 }
    )
    if ($platformNames.Count -ne 1 -or -not $windowsProperty -or
        (@($windowsProperty.Value) -join "`n") -ne ($expectedWindows -join "`n")) {
        Fail "Candidate platform_tested_source_versions.windows does not match the reviewed Windows matrix"
    }
    if ($expectedWindows -notcontains $script:OldBaseline) {
        Fail "Candidate Windows tested-source policy does not include selected baseline $($script:OldBaseline)"
    }

    if ((Compare-Version $TargetVersion $script:HardCutVersion) -ge 0) {
        if (-not $minimumProperty -or -not $bridgeProperty -or -not $automaticProperty -or $minProtocol -lt 2) {
            Fail "Hard-cut candidate lacks its complete protocol-2 bridge contract"
        }
        if ([string]$minimumProperty.Value -ne $script:BridgeVersion -or
            [string]$bridgeProperty.Value -ne $script:BridgeVersion) {
            Fail "Hard-cut candidate must name published bridge $($script:BridgeVersion)"
        }
        $automatic = @($automaticProperty.Value)
        foreach ($value in $automatic) {
            if ($value -isnot [string] -or
                $value -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
                Fail "Hard-cut auto_bridge_from contains a non-canonical version"
            }
        }
        if (@($automatic | Sort-Object -Unique).Count -ne $automatic.Count) {
            Fail "Hard-cut auto_bridge_from contains duplicate versions"
        }
        $missing = @(
            $script:PublishedPreBridgeBaselines |
                Where-Object { $automatic -notcontains ([string]$_) }
        )
        $unexpected = @(
            $automatic |
                Where-Object { $script:PublishedPreBridgeBaselines -notcontains ([string]$_) }
        )
        if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
            Fail (
                "Hard-cut auto_bridge_from must exactly match the reviewed pre-bridge baseline policy " +
                "(missing=$($missing -join ','); unexpected=$($unexpected -join ','))"
            )
        }
        if ($automatic -notcontains $script:OldBaseline) {
            Fail "Hard-cut auto_bridge_from does not include tested baseline $($script:OldBaseline)"
        }
        $required = Get-Property $Manifest "required_cli_migrations"
        if (-not $required -or @($required.Value) -notcontains $script:HardCutVersion) {
            Fail "Hard-cut candidate does not require migration $($script:HardCutVersion)"
        }
        return $true
    }

    if ($hasBridge) { Fail "A pre-hard-cut candidate unexpectedly declares a partial bridge contract" }
    if ($TargetVersion -eq $script:BridgeVersion -and $controllerProtocol -lt 2) {
        Fail "Bridge candidate does not ship a protocol-2 controller"
    }
    return $false
}

function Cleanup {
    foreach ($case in $script:Cases) { Stop-CaseGateway -Case $case }
    foreach ($sentinel in $script:Sentinels) {
        try {
            if (-not $sentinel.HasExited) {
                Stop-Process -Id $sentinel.Id -Force -ErrorAction SilentlyContinue
                $sentinel.WaitForExit(5000) | Out-Null
            }
        } catch { }
    }
    if ($script:ServerProcess) {
        try {
            if (-not $script:ServerProcess.HasExited) {
                Stop-Process -Id $script:ServerProcess.Id -Force -ErrorAction SilentlyContinue
                $script:ServerProcess.WaitForExit(5000) | Out-Null
            }
        } catch { }
    }
    Restore-ProcessEnvironment
    if ($script:WorkRoot -and (Test-Path -LiteralPath $script:WorkRoot)) {
        if ($KeepWorkDir) {
            Write-Host "Kept Windows upgrade gate work directory: $($script:WorkRoot)" -ForegroundColor Yellow
        } else {
            Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Main {
    Assert-RequiredCommands
    Save-ProcessEnvironment
    Read-UpgradeBaselinePolicy
    if ((Compare-Version $TargetVersion $script:OldBaseline) -le 0) {
        Fail "TargetVersion must be newer than published baseline $($script:OldBaseline)"
    }

    $script:WorkRoot = New-PrivateDirectory -Path (
        Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-windows-release-gate-" + [guid]::NewGuid().ToString("N"))
    )
    $script:ReleaseRoot = New-PrivateDirectory -Path (Join-Path $script:WorkRoot "releases")

    Write-Step "Authenticating sealed candidate $TargetVersion"
    [void](Copy-CandidateRelease)
    $candidateManifestPath = Join-Path (Join-Path $script:ReleaseRoot $TargetVersion) "upgrade-manifest.json"
    try {
        $candidateManifest = Get-Content -LiteralPath $candidateManifestPath `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Fail "Authenticated sealed candidate manifest could not be read"
    }
    if ($candidateManifest -isnot [pscustomobject]) {
        Fail "Authenticated sealed candidate manifest is not one JSON object"
    }
    $hardCut = Assert-CandidatePolicy -Manifest $candidateManifest
    [void](Ensure-PublishedRelease -Version $script:OldBaseline)
    if ($hardCut) {
        [void](Ensure-PublishedRelease -Version $script:BridgeVersion)
    }
    Clear-UpgradeTestEnvironment
    Start-ReleaseServer

    if ($hardCut) {
        $refusal = New-UpgradeCase -Name "hard-cut-refusal" -BaselineVersion $script:OldBaseline
        Test-InstallerExistingInstallRefusal -Case $refusal
        Test-HardCutExplicitRefusal -Case $refusal
        Test-ProtectedMaterializationCollision -Case $refusal
        Stop-CaseGateway -Case $refusal

        $phaseOneRollback = New-UpgradeCase -Name "phase-one-rollback" -BaselineVersion $script:OldBaseline
        Test-PhaseOneRollback -Case $phaseOneRollback
        Stop-CaseGateway -Case $phaseOneRollback

        $phaseOneConcurrentDivergence = New-UpgradeCase -Name "phase-one-concurrent-divergence" -BaselineVersion $script:OldBaseline
        Test-PhaseOneConcurrentDivergence -Case $phaseOneConcurrentDivergence
        Stop-CaseGateway -Case $phaseOneConcurrentDivergence

        $phaseOneCrash = New-UpgradeCase -Name "phase-one-crash-recovery" -BaselineVersion $script:OldBaseline
        Test-PhaseOneStopFailures -Case $phaseOneCrash
        Test-PhaseOneCrashRecovery -Case $phaseOneCrash
        Stop-CaseGateway -Case $phaseOneCrash

        $phaseOneParentDeath = New-UpgradeCase -Name "phase-one-parent-death-lease" -BaselineVersion $script:OldBaseline
        Test-PhaseOneParentDeathLeaseRecovery -Case $phaseOneParentDeath
        Stop-CaseGateway -Case $phaseOneParentDeath

        $phaseOneReceiptOrdering = New-UpgradeCase -Name "phase-one-receipt-ordering" -BaselineVersion $script:OldBaseline
        Test-PhaseOneJournalCloseReceiptOrdering -Case $phaseOneReceiptOrdering -Manifest $candidateManifest
        Stop-CaseGateway -Case $phaseOneReceiptOrdering

        $phaseTwoWheelCrash = New-UpgradeCase -Name "phase-two-wheel-crash" -BaselineVersion $script:OldBaseline
        Test-PhaseTwoWheelInstallCrashRecovery -Case $phaseTwoWheelCrash -Manifest $candidateManifest
        Stop-CaseGateway -Case $phaseTwoWheelCrash

        $automatic = New-UpgradeCase -Name "automatic-bridge" -BaselineVersion $script:OldBaseline
        $automaticForeign=@(New-ForeignPhaseOneMutationTemporaries -Case $automatic)
        Write-Step "Running one-command latest path: $($script:OldBaseline) -> $($script:BridgeVersion) -> $TargetVersion"
        Invoke-ResolverUpgrade -Case $automatic -Latest -AdditionalArguments @("-InjectPhaseOneOwnedMutationTemporaries")
        Assert-UpgradeSucceeded -Case $automatic -Manifest $candidateManifest `
            -RequireV8 -RequireAutoBridge -RequireRetainedBridge
        Assert-PhaseOneMutationTemporaries -Case $automatic -ForeignRecords $automaticForeign
        Stop-CaseGateway -Case $automatic

        $splitDefault = New-UpgradeCase -Name "split-data-default-config" -BaselineVersion $script:OldBaseline -SplitDataDir
        if($splitDefault.ConfigExplicit -or ([IO.Path]::GetFullPath($splitDefault.Controller)).Equals([IO.Path]::GetFullPath($splitDefault.Data),[StringComparison]::OrdinalIgnoreCase)){Fail "Raw data_dir case did not preserve a default controller-owned config with split mutable state"}
        Test-PhaseOneCrashRecovery -Case $splitDefault
        Write-Step "Running no-override raw data_dir staged path"
        Invoke-ResolverUpgrade -Case $splitDefault -Latest
        Assert-UpgradeSucceeded -Case $splitDefault -Manifest $candidateManifest -RequireV8 -RequireAutoBridge -RequireRetainedBridge
        Stop-CaseGateway -Case $splitDefault

        $externalConfig = New-UpgradeCase -Name "split-data-external-config" -BaselineVersion $script:OldBaseline -ExternalConfig
        if(-not $externalConfig.ConfigExplicit -or ([IO.Path]::GetFullPath($externalConfig.ConfigPath)).StartsWith(([IO.Path]::GetFullPath($externalConfig.Controller).TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){Fail "External-config case did not bind an explicit config outside controller custody"}
        Test-PhaseOneRollback -Case $externalConfig
        $externalForeign=@(Test-PhaseOneOwnedTemporaryRollback -Case $externalConfig -SeedForeign)
        Write-Step "Running explicit external-config staged path with phase-two crash recovery"
        Test-PhaseTwoWheelInstallCrashRecovery -Case $externalConfig -Manifest $candidateManifest
        Assert-PhaseOneMutationTemporaries -Case $externalConfig -ForeignRecords $externalForeign
        Stop-CaseGateway -Case $externalConfig

        $noOpenClaw = New-UpgradeCase -Name "no-openclaw-install" -BaselineVersion $script:OldBaseline -SplitDataDir -NoOpenClaw
        Set-CaseEnvironment -Case $noOpenClaw
        if(Get-Command openclaw -ErrorAction SilentlyContinue){Fail "No-OpenClaw staged case unexpectedly found an OpenClaw executable"}
        Test-HardCutExplicitRefusal -Case $noOpenClaw
        if(Test-Path -LiteralPath $noOpenClaw.OpenClawHome){Fail "Preflight refusal created an absent OpenClaw home"}
        [void](Test-PhaseOneOwnedTemporaryRollback -Case $noOpenClaw)
        if(Test-Path -LiteralPath $noOpenClaw.OpenClawHome){Fail "Owned-temporary rollback retained an attempt-created OpenClaw home"}
        Test-PhaseOneCrashRecovery -Case $noOpenClaw
        if(Test-Path -LiteralPath $noOpenClaw.OpenClawHome){Fail "Phase-one crash recovery created an absent OpenClaw home"}
        Write-Step "Running staged path with no OpenClaw executable or home"
        Invoke-ResolverUpgrade -Case $noOpenClaw -Latest
        Assert-UpgradeSucceeded -Case $noOpenClaw -Manifest $candidateManifest -RequireV8 -RequireAutoBridge -RequireRetainedBridge
        if(Test-Path -LiteralPath $noOpenClaw.OpenClawHome){Fail "Connector-none staged upgrade created an unowned OpenClaw home"}
        Stop-CaseGateway -Case $noOpenClaw

        $direct = New-UpgradeCase -Name "direct-bridge" -BaselineVersion $script:BridgeVersion
        Write-Step "Running direct published bridge path: $($script:BridgeVersion) -> $TargetVersion"
        Invoke-ResolverUpgrade -Case $direct -Explicit
        Assert-UpgradeSucceeded -Case $direct -Manifest $candidateManifest `
            -RequireV8 -RequireRetainedBridge
        Stop-CaseGateway -Case $direct

        $rollback = New-UpgradeCase -Name "post-publish-staged-rollback" -BaselineVersion $script:OldBaseline
        Test-PostPublishRollback -Case $rollback
        Stop-CaseGateway -Case $rollback
        Write-Ok "Native hard-cut matrix passed: refusal, both phase rollbacks, automatic bridge, and direct bridge"
    } else {
        # This branch is the bridge release's own gate.  It cannot exercise a
        # not-yet-published hard cut, but it must prove the published 0.8.3
        # controller can install this candidate and that install.ps1 cannot be
        # abused as an unsigned existing-install updater.
        $bridgeCandidate = New-UpgradeCase -Name "bridge-candidate" -BaselineVersion $script:OldBaseline
        Test-InstallerExistingInstallRefusal -Case $bridgeCandidate
        Write-Step "Running published $($script:OldBaseline) -> candidate $TargetVersion upgrade"
        Invoke-ResolverUpgrade -Case $bridgeCandidate -Explicit
        Assert-UpgradeSucceeded -Case $bridgeCandidate -Manifest $candidateManifest
        Stop-CaseGateway -Case $bridgeCandidate
        Write-Ok "Native bridge-candidate matrix passed"
    }
}

$exitCode = 0
try {
    Main
} catch {
    $exitCode = 1
    Write-Host ""
    Write-Host "Windows upgrade release gate failed: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Cleanup
}
exit $exitCode
