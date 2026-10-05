# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    CI install lane for the standalone managed-enterprise Windows Setup.
.DESCRIPTION
    Runs the MDM-deployable DefenseClawSetup-Enterprise-Standalone-x64.exe on
    a real Windows x64 host with the Windows service control manager:

      1. /ensure CONFIG=<administrator config> JSON=1 installs the four
         services from the Setup's hash-pinned payload and enrolls this
         account for Claude Code and Codex: the Codex requirements and the
         Claude Code managed-settings fragment name the DefenseClaw hook
      2. /ensure JSON=1 again must be a no-op
      3. the installed CLI's verify and status pass, the services run, the
         HKLM marker and the Add/Remove Programs entry exist, and the MDM
         detect.ps1 (Windows PowerShell 5.1, as Intune runs it) detects it
      4. the installed CLI's own ensure (the command Remediate-Fix.ps1 runs,
         without trust flags) is a no-op and keeps the marker's hash_pinned
         trust mode, so detection keeps working
      5. /uninstall JSON=1 removes the services, the marker, the Add/Remove
         Programs entry, the installed CLI and every DefenseClaw machine-policy
         file, and detect.ps1 stops detecting

    With -UpgradeFrom it is the enterprise upgrade lane instead of step 1:
    the previous release's Setup /ensure installs with the same config, then
    this Setup's /ensure upgrades it. The upgrade must report the applied
    policy from a newer config generation, write migration-v9.json and
    config.yaml.v8.bak, and keep the secrets and the guardian ledger; steps
    2-5 then run on the upgraded deployment. The v8 config, the upgraded
    config and the migration record are kept in -ResultsRoot for
    scripts/check_enterprise_upgrade_config.py. The rollback drill of the
    Linux and macOS upgrade lanes is not run here: the Windows Setup
    transaction has no lifecycle test fault.

    Every lifecycle result is saved under -ResultsRoot and checked with
    scripts/check_enterprise_lifecycle_result.py.

    Standalone enrollment admits a (user, connector) row only when it finds
    the connector's CLI in that user's profile, and the runner has neither
    Claude Code nor Codex. The lane therefore stages the npm package
    manifests listed in testdata/enterprise_install_lane/windows-agents.json
    in this account's profile (a version claim that discovery reads and never
    runs) and removes them at the end. Without them no row is admitted and no
    machine policy is applied.

    It installs and removes Windows services: run it elevated only on a
    disposable host (a CI runner), never on a workstation.
.PARAMETER Setup
    Absolute path of DefenseClawSetup-Enterprise-Standalone-x64.exe built
    without signing (hash-pinned trust).
.PARAMETER Version
    The product version embedded in the Setup.
.PARAMETER ResultsRoot
    Where to keep the lifecycle results (default: a new temporary directory).
.PARAMETER Python
    The Python 3 interpreter that runs the result checker.
.PARAMETER UpgradeFrom
    Absolute path of the previous release's standalone Setup, already
    verified against its signed checksums.txt (the upgrade lane).
.PARAMETER PreviousVersion
    The product version of -UpgradeFrom.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$ResultsRoot = '',
    [string]$Python = 'python',
    [string]$UpgradeFrom = '',
    [string]$PreviousVersion = ''
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$checker = Join-Path $repo 'scripts\check_enterprise_lifecycle_result.py'
$detect = Join-Path $repo 'packaging\mdm\windows\detect.ps1'
$serviceNames = @('DefenseClawGateway', 'DefenseClawHookGuardian', 'DefenseClawHookEnumerator', 'DefenseClawSensorHelper')
$markerKey = 'HKLM:\SOFTWARE\Cisco\DefenseClaw\Enterprise'
$arpKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CiscoDefenseClawEnterprise'
$installRoot = Join-Path $env:ProgramFiles 'Cisco\DefenseClaw'
$cli = Join-Path $installRoot 'bin\defenseclaw.exe'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$agentFixtureList = Join-Path $repo 'testdata\enterprise_install_lane\windows-agents.json'
$profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
# The machine-wide policy standalone Windows writes for enrolled users: the
# Claude Code managed-settings fragment with its ownership sidecar
# (internal/enterprisehooks/managed_policy_windows.go) and the Codex
# requirements (internal/cli/windows_codex_requirements.go), each beside a
# DefenseClaw serialization lock.
$claudePolicyDirectory = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.d'
$claudePolicyFile = Join-Path $claudePolicyDirectory '90-defenseclaw.json'
$codexPolicyDirectory = Join-Path $env:ProgramData 'OpenAI\Codex'
$codexPolicyFile = Join-Path $codexPolicyDirectory 'requirements.toml'
$policyWaitSeconds = 120
$stateRoot = Join-Path $env:ProgramData 'Cisco\DefenseClaw'
$installedConfig = Join-Path $stateRoot 'etc\config.yaml'
$secretsDirectory = Join-Path $stateRoot 'secrets'
$guardianLedger = Join-Path $stateRoot 'hook-guardian-state\protected_targets.json'
$script:StepNumber = 0
$script:SetupRan = $false
$script:CreatedFixturePaths = [Collections.Generic.List[string]]::new()

function Fail([string]$Message) {
    throw "FAIL: $Message"
}

function Step([string]$Title) {
    $script:StepNumber++
    Write-Host ''
    Write-Host ('== {0:D2} {1}' -f $script:StepNumber, $Title)
}

function Test-Elevated {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs an executable, saves stdout as <Name>.json and stderr as <Name>.log.
function Invoke-Lifecycle {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $result = Join-Path $ResultsRoot "$Name.json"
    $log = Join-Path $ResultsRoot "$Name.log"
    & $FilePath @Arguments > $result 2> $log
    $exitCode = $LASTEXITCODE
    Write-Host "$Name exited $exitCode"
    return [pscustomobject]@{ Result = $result; ExitCode = $exitCode }
}

function Assert-Result {
    param(
        [Parameter(Mandatory = $true)]$Run,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Expect
    )
    & $Python $checker $Run.Result --label $Label --platform windows @Expect
    if ($LASTEXITCODE -ne 0) {
        $log = [IO.Path]::ChangeExtension($Run.Result, '.log')
        if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { Write-Host "  stderr: $_" }
        }
        Fail "$Label did not produce the expected lifecycle result"
    }
    if ($Run.ExitCode -ne 0) {
        Fail "$Label exited $($Run.ExitCode)"
    }
}

function Assert-ServicesRunning {
    foreach ($name in $serviceNames) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) { Fail "service $name is not installed" }
        if ($service.Status -ne 'Running') { Fail "service $name is $($service.Status), want Running" }
    }
    Write-Host "services running: $($serviceNames -join ' ')"
}

function Assert-ServicesGone {
    foreach ($name in $serviceNames) {
        if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
            Fail "service $name is still installed after uninstall"
        }
    }
    Write-Host 'no DefenseClaw service is installed'
}

# Every file in the Claude Code or Codex machine-policy folder whose name or
# content names DefenseClaw: the policy fragment, its sidecar and lock, and the
# hooks merged into requirements.toml. A file the lane cannot read counts.
function Get-PolicyArtifacts {
    foreach ($directory in @($claudePolicyDirectory, $codexPolicyDirectory)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -File -Force -Recurse)) {
            if ($file.Name -match 'defenseclaw') {
                $file.FullName
                continue
            }
            try {
                if (Select-String -LiteralPath $file.FullName -Pattern 'defenseclaw' -SimpleMatch -Quiet) { $file.FullName }
            }
            catch {
                "$($file.FullName) (unreadable: $($_.Exception.Message))"
            }
        }
    }
}

function Test-NamesDefenseClaw([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        return [bool](Select-String -LiteralPath $Path -Pattern 'defenseclaw' -SimpleMatch -Quiet)
    }
    catch {
        # Unreadable, for example while it is replaced: not proof of a
        # DefenseClaw entry.
        return $false
    }
}

# The enumerator walks ProfileList, so the fixtures go under this account's
# ProfileImagePath, exactly where it probes (AppData\Roaming\npm\node_modules).
function Get-ProfileHome {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $entry = Get-ItemProperty -LiteralPath (Join-Path $profileListKey $sid) -ErrorAction SilentlyContinue
    if ($null -eq $entry -or $null -eq $entry.PSObject.Properties['ProfileImagePath']) {
        Fail "this account ($sid) has no ProfileList entry, so the enumerator cannot enroll it"
    }
    $profileHome = [Environment]::ExpandEnvironmentVariables([string]$entry.ProfileImagePath)
    if (-not [IO.Path]::IsPathRooted($profileHome) -or -not (Test-Path -LiteralPath $profileHome -PathType Container)) {
        Fail "the ProfileList home of this account ($profileHome) does not exist"
    }
    return $profileHome
}

function Get-AgentFixtures([string]$ProfileHome) {
    $list = Get-Content -LiteralPath $agentFixtureList -Raw | ConvertFrom-Json
    foreach ($agent in @($list.agents)) {
        $relative = 'AppData\Roaming\npm\node_modules\' + ([string]$agent.package).Replace('/', '\')
        [pscustomobject]@{
            Connector = [string]$agent.connector
            Package = [string]$agent.package
            Version = [string]$agent.version
            Directory = Join-Path $ProfileHome $relative
        }
    }
}

# Writes each package.json and records the outermost directory it created, so
# the lane removes only what it added.
function New-AgentFixtures([object[]]$Fixtures, [string]$ProfileHome) {
    foreach ($fixture in $Fixtures) {
        $created = $null
        $directory = $fixture.Directory
        while ($directory -and $directory.Length -gt $ProfileHome.Length -and -not (Test-Path -LiteralPath $directory)) {
            $created = $directory
            $directory = Split-Path -Parent $directory
        }
        New-Item -ItemType Directory -Force -Path $fixture.Directory | Out-Null
        if ($null -ne $created) { $script:CreatedFixturePaths.Add($created) }
        $manifest = Join-Path $fixture.Directory 'package.json'
        $body = [ordered]@{ name = $fixture.Package; version = $fixture.Version } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($manifest, $body + "`n", [Text.UTF8Encoding]::new($false))
        Write-Host "agent fixture: $($fixture.Connector) $($fixture.Version) at $manifest"
    }
}

function Remove-AgentFixtures {
    for ($index = $script:CreatedFixturePaths.Count - 1; $index -ge 0; $index--) {
        $path = $script:CreatedFixturePaths[$index]
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $script:CreatedFixturePaths.Clear()
}

# The Codex requirements are written inside the install transaction; the
# guardian stages the Claude Code fragment for each admitted user, which the
# lane allows a bounded time after the Setup returns.
function Assert-PolicyApplied {
    if (-not (Test-NamesDefenseClaw $codexPolicyFile)) { Fail "$codexPolicyFile does not name the DefenseClaw hook" }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-NamesDefenseClaw $claudePolicyFile)) {
        if ($watch.Elapsed.TotalSeconds -ge $policyWaitSeconds) {
            Fail "$claudePolicyFile did not name the DefenseClaw hook within $policyWaitSeconds seconds"
        }
        Start-Sleep -Seconds 2
    }
    Write-Host ('machine policy applied: {0} and {1} (Claude Code fragment after {2:N0} s)' -f $codexPolicyFile, $claudePolicyFile, $watch.Elapsed.TotalSeconds)
}

function Assert-PolicyGone([string]$When) {
    $artifacts = @(Get-PolicyArtifacts)
    if ($artifacts.Count -gt 0) { Fail "DefenseClaw machine-policy files remain $($When): $($artifacts -join '; ')" }
    Write-Host "no DefenseClaw machine-policy file $When"
}

function Get-MarkerValue([string]$Name) {
    $marker = Get-ItemProperty -LiteralPath $markerKey -ErrorAction SilentlyContinue
    if ($null -eq $marker -or $null -eq $marker.PSObject.Properties[$Name]) { return $null }
    return [string]$marker.$Name
}

# detect.ps1 as Intune runs it: Windows PowerShell 5.1, exit 0 with the
# version on stdout when detected.
function Invoke-Detect {
    param([switch]$RequireHealthy)
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $detect)
    if ($RequireHealthy) { $arguments += @('-RequireHealthy', '-MinimumVersion', $Version) }
    $output = & $windowsPowerShell @arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (@($output) -join "`n").Trim() }
}

function Get-FileSha([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'absent' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# One digest over every file name and content under a folder.
function Get-TreeSha([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return 'absent' }
    $lines = foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse | Sort-Object FullName)) {
        '{0} {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash, $file.FullName.Substring($Path.Length)
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes((@($lines) -join "`n"))
    return [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($bytes)).Replace('-', '')
}

function Get-ConfigGeneration([string]$Result) {
    $document = Get-Content -LiteralPath $Result -Raw | ConvertFrom-Json
    if ($null -eq $document.PSObject.Properties['policy'] -or $null -eq $document.policy) { return 0 }
    return [int64]$document.policy.config_generation
}

function Write-Diagnostics {
    Write-Host '-- diagnostics (bounded)'
    foreach ($name in $serviceNames) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) { Write-Host "$name $($service.Status)" }
    }
    try {
        foreach ($artifact in @(Get-PolicyArtifacts)) { Write-Host "  machine policy: $artifact" }
    }
    catch {
        Write-Host "  machine policy: cannot list ($($_.Exception.Message))"
    }
    $lifecycleLog = Join-Path $env:SystemRoot 'Logs\DefenseClaw\enterprise-lifecycle.log'
    if (Test-Path -LiteralPath $lifecycleLog) {
        Get-Content -LiteralPath $lifecycleLog -Tail 40 | ForEach-Object { Write-Host "  $_" }
    }
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'DefenseClaw Enterprise' } -MaxEvents 10 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "  event $($_.Id): $(($_.Message -split "`n")[0])" }
}

if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'run this lane with PowerShell 7 (pwsh)' }
if (-not $IsWindows) { throw 'this lane runs on Windows only' }
if (-not (Test-Elevated)) { throw 'run this lane from an elevated administrator session on a disposable host' }
if (-not [IO.Path]::IsPathRooted($Setup) -or -not (Test-Path -LiteralPath $Setup -PathType Leaf)) {
    throw "-Setup must be the absolute path of an existing Setup: $Setup"
}
$Setup = (Resolve-Path -LiteralPath $Setup).Path
if ($UpgradeFrom) {
    if (-not [IO.Path]::IsPathRooted($UpgradeFrom) -or -not (Test-Path -LiteralPath $UpgradeFrom -PathType Leaf)) {
        throw "-UpgradeFrom must be the absolute path of an existing Setup: $UpgradeFrom"
    }
    if (-not $PreviousVersion) { throw '-UpgradeFrom needs -PreviousVersion' }
    $UpgradeFrom = (Resolve-Path -LiteralPath $UpgradeFrom).Path
}
if (-not $ResultsRoot) {
    $ResultsRoot = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-install-lane-" + [guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $ResultsRoot | Out-Null
$ResultsRoot = (Resolve-Path -LiteralPath $ResultsRoot).Path

# The Setup refuses a config that a standard user could replace: keep it in
# an administrator-only folder under ProgramData.
$stage = Join-Path $env:ProgramData ("DefenseClawInstallLane-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
$config = Join-Path $stage 'config.yaml'

# What every installed step reports. Codex's requirements verify
# (effective_lock 'enforce') and Claude Code has an enabled target. Windows
# keeps security_complete false until an administrator records the live Claude
# Code policy proof with Repair -AttestClaudeEffectivePolicy
# (docs/WINDOWS-ENTERPRISE-CERTIFICATION.md), which a runner cannot give.
$installedChecks = @(
    '--coverage-complete', '--security-incomplete',
    '--machine-policy-enforced', 'codex', '--machine-policy-target', 'claudecode'
)

try {
    Step 'preflight: this host has no DefenseClaw deployment'
    foreach ($name in $serviceNames) {
        if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
            Fail "service $name already exists; run the lane on a clean host"
        }
    }
    if (Test-Path -LiteralPath $markerKey) { Fail "$markerKey already exists; run the lane on a clean host" }
    if (Test-Path -LiteralPath $cli) { Fail "$cli already exists; run the lane on a clean host" }
    $artifacts = @(Get-PolicyArtifacts)
    if ($artifacts.Count -gt 0) { Fail "DefenseClaw machine-policy files already exist: $($artifacts -join '; ')" }
    $profileHome = Get-ProfileHome
    $fixtures = @(Get-AgentFixtures $profileHome)
    foreach ($fixture in $fixtures) {
        if (Test-Path -LiteralPath $fixture.Directory) { Fail "$($fixture.Directory) already exists; run the lane on a clean host" }
    }
    Write-Host "setup: $Setup"
    Write-Host "version: $Version"
    Write-Host "profile: $profileHome"

    New-Item -ItemType Directory -Path $stage | Out-Null
    & icacls.exe $stage /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not protect $stage" }
    & icacls.exe $stage /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not set the owner of $stage" }
    $configText = @(
        'config_version: 8'
        'deployment_mode: managed_enterprise'
        'enterprise:'
        '  profile: standalone'
        'gateway:'
        '  api_bind: 127.0.0.1'
        '  api_port: 18970'
        'guardrail:'
        '  enabled: true'
        '  mode: observe'
        '  rule_pack_dir: ""'
        '  connectors:'
        '    claudecode:'
        '      enabled: true'
        '    codex:'
        '      enabled: true'
    ) -join "`n"
    [IO.File]::WriteAllText($config, $configText + "`n", [Text.UTF8Encoding]::new($false))
    # An elevated runner account may own what it creates; the Setup trusts
    # only an administrator-, SYSTEM- or TrustedInstaller-owned config.
    & icacls.exe $config /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not set the owner of $config" }
    New-AgentFixtures $fixtures $profileHome

    if ($UpgradeFrom) {
        Step "previous release's Setup /ensure ($PreviousVersion) with the administrator config"
        $script:SetupRan = $true
        $run = Invoke-Lifecycle -Name '01-previous-setup-ensure' -FilePath $UpgradeFrom -Arguments @('/ensure', "CONFIG=$config", 'JSON=1')
        Assert-Result $run 'previous-setup-ensure' (@('--action', 'ensure', '--changed', '--installed', '--version', $PreviousVersion, '--ready') +
            $installedChecks + @('--allow-warning', 'ensure_install'))
        Assert-ServicesRunning
        Assert-PolicyApplied
        Copy-Item -LiteralPath $config -Destination (Join-Path $ResultsRoot 'config-v8.yaml')
        $run = Invoke-Lifecycle -Name '01-previous-status' -FilePath $cli -Arguments @('enterprise', 'windows', 'status', '--profile', 'standalone', '--json')
        Assert-Result $run 'previous-status' (@('--action', 'status', '--installed', '--version', $PreviousVersion) + $installedChecks)
        $previousGeneration = Get-ConfigGeneration $run.Result
        $previousConfigSha = Get-FileSha $installedConfig
        $previousSecretsSha = Get-TreeSha $secretsDirectory
        $previousLedgerSha = Get-FileSha $guardianLedger

        Step "Setup /ensure upgrades to $Version"
        $run = Invoke-Lifecycle -Name '01-setup-ensure-upgrade' -FilePath $Setup -Arguments @('/ensure', "CONFIG=$config", 'JSON=1')
        Assert-Result $run 'setup-ensure-upgrade' (@('--action', 'ensure', '--changed', '--installed', '--version', $Version, '--ready') +
            $installedChecks + @('--allow-warning', 'ensure_upgrade', '--policy-applied', '--config-generation-above', [string]$previousGeneration))
        Assert-ServicesRunning
        $record = Join-Path (Split-Path -Parent $installedConfig) 'migration-v9.json'
        if (-not (Test-Path -LiteralPath $record -PathType Leaf)) { Fail "the upgrade wrote no $record" }
        if ((Get-FileSha "$installedConfig.v8.bak") -ne $previousConfigSha) { Fail "$installedConfig.v8.bak is not the previous config" }
        Copy-Item -LiteralPath $installedConfig -Destination (Join-Path $ResultsRoot 'config-upgraded.yaml')
        Copy-Item -LiteralPath $record -Destination (Join-Path $ResultsRoot 'migration-v9.json')
        if ((Get-TreeSha $secretsDirectory) -ne $previousSecretsSha) { Fail "the upgrade changed the secrets under $secretsDirectory" }
        if ((Get-FileSha $guardianLedger) -ne $previousLedgerSha) { Fail "the upgrade changed the guardian ledger $guardianLedger" }
    }
    else {
        Step 'Setup /ensure with an administrator config (installs the services, enrolls Claude Code and Codex)'
        $script:SetupRan = $true
        $run = Invoke-Lifecycle -Name '01-setup-ensure-install' -FilePath $Setup -Arguments @('/ensure', "CONFIG=$config", 'JSON=1')
        # Ensure reports the action it chose as the warning ensure_install.
        Assert-Result $run 'setup-ensure-install' (@('--action', 'ensure', '--changed', '--installed', '--version', $Version, '--ready') +
            $installedChecks + @('--allow-warning', 'ensure_install'))
        Assert-ServicesRunning
        Assert-PolicyApplied
    }
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { Fail "$cli was not installed" }
    if ((Get-MarkerValue 'Profile') -ne 'standalone') { Fail "the HKLM marker does not name the standalone profile" }
    if ((Get-MarkerValue 'ProductVersion') -ne $Version) { Fail "the HKLM marker version is '$(Get-MarkerValue 'ProductVersion')', want '$Version'" }
    if ((Get-MarkerValue 'TrustMode') -ne 'hash_pinned') { Fail "the HKLM marker trust mode is '$(Get-MarkerValue 'TrustMode')', want 'hash_pinned'" }
    if (-not (Test-Path -LiteralPath $arpKey)) { Fail 'the Add/Remove Programs entry is missing' }

    Step 'Setup /ensure again (must be a no-op)'
    $run = Invoke-Lifecycle -Name '02-setup-ensure-noop' -FilePath $Setup -Arguments @('/ensure', 'JSON=1')
    Assert-Result $run 'setup-ensure-noop' (@('--action', 'ensure', '--noop', '--installed', '--version', $Version, '--ready') + $installedChecks)

    Step 'installed CLI verify'
    $run = Invoke-Lifecycle -Name '03-verify' -FilePath $cli -Arguments @('enterprise', 'windows', 'verify', '--profile', 'standalone', '--json')
    Assert-Result $run 'verify' (@('--action', 'verify', '--installed', '--version', $Version, '--ready') + $installedChecks)

    Step 'installed CLI status'
    $run = Invoke-Lifecycle -Name '04-status' -FilePath $cli -Arguments @('enterprise', 'windows', 'status', '--profile', 'standalone', '--json')
    Assert-Result $run 'status' (@('--action', 'status', '--installed', '--version', $Version) + $installedChecks)
    Assert-ServicesRunning

    Step 'MDM detection (detect.ps1 -RequireHealthy under Windows PowerShell 5.1)'
    $detected = Invoke-Detect -RequireHealthy
    if ($detected.ExitCode -ne 0 -or $detected.Output -notmatch [regex]::Escape($Version)) {
        Fail "detect.ps1 exited $($detected.ExitCode) with '$($detected.Output)', want the installed version"
    }
    Write-Host "detect.ps1: $($detected.Output)"

    Step 'installed CLI ensure without trust flags (the Remediate-Fix command)'
    $run = Invoke-Lifecycle -Name '05-cli-ensure' -FilePath $cli -Arguments @('enterprise', 'windows', 'ensure', '--profile', 'standalone', '--json')
    Assert-Result $run 'cli-ensure' (@('--action', 'ensure', '--noop', '--installed', '--version', $Version, '--ready') + $installedChecks)
    if ((Get-MarkerValue 'TrustMode') -ne 'hash_pinned') {
        Fail "the installed CLI's ensure changed the marker trust mode to '$(Get-MarkerValue 'TrustMode')'"
    }
    $detected = Invoke-Detect -RequireHealthy
    if ($detected.ExitCode -ne 0) { Fail "detect.ps1 stopped detecting after the installed CLI's ensure: $($detected.Output)" }
    Write-Host "detect.ps1 still detects: $($detected.Output)"

    Step 'Setup /uninstall'
    $run = Invoke-Lifecycle -Name '06-setup-uninstall' -FilePath $Setup -Arguments @('/uninstall', 'JSON=1')
    Assert-Result $run 'setup-uninstall' @('--action', 'uninstall', '--changed', '--not-installed')
    Assert-ServicesGone
    if (Test-Path -LiteralPath $markerKey) { Fail "$markerKey remains after uninstall" }
    if (Test-Path -LiteralPath $arpKey) { Fail 'the Add/Remove Programs entry remains after uninstall' }
    if (Test-Path -LiteralPath $cli) { Fail "$cli remains after uninstall" }
    Assert-PolicyGone 'after uninstall'
    $detected = Invoke-Detect
    if ($detected.ExitCode -eq 0) { Fail "detect.ps1 still detects a deployment after uninstall: $($detected.Output)" }
    Write-Host 'detect.ps1: not detected'

    Write-Host ''
    Write-Host "install lane passed: Windows Setup $Version (results in $ResultsRoot)"
    # The last native command (detect.ps1 reporting "not detected") exited 1;
    # a caller that checks $LASTEXITCODE must see the lane's result instead.
    $global:LASTEXITCODE = 0
}
catch {
    # A refused preflight changed nothing; the host's own logs are not ours.
    if ($script:SetupRan) { Write-Diagnostics }
    Write-Host "install lane FAILED (Windows Setup, results in $ResultsRoot)"
    throw
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-AgentFixtures
}
exit 0
