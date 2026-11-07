# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

param([string]$ModulePath)

$ErrorActionPreference = 'Stop'
if (-not $ModulePath) {
    $ModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
}
$source = [IO.File]::ReadAllText($ModulePath)
$begin = $source.IndexOf('function Set-DefenseClawManagedAcls {', [StringComparison]::Ordinal)
$end = $source.IndexOf('function Set-DefenseClawRetainedRuntimeAcls {', $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'managed ACL function was not found' }
Invoke-Expression $source.Substring($begin, $end - $begin)
# GAP-0568: the managed ACL pass also stamps the approved policy copies.
$begin = $source.IndexOf('function Get-DefenseClawApprovedPolicyPath {', [StringComparison]::Ordinal)
$end = $source.IndexOf("`nfunction ", $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'approved policy path function was not found' }
Invoke-Expression $source.Substring($begin, $end - $begin)
# GAP-0766: the managed ACL pass also stamps the lazily created lock files;
# slice the real list from the module so the smoke judges what ships.
$begin = $source.IndexOf('function Get-DefenseClawLazyLockFiles {', [StringComparison]::Ordinal)
$end = $source.IndexOf("`nfunction ", $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'lazy lock file function was not found' }
Invoke-Expression $source.Substring($begin, $end - $begin)
# GAP-0650: the managed ACL pass also stamps the Codex state copy the hook
# reads; slice the real resolver of that copy from the module as well.
$begin = $source.IndexOf('function Resolve-DefenseClawCodexManagedHooksStateCopy {', [StringComparison]::Ordinal)
$end = $source.IndexOf("`nfunction ", $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'Codex state copy resolver was not found' }
Invoke-Expression $source.Substring($begin, $end - $begin)
$script:AdministratorsSID = 'S-1-5-32-544'

function Get-DefenseClawServiceSID { 'S-1-5-80-1-2-3-4-5' }
function Set-DefenseClawPathAcl {
    param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
    $script:Calls += [pscustomobject]@{ Path = $Path; Kind = $Kind; SID = $GatewayServiceSID }
}
function Set-DefenseClawSharedPathAcl { }
function Set-DefenseClawSecureClientInstallMarker { }
function Get-DefenseClawOptionalLayoutValue { '' }
function Grant-DefenseClawStateAncestorTraverse { }
function Invoke-DefenseClawBundleAclContract { }
function Test-DefenseClawLayoutBrokerEnabled { $false }
function Test-DefenseClawStandaloneProfile { $script:Standalone }
# Every layout folder here is the same absent path; the repair's log-folder
# recreation is not what this smoke checks.
function New-DefenseClawDirectory { param([string]$Path) }
function Write-DefenseClawResilienceEvent { param($Marker, $Fields) }

$root = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'dc-env-acl-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $runtime = [IO.Path]::Combine($root, 'runtime')
    [void][IO.Directory]::CreateDirectory($runtime)
    $envPath = [IO.Path]::Combine($runtime, '.env')
    [IO.File]::WriteAllText($envPath, "DC_TEST_TOKEN=fixture`n")
    $missing = [IO.Path]::Combine($root, 'missing')
    $layout = @{
        RuntimeDirectory = $runtime
        StateRootAncestors = @()
        StateRoot = $missing
        InstallRoot = $missing
        BinDirectory = $missing
        LibexecDirectory = $missing
        GatewayPath = $missing
        CLIPath = $missing
        ConfigDirectory = $missing
        GuardianDirectory = $missing
        InstallStateDirectory = $missing
        ConfigPath = $missing
        ManifestPath = $missing
        AuthorizationDirectory = $missing
        AuthorizationLedgerPath = $missing
        LogDirectory = $missing
        GatewayLogDirectory = $missing
        GuardianLogDirectory = $missing
        GatewayLogPath = $missing
        GuardianLogPath = $missing
        MetadataPath = $missing
        CodexRequirementsOwnershipPath = $missing
        CodexRequirementsAclBackupPath = $missing
        CodexManagedHooksStatePath = $missing
        AgentApplicationControlAttestationPath = $missing
        ManagedHooksTeardownJournalPath = $missing
        ManagedIPCDirectory = $missing
    }
    $script:Standalone = $true
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    $envCalls = @($script:Calls | Where-Object { $_.Path -ceq $envPath })
    if ($envCalls.Count -ne 1 -or $envCalls[0].Kind -cne 'RuntimeFile' -or
        $envCalls[0].SID -cne 'S-1-5-80-1-2-3-4-5') {
        throw "existing runtime .env was not repaired for the gateway service: $($envCalls | ConvertTo-Json -Compress)"
    }
    [IO.File]::Delete($envPath)
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    if (@($script:Calls | Where-Object { $_.Path -ceq $envPath }).Count -ne 0) {
        throw 'repair tried to create an absent runtime .env'
    }
    # GAP-0568: Repair rewrites drifted policy from the approved copies, so
    # an existing copy is re-stamped admin-only (no gateway service read).
    $installState = [IO.Path]::Combine($root, 'install-state')
    [void][IO.Directory]::CreateDirectory($installState)
    $approvedConfig = [IO.Path]::Combine($installState, 'approved-config.yaml')
    $approvedManifest = [IO.Path]::Combine($installState, 'approved-targets.yaml')
    [IO.File]::WriteAllText($approvedConfig, "config_version: 1`n")
    $layout.InstallStateDirectory = $installState
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    $approvedCalls = @($script:Calls | Where-Object { $_.Path -ceq $approvedConfig })
    if ($approvedCalls.Count -ne 1 -or $approvedCalls[0].Kind -cne 'AdminFile' -or
        $approvedCalls[0].SID -cne $script:AdministratorsSID) {
        throw "approved config copy was not stamped admin-only: $($approvedCalls | ConvertTo-Json -Compress)"
    }
    if (@($script:Calls | Where-Object { $_.Path -ceq $approvedManifest }).Count -ne 0) {
        throw 'repair tried to stamp an absent approved manifest copy'
    }
    # GAP-0766: an existing lazy lock file in the runtime folder is stamped like
    # the file it guards; an absent one is never created by repair.
    $envLock = [IO.Path]::Combine($runtime, '.env.lock')
    $acpLock = [IO.Path]::Combine($runtime, 'acp', '.enterprise-credentials.lock')
    [IO.File]::WriteAllText($envLock, "")
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    $lockCalls = @($script:Calls | Where-Object { $_.Path -ceq $envLock })
    if ($lockCalls.Count -ne 1 -or $lockCalls[0].Kind -cne 'RuntimeFile' -or
        $lockCalls[0].SID -cne 'S-1-5-80-1-2-3-4-5') {
        throw "existing runtime .env.lock was not stamped for the gateway service: $($lockCalls | ConvertTo-Json -Compress)"
    }
    if (@($script:Calls | Where-Object { $_.Path -ceq $acpLock }).Count -ne 0) {
        throw 'repair tried to create an absent ACP credential lock'
    }
    [IO.File]::WriteAllText($envPath, "DC_TEST_TOKEN=fixture`n")
    $script:Standalone = $false
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    if (@($script:Calls | Where-Object { $_.Path -ceq $envPath }).Count -ne 0) {
        throw 'Secure Client runtime .env was changed by standalone repair'
    }
    if (@($script:Calls | Where-Object { $_.Path -ceq $approvedConfig }).Count -ne 0) {
        throw 'Secure Client repair stamped a standalone approved policy copy'
    }
    if (@($script:Calls | Where-Object { $_.Path -ceq $envLock }).Count -ne 0) {
        throw 'Secure Client repair stamped a standalone lazy lock file'
    }
    Write-Output 'enterprise-standalone-runtime-env-acl-smoke: OK'
}
finally {
    [IO.Directory]::Delete($root, $true)
}
