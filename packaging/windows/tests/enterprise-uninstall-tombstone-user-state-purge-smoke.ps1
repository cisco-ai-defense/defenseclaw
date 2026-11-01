# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# GAP-2094, GAP-0867: Setup /uninstall PURGE=1 over a committed standalone
# tombstone whose hook teardown already finalized (InstallRoot gone, so no
# finalize runs) must still remove each enrolled account's per-user data and
# binaries, with Setup's gateway, before the machine-state purge removes the
# target manifest. Execute only the two committed-uninstall functions from
# the real module; mocks stand in for SCM, ACLs and the Go helper.
$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
foreach ($name in @(
        'Invoke-DefenseClawCommittedUninstallCleanup',
        'Invoke-DefenseClawTombstoneUserStatePurge',
        'Invoke-DefenseClawCommittedUserStatePurge'
    )) {
    $functionAst = @($moduleAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
        },
        $true
    ))
    if ($functionAst.Count -ne 1) {
        throw "expected exactly one $name in the module"
    }
    . ([scriptblock]::Create($functionAst[0].Extent.Text))
}

$root = Microsoft.PowerShell.Management\Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('defenseclaw-tombstone-user-purge-' + [Guid]::NewGuid().ToString('N'))
[void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $root)
$script:ProgramFiles = $root
$script:ProgramData = $root
$script:WindowsDirectory = $root
$layout = @{
    InstallRoot = (Microsoft.PowerShell.Management\Join-Path $root 'install-root-gone')
    PendingPath = (Microsoft.PowerShell.Management\Join-Path $root 'pending.json')
    ManifestPath = (Microsoft.PowerShell.Management\Join-Path $root 'targets.yaml')
    ManagedHooksTeardownJournalPath = (Microsoft.PowerShell.Management\Join-Path $root 'managed-hooks-teardown-journal.json')
    StateRootAncestors = @()
    HookPath = (Microsoft.PowerShell.Management\Join-Path $root 'hook.exe')
    CodexMachinePolicyDirectory = (Microsoft.PowerShell.Management\Join-Path $root 'codex')
}
Microsoft.PowerShell.Management\Set-Content -LiteralPath $layout.ManifestPath -Value 'targets: []'
$source = @{ path = 'C:\setup\payload\defenseclaw-gateway.exe' }

$script:events = [Collections.Generic.List[string]]::new()
$script:recordedUserState = $false
$script:journalPhase = $null
$script:goReport = $null
$script:mergedFinalization = $null
$script:DefenseClawUninstallPurgeUserState = $false

function Test-DefenseClawStandaloneProfile { return $true }
function Get-DefenseClawDeploymentMetadata {
    param([hashtable]$Layout, [switch]$Required)
    return [pscustomobject]@{ installed = $false }
}
function Assert-DefenseClawMetadataIdentity {
    param($Metadata, [string]$GatewayServiceName, [string]$GuardianServiceName)
}
function Test-DefenseClawMetadataInstalled { param($Metadata) return [bool]$Metadata.installed }
function Get-DefenseClawManagedServiceNames {
    param([string]$GatewayServiceName, [string]$GuardianServiceName)
    return @()
}
function Test-DefenseClawServiceExists { param([string]$Name) return $false }
function Resolve-DefenseClawRetiredGatewayServiceSID {
    param([string]$GatewayServiceName, [string]$GatewayServiceSID)
    return 'S-1-5-80-0'
}
function Get-DefenseClawTombstonePurgeUserStateRequested {
    param($Metadata)
    return $script:recordedUserState
}
function Get-DefenseClawManagedHooksTeardownJournalPhase {
    param([hashtable]$Layout, $Metadata, [string]$GatewayServiceName, [switch]$AllowLegacyInactive)
    return $script:journalPhase
}
function Complete-DefenseClawCommittedManagedHooksFinalization {
    throw 'no finalize may run: InstallRoot is gone'
}
function Remove-DefenseClawCommittedManagedHooksTeardownJournal {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
}
function Remove-DefenseClawCommittedManagedHooksSerializationLocks { param([hashtable]$Layout) }
function Remove-DefenseClawRuntimeSelectorState { param([string]$HookPath, [string[]]$Directories) return @() }
function Remove-DefenseClawEmptyClaudeManagedSettingsFolders { param([string]$ProgramFiles) return @() }
function Revoke-DefenseClawStateAncestorTraverse { param([string]$Path, [string]$GatewayServiceSID) }
function Test-DefenseClawStandaloneVendorDirectory { param([string]$Path) return $false }
function Revoke-DefenseClawStandaloneVendorUsersRead { param([string]$Path, [string]$Scope) }
function Publish-DefenseClawStatePurgeIntent {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
    $script:events.Add('state-purge-intent')
}
function Complete-DefenseClawStatePurge {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName, [string]$GatewayServiceSID, [hashtable]$NativeCleanupSource)
    $script:events.Add('state-purge')
    return [pscustomobject]@{ ok = $true; action = 'uninstall'; purged = $true }
}
function Add-DefenseClawUserRegistrationCleanupResult {
    param($Result, [hashtable]$Layout, $Finalization)
    $script:mergedFinalization = $Finalization
    $Result | Microsoft.PowerShell.Utility\Add-Member -MemberType NoteProperty -Name user_state_purged -Value @($Finalization.user_state_purged) -Force
    return $Result
}
function Remove-DefenseClawStaleRunDirectories { param([string]$ProgramData, [string]$WindowsTemp) return @() }
function Remove-DefenseClawStandaloneOrphanedHookMachineState { param([hashtable]$Layout) return @() }
function Remove-DefenseClawStandaloneHookRuntimeLeftovers { return @() }
function Revoke-DefenseClawManagedIPCServiceAccess { param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GatewayServiceSID) }
function Get-DefenseClawLifecycleStatus {
    param([string]$Action, [hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName)
    return [pscustomobject]@{ ok = $true; action = 'uninstall' }
}
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value) return [string]$Value }
function Write-DefenseClawLifecyclePhase { param([string]$Stage) }
function Invoke-DefenseClawGatewayCommand {
    param(
        [hashtable]$Layout,
        [string]$GatewayServiceName,
        [string[]]$Arguments,
        [hashtable]$GatewaySource,
        [string]$GatewayPath,
        [switch]$Capture,
        [switch]$AllowFailure
    )
    if ($null -eq $GatewaySource -or [string]$GatewaySource.path -cne [string]$source.path) {
        throw 'the per-user purge did not run with Setup''s gateway'
    }
    if (($Arguments -join ' ') -cne 'enterprise windows teardown-managed-hooks purge-user-state --json') {
        throw "unexpected helper arguments: $($Arguments -join ' ')"
    }
    # The helper reads the per-user purge request from its environment,
    # which Invoke-DefenseClawGatewayCommand sets from this flag.
    if (-not [bool]$script:DefenseClawUninstallPurgeUserState) {
        throw 'the per-user purge ran without the purge request set'
    }
    $script:events.Add('user-state-purge')
    return [pscustomobject]@{
        exit_code = $(if ([bool]$script:goReport.ok) { 0 } else { 1 })
        output = @(($script:goReport | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -Depth 4))
    }
}

function Invoke-Case {
    param(
        [string]$Name,
        [bool]$Requested,
        [bool]$Recorded,
        [string]$JournalPhase = '',
        [bool]$WithSource = $true,
        [bool]$WantPurge,
        [bool]$GoOK = $true
    )
    $script:events.Clear()
    $script:mergedFinalization = $null
    $script:DefenseClawUninstallPurgeUserState = $Requested
    $script:recordedUserState = $Recorded
    $script:journalPhase = $JournalPhase
    if (-not [string]::IsNullOrEmpty($JournalPhase)) {
        Microsoft.PowerShell.Management\Set-Content -LiteralPath $layout.ManagedHooksTeardownJournalPath -Value '{}'
    }
    elseif (Microsoft.PowerShell.Management\Test-Path -LiteralPath $layout.ManagedHooksTeardownJournalPath) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $layout.ManagedHooksTeardownJournalPath -Force
    }
    $script:goReport = [pscustomobject]@{
        schema_version = 4
        action = 'purge-user-state'
        ok = $GoOK
        manifest_path = $layout.ManifestPath
        journal_path = $layout.ManagedHooksTeardownJournalPath
        user_state_purged = @('R104\dcw-std1 (S-1-5-21-1-2-3-1017): C:\Users\dcw-std1\.defenseclaw')
        error = $(if ($GoOK) { '' } else { 'access denied' })
    }
    $sourceArg = if ($WithSource) { $source } else { $null }
    $result = Invoke-DefenseClawCommittedUninstallCleanup `
        -Layout $layout `
        -GatewayServiceName 'DefenseClawGateway' `
        -GuardianServiceName 'DefenseClawHookGuardian' `
        -Purge `
        -UserStatePurgeSource $sourceArg
    $order = $script:events -join ','
    if ($WantPurge) {
        if ($order -cne 'user-state-purge,state-purge-intent,state-purge') {
            throw "${Name}: the per-user purge must run once, before the machine-state purge (got '$order')"
        }
        if ($null -eq $script:mergedFinalization -or
            @($result.user_state_purged).Count -ne 1) {
            throw "${Name}: the uninstall result does not name the purged account"
        }
    }
    elseif ($order -cne 'state-purge-intent,state-purge') {
        throw "${Name}: no per-user purge may run here (got '$order')"
    }
    if ([bool]$script:DefenseClawUninstallPurgeUserState -ne $Requested) {
        throw "${Name}: the caller's purge request was not restored"
    }
}

try {
    # The GAP-2094 repro: PURGE=1 over a killed plain uninstall's tombstone.
    Invoke-Case -Name 'explicit purge over a plain tombstone' -Requested $true -Recorded $false -JournalPhase '' -WantPurge $true
    # A finalized journal is still there: the same.
    Invoke-Case -Name 'finalized journal' -Requested $true -Recorded $false -JournalPhase 'finalized' -WantPurge $true
    # The tombstone recorded the per-user purge (a recovery replays it).
    Invoke-Case -Name 'recorded per-user purge' -Requested $false -Recorded $true -JournalPhase '' -WantPurge $true
    # A plain uninstall, or a recovery of one, purges no user state.
    Invoke-Case -Name 'plain uninstall' -Requested $false -Recorded $false -JournalPhase '' -WantPurge $false
    # An unfinished teardown belongs to its finalize.
    Invoke-Case -Name 'prepared journal' -Requested $true -Recorded $false -JournalPhase 'prepared' -WantPurge $false
    # Without Setup's gateway nothing changes from before.
    Invoke-Case -Name 'no gateway source' -Requested $true -Recorded $false -JournalPhase '' -WithSource $false -WantPurge $false
    # A failed helper fails the uninstall before the machine-state purge.
    $failed = $false
    try {
        Invoke-Case -Name 'helper failure' -Requested $true -Recorded $false -JournalPhase '' -WantPurge $true -GoOK $false
    }
    catch {
        if ($_.Exception.Message -notlike '*the per-user purge failed: access denied*') {
            throw
        }
        if ($script:events -ccontains 'state-purge-intent') {
            throw 'helper failure: the machine-state purge ran after the per-user purge failed'
        }
        $failed = $true
    }
    if (-not $failed) {
        throw 'helper failure: the uninstall did not fail'
    }
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

'enterprise-uninstall-tombstone-user-state-purge-smoke: PASS'
