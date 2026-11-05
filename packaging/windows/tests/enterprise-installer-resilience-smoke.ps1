# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Seamless-first contracts of the installer and its module that do not need a
# Windows host:
# - both files parse and bind every ambient-sensitive cmdlet module-qualified;
# - a service marked for deletion fails Install with the precise
#   service_pending_delete prerequisite, which Install auto-recovery skips;
# - ReplaceFile's transient access-denied is retried only where asked;
# - the retired gateway's IPC ACEs are all removed, duplicates included;
# - an installed agent whose version cannot be verified is still enabled
#   (best-effort hook contract) and logged, never written disabled.
# Helpers are loaded from the sources by AST; nothing is imported.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$installerPath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'install-enterprise.ps1')
)
$ambientSensitiveCommands = @(
    'Add-Type', 'ConvertFrom-Json', 'ConvertTo-Json', 'Copy-Item',
    'Export-ModuleMember', 'ForEach-Object', 'Get-Acl',
    'Get-AuthenticodeSignature', 'Get-ChildItem', 'Get-Content',
    'Get-FileHash', 'Get-Item', 'Get-ItemProperty',
    'Get-ItemPropertyValue', 'Get-Service', 'Join-Path', 'Move-Item',
    'New-Item', 'New-ItemProperty', 'Out-Null', 'Out-String',
    'Remove-Item', 'Select-Object', 'Set-Acl', 'Set-Content',
    'Set-StrictMode', 'Sort-Object', 'Start-Service', 'Start-Sleep',
    'Stop-Process', 'Stop-Service', 'Test-Path', 'Where-Object',
    'Write-Output'
)
$asts = @{}
foreach ($path in @($modulePath, $installerPath)) {
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) {
        throw "$path does not parse: $(@($parseErrors)[0]) @ line $(@($parseErrors)[0].Extent.StartLineNumber)"
    }
    $unqualified = @(
        $ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst]
            }, $true) |
            ForEach-Object {
                $name = $_.GetCommandName()
                if ($name -in $ambientSensitiveCommands) {
                    '{0}@{1}' -f $name, $_.Extent.StartLineNumber
                }
            }
    )
    if ($unqualified.Count -ne 0) {
        throw "$path leaves ambient cmdlets unqualified: $($unqualified -join ', ')"
    }
    $asts[$path] = $ast
}

# Returns the exact text of one function definition; the caller dot-sources
# it at script scope.
function Get-DefenseClawSmokeFunctionText {
    param([string]$Path, [string]$Name)
    $definition = $asts[$Path].Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
        }, $true)
    if ($null -eq $definition) {
        throw "$Path does not define $Name"
    }
    return $definition.Extent.Text
}

foreach ($name in @(
        'ConvertTo-DefenseClawResilienceFieldValue',
        'Format-DefenseClawResilienceEvent',
        'Get-DefenseClawServicePendingDeleteRemedy',
        'Get-DefenseClawServicePendingDeleteMessage',
        'Test-DefenseClawServicePendingDeleteFailure',
        'Invoke-DefenseClawTransientFileRetry',
        'Remove-DefenseClawSIDFromRawDACL',
        'Test-DefenseClawTrustStrictAncestors'
    )) {
    . ([scriptblock]::Create((Get-DefenseClawSmokeFunctionText -Path $modulePath -Name $name)))
}
$script:ResilienceMarkers = @(
    'defenseclaw_repair', 'defenseclaw_accept', 'defenseclaw_skip',
    'defenseclaw_boundary', 'defenseclaw_prereq', 'defenseclaw_recover',
    'defenseclaw_degraded'
)
$script:TrustStrictAncestorsEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'
[Environment]::SetEnvironmentVariable($script:TrustStrictAncestorsEnv, $null, 'Process')
$script:Events = [Collections.Generic.List[string]]::new()
function Write-DefenseClawResilienceEvent {
    param([string]$Marker, [hashtable]$Fields)
    $script:Events.Add((Format-DefenseClawResilienceEvent -Marker $Marker -Fields $Fields))
}

# A pending delete names the exact prerequisite, and auto-recovery sees it.
# The remedy names open MMC consoles when one is running, a restart otherwise.
$remedy = Get-DefenseClawServicePendingDeleteRemedy
if ($remedy -cnotin @(
        'restart Windows to finish deleting the service, then run Setup again',
        'close Services, Event Viewer and other MMC consoles that are open, then run Setup again; if it still fails, restart Windows'
    )) {
    throw "pending-delete remedy is unexpected: $remedy"
}
$message = Get-DefenseClawServicePendingDeleteMessage -Name 'DefenseClawGateway'
if ($message -cne ('defenseclaw_prereq check="service_pending_delete" remedy="' + $remedy + '" service="DefenseClawGateway"')) {
    throw "pending-delete prerequisite is not in the shared format: $message"
}
if (-not (Test-DefenseClawServicePendingDeleteFailure -Message "Install failed: $message") -or
    (Test-DefenseClawServicePendingDeleteFailure -Message 'sc.exe exited 5') -or
    (Test-DefenseClawServicePendingDeleteFailure -Message '')) {
    throw 'pending-delete failure detection is wrong'
}

# Access denied is retried only when the caller names it.
$script:Attempts = 0
$value = Invoke-DefenseClawTransientFileRetry -Path 'x' -ExtraTransientCodes @(5, 1175) -Action {
    $script:Attempts++
    if ($script:Attempts -lt 3) {
        throw [UnauthorizedAccessException]::new('denied while exiting')
    }
    'replaced'
}
if ($value -cne 'replaced' -or $script:Attempts -ne 3) {
    throw "transient access denied was not retried: attempts=$script:Attempts value=$value"
}
$script:Attempts = 0
$denied = $false
try {
    [void](Invoke-DefenseClawTransientFileRetry -Path 'x' -Action {
            $script:Attempts++
            throw [UnauthorizedAccessException]::new('denied')
        })
}
catch {
    $denied = $true
}
if (-not $denied -or $script:Attempts -ne 1) {
    throw 'access denied was retried without -ExtraTransientCodes'
}
$script:Attempts = 0
$value = Invoke-DefenseClawTransientFileRetry -Path 'x' -ExtraTransientCodes @(1175) -Action {
    $script:Attempts++
    if ($script:Attempts -lt 2) {
        $exception = [IO.IOException]::new('unable to remove replaced', [int](0x80070000 -bor 1175))
        throw $exception
    }
    'replaced'
}
if ($value -cne 'replaced' -or $script:Attempts -ne 2) {
    throw 'ERROR_UNABLE_TO_REMOVE_REPLACED was not retried'
}

# Every ACE of the retired gateway SID goes, duplicates and non-canonical ones
# included; other ACEs stay byte for byte.
# Descriptor checks run only where the ACL APIs exist (not under pwsh off
# Windows).
$aclSupported = $true
try {
    [void][Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:P')
}
catch {
    $aclSupported = $false
}
if ($aclSupported) {
    $retired = 'S-1-5-80-1-2-3-4-5'
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;$retired)(A;;FR;;;$retired)(A;;FA;;;BA)"
    )
    $script:Events.Clear()
    $filtered = Remove-DefenseClawSIDFromRawDACL -Descriptor $descriptor -SID $retired
    if ([int]$filtered.removed -ne 2 -or
        $filtered.descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne 'D:P(A;;FA;;;SY)(A;;FA;;;BA)') {
        throw "retired gateway ACEs were not all removed: $($filtered.descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access))"
    }
    if (@($script:Events | Where-Object { $_.StartsWith('defenseclaw_accept ') }).Count -lt 2) {
        throw 'duplicate or non-canonical retired gateway ACEs were not logged'
    }
}

# The shorthand renderer enables an installed agent it cannot verify.
foreach ($name in @(
        'Format-DefenseClawBootstrapResilienceEvent',
        'Add-DefenseClawBootstrapResilienceEvent',
        'Test-DefenseClawBootstrapStrictAncestors',
        'Test-DefenseClawInteractiveUserSID',
        'Select-DefenseClawActiveInteractiveUserProfiles',
        'ConvertTo-DefenseClawConnectorMetadataVersion',
        'Resolve-DefenseClawConnectorMetadataVersion',
        'Get-DefenseClawRenderedEnterpriseTargets'
    )) {
    . ([scriptblock]::Create((Get-DefenseClawSmokeFunctionText -Path $installerPath -Name $name)))
}
$script:DefenseClawBootstrapResilienceEvents = [Collections.Generic.List[string]]::new()
$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors = @('codex', 'claudecode', 'cursor')
function Get-DefenseClawConnectorMetadataVersion {
    param([string]$Connector, [string]$UserHome, [string]$OwnerSID, [ref]$NativeCandidateObserved)
    # Every connector looks installed but unverifiable (for example a WinGet
    # Codex whose signature does not validate offline).
    if ($null -ne $NativeCandidateObserved) { $NativeCandidateObserved.Value = $true }
    return ''
}
$rendered = Get-DefenseClawRenderedEnterpriseTargets `
    -Connectors @('codex', 'amp') `
    -Profiles @([pscustomobject]@{
        SID = 'S-1-5-21-1000-1000-1000-1001'
        UserName = 'fixture-user'
        UserHome = 'C:\Users\fixture-user'
    })
$blocks = @(
    [regex]::Split($rendered, '(?m)(?=^  - user: )') |
        Where-Object { $_.StartsWith('  - user: ') }
)
$codexBlock = @($blocks | Where-Object { $_ -match '(?m)^    connector: "codex"\r?$' })
$ampBlock = @($blocks | Where-Object { $_ -match '(?m)^    connector: "amp"\r?$' })
if ($codexBlock.Count -ne 1 -or
    $codexBlock[0] -notmatch '(?m)^    enabled: true\r?$' -or
    $codexBlock[0] -match '(?m)^    agent_version:') {
    throw "unverifiable Codex was not enabled with the best-effort contract: $rendered"
}
if ($ampBlock.Count -ne 1 -or $ampBlock[0] -notmatch '(?m)^    enabled: false\r?$') {
    throw "a connector Windows managed mode cannot hook was enabled: $rendered"
}
if (@($script:DefenseClawBootstrapResilienceEvents | Where-Object {
            $_.StartsWith('defenseclaw_accept connector="codex"')
        }).Count -ne 1) {
    throw "unverifiable Codex enablement was not logged: $($script:DefenseClawBootstrapResilienceEvents -join '; ')"
}

'installer resilience smoke passed'
