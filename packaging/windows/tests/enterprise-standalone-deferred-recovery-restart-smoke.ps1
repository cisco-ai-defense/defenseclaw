# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0601: a pending-transaction recovery that could not reactivate the
# restored release left it stopped and disabled for this Setup's release to
# replace. When that requested lifecycle then failed, the endpoint ran no
# DefenseClaw service at all. Restart-DefenseClawDeferredRecoveryRelease
# starts the restored release again with the service set it recorded, and
# never stops it again when readiness is not proven. It does nothing when the
# run deferred nothing, when a transaction of this run is still pending, or
# on Secure Client. The helper is loaded from the module by AST.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @('Restart-DefenseClawDeferredRecoveryRelease', 'Restore-DefenseClawTransactionServiceStartModes')) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:Calls = [Collections.Generic.List[string]]::new()
$script:Standalone = $true
$script:ReadinessFails = $false
function Test-DefenseClawStandaloneProfile { [bool]$script:Standalone }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value) [string]$Value }
function Write-DefenseClawResilienceEvent { param([string]$Marker, [hashtable]$Fields) $script:Calls.Add("event:$Marker") }
function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) 'enum' }
function Get-DefenseClawCMIDBrokerServiceName { param($GatewayServiceName) 'broker' }
function Test-DefenseClawServiceExists { param($Name) $true }
function Set-DefenseClawServiceStartMode { param($Name, [int]$StartMode) $script:Calls.Add("mode:${Name}:$StartMode") }
function Start-DefenseClawService { param($Name, $FailureLogPath) $script:Calls.Add("start:$Name") }
function Restore-DefenseClawServiceStartModeExact { param($Name, [int]$StartMode, [bool]$DelayedAutoStart) $script:Calls.Add("boot:${Name}:$StartMode") }
function Wait-DefenseClawEnterpriseReadiness {
    param($Layout, $GatewayServiceName, $GuardianServiceName, [bool]$RequireBroker, [bool]$RequireEnumerator, [switch]$AllowFailedTargets)
    $script:Calls.Add("ready:allow=$([bool]$AllowFailedTargets)")
    if ($script:ReadinessFails) { throw 'guardian coverage not proven' }
}
function Get-DefenseClawTransactionServiceStates {
    param($Services, $GatewayServiceName, $GuardianServiceName)
    $states = @{}
    foreach ($service in @($Services)) {
        $states[[string]$service.name] = [pscustomobject]@{
            existed = ([int]$service.start_mode -ne 0)
            running = [bool]$service.running
            start_mode = [int]$service.start_mode
            delayed_auto_start = $false
        }
    }
    return $states
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("dc-deferred-restart-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$layout = @{ PendingPath = (Join-Path $scratch 'pending.json') }
function Set-Deferred {
    $script:DefenseClawRecoveryActivationDeferred = $true
    $script:DefenseClawDeferredRecoveryServices = [pscustomobject]@{
        services = @(
            [pscustomobject]@{ name = 'broker'; start_mode = 0; running = $false },
            [pscustomobject]@{ name = 'guardian'; start_mode = 2; running = $true },
            [pscustomobject]@{ name = 'gw'; start_mode = 2; running = $true },
            [pscustomobject]@{ name = 'enum'; start_mode = 2; running = $true }
        )
        gateway_service = 'gw'
        guardian_service = 'guardian'
        sensor_helper = 'sensor'
    }
    $script:Calls.Clear()
}
try {
    # Nothing deferred: nothing is started.
    $script:DefenseClawRecoveryActivationDeferred = $false
    $script:DefenseClawDeferredRecoveryServices = $null
    if ((Restart-DefenseClawDeferredRecoveryRelease -Layout $layout) -ne '' -or $script:Calls.Count -ne 0) {
        throw 'a run that deferred nothing started services'
    }

    # Deferred: the restored release starts in the rollback order, gets its
    # recorded boot policy back, and readiness accepts failed user targets.
    Set-Deferred
    $note = Restart-DefenseClawDeferredRecoveryRelease -Layout $layout
    $want = @(
        'mode:sensor:3', 'start:sensor',
        'mode:guardian:3', 'start:guardian', 'mode:gw:3', 'start:gw', 'mode:enum:3', 'start:enum',
        'boot:guardian:2', 'boot:gw:2', 'boot:enum:2',
        'mode:sensor:2', 'ready:allow=True', 'event:defenseclaw_recover'
    )
    if ((@($script:Calls) -join ',') -cne ($want -join ',')) {
        throw "restart order: $(@($script:Calls) -join ',')"
    }
    if ($note -notlike '*started the restored release again*ready*') {
        throw "note: $note"
    }
    if ($null -ne $script:DefenseClawDeferredRecoveryServices) {
        throw 'the deferred service set was not consumed'
    }
    # A second call in the same run does nothing.
    $script:Calls.Clear()
    if ((Restart-DefenseClawDeferredRecoveryRelease -Layout $layout) -ne '' -or $script:Calls.Count -ne 0) {
        throw 'a second restart ran'
    }

    # Readiness not proven: the services stay running and the note says so.
    Set-Deferred
    $script:ReadinessFails = $true
    $note = Restart-DefenseClawDeferredRecoveryRelease -Layout $layout
    $script:ReadinessFails = $false
    if ($note -notlike '*it is running, but its readiness was not proven: guardian coverage not proven*' -or
        @($script:Calls | Where-Object { $_ -like 'mode:*:4' }).Count -ne 0) {
        throw "unproven readiness: $note / $(@($script:Calls) -join ',')"
    }

    # A transaction of this run still pending owns the services.
    Set-Deferred
    Set-Content -LiteralPath $layout.PendingPath -Value '{}'
    if ((Restart-DefenseClawDeferredRecoveryRelease -Layout $layout) -ne '' -or $script:Calls.Count -ne 0) {
        throw 'restarted while a transaction is pending'
    }
    Remove-Item -LiteralPath $layout.PendingPath

    # Secure Client never defers, and is never restarted here.
    Set-Deferred
    $script:Standalone = $false
    if ((Restart-DefenseClawDeferredRecoveryRelease -Layout $layout) -ne '' -or $script:Calls.Count -ne 0) {
        throw 'Secure Client restarted a deferred release'
    }
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

'deferred recovery restart smoke passed'