# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for the standalone sensor helper around uninstall.
# Uninstall quiesces it for the servicing boundary (it failed every uninstall
# of a running deployment with "startup mode drift: 2, expected 4"), and the
# managed-hook rollback restart brings it back.
# Restore-DefenseClawTransaction quiesces the standalone sensor helper, which
# transaction snapshots do not record. When the managed-hook teardown had to
# be rolled back, Restore-DefenseClawTransactionWithManagedHooksRollback
# restarted the restored services without it; the gateway depends on the
# helper, so SCM refused to start it ("Cannot start service
# 'DefenseClawGateway'"), every such rollback failed, and the deployment was
# left down with a pending transaction. A forced uninstall whose StateRoot move
# fails (GAP-1438), or whose purge after the move is refused (GAP-1486), gives
# the services back their startup mode and running state.
# The service-control calls are stubbed.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$failures = & $module {
    param([string]$ModulePath, [string]$ScratchRoot)

    $script:TestCalls = [Collections.Generic.List[string]]::new()
    $script:TestServices = @{}
    function Test-DefenseClawServiceExists {
        param([string]$Name)
        return $script:TestServices.ContainsKey($Name)
    }
    function Assert-DefenseClawStandaloneSensorHelperOwned {
        param($Name, $Layout)
        $script:TestCalls.Add("owned:$Name")
    }
    function Set-DefenseClawServiceStartMode {
        param([string]$Name, [int]$StartMode)
        $script:TestCalls.Add("mode:${Name}=$StartMode")
    }
    function Start-DefenseClawService {
        param([string]$Name)
        $script:TestCalls.Add("start:$Name")
    }

    $originalProfile = Get-DefenseClawEnterpriseProfile
    $failures = [Collections.Generic.List[string]]::new()
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
    try {
        $layout = @{}
        $helper = Get-DefenseClawSensorHelperServiceName -GatewayServiceName 'DefenseClawGateway'
        $snapshot = [pscustomobject][ordered]@{
            gateway_service = 'DefenseClawGateway'
            guardian_service = 'DefenseClawHookGuardian'
            services = @(
                [pscustomobject]@{ name = 'DefenseClawGateway'; existed = $true; running = $true; start_mode = 2 },
                [pscustomobject]@{ name = 'DefenseClawHookGuardian'; existed = $true; running = $true; start_mode = 3 }
            )
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $script:TestServices[$helper] = $true
        $started = Start-DefenseClawRestoredStandaloneSensorHelper -Snapshot $snapshot -Layout $layout
        Set-DefenseClawRestoredStandaloneSensorHelperBootPolicy -Snapshot $snapshot -Name $started
        $expected = @("owned:$helper", "mode:$helper=3", "start:$helper", "mode:$helper=2")
        if ($started -cne $helper -or (@($script:TestCalls) -join '|') -cne ($expected -join '|')) {
            $failures.Add("restored gateway: expected $($expected -join ', '), got $(@($script:TestCalls) -join ', ')")
        }

        # A fresh install's rollback restores no pre-existing gateway.
        $script:TestCalls.Clear()
        $fresh = [pscustomobject][ordered]@{
            gateway_service = 'DefenseClawGateway'
            guardian_service = 'DefenseClawHookGuardian'
            services = @([pscustomobject]@{ name = 'DefenseClawGateway'; existed = $false; running = $false; start_mode = 0 })
        }
        $started = Start-DefenseClawRestoredStandaloneSensorHelper -Snapshot $fresh -Layout $layout
        Set-DefenseClawRestoredStandaloneSensorHelperBootPolicy -Snapshot $fresh -Name $started
        if (-not [string]::IsNullOrEmpty($started) -or $script:TestCalls.Count -ne 0) {
            $failures.Add('a fresh-install rollback touched the sensor helper')
        }

        # No helper service registered: nothing to start.
        $script:TestCalls.Clear()
        $script:TestServices.Clear()
        $started = Start-DefenseClawRestoredStandaloneSensorHelper -Snapshot $snapshot -Layout $layout
        if (-not [string]::IsNullOrEmpty($started) -or $script:TestCalls.Count -ne 0) {
            $failures.Add('a missing sensor helper was touched')
        }

        # Secure Client has no standalone sensor helper to restore.
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        $script:TestServices[$helper] = $true
        $script:TestCalls.Clear()
        $started = Start-DefenseClawRestoredStandaloneSensorHelper -Snapshot $snapshot -Layout $layout
        if (-not [string]::IsNullOrEmpty($started) -or $script:TestCalls.Count -ne 0) {
            $failures.Add('Secure Client rollback touched the standalone sensor helper')
        }

        # Uninstall quiesces the helper for the servicing boundary (standalone only).
        $layout['SensorHelperServiceName'] = $helper
        $script:TestServices[$helper] = $true
        $script:TestCalls.Clear()
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        function Stop-DefenseClawService {
            param([string]$Name)
            $script:TestCalls.Add("stop:$Name")
        }
        if (-not (Suspend-DefenseClawStandaloneSensorHelperForServicing -Layout $layout) -or
            (@($script:TestCalls) -join '|') -cne ("owned:$helper|mode:$helper=4|stop:$helper")) {
            $failures.Add("uninstall quiesce: got $(@($script:TestCalls) -join ', ')")
        }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        $script:TestCalls.Clear()
        if ((Suspend-DefenseClawStandaloneSensorHelperForServicing -Layout $layout) -or $script:TestCalls.Count -ne 0) {
            $failures.Add('Secure Client uninstall quiesced the standalone sensor helper')
        }
        $uninstall = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-DefenseClawUninstallLifecycle'
        }, $true).Body.Extent.Text
        $open = $uninstall.IndexOf('$snapshot = New-DefenseClawTransaction')
        $suspend = $uninstall.IndexOf('Suspend-DefenseClawStandaloneSensorHelperForServicing')
        $servicing = $uninstall.IndexOf('-ServicingTransaction')
        if ($open -lt 0 -or $suspend -lt 0 -or $servicing -lt 0 -or
            -not ($open -lt $suspend -and $suspend -lt $servicing)) {
            $failures.Add('uninstall does not quiesce the sensor helper between transaction open and the servicing assertion')
        }

        # GAP-1438: FORCE=1 stopped and disabled the services, and a StateRoot
        # move refused by an open file left them so. Put them back as they were.
        $guardian = 'DefenseClawHookGuardian'
        $enumerator = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $guardian
        $script:TestModes = @{ $enumerator = 3; $guardian = 2; 'DefenseClawGateway' = 2; $helper = 2 }
        $script:TestStoppedService = $enumerator
        $script:TestServices.Clear()
        foreach ($name in $script:TestModes.Keys) {
            $script:TestServices[$name] = $true
        }
        function Assert-DefenseClawOwnedServiceOrAbsent {
            param($Name, $ExpectedGatewayPath, $ExpectedManifestPath, $ExpectedSensorHelperImage,
                [switch]$Guardian, [switch]$Enumerator, [switch]$SensorHelper)
        }
        function Get-DefenseClawSensorHelperImage {
            param($Layout, $GatewayServiceName)
            return ''
        }
        function Assert-DefenseClawNoReparsePath {
            param($Path)
        }
        function Get-DefenseClawServiceStartMode {
            param([string]$Name)
            return $script:TestModes[$Name]
        }
        function Get-DefenseClawServiceState {
            param([string]$Name)
            if ($Name -ceq $script:TestStoppedService) { return 'stopped' }
            return 'running'
        }
        $root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), 'dc-forced-' + [Guid]::NewGuid().ToString('N'))
        $stateRoot = [IO.Path]::Combine($root, 'DefenseClaw')
        [void][IO.Directory]::CreateDirectory($stateRoot)
        $held = [IO.File]::Open([IO.Path]::Combine($stateRoot, 'audit.db'), 'CreateNew', 'ReadWrite', 'None')
        $script:TestCalls.Clear()
        $threw = ''
        try {
            [void](Invoke-DefenseClawForcedUninstallPreparation `
                -Layout @{
                    StateRoot = $stateRoot
                    GatewayPath = ''
                    ManifestPath = ''
                    SensorHelperPath = ''
                    SensorHelperServiceName = $helper
                } `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName $guardian)
        }
        catch {
            $threw = $_.Exception.Message
        }
        finally {
            $held.Dispose()
        }
        $stateKept = [IO.Directory]::Exists($stateRoot)
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        $expected = @(
            "mode:$enumerator=4", "stop:$enumerator", "mode:$guardian=4", "stop:$guardian",
            'mode:DefenseClawGateway=4', 'stop:DefenseClawGateway', "mode:$helper=4", "stop:$helper",
            "mode:$helper=2", "start:$helper", 'mode:DefenseClawGateway=2', 'start:DefenseClawGateway',
            "mode:$guardian=2", "start:$guardian", "mode:$enumerator=3"
        )
        if (-not $threw -or -not $stateKept -or (@($script:TestCalls) -join '|') -cne ($expected -join '|')) {
            $failures.Add("failed forced uninstall ($threw): kept=$stateKept calls $(@($script:TestCalls) -join ', ')")
        }

        # GAP-1486: the exact-scope purge after the preparation was refused
        # (an open file under InstallRoot), and StateRoot stayed moved aside
        # with the services stopped and disabled. Move it back, restore the
        # services and rethrow the refusal; a completed purge restores nothing.
        function Invoke-DefenseClawPreLayoutRecovery {
            param($Action, $Layout, $Sources, $GatewayServiceName, $GuardianServiceName, [switch]$Purge,
                $RequestedCertificationCodexHome, [switch]$RequestedCoreHardeningCertification, $SelfUninstallCallerPID)
            $script:TestCalls.Add("purge:$([IO.Directory]::Exists($Layout.StateRoot))")
            if ($script:TestPurgeRefuses) {
                throw 'purge refused: marker sharing violation'
            }
            return [pscustomobject]@{ handled = $true; result = [pscustomobject]@{ ok = $true } }
        }
        $stopped = @(
            "mode:$enumerator=4", "stop:$enumerator", "mode:$guardian=4", "stop:$guardian",
            'mode:DefenseClawGateway=4', 'stop:DefenseClawGateway', "mode:$helper=4", "stop:$helper", 'purge:False'
        )
        foreach ($refuses in @($true, $false)) {
            $script:TestPurgeRefuses = $refuses
            $root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), 'dc-forced-' + [Guid]::NewGuid().ToString('N'))
            $stateRoot = [IO.Path]::Combine($root, 'DefenseClaw')
            [void][IO.Directory]::CreateDirectory($stateRoot)
            [IO.File]::WriteAllText([IO.Path]::Combine($stateRoot, 'audit.db'), 'kept')
            $script:TestCalls.Clear()
            $threw = ''
            $result = $null
            try {
                $result = Invoke-DefenseClawForcedUninstall `
                    -Layout @{
                        StateRoot = $stateRoot
                        GatewayPath = ''
                        ManifestPath = ''
                        SensorHelperPath = ''
                        SensorHelperServiceName = $helper
                    } `
                    -GatewayServiceName 'DefenseClawGateway' `
                    -GuardianServiceName $guardian `
                    -Purge
            }
            catch {
                $threw = $_.Exception.Message
            }
            $stateBack = [IO.File]::Exists([IO.Path]::Combine($stateRoot, 'audit.db'))
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            $calls = @($script:TestCalls) -join '|'
            if ($refuses) {
                $expected = $stopped + @(
                    "mode:$helper=2", "start:$helper", 'mode:DefenseClawGateway=2', 'start:DefenseClawGateway',
                    "mode:$guardian=2", "start:$guardian", "mode:$enumerator=3"
                )
                if ($threw -cne 'purge refused: marker sharing violation' -or -not $stateBack -or $calls -cne ($expected -join '|')) {
                    $failures.Add("refused forced purge ($threw): StateRoot back=$stateBack calls $calls")
                }
            }
            elseif ($threw -or $stateBack -or $null -eq $result -or -not [bool]$result.forced -or $calls -cne ($stopped -join '|')) {
                $failures.Add("completed forced purge ($threw): StateRoot back=$stateBack calls $calls")
            }
        }

        # A committed standalone uninstall retires bin with the ACP bridge and
        # the sensor helper still present; Secure Client keeps its allowlist.
        $retired = 'C:\\RetiredRoot'
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $standaloneFiles = @((Get-DefenseClawRetiredInstallTreeAllowlist -Layout $layout -RetiredRoot $retired).files)
        foreach ($leaf in @('bin\defenseclaw-acp.exe', 'bin\defenseclaw-sensor-helper.exe', 'bin\defenseclaw-gateway.exe')) {
            if ([IO.Path]::GetFullPath((Join-Path $retired $leaf)) -notin $standaloneFiles) {
                $failures.Add("standalone retired-tree allowlist lacks $leaf")
            }
        }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        $secureClientFiles = @((Get-DefenseClawRetiredInstallTreeAllowlist -Layout $layout -RetiredRoot $retired).files)
        if ($secureClientFiles.Count -ne ($standaloneFiles.Count - 2)) {
            $failures.Add('Secure Client retired-tree allowlist changed')
        }

        # Wiring: the deferred managed-hook rollback restart starts the helper
        # before the restored services and then applies its boot policy.
        $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Restore-DefenseClawTransactionWithManagedHooksRollback'
        }, $true)
        $body = $definition.Body.Extent.Text
        $start = $body.IndexOf('Start-DefenseClawRestoredStandaloneSensorHelper')
        $services = $body.LastIndexOf('Start-DefenseClawTransactionServices')
        $policy = $body.IndexOf('Set-DefenseClawRestoredStandaloneSensorHelperBootPolicy')
        if ($start -lt 0 -or $services -lt 0 -or $policy -lt 0 -or
            -not ($start -lt $services -and $services -lt $policy)) {
            $failures.Add('the deferred managed-hook rollback restart does not bring back the sensor helper around the service restart')
        }
    }
    finally {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
    }
    return , $failures
} $modulePath $ScratchRoot

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-rollback-sensor-helper-smoke: OK'
