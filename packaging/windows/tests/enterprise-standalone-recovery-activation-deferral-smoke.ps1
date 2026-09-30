# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression test. A standard account moved its own
# ~\.defenseclaw aside; the installed guardian could no longer publish full
# coverage, a repair failed, and its rollback failed the same way, leaving a
# pending transaction and every DefenseClaw service stopped. Each later
# recovery restored and reactivated that same release, whose guardian failed
# the fresh-coverage wait again, so no Setup could ever recover the host.
# A standalone recovery whose running Setup gateway passes the recovery
# admission now completes with the restored release stopped and disabled,
# records the decision, and lets the requested Upgrade activate its own
# release; Repair stops with the next step. Service control is stubbed.

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
    param([string]$ScratchRoot, [string]$ModulePath)

    $script:TestCalls = [Collections.Generic.List[string]]::new()
    $script:TestAdmission = $null
    $script:TestAdmissionCalls = 0
    function Set-DefenseClawServiceStartMode {
        param([string]$Name, [int]$StartMode)
        $script:TestCalls.Add("mode:${Name}=$StartMode")
    }
    function Stop-DefenseClawService {
        param([string]$Name)
        $script:TestCalls.Add("stop:$Name")
    }
    function Start-DefenseClawService {
        param([string]$Name)
        $script:TestCalls.Add("start:$Name")
    }
    function Wait-DefenseClawServiceFailureRestartQuiescence {
        param($ServicesQuiescedAt, $GatewayServiceName, $GuardianServiceName)
    }
    function Wait-DefenseClawFreshGuardianReconcile {
        param($Layout, $GatewayServiceName, $GuardianServiceName)
        $script:TestCalls.Add('wait:coverage')
        throw 'LocalSystem guardian restarted but did not publish fresh required coverage within 90 seconds; last_status=last guardian reconcile failed for opencode'
    }
    function Wait-DefenseClawEnterpriseReadiness {
        param($Layout, $GatewayServiceName, $GuardianServiceName)
        $script:TestCalls.Add('wait:readiness')
    }
    function Restore-DefenseClawTransactionServiceStartModes {
        param($Services, $GatewayServiceName, $GuardianServiceName)
        $script:TestCalls.Add('restore:modes')
    }
    function Get-DefenseClawServiceChecked {
        param([string]$Name)
        return [pscustomobject]@{ Name = $Name }
    }
    function Get-DefenseClawRecoveryGatewayAdmission {
        param([hashtable]$Layout)
        $script:TestAdmissionCalls++
        return $script:TestAdmission
    }

    $failures = [Collections.Generic.List[string]]::new()
    $originalProfile = Get-DefenseClawEnterpriseProfile
    $gateway = 'DefenseClawGateway'
    $guardian = 'DefenseClawHookGuardian'
    $enumerator = Get-DefenseClawEnumeratorServiceName -GuardianServiceName $guardian
    $services = @(
        [pscustomobject]@{ name = $gateway; existed = $true; running = $true; start_mode = 2 },
        [pscustomobject]@{ name = $guardian; existed = $true; running = $true; start_mode = 2 },
        [pscustomobject]@{ name = $enumerator; existed = $true; running = $true; start_mode = 2 }
    )
    $layout = @{ GatewayPath = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' }
    $admitted = [pscustomobject]@{
        admitted = $true
        code = ''
        message = ''
        source = @{ path = 'C:\ProgramData\DefenseClaw-Enterprise-Setup-0f\defenseclaw-gateway.exe'; signer_thumbprint = '' }
        sha256 = ('b' * 64)
        trust = 'hash_pinned'
        replaced_sha256 = ('a' * 64)
        product_version = '1.0.50'
        staged_version = '1.0.48'
    }
    $refused = [pscustomobject]@{ admitted = $false; code = 'same_binary'; message = 'the running Setup gateway is the staged gateway that failed' }
    function Invoke-TestStart {
        Start-DefenseClawTransactionServices `
            -Services $services `
            -Layout $layout `
            -ServicesQuiescedAt ([DateTime]::UtcNow.ToString('o')) `
            -TrustInProcessQuiescence `
            -GatewayServiceName $gateway `
            -GuardianServiceName $guardian
    }
    function Reset-TestState {
        $script:TestCalls.Clear()
        $script:TestAdmissionCalls = 0
        $script:DefenseClawRecoveryGatewayRuns = @()
        $script:DefenseClawRecoveryGatewayRefusal = $null
        $script:DefenseClawRecoveryActivationDeferred = $false
    }
    try {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

        # 1. A recovery that may defer, with an admitted Setup gateway: the
        #    restored release is left stopped and disabled, nothing starts the
        #    gateway or the enumerator, and the decision is recorded.
        Reset-TestState
        $script:TestAdmission = $admitted
        $script:DefenseClawRecoveryActivationDeferrable = $true
        try {
            Invoke-TestStart
        }
        catch {
            $failures.Add("admitted deferral threw: $($_.Exception.Message)")
        }
        $calls = @($script:TestCalls)
        if (-not [bool]$script:DefenseClawRecoveryActivationDeferred) {
            $failures.Add('admitted deferral did not record the deferred activation')
        }
        foreach ($forbidden in @("start:$gateway", "start:$enumerator", 'wait:readiness', 'restore:modes')) {
            if ($calls -contains $forbidden) {
                $failures.Add("admitted deferral still ran $forbidden")
            }
        }
        $lastGuardianStart = [Array]::LastIndexOf([object[]]$calls, "start:$guardian")
        $lastGuardianStop = [Array]::LastIndexOf([object[]]$calls, "stop:$guardian")
        if ($lastGuardianStop -lt $lastGuardianStart) {
            $failures.Add("the guardian was left running after the deferral: $($calls -join ', ')")
        }
        foreach ($name in @($gateway, $guardian)) {
            if ([Array]::LastIndexOf([object[]]$calls, "mode:$name=4") -lt [Array]::LastIndexOf([object[]]$calls, "mode:$name=3")) {
                $failures.Add("$name was not left disabled: $($calls -join ', ')")
            }
        }
        $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
        if ($runs.Count -ne 1 -or [string]$runs[0].action -cne 'service-reactivation' -or
            [string]$runs[0].outcome -cne 'deferred' -or [string]$runs[0].product_version -cne '1.0.50' -or
            [string]$runs[0].staged_version -cne '1.0.48' -or
            -not ([string]$runs[0].staged_error).Contains('did not publish fresh required coverage')) {
            $failures.Add("deferral record: $(@($runs) | ConvertTo-Json -Compress)")
        }

        # 2. A refused admission (for example the same release) keeps the
        #    coverage failure and records why.
        Reset-TestState
        $script:TestAdmission = $refused
        $threw = $false
        try {
            Invoke-TestStart
        }
        catch {
            $threw = ([string]$_.Exception.Message).Contains('did not publish fresh required coverage')
        }
        if (-not $threw -or [bool]$script:DefenseClawRecoveryActivationDeferred -or
            $null -eq $script:DefenseClawRecoveryGatewayRefusal -or
            [string]$script:DefenseClawRecoveryGatewayRefusal.action -cne 'service-reactivation' -or
            [string]$script:DefenseClawRecoveryGatewayRefusal.code -cne 'same_binary') {
            $failures.Add("refused admission: threw=$threw deferred=$script:DefenseClawRecoveryActivationDeferred refusal=$($script:DefenseClawRecoveryGatewayRefusal | ConvertTo-Json -Compress)")
        }

        # 3. Outside a deferrable recovery (an in-process rollback) the
        #    coverage failure is final and the admission is not consulted.
        Reset-TestState
        $script:TestAdmission = $admitted
        $script:DefenseClawRecoveryActivationDeferrable = $false
        $threw = $false
        try {
            Invoke-TestStart
        }
        catch {
            $threw = $true
        }
        if (-not $threw -or $script:TestAdmissionCalls -ne 0 -or [bool]$script:DefenseClawRecoveryActivationDeferred) {
            $failures.Add("non-deferrable rollback: threw=$threw admission_calls=$script:TestAdmissionCalls")
        }

        # 4. Secure Client never defers.
        Reset-TestState
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        $script:DefenseClawRecoveryActivationDeferrable = $true
        $threw = $false
        try {
            Invoke-TestStart
        }
        catch {
            $threw = $true
        }
        if (-not $threw -or $script:TestAdmissionCalls -ne 0) {
            $failures.Add("Secure Client deferral: threw=$threw admission_calls=$script:TestAdmissionCalls")
        }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $script:DefenseClawRecoveryActivationDeferrable = $false

        # 5. Repair after a deferred recovery stops with the next step;
        #    Upgrade and Uninstall continue; nothing stops without a deferral.
        $deferredRecovery = [pscustomobject]@{ recovered = $true; activation_deferred = $true }
        $plainRecovery = [pscustomobject]@{ recovered = $true; activation_deferred = $false }
        $legacyRecovery = [pscustomobject]@{ recovered = $true }
        try {
            Assert-DefenseClawRecoveryActivatedForAction -Recovery $deferredRecovery -Action Repair
            $failures.Add('Repair continued after a deferred recovery')
        }
        catch {
            if (-not ([string]$_.Exception.Message).Contains('upgrade')) {
                $failures.Add("Repair refusal does not name the next step: $($_.Exception.Message)")
            }
        }
        foreach ($case in @(
                @($deferredRecovery, 'Upgrade'), @($deferredRecovery, 'Uninstall'),
                @($plainRecovery, 'Repair'), @($legacyRecovery, 'Repair'))) {
            try {
                Assert-DefenseClawRecoveryActivatedForAction -Recovery $case[0] -Action $case[1]
            }
            catch {
                $failures.Add("$($case[1]) was refused: $($_.Exception.Message)")
            }
        }

        # 6. Recover-DefenseClawPendingTransaction opts in only when asked and
        #    always clears the opt-in, also when the restore fails.
        $scratch = Microsoft.PowerShell.Management\Join-Path $ScratchRoot ("dc-deferral-" + [Guid]::NewGuid().ToString('N'))
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $scratch -Force)
        try {
            $pendingPath = Microsoft.PowerShell.Management\Join-Path $scratch 'pending.json'
            Microsoft.PowerShell.Management\Set-Content -LiteralPath $pendingPath -Value '{"snapshot":"C:\\x\\snapshot.json"}' -Encoding ASCII
            $recoverLayout = @{ PendingPath = $pendingPath }
            $script:TestSeenDeferrable = @()
            $script:TestRestoreThrows = $false
            function Assert-DefenseClawNoReparsePath { param([string]$Path) }
            function Restore-DefenseClawTransactionWithManagedHooksRollback {
                param($SnapshotPath, $Layout)
                $script:TestSeenDeferrable += [bool]$script:DefenseClawRecoveryActivationDeferrable
                if ($script:TestRestoreThrows) { throw 'restore failed' }
                $script:DefenseClawRecoveryActivationDeferred = [bool]$script:DefenseClawRecoveryActivationDeferrable
                return [pscustomobject]@{ install_root_created = $false; state_root_created = $false }
            }
            function Complete-DefenseClawTransaction { param($SnapshotPath, $Layout, [switch]$Rollback) }
            $result = Recover-DefenseClawPendingTransaction -Layout $recoverLayout -GatewayServiceName $gateway -GuardianServiceName $guardian -AllowDeferredActivation
            if (-not [bool]$result.activation_deferred -or [bool]$script:DefenseClawRecoveryActivationDeferrable) {
                $failures.Add("opted-in recovery: deferred=$($result.activation_deferred) deferrable_after=$script:DefenseClawRecoveryActivationDeferrable")
            }
            $result = Recover-DefenseClawPendingTransaction -Layout $recoverLayout -GatewayServiceName $gateway -GuardianServiceName $guardian
            if ([bool]$result.activation_deferred) {
                $failures.Add('a recovery that did not opt in reported a deferred activation')
            }
            $script:TestRestoreThrows = $true
            try {
                [void](Recover-DefenseClawPendingTransaction -Layout $recoverLayout -GatewayServiceName $gateway -GuardianServiceName $guardian -AllowDeferredActivation)
            }
            catch {
            }
            if ([bool]$script:DefenseClawRecoveryActivationDeferrable) {
                $failures.Add('a failed restore left the deferral opt-in set')
            }
            if ((@($script:TestSeenDeferrable) -join ',') -cne 'True,False,True') {
                $failures.Add("restore saw deferrable=$(@($script:TestSeenDeferrable) -join ',')")
            }
        }
        finally {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
        }

        # 7. The production call sites opt in only for Upgrade, Repair and
        #    Uninstall, and check the Repair next step.
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
        $calls = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Recover-DefenseClawPendingTransaction'
        }, $true))
        $optedIn = @($calls | Where-Object { $_.Extent.Text.Contains("-AllowDeferredActivation:(`$Action -in @('Upgrade', 'Repair', 'Uninstall'))") })
        if ($optedIn.Count -ne 2) {
            $failures.Add("expected 2 opted-in recovery call sites, found $($optedIn.Count) of $($calls.Count)")
        }
    }
    finally {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        $script:DefenseClawRecoveryActivationDeferrable = $false
        $script:DefenseClawRecoveryActivationDeferred = $false
        $script:DefenseClawRecoveryGatewayRuns = @()
        $script:DefenseClawRecoveryGatewayRefusal = $null
    }
    return @($failures)
} $ScratchRoot $modulePath

if (@($failures).Count -gt 0) {
    foreach ($failure in @($failures)) {
        [Console]::Error.WriteLine("FAIL: $failure")
    }
    exit 1
}
'enterprise-standalone-recovery-activation-deferral-smoke: OK'
