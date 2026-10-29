# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-2438: a standalone uninstall removes StateRoot, which holds bundle.lock.
# It takes bundle.lock (the byte-range lock the Go bundle apply, TRUSTANCHORS=
# ensure and secret set take) before it changes anything: a lock held past the
# bounded wait is the lifecycle busy refusal, a free one is held until StateRoot
# is removed, and no bundle.lock is nothing to wait for.

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = Microsoft.PowerShell.Management\Join-Path ([IO.Path]::GetTempPath()) ("dc-bundlelock-" + [guid]::NewGuid().ToString('N'))
[void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $root)
try {
    $failures = & $module {
        param($root)
        $failures = [Collections.Generic.List[string]]::new()
        function Write-DefenseClawLifecyclePhase { param([string]$Stage) }
        $layout = @{ InstallStateDirectory = $root }
        $path = Microsoft.PowerShell.Management\Join-Path $root 'bundle.lock'
        # The Go runs' lock: share read and write, no delete, one byte locked.
        $goLock = {
            $stream = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
            try { $stream.Lock(0, 1); return $stream } catch { $stream.Dispose(); return $null }
        }

        if ($null -ne (Enter-DefenseClawBundleStoreLock -Layout $layout -TimeoutSeconds 1)) {
            $failures.Add('no bundle.lock returned a lock')
        }

        $held = & $goLock
        if ($null -eq $held) { throw 'the fixture could not take bundle.lock' }
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $message = ''
        try {
            $stray = Enter-DefenseClawBundleStoreLock -Layout $layout -TimeoutSeconds 2
            if ($null -ne $stray) { $stray.Dispose() }
            $failures.Add('a held bundle.lock was taken')
        }
        catch { $message = $_.Exception.Message }
        if ($message -notmatch 'holds the protected file lock' -or $message -notmatch 'bundle\.lock' -or
            $message -notmatch 'changed nothing') {
            $failures.Add("held bundle.lock refusal is not the lifecycle busy refusal: $message")
        }
        if ($clock.Elapsed.TotalSeconds -lt 1.5) {
            $failures.Add('a held bundle.lock was not waited for')
        }
        $held.Dispose()

        $script:DefenseClawPurgeBundleLock = Enter-DefenseClawBundleStoreLock -Layout $layout -TimeoutSeconds 2
        if ($null -eq $script:DefenseClawPurgeBundleLock) {
            $failures.Add('a free bundle.lock was not taken')
        }
        else {
            $other = & $goLock
            if ($null -ne $other) {
                $other.Dispose()
                $failures.Add('a bundle run took bundle.lock while the uninstall held it')
            }
        }
        Exit-DefenseClawPurgeBundleLock
        Exit-DefenseClawPurgeBundleLock
        if ($null -ne $script:DefenseClawPurgeBundleLock) {
            $failures.Add('the uninstall kept bundle.lock after the release')
        }
        $after = & $goLock
        if ($null -eq $after) {
            $failures.Add('a bundle run could not take bundle.lock after the release')
        }
        else {
            $after.Dispose()
        }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Force

        # GAP-2506: the printed FORCE=1 moves StateRoot aside while this run
        # holds bundle.lock inside it; Windows refuses to move a folder with
        # an open file under it, so the preparation releases the lock first.
        function Assert-DefenseClawOwnedServiceOrAbsent { }
        function Get-DefenseClawEnumeratorServiceName { param($GuardianServiceName) 'DefenseClawPodTestEnumerator' }
        function Get-DefenseClawSensorHelperImage { param($Layout, $GatewayServiceName) '' }
        function Test-DefenseClawServiceExists { param($Name) $false }
        $stateRoot = Microsoft.PowerShell.Management\Join-Path $root 'state'
        $installState = Microsoft.PowerShell.Management\Join-Path $stateRoot 'install'
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $installState)
        [IO.File]::WriteAllBytes((Microsoft.PowerShell.Management\Join-Path $installState 'bundle.lock'), [byte[]]@(0))
        $forcedLayout = @{
            StateRoot = $stateRoot
            InstallStateDirectory = $installState
            GatewayPath = 'C:\missing\defenseclaw-gateway.exe'
            ManifestPath = 'C:\missing\manifest.json'
            SensorHelperServiceName = 'DefenseClawPodTestSensorHelper'
            SensorHelperPath = 'C:\missing\defenseclaw-sensor-helper.exe'
        }
        $script:DefenseClawPurgeBundleLock = Enter-DefenseClawBundleStoreLock -Layout $forcedLayout -TimeoutSeconds 2
        if ($null -eq $script:DefenseClawPurgeBundleLock) {
            $failures.Add('the forced uninstall fixture could not take bundle.lock')
        }
        $preparation = $null
        try {
            $preparation = Invoke-DefenseClawForcedUninstallPreparation `
                -Layout $forcedLayout `
                -GatewayServiceName 'DefenseClawPodTestGateway' `
                -GuardianServiceName 'DefenseClawPodTestGuardian'
        }
        catch {
            $failures.Add("the forced uninstall could not move StateRoot aside while it held bundle.lock: $($_.Exception.Message)")
        }
        if ($null -ne $preparation) {
            $moved = [string]$preparation.moved_state_root
            if ([string]::IsNullOrEmpty($moved) -or -not [IO.Directory]::Exists($moved) -or [IO.Directory]::Exists($stateRoot)) {
                $failures.Add("StateRoot was not moved aside: moved='$moved'")
            }
        }
        if ($null -ne $script:DefenseClawPurgeBundleLock) {
            $failures.Add('the forced uninstall kept bundle.lock after it moved StateRoot aside')
        }
        Exit-DefenseClawPurgeBundleLock
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-purge-bundle-lock-smoke: OK'
