# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Child,
    [string]$Root,
    [int]$OwnerProcessId,
    [long]$OwnerStartTicks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (
        Microsoft.PowerShell.Management\Join-Path `
            $PSScriptRoot `
            '..\DefenseClawEnterprise.psm1'
    )
)

if ($Child) {
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'detached-helper child mode requires -Root'
    }
    if ($OwnerProcessId -le 0 -or $OwnerStartTicks -le 0) {
        throw 'detached-helper child mode requires the owning smoke identity'
    }
    $childRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $helperPath = Microsoft.PowerShell.Management\Join-Path `
        $childRoot `
        'wait-helper.ps1'
    $environmentRoot = Microsoft.PowerShell.Management\Join-Path `
        $childRoot `
        'environment'
    $observationPath = Microsoft.PowerShell.Management\Join-Path `
        $environmentRoot `
        'environment-observation.json'
    Microsoft.PowerShell.Management\New-Item `
        -ItemType Directory `
        -Path $environmentRoot `
        -Force | Microsoft.PowerShell.Core\Out-Null
    $moduleLiteral = $modulePath.Replace("'", "''")
    $observationLiteral = $observationPath.Replace("'", "''")
    $helperBody = @"
#Requires -Version 5.1
`$ErrorActionPreference = 'Stop'
Microsoft.PowerShell.Core\Import-Module -Name '$moduleLiteral' -Force
`$module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
& `$module {
    [void](Initialize-DefenseClawNativeSecurity)
}
`$observation = [ordered]@{
    TEMP = [Environment]::GetEnvironmentVariable('TEMP', 'Process')
    TMP = [Environment]::GetEnvironmentVariable('TMP', 'Process')
    LOCALAPPDATA = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
    APPDATA = [Environment]::GetEnvironmentVariable('APPDATA', 'Process')
    USERPROFILE = [Environment]::GetEnvironmentVariable('USERPROFILE', 'Process')
    HOME = [Environment]::GetEnvironmentVariable('HOME', 'Process')
    HOMEDRIVE = [Environment]::GetEnvironmentVariable('HOMEDRIVE', 'Process')
    HOMEPATH = [Environment]::GetEnvironmentVariable('HOMEPATH', 'Process')
    PSModuleAnalysisCachePath = [Environment]::GetEnvironmentVariable(
        'PSModuleAnalysisCachePath',
        'Process'
    )
}
[IO.File]::WriteAllText(
    '$observationLiteral.tmp',
    (
        `$observation |
            Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
    ),
    [Text.UTF8Encoding]::new(`$false)
)
# Publish atomically, then live exactly as long as the owning smoke. The
# smoke outlives every capture wait, so "alive after captured EOF" is a causal
# no-inheritance proof; the smoke kills this helper after the proof, and on any
# path where the smoke ends first this helper exits with it instead of leaking.
[IO.File]::Move('$observationLiteral.tmp', '$observationLiteral')
try {
    `$owner = [Diagnostics.Process]::GetProcessById($OwnerProcessId)
    try {
        if (`$owner.StartTime.ToUniversalTime().Ticks -eq $OwnerStartTicks) {
            `$owner.WaitForExit()
        }
    }
    finally {
        `$owner.Dispose()
    }
}
catch {
    # The owning smoke already exited (or its PID was reused).
}
"@
    [IO.File]::WriteAllText(
        $helperPath,
        $helperBody,
        [Text.UTF8Encoding]::new($false)
    )
    Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
    $module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
    if ($null -eq $module) {
        throw 'DefenseClawEnterprise module was not imported'
    }
    # Exclude nested engine/module startup from the capture-EOF timing. The
    # timed region begins immediately before the production native launcher.
    [Console]::Out.WriteLine(
        'DEFENSECLAW_DETACHED_HELPER_READY_V1'
    )
    [Console]::Out.Flush()
    $started = & $module {
        param(
            [Parameter(Mandatory)][string]$HelperPath,
            [Parameter(Mandatory)][string]$ChildRoot,
            [Parameter(Mandatory)][string]$EnvironmentRoot,
            [Parameter(Mandatory)][string]$ObservationPath
        )
        function script:Assert-DefenseClawSelfUninstallHelper {
            param(
                [Parameter(Mandatory)][hashtable]$Layout,
                [Parameter(Mandatory)]$Receipt
            )
            return $Layout.SelfUninstallHelperPath
        }
        function script:Initialize-DefenseClawSelfUninstallEnvironment {
            param([Parameter(Mandatory)][hashtable]$Layout)
            return $Layout.SelfUninstallEnvironmentRoot
        }
        $layout = @{
            SelfUninstallHelperPath = $HelperPath
            LifecycleLockDirectory = $ChildRoot
            SelfUninstallEnvironmentRoot = $EnvironmentRoot
        }
        $receipt = [pscustomobject]@{
            helper_sha256 = ('0' * 64)
        }
        $helperPID = Start-DefenseClawSelfUninstallHelper `
            -Layout $layout `
            -Receipt $receipt
        $process = Microsoft.PowerShell.Management\Get-Process `
            -Id ([int]$helperPID) `
            -ErrorAction SilentlyContinue
        try {
            return [pscustomobject]@{
                schema_version = 1
                ok = $null -ne $process
                helper_pid = [int]$helperPID
                helper_alive_before_parent_exit = $null -ne $process
                helper_environment_root = $EnvironmentRoot
                observation_path = $ObservationPath
            }
        }
        finally {
            if ($null -ne $process) {
                $process.Dispose()
            }
        }
    } $helperPath $childRoot $environmentRoot $observationPath
    $started |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
    return
}

$testRoot = Microsoft.PowerShell.Management\Join-Path `
    ([IO.Path]::GetTempPath()) `
    (
        'defenseclaw-detached-helper-' +
        [Guid]::NewGuid().ToString('N')
    )
$nestedProcess = $null
$helperProcess = $null
$helperPID = 0
$environmentRootRetired = $false
try {
    Microsoft.PowerShell.Management\New-Item `
        -ItemType Directory `
        -Path $testRoot `
        -Force | Microsoft.PowerShell.Core\Out-Null
    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $enginePath = [IO.Path]::GetFullPath(
            [string]$currentProcess.MainModule.FileName
        )
        $ownerProcessId = $currentProcess.Id
        $ownerStartTicks = $currentProcess.StartTime.ToUniversalTime().Ticks
    }
    finally {
        $currentProcess.Dispose()
    }
    $quotedScript = '"' + $PSCommandPath.Replace('"', '\"') + '"'
    $quotedRoot = '"' + $testRoot.Replace('"', '\"') + '"'
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $enginePath
    $startInfo.Arguments = (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        "-File $quotedScript -Child -Root $quotedRoot " +
        "-OwnerProcessId $ownerProcessId -OwnerStartTicks $ownerStartTicks"
    )
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $testHomeDrive = [IO.Path]::GetPathRoot($testRoot).TrimEnd('\')
    $testHomePath = $testRoot.Substring($testHomeDrive.Length)
    foreach ($pair in @(
        @('TEMP', $testRoot),
        @('TMP', $testRoot),
        @('LOCALAPPDATA', $testRoot),
        @('APPDATA', $testRoot),
        @('USERPROFILE', $testRoot),
        @('HOME', $testRoot),
        @('HOMEDRIVE', $testHomeDrive),
        @('HOMEPATH', $testHomePath),
        @('PSModuleAnalysisCachePath', 'NUL')
    )) {
        $startInfo.EnvironmentVariables[[string]$pair[0]] =
            [string]$pair[1]
    }
    $nestedProcess = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $nestedProcess) {
        throw 'failed to start captured detached-helper smoke child'
    }
    $nestedProcess.StandardInput.Close()
    $readyMarker = $nestedProcess.StandardOutput.ReadLine()
    if ($readyMarker -cne 'DEFENSECLAW_DETACHED_HELPER_READY_V1') {
        throw (
            'captured detached-helper child did not reach its launch ' +
            "barrier: $readyMarker"
        )
    }
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    # Drain BOTH pipes asynchronously. A single sync ReadToEnd on either
    # stream can block the parent before the bounded WaitForExit below
    # runs (a PowerShell error record with its stack trace easily exceeds
    # the pipe buffer, and stdout can burst similarly). Concurrent async
    # reads let the child make progress on both streams while the parent
    # only waits on the ordered task pair below.
    $stdoutReadTask = $nestedProcess.StandardOutput.ReadToEndAsync()
    $stderrReadTask = $nestedProcess.StandardError.ReadToEndAsync()
    $detachedHelperWaitBudgetMs = 5 * 60 * 1000
    if (-not $nestedProcess.WaitForExit($detachedHelperWaitBudgetMs)) {
        # Process.Kill([bool]) is a .NET Core 2.1+ overload and is NOT
        # available under Windows PowerShell 5.1 (.NET Framework 4.x).
        # Fall back to taskkill.exe /T /F, which the runtime always ships
        # on Windows. Best-effort; the throw below still reports the hang.
        try {
            $taskkillPath = [IO.Path]::Combine(
                [Environment]::GetFolderPath('System'),
                'taskkill.exe'
            )
            $killArgs = @('/PID', $nestedProcess.Id, '/T', '/F')
            & $taskkillPath @killArgs | Out-Null
        } catch { }
        throw (
            'captured detached-helper smoke child did not exit within ' +
            "$($detachedHelperWaitBudgetMs / 1000)s"
        )
    }
    if (-not $stdoutReadTask.Wait($detachedHelperWaitBudgetMs)) {
        throw 'captured detached-helper smoke child stdout drain did not complete'
    }
    if (-not $stderrReadTask.Wait($detachedHelperWaitBudgetMs)) {
        throw 'captured detached-helper smoke child stderr drain did not complete'
    }
    $capturedOutput = $stdoutReadTask.Result
    $capturedError = $stderrReadTask.Result
    $stopwatch.Stop()
    if ($nestedProcess.ExitCode -ne 0) {
        throw (
            'captured detached-helper smoke child failed: ' +
            $capturedError.Trim()
        )
    }
    $childResult = $capturedOutput.Trim() |
        Microsoft.PowerShell.Utility\ConvertFrom-Json
    $helperPID = [int]$childResult.helper_pid
    $environmentRoot = [IO.Path]::GetFullPath(
        [string]$childResult.helper_environment_root
    ).TrimEnd('\')
    $expectedEnvironmentRoot = [IO.Path]::GetFullPath(
        (
            Microsoft.PowerShell.Management\Join-Path `
                $testRoot `
                'environment'
        )
    ).TrimEnd('\')
    if (-not [string]::Equals(
            $environmentRoot,
            $expectedEnvironmentRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'captured child returned an unexpected helper environment root'
    }
    $helperProcess = Microsoft.PowerShell.Management\Get-Process `
        -Id $helperPID `
        -ErrorAction SilentlyContinue
    $helperAlive = $null -ne $helperProcess
    $elapsedMilliseconds = [int64]$stopwatch.ElapsedMilliseconds
    if (-not [bool]$childResult.ok -or
        -not [bool]$childResult.helper_alive_before_parent_exit -or
        -not $helperAlive) {
        throw (
            'detached helper did not remain alive after its captured parent ' +
            'returned'
        )
    }
    # The helper lives until this smoke exits or kills it, so both pipes
    # reaching EOF while it is still alive proves it inherited no capture
    # handle. That proof is causal; capture_elapsed_ms is diagnostic only.
    $observationPath = [IO.Path]::GetFullPath(
        [string]$childResult.observation_path
    ).TrimEnd('\')
    if (-not $observationPath.StartsWith(
            $environmentRoot + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'helper environment observation escaped its protected root'
    }
    # Wait for the helper's observation or its exit, never a wall clock: a
    # cold Windows PowerShell import of the module is slow, not failed.
    while (-not (Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $observationPath `
            -PathType Leaf)) {
        if ($helperProcess.HasExited -and
            -not (Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath $observationPath `
                -PathType Leaf)) {
            throw 'detached helper did not publish its isolated environment'
        }
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
    }
    $observation = Microsoft.PowerShell.Management\Get-Content `
        -LiteralPath $observationPath `
        -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    foreach ($name in @(
        'TEMP',
        'TMP',
        'LOCALAPPDATA',
        'APPDATA',
        'USERPROFILE',
        'HOME'
    )) {
        if (-not [string]::Equals(
                [string]$observation.$name,
                $environmentRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "detached helper did not pin $name to its protected root"
        }
    }
    $homeDrive = [IO.Path]::GetPathRoot(
        $environmentRoot
    ).TrimEnd('\')
    $homePath = $environmentRoot.Substring($homeDrive.Length)
    if ([string]$observation.HOMEDRIVE -cne $homeDrive -or
        [string]$observation.HOMEPATH -cne $homePath -or
        [string]$observation.PSModuleAnalysisCachePath -cne 'NUL') {
        throw 'detached helper home/cache environment is not fail-closed'
    }
    $ambientModuleCache = Microsoft.PowerShell.Management\Join-Path `
        $environmentRoot `
        'Microsoft\Windows\PowerShell\ModuleAnalysisCache'
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $ambientModuleCache) {
        throw 'detached helper wrote a profile ModuleAnalysisCache despite NUL'
    }
    if (-not $helperProcess.HasExited) {
        $helperProcess.Kill()
    }
    # The exit event, not a bound: the root below is removable only after
    # the killed helper has released it.
    $helperProcess.WaitForExit()
    $helperProcess.Dispose()
    $helperProcess = $null
    Microsoft.PowerShell.Management\Remove-Item `
        -LiteralPath $environmentRoot `
        -Recurse `
        -Force
    $environmentRootRetired = -not (
        Microsoft.PowerShell.Management\Test-Path `
            -LiteralPath $environmentRoot
    )
    if (-not $environmentRootRetired) {
        throw 'helper-specific protected environment root survived cleanup'
    }
    [pscustomobject]@{
        schema_version = 1
        ok = $true
        engine = $PSVersionTable.PSVersion.ToString()
        capture_elapsed_ms = $elapsedMilliseconds
        helper_pid = $helperPID
        helper_alive_after_capture = $helperAlive
        no_inherited_capture_handles = $true
        protected_environment_pinned = $true
        module_analysis_cache_disabled = $true
        profile_cache_writes_confined = $true
        environment_root_retired = $environmentRootRetired
    } |
        Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
}
finally {
    if ($null -ne $helperProcess) {
        try {
            if (-not $helperProcess.HasExited) {
                $helperProcess.Kill()
                $helperProcess.WaitForExit()
            }
        }
        finally {
            $helperProcess.Dispose()
        }
    }
    elseif ($helperPID -gt 0) {
        Microsoft.PowerShell.Management\Stop-Process `
            -Id $helperPID `
            -Force `
            -ErrorAction SilentlyContinue
    }
    if ($null -ne $nestedProcess) {
        if (-not $nestedProcess.HasExited) {
            $nestedProcess.Kill()
            $nestedProcess.WaitForExit()
        }
        $nestedProcess.Dispose()
    }
    if (Microsoft.PowerShell.Management\Test-Path `
        -LiteralPath $testRoot) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $testRoot `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
