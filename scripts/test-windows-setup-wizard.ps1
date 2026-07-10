# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Drives the native setup wizard through bounded Win32 controls.

.DESCRIPTION
    The default cancel-only probe is safe for a developer workstation: it
    cycles every connector, mode, and start-gateway control, then cancels
    without entering setup. -ActivateInstall is intentionally restricted to a
    GitHub-hosted Windows runner and a state directory below RUNNER_TEMP. In
    that mode the same real controls select the requested values, activate
    Install, wait for the completion page, and activate Finish.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SetupPath,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) "defenseclaw-wizard-smoke-$PID"),
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 15,
    [ValidateSet('none', 'codex', 'claudecode')]
    [string]$Connector = 'claudecode',
    [ValidateSet('observe', 'action')]
    [string]$Mode = 'observe',
    [switch]$StartGateway,
    [switch]$ActivateInstall,
    [switch]$InteropSelfTestOnly,
    [ValidateRange(30, 1800)]
    [int]$InstallTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'The setup wizard probe requires native Windows.'
}

$setup = [IO.Path]::GetFullPath($SetupPath)
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "Setup executable not found: $setup"
}
if (-not [IO.Path]::GetExtension($setup).Equals('.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Setup path must name an executable: $setup"
}

$state = [IO.Path]::GetFullPath($StateRoot)
if ($ActivateInstall) {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
        throw '-ActivateInstall is restricted to a disposable GitHub-hosted Actions user.'
    }
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        throw '-ActivateInstall requires RUNNER_TEMP.'
    }
    $runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
    $relativeState = [IO.Path]::GetRelativePath($runnerTemp, $state)
    $parentPrefix = '..' + [IO.Path]::DirectorySeparatorChar
    if ($relativeState -eq '.' -or $relativeState -eq '..' -or
        $relativeState.StartsWith($parentPrefix, [StringComparison]::Ordinal) -or
        [IO.Path]::IsPathRooted($relativeState)) {
        throw "Install-driving wizard state must be a child of RUNNER_TEMP: $state"
    }
}
[IO.Directory]::CreateDirectory($state) | Out-Null

if (-not ('DefenseClaw.SetupWizardSmokeNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace DefenseClaw
{
    public static class SetupWizardSmokeNativeMethods
    {
        [DllImport(
            "user32.dll",
            EntryPoint = "CreateWindowExW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        public static extern IntPtr CreateWindowExW(
            uint extendedStyle,
            string className,
            string windowName,
            uint style,
            int x,
            int y,
            int width,
            int height,
            IntPtr parent,
            IntPtr menu,
            IntPtr instance,
            IntPtr parameter);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyWindow(IntPtr window);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetDlgItem(IntPtr dialog, int controlId);

        [DllImport(
            "user32.dll",
            EntryPoint = "PostMessageW",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessage(
            IntPtr window,
            uint message,
            UIntPtr wParam,
            IntPtr lParam);

        [DllImport(
            "user32.dll",
            EntryPoint = "SendMessageTimeoutW",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr window,
            uint message,
            UIntPtr wParam,
            IntPtr lParam,
            uint flags,
            uint timeoutMilliseconds,
            out UIntPtr result);
    }
}
'@
}

function Invoke-BoundedWindowMessage {
    param(
        [Parameter(Mandatory)][IntPtr]$Window,
        [Parameter(Mandatory)][uint32]$Message,
        [UIntPtr]$WParam = [UIntPtr]::Zero,
        [IntPtr]$LParam = [IntPtr]::Zero,
        [uint32]$TimeoutMilliseconds = 2000
    )
    $result = [UIntPtr]::Zero
    $flags = [uint32](0x0001 -bor 0x0002) # SMTO_BLOCK | SMTO_ABORTIFHUNG
    $response = [DefenseClaw.SetupWizardSmokeNativeMethods]::SendMessageTimeout(
        $Window,
        $Message,
        $WParam,
        $LParam,
        $flags,
        $TimeoutMilliseconds,
        [ref]$result
    )
    if ($response -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Wizard did not process Win32 message 0x$($Message.ToString('X')) within $TimeoutMilliseconds ms (error $errorCode)."
    }
    return $result.ToUInt64()
}

function Get-BoundedWindowText([IntPtr]$Window) {
    $length = [int](Invoke-BoundedWindowMessage -Window $Window -Message 0x000E) # WM_GETTEXTLENGTH
    $characters = $length + 1
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($characters * 2)
    try {
        $null = Invoke-BoundedWindowMessage -Window $Window -Message 0x000D `
            -WParam ([UIntPtr]$characters) -LParam $buffer # WM_GETTEXT
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($buffer)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

function Assert-UnicodeWindowTextInterop {
    $expected = 'DefenseClaw → installed'
    $window = [DefenseClaw.SetupWizardSmokeNativeMethods]::CreateWindowExW(
        0,
        'STATIC',
        $expected,
        0,
        0,
        0,
        1,
        1,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [IntPtr]::Zero
    )
    if ($window -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not create the Unicode window-text interop probe (error $errorCode)."
    }
    try {
        $observed = Get-BoundedWindowText $window
        if (-not [string]::Equals($observed, $expected, [StringComparison]::Ordinal)) {
            throw "Unicode window-text interop decoded '$observed'; expected '$expected'."
        }
    } finally {
        $null = [DefenseClaw.SetupWizardSmokeNativeMethods]::DestroyWindow($window)
    }
}

function Get-WizardControl([IntPtr]$Window, [int]$ControlId, [string]$Label) {
    $control = [DefenseClaw.SetupWizardSmokeNativeMethods]::GetDlgItem($Window, $ControlId)
    if ($control -eq [IntPtr]::Zero) {
        throw "Setup wizard did not expose the $Label control (id $ControlId)."
    }
    return $control
}

function Set-AndAssertComboSelection([IntPtr]$Control, [int]$Index, [string]$Label) {
    $selected = Invoke-BoundedWindowMessage -Window $Control -Message 0x014E -WParam ([UIntPtr]$Index)
    if ($selected -ne $Index) {
        throw "$Label selection returned index $selected; expected $Index."
    }
    $observed = Invoke-BoundedWindowMessage -Window $Control -Message 0x0147
    if ($observed -ne $Index) {
        throw "$Label control reported index $observed; expected $Index."
    }
}

function Set-AndAssertCheckState([IntPtr]$Control, [bool]$Checked) {
    $expected = if ($Checked) { 1 } else { 0 }
    $null = Invoke-BoundedWindowMessage -Window $Control -Message 0x00F1 -WParam ([UIntPtr]$expected)
    $observed = Invoke-BoundedWindowMessage -Window $Control -Message 0x00F0
    if ($observed -ne $expected) {
        throw "Start-gateway control reported state $observed; expected $expected."
    }
}

function Send-WizardCommand([IntPtr]$Window, [int]$ControlId, [string]$Label) {
    if (-not [DefenseClaw.SetupWizardSmokeNativeMethods]::PostMessage(
        $Window,
        0x0111,
        [UIntPtr]$ControlId,
        [IntPtr]::Zero
    )) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not post the wizard $Label command (error $errorCode)."
    }
}

function Write-WizardTrace([string]$Event, [System.Collections.IDictionary]$Fields = $null) {
    if (-not $ActivateInstall) { return }
    $record = [ordered]@{
        timestamp_utc = [DateTime]::UtcNow.ToString('o')
        elapsed_ms    = [Math]::Round($total.Elapsed.TotalMilliseconds, 1)
        event         = $Event
    }
    if ($null -ne $Fields) {
        foreach ($entry in $Fields.GetEnumerator()) {
            $record[[string]$entry.Key] = $entry.Value
        }
    }
    [IO.File]::AppendAllText(
        $wizardTracePath,
        (($record | ConvertTo-Json -Compress -Depth 4) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-WizardObservation(
    [Diagnostics.Process]$WizardProcess,
    [IntPtr]$PrimaryControl,
    [IntPtr]$HeadingControl
) {
    $cpuMilliseconds = $null
    $workingSetBytes = $null
    try {
        $WizardProcess.Refresh()
        $cpuMilliseconds = [Math]::Round($WizardProcess.TotalProcessorTime.TotalMilliseconds, 1)
        $workingSetBytes = $WizardProcess.WorkingSet64
    } catch {
        # HasExited below remains the authoritative process-state check.
    }
    $maintenanceBytes = 0
    if (Test-Path -LiteralPath $observedMaintenancePath -PathType Leaf) {
        $maintenanceBytes = (Get-Item -LiteralPath $observedMaintenancePath -Force).Length
    }
    return [ordered]@{
        process_id       = $WizardProcess.Id
        process_exited   = $WizardProcess.HasExited
        process_cpu_ms   = $cpuMilliseconds
        working_set      = $workingSetBytes
        primary_text     = Get-BoundedWindowText $PrimaryControl
        heading_text     = Get-BoundedWindowText $HeadingControl
        install_root     = Test-Path -LiteralPath $observedInstallRoot -PathType Container
        install_state    = Test-Path -LiteralPath $observedInstallState -PathType Leaf
        maintenance_copy = Test-Path -LiteralPath $observedMaintenancePath -PathType Leaf
        maintenance_size = $maintenanceBytes
        installed_app    = Test-Path -LiteralPath $observedARPKey
        config_present   = Test-Path -LiteralPath $observedConfigPath -PathType Leaf
        gateway_pid      = Test-Path -LiteralPath $observedGatewayPID -PathType Leaf
        watchdog_pid     = Test-Path -LiteralPath $observedWatchdogPID -PathType Leaf
    }
}

$connectorIndices = @{ none = 0; codex = 1; claudecode = 2 }
$modeIndices = @{ observe = 0; action = 1 }
$process = $null
$finished = $false
$total = [Diagnostics.Stopwatch]::StartNew()
$wizardTracePath = Join-Path $state 'wizard-driver.log'
$observedInstallRoot = Join-Path ([Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)) 'Programs\DefenseClaw'
$observedInstallState = Join-Path $observedInstallRoot 'installer\install-state.json'
$observedMaintenancePath = Join-Path ([Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)) 'DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe'
$observedDataRoot = Join-Path ([Environment]::GetFolderPath(
    [Environment+SpecialFolder]::UserProfile
)) '.defenseclaw'
$observedConfigPath = Join-Path $observedDataRoot 'config.yaml'
$observedGatewayPID = Join-Path $observedDataRoot 'gateway.pid'
$observedWatchdogPID = Join-Path $observedDataRoot 'watchdog.pid'
$observedARPKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw'
if ($ActivateInstall) {
    [IO.File]::WriteAllText($wizardTracePath, '', [Text.UTF8Encoding]::new($false))
    Write-WizardTrace 'driver-start' ([ordered]@{
        connector      = $Connector
        mode           = $Mode
        start_gateway  = $StartGateway.IsPresent
        timeout_seconds = $InstallTimeoutSeconds
    })
}
$unicodeInterop = [Diagnostics.Stopwatch]::StartNew()
Assert-UnicodeWindowTextInterop
$unicodeInterop.Stop()
Write-WizardTrace 'unicode-interop-passed' ([ordered]@{
    duration_ms = [Math]::Round($unicodeInterop.Elapsed.TotalMilliseconds, 1)
})
if ($InteropSelfTestOnly) {
    [ordered]@{
        unicode_window_text = 'pass'
        duration_ms         = [Math]::Round($unicodeInterop.Elapsed.TotalMilliseconds, 1)
    } | ConvertTo-Json -Compress
    return
}
try {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $setup
    $startInfo.WorkingDirectory = $state
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw 'Starting the setup wizard returned no process.'
    }
    Write-WizardTrace 'process-started' ([ordered]@{ process_id = $process.Id })

    $inputIdle = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.WaitForInputIdle($TimeoutSeconds * 1000)) {
        throw "Setup wizard did not become input-idle within $TimeoutSeconds seconds."
    }
    $inputIdle.Stop()

    $windowReady = [Diagnostics.Stopwatch]::StartNew()
    $window = [IntPtr]::Zero
    while ($windowReady.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ($process.HasExited) {
            throw "Setup wizard exited before exposing its window (exit code $($process.ExitCode))."
        }
        $process.Refresh()
        $window = $process.MainWindowHandle
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 25
    }
    $windowReady.Stop()
    if ($window -eq [IntPtr]::Zero) {
        throw "Setup wizard did not expose a main window within $TimeoutSeconds seconds."
    }

    $ping = [Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-BoundedWindowMessage -Window $window -Message 0x0000
    $ping.Stop()

    $connectorControl = Get-WizardControl $window 1001 'connector'
    $modeControl = Get-WizardControl $window 1002 'mode'
    $startControl = Get-WizardControl $window 1003 'start-gateway'
    $primaryControl = Get-WizardControl $window 1005 'primary action'
    $descriptionControl = Get-WizardControl $window 1009 'description'
    $headingControl = Get-WizardControl $window 1011 'heading'

    $control = [Diagnostics.Stopwatch]::StartNew()
    foreach ($index in 0..2) {
        Set-AndAssertComboSelection $connectorControl $index 'Connector'
    }
    foreach ($index in 0..1) {
        Set-AndAssertComboSelection $modeControl $index 'Mode'
    }
    Set-AndAssertCheckState $startControl $false
    Set-AndAssertCheckState $startControl $true
    Set-AndAssertComboSelection $connectorControl $connectorIndices[$Connector] 'Connector'
    Set-AndAssertComboSelection $modeControl $modeIndices[$Mode] 'Mode'
    Set-AndAssertCheckState $startControl $StartGateway.IsPresent
    $control.Stop()
    Write-WizardTrace 'controls-selected' ([ordered]@{
        connector_index = $connectorIndices[$Connector]
        mode_index      = $modeIndices[$Mode]
        start_gateway   = $StartGateway.IsPresent
    })

    $completion = $null
    if ($ActivateInstall) {
        $install = [Diagnostics.Stopwatch]::StartNew()
        Send-WizardCommand $window 1005 'Install'
        Write-WizardTrace 'install-posted'
        $nextTraceSeconds = 0
        $lastObservation = $null
        while ($install.Elapsed.TotalSeconds -lt $InstallTimeoutSeconds) {
            if ($process.HasExited) {
                throw "Setup wizard exited before showing its completion page (exit code $($process.ExitCode))."
            }
            $null = Invoke-BoundedWindowMessage -Window $window -Message 0x0000
            $primaryText = Get-BoundedWindowText $primaryControl
            if ($primaryText -eq 'Finish') {
                $lastObservation = Get-WizardObservation $process $primaryControl $headingControl
                break
            }
            try {
                if ($install.Elapsed.TotalSeconds -ge $nextTraceSeconds) {
                    $lastObservation = Get-WizardObservation $process $primaryControl $headingControl
                    Write-WizardTrace 'install-progress' $lastObservation
                    $nextTraceSeconds += 5
                }
            } catch {
                Write-WizardTrace 'ui-probe-failed' ([ordered]@{ error = $_.Exception.Message })
                throw
            }
            Start-Sleep -Milliseconds 100
        }
        $install.Stop()
        if ($null -eq $lastObservation -or $lastObservation.primary_text -ne 'Finish') {
            $lastObservation = Get-WizardObservation $process $primaryControl $headingControl
            Write-WizardTrace 'install-timeout' $lastObservation
            throw "Setup wizard did not reach Finish within $InstallTimeoutSeconds seconds: $($lastObservation | ConvertTo-Json -Compress -Depth 4)"
        }
        $heading = Get-BoundedWindowText $headingControl
        $description = Get-BoundedWindowText $descriptionControl
        Write-WizardTrace 'completion-visible' ([ordered]@{
            heading = $heading
            install_ms = [Math]::Round($install.Elapsed.TotalMilliseconds, 1)
        })
        if ($heading -ne 'DefenseClaw is installed') {
            throw "Setup wizard completion heading was '$heading': $description"
        }
        Send-WizardCommand $window 1005 'Finish'
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            throw "Setup wizard did not exit after Finish within $TimeoutSeconds seconds."
        }
        $finished = $true
        if ($process.ExitCode -ne 0) {
            throw "Setup wizard exit code was $($process.ExitCode); expected 0 after install."
        }
        $completion = [ordered]@{
            heading     = $heading
            description = $description
            install_ms  = [Math]::Round($install.Elapsed.TotalMilliseconds, 1)
        }
    } else {
        # WM_COMMAND/Cancel closes the initial page without entering startAction.
        Send-WizardCommand $window 1006 'Cancel'
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            throw "Setup wizard did not exit after Cancel within $TimeoutSeconds seconds."
        }
        $finished = $true
        if ($process.ExitCode -ne 1602) {
            throw "Setup wizard exit code was $($process.ExitCode); expected cancel code 1602."
        }
    }
    $total.Stop()

    [ordered]@{
        setup_path       = $setup
        process_id       = $process.Id
        action           = if ($ActivateInstall) { 'install' } else { 'cancel-only' }
        connector        = $Connector
        mode             = $Mode
        start_gateway    = $StartGateway.IsPresent
        unicode_interop_ms = [Math]::Round($unicodeInterop.Elapsed.TotalMilliseconds, 1)
        input_idle_ms    = [Math]::Round($inputIdle.Elapsed.TotalMilliseconds, 1)
        window_ready_ms  = [Math]::Round($windowReady.Elapsed.TotalMilliseconds, 1)
        responsive_ms    = [Math]::Round($ping.Elapsed.TotalMilliseconds, 1)
        control_ms       = [Math]::Round($control.Elapsed.TotalMilliseconds, 1)
        total_ms         = [Math]::Round($total.Elapsed.TotalMilliseconds, 1)
        exit_code        = $process.ExitCode
        completion       = $completion
    } | ConvertTo-Json -Compress -Depth 4
} finally {
    if ($null -ne $process) {
        if (-not $finished) {
            try {
                if (-not $process.HasExited) {
                    try {
                        Write-WizardTrace 'terminating-failed-probe' ([ordered]@{ process_id = $process.Id })
                    } catch {
                        Write-Warning "Could not record failed setup wizard probe: $($_.Exception.Message)"
                    }
                    $process.Kill($true)
                    $null = $process.WaitForExit(5000)
                }
            } catch {
                Write-Warning "Could not terminate failed setup wizard probe: $($_.Exception.Message)"
            }
        }
        $process.Dispose()
    }
}
