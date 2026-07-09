# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Verifies that the native setup wizard remains responsive before installation.

.DESCRIPTION
    Launches the setup executable without install arguments, waits for its Win32
    input queue, sends bounded responsiveness probes, changes the connector
    selection, and cancels the wizard. The harness never activates the Install
    button, so it does not write product files or modify current-user setup state.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SetupPath,
    [string]$StateRoot = (Join-Path ([IO.Path]::GetTempPath()) "defenseclaw-wizard-smoke-$PID"),
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'The setup wizard responsiveness probe requires native Windows.'
}

$setup = [IO.Path]::GetFullPath($SetupPath)
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "Setup executable not found: $setup"
}
if (-not [IO.Path]::GetExtension($setup).Equals('.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Setup path must name an executable: $setup"
}

$state = [IO.Path]::GetFullPath($StateRoot)
[IO.Directory]::CreateDirectory($state) | Out-Null

if (-not ('DefenseClaw.SetupWizardSmokeNativeMethods' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace DefenseClaw
{
    public static class SetupWizardSmokeNativeMethods
    {
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetDlgItem(IntPtr dialog, int controlId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool PostMessage(
            IntPtr window,
            uint message,
            UIntPtr wParam,
            IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
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

$process = $null
$finished = $false
$total = [Diagnostics.Stopwatch]::StartNew()
try {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $setup
    $startInfo.WorkingDirectory = $state
    $startInfo.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw 'Starting the setup wizard returned no process.'
    }

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

    $connector = [DefenseClaw.SetupWizardSmokeNativeMethods]::GetDlgItem($window, 1001)
    if ($connector -eq [IntPtr]::Zero) {
        throw 'Setup wizard did not expose the connector control.'
    }
    $control = [Diagnostics.Stopwatch]::StartNew()
    $selected = Invoke-BoundedWindowMessage -Window $connector -Message 0x014E -WParam ([UIntPtr]2)
    if ($selected -ne 2) {
        throw "Connector selection returned index $selected; expected 2."
    }
    $observed = Invoke-BoundedWindowMessage -Window $connector -Message 0x0147
    if ($observed -ne 2) {
        throw "Connector control reported index $observed; expected 2."
    }
    $control.Stop()

    # WM_COMMAND/Cancel closes the initial page without entering startAction.
    if (-not [DefenseClaw.SetupWizardSmokeNativeMethods]::PostMessage(
        $window,
        0x0111,
        [UIntPtr]1006,
        [IntPtr]::Zero
    )) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Could not post the wizard Cancel command (error $errorCode)."
    }
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "Setup wizard did not exit after Cancel within $TimeoutSeconds seconds."
    }
    $finished = $true
    if ($process.ExitCode -ne 1602) {
        throw "Setup wizard exit code was $($process.ExitCode); expected cancel code 1602."
    }
    $total.Stop()

    [ordered]@{
        setup_path       = $setup
        process_id       = $process.Id
        action           = 'cancel-only'
        input_idle_ms    = [Math]::Round($inputIdle.Elapsed.TotalMilliseconds, 1)
        window_ready_ms  = [Math]::Round($windowReady.Elapsed.TotalMilliseconds, 1)
        responsive_ms    = [Math]::Round($ping.Elapsed.TotalMilliseconds, 1)
        control_ms       = [Math]::Round($control.Elapsed.TotalMilliseconds, 1)
        total_ms         = [Math]::Round($total.Elapsed.TotalMilliseconds, 1)
        exit_code        = $process.ExitCode
    } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $process) {
        if (-not $finished) {
            try {
                if (-not $process.HasExited) {
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
