# defenseclaw-managed-hook v7
# Copilot CLI on Windows sends each hook event as UTF-8 JSON on stdin. The
# release hook launcher uses the GUI subsystem, so Start-Process cannot be
# trusted to inherit redirected stdin/stdout. This adapter preserves the bytes
# in memory and waits inside Copilot's 30-second hook budget. When the
# launcher is missing, fails or times out, a closed fail mode denies a tool
# call with Copilot's native answer (Copilot ignores a failed hook process);
# only an open one lets it run.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'sessionStart', 'sessionEnd', 'userPromptSubmitted', 'userPromptTransformed',
        'preToolUse', 'postToolUse', 'permissionRequest', 'agentStop',
        'subagentStart', 'subagentStop', 'postToolUseFailure', 'errorOccurred',
        'preCompact', 'notification'
    )]
    [string]$Event
)

$ErrorActionPreference = 'Stop'
{{if and (eq .FailMode "open") (not .Managed)}}function Test-DefenseClawInstallLockHeld {
    # The one install check of the Windows adapters: true while this
    # account's installer holds its data directory, the folder above this
    # adapter's hooks folder: its .install.lock exists as any type, or its
    # state cannot be read. Only "not found" is free, as for the native hook
    # (installLockHeld), the shell hooks and the in-agent plugins (GAP-0915).
    try {
        $dataDir = Split-Path -Parent $PSScriptRoot
        if ([string]::IsNullOrEmpty($dataDir)) { return $true }
        [void][System.IO.File]::GetAttributes((Join-Path $dataDir '.install.lock'))
        return $true
    }
    catch {
        $cause = $_.Exception
        while ($null -ne $cause) {
            if ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) {
                return $false
            }
            $cause = $cause.InnerException
        }
        return $true
    }
}
{{end}}$hook = '{{.HookBinaryPS}}'
$timeoutMS = {{.CopilotHookTimeoutMS}}
$process = $null
$started = $false
$stdinClosed = $false
$responseWritten = $false
$deadline = [System.Diagnostics.Stopwatch]::StartNew()

try {
    if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
        throw "DefenseClaw hook launcher is missing: $hook"
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Windows PowerShell's .NET Framework Process API has no
    # ProcessStartInfo.StandardInputEncoding property. Process instead builds
    # its redirected readers/writer from these console encodings. Set them
    # before ReadToEnd so Copilot's UTF-8 JSON is decoded as UTF-8, not the
    # console default.
    [Console]::InputEncoding = $utf8NoBom
    [Console]::OutputEncoding = $utf8NoBom
    $payload = [Console]::In.ReadToEnd()
    # Windows PowerShell 5.1 materializes the redirected-stream encoding marker
    # as U+FEFF even when the original Copilot JSON bytes had no BOM. JSON must
    # begin with the object itself, so remove exactly one leading marker while
    # preserving every byte of the event body after it.
    if ($payload.Length -gt 0 -and $payload[0] -eq [char]0xFEFF) {
        $payload = $payload.Substring(1)
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $hook
    $startInfo.Arguments = 'hook --connector copilot --event ' + $Event
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'DefenseClaw hook launcher did not start'
    }
    $started = $true
    # Child stdin budget starts after the launcher exists. PowerShell 5.1
    # startup must not steal the hook-input window, or a busy CI host
    # fail-opens as "timed out while receiving input".
    $deadline.Restart()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    # stdout/stderr are already being drained, so a small synchronous write
    # cannot deadlock. Waiting on a LongRunning Task previously burned the
    # remaining budget when the pool was slow to schedule the writer.
    $process.StandardInput.AutoFlush = $true
    $process.StandardInput.Write($payload)
    $process.StandardInput.Close()
    $stdinClosed = $true

    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $process.WaitForExit($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms"
    }
    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $stdoutTask.Wait($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms while reading output"
    }
    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $stderrTask.Wait($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms while reading diagnostics"
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    # The native hook answers a tool boundary on stdout with exit 0, a failed
    # check too; a launcher that exits non-zero without an answer crashed.
    if ($stdout.Length -eq 0 -and $process.ExitCode -ne 0) {
        if ($stderr.Length -gt 0) {
            [Console]::Error.Write($stderr)
        }
        throw "DefenseClaw hook launcher exited $($process.ExitCode) without an answer"
    }
    if ($stdout.Length -gt 0) {
        [Console]::Out.Write($stdout)
        $responseWritten = $true
    }
    if ($stderr.Length -gt 0) {
        [Console]::Error.Write($stderr)
    }
}
catch {
{{if and (eq .FailMode "open") (not .Managed)}}    # While this account's installer holds its data directory the answer is
    # closed, as fail mode closed answers (GAP-0915).
    if (Test-DefenseClawInstallLockHeld) {
        [Console]::Error.WriteLine('defenseclaw: DefenseClaw is being installed or upgraded for this account; blocking (fail mode closed)')
        [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed closed: ' + $_.Exception.Message); if (-not $responseWritten) { if ($Event -ceq 'preToolUse') { [Console]::Out.Write('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}') } elseif ($Event -ceq 'permissionRequest') { [Console]::Out.Write('{"behavior":"deny","message":"DefenseClaw hook failed closed"}') } }
    } else {
        [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed open: ' + $_.Exception.Message)
    }
{{else if eq .FailMode "open"}}    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed open: ' + $_.Exception.Message)
{{else}}    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed closed: ' + $_.Exception.Message); if (-not $responseWritten) { if ($Event -ceq 'preToolUse') { [Console]::Out.Write('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}') } elseif ($Event -ceq 'permissionRequest') { [Console]::Out.Write('{"behavior":"deny","message":"DefenseClaw hook failed closed"}') } }
{{end}}}
finally {
    if ($started -and -not $process.HasExited) {
        try {
            # Kill() only starts termination. Wait briefly: this wait and the
            # exit below share the reserve left after $timeoutMS inside
            # Copilot's 30-second hook budget.
            $process.Kill()
            [void]$process.WaitForExit(2000)
        }
        catch {
            [Console]::Error.WriteLine('defenseclaw: could not stop failed Copilot hook launcher: ' + $_.Exception.Message)
        }
    }
    if ($started -and -not $stdinClosed) {
        try {
            $process.StandardInput.Close()
        }
        catch {
            [Console]::Error.WriteLine('defenseclaw: could not close failed Copilot hook input: ' + $_.Exception.Message)
        }
    }
    if ($null -ne $process) {
        $process.Dispose()
    }
    $deadline.Stop()
}

[Console]::Out.Flush()
[Console]::Error.Flush()
# Exit through the console host. Windows PowerShell 5.1 spends seconds in
# runtime shutdown after [System.Environment]::Exit (about 3s on an idle host,
# more on a busy one), and Copilot counts that time against the hook budget.
# Hosts that do not support SetShouldExit keep the forced exit.
try {
    $Host.SetShouldExit(0)
}
catch {
    [System.Environment]::Exit(0)
}
