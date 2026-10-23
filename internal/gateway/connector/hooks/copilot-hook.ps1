# defenseclaw-managed-hook v7
# Copilot CLI on Windows sends each hook event as UTF-8 JSON on stdin. The
# release hook launcher uses the GUI subsystem, so Start-Process cannot be
# trusted to inherit redirected stdin/stdout. This adapter preserves the bytes
# in memory and waits inside Copilot's 30-second hook budget. When the
# launcher is missing, fails or times out, a closed fail mode denies a tool
# call with Copilot's native answer (Copilot ignores a failed hook process);
# only an open one lets it run.
{{if not .Managed}}# During an install or upgrade a per-user hook returns a native denial in
# every fail mode.
{{end}}{{if .SecureClientDelivery}}[CmdletBinding()]
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

{{else}}# Parse the binding ourselves: PowerShell parameter validation exits before
# the adapter can print Copilot's native denial, which the agent requires.
$Event = ''
if ($args.Count -eq 2 -and $args[0] -ieq '-Event') {
    $Event = [string]$args[1]
}
$reviewedEvents = @(
    'sessionStart', 'sessionEnd', 'userPromptSubmitted', 'userPromptTransformed',
    'preToolUse', 'postToolUse', 'permissionRequest', 'agentStop',
    'subagentStart', 'subagentStop', 'postToolUseFailure', 'errorOccurred',
    'preCompact', 'notification'
)
if ($reviewedEvents -cnotcontains $Event) {
    [Console]::Out.WriteLine('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook has no reviewed event binding; run defenseclaw setup copilot","behavior":"deny","message":"DefenseClaw hook has no reviewed event binding; run defenseclaw setup copilot"}')
    exit 0
}

{{end}}$ErrorActionPreference = 'Stop'
$hook = '{{.HookBinaryPS}}'
$timeoutMS = {{.CopilotHookTimeoutMS}}
$process = $null
$started = $false
$stdinClosed = $false
$responseWritten = $false
$deadline = [System.Diagnostics.Stopwatch]::StartNew()

{{if not .Managed}}function Test-DefenseClawInstallLockHeld {
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
$installGuard = $false
{{end}}try {
{{if not .Managed}}    if (Test-DefenseClawInstallLockHeld) {
        $installGuard = $true
        throw 'DefenseClaw install or upgrade in progress'
    }
{{end}}    if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
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
{{if not .Managed}}    if (Test-DefenseClawInstallLockHeld) {
        $installGuard = $true
        throw 'DefenseClaw install or upgrade in progress'
    }
{{end}}    if ($stdout.Length -gt 0) {
        [Console]::Out.Write($stdout)
        $responseWritten = $true
    }
    if ($stderr.Length -gt 0) {
        [Console]::Error.Write($stderr)
    }
}
catch {
{{if not .Managed}}    $failure = $_.Exception.Message
    # This adapter is the first Windows hook process Copilot starts. If
    # its launcher is missing or times out during an upgrade, the native hook
    # cannot answer, so the adapter must supply Copilot's own denial.
    if (-not $responseWritten -and ($installGuard -or (Test-DefenseClawInstallLockHeld))) {
        [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed closed while DefenseClaw is being installed or upgraded: ' + $failure)
        $message = 'DefenseClaw is being installed or upgraded for this account; try again in a moment, or run the installer again if it has stopped.'
        switch ($Event) {
            'preToolUse' {
                [Console]::Out.WriteLine('{"permissionDecision":"deny","permissionDecisionReason":"' + $message + '"}')
            }
            'permissionRequest' {
                [Console]::Out.WriteLine('{"behavior":"deny","message":"' + $message + '"}')
            }
        }
    }
    else {
{{end}}{{if eq .FailMode "open"}}    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed open: ' + $_.Exception.Message)
{{else}}    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed closed: ' + $_.Exception.Message); if (-not $responseWritten) { if ($Event -ceq 'preToolUse') { [Console]::Out.Write('{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}') } elseif ($Event -ceq 'permissionRequest') { [Console]::Out.Write('{"behavior":"deny","message":"DefenseClaw hook failed closed"}') } }
{{end}}{{if not .Managed}}    }
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
