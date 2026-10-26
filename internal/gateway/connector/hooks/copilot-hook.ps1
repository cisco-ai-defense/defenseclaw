# defenseclaw-managed-hook v7
# defenseclaw-copilot-closed-adapter v1
# Copilot CLI on Windows sends each hook event as UTF-8 JSON on stdin. The
# release hook launcher uses the GUI subsystem, so Start-Process cannot be
# trusted to inherit redirected stdin/stdout. This adapter preserves the bytes
# in memory and waits inside Copilot's 30-second hook budget. When the
# launcher is missing, fails or times out, a closed fail mode denies a tool
# call with Copilot's native answer (Copilot ignores a failed hook process);
# only an open one lets it run.
{{if not .Managed}}# During an install or upgrade a per-user adapter whose launcher fails returns
# a native denial in every fail mode; the native hook answers every other call.
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
    # The installer may keep its lock in DEFENSECLAW_HOME while config.data_dir
    # puts this adapter elsewhere. The native hook's installer-written state
    # records that home beside the launcher, independent of the agent's env.
    $dataDir = Split-Path -Parent $PSScriptRoot
    $hookDir = Split-Path -Parent $hook
    if ([string]::IsNullOrEmpty($dataDir) -or [string]::IsNullOrEmpty($hookDir)) { return $true }
    $roots = @($dataDir)
    $statePath = Join-Path $hookDir 'defenseclaw-hook-state.json'
    $statePresent = $false
    try {
        $attributes = [System.IO.File]::GetAttributes($statePath)
        $statePresent = $true
    }
    catch {
        $missing = $false
        for ($cause = $_.Exception; $null -ne $cause; $cause = $cause.InnerException) {
            if ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) { $missing = $true; break }
        }
        if (-not $missing) { return $true }
    }
    if ($statePresent) {
        if (($attributes -band [System.IO.FileAttributes]::Directory) -or
            ($attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $true }
        try {
            $info = [System.IO.FileInfo]::new($statePath)
            if ($info.Length -gt 65536) { return $true }
            $state = [System.IO.File]::ReadAllText($statePath) | ConvertFrom-Json -ErrorAction Stop
            $expectedDir = [System.IO.Path]::GetFullPath($hookDir).TrimEnd([char]92)
            $root = [string]$state.data_root
            if ([int]$state.schema_version -ne 1 -or $state.install_kind -cne 'powershell-windows' -or
                $state.install_scope -cne 'user' -or $state.command_dir -ine $expectedDir -or
                -not [System.IO.Path]::IsPathRooted($root) -or
                -not [string]::Equals([System.IO.Path]::GetFullPath($root).TrimEnd([char]92), $root.TrimEnd([char]92), [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
            $roots += $root
        }
        catch { return $true }
    }
    foreach ($root in $roots) {
        if (Test-DefenseClawInstallLockCurrent (Join-Path $root '.install.lock')) { return $true }
    }
    return $false
}

function Test-DefenseClawInstallLockCurrent([string]$lock) {
    try { [void][System.IO.File]::GetAttributes($lock) }
    catch {
        $missing = $false
        for ($cause = $_.Exception; $null -ne $cause; $cause = $cause.InnerException) {
            if ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) { $missing = $true; break }
        }
        return (-not $missing)
    }
    try { $item = Get-Item -LiteralPath $lock -Force -ErrorAction Stop }
    catch { return $true }
    $age = ([DateTime]::UtcNow - $item.LastWriteTimeUtc).TotalSeconds
    if ($age -gt 600 -or $age -lt -60) { return $false }
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $true }
    $pidPath = Join-Path $lock 'pid'
    try {
        $pidFile = Get-Item -LiteralPath $pidPath -Force -ErrorAction Stop
        if ($pidFile.PSIsContainer -or ($pidFile.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or $pidFile.Length -gt 64) { return $true }
        $holder = [System.IO.File]::ReadAllText($pidPath).Trim()
        [int]$holderId = 0
        if ($holder -notmatch '^[1-9][0-9]*$' -or -not [int]::TryParse($holder, [ref]$holderId)) { return $true }
        try { return (-not [System.Diagnostics.Process]::GetProcessById($holderId).HasExited) }
        catch [System.ArgumentException] { return $false }
        catch { return $true }
    }
    catch { return $true }
}
$installGuard = $false
{{end}}try {
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
    # A successful native hook answers with exit 0, including a denial.
    # A failed child may have written a partial or even complete answer before
    # failing. None of that output proves that the check completed.
    if ($process.ExitCode -ne 0) {
        if ($stderr.Length -gt 0) {
            [Console]::Error.Write($stderr)
        }
        throw "DefenseClaw hook launcher exited $($process.ExitCode)"
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
{{if not .Managed}}    $failure = $_.Exception.Message
    # This adapter is the first Windows hook process Copilot starts. If
    # its launcher is missing or times out during an upgrade, the native hook
    # cannot answer, so the adapter must supply Copilot's own denial.
    if (-not $responseWritten -and (Test-DefenseClawInstallLockHeld)) {
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
