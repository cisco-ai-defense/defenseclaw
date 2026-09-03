# defenseclaw-managed-hook v7
# Copilot CLI on Windows sends each hook event as UTF-8 JSON on stdin. The
# release hook launcher uses the GUI subsystem, so Start-Process cannot be
# trusted to inherit redirected stdin/stdout. This adapter preserves the bytes
# in memory, waits inside Copilot's 30-second hook budget, and deliberately
# fails open on integration errors to match the Copilot connector contract.
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
$hook = '{{.HookBinaryPS}}'
$timeoutMS = {{.CopilotHookTimeoutMS}}
$process = $null
$started = $false
$stdinClosed = $false
$deadline = [System.Diagnostics.Stopwatch]::StartNew()

try {
    if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
        throw "DefenseClaw hook launcher is missing: $hook"
    }
    $payload = [Console]::In.ReadToEnd()
    # Windows PowerShell 5.1 materializes the redirected-stream encoding marker
    # as U+FEFF even when the original Copilot JSON bytes had no BOM. JSON must
    # begin with the object itself, so remove exactly one leading marker while
    # preserving every byte of the event body after it.
    if ($payload.Length -gt 0 -and $payload[0] -eq [char]0xFEFF) {
        $payload = $payload.Substring(1)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Windows PowerShell's .NET Framework Process API has no
    # ProcessStartInfo.StandardInputEncoding property. Process instead builds
    # its redirected readers/writer from these console encodings.
    [Console]::InputEncoding = $utf8NoBom
    [Console]::OutputEncoding = $utf8NoBom

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
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    # StreamWriter.WriteAsync may depend on a shared worker under Windows
    # PowerShell 5.1. A busy host can starve that worker while the child waits
    # for EOF, turning a tiny payload into a false timeout. Bind TextWriter's
    # native method directly to a dedicated long-running task so no PowerShell
    # script block crosses threads and exceptions remain observable here.
    $process.StandardInput.AutoFlush = $true
    $writeMethod = [System.IO.TextWriter].GetMethod('Write', [Type[]]@([object]))
    $writeAction = [System.Delegate]::CreateDelegate(
        [System.Action[object]],
        $process.StandardInput,
        $writeMethod
    )
    $stdinTask = [System.Threading.Tasks.Task]::Factory.StartNew(
        [System.Action[object]]$writeAction,
        [object]$payload,
        [System.Threading.CancellationToken]::None,
        [System.Threading.Tasks.TaskCreationOptions]::LongRunning,
        [System.Threading.Tasks.TaskScheduler]::Default
    )

    $remainingMS = $timeoutMS - [int]$deadline.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $stdinTask.Wait($remainingMS)) {
        throw "DefenseClaw hook launcher timed out after ${timeoutMS}ms while receiving input"
    }
    [void]$stdinTask.GetAwaiter().GetResult()
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
    if ($stdout.Length -gt 0) {
        [Console]::Out.Write($stdout)
    }
    if ($stderr.Length -gt 0) {
        [Console]::Error.Write($stderr)
    }
}
catch {
    [Console]::Error.WriteLine('defenseclaw: Copilot hook adapter failed open: ' + $_.Exception.Message)
}
finally {
    if ($started -and -not $process.HasExited) {
        try {
            $process.Kill()
            [void]$process.WaitForExit(5000)
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
[System.Environment]::Exit(0)
