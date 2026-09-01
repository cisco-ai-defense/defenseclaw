# DefenseClaw Windsurf native Windows hook adapter.
# defenseclaw-managed-hook v7
#
# Windsurf invokes this script through its documented `powershell` hook field.
# Copy the vendor's JSON stdin byte-for-byte into the exact packaged HookRuntime
# launcher, stream the launcher's stdout/stderr back unchanged, wait for it to
# finish, and preserve its exit code (including Windsurf's blocking exit 2).

$ErrorActionPreference = "Stop"
$hookBinary = '{{.HookBinaryPS}}'
$timeoutMS = {{.HookTimeoutMS}}
$failClosed = ('{{.FailMode}}' -eq 'closed') -or ($env:DEFENSECLAW_STRICT_AVAILABILITY -eq '1')
$process = $null
$exitCode = if ($failClosed) { 2 } else { 0 }

try {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $hookBinary
    $startInfo.Arguments = 'hook --connector windsurf'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    # Windows PowerShell 5.1 constructs Process.StandardInput with the current
    # console input encoding. Pin that writer to BOM-free UTF-8 before Start so
    # the raw copy below preserves Windsurf's JSON bytes.
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    if (-not $process.Start()) {
        throw "failed to start the packaged DefenseClaw hook launcher"
    }

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
    $stderrTask = $process.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
    $stdinTask = [Console]::OpenStandardInput().CopyToAsync($process.StandardInput.BaseStream)

    if (-not $stdinTask.Wait($timeoutMS)) {
        throw "timed out forwarding Windsurf hook stdin"
    }
    $process.StandardInput.Close()

    $remainingMS = $timeoutMS - [int]$clock.ElapsedMilliseconds
    if ($remainingMS -le 0 -or -not $process.WaitForExit($remainingMS)) {
        throw "DefenseClaw hook launcher timed out"
    }

    $null = $stdoutTask.GetAwaiter().GetResult()
    $null = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
} catch {
    if ($null -ne $process) {
        try {
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
        } catch {
            # The original adapter failure remains the actionable diagnostic.
        }
    }
    [Console]::Error.WriteLine("DefenseClaw Windsurf hook adapter: {0}", $_.Exception.Message)
    $exitCode = if ($failClosed) { 2 } else { 0 }
} finally {
    if ($null -ne $process) {
        try {
            $process.Dispose()
        } catch {
            # Cleanup cannot override the hook runtime's decision or fail mode.
        }
    }
}

[Environment]::Exit([int]$exitCode)
