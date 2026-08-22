# defenseclaw-managed-hook v9
# Cursor 3.9.x on Windows delivers command-hook JSON as PowerShell pipeline
# objects. Native executables receive only encoding preambles on that path, so
# this adapter streams the reconstructed UTF-8 JSON directly to the shared
# consoleless launcher. It never materializes prompts or tool payloads on disk.
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [AllowNull()]
    [object]$InputObject
)

begin {
    $ErrorActionPreference = "Stop"
    $parts = [System.Collections.Generic.List[string]]::new()
}

process {
    if ($null -ne $InputObject) {
        [void]$parts.Add([string]$InputObject)
    }
}

end {
    $hook = '{{.HookBinaryPS}}'
    $exitCode = 2
    $responseWritten = $false
    try {
        if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
            throw "DefenseClaw hook launcher is missing: $hook"
        }
        $payload = $parts -join [Environment]::NewLine
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $payloadBytes = $utf8NoBom.GetBytes($payload)
        # Windows PowerShell does not wait for GUI-subsystem executables when
        # they are invoked with `&`, and it does not reliably connect their
        # standard handles. defenseclaw-hook.exe intentionally uses that
        # subsystem to avoid popup consoles, so launch it explicitly with
        # redirected handles and wait for the verdict before returning.
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $hook
        $startInfo.Arguments = 'hook --connector cursor{{if .Managed}} --enterprise-managed{{end}}'
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $started = $false
        $stdinClosed = $false
        $stdinTask = $null
        $timeoutMs = {{.HookTimeoutMS}}
        $deadline = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            if (-not $process.Start()) {
                throw "DefenseClaw hook launcher did not start"
            }
            $started = $true
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $stdinStream = $process.StandardInput.BaseStream
            $stdinTask = $stdinStream.WriteAsync($payloadBytes, 0, $payloadBytes.Length)
            $remainingMs = $timeoutMs - [int]$deadline.ElapsedMilliseconds
            if ($remainingMs -le 0 -or -not $stdinTask.Wait($remainingMs)) {
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms while receiving input"
            }
            $stdinTask.GetAwaiter().GetResult()
            $process.StandardInput.Close()
            $stdinClosed = $true

            $remainingMs = $timeoutMs - [int]$deadline.ElapsedMilliseconds
            if ($remainingMs -le 0 -or -not $process.WaitForExit($remainingMs)) {
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms"
            }
            $remainingMs = $timeoutMs - [int]$deadline.ElapsedMilliseconds
            if ($remainingMs -le 0 -or -not $stdoutTask.Wait($remainingMs)) {
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms while reading output"
            }
            $remainingMs = $timeoutMs - [int]$deadline.ElapsedMilliseconds
            if ($remainingMs -le 0 -or -not $stderrTask.Wait($remainingMs)) {
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms while reading diagnostics"
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($stdout.Length -eq 0) {
                throw "DefenseClaw hook launcher returned no response"
            }
            [Console]::Out.Write($stdout)
            $responseWritten = $true
            if ($stderr.Length -gt 0) {
                [Console]::Error.Write($stderr)
            }
            $exitCode = $process.ExitCode
        }
        finally {
            if ($started -and -not $process.HasExited) {
                try {
                    $process.Kill()
                    [void]$process.WaitForExit(5000)
                }
                catch {
                    [Console]::Error.WriteLine(
                        "defenseclaw: could not stop failed Cursor hook launcher: " + $_.Exception.Message
                    )
                }
            }
            if ($started -and -not $stdinClosed) {
                try {
                    $process.StandardInput.Close()
                }
                catch {
                    [Console]::Error.WriteLine(
                        "defenseclaw: could not close failed Cursor hook input: " + $_.Exception.Message
                    )
                }
            }
            $deadline.Stop()
            $process.Dispose()
        }
    }
    catch {
        [Console]::Error.WriteLine("defenseclaw: Cursor hook adapter failed: " + $_.Exception.Message)
        if (-not $responseWritten) {
{{if eq .FailMode "open"}}
            [Console]::Out.Write('{"continue":true}')
{{else}}
            [Console]::Out.Write('{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}')
{{end}}
        }
{{if eq .FailMode "open"}}
        $exitCode = 0
{{else}}
        $exitCode = 2
{{end}}
    }
    exit $exitCode
}
