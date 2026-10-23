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
{{if and (eq .FailMode "open") (not .Managed)}}    function Test-DefenseClawInstallLockHeld {
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
{{end}}    $hook = '{{.HookBinaryPS}}'
    $exitCode = 2
    $responseWritten = $false
{{if .CursorTargetModesJSON64}}    $failMode = 'closed'
{{end}}    try {
{{if .CursorTargetModesJSON64}}        $targetModesJSON64 = '{{.CursorTargetModesJSON64}}'
        $targetModes = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($targetModesJSON64)) | ConvertFrom-Json
        $currentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $targetMode = $targetModes.PSObject.Properties[$currentSID]
        if ($null -ne $targetMode -and $targetMode.Value -cin @('open', 'closed')) {
            $failMode = [string]$targetMode.Value
        }
{{end}}        if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
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
            # Windows PowerShell writes non-void .NET return values to the
            # success stream. Task[VoidTaskResult].GetResult() must therefore
            # be discarded explicitly or it precedes and corrupts the JSON
            # response Cursor expects on stdout.
            [void]$stdinTask.GetAwaiter().GetResult()
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
                    # Kill() only starts termination. Wait briefly: this wait
                    # and the exit below share the reserve left after
                    # $timeoutMs inside Cursor's 30-second hook budget.
                    $process.Kill()
                    [void]$process.WaitForExit(2000)
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
{{if .CursorTargetModesJSON64}}        if (-not $responseWritten) {
            if ($failMode -ceq 'open') {
                [Console]::Error.WriteLine('defenseclaw: WARNING hook fail-open; inspection bypassed connector=cursor reason=adapter_delivery_failure')
                [Console]::Out.Write('{"continue":true}')
                $exitCode = 0
            } else {
                [Console]::Out.Write('{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}')
                $exitCode = 2
            }
        }
{{else}}{{if and (eq .FailMode "open") (not .Managed)}}        # While this account's installer holds its data directory the answer
        # is closed, as fail mode closed answers (GAP-0915).
        $installing = Test-DefenseClawInstallLockHeld
        if (-not $responseWritten) {
            if ($installing) {
                [Console]::Error.WriteLine('defenseclaw: DefenseClaw is being installed or upgraded for this account; blocking (fail mode closed)')
                [Console]::Out.Write('{"continue":false,"permission":"deny","user_message":"DefenseClaw hook failed closed","agent_message":"DefenseClaw hook failed closed"}')
            } else {
                [Console]::Out.Write('{"continue":true}')
            }
        }
        $exitCode = 0
        if ($installing) { $exitCode = 2 }
{{else}}        if (-not $responseWritten) {
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
{{end}}{{end}}{{end}}
    }
    # powershell.exe -Command reduces a non-zero exit from an invoked script
    # to the generic process code 1. Cursor distinguishes the adapter's exact
    # fail-closed code, so flush the direct console writes and have this
    # dedicated hook host exit with the intended code. SetShouldExit does that
    # through the console host; Windows PowerShell 5.1 spends seconds in
    # runtime shutdown after [System.Environment]::Exit (about 3s on an idle
    # host, more on a busy one), which Cursor counts against the hook budget.
    # Hosts that do not support SetShouldExit keep the forced exit.
    [Console]::Out.Flush()
    [Console]::Error.Flush()
    try {
        $Host.SetShouldExit([int]$exitCode)
    }
    catch {
        [System.Environment]::Exit([int]$exitCode)
    }
}
