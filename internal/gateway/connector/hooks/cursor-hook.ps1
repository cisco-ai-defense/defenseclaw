# defenseclaw-managed-hook v8
# Cursor on Windows delivers command-hook input through the PowerShell object
# pipeline. This adapter materializes exact UTF-8 JSON bytes for the
# consoleless native launcher.
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
    $failClosed = {{if eq .FailMode "closed"}}$true{{else}}$false{{end}}
    $payload = $parts -join [Environment]::NewLine
    $eventName = ""
    try {
        $parsedPayload = $payload | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $parsedPayload.hook_event_name) {
            $eventName = [string]$parsedPayload.hook_event_name
        }
    }
    catch {
        # The native launcher owns malformed-input handling. If the adapter
        # itself fails first, an unknown event can emit only Cursor's exact
        # no-fields response object.
    }
    function Get-CursorFallbackJson {
        param(
            [string]$EventName,
            [bool]$Deny
        )
        if (-not $Deny) {
            switch ($EventName) {
                "beforeSubmitPrompt" { return '{"continue":true}' }
                { $_ -in @(
                    "preToolUse",
                    "subagentStart",
                    "beforeShellExecution",
                    "beforeMCPExecution",
                    "beforeReadFile",
                    "beforeTabFileRead"
                ) } { return '{"permission":"allow"}' }
                default { return '{}' }
            }
        }
        switch ($EventName) {
            "beforeSubmitPrompt" {
                return '{"continue":false,"user_message":"DefenseClaw hook unavailable"}'
            }
            { $_ -in @("preToolUse", "beforeShellExecution", "beforeMCPExecution") } {
                return '{"permission":"deny","user_message":"DefenseClaw hook unavailable","agent_message":"DefenseClaw hook unavailable"}'
            }
            { $_ -in @("subagentStart", "beforeReadFile") } {
                return '{"permission":"deny","user_message":"DefenseClaw hook unavailable"}'
            }
            "beforeTabFileRead" { return '{"permission":"deny"}' }
            default { return '{}' }
        }
    }
    $payloadPath = Join-Path $PSScriptRoot (".cursor-input-" + [Guid]::NewGuid().ToString("N") + ".json")
    $exitCode = 2
    $responseWritten = $false
    try {
        if (-not (Test-Path -LiteralPath $hook -PathType Leaf)) {
            throw "DefenseClaw hook launcher is missing: $hook"
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $payloadBytes = $utf8NoBom.GetBytes($payload)
        $stream = [IO.File]::Open(
            $payloadPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($payloadBytes, 0, $payloadBytes.Length)
        }
        finally {
            $stream.Dispose()
        }
        # Windows PowerShell does not wait for GUI-subsystem executables when
        # they are invoked with `&`, and it does not reliably connect their
        # standard handles. defenseclaw-hook.exe intentionally uses that
        # subsystem to avoid popup consoles, so launch it explicitly with
        # redirected handles and wait for the verdict before returning.
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $hook
        $startInfo.Arguments = 'hook --connector cursor --input-file "' + $payloadPath + '"'
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        try {
            if (-not $process.Start()) {
                throw "DefenseClaw hook launcher did not start"
            }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $timeoutMs = {{.HookTimeoutMS}}
            if (-not $process.WaitForExit($timeoutMs)) {
                try {
                    $process.Kill()
                    [void]$process.WaitForExit(5000)
                }
                catch {
                    [Console]::Error.WriteLine(
                        "defenseclaw: could not stop timed-out Cursor hook launcher: " + $_.Exception.Message
                    )
                }
                throw "DefenseClaw hook launcher timed out after ${timeoutMs}ms"
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
            $process.Dispose()
        }
    }
    catch {
        [Console]::Error.WriteLine("defenseclaw: Cursor hook adapter failed: " + $_.Exception.Message)
        if (-not $responseWritten) {
            [Console]::Out.Write((Get-CursorFallbackJson -EventName $eventName -Deny $failClosed))
        }
        $exitCode = if ($failClosed) { 2 } else { 0 }
    }
    finally {
        try {
            if (Test-Path -LiteralPath $payloadPath) {
                Remove-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
            }
        }
        catch {
            [Console]::Error.WriteLine(
                "defenseclaw: could not remove temporary Cursor payload: " + $_.Exception.Message
            )
        }
    }
    # Cursor invokes this adapter from a PowerShell pipeline. `exit N` inside
    # that nested pipeline is normalized by Windows PowerShell to process exit
    # code 1. Set the host exit code explicitly so Cursor receives the
    # documented exit-2 deny signal.
    $host.SetShouldExit($exitCode)
}
