param(
    [Parameter(Mandatory)][ValidateSet('allow', 'block', 'secret', 'stdin', 'timeout', 'drain-timeout', 'child', 'hold')][string]$Action,
    [string]$StateRoot = '',
    # Name of an event the caller created; set once the timeout child exists,
    # so the caller can order its timeout after that marker.
    [string]$ReadyEvent = ''
)

switch ($Action) {
    'allow' { Write-Output '{"decision":"allow"}'; exit 0 }
    'block' { Write-Output '{"decision":"block"}'; exit 2 }
    'secret' { Write-Output $env:DC_E2E_TEST_SECRET; exit 0 }
    'stdin' { Write-Output ([Console]::In.ReadToEnd()); exit 0 }
    'timeout' {
        # Root and child both run until killed, so only the caller's timeout
        # or TerminateTree can end them.
        $child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-File', $PSCommandPath, '-Action', 'hold', '-StateRoot', $StateRoot) -PassThru -WindowStyle Hidden
        [IO.File]::WriteAllText((Join-Path $StateRoot 'child.pid'), [string]$child.Id)
        if ($ReadyEvent) {
            $ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEvent)
            [void]$ready.Set()
            $ready.Dispose()
        }
        [Threading.Thread]::Sleep(-1)
    }
    'drain-timeout' {
        # UseShellExecute=false with no child redirection deliberately inherits
        # this process's redirected stdout/stderr handles. The parent exits at
        # once, so a wrapper that only bounds WaitForExit will hang in its
        # subsequent ReadToEndAsync drain until this child exits.
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Get-Process -Id $PID).Path
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        foreach ($argument in @('-NoProfile', '-File', $PSCommandPath, '-Action', 'hold', '-StateRoot', $StateRoot)) {
            [void]$start.ArgumentList.Add($argument)
        }
        $child = [Diagnostics.Process]::Start($start)
        [IO.File]::WriteAllText((Join-Path $StateRoot 'drain-child.pid'), [string]$child.Id)
        $child.Dispose()
        exit 0
    }
    'child' { Start-Sleep -Seconds 30; exit 0 }
    'hold' { [Threading.Thread]::Sleep(-1) }
}
