param(
    [Parameter(Mandatory)][ValidateSet('allow', 'block', 'secret', 'stdin', 'timeout', 'child')][string]$Action,
    [string]$StateRoot = ''
)

switch ($Action) {
    'allow' { Write-Output '{"decision":"allow"}'; exit 0 }
    'block' { Write-Output '{"decision":"block"}'; exit 2 }
    'secret' { Write-Output $env:DC_E2E_TEST_SECRET; exit 0 }
    'stdin' { Write-Output ([Console]::In.ReadToEnd()); exit 0 }
    'timeout' {
        $child = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-File', $PSCommandPath, '-Action', 'child', '-StateRoot', $StateRoot) -PassThru -WindowStyle Hidden
        [IO.File]::WriteAllText((Join-Path $StateRoot 'child.pid'), [string]$child.Id)
        Start-Sleep -Seconds 30
        exit 0
    }
    'child' { Start-Sleep -Seconds 30; exit 0 }
}
