# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Advisory packaged OmniGent native-Windows degraded-mode contract.

.DESCRIPTION
    Installs the official OmniGent 0.7.0 client with its documented uv-tool
    path, installs the packaged DefenseClaw distribution, registers the
    in-process policy, starts the real OmniGent server, and verifies live,
    fail-closed, and teardown behavior. No WSL, shell compatibility layer,
    terminal wrapper, container, or sandbox-parity assertion is involved.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$StateRoot,
    [string]$UvPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or [Environment]::Is64BitOperatingSystem -ne $true) {
    throw 'OmniGent native contract requires Windows x64'
}

$state = [IO.Path]::GetFullPath($StateRoot)
$artifacts = [IO.Path]::GetFullPath($ArtifactRoot)
if (-not (Test-Path -LiteralPath $artifacts -PathType Container)) {
    throw "packaged artifact directory is missing: $artifacts"
}
[IO.Directory]::CreateDirectory($state) | Out-Null

$env:OMNIGENT_CONFIG_HOME = Join-Path $state 'omnigent-config'
$env:OMNIGENT_DATA_DIR = Join-Path $state 'omnigent-data'
$env:UV_TOOL_DIR = Join-Path $state 'uv-tools'
$env:UV_TOOL_BIN_DIR = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin'
$env:UV_CACHE_DIR = Join-Path $state 'uv-cache'
$env:OMNIGENT_ACCOUNTS_AUTO_OPEN = '0'
$env:PATH = $env:UV_TOOL_BIN_DIR + ';' + $env:PATH
foreach ($directory in @(
    $env:OMNIGENT_CONFIG_HOME,
    $env:OMNIGENT_DATA_DIR,
    $env:UV_TOOL_DIR,
    $env:UV_TOOL_BIN_DIR
)) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [ValidateRange(1, 1800)][int]$TimeoutSeconds = 120,
        [int[]]$AcceptedExitCodes = @(0)
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [IO.Path]::GetFullPath($FilePath)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        if (-not $process.Start()) {
            throw "native process did not start: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $remaining = [Math]::Max(
            1,
            [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        )
        if (-not $process.WaitForExit($remaining)) {
            $process.Kill($true)
            if (-not $process.WaitForExit(10000)) {
                throw "native process tree did not exit within 10 seconds after termination: $FilePath"
            }
            throw "native process timed out after $TimeoutSeconds seconds: $FilePath"
        }
        $remaining = [Math]::Max(
            1,
            [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
        )
        $outputTasks = [Threading.Tasks.Task]::WhenAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
        )
        if (-not $outputTasks.Wait($remaining)) {
            throw "native process output did not close before the $TimeoutSeconds second deadline: $FilePath"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($stderr) {
            [Console]::Error.Write($stderr)
        }
        if ($process.ExitCode -notin $AcceptedExitCodes) {
            throw "native process failed with exit code $($process.ExitCode)`: $FilePath"
        }
        return $stdout
    } finally {
        $process.Dispose()
    }
}

function Invoke-LoopbackJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][Uri]$Uri,
        [object]$Body = $null
    )
    if ($Uri.Scheme -cne 'http' -or $Uri.Host -notin @('127.0.0.1', 'localhost')) {
        throw "policy probe refused non-loopback URI: $Uri"
    }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $request = [Net.Http.HttpRequestMessage]::new(
        [Net.Http.HttpMethod]::new($Method),
        $Uri
    )
    try {
        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Depth 12 -Compress
            $request.Content = [Net.Http.StringContent]::new(
                $json,
                [Text.Encoding]::UTF8,
                'application/json'
            )
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) {
                throw "loopback policy request failed with HTTP $([int]$response.StatusCode)"
            }
            if ([string]::IsNullOrWhiteSpace($responseBody)) {
                return $null
            }
            return $responseBody | ConvertFrom-Json
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
        $client.Dispose()
    }
}

$uv = if ([string]::IsNullOrWhiteSpace($UvPath)) {
    (Get-Command uv.exe -CommandType Application -ErrorAction Stop).Source
} else {
    (Get-Item -LiteralPath $UvPath -ErrorAction Stop).FullName
}
$uvDirectory = Split-Path -Parent $uv
$env:PATH = $uvDirectory + ';' + $env:PATH
Invoke-NativeChecked $uv @(
    'tool', 'install', '--python', '3.12', '--force', 'omnigent==0.7.0'
) -TimeoutSeconds 600
$omnigent = Join-Path $env:UV_TOOL_BIN_DIR 'omnigent.exe'
$omnigentPython = Join-Path $env:UV_TOOL_DIR 'omnigent\Scripts\python.exe'
foreach ($required in @($omnigent, $omnigentPython)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "official OmniGent uv-tool installation is incomplete: $required"
    }
}
$version = (Invoke-NativeChecked $omnigent @('--version') -TimeoutSeconds 30).Trim()
if ($version -notmatch '\b0\.7\.0\b') {
    throw "official OmniGent version probe was not 0.7.0: $version"
}

$defenseclawData = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.defenseclaw'
$nativeInstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\DefenseClaw'
if ((Test-Path -LiteralPath $nativeInstallRoot) -or
    (Test-Path -LiteralPath (Join-Path $defenseclawData 'active_connector.json'))) {
    throw 'OmniGent advisory Setup lifecycle requires a clean disposable Windows user'
}
$config = Join-Path $env:OMNIGENT_CONFIG_HOME 'config.yaml'
$env:OMNIGENT_CONFIG = $config
$module = Join-Path $defenseclawData 'hooks\defenseclaw_omnigent_policy.py'
$pth = Join-Path $env:UV_TOOL_DIR 'omnigent\Lib\site-packages\defenseclaw_omnigent.pth'
foreach ($parent in @(
    (Split-Path -Parent $config),
    (Split-Path -Parent $module),
    (Split-Path -Parent $pth)
)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($config, "policy_modules: []`npolicies: {}`n", $utf8)
[IO.File]::WriteAllText($module, "# operator-owned preexisting module`n", $utf8)
[IO.File]::WriteAllText($pth, "C:\operator-owned-python-path`n", $utf8)
$originalHashes = @{}
foreach ($path in @($config, $module, $pth)) {
    $originalHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

$setupPackage = Join-Path $artifacts 'DefenseClawSetup-x64.exe'
if (-not (Test-Path -LiteralPath $setupPackage -PathType Leaf)) {
    throw "packaged DefenseClaw Setup is missing: $setupPackage"
}
Invoke-NativeChecked $setupPackage @(
    '/quiet', '/norestart', 'INSTALLSCOPE=user', 'CONNECTOR=omnigent',
    'MODE=action', 'STARTGATEWAY=1'
) -TimeoutSeconds 600

$defenseclaw = Join-Path $nativeInstallRoot 'bin\defenseclaw.exe'
$gateway = Join-Path $nativeInstallRoot 'bin\defenseclaw-gateway.exe'
$installStatePath = Join-Path $nativeInstallRoot 'installer\install-state.json'
foreach ($required in @($defenseclaw, $gateway, $installStatePath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "packaged DefenseClaw installation is incomplete: $required"
    }
}
$installState = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
if ([string]$installState.connector -cne 'omnigent' -or
    [IO.Path]::GetFullPath([string]$installState.omnigent_config_home) -cne
        [IO.Path]::GetFullPath($env:OMNIGENT_CONFIG_HOME)) {
    throw 'native Setup did not persist the OmniGent connector and exact config-home custody'
}
$setup = [string]$installState.maintenance_path
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "native Setup maintenance executable is missing: $setup"
}

Invoke-NativeChecked $defenseclaw @(
    'setup', 'omnigent', '--yes', '--mode', 'action',
    '--fail-mode', 'closed', '--restart'
)

foreach ($required in @($config, $module, $pth)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "OmniGent policy setup did not create required state: $required"
    }
}
Invoke-NativeChecked $setup @('/repair', '/quiet', '/norestart')
Invoke-NativeChecked $setup @('/upgrade', '/quiet', '/norestart')
$preservedState = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
if ([string]$preservedState.connector -cne 'omnigent' -or
    [IO.Path]::GetFullPath([string]$preservedState.omnigent_config_home) -cne
        [IO.Path]::GetFullPath($env:OMNIGENT_CONFIG_HOME)) {
    throw 'native Setup repair/upgrade did not preserve the OmniGent custody ledger'
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$agent = Join-Path $state 'defenseclaw-policy-probe.yaml'
[IO.File]::WriteAllText(
    $agent,
    "name: defenseclaw-policy-probe`ndescription: Unauthenticated advisory policy-path fixture.`nexecutor:`n  model: gpt-4o`nprompt: Exercise the configured server policy path without invoking a model.`n",
    $utf8
)
$serverOut = Join-Path $state 'omnigent-server.stdout.log'
$serverErr = Join-Path $state 'omnigent-server.stderr.log'
$server = Start-Process -FilePath $omnigent -ArgumentList @(
    'server', '--host', '127.0.0.1', '--port', [string]$port,
    '--config', $config, '--agent', $agent, '--no-open'
) -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($server.HasExited) {
            throw "official OmniGent server exited before readiness with code $($server.ExitCode)"
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $port)
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        } finally {
            $client.Dispose()
        }
    }
    if (-not $ready) {
        throw 'official OmniGent server did not bind its native loopback listener'
    }

    $baseUri = "http://127.0.0.1:$port"
    $agents = Invoke-LoopbackJson -Method GET -Uri "$baseUri/v1/agents?limit=1000"
    $probeAgent = @($agents.data | Where-Object { [string]$_.name -ceq 'defenseclaw-policy-probe' })
    if ($probeAgent.Count -cne 1 -or [string]::IsNullOrWhiteSpace([string]$probeAgent[0].id)) {
        throw 'official OmniGent server did not register the advisory policy-path agent'
    }
    $session = Invoke-LoopbackJson -Method POST -Uri "$baseUri/v1/sessions" -Body @{
        agent_id = [string]$probeAgent[0].id
        initial_items = @()
        title = 'DefenseClaw advisory policy path'
    }
    if ([string]::IsNullOrWhiteSpace([string]$session.id)) {
        throw 'official OmniGent server did not create the advisory policy-path session'
    }
    $policyRequest = @{
        event = @{
            type = 'PHASE_TOOL_RESULT'
            target = 'read_file'
            data = @{
                result = @{ text = 'deterministic advisory result' }
            }
            context = @{ harness = 'windows-native-advisory' }
            request_data = @{
                name = 'read_file'
                arguments = @{ path = 'README.md' }
            }
        }
    }
    $policyUri = "$baseUri/v1/sessions/$([Uri]::EscapeDataString([string]$session.id))/policies/evaluate"
    $liveVerdict = Invoke-LoopbackJson -Method POST -Uri $policyUri -Body $policyRequest
    if ([string]$liveVerdict.result -notin @(
        'POLICY_ACTION_ALLOW',
        'POLICY_ACTION_ASK',
        'POLICY_ACTION_DENY'
    )) {
        throw 'official OmniGent server policy endpoint returned no recognized policy action'
    }

    Invoke-NativeChecked $gateway @('stop')
    $closedVerdict = Invoke-LoopbackJson -Method POST -Uri $policyUri -Body $policyRequest
    if ([string]$closedVerdict.result -cne 'POLICY_ACTION_DENY') {
        throw 'official OmniGent server policy path did not fail closed after the gateway stopped'
    }

} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        $server.WaitForExit(10000)
    }
    $server.Dispose()
}

Invoke-NativeChecked $setup @('/uninstall', '/quiet', '/norestart') `
    -TimeoutSeconds 300 -AcceptedExitCodes @(0, 3010)
foreach ($path in @($config, $module, $pth)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "native Setup uninstall did not restore the preexisting OmniGent file: $path"
    }
    $restoredHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($restoredHash -cne $originalHashes[$path]) {
        throw "native Setup uninstall did not restore exact OmniGent bytes: $path"
    }
}

Write-Host 'OmniGent 0.7.0 advisory native-Windows degraded checks passed; this is not certification evidence.'
