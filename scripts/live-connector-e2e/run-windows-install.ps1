# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Windows connector contract and install lifecycle on an install.ps1 install.
.DESCRIPTION
    The required Windows connector coverage (windows-native.yml
    connector-contract and install-lifecycle). It installs release-shaped
    assets of this checkout (scripts/build-release-assets.sh ... windows/amd64)
    with install.ps1 -Local into a throwaway profile below -StateRoot, the way
    a user installs DefenseClaw on Windows, and never touches the real one.

      -Operation contract -Connector <name>
        1. observe: `defenseclaw setup <connector> --mode observe`, then the
           Windows checks of what setup wrote (the exact hook commands and
           adapters, the plugin contracts, the Doctor row), then teardown and
           the vendor config restored byte for byte;
        2. action: contract-smoke.sh (Git Bash) feeds the golden payloads to
           the installed hook entrypoint (allow exits 0, block exits 2 or
           returns a deny), checks the gateway saw them and that teardown
           restores the vendor config. OpenCode is a plugin, so its golden
           commands go through the installed plugin instead
           (assert-opencode-plugin.mjs);
        3. the canonical observability v8 records of the run (audit
           projection and the JSONL destination) are valid.
      -Operation lifecycle
        install, version, status, doctor, the TUI at 80x24, a repair re-run of
        install.ps1, then `defenseclaw uninstall --all --binaries --yes` and
        nothing of the install left (files, processes, Run value, Path entry).

    No vendor agent is installed or run: the hook contract is the installed
    DefenseClaw entrypoint. A green cell is not connector certification.
#>
[CmdletBinding()]
param(
    [ValidateSet('contract', 'lifecycle')][string]$Operation = 'contract',
    [ValidateSet('codex', 'claudecode', 'amp', 'copilot', 'cursor', 'devin', 'hermes', 'antigravity', 'opencode')]
    [string]$Connector = 'codex',
    [Parameter(Mandatory = $true)][string]$Assets,
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [int]$CommandTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Assets = (Resolve-Path -LiteralPath $Assets).ProviderPath
New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
# Real path: DefenseClaw refuses a data dir reached through a junction.
$StateRoot = (Get-Item -LiteralPath $StateRoot).FullName
$script:Results = Join-Path $StateRoot 'results.jsonl'
$script:Failures = [Collections.Generic.List[string]]::new()
$WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Write-Result([string]$EventName, [ValidateSet('pass', 'fail', 'skip')][string]$Status, [string]$Detail = '') {
    $record = [ordered]@{ connector = $(if ($Operation -eq 'lifecycle') { 'lifecycle' } else { $Connector }); os = 'windows'; event = $EventName; status = $Status; detail = $Detail }
    Add-Content -LiteralPath $script:Results -Value ($record | ConvertTo-Json -Compress) -Encoding utf8
    Write-Host ("[windows-install] [{0}] {1} {2}" -f $Status.ToUpperInvariant(), $EventName, $Detail)
    if ($Status -eq 'fail') { $script:Failures.Add("${EventName}: $Detail") }
}

# Invoke-Tool FILE ARGS [-Allowed codes]: run a native program, return its exit code and output.
function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [string[]]$Arguments = @(),
        [int[]]$Allowed = @(0),
        [int]$Timeout = $CommandTimeoutSeconds,
        [string]$StandardInput = $null
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $File
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $null -ne $StandardInput
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($null -ne $StandardInput) {
        $process.StandardInput.Write($StandardInput)
        $process.StandardInput.Close()
    }
    if (-not $process.WaitForExit($Timeout * 1000)) {
        try { $process.Kill($true) } catch { Write-Verbose "kill: $($_.Exception.Message)" }
        throw "$([IO.Path]::GetFileName($File)) $($Arguments -join ' ') did not finish within $Timeout s"
    }
    $process.WaitForExit()
    $result = [pscustomobject]@{ ExitCode = $process.ExitCode; StdOut = $stdout.Result; StdErr = $stderr.Result }
    if ($result.ExitCode -notin $Allowed) {
        $tail = (($result.StdOut + "`n" + $result.StdErr).Trim() -split "`r?`n" | Select-Object -Last 40) -join "`n"
        throw "$([IO.Path]::GetFileName($File)) $($Arguments -join ' ') exited $($result.ExitCode):`n$tail"
    }
    return $result
}

# -- Throwaway profile and install ---------------------------------------------

function Enter-Profile {
    $script:ProfileHome = Join-Path $StateRoot 'home'
    if (Test-Path -LiteralPath $script:ProfileHome) { throw "profile $script:ProfileHome already exists; use a new -StateRoot" }
    # Laid out like a real profile: .NET resolves the known folders from
    # USERPROFILE and answers "" when they are missing.
    foreach ($dir in 'AppData\Local', 'AppData\Roaming', 'AppData\Local\Temp') {
        New-Item -ItemType Directory -Force -Path (Join-Path $script:ProfileHome $dir) | Out-Null
    }
    $env:USERPROFILE = $script:ProfileHome
    $env:HOME = $script:ProfileHome
    $env:LOCALAPPDATA = Join-Path $script:ProfileHome 'AppData\Local'
    $env:APPDATA = Join-Path $script:ProfileHome 'AppData\Roaming'
    $env:TEMP = Join-Path $script:ProfileHome 'AppData\Local\Temp'
    $env:TMP = $env:TEMP
    $env:TMPDIR = $env:TEMP
    foreach ($name in @(
        'DEFENSECLAW_HOME', 'DEFENSECLAW_CONFIG', 'DEFENSECLAW_GATEWAY_ADDR', 'DEFENSECLAW_UPGRADE_FRESH_PROCESS',
        'DEFENSECLAW_UPGRADE_LOCAL_DIR', 'DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT', 'CODEX_HOME', 'CLAUDE_CONFIG_DIR',
        'COPILOT_HOME', 'DEFENSECLAW_CURSOR_CONFIG_HOME', 'DEFENSECLAW_DEVIN_CONFIG_HOME', 'OPENCODE_CONFIG_DIR', 'HERMES_HOME'
    )) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    $env:DEFENSECLAW_NO_UPDATE_CHECK = '1'
    $script:Bin = Join-Path $script:ProfileHome '.local\bin'
    $script:DcHome = Join-Path $script:ProfileHome '.defenseclaw'
    $script:VenvPython = Join-Path $script:DcHome '.venv\Scripts\python.exe'
    # The install's commands first; the runner's tools (Git Bash, jq, node, uv) after them.
    $env:Path = "$script:Bin;$env:Path"
}

function Install-DefenseClaw {
    $installer = Join-Path $Assets 'install.ps1'
    $started = Get-Date
    # Windows PowerShell 5.1 runs the installer, as for users.
    $result = Invoke-Tool $WindowsPowerShell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installer, '-Local', $Assets, '-Yes', '-NoPersistPath') -Allowed @(0, 1) -Timeout 900
    if ($result.ExitCode -ne 0) {
        throw "install.ps1 -Local exited $($result.ExitCode):`n$((($result.StdOut + $result.StdErr) -split "`r?`n" | Select-Object -Last 40) -join "`n")"
    }
    foreach ($name in 'defenseclaw.exe', 'defenseclaw.cmd', 'defenseclaw-gateway.exe', 'defenseclaw-hook.exe', 'defenseclaw-acp.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $script:Bin $name) -PathType Leaf)) { throw "install.ps1 did not install $name in $script:Bin" }
    }
    Write-Result install pass ("install.ps1 -Local {0} in {1:n0}s" -f $Assets, ((Get-Date) - $started).TotalSeconds)
}

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

# Initialize-DefenseClaw: config with no connector, the gateway on a free
# loopback port, and the contract's own observability JSONL destination.
function Initialize-DefenseClaw {
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw.exe') @(
        'init', '--non-interactive', '--yes', '--no-start-gateway', '--no-verify', '--skip-install', '--connector', 'none'
    ) | Out-Null
    $config = Join-Path $script:DcHome 'config.yaml'
    $script:ContractJsonl = Join-Path $script:DcHome 'gateway.jsonl'
    Invoke-Tool $script:VenvPython @(
        (Join-Path $WorkspaceRoot 'scripts\prepare-windows-contract-v8.py'),
        '--config', $config, '--data-dir', $script:DcHome, '--jsonl-path', $script:ContractJsonl
    ) | Out-Null
    $script:Port = Get-FreePort
    Invoke-Tool $script:VenvPython @('-I', '-c', @'
import sys, yaml
path, port = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
config.setdefault("gateway", {})["api_port"] = port
with open(path, "w", encoding="utf-8") as stream:
    yaml.safe_dump(config, stream, sort_keys=False)
'@, $config, [string]$script:Port) | Out-Null
    Write-Result init pass "config v8 with the contract JSONL destination; gateway on 127.0.0.1:$script:Port"
}

function Wait-Gateway([int]$Timeout = 90) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
    do {
        $status = Invoke-Tool (Join-Path $script:Bin 'defenseclaw-gateway.exe') @('status') -Allowed @(0, 1, 2, 3) -Timeout 30
        if ($status.ExitCode -eq 0) { return }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "gateway did not report healthy within $Timeout s: $($status.StdOut) $($status.StdErr)"
}

function Stop-Gateway {
    $gateway = Join-Path $script:Bin 'defenseclaw-gateway.exe'
    if (Test-Path -LiteralPath $gateway) { Invoke-Tool $gateway @('stop') -Allowed @(0, 1, 2, 3) -Timeout 60 | Out-Null }
}

# -- Where each connector's vendor config lives on Windows ----------------------

function Get-ConnectorConfigPath([string]$Name) {
    $relative = switch ($Name) {
        'codex' { '.codex\config.toml' }
        'claudecode' { '.claude\settings.json' }
        'amp' { '.config\amp\plugins\defenseclaw.ts' }
        'copilot' { '.copilot\hooks\defenseclaw.json' }
        'cursor' { '.cursor\hooks.json' }
        'devin' { 'AppData\Roaming\devin\config.json' }
        'hermes' { 'AppData\Local\hermes\config.yaml' }
        'antigravity' { '.gemini\config\hooks.json' }
        'opencode' { '.config\opencode\plugins\defenseclaw.js' }
    }
    return Join-Path $script:ProfileHome $relative
}

function Get-SetupSubcommand([string]$Name) { if ($Name -eq 'claudecode') { return 'claude-code' } return $Name }

function Get-DoctorLabel([string]$Name) {
    switch ($Name) {
        'codex' { 'Codex hooks' }
        'claudecode' { 'Claude Code hooks' }
        'amp' { 'Amp policy plugin' }
        'copilot' { 'Copilot hooks' }
        'cursor' { 'Cursor hooks' }
        'devin' { 'Devin hooks' }
        'hermes' { 'Hermes hooks' }
        'antigravity' { 'Antigravity hooks' }
        'opencode' { 'OpenCode hooks' }
    }
}

function Get-FileState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'missing' }
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# -- The Windows checks of what setup wrote (ported from the per-user Setup lane) --

function Test-ObsoleteWindowsHookGuidance([string]$Text) {
    # A shell script name, not a member name such as client.tui.showToast.
    if ([regex]::IsMatch($Text, [string]::Concat('(?i)\.', 's', 'h', '\b'))) { return $true }
    foreach ($term in @([string]::Concat('b', 'a', 's', 'h'), [string]::Concat('w', 's', 'l'), [string]::Concat('c', 'h', 'm', 'o', 'd'))) {
        if ($Text.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Remove-PluginSourceComments([string]$Source) {
    return (@([regex]::Split($Source, '\r?\n') | Where-Object { $_ -notmatch '^\s*//' }) -join "`n")
}

# The direct Codex hook command: <system>\cmd.exe /d /v:off /c "<launcher>" <arguments>.
function Get-DirectHookCommand([string]$Command) {
    $match = [regex]::Match(
        $Command,
        '^(?<cmd>[A-Za-z]:\\[A-Za-z0-9\\._~-]+) /d /v:off /c "(?<file>[A-Za-z]:\\[\p{L}\p{Nd} \\._~-]+)"(?<arguments>(?: [A-Za-z0-9._-]+)+)$'
    )
    if (-not $match.Success) { return $null }
    if (-not [string]::Equals($match.Groups['cmd'].Value, (Join-Path ([Environment]::SystemDirectory) 'cmd.exe'), [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    return [pscustomobject]@{ File = $match.Groups['file'].Value; Arguments = [string[]]@($match.Groups['arguments'].Value.Substring(1).Split(' ')) }
}

# The awaited PowerShell bridge: Process.Start keeps the CreateProcess handle so
# a launcher that exits at once still returns its status, and Constrained
# Language mode falls back to the call operator.
function Get-AwaitedHookBridge([string]$Script) {
    $pattern = '^\$ErrorActionPreference=''Stop''; \$env:NoDefaultCurrentDirectoryInExePath=''1''; ' +
        'if \(\$ExecutionContext\.SessionState\.LanguageMode -ne ''FullLanguage''\) \{ \$ErrorActionPreference=''Continue''; ' +
        '& (?<file>''(?:''''|[^''])+'')(?<quoted>(?: ''[^'' ]+'')+) \| Microsoft\.PowerShell\.Core\\Out-Host; ' +
        'if \(\$null -eq \$LASTEXITCODE\) \{ exit 1 \}; exit \$LASTEXITCODE \}; ' +
        '\$hookStart=\[System\.Diagnostics\.ProcessStartInfo\]::new\(\k<file>,''(?<arguments>[^'' ]+(?: [^'' ]+)*)''\); ' +
        '\$hookStart\.UseShellExecute=\$false; \$hookStart\.RedirectStandardError=\$true; ' +
        '\$hookProcess=\[System\.Diagnostics\.Process\]::Start\(\$hookStart\); ' +
        '\$hookProcess\.StandardError\.BaseStream\.CopyTo\(\[Console\]::OpenStandardError\(\)\); ' +
        '\$hookProcess\.WaitForExit\(\); exit \$hookProcess\.ExitCode$'
    $match = [regex]::Match($Script, $pattern)
    if (-not $match.Success) { return $null }
    $arguments = @($match.Groups['arguments'].Value.Split(' '))
    if ((@($arguments | ForEach-Object { " '" + $_ + "'" }) -join '') -cne $match.Groups['quoted'].Value) { return $null }
    $fileLiteral = $match.Groups['file'].Value
    return [pscustomobject]@{ File = $fileLiteral.Substring(1, $fileLiteral.Length - 2).Replace("''", "'"); Arguments = $arguments }
}

function Get-EncodedHookBridge([string]$Command, [string]$Context) {
    $encoded = [regex]::Match($Command, '(?i)(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)(?:\s|$)')
    if (-not $encoded.Success) { throw "$Context uses neither the direct cmd.exe command nor the EncodedCommand form" }
    try { $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded.Groups[1].Value)) }
    catch { throw "$Context has invalid encoded content: $($_.Exception.Message)" }
    return Get-AwaitedHookBridge $script
}

function Assert-InstalledHook([string]$File, [string]$Context) {
    if (-not [string]::Equals([IO.Path]::GetFullPath($File), (Join-Path $script:Bin 'defenseclaw-hook.exe'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Context runs $File, not the installed $(Join-Path $script:Bin 'defenseclaw-hook.exe')"
    }
}

function Assert-CodexRegistration([string]$Config) {
    $commands = @([regex]::Matches($Config, '(?m)^\s*command_windows\s*=\s*(?<literal>"(?:\\.|[^"\\])*"|''[^'']*'')\s*$'))
    if ($commands.Count -eq 0) { throw 'Codex config has no command_windows hook override' }
    $contractEvents = @{
        'codex-hooks-v1' = @('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'Stop')
        'codex-hooks-v2' = @('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'PreCompact', 'PostCompact', 'Stop')
        'codex-hooks-v3' = @('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'SubagentStart', 'SubagentStop', 'PreCompact', 'PostCompact', 'Stop')
        'codex-hooks-v3-generic' = @('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'SubagentStart', 'SubagentStop', 'PreCompact', 'PostCompact', 'Stop')
        'codex-hooks-v4' = @('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'SubagentStart', 'SubagentStop', 'PreCompact', 'PostCompact', 'Stop', 'SessionEnd')
    }
    $bound = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $commands) {
        $literal = $entry.Groups['literal'].Value
        $command = if ($literal.StartsWith("'", [StringComparison]::Ordinal)) { $literal.Substring(1, $literal.Length - 2) } else { $literal | ConvertFrom-Json }
        $bridge = Get-DirectHookCommand $command
        if ($null -eq $bridge) { $bridge = Get-EncodedHookBridge $command 'Codex command_windows' }
        $arguments = @(if ($null -ne $bridge) { $bridge.Arguments })
        $hookEvent = if ($arguments.Count -eq 7) { $arguments[4] } else { '' }
        $contract = if ($arguments.Count -eq 7) { $arguments[6] } else { '' }
        if ($null -eq $bridge -or $arguments.Count -ne 7 -or
            ($arguments -join "`0") -cne (@('hook', '--connector', 'codex', '--event', $hookEvent, '--hook-contract', $contract) -join "`0") -or
            -not $contractEvents.ContainsKey($contract) -or $hookEvent -cnotin @($contractEvents[$contract])) {
            throw "Codex command_windows is not the exact synchronous native hook command: $command"
        }
        Assert-InstalledHook $bridge.File "Codex $hookEvent"
        [void]$bound.Add($hookEvent)
    }
    if (-not $bound.Contains('PreToolUse')) { throw 'Codex registration has no PreToolUse hook' }
    return "$($bound.Count) events bound to the installed defenseclaw-hook.exe"
}

function Assert-CopilotRegistration([string]$Config) {
    $document = $Config | ConvertFrom-Json
    if ($document.version -ne 1 -or $null -eq $document.hooks) { throw 'Copilot hooks are not a version-1 hook document' }
    $events = @(
        'sessionStart', 'sessionEnd', 'userPromptSubmitted', 'userPromptTransformed', 'preToolUse', 'postToolUse',
        'postToolUseFailure', 'permissionRequest', 'agentStop', 'subagentStart', 'subagentStop', 'errorOccurred',
        'preCompact', 'notification'
    )
    if ((@($document.hooks.PSObject.Properties.Name | Sort-Object) -join "`0") -cne (($events | Sort-Object) -join "`0")) {
        throw 'Copilot registration does not contain the exact 14-event hook set'
    }
    $adapters = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pattern = '(?i)^&\s+''(?<adapter>(?:''''|[^''])+copilot-hook\.ps1)''\s+-Event\s+''(?<event>[a-zA-Z]+)''$'
    foreach ($hookEvent in $events) {
        $owned = @($document.hooks.PSObject.Properties[$hookEvent].Value | Where-Object { $_.type -ceq 'command' -and [string]$_.powershell -match 'copilot-hook\.ps1' })
        if ($owned.Count -ne 1) { throw "Copilot event $hookEvent has $($owned.Count) DefenseClaw adapter handlers" }
        $entry = $owned[0]
        if ([int]$entry.timeoutSec -ne 30 -or $null -ne $entry.PSObject.Properties['bash'] -or $null -ne $entry.PSObject.Properties['command']) {
            throw "Copilot event $hookEvent has a malformed Windows command entry"
        }
        $command = [string]$entry.powershell
        $match = [regex]::Match($command, $pattern)
        if (-not $match.Success -or $match.Groups['event'].Value -cne $hookEvent -or $command -match '(?i)&\s+&|\$LASTEXITCODE|Start-Process') {
            throw "Copilot event $hookEvent does not use the exact synchronous PowerShell command: $command"
        }
        [void]$adapters.Add($match.Groups['adapter'].Value.Replace("''", "'"))
    }
    if ($adapters.Count -ne 1) { throw 'Copilot registration uses inconsistent adapters' }
    $adapter = @($adapters)[0]
    if (-not [IO.Path]::IsPathFullyQualified($adapter) -or -not (Test-Path -LiteralPath $adapter -PathType Leaf)) { throw "Copilot adapter is missing: $adapter" }
    $text = [IO.File]::ReadAllText($adapter)
    # The byte-stream adapter: UTF-8 stdin without a BOM, a bounded wait, and fail open.
    foreach ($marker in @(
        'defenseclaw-managed-hook v7', 'defenseclaw-hook.exe', '[Console]::In.ReadToEnd()', '$payload[0] -eq [char]0xFEFF',
        'RedirectStandardInput = $true', 'RedirectStandardOutput = $true', 'RedirectStandardError = $true',
        '[Console]::InputEncoding = $utf8NoBom', '[Console]::OutputEncoding = $utf8NoBom', '$timeoutMS = 25000',
        '$process.StandardInput.AutoFlush = $true', '$deadline.Restart()', '$process.StandardInput.Write($payload)',
        'WaitForExit', '[System.Environment]::Exit(0)'
    )) {
        if ($text.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) { throw "Copilot adapter $adapter is missing marker $marker" }
    }
    return "14 events through $adapter"
}

# A per-user Cursor registration sets failClosed in every mode.
function Assert-CursorRegistration([string]$Config) {
    $document = $Config | ConvertFrom-Json
    if ([int]$document.version -ne 1 -or $null -eq $document.hooks) { throw 'Cursor hooks do not use schema version 1' }
    $events = @(
        'sessionStart', 'sessionEnd', 'preToolUse', 'postToolUse', 'postToolUseFailure', 'subagentStart', 'subagentStop',
        'beforeShellExecution', 'beforeMCPExecution', 'afterShellExecution', 'afterMCPExecution', 'beforeReadFile',
        'beforeTabFileRead', 'afterFileEdit', 'afterTabFileEdit', 'beforeSubmitPrompt', 'afterAgentResponse',
        'afterAgentThought', 'stop', 'preCompact', 'workspaceOpen'
    )
    $commands = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($hookEvent in $events) {
        $property = $document.hooks.PSObject.Properties[$hookEvent]
        if ($null -eq $property) { throw "Cursor registration is missing event $hookEvent" }
        $managed = @($property.Value | Where-Object { [string]$_.command -match '(?i)cursor-hook\.ps1' })
        if ($managed.Count -ne 1) { throw "Cursor registration has $($managed.Count) managed handlers for $hookEvent" }
        $entry = $managed[0]
        if ([string]$entry.type -cne 'command' -or [int]$entry.timeout -ne 30 -or -not [bool]$entry.failClosed) {
            throw "Cursor registration has invalid type/timeout/failClosed for $hookEvent"
        }
        [void]$commands.Add([string]$entry.command)
    }
    if ($commands.Count -ne 1) { throw 'Cursor registration uses inconsistent hook commands' }
    $match = [regex]::Match(@($commands)[0], "^& '((?:''|[^'])+)'$")
    if (-not $match.Success) { throw 'Cursor registration does not invoke one native PowerShell adapter' }
    $adapter = $match.Groups[1].Value.Replace("''", "'")
    $expected = Join-Path $script:DcHome 'hooks\cursor-hook.ps1'
    if (-not [string]::Equals($adapter, $expected, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $adapter -PathType Leaf)) {
        throw "Cursor adapter is $adapter, expected $expected"
    }
    $text = [IO.File]::ReadAllText($adapter)
    foreach ($marker in @(
        'defenseclaw-managed-hook v9', 'defenseclaw-hook.exe', 'ProcessStartInfo', 'RedirectStandardInput',
        'RedirectStandardOutput', 'WaitForExit', '"permission":"deny"'
    )) {
        if ($text.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) { throw "Cursor adapter is missing marker $marker" }
    }
    return "$($events.Count) events through $adapter"
}

function Assert-AntigravityRegistration([string]$Config) {
    $document = $Config | ConvertFrom-Json
    $events = @('PreInvocation', 'PreToolUse', 'PostToolUse', 'PostInvocation', 'Stop')
    foreach ($hookEvent in $events) {
        $key = "defenseclaw-antigravity-$($hookEvent.ToLowerInvariant())"
        $outer = $document.PSObject.Properties[$key]
        if ($null -eq $outer) { throw "Antigravity registration is missing $key" }
        $entries = @($outer.Value.PSObject.Properties[$hookEvent].Value)
        if ($entries.Count -ne 1) { throw "Antigravity $hookEvent must contain exactly one entry" }
        if ($hookEvent -in @('PreToolUse', 'PostToolUse')) {
            if ([string]$entries[0].matcher -cne '*') { throw "Antigravity $hookEvent matcher is not '*'" }
            $handlers = @($entries[0].hooks)
        } else {
            if ($null -ne $entries[0].PSObject.Properties['matcher'] -or $null -ne $entries[0].PSObject.Properties['hooks']) {
                throw "Antigravity $hookEvent reused a matcher-group schema"
            }
            $handlers = @($entries[0])
        }
        if ($handlers.Count -ne 1 -or [string]$handlers[0].type -cne 'command' -or [int]$handlers[0].timeout -ne 30) {
            throw "Antigravity $hookEvent handler type/timeout is invalid"
        }
        $command = [string]$handlers[0].command
        if ($command -match "['`"]") { throw "Antigravity $hookEvent visible command contains quote characters" }
        $bridge = Get-EncodedHookBridge $command "Antigravity $hookEvent"
        if ($null -eq $bridge -or (@($bridge.Arguments) -join "`0") -cne (@('hook', '--connector', 'antigravity', '--event', $hookEvent) -join "`0")) {
            throw "Antigravity $hookEvent does not use the exact synchronous event-bound native command"
        }
        Assert-InstalledHook $bridge.File "Antigravity $hookEvent"
    }
    return '5 event-bound EncodedCommand bridges to the installed defenseclaw-hook.exe'
}

function Assert-DevinRegistration([string]$Config) {
    $settings = $Config | ConvertFrom-Json
    $command = [string]@($settings.hooks.PreToolUse)[0].hooks[0].command
    $target = (Join-Path $script:Bin 'defenseclaw-hook.exe').Replace('\', '/')
    $expected = "'" + $target.Replace("'", "'\''") + "' hook --connector devin"
    if (-not [string]::Equals($command, $expected, [StringComparison]::Ordinal)) {
        throw "Devin PreToolUse is not the exact POSIX-quoted direct native command: $command (want $expected)"
    }
    return "PreToolUse runs $expected"
}

function Assert-HermesRegistration([string]$ConfigPath) {
    $code = @'
import json, os, re, shlex, sys
import yaml
expected = {
    "pre_tool_call": ".*", "post_tool_call": ".*", "transform_terminal_output": None, "transform_tool_result": None,
    "transform_llm_output": None, "pre_llm_call": None, "post_llm_call": None, "pre_verify": None,
    "pre_api_request": None, "post_api_request": None, "api_request_error": None, "on_session_start": None,
    "on_session_end": None, "on_session_finalize": None, "on_session_reset": None, "subagent_start": None,
    "subagent_stop": None, "pre_gateway_dispatch": None, "pre_approval_request": None, "post_approval_response": None,
    "kanban_task_claimed": None, "kanban_task_completed": None, "kanban_task_blocked": None,
}
hook = sys.argv[2].replace("\\", "/")
with open(sys.argv[1], encoding="utf-8") as stream:
    document = yaml.safe_load(stream) or {}
if "hooks_auto_accept" in document:
    raise SystemExit("setup introduced operator-owned hooks_auto_accept")
hooks = document.get("hooks")
if not isinstance(hooks, dict) or set(hooks) != set(expected):
    raise SystemExit("Hermes event inventory mismatch: " + json.dumps(sorted(hooks) if isinstance(hooks, dict) else hooks))
commands = set()
for event, matcher in expected.items():
    entries = hooks[event]
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise SystemExit(f"{event} does not have exactly one mapping entry")
    entry = entries[0]
    if type(entry.get("timeout")) is not int or entry["timeout"] != 30:
        raise SystemExit(f"{event} timeout is not exactly 30")
    if entry.get("matcher") != matcher:
        raise SystemExit(f"{event} matcher is not {matcher!r}")
    command = entry.get("command")
    if not isinstance(command, str) or "\\" in command:
        raise SystemExit(f"{event} command is not a forward-slash argv")
    argv = shlex.split(command)
    if (len(argv) != 4 or argv[0].lower() != hook.lower() or argv[1:] != ["hook", "--connector", "hermes"]
            or not command.startswith('"')):
        raise SystemExit(f"{event} command is not the direct absolute installed Hermes argv: {command}")
    commands.add(command)
if len(commands) != 1:
    raise SystemExit("Hermes handlers do not share one command identity")
command = next(iter(commands))
with open(os.path.join(os.path.dirname(sys.argv[1]), "shell-hooks-allowlist.json"), encoding="utf-8") as stream:
    approvals = json.load(stream).get("approvals")
owned = [e for e in approvals or [] if isinstance(e, dict) and e.get("defenseclaw_managed") is True]
if len(owned) != len(expected) or {e.get("event") for e in owned} != set(expected) or any(e.get("command") != command for e in owned):
    raise SystemExit("Hermes allowlist does not hold exactly one scoped owned approval per event")
print(len(expected))
'@
    $probe = Invoke-Tool $script:VenvPython @('-I', '-X', 'utf8', '-c', $code, $ConfigPath, (Join-Path $script:Bin 'defenseclaw-hook.exe')) -Allowed @(0, 1)
    if ($probe.ExitCode -ne 0 -or $probe.StdOut.Trim() -ne '23') { throw "Hermes registration: $($probe.StdOut)$($probe.StdErr)".Trim() }
    return '23 events and 23 scoped allowlist approvals for the installed defenseclaw-hook.exe'
}

# The pattern internal/gateway/connector/amp_plugin_shell_layer_test.go pins.
$AmpShellLayerPattern = '(?i)defenseclaw-hook(?:\.exe|\.cmd)|\bwsl\b|\bbash\b|\bchmod\b'

function Assert-AmpRegistration([string]$Config, [string]$PluginPath) {
    foreach ($marker in @(
        'DefenseClaw Amp policy bridge', '/api/v1/amp/hook', 'amp.on("session.start"', 'amp.on("agent.start"',
        'amp.on("tool.call"', 'amp.on("tool.result"', 'amp.on("agent.end"', 'const DC_FAIL_MODE: string = "closed"',
        'const DC_TIMEOUT_MS = 10000', 'new AbortController()', 'ctx.ui.confirm', 'amp.activeThread.current',
        'isPluginUINotAvailableError', 'action: "reject-and-continue"',
        'const DC_TOKEN_FILE = "', '.hook-amp.token', 'const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/',
        'const DC_MAX_TOKEN_FILE_BYTES = 4096', 'runtime.file(DC_TOKEN_FILE).slice(0, DC_MAX_TOKEN_FILE_BYTES + 1).text()',
        'if (!DC_TOKEN_PATTERN.test(token))', 'headers.Authorization = `Bearer ${token}`'
    )) {
        if ($Config.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) { throw "Amp policy plugin is missing $marker" }
    }
    if ($Config.IndexOf('const DC_API_TOKEN =', [StringComparison]::Ordinal) -ge 0) { throw 'Amp policy plugin keeps the obsolete embedded token' }
    if ($Config -match $AmpShellLayerPattern) { throw 'Amp policy plugin depends on a shell hook or compatibility layer' }
    $tokenPath = Join-Path $script:DcHome 'hooks\.hook-amp.token'
    $declared = [regex]::Match($Config, '(?m)^const DC_TOKEN_FILE\s*=\s*(?<literal>"(?:\\.|[^"\\])*")\s*$')
    if (-not $declared.Success -or -not [string]::Equals([IO.Path]::GetFullPath(($declared.Groups['literal'].Value | ConvertFrom-Json)), $tokenPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Amp policy plugin does not name the connector-scoped token sidecar'
    }
    $token = [IO.File]::ReadAllText($tokenPath).Trim()
    if ($token -cnotmatch '^[0-9a-f]{64}$') { throw 'Amp token sidecar is malformed' }
    if ($Config.Contains($token) -or $Config.Contains([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($token)))) {
        throw 'Amp policy plugin embeds the scoped token'
    }
    # A regular file, owned by this account, with a protected DACL of this account and SYSTEM only.
    $item = Get-Item -LiteralPath $PluginPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Amp policy plugin is a reparse point' }
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath $PluginPath
    $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($owner -cne $user) { throw "Amp policy plugin is owned by $owner, not $user" }
    if (-not $acl.AreAccessRulesProtected) { throw 'Amp policy plugin DACL inherits from its folder' }
    $allowed = @{}
    foreach ($rule in @($acl.Access)) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($sid -notin @($user, 'S-1-5-18')) { throw "Amp policy plugin grants access to $sid" }
        $allowed[$sid] = [int64]$(if ($allowed.ContainsKey($sid)) { $allowed[$sid] } else { 0 }) -bor [int64]$rule.FileSystemRights
    }
    $full = [int64][Security.AccessControl.FileSystemRights]::FullControl
    foreach ($sid in @($user, 'S-1-5-18')) {
        if (-not $allowed.ContainsKey($sid) -or ($allowed[$sid] -band $full) -ne $full) { throw "Amp policy plugin does not give $sid full control" }
    }
    return 'five callbacks, scoped bearer token, closed fail mode, no shell layer, owner-and-SYSTEM DACL'
}

function Assert-OpenCodeRegistration([string]$Config) {
    foreach ($marker in @(
        'export default {', 'ctx.tool.hook("execute.before"', 'ctx.tool.hook("execute.after"', '"tool.execute.before": async',
        'const verdict = await defenseclawPost(', 'if (verdict && verdict.reason) throw defenseclawBlock(client, verdict.reason);',
        'verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE', '"tool.execute.after": async'
    )) {
        if ($Config.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) { throw "OpenCode plugin is missing synchronous enforcement marker $marker" }
    }
    $after = $Config.Substring($Config.IndexOf('"tool.execute.after": async', [StringComparison]::Ordinal))
    if ($after -match 'await\s+defenseclawPost\("tool\.execute\.after"') { throw 'OpenCode tool.execute.after became an enforcement boundary' }
    return 'awaited execute.before, observe-only execute.after'
}

function Get-DoctorRow([string]$Label) {
    $doctor = Invoke-Tool (Join-Path $script:Bin 'defenseclaw.exe') @('doctor', '--json-output') -Allowed @(0, 1) -Timeout 360
    $rows = @(($doctor.StdOut | ConvertFrom-Json).checks | Where-Object { $_.label -like "$Label*" })
    if ($rows.Count -ne 1) { throw "doctor returned $($rows.Count) '$Label' rows" }
    return $rows[0]
}

function Assert-Registration {
    $config = Get-ConnectorConfigPath $Connector
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "setup did not write $config" }
    $text = [IO.File]::ReadAllText($config)
    $detail = switch ($Connector) {
        'codex' { Assert-CodexRegistration $text }
        'copilot' { Assert-CopilotRegistration $text }
        'cursor' { Assert-CursorRegistration $text }
        'antigravity' { Assert-AntigravityRegistration $text }
        'devin' { Assert-DevinRegistration $text }
        'hermes' { Assert-HermesRegistration $config }
        'amp' { Assert-AmpRegistration $text $config }
        'opencode' { Assert-OpenCodeRegistration $text }
        'claudecode' {
            if ($text -notmatch '(?i)defenseclaw-hook(?:-guard)?\.exe') { throw 'Claude Code settings do not run a native DefenseClaw hook' }
            'settings run the native hook'
        }
    }
    $guidance = if ($Connector -in @('amp', 'opencode')) { Remove-PluginSourceComments $text } else { $text }
    if (Test-ObsoleteWindowsHookGuidance $guidance) { throw "$config contains Unix shell guidance on Windows" }
    Write-Result "$Connector`:registration" pass $detail

    $row = Get-DoctorRow (Get-DoctorLabel $Connector)
    if ($row.status -ne 'pass') { throw "doctor rejected the setup-created $Connector registration: $($row.status) $($row.detail)" }
    if (Test-ObsoleteWindowsHookGuidance ([string]$row.detail)) { throw "doctor gave Unix guidance for Windows $Connector hooks: $($row.detail)" }
    if ($Connector -eq 'opencode' -and $row.detail -notmatch 'digest current') { throw "doctor did not report the OpenCode plugin digest: $($row.detail)" }
    if ($Connector -eq 'hermes' -and ($row.detail -notmatch 'hook_entries=23' -or $row.detail -notmatch 'allowlist_entries=23')) {
        throw "doctor did not report the Hermes hook inventory: $($row.detail)"
    }
    Write-Result "$Connector`:doctor" pass ([string]$row.detail)
}

# -- Setup, teardown and the observe phase --------------------------------------

function Invoke-Setup([string]$Mode) {
    # No vendor client is installed, so setup stages the connector offline and
    # the gateway restarts explicitly (contract-smoke.sh does the same).
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw.exe') @('setup', (Get-SetupSubcommand $Connector), '--yes', '--replace', '--mode', $Mode, '--no-restart') -Timeout 600 | Out-Null
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw-gateway.exe') @('restart') -Timeout 120 | Out-Null
    Wait-Gateway
}

function Invoke-Teardown {
    # The running gateway's connector guard would put a removed registration
    # back; stop it so teardown owns the lifecycle, then require verify clean.
    Stop-Gateway
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw-gateway.exe') @('connector', 'teardown', '--connector', $Connector) -Allowed @(0, 1) | Out-Null
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw-gateway.exe') @('connector', 'verify', '--connector', $Connector) | Out-Null
}

function Invoke-ObservePhase {
    $config = Get-ConnectorConfigPath $Connector
    $before = Get-FileState $config
    Invoke-Setup observe
    Assert-Registration
    if ($Connector -eq 'opencode') { Assert-OpenCodeTamper }
    Invoke-Teardown
    $after = Get-FileState $config
    if ($after -cne $before) { throw "teardown left $config as $after, was $before" }
    if ($Connector -eq 'cursor') {
        foreach ($name in 'cursor-hook.ps1', 'cursor-hook.sh') {
            if (Test-Path -LiteralPath (Join-Path $script:DcHome "hooks\$name")) { throw "teardown left the Cursor adapter $name" }
        }
    }
    Write-Result "$Connector`:observe-teardown" pass "vendor config restored ($before)"
}

# -- The action phase: contract-smoke.sh under Git Bash -------------------------

function Get-GitBash {
    $git = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    foreach ($candidate in @(
        $(if ($git) { Join-Path (Split-Path -Parent (Split-Path -Parent $git.Source)) 'bin\bash.exe' }),
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    throw 'Git Bash (bash.exe of Git for Windows) is required for contract-smoke.sh'
}

# The bash harness runs python3 and jq. The install's own interpreter stands
# in for python3; jq comes from the runner (Git for Windows does not ship it).
function Initialize-HarnessBash {
    if ($script:HarnessBash) { return }
    $script:HarnessBash = Get-GitBash
    $shims = Join-Path $StateRoot 'shims'
    New-Item -ItemType Directory -Force -Path $shims | Out-Null
    $python = $script:VenvPython.Replace('\', '/')
    [IO.File]::WriteAllText((Join-Path $shims 'python3'), "#!/bin/sh`nexec `"$python`" `"`$@`"`n", [Text.UTF8Encoding]::new($false))
    $env:Path = "$shims;$env:Path"
    $env:DC_E2E_OS = 'windows'
    $env:DC_E2E_RESULTS = $script:Results
    $env:DEFENSECLAW_HOME = $script:DcHome
}

# Invoke-HarnessBash COMMAND: run COMMAND with lib/common.sh and lib/assert.sh loaded; throws unless it exits 0.
function Invoke-HarnessBash([string]$Command) {
    Initialize-HarnessBash
    $lib = (Join-Path $PSScriptRoot 'lib').Replace('\', '/')
    $result = Invoke-Tool $script:HarnessBash @('-c', ". '$lib/common.sh'; . '$lib/assert.sh'; $Command") -Allowed @(0, 1, 2) -Timeout 120
    if ($result.ExitCode -ne 0) { throw "bash harness '$Command' exited $($result.ExitCode): $($result.StdErr.Trim())" }
    return $result.StdOut
}

function Invoke-ContractSmoke {
    Initialize-HarnessBash
    $smoke = Invoke-Tool $script:HarnessBash @((Join-Path $PSScriptRoot 'contract-smoke.sh').Replace('\', '/'), $Connector) -Allowed @(0, 1) -Timeout 900
    Write-Host $smoke.StdErr
    if ($smoke.ExitCode -ne 0) { throw "contract-smoke.sh $Connector exited $($smoke.ExitCode)" }
}

# -- OpenCode: the golden commands through the installed plugin ------------------

function Invoke-OpenCodePlugin([ValidateSet('allow', 'block')][string]$Expected, [string]$Command, [string]$Label) {
    $node = (Get-Command 'node.exe' -ErrorAction Stop).Source
    $scratch = Join-Path $StateRoot ("opencode-$Label-" + [Guid]::NewGuid().ToString('N') + '.mjs')
    $result = Invoke-Tool $node @(
        (Join-Path $PSScriptRoot 'assert-opencode-plugin.mjs'), (Get-ConnectorConfigPath 'opencode'), $scratch, $Expected, $Command
    ) -Allowed @(0, 1) -Timeout 60
    if ($result.ExitCode -ne 0) { throw "OpenCode plugin $Label ($Expected): $($result.StdErr.Trim())" }
}

function Assert-OpenCodeTamper {
    $plugin = Get-ConnectorConfigPath 'opencode'
    $original = [IO.File]::ReadAllBytes($plugin)
    Stop-Gateway
    try {
        [IO.File]::WriteAllText($plugin, [IO.File]::ReadAllText($plugin) + "`n// defenseclaw contract tamper", [Text.UTF8Encoding]::new($false))
        $row = Get-DoctorRow 'OpenCode hooks'
        if ($row.status -ne 'fail' -or $row.detail -notmatch 'drift detected' -or $row.detail -notmatch 'setup opencode --yes --restart') {
            throw "doctor did not reject OpenCode plugin drift with repair guidance: $($row.status) $($row.detail)"
        }
    } finally {
        [IO.File]::WriteAllBytes($plugin, $original)
    }
    Write-Result 'opencode:tamper' pass 'doctor rejects plugin drift with the repair command'
}

function Invoke-OpenCodeActionPhase {
    $config = Get-ConnectorConfigPath 'opencode'
    $before = Get-FileState $config
    try {
        $env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'
        Invoke-Setup action
    } finally {
        Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT -ErrorAction SilentlyContinue
    }
    $golden = Join-Path $PSScriptRoot 'golden\opencode'
    $allow = ([IO.File]::ReadAllText((Join-Path $golden 'pre_tool_allow.json')) | ConvertFrom-Json).tool_input.command
    $block = ([IO.File]::ReadAllText((Join-Path $golden 'pre_tool_block_windows.json')) | ConvertFrom-Json).tool_input.command
    foreach ($probe in @(@('allow', $allow, 'PreTool-allow'), @('block', $block, 'PreTool-block'))) {
        $since = [int](Invoke-HarnessBash 'dc_event_cursor').Trim()
        Invoke-OpenCodePlugin $probe[0] $probe[1] $probe[0]
        Write-Result "$($probe[2]):verdict-shape" pass "plugin $($probe[0])ed: $($probe[1])"
        # The same canonical SQLite checks contract-smoke.sh makes.
        Invoke-HarnessBash "dc_wait_for_connector_event opencode $since && dc_assert_fired opencode $since" | Out-Null
        Write-Result "$($probe[2]):fires" pass "sqlite after row $since"
        if ($probe[0] -eq 'block') {
            Invoke-HarnessBash "dc_assert_verdict_block $since" | Out-Null
            Write-Result "$($probe[2]):verdict-gateway" pass ''
        }
    }
    Invoke-Teardown
    $after = Get-FileState $config
    if ($after -cne $before) { throw "teardown left $config as $after, was $before" }
    Write-Result teardown pass "vendor config restored ($before)"
}

# -- Observability v8 records ---------------------------------------------------

function Assert-ObservabilityV8 {
    $projection = Join-Path $StateRoot 'audit-projection.jsonl'
    Invoke-Tool $script:VenvPython @('-I', (Join-Path $PSScriptRoot 'project-audit-events.py'), '--audit-db', (Join-Path $script:DcHome 'audit.db'), '--out', $projection) | Out-Null
    $assert = Join-Path $WorkspaceRoot 'scripts\assert-observability-v8-jsonl.py'
    Invoke-Tool $script:VenvPython @('-I', $assert, $projection, '--min-records', '1', '--require-event-name', 'hook_decision') | Out-Null
    Write-Result 'observability:audit-projection' pass 'canonical v8 records with a hook_decision'
    if (-not (Test-Path -LiteralPath $script:ContractJsonl -PathType Leaf)) { throw "the JSONL destination wrote nothing to $script:ContractJsonl" }
    Invoke-Tool $script:VenvPython @('-I', $assert, $script:ContractJsonl, '--min-records', '1') | Out-Null
    Write-Result 'observability:jsonl-destination' pass $script:ContractJsonl
}

# -- Lifecycle ------------------------------------------------------------------

function Invoke-Lifecycle {
    $cli = Join-Path $script:Bin 'defenseclaw.exe'
    $wheel = (Get-ChildItem -LiteralPath $Assets -Filter 'defenseclaw-*-py3-none-any.whl' | Select-Object -First 1).Name
    $version = [regex]::Match($wheel, '\d+\.\d+\.\d+').Value
    $reported = (Invoke-Tool $cli @('--version')).StdOut
    if ($reported -notmatch [regex]::Escape($version)) { throw "defenseclaw --version says '$reported', the assets are $version" }
    Write-Result 'lifecycle:version' pass $version
    Invoke-Tool (Join-Path $script:Bin 'defenseclaw-gateway.exe') @('start') -Timeout 120 | Out-Null
    Wait-Gateway
    $status = Invoke-Tool $cli @('status') -Allowed @(0, 1)
    if ($status.ExitCode -ne 0 -or $status.StdOut -notmatch '(?i)gateway') { throw "defenseclaw status: $($status.StdOut)$($status.StdErr)" }
    Write-Result 'lifecycle:status' pass 'exit 0'
    $doctor = Invoke-Tool $cli @('doctor', '--json-output') -Allowed @(0, 1) -Timeout 360
    $checks = @(($doctor.StdOut | ConvertFrom-Json).checks)
    $failed = @($checks | Where-Object { $_.status -eq 'fail' })
    if ($checks.Count -eq 0 -or $failed.Count) { throw "doctor failed: $(($failed | ForEach-Object { "$($_.label): $($_.detail)" }) -join '; ')" }
    Write-Result 'lifecycle:doctor' pass "$($checks.Count) checks, none failed"
    $render = @'
import asyncio, io, sys
from rich.console import Console
from defenseclaw import config
from defenseclaw.tui.app import DefenseClawTUI

async def main() -> str:
    app = DefenseClawTUI(config=config.load(), first_run=False, config_path=config.config_path())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(3)
        console = Console(width=80, height=24, file=io.StringIO(), force_terminal=True, color_system=None,
                          record=True, legacy_windows=False, safe_box=False)
        console.print(app.screen._compositor.render_update(full=True, screen_stack=app._background_screens))
        return console.export_text(styles=False)

text = asyncio.run(main())
print(text)
sys.exit(0 if "DefenseClaw" in text and "Traceback" not in text else 1)
'@
    $tui = Invoke-Tool $script:VenvPython @('-I', '-X', 'utf8', '-c', $render) -Allowed @(0, 1) -Timeout 180
    Write-Host $tui.StdOut
    if ($tui.ExitCode -ne 0) { throw "the TUI did not render at 80x24: $($tui.StdErr)" }
    Write-Result 'lifecycle:tui-80x24' pass 'rendered'
    $config = Join-Path $script:DcHome 'config.yaml'
    $configBefore = Get-FileState $config
    Install-DefenseClaw
    Wait-Gateway
    if ((Get-FileState $config) -cne $configBefore) { throw 'the repair re-run changed config.yaml' }
    Write-Result 'lifecycle:repair' pass 'install.ps1 re-run kept config.yaml and the gateway healthy'

    $uninstall = Invoke-Tool $cli @('uninstall', '--all', '--binaries', '--yes') -Allowed @(0, 1) -Timeout 600
    if ($uninstall.ExitCode -ne 0) { throw "uninstall --all --binaries exited $($uninstall.ExitCode): $($uninstall.StdOut)$($uninstall.StdErr)" }
    # Windows cannot delete a running program, so uninstall finishes in a
    # detached helper after it exits.
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    $left = @()
    do {
        Start-Sleep -Seconds 2
        $left = @(
            @('defenseclaw.exe', 'defenseclaw.cmd', 'defenseclaw', 'defenseclaw-gateway.exe', 'defenseclaw-hook.exe', 'defenseclaw-acp.exe', 'defenseclaw-hook-guard.exe') |
                ForEach-Object { Join-Path $script:Bin $_ } | Where-Object { Test-Path -LiteralPath $_ }
        ) + @(if (Test-Path -LiteralPath $script:DcHome) { $script:DcHome })
    } while ($left.Count -and [DateTime]::UtcNow -lt $deadline)
    if ($left.Count) { throw "uninstall left $($left -join ', ')" }
    $prefix = $script:ProfileHome.TrimEnd('\') + '\'
    $running = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
    if ($running.Count) { throw "uninstall left processes running: $(($running | ForEach-Object { "$($_.ProcessId) $($_.ExecutablePath)" }) -join '; ')" }
    $run = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    $runValues = @(if ($run) { $run.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value.IndexOf($prefix, [StringComparison]::OrdinalIgnoreCase) -ge 0 } })
    if ($runValues.Count) { throw "uninstall left Run values: $(($runValues | ForEach-Object Name) -join ', ')" }
    $userPath = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath.IndexOf($script:Bin, [StringComparison]::OrdinalIgnoreCase) -ge 0) { throw "uninstall left $script:Bin on the user Path" }
    Write-Result 'lifecycle:uninstall' pass 'no files, processes, Run value or Path entry left'
}

# -- Main -----------------------------------------------------------------------

$exitCode = 0
try {
    Enter-Profile
    Install-DefenseClaw
    Initialize-DefenseClaw
    if ($Operation -eq 'lifecycle') {
        Invoke-Lifecycle
    } else {
        Invoke-ObservePhase
        if ($Connector -eq 'opencode') { Invoke-OpenCodeActionPhase } else { Invoke-ContractSmoke }
        Assert-ObservabilityV8
    }
} catch {
    Write-Result $(if ($Operation -eq 'lifecycle') { 'lifecycle' } else { "$Connector`:contract" }) fail "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
} finally {
    if ($Operation -ne 'lifecycle') { try { Stop-Gateway } catch { Write-Host "gateway stop: $($_.Exception.Message)" } }
}
$failed = @(Get-Content -LiteralPath $script:Results -ErrorAction SilentlyContinue | Where-Object { $_ -match '"status":"fail"' })
if ($failed.Count -or $script:Failures.Count) {
    Write-Host "[windows-install] FAILED: $($failed.Count) failed result(s)"
    $exitCode = 1
} else {
    Write-Host "[windows-install] PASSED: $Operation $(if ($Operation -eq 'contract') { $Connector })"
}
exit $exitCode
