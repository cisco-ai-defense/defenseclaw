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
      -Operation lifecycle [-PersistPath]
        install, version, status, doctor, the TUI at 80x24, a repair re-run of
        install.ps1, then `defenseclaw uninstall --all --binaries --yes` and
        nothing of the install left (files, processes and, with -PersistPath,
        the user Path entry install.ps1 added; the user Path is back to what it
        was). install.ps1 writes no Run value (it only removes the ones a 0.8
        Setup wrote), so there is none to check.
      -Operation self-test
        the hook command parsers read every form setup renders (no install).

    No vendor agent is installed or run: the hook contract is the installed
    DefenseClaw entrypoint. A green cell is not connector certification.

    Run it on an ephemeral CI runner. The version-only vendor stand-ins go in
    the account's real Known Folders (the folders setup trusts), and a
    lifecycle with -PersistPath edits the account's user Path, so the harness
    refuses to run outside a GitHub-hosted runner unless
    DEFENSECLAW_CONTRACT_ALLOW_REAL_PROFILE=1 says the account is disposable.
#>
[CmdletBinding()]
param(
    [ValidateSet('contract', 'lifecycle', 'self-test')][string]$Operation = 'contract',
    [ValidateSet('codex', 'claudecode', 'amp', 'copilot', 'cursor', 'devin', 'hermes', 'antigravity', 'opencode')]
    [string]$Connector = 'codex',
    [string]$Assets = '',
    [string]$StateRoot = '',
    # lifecycle: let install.ps1 add the install's bin folder to the user Path,
    # so that "uninstall leaves no Path entry" is checked against a real entry.
    [switch]$PersistPath,
    [int]$CommandTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The stand-ins below go in the account's real Known Folders and -PersistPath
# edits its user Path: only a disposable account may run this.
if ($Operation -ne 'self-test' -and -not ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') -and
    $env:DEFENSECLAW_CONTRACT_ALLOW_REAL_PROFILE -ne '1') {
    throw 'run-windows-install.ps1 writes agent stand-ins to the real Known Folders of this account and may edit its user Path. ' +
        'It runs on a GitHub-hosted runner; elsewhere set DEFENSECLAW_CONTRACT_ALLOW_REAL_PROFILE=1 only on a disposable account.'
}

$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if ($Operation -eq 'self-test') { $StateRoot = Join-Path ([IO.Path]::GetTempPath()) ('dc-contract-self-test-' + [Guid]::NewGuid().ToString('N')) }
elseif (-not $Assets -or -not $StateRoot) { throw "-Operation $Operation needs -Assets and -StateRoot" }
else { $Assets = (Resolve-Path -LiteralPath $Assets).ProviderPath }
New-Item -ItemType Directory -Force -Path $StateRoot | Out-Null
# Real path: DefenseClaw refuses a data dir reached through a junction.
$StateRoot = (Get-Item -LiteralPath $StateRoot).FullName
$script:Results = Join-Path $StateRoot 'results.jsonl'
$script:Failures = [Collections.Generic.List[string]]::new()
$script:HarnessBash = $null
$script:Bin = ''
# True when the install folder has a character cmd.exe cannot be handed bare
# (a parenthesis, an apostrophe, ...): setup then registers Codex's PowerShell
# bridge instead of the direct cmd.exe command, and the cell checks it did.
$script:BinNeedsBridge = $false
$script:AgentFixtures = @()
$script:UserPathBefore = ''
$script:SeededConfig = $null
$script:FixtureDirectories = [Collections.Generic.List[string]]::new()
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
    # A real profile's DACL: this account, SYSTEM and Administrators, not
    # inherited. DefenseClaw refuses private folders other users can write to,
    # and a state root below a shared folder inherits such grants.
    New-Item -ItemType Directory -Force -Path $script:ProfileHome | Out-Null
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($sid in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    $security.SetOwner($user)
    Set-Acl -LiteralPath $script:ProfileHome -AclObject $security
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
    # Hermes resolves its home through the LocalAppData Known Folder, not the
    # environment, unless HERMES_HOME names it: keep its config in this profile.
    $env:HERMES_HOME = Join-Path $env:LOCALAPPDATA 'hermes'
    $script:Bin = Join-Path $script:ProfileHome '.local\bin'
    # The direct form carries only letters, digits and \ . _ - ~ (and spaces,
    # quoted): windowsCmdDirectPath in internal/gateway/connector/helpers.go.
    $script:BinNeedsBridge = $script:Bin -notmatch '^[A-Za-z]:\\[\p{L}\p{Nd} \\._~-]+$'
    $script:DcHome = Join-Path $script:ProfileHome '.defenseclaw'
    $script:VenvPython = Join-Path $script:DcHome '.venv\Scripts\python.exe'
    # The install's commands first; the runner's tools (Git Bash, jq, node, uv) after them.
    $env:Path = "$script:Bin;$env:Path"
}

function Install-DefenseClaw {
    $installer = Join-Path $Assets 'install.ps1'
    $started = Get-Date
    # Windows PowerShell 5.1 runs the installer, as for users.
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installer, '-Local', $Assets, '-Yes')
    if (-not $PersistPath) { $arguments += '-NoPersistPath' }
    $result = Invoke-Tool $WindowsPowerShell $arguments -Allowed @(0, 1) -Timeout 900
    if ($result.ExitCode -ne 0) {
        throw "install.ps1 -Local exited $($result.ExitCode):`n$((($result.StdOut + $result.StdErr) -split "`r?`n" | Select-Object -Last 40) -join "`n")"
    }
    foreach ($name in 'defenseclaw.exe', 'defenseclaw.cmd', 'defenseclaw-gateway.exe', 'defenseclaw-hook.exe', 'defenseclaw-acp.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $script:Bin $name) -PathType Leaf)) { throw "install.ps1 did not install $name in $script:Bin" }
    }
    Write-Result install pass ("install.ps1 -Local {0} in {1:n0}s" -f $Assets, ((Get-Date) - $started).TotalSeconds)
}

# The user Path as stored (unexpanded), and the edits a lifecycle with -PersistPath needs.
function Get-UserPathRaw {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    if ($null -eq $key) { return '' }
    try { return [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
}

function Get-UserPathEntryCount([string]$Directory) {
    return @((Get-UserPathRaw) -split ';' | Where-Object { $_ -and [string]::Equals($_.TrimEnd('\'), $Directory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) }).Count
}

function Remove-UserPathEntry([string]$Directory) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -eq $key) { return }
    try {
        $kind = $key.GetValueKind('Path')
        $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kept = @($raw -split ';' | Where-Object { -not ($_ -and [string]::Equals($_.TrimEnd('\'), $Directory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) }) -join ';'
        if ($kept -cne $raw) { $key.SetValue('Path', $kept, $kind) }
    } finally { $key.Close() }
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
    # Commands that reach the gateway without a connector binding (the Amp
    # plugin's `defenseclaw-gateway hook` path) use the default port unless told.
    $env:DEFENSECLAW_GATEWAY_ADDR = "127.0.0.1:$script:Port"
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

# -- Version-only stand-ins for the vendor clients -------------------------------

# Setup on Windows records the agent executable it guards (Codex, Claude Code,
# Amp, Hermes, OpenCode) and admits it only from a built-in trusted folder,
# which it resolves through the Known Folder API, not the environment. These
# stand-ins answer the version probe (and Codex's app-server policy read) the
# way the client releases do; they go in the current account's real Known
# Folders, refuse to replace an existing file and are removed afterwards. They
# are the fixtures the per-user Setup lanes used. No vendor agent runs.

function Get-KnownFolder([string]$Id) {
    if (-not ('DefenseClawContract.KnownFolder' -as [type])) {
        Add-Type -Namespace DefenseClawContract -Name KnownFolder -MemberDefinition @'
[DllImport("shell32.dll", CharSet = CharSet.Unicode)]
public static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
[DllImport("ole32.dll")]
public static extern void CoTaskMemFree(IntPtr pv);
'@
    }
    $pointer = [IntPtr]::Zero
    $hr = [DefenseClawContract.KnownFolder]::SHGetKnownFolderPath([Guid]$Id, 0, [IntPtr]::Zero, [ref]$pointer)
    if ($hr -ne 0) { throw "SHGetKnownFolderPath $Id failed: $hr" }
    try { return [Runtime.InteropServices.Marshal]::PtrToStringUni($pointer) } finally { [DefenseClawContract.KnownFolder]::CoTaskMemFree($pointer) }
}

function New-FixtureExecutable([string]$AssemblyName, [string]$Source, [string]$OutputPath) {
    # In-process Roslyn (it ships with PowerShell 7): no compiler child process
    # to race a deadline on a loaded runner. The output references only
    # mscorlib and carries the default asInvoker manifest.
    $mscorlib = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll'
    Add-Type -AssemblyName Microsoft.CodeAnalysis, Microsoft.CodeAnalysis.CSharp
    $compilation = [Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create(
        $AssemblyName,
        [Microsoft.CodeAnalysis.SyntaxTree[]]@([Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($Source)),
        [Microsoft.CodeAnalysis.MetadataReference[]]@([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($mscorlib)),
        [Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new([Microsoft.CodeAnalysis.OutputKind]::ConsoleApplication)
    )
    $resources = $compilation.CreateDefaultWin32Resources($true, $false, $null, $null)
    try {
        $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $result = $compilation.Emit($stream, $null, $null, $resources) } finally { $stream.Dispose() }
    } finally { $resources.Dispose() }
    if (-not $result.Success) {
        Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
        throw "fixture $AssemblyName did not compile: $(@($result.Diagnostics | Where-Object Severity -eq 'Error') -join '; ')"
    }
}

function Get-VersionFixtureSource([string]$Class, [string]$Version) {
    return "using System; public static class $Class { public static int Main(string[] arguments) { Console.WriteLine(""$Version""); return 0; } }"
}

function Install-AgentFixtures {
    $local = Get-KnownFolder 'F1B32785-6FBA-4FCF-9D55-7B8E7F157091'
    $profileRoot = Get-KnownFolder '5E6C858F-0E22-4760-9AFE-EA3317B67173'
    $codexRoot = Join-Path $local 'OpenAI\Codex\bin'
    $codexBin = Join-Path $codexRoot ('000-defenseclaw-ci-' + [Guid]::NewGuid().ToString('N'))
    $localBin = Join-Path $profileRoot '.local\bin'
    # Setup selects Codex only from 0.136.0, the first release with app-server --stdio.
    $codexSource = @'
using System;
public static class CodexVersionFixture {
    public static int Main(string[] arguments) {
        if (arguments.Length == 2 && arguments[0] == "app-server" && arguments[1] == "--stdio") {
            string line;
            while ((line = Console.ReadLine()) != null) {
                if (line.IndexOf("\"method\":\"initialize\"", StringComparison.Ordinal) >= 0) {
                    Console.WriteLine("{\"id\":1,\"result\":{}}"); Console.Out.Flush();
                } else if (line.IndexOf("\"method\":\"configRequirements/read\"", StringComparison.Ordinal) >= 0) {
                    Console.WriteLine("{\"id\":2,\"result\":{\"requirements\":{\"allowManagedHooksOnly\":false}}}"); Console.Out.Flush();
                }
            }
            return 0;
        }
        Console.WriteLine("codex-cli 0.136.0");
        return 0;
    }
}
'@
    $script:AgentFixtures = @(
        [pscustomobject]@{ Path = Join-Path $codexBin 'codex.exe'; Class = 'CodexVersionFixture'; Source = $codexSource; Version = 'codex-cli 0.136.0' },
        [pscustomobject]@{ Path = Join-Path $localBin 'claude.exe'; Class = 'ClaudeVersionFixture'; Version = 'claude 2.1.154' },
        [pscustomobject]@{ Path = Join-Path $localBin 'agent.exe'; Class = 'CursorAgentVersionFixture'; Version = 'cursor-agent 2026.07.23-e383d2b' },
        [pscustomobject]@{ Path = Join-Path $localBin 'amp.exe'; Class = 'AmpVersionFixture'; Version = 'amp 0.0.1785334225-g9abe75' },
        [pscustomobject]@{ Path = Join-Path $local 'hermes\hermes-agent\venv\Scripts\hermes.exe'; Class = 'HermesVersionFixture'; Version = 'Hermes Agent v0.20.0 (2026.8.3)' },
        [pscustomobject]@{ Path = Join-Path $local 'Microsoft\WinGet\Packages\SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe\opencode.exe'; Class = 'OpenCodeVersionFixture'; Version = 'opencode 2.1.4' }
    )
    $script:FixtureDirectories = [Collections.Generic.List[string]]::new()
    foreach ($fixture in $script:AgentFixtures) {
        if (Test-Path -LiteralPath $fixture.Path) { throw "refusing to replace an existing agent executable: $($fixture.Path)" }
    }
    foreach ($fixture in $script:AgentFixtures) {
        # Remember each folder this run creates, deepest last, to remove only those.
        $missing = [Collections.Generic.List[string]]::new()
        for ($dir = Split-Path -Parent $fixture.Path; -not (Test-Path -LiteralPath $dir); $dir = Split-Path -Parent $dir) { $missing.Insert(0, $dir) }
        foreach ($dir in $missing) { New-Item -ItemType Directory -Path $dir | Out-Null; $script:FixtureDirectories.Add($dir) }
        $source = if ($fixture.PSObject.Properties['Source'] -and $fixture.Source) { $fixture.Source } else { Get-VersionFixtureSource $fixture.Class $fixture.Version }
        New-FixtureExecutable $fixture.Class $source $fixture.Path
        $fixture | Add-Member -NotePropertyName Created -NotePropertyValue $true
        $version = (Invoke-Tool $fixture.Path @('--version') -Timeout 30).StdOut.Trim()
        if ($version -cne $fixture.Version) { throw "fixture $($fixture.Path) reports '$version'" }
    }
    $env:Path = "$localBin;$codexBin;$env:Path"
    Write-Result agent-fixtures pass "$($script:AgentFixtures.Count) version-only stand-ins in the Known Folder trusted roots"
}

function Remove-AgentFixtures {
    foreach ($fixture in @($script:AgentFixtures)) {
        if ($fixture -and $fixture.PSObject.Properties['Created'] -and (Test-Path -LiteralPath $fixture.Path -PathType Leaf)) {
            Remove-Item -LiteralPath $fixture.Path -Force
        }
    }
    $dirs = @($script:FixtureDirectories)
    [array]::Reverse($dirs)
    foreach ($dir in $dirs) {
        if ((Test-Path -LiteralPath $dir) -and -not @(Get-ChildItem -LiteralPath $dir -Force).Count) { Remove-Item -LiteralPath $dir -Force }
    }
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
# On the events Codex can block, the one-line install may start its guard
# program instead, which runs the defenseclaw-hook.exe beside it (rel-1-0-6
# GAP-0676): <system>\cmd.exe /d /v:off /c "<bin>\defenseclaw-hook-guard.exe"
# launcher-guard-sibling <arguments>. Both forms are read (same parser as
# windows-native-ci.ps1), so the contract holds before and after that change.
function Get-DirectHookCommand([string]$Command) {
    $match = [regex]::Match(
        $Command,
        '^(?<cmd>[A-Za-z]:\\[A-Za-z0-9\\._~-]+) /d /v:off /c "(?<file>[A-Za-z]:\\[\p{L}\p{Nd} \\._~-]+)"(?<arguments>(?: [A-Za-z0-9._-]+)+)$'
    )
    if (-not $match.Success) { return $null }
    if (-not [string]::Equals($match.Groups['cmd'].Value, (Join-Path ([Environment]::SystemDirectory) 'cmd.exe'), [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    $file = $match.Groups['file'].Value
    $arguments = [string[]]@($match.Groups['arguments'].Value.Substring(1).Split(' '))
    if ([string]::Equals([IO.Path]::GetFileName($file), 'defenseclaw-hook-guard.exe', [StringComparison]::OrdinalIgnoreCase) -and
        $arguments.Count -gt 1 -and $arguments[0] -ceq 'launcher-guard-sibling') {
        $file = Join-Path ([IO.Path]::GetDirectoryName($file)) 'defenseclaw-hook.exe'
        $arguments = [string[]]@($arguments[1..($arguments.Count - 1)])
    }
    return [pscustomobject]@{ File = $file; Arguments = $arguments }
}

# The awaited PowerShell bridge: Process.Start keeps the CreateProcess handle so
# a launcher that exits at once still returns its status, and Constrained
# Language mode falls back to the call operator. A per-user bridge since 1.0.9
# answers a launcher that cannot start with the agent's block instead, the
# same statements in all three places (rel-1-0-6 GAP-0676); both are read. The
# answer is what launcherStartAnswer.powershell() renders: its sentence goes to
# stderr through [Console]::Error, and through Write-Error where Constrained
# Language mode refuses that call. The earlier `catch { }` was never rendered
# by a release, so it is refused (the self-test checks it).
function Get-AwaitedHookBridge([string]$Script) {
    $pattern = '^\$ErrorActionPreference=''Stop''; \$env:NoDefaultCurrentDirectoryInExePath=''1''; ' +
        'if \(\$ExecutionContext\.SessionState\.LanguageMode -ne ''FullLanguage''\) \{ \$ErrorActionPreference=''Continue''; ' +
        '& (?<file>''(?:''''|[^''])+'')(?<quoted>(?: ''[^'' ]+'')+) \| Microsoft\.PowerShell\.Core\\Out-Host; ' +
        '(?:if \(\$null -eq \$LASTEXITCODE\) \{ exit 1 \}; |if \(\$null -eq \$LASTEXITCODE -or \$LASTEXITCODE -lt 0\) \{ ' +
        '(?<answer>try \{ \[Console\]::Error\.WriteLine\(''[^'']*''\) \} catch \{ Microsoft\.PowerShell\.Utility\\Write-Error -Message ''[^'']*'' -ErrorAction Continue \}; (?:''[^'']*''; )?exit [02]) \}; )' +
        'exit \$LASTEXITCODE \}; ' +
        '\$hookStart=\[System\.Diagnostics\.ProcessStartInfo\]::new\(\k<file>,''(?<arguments>[^'' ]+(?: [^'' ]+)*)''\); ' +
        '\$hookStart\.UseShellExecute=\$false; \$hookStart\.RedirectStandardError=\$true; ' +
        '(?(answer)try \{ \$hookProcess=\[System\.Diagnostics\.Process\]::Start\(\$hookStart\) \} catch \{ \k<answer> \}|' +
        '\$hookProcess=\[System\.Diagnostics\.Process\]::Start\(\$hookStart\)); ' +
        '\$hookProcess\.StandardError\.BaseStream\.CopyTo\(\[Console\]::OpenStandardError\(\)\); ' +
        '\$hookProcess\.WaitForExit\(\); (?(answer)if \(\$hookProcess\.ExitCode -lt 0\) \{ \k<answer> \}; )exit \$hookProcess\.ExitCode$'
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
    $contracts = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $commands) {
        $literal = $entry.Groups['literal'].Value
        $command = if ($literal.StartsWith("'", [StringComparison]::Ordinal)) { $literal.Substring(1, $literal.Length - 2) } else { $literal | ConvertFrom-Json }
        $bridge = Get-DirectHookCommand $command
        if ($script:BinNeedsBridge -and $null -ne $bridge) {
            throw "Codex command_windows starts the launcher through cmd.exe although $script:Bin has a character that form cannot carry; the PowerShell bridge is the only fail-closed answer there: $command"
        }
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
        [void]$contracts.Add($contract)
    }
    if ($contracts.Count -ne 1) { throw "Codex hooks bind more than one hook contract: $($contracts -join ', ')" }
    # contract-smoke.sh calls the installed hook with the contract setup bound
    # for this Codex version (the hook refuses any other).
    $env:DC_E2E_CODEX_HOOK_CONTRACT = @($contracts)[0]
    if (-not $bound.Contains('PreToolUse')) { throw 'Codex registration has no PreToolUse hook' }
    $form = if ($script:BinNeedsBridge) { ', every one through the PowerShell bridge (the install folder cannot be a direct cmd.exe path)' } else { '' }
    return "$($bound.Count) events bound to the installed defenseclaw-hook.exe ($env:DC_E2E_CODEX_HOOK_CONTRACT)$form"
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
    # A one-line install starts the guard program beside the launcher on
    # PreToolUse (rel-1-0-6 GAP-0676).
    $guard = (Join-Path $script:Bin 'defenseclaw-hook-guard.exe').Replace('\', '/')
    $guarded = "'" + $guard.Replace("'", "'\''") + "' launcher-guard-devin PreToolUse hook --connector devin"
    if ([string]::Equals($command, $guarded, [StringComparison]::Ordinal)) { return "PreToolUse runs $guarded" }
    if (-not [string]::Equals($command, $expected, [StringComparison]::Ordinal)) {
        throw "Devin PreToolUse is not the exact POSIX-quoted direct native command or its guarded start: $command (want $expected)"
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

    if ($Connector -eq 'opencode') {
        # Doctor checks the plugin's load heartbeat; OpenCode is not running,
        # so load the installed plugin once the way OpenCode does.
        Invoke-OpenCodePlugin load 'dc-setup-load' 'load'
        Write-Result 'opencode:plugin-load' pass 'the installed plugin loaded and sent its heartbeat'
    }
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

# A user's own vendor config, in a shape setup does not write (CRLF, tabs, no
# final newline for Codex), that setup must merge into and teardown must give
# back byte for byte. Absent for the connectors whose config setup owns whole.
function Get-UserVendorSeed([string]$Name) {
    switch ($Name) {
        'codex' { return @{
            Text = "model = `"gpt-5.2`"`r`nuser_marker_defenseclaw_contract = true`r`n`r`n[projects.'C:\Users\work']`r`ntrust_level = `"trusted`""
            Markers = @('user_marker_defenseclaw_contract', 'trust_level') } }
        'claudecode' { return @{
            Text = "{`r`n`t`"theme`": `"dark`",`r`n`t`"userMarkerDefenseclawContract`": true,`r`n`t`"hooks`": {`r`n`t`t`"Notification`": [ { `"hooks`": [ { `"type`": `"command`", `"command`": `"echo user-notification`" } ] } ]`r`n`t}`r`n}`r`n"
            Markers = @('userMarkerDefenseclawContract', 'echo user-notification') } }
        'cursor' { return @{
            Text = "{`r`n  `"version`": 1,`r`n  `"userMarkerDefenseclawContract`": true,`r`n  `"hooks`": {`r`n    `"afterFileEdit`": [ { `"command`": `"node user-format.js`" } ]`r`n  }`r`n}"
            Markers = @('userMarkerDefenseclawContract', 'node user-format.js') } }
    }
    return $null
}

function Set-UserVendorConfig([string]$Config) {
    $seed = Get-UserVendorSeed $Connector
    if ($null -eq $seed) { return $null }
    if (Test-Path -LiteralPath $Config) { throw "the throwaway profile already has $Config" }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Config) | Out-Null
    [IO.File]::WriteAllBytes($Config, [Text.UTF8Encoding]::new($false).GetBytes($seed.Text))
    $script:SeededConfig = @{ Path = $Config; State = Get-FileState $Config; Markers = $seed.Markers }
    return $script:SeededConfig
}

# The seeded config is the baseline of both phases: after setup it still holds
# the user's own entries, and after teardown it is the same bytes.
function Assert-UserVendorConfigKept([string]$Stage) {
    if ($null -eq $script:SeededConfig) { return }
    $state = Get-FileState $script:SeededConfig.Path
    if ($state -cne $script:SeededConfig.State) { throw "$Stage left the user's $Connector config as $state, was $($script:SeededConfig.State)" }
    Write-Result "$Connector`:user-config" pass "$Stage restored the user's own config byte for byte ($state)"
}

function Invoke-ObservePhase {
    $config = Get-ConnectorConfigPath $Connector
    $seeded = Set-UserVendorConfig $config
    $before = Get-FileState $config
    Invoke-Setup observe
    Assert-Registration
    if ($seeded) {
        $text = [IO.File]::ReadAllText($config)
        foreach ($marker in $seeded.Markers) {
            if ($text.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) { throw "setup dropped the user's own entry '$marker' from $config" }
        }
    }
    if ($Connector -eq 'opencode') { Assert-OpenCodeTamper }
    Invoke-Teardown
    $after = Get-FileState $config
    if ($after -cne $before) { throw "teardown left $config as $after, was $before" }
    Assert-UserVendorConfigKept 'the observe teardown'
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

function Invoke-OpenCodePlugin([ValidateSet('allow', 'block', 'load')][string]$Expected, [string]$Command, [string]$Label) {
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
    if ($PersistPath) {
        if ((Get-UserPathEntryCount $script:Bin) -ne 1) { throw "install.ps1 left $(Get-UserPathEntryCount $script:Bin) entries for $script:Bin on the user Path, want 1" }
        Write-Result 'lifecycle:path-added' pass "install.ps1 added $script:Bin to the user Path"
    }
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
# The Overview tab with the product banner, as at a real 80x24 terminal.
sys.exit(0 if "DEFENSECLAW" in text.upper() and "Overview" in text and "Traceback" not in text else 1)
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
    if ($PersistPath -and (Get-UserPathEntryCount $script:Bin) -ne 1) { throw "the repair re-run left $(Get-UserPathEntryCount $script:Bin) user Path entries for $script:Bin, want 1" }
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
    if ($PersistPath) {
        if ((Get-UserPathEntryCount $script:Bin) -ne 0) { throw "uninstall left $script:Bin on the user Path" }
        if ((Get-UserPathRaw) -cne $script:UserPathBefore) { throw 'uninstall left the user Path different from what it was before the install' }
    }
    Write-Result 'lifecycle:uninstall' pass $(if ($PersistPath) { 'no files or processes left; the user Path is as it was before the install' } else { 'no files or processes left (-NoPersistPath: the user Path was not touched)' })
}

# -- Self-test of the hook command parsers -------------------------------------

function Invoke-ParserSelfTest {
    $hook = 'C:\Users\u\.local\bin\defenseclaw-hook.exe'
    $guard = 'C:\Users\u\.local\bin\defenseclaw-hook-guard.exe'
    $cmd = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $bound = @('hook', '--connector', 'codex', '--event', 'PreToolUse', '--hook-contract', 'codex-hooks-v4')
    $cases = 0
    foreach ($case in @(
        @{ Command = "$cmd /d /v:off /c `"$hook`" $($bound -join ' ')"; File = $hook },
        @{ Command = "$cmd /d /v:off /c `"$guard`" launcher-guard-sibling $($bound -join ' ')"; File = $hook }
    )) {
        $parsed = Get-DirectHookCommand $case.Command
        if ($null -eq $parsed -or $parsed.File -cne $case.File -or ($parsed.Arguments -join ' ') -cne ($bound -join ' ')) { throw "direct form not read: $($case.Command)" }
        $cases++
    }
    foreach ($lookalike in @(
        "$cmd /d /v:off /c `"$guard`" launcher-guard $($bound -join ' ')",
        "$cmd /d /v:off /c `"C:\Users\u\.local\bin\other-guard.exe`" launcher-guard-sibling $($bound -join ' ')"
    )) {
        $parsed = Get-DirectHookCommand $lookalike
        if ($null -ne $parsed -and $parsed.File -ceq $hook -and ($parsed.Arguments -join ' ') -ceq ($bound -join ' ')) { throw "lookalike read as the hook: $lookalike" }
        $cases++
    }
    # The bridges as the generator renders them: testdata\windows-hook-bridges.json
    # holds the decoded scripts of windowsAnsweringPowerShellHookCommand
    # (internal/gateway/connector/launcher_start_answer.go), not hand-written
    # copies: the answering bridges of Antigravity PreToolUse and of Codex's
    # blockable events, and the ones that keep the earlier form.
    $fixture = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'testdata\windows-hook-bridges.json')) | ConvertFrom-Json
    $bridges = @($fixture.bridges)
    $answering = 0
    $writeError = 'catch \{ Microsoft\.PowerShell\.Utility\\Write-Error -Message ''[^'']*'' -ErrorAction Continue \}'
    foreach ($entry in $bridges) {
        $script = [string]$entry.script
        $bridge = Get-AwaitedHookBridge $script
        if ($null -eq $bridge -or $bridge.File -cne $entry.hook -or ($bridge.Arguments -join ' ') -cne $entry.arguments) { throw "bridge not read: $($entry.name)" }
        $encoded = '-NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        if ((Get-EncodedHookBridge $encoded "self-test $($entry.name)").File -cne $entry.hook) { throw "encoded bridge not read: $($entry.name)" }
        $cases++
        $isAnswering = $script -cmatch $writeError
        if ($entry.name -like '*unanswered') {
            if ($isAnswering) { throw "$($entry.name) is not the earlier bridge" }
            continue
        }
        if (-not $isAnswering) { throw "$($entry.name) does not answer a launcher that cannot start" }
        $answering++
        # Lookalikes of the answer: the plain `catch { }` form no release renders, in all three places
        # or in the first only, and a last answer that exits with another status. None may be read.
        $lastExit = $script.LastIndexOf('exit 0 }; exit $hookProcess.ExitCode')
        foreach ($lookalike in @(
            @{ Name = 'catch { } in all three places'; Script = [regex]::Replace($script, $writeError, 'catch { }') },
            @{ Name = 'catch { } in the first place'; Script = [regex]::new($writeError).Replace($script, 'catch { }', 1) },
            @{ Name = 'another exit status in the last answer'; Script = $(if ($lastExit -ge 0) { $script.Substring(0, $lastExit) + 'exit 2 }; exit $hookProcess.ExitCode' } else { $script }) }
        )) {
            if ($lookalike.Script -ceq $script) { throw "lookalike '$($lookalike.Name)' did not change $($entry.name)" }
            if ($null -ne (Get-AwaitedHookBridge $lookalike.Script)) { throw "$($entry.name): a bridge with $($lookalike.Name) was read" }
            $cases++
        }
    }
    if ($answering -lt 8 -or $bridges.Count -le $answering) { throw "windows-hook-bridges.json holds $answering answering of $($bridges.Count) bridges" }
    # Devin's direct command and its guarded start (rel-1-0-6 GAP-0676).
    $script:Bin = 'C:\Users\u\.local\bin'
    foreach ($command in @(
        "'C:/Users/u/.local/bin/defenseclaw-hook.exe' hook --connector devin",
        "'C:/Users/u/.local/bin/defenseclaw-hook-guard.exe' launcher-guard-devin PreToolUse hook --connector devin"
    )) {
        $config = @{ hooks = @{ PreToolUse = @(@{ hooks = @(@{ command = $command }) }) } } | ConvertTo-Json -Depth 6
        $null = Assert-DevinRegistration $config
        $cases++
    }
    $lookalike = @{ hooks = @{ PreToolUse = @(@{ hooks = @(@{ command = "'C:/Users/u/.local/bin/defenseclaw-hook-guard.exe' launcher-guard-devin Stop hook --connector devin" }) }) } } | ConvertTo-Json -Depth 6
    $refused = $false
    try { $null = Assert-DevinRegistration $lookalike } catch { $refused = $true }
    if (-not $refused) { throw 'a Devin guard start bound to another event was accepted' }
    $cases++
    $script:Bin = ''
    Write-Result 'self-test:parsers' pass "$cases cases: direct and guard-sibling Codex commands, $($bridges.Count) bridges as the generator renders them ($answering answering), direct and guarded Devin, lookalikes refused"
}

# -- Main -----------------------------------------------------------------------

$exitCode = 0
if ($Operation -eq 'self-test') {
    try { Invoke-ParserSelfTest } catch { Write-Result 'self-test:parsers' fail $_.Exception.Message }
} else {
    try {
        Enter-Profile
        if ($PersistPath) { $script:UserPathBefore = Get-UserPathRaw }
        Install-DefenseClaw
        Initialize-DefenseClaw
        if ($Operation -eq 'contract') { Install-AgentFixtures }
        if ($Operation -eq 'lifecycle') {
            Invoke-Lifecycle
        } else {
            Invoke-ObservePhase
            if ($Connector -eq 'opencode') { Invoke-OpenCodeActionPhase } else { Invoke-ContractSmoke }
            Assert-UserVendorConfigKept 'the action-mode run and its teardown'
            Assert-ObservabilityV8
        }
    } catch {
        Write-Result $(if ($Operation -eq 'lifecycle') { 'lifecycle' } else { "$Connector`:contract" }) fail "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
    } finally {
        # A lifecycle that stopped before its uninstall leaves the gateway running.
        if ($script:Bin) { try { Stop-Gateway } catch { Write-Host "gateway stop: $($_.Exception.Message)" } }
        try { Remove-AgentFixtures } catch { Write-Result agent-fixtures fail "cleanup: $($_.Exception.Message)" }
        # A lifecycle that stopped before its uninstall leaves the entry install.ps1 added.
        if ($PersistPath -and $script:Bin) {
            try { Remove-UserPathEntry $script:Bin } catch { Write-Result 'lifecycle:path-cleanup' fail $_.Exception.Message }
        }
    }
}
$failed = @(Get-Content -LiteralPath $script:Results -ErrorAction SilentlyContinue | Where-Object { $_ -match '"status":"fail"' })
if ($failed.Count -or $script:Failures.Count) {
    Write-Host "[windows-install] FAILED: $($failed.Count) failed result(s)"
    $exitCode = 1
} else {
    Write-Host "[windows-install] PASSED: $Operation $(if ($Operation -eq 'contract') { $Connector })"
}
if ($Operation -eq 'self-test') { Remove-Item -LiteralPath $StateRoot -Recurse -Force -ErrorAction SilentlyContinue }
exit $exitCode
