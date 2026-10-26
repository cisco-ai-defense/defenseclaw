# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Contracts of scripts/install.ps1, the Windows installer and upgrader.

The installer's behavior is tested end to end on Windows by
scripts/test-install-lifecycle.ps1. These checks pin what other code relies on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from defenseclaw import upgrade_shim
from defenseclaw.commands import cmd_uninstall, windows_uninstall_helper
from defenseclaw.platform_support import ACP_ONLY_CONNECTORS, UNSUPPORTED, WINDOWS_CONNECTOR_SUPPORT

ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
LIFECYCLE_PS1 = ROOT / "scripts" / "test-install-lifecycle.ps1"
TOKEN = "__DEFENSECLAW_VERSION__"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")


@pytest.fixture(autouse=True)
def _engine_module_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # A PowerShell 7 step (the Windows CI shell) puts its own module folders
    # first in PSModulePath. Windows PowerShell 5.1 started from Python
    # inherits them, cannot load Microsoft.PowerShell.Utility from there, and
    # then has no Get-FileHash, so Get-Sha256 says it "could not read" every
    # file. pwsh starting powershell.exe drops those folders, and so do the
    # installer's -File entry and `defenseclaw upgrade` (upgrade_shim); the
    # extracted functions these tests run have no entry, so every engine here
    # starts with the module path it builds itself.
    monkeypatch.delenv("PSModulePath", raising=False)


def _text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_lifecycle_proof_requires_json_connector_readback(tmp_path: Path) -> None:
    # rel-1-0-4:GAP-0745: a plain status answer cannot prove hook coverage.
    script = f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{tmp_path}'
$ManagedBinaries = @()
function Test-BinDirProtected {{ return $true }}
function Get-GatewayProcess {{ return [pscustomobject]@{{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
function Get-GatewayHealthReport {{ return $null }}
function Invoke-Native {{ return 0 }}
function Get-GatewayDigestProblem {{ return '' }}
{_ps1_function('Get-Field')}
{_ps1_function('ConvertTo-Map')}
{_ps1_function('Test-LifecycleProof')}
$problems = @(Test-LifecycleProof @{{}} $true @('codex'))
if (-not @($problems | Where-Object {{ $_ -match 'JSON health report' }}).Count) {{
    throw "missing JSON connector proof was accepted: $($problems -join '; ')"
}}
$emptyRoster = @(Test-LifecycleProof @{{}} $true @())
if (-not @($emptyRoster | Where-Object {{ $_ -match 'JSON health report' }}).Count) {{
    throw 'a current release with no registered connectors accepted missing JSON proof'
}}
$legacy = @(Test-LifecycleProof @{{}} $true @('codex') -AllowLegacyStatus)
if ($legacy.Count) {{ throw "a byte-verified old gateway cannot be restored: $($legacy -join '; ')" }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr
    restore = _ps1_function("Assert-LifecycleRestored")
    assert "0\\.8\\.10|1\\.0\\.[0-3]" in restore
    assert "-AllowLegacyStatus:$allowLegacyStatus" in restore
    # A rollback to one of those releases also needs its own legacy proof,
    # including both interrupted resume branches and the direct rollback.
    resume = _ps1_function("Resume-InterruptedRun")
    rollback = _ps1_function("Invoke-Rollback")
    assert resume.count("-AllowLegacyStatus:$legacyTarget") == 2
    assert "-AllowLegacyStatus:$legacyTarget" in rollback


def test_upgrade_requires_recorded_connectors_even_when_start_needs_attention() -> None:
    # rel-1-0-4:GAP-0679: a gateway start exit 3 must not erase prior guards.
    install = _ps1_function("Invoke-Install")
    assert '$guardedBefore = @(@(Get-Field $Manifest "Connectors")' in install
    assert '$guardedBefore = if ($startRc -eq 0)' not in install


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("json_report", [False, True])
def test_lifecycle_record_preserves_configured_connectors_when_health_omits_them(
    tmp_path: Path, json_report: bool,
) -> None:
    # GAP-0745/0679: old releases may lack JSON status, while a gateway that
    # does report JSON can still omit a configured external connector.
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$BinDir = '{tmp_path}'
function Get-GatewayProcess {{ return [pscustomobject]@{{ Id = 1 }} }}
function Get-GatewayHealthReport {{ return $(if (${str(json_report).lower()}) {{ [pscustomobject]@{{ health = [pscustomobject]@{{ connectors = @() }} }} }} else {{ $null }}) }}
function Get-GuardedConnectors {{ return @() }}
function Get-ConfiguredConnectors {{ return @() }}
function Get-EffectiveConfigConnectors {{ return @('codex') }}
function Get-ExternalConfig {{ return '' }}
function Get-BinariesState {{ return @{{}} }}
function Get-OptionalSha256 {{ return '' }}
function Test-BinDirProtected {{ return $true }}
{_ps1_function('Get-Field')}
{_ps1_function('Get-HeldConnectors')}
{_ps1_function('Get-LifecycleState')}
$state = Get-LifecycleState
if (@($state.Connectors).Count -ne 1 -or $state.Connectors[0] -ne 'codex') {{
    throw 'gateway health erased the configured connector'
}}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_lifecycle_record_excludes_connectors_old_gateway_reported_unhealthy(tmp_path: Path) -> None:
    # A repair cannot promise that a connector already needing attention was
    # guarded before the upgrade. A stale active_connector.json cannot add it.
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$BinDir = '{tmp_path}'
$ManagedBinaries = @()
function Get-GatewayProcess {{ return [pscustomobject]@{{ Id = 1; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
function Get-GatewayHealthReport {{ return [pscustomobject]@{{ running = $true; health = [pscustomobject]@{{ connectors = @(
    [pscustomobject]@{{ name = 'codex'; state = 'running' }},
    [pscustomobject]@{{ name = 'cursor'; state = 'needs_attention' }}
) }} }} }}
function Get-ConfiguredConnectors {{ return @('codex', 'cursor') }}
function Get-EffectiveConfigConnectors {{ return @('codex', 'cursor') }}
function Get-ExternalConfig {{ return '' }}
function Get-BinariesState {{ return @{{}} }}
function Get-OptionalSha256 {{ return '' }}
function Test-BinDirProtected {{ return $true }}
function Get-GatewayDigestProblem {{ return '' }}
{_ps1_function('Get-Field')}
{_ps1_function('Get-GuardedConnectors')}
{_ps1_function('Get-HeldConnectors')}
{_ps1_function('ConvertTo-Map')}
{_ps1_function('Get-LifecycleState')}
{_ps1_function('Test-LifecycleProof')}
$state = Get-LifecycleState
if (($state.Connectors -join ',') -ne 'codex') {{ throw "unsafe proof roster: $($state.Connectors -join ',')" }}
$problems = @(Test-LifecycleProof @{{}} $true ([string[]]$state.Connectors) -RequireProtected $false)
if ($problems.Count) {{ throw "upgrade could not prove its old guarded set: $($problems -join '; ')" }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


def test_effective_config_fallback_reads_old_external_connector_roster(tmp_path: Path) -> None:
    # The staged interpreter reads the old config as data, so a missing old
    # status --json does not erase a multi-connector external deployment.
    config = tmp_path / "external.yaml"
    config.write_text(
        "guardrail:\n  enabled: true\n  connectors:\n    codex: {}\n    claude-code: {}\n    cursor:\n      enabled: false\n",
        encoding="utf-8",
    )
    assert _effective_config_roster(config) == ["claudecode", "codex"]


def _effective_config_roster(config: Path) -> list[str]:
    helper = _ps1_function("Get-EffectiveConfigConnectors")
    match = re.search(r"\$code = '((?:''|[^'])*)'", helper)
    assert match is not None
    result = subprocess.run(
        [
            sys.executable, "-I", "-c",
            f"import sys; sys.path.insert(0, {str(ROOT / 'cli')!r}); " + match.group(1).replace("''", "'"),
            str(config),
        ],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "guardrail",
    [
        # 'uninstall' and 'setup guardrail --disable' write enabled: false.
        "guardrail:\n  enabled: false\n  connectors:\n    codex: {}\n    claude-code: {}\n",
        # Every release (0.8.10 through 1.0.4) defaults guardrail.enabled to false.
        "guardrail:\n  connectors:\n    codex: {}\n",
        "guardrail:\n  enabled: null\n  connectors:\n    codex: {}\n",
        "guardrail:\n  enabled: \"false\"\n  connectors:\n    codex: {}\n",
        # The single-connector and claw.mode forms are disabled the same way.
        "guardrail:\n  enabled: false\n  connector: codex\n",
        "claw:\n  mode: codex\nguardrail:\n  enabled: false\n",
        "claw:\n  mode: codex\n",
    ],
)
def test_effective_config_roster_is_empty_when_the_guardrail_is_disabled(tmp_path: Path, guardrail: str) -> None:
    # rel-1-0-4 review: a disabled guardrail tears every connector down, so the
    # old gateway guards none of the configured connectors. Recording them made
    # the new install demand hooks that never existed and roll back.
    config = tmp_path / "config.yaml"
    config.write_text(guardrail, encoding="utf-8")
    assert _effective_config_roster(config) == []


# Loop round 2 review (Windows consolidation): the fallback roster read the
# guardrail.connector scalar only when guardrail.connectors was empty, so a
# disabled map entry dropped an enabled scalar, and it never read
# enterprise.machine_policy.connectors. An older gateway that omits connector
# status then left those connectors out of an accepted retry's record, and
# its restore passed without proving their hooks. The roster is now the union
# EffectiveWindowsStandaloneHookConnectors protects, less explicit disables.
_STANDALONE = "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"
_UNION_ROSTERS = [
    ("a disabled map entry and an enabled scalar",
     "guardrail:\n  enabled: true\n  connector: codex\n  connectors:\n    cursor:\n      enabled: false\n", ["codex"]),
    ("a map entry and another scalar",
     "guardrail:\n  enabled: true\n  connector: codex\n  connectors:\n    claude-code: {}\n", ["claudecode", "codex"]),
    ("claw.mode next to a disabled map entry",
     "claw:\n  mode: codex\nguardrail:\n  enabled: true\n  connectors:\n    cursor:\n      enabled: false\n", ["codex"]),
    ("claw.mode next to an enabled map entry",
     "claw:\n  mode: codex\nguardrail:\n  enabled: true\n  connectors:\n    claude-code: {}\n", ["claudecode"]),
    ("the scalar turned off in the map",
     "guardrail:\n  enabled: true\n  connector: claude_code\n  connectors:\n    claude-code:\n      enabled: false\n", []),
    ("a machine policy connector only",
     _STANDALONE + "  machine_policy:\n    connectors:\n      cursor: {}\nguardrail:\n  enabled: true\n  connector: codex\n",
     ["codex", "cursor"]),
    ("a machine policy connector with a disabled map entry",
     _STANDALONE + "  machine_policy:\n    connectors:\n      cursor: {}\n      codex: {}\nguardrail:\n  enabled: true\n"
     "  connectors:\n    codex:\n      enabled: false\n", ["cursor"]),
    ("a machine policy connector outside a standalone config",
     "enterprise:\n  machine_policy:\n    connectors:\n      cursor: {}\nguardrail:\n  enabled: true\n  connector: codex\n",
     ["codex"]),
    ("a machine policy connector with the guardrail disabled",
     _STANDALONE + "  machine_policy:\n    connectors:\n      cursor: {}\nguardrail:\n  enabled: false\n", []),
]


@pytest.mark.parametrize(("config", "want"), [(c, w) for _, c, w in _UNION_ROSTERS], ids=[n for n, _, _ in _UNION_ROSTERS])
def test_effective_config_roster_is_the_union_the_gateway_protects(tmp_path: Path, config: str, want: list[str]) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(config, encoding="utf-8")
    assert _effective_config_roster(path) == want


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(("config", "want"), [(c, w) for _, c, w in _UNION_ROSTERS if w],
                         ids=[n for n, _, w in _UNION_ROSTERS if w])
def test_an_accepted_retry_records_every_connector_the_config_protects(tmp_path: Path, config: str, want: list[str]) -> None:
    # The accepted gateway is an older one that gives no status --json, so
    # its record (and the journal its restore proves) comes from the
    # effective config alone: every connector of the union is held.
    path = tmp_path / "config.yaml"
    path.write_text(config, encoding="utf-8")
    roster = ", ".join(f"'{name}'" for name in _effective_config_roster(path))
    result = _txn_harness(tmp_path, f"""
$closer = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
[void][IO.Directory]::CreateDirectory($LifecycleCloser)
[IO.File]::WriteAllText($closer, 'checked 1.0.4 gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
$script:enabled = @({roster})
$original = @{{ Schema = 1; Operation = 'install'; From = ''; To = '1.0.4'; Slot = ''; SetupRoot = ''; Bins = @{{}};
    GatewayWasRunning = $false; Connectors = @(); Config = ''; ExternalConfig = ''; ExternalConfigSha256 = '';
    HookFailModes = ''; BinDirProtected = $false; Committed = $false; ReplacementGatewayWasRunning = $true }}
Write-DurableText $LifecycleManifest ($original | ConvertTo-Json -Depth 4)
$Run.UnprovenConnectors = @(); $Run.UnprovenGatewayWasRunning = $true
$script:health = ''
Save-AcceptedConnectors $closer ([pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }})
"SAVED=$(@(Get-Field (Read-LifecycleManifest) 'ReplacementConnectors') -join ',')"
$Run.UnprovenReplacement = Read-LifecycleManifest
$Run.UnprovenAcceptedBins = Get-BinariesState $BinDir
$Run.UnprovenCloserSha256 = Get-Sha256 $closer
$journal = Write-LifecycleManifest 'upgrade' '1.0.3' '1.0.4' (Join-Path $DataDir 'previous.new')
"JOURNAL=$(@(Get-Field $journal 'Connectors') -join ',')"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    joined = ",".join(want)
    assert f"SAVED={joined}\n" in out and f"JOURNAL={joined}\n" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_accepted_retry_proves_the_connectors_its_record_lists_from_the_start(tmp_path: Path) -> None:
    # Continuation 2 review: a retry of -AcceptCurrentInstall over a record
    # an earlier accepted run wrote (ReplacementConnectors, its gateway
    # stopped) started with no connector roster. A failure before this run
    # asked the gateway again restored it and proved none of them. The
    # retry now starts from the record's list (or, with none recorded and
    # the gateway stopped, every connector the config enables).
    result = _txn_harness(tmp_path, _resume_functions("Start-AcceptedReplacement", "Restore-AcceptedReplacement") + r"""
function Write-Warn { param($Message) }
function Write-Err { param($Message) }
function Start-Gateway { $script:gateway = [pscustomobject]@{ Id = 200; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }; return 0 }
$record = @{ Schema = 1; Operation = 'install'; From = ''; To = '1.0.4'; Slot = ''; SetupRoot = ''; Bins = @{};
    GatewayWasRunning = $false; Connectors = @(); Config = ''; ExternalConfig = ''; ExternalConfigSha256 = '';
    HookFailModes = ''; BinDirProtected = $false; Committed = $false; ReplacementGatewayWasRunning = $true;
    ReplacementConnectors = @('codex', 'claudecode') }
Write-DurableText $LifecycleManifest ($record | ConvertTo-Json -Depth 4)
$manifest = Read-LifecycleManifest
$script:enabled = @('cursor')
"RECORDED=$(@(Get-RecordedAcceptedConnectors $manifest $true) -join ',')"
"UNRECORDED_STOPPED=$(@(Get-RecordedAcceptedConnectors ([pscustomobject]@{ Schema = 1 }) $true) -join ',')"
"UNRECORDED_RUNNING=$(@(Get-RecordedAcceptedConnectors ([pscustomobject]@{ Schema = 1 }) $false) -join ',')"
# Loop round 1 (rc.7): a persisted list that is empty, null or names none
# proves nothing, so a stopped gateway is held to the effective config.
foreach ($recordedList in @('[]', 'null', '[""]', '["none"]')) {
    $persisted = ('{"Schema": 1, "ReplacementConnectors": ' + $recordedList + '}') | ConvertFrom-Json
    "EMPTY_STOPPED[$recordedList]=$(@(Get-RecordedAcceptedConnectors $persisted $true) -join ',')"
    "EMPTY_RUNNING[$recordedList]=$(@(Get-RecordedAcceptedConnectors $persisted $false) -join ',')"
}
# ... and Save-AcceptedConnectors holds a stopped gateway over such a record
# to the effective config too.
$emptyRecord = $record.Clone(); $emptyRecord.ReplacementConnectors = @()
Write-DurableText $LifecycleManifest ($emptyRecord | ConvertTo-Json -Depth 4)
$Run.UnprovenConnectors = @(); $Run.UnprovenGatewayWasRunning = $true
Save-AcceptedConnectors (Join-Path $LifecycleCloser 'defenseclaw-gateway.exe') $null
"SAVED_EMPTY=$(@(Get-Field (Read-LifecycleManifest) 'ReplacementConnectors') -join ',')"
Write-DurableText $LifecycleManifest ($record | ConvertTo-Json -Depth 4)
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
$Run.UnprovenReplacement = $manifest; $Run.UnprovenGatewayWasRunning = $true
$Run.UnprovenAcceptedBins = Get-BinariesState $BinDir
$Run.UnprovenConnectors = @(Get-RecordedAcceptedConnectors $manifest $true)
$script:health = '{"running": true, "health": {"connectors": [{"name": "codex", "state": "running"}, {"name": "claudecode", "state": "error"}]}}'
$script:digest = '{"effective_digest": "sha256:aa", "gateway_reported_digest": "sha256:aa"}'
$script:gateway = $null
"DOWN=$(Restore-AcceptedReplacement)"
$script:health = '{"running": true, "health": {"connectors": [{"name": "codex", "state": "running"}, {"name": "claudecode", "state": "running"}]}}'
$script:gateway = $null
"UP=$(Restore-AcceptedReplacement)"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "RECORDED=claudecode,codex\n" in out and "UNRECORDED_STOPPED=cursor\n" in out and "UNRECORDED_RUNNING=\n" in out, out
    for recorded in ('[]', 'null', '[""]', '["none"]'):
        assert f"EMPTY_STOPPED[{recorded}]=cursor\n" in out and f"EMPTY_RUNNING[{recorded}]=\n" in out, out
    assert "SAVED_EMPTY=cursor\n" in out, out
    assert "DOWN= The accepted install's gateway is not proven running" in out and "claudecode" in out.split("DOWN=")[1].split("\n")[0], out
    assert "UP= The accepted install's gateway is running.\n" in out, out
    resume = _ps1_function("Resume-InterruptedRun")
    seeded = resume.index("$Run.UnprovenConnectors = @(Get-RecordedAcceptedConnectors $manifest")
    assert resume.index("$Run.UnprovenAcceptedBins = Get-BinariesState $BinDir") < seeded


@pytest.mark.parametrize("enabled", ["true", "True", "\"true\"", "1"])
def test_effective_config_roster_reads_an_enabled_guardrail_as_the_gateway_does(tmp_path: Path, enabled: str) -> None:
    # The gateway reads guardrail.enabled with strconv.ParseBool semantics.
    config = tmp_path / "config.yaml"
    config.write_text(f"guardrail:\n  enabled: {enabled}\n  connector: codex\n", encoding="utf-8")
    assert _effective_config_roster(config) == ["codex"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("reported", [[], ["codex"]])
def test_lifecycle_record_with_a_disabled_guardrail_keeps_only_running_connectors(
    tmp_path: Path, reported: list[str],
) -> None:
    # A disabled guardrail leaves the effective config roster empty. The proof
    # roster is then exactly what the old gateway reports running, and the new
    # install can prove it.
    entries = ", ".join(f"[pscustomobject]@{{ name = '{n}'; state = 'running' }}" for n in reported)
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$BinDir = '{tmp_path}'
$ManagedBinaries = @()
function Get-GatewayProcess {{ return [pscustomobject]@{{ Id = 1; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
function Get-GatewayHealthReport {{ return [pscustomobject]@{{ running = $true; health = [pscustomobject]@{{ connectors = @({entries}) }} }} }}
function Get-ConfiguredConnectors {{ return @('codex', 'cursor') }}
function Get-EffectiveConfigConnectors {{ return @() }}
function Get-ExternalConfig {{ return '' }}
function Get-BinariesState {{ return @{{}} }}
function Get-OptionalSha256 {{ return '' }}
function Test-BinDirProtected {{ return $true }}
function Get-GatewayDigestProblem {{ return '' }}
{_ps1_function('Get-Field')}
{_ps1_function('Get-GuardedConnectors')}
{_ps1_function('Get-HeldConnectors')}
{_ps1_function('ConvertTo-Map')}
{_ps1_function('Get-LifecycleState')}
{_ps1_function('Test-LifecycleProof')}
$state = Get-LifecycleState
if ((@($state.Connectors) -join ',') -ne '{",".join(reported)}') {{ throw "proof roster: $(@($state.Connectors) -join ',')" }}
$problems = @(Test-LifecycleProof @{{}} $true ([string[]]@($state.Connectors)) -RequireProtected $false)
if ($problems.Count) {{ throw "upgrade could not prove its old guarded set: $($problems -join '; ')" }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(sys.platform != "win32" or POWERSHELL is None, reason="native Windows PowerShell required")
def test_effective_config_reader_works_through_native_windows_powershell(tmp_path: Path) -> None:
    # The installed Python -c reader must survive Windows PowerShell 5.1's
    # native argument quoting during a live local upgrade.
    config = tmp_path / "config.yaml"
    config.write_text(
        "guardrail:\n  enabled: true\n  connectors:\n    codex: {}\n    claude-code: {}\n    cursor:\n      enabled: false\n",
        encoding="utf-8",
    )
    quoted_data_dir = str(tmp_path).replace("'", "''")
    quoted_venv = str(Path(sys.executable).parents[1]).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{quoted_data_dir}'
$Venv = '{quoted_venv}'
$Staging = Join-Path $DataDir 'missing-stage'
{_ps1_function('Get-NativeProbe')}
{_ps1_function('Get-EffectiveConfigConnectors')}
$roster = @(Get-EffectiveConfigConnectors)
if (($roster -join ',') -ne 'claudecode,codex') {{ throw "effective roster = $($roster -join ',')" }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_early_restore_reports_prior_unproven_baseline_without_false_binary_claim() -> None:
    # GAP-0702: a held hook can time out the safe drain. The current attempt
    # restores its hook, while a previous install's empty baseline remains
    # unproven. That state needs its own explanation and a retained lock.
    script = f"""
$ErrorActionPreference = 'Stop'
$Run = @{{ UnprovenReplacement = $true; RestorePending = $false }}
$script:asserted = $false
$script:warning = ''
function Test-RecoveryPending {{ return $false }}
function Set-RecoveryPending {{ $Run.RestorePending = $true }}
function Write-Warn([string]$Message) {{ $script:warning = $Message }}
function Assert-LifecycleRestored {{ $script:asserted = $true; throw 'false binary mismatch' }}
{_ps1_function('Finish-EarlySnapshotRestore')}
Finish-EarlySnapshotRestore ([pscustomobject]@{{ Bins = @{{}} }})
if ($script:asserted -or -not $Run.RestorePending -or
    $script:warning -notmatch 'earlier.*binary baseline' -or
    $script:warning -match 'not proven back') {{ throw 'misreported the held-hook restore' }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_in_memory_lifecycle_record_keeps_its_binary_baseline() -> None:
    # GAP-0702: early restore sees the ordered record before JSON readback.
    script = """
$ErrorActionPreference = 'Stop'
__GET_FIELD__
$record = [ordered]@{ Bins = [ordered]@{ 'defenseclaw-hook.exe' = 'old-sha' }; Connectors = @('codex') }
$bins = Get-Field $record 'Bins'
if (-not $bins -or $bins['defenseclaw-hook.exe'] -ne 'old-sha') { throw 'lost in-memory binary baseline' }
if (@(Get-Field $record 'Connectors') -join ',' -ne 'codex') { throw 'lost in-memory connector roster' }
$readback = $record | ConvertTo-Json -Depth 3 | ConvertFrom-Json
if ((Get-Field $readback 'Bins').'defenseclaw-hook.exe' -ne 'old-sha') { throw 'lost JSON binary baseline' }
'OK'
""".replace("__GET_FIELD__", _ps1_function("Get-Field"))
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_outlived_recovery_keeps_connector_named_by_external_config(tmp_path: Path) -> None:
    # rel-1-0-4:GAP-0679: a changed external config can still require the hook.
    external = tmp_path / "external.yaml"
    external.write_text("guardrail:\n  enabled: true\n  connectors:\n    codex: {}\n", encoding="utf-8")
    roster = ", ".join(f"'{name}'" for name in _effective_config_roster(external))
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path / 'data'}'
$BinDir = '{tmp_path / 'bin'}'
$LifecycleManifest = '{tmp_path / 'txn.json'}'
$env:DEFENSECLAW_CONFIG = '{external}'
$Run = @{{ RestorePending = $false }}
$AcceptCurrentInstall = $false
function Wait-LifecycleProof {{ return @('connector codex is not guarded again: the gateway does not report its hooks running') }}
function Test-LifecycleProof {{ return @() }}
function Get-GatewayHealthReport {{ return [pscustomobject]@{{ health = [pscustomobject]@{{ connectors = @() }} }} }}
function Get-EffectiveConfigConnectors {{ return @({roster}) }}
function Get-OptionalSha256 {{ param($Path) return 'new' }}
function Get-GatewayDigestProblem {{ return '' }}
function Set-RecoveryPending {{ $Run.RestorePending = $true }}
function Get-LifecycleNextStep {{ return 'retry' }}
function Remove-LifecycleManifest {{ }}
function Write-Warn {{ param($Message) }}
{_ps1_function('Get-Field')}
{_ps1_function('Assert-LifecycleRestored')}
$manifest = [pscustomobject]@{{ Bins = @{{}}; GatewayWasRunning = $true; Connectors = @('codex'); Config = ''; ExternalConfig = '{external}'; ExternalConfigSha256 = 'old'; HookFailModes = ''; BinDirProtected = $false; SetupRoot = '' }}
try {{ Assert-LifecycleRestored $manifest -Outlived; throw 'external configured connector was accepted unguarded' }}
catch {{ if ($_.Exception.Message -notmatch 'connector codex is not guarded again') {{ throw }} }}
'OK'
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


def _list(name: str) -> list[str]:
    match = re.search(rf"\${name} = @\((.*?)\)", _text(), re.S)
    assert match is not None, name
    return re.findall(r'"([^"]+)"', match.group(1))


def test_version_token_is_only_on_the_stamp_line() -> None:
    # `make dist-installers` replaces every occurrence, so a second one (say, to
    # detect an unstamped copy) would be stamped too and turn that check around.
    text = _text()
    assert text.count(TOKEN) == 1
    assert f'$DcVersion = "{TOKEN}"' in text
    assert "if (-not (Test-Version $Ver))" in text


def test_upgrade_shim_reads_the_stamped_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "install.ps1").write_text(_text().replace(TOKEN, "1.2.3"), encoding="utf-8")
    monkeypatch.setattr(upgrade_shim, "_installer_name", lambda: "install.ps1")
    assert upgrade_shim._local_version(str(tmp_path)) == "1.2.3"


def test_scripts_are_ascii() -> None:
    # Windows PowerShell 5.1 reads a script without a BOM, and an `irm | iex`
    # download, in the ANSI code page.
    INSTALL_PS1.read_text(encoding="utf-8").encode("ascii")
    LIFECYCLE_PS1.read_text(encoding="utf-8").encode("ascii")


def test_only_a_file_run_exits() -> None:
    # `exit` from a script block run by `irm | iex` closes the user's window.
    assert re.findall(r"(?:^|[{;]\s*)exit\b[^\n]*", _text(), re.M) == ["{ exit $code }"]
    assert "if ($RunAsFile) { exit $code }" in _text()


def test_permanent_parameters_and_unknown_arguments() -> None:
    parameters = _text().split("param(", 1)[1].split("\n)\n", 1)[0]
    for name in ("Yes", "Version", "Local", "Rollback", "Connector", "NoOpenclaw", "Quickstart",
                 "QuickstartMode", "NoPersistPath", "CosignPath", "Help"):
        assert re.search(rf"\]\${name}\b", parameters), name
    assert "[Parameter(ValueFromRemainingArguments = $true)]" in parameters
    assert "[CmdletBinding(PositionalBinding = $false)]" in _text()


def test_enterprise_policy_stops_it_before_any_change() -> None:
    # The policy 0.8.x `defenseclaw upgrade` honored; install.ps1 would otherwise
    # replace a per-user Setup an enterprise pushed through Intune or SCCM.
    text = _text()
    check = text.index('GetValue("DisableSelfUpdate")')
    assert 'OpenSubKey("SOFTWARE\\Policies\\Cisco\\DefenseClaw")' in text
    assert "[Microsoft.Win32.RegistryView]::Registry64" in text
    assert "DefenseClaw self-update is disabled by enterprise policy; use the managed deployment channel." in text
    assert "Could not read the enterprise update policy" in text
    # Before -Version and unstamped hand-offs, the lock, and -Rollback.
    assert check < text.index("return Invoke-ReleaseInstaller") < text.index("# Lock and log.")
    assert check < text.index("if ($Rollback) { return Invoke-Rollback }")


def test_connector_choices_are_the_windows_supported_connectors() -> None:
    choices = _list("ConnectorChoices")
    supported = {
        name
        for name, support in WINDOWS_CONNECTOR_SUPPORT.items()
        if support.status != UNSUPPORTED and name not in ACP_ONLY_CONNECTORS
    }
    assert choices[-1] == "none"
    assert len(choices) == len(set(choices))
    assert set(choices[:-1]) == supported


def test_uninstall_owns_every_file_the_installer_writes_to_local_bin() -> None:
    hook_state = re.search(r'\$HookState = "([^"]+)"', _text())
    posix_shim = re.search(r'\$PosixShim = "([^"]+)"', _text())
    cli_launcher = re.search(r'\$CliLauncher = "([^"]+)"', _text())
    assert hook_state is not None and posix_shim is not None and cli_launcher is not None
    written = (
        set(_list("ManagedBinaries"))
        | {f"{shim}.cmd" for shim in _list("ManagedShims")}
        | {hook_state.group(1), posix_shim.group(1), cli_launcher.group(1)}
    )
    _root, targets = cmd_uninstall._owned_binary_targets("win32")
    assert written == {re.split(r"[\\/]", target)[-1] for target in targets}
    # Install-Uv adds uv and the digest record uninstall checks it against.
    uv = re.search(r"foreach \(\$name in @\(([^)]*)\)\)", _text()[_text().index("function Install-Uv") :])
    assert uv is not None
    uv_written = set(re.findall(r'"([^"]+)"', uv.group(1))) | {cmd_uninstall._UV_RECORD}
    assert uv_written == set(cmd_uninstall._UV_NAMES["win32"]) | {cmd_uninstall._UV_RECORD}
    assert written | uv_written == windows_uninstall_helper._ALLOWED_BINARIES


def test_a_release_install_removes_the_developer_install_files() -> None:
    # GAP-1493: defenseclaw.exe from `make all` shadows the release
    # defenseclaw.cmd (PATHEXT), so the release install removes what make all
    # published beyond the managed binaries, once the swap is done.
    # Its defenseclaw.exe is replaced by the installer's launcher (GAP-2237).
    developer = set(cmd_uninstall._WINDOWS_DEVELOPER_FILES) - set(_list("ManagedBinaries")) - {"defenseclaw.exe"}
    assert set(_list("DeveloperFiles")) == developer
    text = _text()
    assert '(Join-Path $BinDir ".defenseclaw-source-root") -PathType Leaf' in text
    assert "    Complete-Swap\n    Remove-LifecycleManifest\n    Remove-DeveloperFiles\n" in text


def test_powershell_runs_a_native_cli_launcher() -> None:
    # GAP-2237: through defenseclaw.cmd, cmd.exe asked "Terminate batch job
    # (Y/N)?" after Ctrl+C. PATHEXT runs .exe before .cmd, so the installer
    # puts the venv's own launcher beside the shim, and rollback keeps it.
    text = _text()
    assert '$CliLauncher = "defenseclaw.exe"' in text
    assert "@($PosixShim, $CliLauncher, $HookState)" in text
    assert "Write-PosixShim $target; Install-File $target (Join-Path $BinDir $CliLauncher)" in text
    assert "defenseclaw.exe" not in _list("DeveloperFiles")


def test_cli_shim_is_the_one_uninstall_recognizes() -> None:
    match = re.search(r'\$text = "(@echo off[^\n]*)"\n', _text())
    assert match is not None
    venv = "C:\\Users\\Zoe\\.defenseclaw\\.venv"
    target = f"{venv}\\Scripts\\defenseclaw.exe"
    shim = match.group(1).replace("`r", "\r").replace("`n", "\n").replace('`"', '"').replace("$Target", target)
    assert shim == f'@echo off\r\n"{target}" %*\r\n'
    # cmd_uninstall._validate_windows_binary_ownership and the deferred helper
    # look for exactly this command line.
    assert f'"{target}" %*'.lower() in shim.lower()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_powershell_parses_the_scripts_and_help_runs(tmp_path: Path) -> None:
    script = rf"""
foreach ($path in '{INSTALL_PS1}', '{LIFECYCLE_PS1}') {{
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    if (@($errors).Count) {{ throw "${{path}}: $($errors -join '; ')" }}
}}
& '{POWERSHELL}' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '{INSTALL_PS1}' -Help
exit $LASTEXITCODE
"""
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        # pwsh on Linux and macOS has no profile folders; the script computes its paths up front.
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "-Rollback" in completed.stdout
    assert not (tmp_path / "home").exists()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    ("argument", "message"),
    [("-Frobnicate", "Unknown option: -Frobnicate"), ("-Connector=bogus", "Invalid -Connector 'bogus'")],
)
def test_an_unknown_argument_stops_with_exit_2(tmp_path: Path, argument: str, message: str) -> None:
    # GAP-0361: an unknown argument (a typo, or the -Name=value form) was
    # ignored with a warning and the install went on without it.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), argument],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert message in completed.stdout + completed.stderr
    assert not (tmp_path / "home").exists()


def test_hook_state_matches_what_the_hook_reads() -> None:
    # internal/cli/hook_trusted_state_windows.go accepts a PowerShell install's
    # state only with these values; anything else makes the hook fall back to
    # the profile's .defenseclaw and ignore a custom DEFENSECLAW_HOME.
    body = re.search(r"function Write-HookState \{(.*?)\n\}", _text(), re.S)
    assert body is not None
    for field in ('schema_version = 1', 'install_kind = "powershell-windows"', 'install_scope = "user"'):
        assert field in body.group(1)
    for field in ("install_root = $root", "command_dir = $root", "data_root = "):
        assert field in body.group(1)
    go = (ROOT / "internal" / "cli" / "hook_trusted_state_windows.go").read_text(encoding="utf-8")
    assert 'powerShellHookStateName = "defenseclaw-hook-state.json"' in go
    assert re.search(r'\$HookState = "defenseclaw-hook-state.json"', _text())


def test_a_failed_first_run_quickstart_keeps_the_install_and_exits_4() -> None:
    text = _text()
    extras = text[text.index("function Invoke-FirstInstallExtras") : text.index("function Show-Usage")]
    assert "$quickstartRc = Invoke-Native" in extras
    assert '$Run.QuickstartRerun = "defenseclaw " + ($quickstartArgs -join " ")' in extras
    summary = text[text.index('Write-Host "  DefenseClaw $Ver is installed."') : text.index("$savedEnv = @{}")]
    assert summary.index("if ($Run.QuickstartRerun)") < summary.index("return 4") < summary.index("return $startRc")
    # `irm | iex` cannot exit; it reports the installed-but-not-set-up outcome instead.
    tail = text[text.index("Wait-BeforeClose $code\nif ($RunAsFile) { exit $code }") :]
    assert tail.index("if ($code -eq 4) { & ([scriptblock]::Create('throw") < tail.index(
        "if ($code -ne 0 -and $code -ne 3) { & ([scriptblock]::Create('throw"
    )


def test_the_upgrade_window_keeps_the_outcome_on_screen_with_yes() -> None:
    # `defenseclaw upgrade --yes` runs install.ps1 in its own console: -Yes must
    # not close it at once, but it must not wait forever either.
    text = _text()
    body = text[text.index("function Wait-BeforeClose") : text.index("# -- Existing install")]
    assert "if ($Yes -or" not in body
    assert "[Console]::KeyAvailable" in body and "$Run.Log" in body
    # Windows PowerShell 5.1 runs this installer and has no [uint] accelerator.
    assert '"uint[]"' not in body
    # GAP-1570: `& install.ps1` typed into the user's own shell returns at once;
    # only a console started for the script waits before closing.
    started_for_script = (
        "[Environment]::CommandLine.IndexOf($scriptName, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }"
    )
    assert body.index("$Run.Log") < body.index(started_for_script) < body.index("if (-not $Yes)")


def test_the_suggested_cleanup_removes_the_read_only_key_copy() -> None:
    # GAP-1645: Remove-Item -Force first resets each file's attributes, which the
    # read-only redaction key copy refuses; rd /s /q deletes it through the folder.
    text = _text()
    assert "Remove-Item -Recurse -Force '" not in text
    assert text.count('cmd /c rd /s /q `"') == 2
    # A failed install can own unresolved external connector transactions;
    # its troubleshooting copy must not be advertised as safe to delete.
    failed = _ps1_function("Restore-Snapshot")
    assert "keep this copy until any connector recovery is complete" in failed
    assert "cmd /c rd /s /q" not in failed
    # The installer's own cleanup deletes through .NET first, which is also much
    # faster than Remove-Item in Windows PowerShell 5.1 (GAP-1600).
    body = text[text.index("function Remove-Tree") : text.index("function New-InstallDirectory")]
    assert body.index("[IO.Directory]::Delete(") < body.index("-Recurse -Force -ErrorAction SilentlyContinue")


def test_remove_tree_retries_without_logging_a_terminating_error() -> None:
    # WIN2-U3-13 item 10: a caught Remove-Item -ErrorAction Stop still wrote
    # "TerminatingError(Remove-Item)" into the upgrade transcript.
    text = _text()
    body = text[text.index("function Remove-Tree") : text.index("function New-InstallDirectory")]
    retry = body[: body.index("if ($attempt -ge 30)")] + body[body.index("Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue") :]
    assert "-ErrorAction Stop" not in retry
    assert "if ($attempt -ge 30) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return }" in body


def test_architecture_check_avoids_the_psreadline_polyfill() -> None:
    # GAP-1054: in an interactive Windows PowerShell 5.1 console (`irm | iex`)
    # [Runtime.InteropServices.RuntimeInformation] is PSReadLine's polyfill.
    text = _text()
    assert "[Runtime.InteropServices.RuntimeInformation]::OSArchitecture" not in text
    assert "switch (Get-OSArchitectureName) {" in text
    body = text[text.index("function Get-OSArchitectureName {") :][:900]
    assert '[object].Assembly.GetType("System.Runtime.InteropServices.RuntimeInformation")' in body
    assert "$env:PROCESSOR_ARCHITEW6432" in body and "$env:PROCESSOR_ARCHITECTURE" in body


def test_a_uv_in_the_bin_folder_is_used_not_replaced() -> None:
    # GAP-1125: a uv.exe in %USERPROFILE%\\.local\\bin that is not on PATH yet is
    # the user's; the installer must not overwrite and record it.
    text = _text()
    lookup = text[text.index("$Uv = [string](Get-Command uv.exe") :][:1000]
    assert '(Test-Path -LiteralPath (Join-Path $BinDir "uv.exe") -PathType Leaf)) { $Uv = Join-Path $BinDir "uv.exe" }' in lookup
    assert '-not $Run.UnprovenReplacement' in lookup
    assert lookup.index("Join-Path $BinDir") < lookup.index("Install-Uv (Join-Path $DataDir")
    assert 'Install-Uv (Join-Path $DataDir ".uv\\bin")' in lookup


def test_the_locked_package_install_is_retried_with_backoff() -> None:
    # GAP-1315: a sharing violation (os error 32) on uv's cache rename failed
    # the whole Windows install.
    # The DefenseClaw wheel install hit the same hold, so both uv pip steps
    # go through the retry helper.
    start = _text().index("function New-Venv")
    body = _text()[start : _text().index("function Invoke-UvPipInstall")]
    assert body.count("Invoke-UvPipInstall") == 2
    assert "Invoke-Native $Uv @(\"pip\"" not in body
    # GAP-1941: on a busy host one retry hit the same hold on the next
    # package, so it backs off several times, checks for a full disk before
    # each attempt, and the last failure says to run the command again.
    helper = _text()[_text().index("function Invoke-UvPipInstall(") :][:1200]
    assert "$waits = @(5, 15, 30)" in helper
    assert helper.index("Test-DiskFull") > helper.index("for ($i = 0")
    assert "Start-Sleep -Seconds $waits[$i]" in helper
    assert "run the same command again" in helper


# Harnesses that test one step of the installer, not its lifecycle
# transaction, run with the transaction's record and proof stubbed out (the
# transaction has its own tests below, fix/r104-windows).
_NO_TXN = (
    "function Write-DurableText { param($Path, $Text) [IO.File]::WriteAllText($Path, $Text) }\n"
    "function Save-LifecycleHookTransition { param($Slot) Undo-HookFirst $Slot; return '' }\n"
    "function Write-LifecycleManifest { return $null }\n"
    "function Read-LifecycleManifest { return $null }\n"
    "function New-RecoveryManifest { return $null }\n"
    "function Complete-LifecycleManifest { }\n"
    "function Remove-LifecycleManifest { }\n"
    "function Assert-LifecycleRestored { param($Manifest, [switch]$KeepStopped) }\n"
    "function Test-LifecycleProof { return @() }\n"
    "function Wait-LifecycleProof { return @() }\n"
    "function Get-LifecycleNextStep { return 'the same install command' }\n"
    "function Get-BinariesState { return @{} }\n"
    "function Start-HookFailModeHold { return $true }\n"
    "function Stop-HookFailModeHold { }\n"
    "function Set-RecoverySetupRoot { param($Manifest) }\n"
    "function Save-LifecycleCloser { param([string]$Slot) }\n"
    "function Set-RecoveryPending { param([string]$Flag = 'RestorePending') if (Get-Variable -Name Run -ErrorAction SilentlyContinue) { $Run.$Flag = $true } }\n"
    "function Start-RecoveredGateway { param([string]$What) if ((Start-Gateway) -notin @(0, 3)) { throw \"The $What gateway did not become healthy; run 'defenseclaw-gateway start', then run the installer again\" } }\n"
)


def _ps1_function(name: str) -> str:
    text = _text()
    match = re.search(rf"^function {re.escape(name)}[ (]", text, re.M)
    assert match is not None, name
    start = match.start()
    return text[start : text.index("\n}\n", start) + 3]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_rollback_manifest_records_an_oss_install_without_setup(tmp_path: Path) -> None:
    # A rollback enters before the install path discovers an old Setup install.
    # Under StrictMode an unbound $Setup used to abort before any swap began.
    manifest = tmp_path / "lifecycle.json"
    script = f"""
Set-StrictMode -Version Latest
$LifecycleManifest = '{manifest}'
function Get-LifecycleState {{ return [ordered]@{{ Bins = @{{}} }} }}
function Write-DurableText($Path, $Body) {{ [IO.File]::WriteAllText($Path, $Body) }}
{_ps1_function('Write-LifecycleManifest')}
$record = Write-LifecycleManifest 'rollback' '1.0.4' '1.0.2' ''
if ($record.SetupRoot -cne '' -or $record.Operation -cne 'rollback') {{ throw 'wrong rollback record' }}
if (([IO.File]::ReadAllText($LifecycleManifest) | ConvertFrom-Json).SetupRoot -cne '') {{
    throw 'rollback record references Setup'
}}
"""
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_failed_readiness_preserves_hooks_without_restarting_the_old_setup(tmp_path: Path) -> None:
    install = _ps1_function("Invoke-Install")
    startup = install[install.index("    $startRc = 0") : install.index("    Complete-Swap")]
    functions = "\n".join(_ps1_function(name) for name in (
        "Restore-Snapshot", "Restart-Old", "Restore-SetupInstall", "Get-RestoredNote",
        "Resume-InterruptedRun", "Read-Text",
    ))
    script = tmp_path / "failed-start.ps1"
    script.write_text(
        r"""param([string]$Root)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Clear-StagedRelease {}
function Restore-Slot { param($Slot) $script:restores++; [IO.Directory]::Delete($Slot, $true); return (Join-Path $Root 'failed') }
function Read-LifecycleManifest { return $null }
function New-RecoveryManifest { return $null }
function Assert-LifecycleRestored { param($Manifest, [switch]$KeepStopped) }
function Set-RecoverySetupRoot { param($Manifest) }
function Save-LifecycleCloser { param([string]$Slot) }
function Start-RecoveredGateway { param([string]$What) if ((Start-Gateway) -notin @(0, 3)) { throw "The $What gateway did not become healthy" } }
function Clear-SetupDataDir { param($Failed) }
function Remove-Tree { param($Path) }
function Find-SetupInstall { return $Setup }
function Get-TreeSize { param($Path) return 0 }
function Write-Warn { param($Message) $script:messages.Add($Message) }
function Write-Info { param($Message) $script:messages.Add($Message) }
function Write-Err { param($Message) $script:messages.Add($Message) }
function Die { param($Message) throw $Message }
function Get-GatewayProcess { return $null }
function Get-UtcClock { return '00:00:00Z' }
function Stop-Gateway { return $true }
function Start-Gateway {
    $script:starts++
    if ($script:starts -eq 1) { return 1 }
    # Earlier releases can remove hooks after meeting the same sharing error.
    [IO.File]::WriteAllText($script:settings, 'hookless predecessor')
    return 0
}
function Start-SetupGateway { param($Path) [void](Start-Gateway) }
"""
        + functions
        + r"""
foreach ($legacySetup in @($false, $true)) {
    $DataDir = Join-Path $Root ([string]$legacySetup)
    $Snap = Join-Path $DataDir 'snapshot'
    $Staging = Join-Path $DataDir 'staging'
    $BinDir = Join-Path $DataDir 'bin'
    [void][IO.Directory]::CreateDirectory($Snap)
    [IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'config_version: 9')
    $script:settings = Join-Path $DataDir 'settings.json'
    [IO.File]::WriteAllText($script:settings, 'working native hooks')
    $Setup = if ($legacySetup) { @{ Root = (Join-Path $DataDir 'legacy') } } else { $null }
    $SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
    $Run = @{ OldGatewayDown = $false; Log = 'install.log' }
    $WasRunning = $true
    $PrevVersion = '1.0.2'
    $Ver = '1.0.4'
    $previousLabel = 'the previous state'
    $script:starts = 0
    $script:restores = 0
    $script:messages = [Collections.Generic.List[string]]::new()
    $failed = $false
    try {
"""
        + startup
        + r"""
    } catch { $failed = $true }
    if (-not $failed -or $script:starts -ne 1 -or $script:restores -ne 1) {
        throw "failed readiness: failed=$failed starts=$script:starts restores=$script:restores"
    }
    if ([IO.File]::ReadAllText($script:settings) -cne 'working native hooks') { throw 'rollback removed the previous hooks' }
    if (-not $Run.OldGatewayDown -or ($script:messages -join ' ') -notlike '*then run:*defenseclaw-gateway.exe*start*') {
        throw 'the stopped gateway has no exact recovery command'
    }
    # The same refusal survives interruption before snapshot restoration.
    $resume = Join-Path $DataDir 'previous.new'
    $Previous = Join-Path $DataDir 'previous'
    [void][IO.Directory]::CreateDirectory($resume)
    foreach ($entry in @(@('COMPLETE', ''), @('VERSION', '1.0.2'), @('GATEWAY_WAS_RUNNING', 'true'), @('GATEWAY_RESTART_UNPROVEN', ''))) {
        [IO.File]::WriteAllText((Join-Path $resume $entry[0]), $entry[1])
    }
    $script:starts = 0
    $script:restores = 0
    Resume-InterruptedRun
    if ($script:starts -ne 0 -or $script:restores -ne 1 -or [IO.File]::ReadAllText($script:settings) -cne 'working native hooks') {
        throw 'interrupted recovery started an older setup after an unproven start'
    }
}
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script), "-Root", str(tmp_path)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_loaded_plugins_block_windows_install_before_gateway_stop() -> None:
    # A running 1.0.3 Amp or OpenCode process retains its old plugin even
    # after the installer replaces the file. Keep the old gateway enforcing.
    guard = _ps1_function("Assert-NoLoadedPluginAgents")
    assert "Get-CimInstance Win32_Process" in guard
    assert "GetOwner" in guard
    install = _ps1_function("Invoke-Install")
    rollback = _ps1_function("Invoke-Rollback")
    handoff = _ps1_function("Invoke-ReleaseInstaller")
    assert install.index("Assert-NoLoadedPluginAgents") < install.index("Stop-Gateway")
    # Wait-VenvFree and setup work can outlive the first scan. Recheck at
    # the gateway-stop boundary so a newly started old plugin is refused.
    setup = install.index("$Setup.ClaudeConfigDir")
    stop = install.index("Stop-Gateway", setup)
    assert install.index("Assert-NoLoadedPluginAgents", setup) < stop
    assert re.search(
        r"try\s*\{\s*Assert-NoLoadedPluginAgents\s*\}\s*catch\s*\{\s*"
        r"if \(\$Setup\) \{ Restore-SetupInstall -KeepStopped \}\s*throw\s*\}",
        install[setup:stop],
    )
    assert rollback.index("Assert-NoLoadedPluginAgents") < rollback.index("Stop-Gateway")
    assert handoff.index("Assert-NoLoadedPluginAgents") < handoff.index("Stop-Gateway")


@pytest.mark.skipif(os.name != "nt" or POWERSHELL is None, reason="native Windows identity required")
@pytest.mark.allow_subprocess
def test_windows_agent_scan_audits_owner_denial_and_refuses_the_same_account() -> None:
    # An unreadable owner (another account on a shared host) cannot prove a
    # live agent of this account: audit it and go on. A readable owner that is
    # this account refuses the swap in any session (w25-setup + GAP-1128).
    script = (
        "Set-StrictMode -Version Latest\n"
        "function Get-InstalledAgentPrograms { return @{ 'c:\\agent.exe' = 'opencode' } }\n"
        "$script:row = [pscustomobject]@{ ProcessId = 7001; ExecutablePath = 'C:\\agent.exe'; CommandLine = 'agent'; SessionId = 9 }\n"
        "function Get-CimInstance { param($Class, $Filter, $ErrorAction) return $script:row }\n"
        "function Get-LoadedPluginAgent($Process) { return 'opencode' }\n"
        "$script:owner = [pscustomobject]@{ ReturnValue = 2; Domain = ''; User = '' }\n"
        "function Invoke-CimMethod { param($InputObject, $MethodName, $ErrorAction) return $script:owner }\n"
        "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Output \"audit: $Reason\" }\n"
        "function Die([string]$Message) { throw $Message }\n"
        + _ps1_function("Assert-NoLoadedPluginAgents")
        + "Assert-NoLoadedPluginAgents\n'owner-denied-audited'\n"
        "$parts = [Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\\\', 2\n"
        "$script:owner = [pscustomobject]@{ ReturnValue = 0; Domain = $parts[0]; User = $parts[1] }\n"
        "try { Assert-NoLoadedPluginAgents; throw 'same-account-was-ignored' } "
        "catch { if ($_.Exception.Message -notlike 'Close OpenCode and Amp*') { throw } }\n"
        "'same-account-refused'\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "audit: process owner unreadable" in result.stdout
    assert "owner-denied-audited" in result.stdout
    assert "same-account-refused" in result.stdout


def test_refused_late_swap_restores_setup_hooks_without_restarting_gateway(tmp_path: Path) -> None:
    if not POWERSHELL:
        pytest.skip("PowerShell is unavailable")
    staged = tmp_path / "hook-runtime-state.json"
    restored = tmp_path / "active-state.json"
    staged.write_text("enforcing", encoding="ascii")
    root = str(tmp_path).replace("'", "''")
    destination = str(restored).replace("'", "''")
    script = _ps1_function("Enable-SetupHooks") + _ps1_function("Restore-SetupInstall") + f"""
$Staging = '{root}'
$SetupHookState = '{destination}'
$WasRunning = $true
$Setup = [pscustomobject]@{{ Root = '{root}' }}
function Move-Path([string]$Source, [string]$Destination) {{ Move-Item -LiteralPath $Source -Destination $Destination -Force }}
function Start-SetupGateway {{ throw 'the gateway was never stopped' }}
Restore-SetupInstall -KeepStopped
"""
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert restored.read_text(encoding="ascii") == "enforcing"
    assert not staged.exists()


_GUARDRAIL_CONFIGS = {
    # What 'uninstall --binaries' and 'setup guardrail --disable' save.
    "off": ("guardrail:\n  enabled: false\n  mode: action\n  judge:\n    enabled: true\ngateway:\n  port: 18970\n", True),
    "on": ("guardrail:\n  enabled: true\n  judge:\n    enabled: false\n", False),
    "other-section": ("guardrail:\n  mode: action\nwebhook:\n  enabled: false\n", False),
    "no-guardrail": ("gateway:\n  enabled: false\n", False),
}


def test_reinstall_over_a_disabled_guardrail_names_setup_guardrail() -> None:
    # GAP-2481: after 'uninstall --binaries' (guardrail off, hooks torn down)
    # the reinstall said only "Start it with: defenseclaw-gateway start".
    install = _ps1_function("Invoke-Install")
    branch = install[install.index("if (Test-GuardrailOff) {") :]
    assert branch.index("Turn it back on with: defenseclaw setup guardrail") < branch.index(
        "Start it with: defenseclaw-gateway start"
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("name", sorted(_GUARDRAIL_CONFIGS))
def test_test_guardrail_off_reads_the_kept_config(tmp_path: Path, name: str) -> None:
    body, expected = _GUARDRAIL_CONFIGS[name]
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")
    script = f"$DataDir = '{tmp_path}'\n{_ps1_function('Test-GuardrailOff')}\nif (Test-GuardrailOff) {{ 'off' }} else {{ 'on' }}\n"
    env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_CONFIG"}
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == ("off" if expected else "on")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_the_agent_prompt_with_no_console_picks_no_agent() -> None:
    # GAP-0568: with no console to answer on, Select-Connector picked codex and
    # recorded it in picked_connector.
    choices = _text()[_text().index("$ConnectorChoices = @(") :]
    choices = choices[: choices.index(")\n") + 2]
    script = (
        "function Write-Step { }\nfunction Write-Ok { param($m) Write-Output $m }\n"
        "function Write-Warn { param($m) Write-Output $m }\nfunction Stop-Usage { param($m) throw $m }\n"
        f"{choices}{_ps1_function('Select-Connector')}Select-Connector\n"
    )
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "none"
    assert "Connector: codex" not in completed.stdout


def test_the_agent_prompt_default_is_no_agent() -> None:
    # GAP-0568: Enter at the prompt, or no console, picks no agent, as install.sh.
    body = _ps1_function("Select-Connector")
    assert "[default none]" in body
    assert 'if (-not $answer) { $answer = "none" }' in body
    assert "1=codex" not in body


def test_a_slow_first_start_is_waited_for_before_restoring() -> None:
    # GAP-1348: a 1.x gateway over a large audit database outlasted start's
    # 60-second readiness wait, and the upgrade rolled back while it was
    # still starting.
    body = _ps1_function("Start-Gateway")
    assert "if ($rc -in @(0, 3) -or -not (Get-GatewayProcess)) { return $rc }" in body
    assert "$deadline = (Get-Date).AddMinutes(3)" in body
    assert 'Invoke-Native $gateway @("status") -Quiet' in body
    assert 'Write-Ok "The gateway finished starting"' in body


def test_a_restore_that_leaves_the_old_gateway_down_says_so() -> None:
    # GAP-1349: "Your previous install is back" while the gateway that ran
    # before stayed down and fail-closed connectors blocked every tool call.
    body = _ps1_function("Restart-Old")
    assert "$Run.OldGatewayDown = $oldRan -and -not (Get-GatewayProcess)" in body
    # An accepted retry stopped its gateway before $WasRunning was read.
    assert "$oldRan = [bool]$WasRunning -or [bool]($Run.UnprovenReplacement -and $Run.UnprovenGatewayWasRunning)" in body
    assert "did not start again, so agent hooks are not guarded" in body
    assert "but its gateway is not running" in _ps1_function("Get-RestoredNote")
    text = _text()
    # A failed install, a failed start and an unproven install restore it.
    assert text.count("$(Get-RestoredNote) Log: $($Run.Log)") == 3
    assert "Your previous install is back. Log:" not in text


def test_a_later_upgrade_keeps_the_0_x_audit_history() -> None:
    # GAP-1360: previous\ held the only copy of the 0.x audit history, and the
    # next upgrade replaced it.
    body = _ps1_function("Save-RolledBackData")
    assert '$label = "audit-history"' in body
    assert '[version]$version -lt [version]"1.0.0"' in body
    assert "backups\\$label-$version-" in body


def test_the_rollback_copy_states_its_size_and_the_free_space() -> None:
    # GAP-1519: an upgrade with a 1.3 GB audit.db never said how much it copied.
    body = _text()[_text().index("function Save-Snapshot") :][:1400]
    assert "Saving a rollback copy of the data folder ({0:N0} MB needed{1})" in body
    assert body.index("Saving a rollback copy") < body.index("Not enough free disk space")


def test_a_pending_uninstall_cleanup_is_waited_for_before_the_data_dir_is_touched() -> None:
    # GAP-1647: an install started right after `uninstall --all` lost its
    # .staging to the deferred cleanup, which runs after the CLI exits.
    start = _text().index("function Wait-UninstallCleanup(")
    body = _text()[start : _text().index("\n}\n", start)]
    assert '-Filter "defenseclaw-uninstall-*"' in body and '"plan.json"' in body
    assert '"interpreter_dirs"' in body
    assert "AddMinutes(-10)" in body
    assert "wait a minute, then run the installer again. Nothing was changed." in body
    install = _ps1_function("Invoke-Install")
    assert install.index("Wait-UninstallCleanup") < install.index('Join-Path $DataDir "logs"')
    # The helper's folder names match what uninstall writes.
    uninstall = (ROOT / "cli" / "defenseclaw" / "commands" / "cmd_uninstall.py").read_text(encoding="utf-8")
    assert 'tempfile.mkdtemp(prefix=f"defenseclaw-uninstall-{token}-")' in uninstall
    assert 'os.path.join(helper_dir, "plan.json")' in uninstall
    assert '"interpreter_dirs"' in uninstall


def test_uv_gets_load_tolerant_timeouts_and_they_are_restored() -> None:
    # GAP-1776: uv's 60 s bytecode and 30 s HTTP limits failed installs on a
    # busy Windows host.
    install = _ps1_function("Invoke-Install")
    assert 'if (-not $env:UV_COMPILE_BYTECODE_TIMEOUT) { $env:UV_COMPILE_BYTECODE_TIMEOUT = "600" }' in install
    assert 'if (-not $env:UV_HTTP_TIMEOUT) { $env:UV_HTTP_TIMEOUT = "300" }' in install
    restore = _text()[_text().index("$savedEnv = @{}") :][:400]
    assert '"UV_COMPILE_BYTECODE_TIMEOUT", "UV_HTTP_TIMEOUT"' in restore


def test_a_first_install_does_not_mention_a_previous_install() -> None:
    # GAP-1827: a first install printed "Saving a rollback copy ... (0 MB needed)"
    # and "Cleaning up the previous install's files".
    assert "if ($PrevVersion -or $need -gt 0) {" in _ps1_function("Save-Snapshot")
    swap = _ps1_function("Complete-Swap")
    assert "if ($PrevVersion) { Write-Info \"Cleaning up the previous install's files" in swap
    assert 'else { Write-Info "Removing the staging files" }' in swap


def test_the_install_log_can_time_a_failed_gateway_start() -> None:
    # GAP-1797: no line of the install log (a transcript) had a time.
    text = _text()
    assert '"--- $Message  [$(Get-UtcClock)]"' in text
    assert 'Write-Info "Starting the gateway [$(Get-UtcClock)]"' in _ps1_function("Start-Gateway")
    assert "did not become healthy within {0:N0} s [{1}]" in text


def test_the_previous_watchdog_is_stopped_even_when_the_gateway_is_down() -> None:
    # GAP-1833: with the gateway down the old watchdog kept running from the
    # renamed binary and held its ownership lock against the new one.
    body = _ps1_function("Stop-Watchdog")
    assert '$image = Join-Path $BinDir "defenseclaw-gateway.exe"' in body
    assert "Get-ProcessesUnder @($image)" in body  # a prefix: .old-* too
    assert 'Invoke-Native $image @("watchdog", "stop") -Quiet' in body
    assert "Stop-Process -Id $_.ProcessId -Force" in body
    # Rollback and recovery stop the gateway through Stop-Gateway, running or not.
    stop_gateway = _ps1_function("Stop-Gateway")
    assert "if (-not $process) { Stop-Watchdog; return $true }" in stop_gateway
    assert stop_gateway.count("Stop-Watchdog") == 2
    install = _ps1_function("Invoke-Install")
    stop = install.index("else { Stop-Watchdog }")
    assert install.index('Write-Info "Stopping the gateway') < stop < install.index("Save-Snapshot")
    assert not install[install.index("if ($WasRunning) {") : stop].count("Stop-Watchdog")


def test_disk_room_is_checked_before_staging_and_before_the_gateway_stops() -> None:
    # GAP-1841: only the rollback copy was checked, after staging and after
    # the gateway was stopped. GAP-1839: the staging and environment sizes
    # were never counted.
    text = _text()
    room = text[text.index("function Assert-InstallRoom(") :][:1400]
    assert "$data = Get-DataSize" in room
    assert "$free -ge $data + $Extra + 100MB" in room
    assert "nothing was changed" in room
    install = _ps1_function("Invoke-Install")
    first = install.index('Assert-InstallRoom $InstallRoom "the new version"')
    assert first < install.index("New-InstallDirectory $Staging")
    second = install.index('Assert-InstallRoom $FinalEnvRoom "the final Python environment"')
    assert install.index("is staged and checked") < second < install.index('Write-Info "Stopping the gateway')


def test_a_room_refusal_runs_before_the_uv_folder_or_uv_is_created() -> None:
    # GAP-2614: "nothing was changed", but the refusal came after
    # Protect-UvDirectory -Create had made an empty .uv in the data folder.
    install = _ps1_function("Invoke-Install")
    room = install.index('Assert-InstallRoom $InstallRoom "the new version"')
    assert room < install.index("Protect-UvDirectory -Create") < install.index("$Uv = if ($Run.UnprovenReplacement)")


def _bin_dir_functions() -> str:
    text = _text()
    out = []
    for name in ("Copy-BinDir", "Restore-BinDir", "Assert-BinDirRestored", "Get-Sha256"):
        start = text.index(f"function {name}(")
        out.append(text[start : text.index("\n}\n", start) + 3])
    return "\n".join(out)


def test_a_restore_removes_the_bin_folder_only_when_the_run_created_it() -> None:
    # GAP-2614: "Nothing was left installed." / "Your previous install is
    # back." left an empty ~\.local\bin after a failed first install or a
    # restored DefenseClaw Setup upgrade.
    body = _bin_dir_functions()
    copy = body[: body.index("function Restore-BinDir(")]
    assert copy.index('(Join-Path $To "NO_BINDIR")') < copy.index("foreach ($name in $ManagedFiles)")
    # A first install also made ~\.local; the restore takes that out too.
    assert "$made += $parent" in copy
    restore = body[body.index("function Restore-BinDir(") :]
    marker = restore.index('$marker = Join-Path $From "NO_BINDIR"')
    # With no bin folder before, the restore never recreates it.
    assert marker < restore.index("New-Item -ItemType Directory -Path $BinDir")
    assert "Remove-Item -LiteralPath $dir -Force" in restore
    assert "-Recurse" not in restore


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("existed", ["none", "parent", "bin"])
def test_restore_bin_dir_puts_the_bin_folder_back_as_it_was(tmp_path: Path, existed: str) -> None:
    bin_dir, slot = tmp_path / "local" / "bin", tmp_path / "slot"
    if existed != "none":
        bin_dir.parent.mkdir()
    if existed == "bin":
        bin_dir.mkdir()
    script = f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{bin_dir}'
$ManagedFiles = @('defenseclaw-gateway.exe')
function Install-File([string]$From, [string]$To) {{ Copy-Item -LiteralPath $From -Destination $To -Force }}
function Remove-Aside([string]$Path) {{ Remove-Item -LiteralPath $Path -Force }}
{_bin_dir_functions()}
Copy-BinDir '{slot}'
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $BinDir 'defenseclaw-gateway.exe') -Value 'new'
Restore-BinDir '{slot}'
"""
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert bin_dir.parent.is_dir() is (existed != "none")
    assert bin_dir.is_dir() is (existed == "bin")
    if existed == "bin":
        assert list(bin_dir.iterdir()) == []


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_file_robocopy_refuses_is_copied_or_named_with_a_next_step(tmp_path: Path) -> None:
    # GAP-1048: robocopy exit 8 on the audit.db a failed 0.8.10 Setup left
    # stopped the upgrade with no cause and no next step.
    source = tmp_path / "data" / "audit.db"
    source.parent.mkdir()
    source.write_text("db", encoding="utf-8")
    slot = tmp_path / "slot"
    slot.mkdir()
    script = f"""
$ErrorActionPreference = 'Stop'
function Invoke-Robocopy([string[]]$Arguments) {{
    [pscustomobject]@{{ Code = 8; Error = 'ERROR 5 (0x00000005) Copying NTFS Security to Destination File Access is denied.' }}
}}
{_ps1_function("Copy-Kept")}
Copy-Kept '{source}' '{slot}'
try {{ Copy-Kept '{source}' '{tmp_path / "missing"}' }} catch {{ Write-Output $_.Exception.Message }}
"""
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (slot / "audit.db").read_text(encoding="utf-8") == "db"
    assert "ERROR 5" in completed.stdout and "then run the installer again" in completed.stdout, completed.stdout


def test_a_stopped_or_undone_install_frees_the_staged_release_first() -> None:
    # GAP-1839/GAP-1841: the 873 MB .staging left no room for the restore or
    # for the old gateway's restart.
    clear = _ps1_function("Clear-StagedRelease")
    assert 'Where-Object { $_.Name -ne "hook-runtime-state.json" }' in clear
    restore = _ps1_function("Restore-Snapshot")
    assert restore.index("Clear-StagedRelease") < restore.index("Restore-Slot $Snap")
    assert "run the installer again to finish restoring it" in restore
    install = _ps1_function("Invoke-Install")
    failed = install[install.index("if (-not $saved) {") :][:500]
    assert failed.index("Clear-StagedRelease") < failed.index("Restart-Old")
    assert "it was not changed, but it is not proven back" in failed
    assert "Finish-InstallLock $code" in _text()
    assert "Close-InstallLock" in _ps1_function("Finish-InstallLock")
    close = _ps1_function("Close-InstallLock")
    assert close.index("Invoke-Quietly { Clear-StagedRelease }") < close.index("Remove-Tree $LockDir")


def test_a_first_install_on_a_full_disk_says_so_and_keeps_no_failed_copy() -> None:
    # GAP-1883: the uv retry blamed a busy host, and a failed first install
    # kept about 2 GB (.failed-*, .venv) that held the disk full.
    uv = _text()[_text().index("function Invoke-UvPipInstall(") :][:1200]
    assert uv.index("if (Test-DiskFull) { return $false }") < uv.index("Retrying the Python package install")
    full = _ps1_function("Test-DiskFull")
    assert "$free -ge 300MB" in full and "then run the installer again" in full
    restore = _ps1_function("Restore-Snapshot")
    first = restore[restore.index("if (-not $PrevVersion) {") :]
    assert first.index("Remove-FailedInstall $failed") < first.index("return") < first.index("was kept in $failed")
    assert 'if (-not $PrevVersion) { return "Nothing was left installed." }' in _ps1_function("Get-RestoredNote")


def test_an_interrupted_setup_upgrade_restarts_the_setup_gateway() -> None:
    # GAP-1839: recovery ran ~\.local\bin\defenseclaw-gateway.exe, which a
    # DefenseClaw Setup install never had ("is not recognized").
    start = _ps1_function("Start-Gateway")
    assert "if (-not (Test-Path -LiteralPath $gateway -PathType Leaf))" in start
    assert start.index("Test-Path -LiteralPath $gateway") < start.index("$rc = Invoke-Native $gateway $startArgs")
    resume = _ps1_function("Resume-InterruptedRun")
    assert 'Start-RecoveredGateway "restored"' in resume and "Start-Gateway)" not in resume
    assert "Start-SetupGateway $setupInstall.Root" in _ps1_function("Start-RecoveredGateway")
    assert "Start-SetupGateway $Setup.Root" in _ps1_function("Restore-SetupInstall")


def test_a_restored_setup_install_keeps_no_failed_copy_or_uv_cache_in_its_data_dir() -> None:
    # GAP-1839: the failed 1.0 copy and the uv cache stayed in Setup's data
    # dir, and Setup's gateway, which walks it all before it starts, then
    # timed out on every start.
    clear = _ps1_function("Clear-SetupDataDir")
    assert "Remove-FailedInstall $Failed" in clear
    assert 'Remove-Tree (Join-Path $DataDir ".uv")' in clear
    restore = _ps1_function("Restore-Snapshot")
    assert restore.index("Restore-Slot $Snap") < restore.index("Clear-SetupDataDir $failed") < restore.index("Restart-Old")
    resume = _ps1_function("Resume-InterruptedRun")
    assert resume.index("Clear-SetupDataDir $failed") < resume.index('Start-RecoveredGateway "restored"')
    assert '} elseif (-not $setupBack) {\n                Write-Warn "The interrupted install was kept in $failed"' in resume


def test_the_uv_folder_is_protected_before_uv_runs_and_before_a_rollback_starts_the_gateway() -> None:
    # GAP-1988: the uv cache and Python in the data dir inherited its
    # permissions, so the 1.0.0 gateway, which re-applies them on every private
    # write, missed its 5-second start window after a rollback to 1.0.0.
    protect = _ps1_function("Protect-UvDirectory")
    assert protect.index("if (-not $Create) { return }") < protect.index("New-Item -ItemType Directory")
    assert "if ($acl.AreAccessRulesProtected) { return }" in protect
    assert "$acl.SetAccessRuleProtection($true, $true)" in protect
    install = _ps1_function("Invoke-Install")
    uv_env = install.index('$env:UV_PYTHON_INSTALL_DIR = Join-Path $DataDir ".uv\\python"')
    assert uv_env < install.index("Protect-UvDirectory -Create") < install.index("$Uv = if ($Run.UnprovenReplacement)")
    rollback = _ps1_function("Invoke-Rollback")
    # GAP-1284: this install's gateway converts its hook entries before the older one is restored.
    assert rollback.index("if ($canConvertHooks)") < rollback.index("Convert-HooksForRollback") < rollback.index("Switch-WithPrevious")
    assert (
        rollback.index("Switch-WithPrevious")
        < rollback.index("Protect-UvDirectory")
        < rollback.index("if ($startAfter -and (Start-Gateway)")
    )


def test_a_rollback_to_1_0_0_starts_its_gateway_on_a_large_wal_audit_db(tmp_path: Path) -> None:
    # GAP-1988: the 1.0.0 gateway refuses a WAL-mode audit.db whose 5-second
    # startup check times out ("SQLite sidecar -wal changed before secure
    # open"), so the installers put the store in rollback-journal mode before
    # they start a gateway older than 1.0.1.
    import sqlite3
    import sys

    ps1 = re.search(r'^\$AuditJournalPy = "([^"]+)"$', _text(), re.M)
    sh_text = (Path(__file__).resolve().parents[2] / "scripts" / "install.sh").read_text(encoding="utf-8")
    sh = re.search(r'^AUDIT_JOURNAL_PY="([^"]+)"$', sh_text, re.M)
    assert ps1 and sh and ps1.group(1) == sh.group(1)
    db = tmp_path / "audit.db"
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        conn.execute("CREATE TABLE audit_events (id TEXT)")
        conn.execute("INSERT INTO audit_events VALUES ('kept')")
    conn.close()
    for _ in range(2):  # a store already in rollback-journal mode is left as it is
        subprocess.run([sys.executable, "-c", ps1.group(1), str(db)], check=True)
        conn = sqlite3.connect(db)
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert conn.execute("SELECT id FROM audit_events").fetchall() == [("kept",)]
        conn.close()
        assert not (tmp_path / "audit.db-wal").exists()
    start = _ps1_function("Start-Gateway")
    guard = 'if ((Test-Version $version) -and [version]$version -lt [version]"1.0.1") { Reset-AuditJournalMode }'
    assert start.index(guard) < start.index("$rc = Invoke-Native $gateway $startArgs")
    sh_start = sh_text[sh_text.index("\nstart_gateway() {") :]
    assert sh_start.index('version_lt "${version}" 1.0.1; then reset_audit_journal_mode; fi') < sh_start.index(
        '"${BIN_DIR}/defenseclaw-gateway" start'
    )


def test_a_rollback_to_0_x_checks_the_saved_stores_and_undoes_itself_when_0_x_stays_down(tmp_path: Path) -> None:
    # GAP-1388: a rollback restored a damaged 0.8.10 audit.db, its gateway
    # could not start, and the agents were left unguarded. Both installers
    # check the saved stores with the same code, without writing beside them.
    import sqlite3
    import sys

    ps1 = re.search(r"^\$RollbackDbCheckPy = @'\n(.*?)'@$", _text(), re.M | re.S)
    sh_text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    sh = re.search(r"^ROLLBACK_DB_CHECK_PY='(.*?)'$", sh_text, re.M | re.S)
    assert ps1 and sh and ps1.group(1) == sh.group(1)
    good, bad = tmp_path / "good.db", tmp_path / "audit.db"
    stores = {}
    for path in (good, bad):
        stores[path] = sqlite3.connect(path)
        stores[path].execute("PRAGMA journal_mode=WAL")
        stores[path].execute("CREATE TABLE audit_events (detail TEXT)")
        stores[path].executemany("INSERT INTO audit_events VALUES (?)", [("x" * 500,)] * 2000)
        stores[path].commit()
    stores[bad].close()
    with bad.open("r+b") as handle:
        handle.seek(4096 * 2)
        handle.write(b"\xff" * 4096 * 3)
    # good.db is still open, with its -wal: the check reads a copy of it.
    before = sorted(p.name for p in tmp_path.iterdir())
    found = subprocess.run(
        [sys.executable, "-I", "-c", sh.group(1), str(good), str(bad), str(tmp_path / "missing.db")],
        capture_output=True,
        text=True,
        check=True,
    )
    after = sorted(p.name for p in tmp_path.iterdir())
    stores[good].close()
    assert found.stdout.splitlines() == [str(bad)], found.stdout + found.stderr
    assert after == before
    rollback = _ps1_function("Invoke-Rollback")
    assert (
        rollback.index("Test-RollbackData $backTo")
        < rollback.index("Stop-Gateway")
        < rollback.index("Switch-WithPrevious")
        < rollback.index("Move-DamagedAuditStore $backTo")
        < rollback.index("if ($startAfter -and (Start-Gateway)")
        < rollback.index('return Undo-Rollback "DefenseClaw $backTo is not proven running')
    )
    undo = _ps1_function("Undo-Rollback")
    assert undo.index("Switch-WithPrevious $BackTo") < undo.index("Start-Gateway") < undo.rindex("return 1")


def test_install_folders_set_only_the_acl_part_that_changed() -> None:
    # GAP-2004: Set-Acl writes every part of the security descriptor and was
    # refused for a standard user on a second NTFS volume, so a
    # DEFENSECLAW_HOME there died with a raw PowerShell error.
    helper = _text()[_text().index("function Set-DirectoryAcl(") :][:600]
    assert "$dir.SetAccessControl($Acl)" in helper
    assert "[IO.FileSystemAclExtensions]::SetAccessControl($dir, $Acl)" in helper
    new_dir = _text()[_text().index("function New-InstallDirectory(") :][:900]
    assert "Set-Acl" not in new_dir
    assert 'catch { Die "Could not set the permissions of ${Path}:' in new_dir
    assert "Set-Acl" not in _ps1_function("Protect-UvDirectory")
    assert "Set-DirectoryAcl $DataDir $acl" in _ps1_function("Invoke-Install")


def test_the_last_uv_hint_names_both_lock_errors() -> None:
    # GAP-2025: a held uv cache file fails with os error 5 as well as 32.
    assert "file in use or access denied (os error 32 or 5)" in _text()[_text().index("function Invoke-UvPipInstall(") :][:1300]


def test_tree_sizes_do_not_read_sum_from_measure_object() -> None:
    # GAP-2616: under StrictMode, Measure-Object over no files has no .Sum, so
    # the space refusal on a fresh first install (no or an empty .uv) crashed.
    assert "Measure-Object -Property Length -Sum" not in _text()
    assert "$bytes = Get-TreeSize $uvDir" in _ps1_function("Write-KeptUvCache")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("cache", ["missing", "empty", "one-file"])
def test_write_kept_uv_cache_runs_under_strict_mode(tmp_path: Path, cache: str) -> None:
    if cache != "missing":
        (tmp_path / ".uv").mkdir()
    if cache == "one-file":
        (tmp_path / ".uv" / "wheel").write_bytes(b"x" * 2048)
    tree = _text()[_text().index("function Get-TreeSize(") :]
    tree = tree[: tree.index("\n}\n") + 3]
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path}'\nfunction Write-Info([string]$m) {{ 'info: ' + $m }}\n"
        f"{tree}\n{_ps1_function('Write-KeptUvCache')}\nWrite-KeptUvCache\n'done'\n"
    )
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = completed.stdout.strip().splitlines()
    assert lines[-1] == "done"
    assert any("download cache" in line for line in lines) == (cache == "one-file")


def test_a_failed_first_install_names_the_kept_uv_cache_and_a_full_disk() -> None:
    # GAP-1883: the space refusal and a staging failure kept the uv cache
    # silently, and a disk that filled at the binary copy showed only the
    # raw .NET text.
    assert "Write-KeptUvCache" in _ps1_function("Restore-Snapshot")
    room = _text()[_text().index("function Assert-InstallRoom(") :][:1400]
    assert room.index("if (-not $PrevVersion) { Write-KeptUvCache }") < room.index("Die (")
    install = _ps1_function("Invoke-Install")
    staging = install[install.index('(New-Venv (Join-Path $Staging "venv")') :][:300]
    assert staging.index("Write-KeptUvCache") < staging.index("Die ")
    assert "Write-Err $_.Exception.Message; [void](Test-DiskFull); $installed = $false" in install
    assert "Write-Err $_.Exception.Message; [void](Test-DiskFull); $saved = $false" in install


def test_an_interrupted_first_install_leaves_no_new_files_or_failed_copy() -> None:
    # GAP-2618: a first install killed mid-copy left ~\.local\bin\*.new (so
    # ~\.local\bin and ~\.local stayed), a .failed-<time> copy of a venv that
    # never was an install, and "restoring the install it replaced".
    restore = _bin_dir_functions()
    restore = restore[restore.index("function Restore-BinDir(") :]
    no_bin = restore[: restore.index("New-Item -ItemType Directory -Path $BinDir")]
    assert '(Join-Path $BinDir "$name.new")' in no_bin
    resume = _ps1_function("Resume-InterruptedRun")
    first = resume.index('$firstInstall = -not (Read-Text (Join-Path $slot "VERSION"))')
    assert first < resume.index("$failed = Restore-Slot $slot")
    assert "An earlier first install was interrupted; removing what it had copied" in resume
    assert resume.index("$failed = Restore-Slot $slot") < resume.index(
        "if ($firstInstall -and -not $setupBack) { Invoke-Quietly { Remove-FailedInstall $failed } }"
    )
    assert 'Write-Info "Nothing was left installed"' in resume


# ── 1.0.2 (FG-01) ───────────────────────────────────────────────────────────


def _lifecycle_record(path: Path, running: bool = True) -> None:
    # The lifecycle record (Write-LifecycleManifest) a run writes before its
    # first change, here with no binaries recorded.
    path.write_text(json.dumps({
        "Schema": 1, "Operation": "upgrade", "From": "1.0.3", "To": "1.0.4", "Slot": "", "SetupRoot": "",
        "Bins": {}, "GatewayWasRunning": running, "Connectors": [], "Config": "", "ExternalConfig": "",
        "ExternalConfigSha256": "", "HookFailModes": "", "BinDirProtected": False, "Committed": False,
    }), encoding="utf-8")


_TXN_REAL = ("Write-DurableText", "ConvertTo-Map", "Get-BinariesState", "Get-OptionalSha256", "Get-GuardedConnectors",
             "Read-LifecycleManifest", "New-RecoveryManifest", "Remove-LifecycleManifest", "Test-LifecycleProof",
             "Set-RecoveryPending", "Set-RecoverySetupRoot", "Wait-LifecycleProof", "Get-LifecycleNextStep", "Assert-LifecycleRestored",
             "Close-AllHooks", "Save-LifecycleCloser", "Test-SameBinaries", "Read-Json", "Get-ConfiguredConnectors",
             "Get-Field", "Get-Sha256", "Get-ExternalConfig")


def _txn_real_functions() -> str:
    return "\n".join(_ps1_function(name) for name in _TXN_REAL)


_TXN_PRELUDE = (
    "$LifecycleProofSeconds = 0\n"
    "$ManagedBinaries = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')\n"
    "$LifecycleManifest = Join-Path $DataDir '.lifecycle-txn.json'\n"
    "if (-not (Get-Variable -Name Run -ErrorAction SilentlyContinue)) { $Run = @{ RestorePending = $false; UndoPending = $false } }\n"
    "$Local = ''\n"
    "function Get-GatewayHealthReport { if (Get-GatewayProcess) { return [pscustomobject]@{ running = $true; health = $null } }; return $null }\n"
    "function Get-GatewayDigestProblem { return 'unsupported' }\n"
    "function Test-BinDirProtected { return $true }\n"
)


def _run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    # A script of extracted installer functions can pass Windows' 32,767
    # character command-line limit (WinError 206), so the text goes through a
    # file kept outside the test's data folders. It still runs as a -Command
    # script, dot-sourced from a script block: it has no script path, as the
    # installer has none when run from `irm | iex`, so Get-LifecycleNextStep
    # names the release's installer. ReadAllText reads the BOM'd UTF-8.
    with tempfile.TemporaryDirectory(prefix="dc-ps1-test-") as case:
        path = Path(case) / "case.ps1"
        path.write_text(script, encoding="utf-8-sig")
        command = f". ([scriptblock]::Create([IO.File]::ReadAllText('{path}')))"
        return subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("snapshot", ["complete", "incomplete", "no-snapshot", "rollback"])
def test_interrupted_recovery_refuses_to_continue_when_the_gateway_cannot_start(
    tmp_path: Path, snapshot: str
) -> None:
    # GAP-0444: losing the saved running state let the resumed install skip
    # its health gate and report success with the gateway still down.
    # "no-snapshot": the run was cut off after it wrote its lifecycle record
    # and stopped the gateway, but before its snapshot began.
    if snapshot == "no-snapshot":
        _lifecycle_record(tmp_path / ".lifecycle-txn.json")
    else:
        slot = tmp_path / (".rollback-hold" if snapshot == "rollback" else "previous.new")
        slot.mkdir()
        (slot / "GATEWAY_WAS_RUNNING").write_text("true", encoding="ascii")
        (slot / "VERSION").write_text("1.0.3", encoding="ascii")
        if snapshot == "complete":
            (slot / "COMPLETE").touch()
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = Join-Path $DataDir 'bin'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
{_ps_functions("Invoke-Native")}
$global:LASTEXITCODE = 0
$failedLaunch = Invoke-Native (Join-Path $DataDir 'missing-gateway.exe') -Quiet
$successfulLaunch = Invoke-Native '{POWERSHELL}' @('-NoProfile', '-NonInteractive', '-Command', 'exit 0') -Quiet
Write-Output "FAILED_LAUNCH=$failedLaunch SUCCESSFUL_LAUNCH=$successfulLaunch"
$script:starts = 0
$script:startCode = 1
$script:running = $false
$ManagedBinaries = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')
$LifecycleManifest = Join-Path $DataDir '.lifecycle-txn.json'
$Run = @{{ RestorePending = $false; UndoPending = $false }}
$Local = ''
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Stop-Gateway {{ $script:running = $false; return $true }}
function Get-GatewayProcess {{ if ($script:running) {{ return [pscustomobject]@{{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}; return $null }}
function Start-Gateway {{ $script:starts++; if ($script:startCode -in @(0, 3)) {{ $script:running = $true }}; return $script:startCode }}
function Get-GatewayHealthReport {{ return [pscustomobject]@{{ running = $script:running; health = $null }} }}
function Get-GatewayDigestProblem {{ return 'unsupported' }}
function Test-BinDirProtected {{ return $true }}
{chr(10).join(_ps1_function(name) for name in ('Write-DurableText', 'ConvertTo-Map', 'Get-BinariesState', 'Get-OptionalSha256',
    'Get-GuardedConnectors', 'Read-LifecycleManifest', 'New-RecoveryManifest', 'Remove-LifecycleManifest', 'Test-LifecycleProof',
    'Set-RecoveryPending', 'Set-RecoverySetupRoot', 'Wait-LifecycleProof', 'Get-LifecycleNextStep', 'Assert-LifecycleRestored', 'Get-Field', 'Get-Sha256',
    'Close-AllHooks', 'Save-LifecycleCloser', 'Test-SameBinaries'))}
$LifecycleProofSeconds = 0
function Find-SetupInstall {{ return $null }}
function Die([string]$Message) {{ throw $Message }}
function Undo-HookFirst {{ }}
function Restore-LiveTree {{ }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Restore-Slot([string]$Slot) {{ Remove-Tree $Slot; return (Join-Path $DataDir '.failed-test') }}
{_ps_functions("Read-Text", "Undo-Snapshot", "Remove-Hold", "Start-RecoveredGateway")}
{_ps1_function("Resume-InterruptedRun")}
foreach ($attempt in 1..2) {{
    try {{ Resume-InterruptedRun; Write-Output 'CONTINUED' }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
}}
$script:startCode = 3
Resume-InterruptedRun
Write-Output 'RECOVERED'
Write-Output "STARTS=$script:starts"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "CONTINUED" not in out and "REFUSED:" in out, out
    assert out.count("REFUSED:") == 2 and "defenseclaw-gateway start" in out, out
    assert "STARTS=3" in out and "RECOVERED" in out, out
    assert "FAILED_LAUNCH=0 " not in out and "SUCCESSFUL_LAUNCH=0" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    "case, accepted, override_accepted, hint",
    [
        # The gateway proves it enforces the edited config: kept as it is now.
        ("config-edited", True, True, False),
        ("config-edited-connector-removed", True, True, False),
        # An older restored gateway cannot report the digest: only the override keeps it.
        ("config-edited-old-gateway", False, True, True),
        # A guarded connector is gone while the config still names it.
        ("connector-removed", False, True, True),
        # The config edit (a new port) proves nothing about a connector the
        # gateway still lists, or the live config still enables, but does
        # not guard.
        ("config-edited-connector-error", False, True, True),
        ("config-edited-connector-in-config", False, True, True),
        # Review (loop round 3): a connector the live config turned off on
        # purpose is accepted once the gateway enforces that config, though
        # its name is still in the YAML or in a restored active_connector.json.
        ("config-edited-connector-disabled", True, True, False),
        ("config-edited-guardrail-disabled", True, True, False),
        ("config-edited-connector-still-active", True, True, False),
        # An effective roster that cannot be read keeps every connector.
        ("config-edited-roster-unreadable", False, True, True),
        # Trust and health checks are never waived.
        ("config-edited-gateway-rejects-config", False, False, False),
        ("config-edited-gateway-down", False, False, False),
        ("config-edited-bin-dir-open", False, False, False),
    ],
)
def test_a_lifecycle_record_that_outlived_its_restore_accepts_later_changes_only_once_proven(
    tmp_path: Path, case: str, accepted: bool, override_accepted: bool, hint: bool
) -> None:
    # A restore whose gateway did not start (a port clash) left its record
    # with no snapshot. The user then fixed the cause by editing config.yaml,
    # or removed a connector: the record still demanded the recorded config
    # bytes and every recorded connector, so every later install, upgrade,
    # repair and rollback refused, until the record was deleted by hand.
    data = tmp_path / "data"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    data.mkdir()
    gateway = bin_dir / "defenseclaw-gateway.exe"
    gateway.write_bytes(b"gateway 1.0.3")
    gateway_sha = hashlib.sha256(gateway.read_bytes()).hexdigest()
    config = data / "config.yaml"
    config.write_text("gateway:\n  port: 18970\n", encoding="utf-8")
    config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
    record = {
        "Schema": 1, "Operation": "upgrade", "From": "1.0.3", "To": "1.0.4", "Slot": "", "SetupRoot": "",
        "Bins": {"defenseclaw-gateway.exe": gateway_sha}, "GatewayWasRunning": True,
        "Connectors": ["claudecode", "codex"], "Config": config_sha, "ExternalConfig": "",
        "ExternalConfigSha256": "", "HookFailModes": "", "BinDirProtected": True, "Committed": False,
    }
    if "config-edited" in case:
        config.write_text("gateway:\n  port: 18971\n", encoding="utf-8")
    if "in-config" in case:
        config.write_text(
            "gateway:\n  port: 18971\nguardrail:\n  enabled: true\n  connectors:\n    claudecode: {}\n"
            "    codex: {mode: observe}\n",
            encoding="utf-8",
        )
    if "connector-disabled" in case:
        config.write_text(
            "gateway:\n  port: 18971\nguardrail:\n  enabled: true\n  connectors:\n    claudecode: {}\n"
            "    codex: {enabled: false}\n",
            encoding="utf-8",
        )
    if "guardrail-disabled" in case:
        config.write_text(
            "gateway:\n  port: 18971\nguardrail:\n  enabled: false\n  connectors:\n    claudecode: {}\n"
            "    codex: {}\n",
            encoding="utf-8",
        )
    if "still-active" in case:
        (data / "active_connector.json").write_text(json.dumps({"names": ["claudecode", "codex"]}), encoding="utf-8")
    states = {"claudecode": "running", "codex": "running"}
    if any(part in case for part in ("connector-removed", "still-active", "in-config", "connector-disabled", "roster-unreadable")):
        del states["codex"]
    if "guardrail-disabled" in case:
        states = {}
    if "connector-error" in case:
        states["codex"] = "error"
    if "roster-unreadable" in case:
        roster_function = "function Get-EffectiveConfigConnectors { throw 'no checked Python environment' }"
    else:
        roster = ", ".join(f"'{name}'" for name in _effective_config_roster(config))
        roster_function = f"function Get-EffectiveConfigConnectors {{ return @({roster}) }}"
    digest = {"old-gateway": "unsupported", "rejects-config": "the gateway rejected the live config"}
    digest_result = next((v for k, v in digest.items() if k in case), "")
    results = []
    for override in (False, True):
        manifest = data / ".lifecycle-txn.json"
        manifest.write_text(json.dumps(record), encoding="utf-8")
        script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = '{bin_dir}'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$AcceptCurrentInstall = ${str(override).lower()}
function Write-Warn([string]$Message) {{ Write-Host "WARN: $Message" }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Find-SetupInstall {{ return $null }}
function Die([string]$Message) {{ throw $Message }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Start-RecoveredGateway {{ }}
{_resume_functions("Read-Text", "Resume-InterruptedRun")}
{_txn_real_functions()}
{_TXN_PRELUDE}
function Get-GatewayProcess {{
    if ('{case}' -like '*gateway-down') {{ return $null }}
    return [pscustomobject]@{{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
}}
function Get-GatewayHealthReport {{
    $entries = @({", ".join(f"[pscustomobject]@{{ name = '{c}'; state = '{v}' }}" for c, v in states.items())})
    return [pscustomobject]@{{ running = $true; health = [pscustomobject]@{{ connectors = $entries }} }}
}}
function Get-GatewayDigestProblem {{ return '{digest_result}' }}
function Test-BinDirProtected {{ return -not ('{case}' -like '*bin-dir-open') }}
{roster_function}
try {{ Resume-InterruptedRun; Write-Output 'ACCEPTED' }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
Write-Output "RECORD=$(Test-Path -LiteralPath $LifecycleManifest)"
"""
        completed = _run_powershell(script)
        out = completed.stdout + completed.stderr
        assert completed.returncode == 0, out
        results.append(out)
    plain, overridden = results
    for out, want in ((plain, accepted), (overridden, override_accepted)):
        if want:
            assert "ACCEPTED" in out and "REFUSED" not in out and "RECORD=False" in out, out
            assert "accepted as it is now" in out, out
        else:
            assert "REFUSED: The previous install is not proven back" in out and "RECORD=True" in out, out
    assert ("-AcceptCurrentInstall" in plain) == hint, plain
    if hint:
        # A command that runs as given however the installer ran: the
        # release's installer, not a deleted temporary copy.
        assert "& ([scriptblock]::Create((irm '" in plain and "-Yes -AcceptCurrentInstall" in plain, plain
    if accepted:
        assert "its gateway enforces the live config" in plain, plain
    elif override_accepted:
        assert "(-AcceptCurrentInstall)" in overridden, overridden


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("gateway_running", [True, False])
@pytest.mark.parametrize("replaced", ["gateway", "hook-added", "hook-removed", "gateway-removed-hook-left"])
def test_a_lifecycle_record_whose_programs_an_older_installer_replaced_has_a_way_out_that_never_starts_them(
    tmp_path: Path, gateway_running: bool, replaced: str
) -> None:
    # A restore whose gateway did not start left its record. An older
    # installer (`defenseclaw upgrade --version 1.0.2`, or its one-liner)
    # does not read the record: it cleared the stale lock and installed its
    # own programs. Every later run refused "not proven back", and
    # -AcceptCurrentInstall could not clear it, so the install stayed blocked
    # until the record was deleted by hand. The replaced programs are never
    # started: the switch retires the record and the run installs over them.
    data = tmp_path / "data"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    data.mkdir()
    gateway = bin_dir / "defenseclaw-gateway.exe"
    hook = bin_dir / "defenseclaw-hook.exe"
    gateway.write_bytes(b"gateway 1.0.3")
    hook.write_bytes(b"hook 1.0.3")
    bins = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (gateway, hook)}
    if replaced in ("hook-added", "gateway-removed-hook-left"):
        del bins["defenseclaw-hook.exe"]
    record = {
        "Schema": 1, "Operation": "upgrade", "From": "1.0.3", "To": "1.0.4", "Slot": "", "SetupRoot": "",
        "Bins": bins, "GatewayWasRunning": True, "Connectors": ["codex"], "Config": "", "ExternalConfig": "",
        "ExternalConfigSha256": "", "HookFailModes": "", "BinDirProtected": True, "Committed": False,
    }
    if replaced == "gateway":
        gateway.write_bytes(b"gateway 1.0.2")
    elif replaced == "hook-removed":
        hook.unlink()
    elif replaced == "gateway-removed-hook-left":
        gateway.unlink()
    results = {}
    for name, override, rollback in (("plain", False, False), ("accept", True, False), ("rollback", True, True)):
        manifest = data / ".lifecycle-txn.json"
        manifest.write_text(json.dumps(record), encoding="utf-8")
        script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = '{bin_dir}'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$AcceptCurrentInstall = ${str(override).lower()}
$Rollback = ${str(rollback).lower()}
$Ver = '1.0.4'
$ReleaseBase = 'https://github.com/cisco-ai-defense/defenseclaw'
$script:starts = 0
function Write-Warn([string]$Message) {{ Write-Host "WARN: $Message" }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Find-SetupInstall {{ return $null }}
function Die([string]$Message) {{ throw $Message }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Start-RecoveredGateway {{ $script:starts++ }}
{_resume_functions("Read-Text", "Resume-InterruptedRun")}
{_txn_real_functions()}
{_TXN_PRELUDE}
function Get-GatewayProcess {{
    if (-not ${str(gateway_running).lower()}) {{ return $null }}
    return [pscustomobject]@{{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
}}
function Get-GatewayDigestProblem {{ return '' }}
try {{ Resume-InterruptedRun; Write-Output 'CONTINUED' }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
Write-Output "RECORD=$(Test-Path -LiteralPath $LifecycleManifest) STARTS=$script:starts PENDING=$($Run.RestorePending)"
"""
        completed = _run_powershell(script)
        out = completed.stdout + completed.stderr
        assert completed.returncode == 0, out
        assert "STARTS=0" in out, out
        results[name] = out
    plain = results["plain"]
    assert "REFUSED: The previous install is not proven back" in plain and "RECORD=True" in plain, plain
    # Nothing was recovered or stopped: the refusal keeps the record but
    # does not lock the install over the other installer's programs.
    assert "PENDING=False" in plain and "they are not started" in plain, plain
    assert (
        "& ([scriptblock]::Create((irm 'https://github.com/cisco-ai-defense/defenseclaw/releases/download/1.0.4/install.ps1')))"
        " -Version '1.0.4' -Yes -AcceptCurrentInstall"
    ) in plain, plain
    accepted = results["accept"]
    assert "CONTINUED" in accepted and "RECORD=False" in accepted and "REFUSED" not in accepted, accepted
    assert "its record is retired (-AcceptCurrentInstall)" in accepted, accepted
    rolled = results["rollback"]
    assert "REFUSED: The previous install is not proven back" in rolled and "RECORD=True" in rolled, rolled


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("gateway_running", [True, False])
@pytest.mark.parametrize("case", [
    "empty-record", "replaced", "replaced-after-rollback", "restore-unproven", "closer-missing", "rollback-unproven",
])
def test_every_interrupted_recovery_refusal_closes_the_hooks_or_releases_the_lock(
    tmp_path: Path, case: str, gateway_running: bool
) -> None:
    # .install.lock stops hooks from cold-starting a gateway, so while it is
    # held they follow their outage mode, which the config may set open. A
    # refusal in Resume-InterruptedRun must therefore end in one of two
    # states: the gateway down with every hook closed by this run, or the
    # lock released (the record stays and names the retry). It must never
    # keep the lock over a running gateway whose hooks it did not close
    # (a 1.0.3 install another installer put in place, or a restored gateway
    # whose proof failed): after a crash or reboot that lock lets every call
    # through in open mode. A refusal that changed nothing stops nothing.
    data = tmp_path / "data"
    bin_dir = tmp_path / "bin"
    (data / "hooks").mkdir(parents=True)
    bin_dir.mkdir()
    gateway = bin_dir / "defenseclaw-gateway.exe"
    hook = bin_dir / "defenseclaw-hook.exe"
    gateway.write_bytes(b"gateway 1.0.3")
    hook.write_bytes(b"hook 1.0.3")
    bins = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (gateway, hook)}
    record = {
        "Schema": 1, "Operation": "upgrade", "From": "1.0.3", "To": "1.0.4", "Slot": "", "SetupRoot": "",
        "Bins": bins, "GatewayWasRunning": True, "Connectors": [], "Config": "", "ExternalConfig": "",
        "ExternalConfigSha256": "", "HookFailModes": "", "BinDirProtected": True, "Committed": False,
    }
    changed = case in ("replaced-after-rollback", "restore-unproven", "closer-missing", "rollback-unproven")
    if case == "empty-record":
        record["Bins"] = {}
        record["GatewayWasRunning"] = False
    elif case in ("replaced", "replaced-after-rollback"):
        gateway.write_bytes(b"gateway 1.0.3 put in place by the 1.0.3 one-liner")
        if case == "replaced-after-rollback":
            (data / ".rollback-hold").mkdir()
            (data / ".rollback-hold" / "ROLLED_BACK").touch()
    elif case == "closer-missing":
        record["Bins"] = {}
        record["GatewayWasRunning"] = False
        record["UnprovenReplacement"] = True
        slot = data / "previous.new"
        slot.mkdir()
        (slot / "COMPLETE").touch()
    elif case == "rollback-unproven":
        record["Operation"] = "rollback"
        record["TargetBins"] = bins
        record["StartAfter"] = True
    (data / ".lifecycle-txn.json").write_text(json.dumps(record), encoding="utf-8")
    script = f"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = '{bin_dir}'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$LifecycleCloser = Join-Path $DataDir '.lifecycle-closer'
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
$AcceptCurrentInstall = $false
$Rollback = $false
$Ver = '1.0.4'
$ReleaseBase = 'https://github.com/cisco-ai-defense/defenseclaw'
$Run = @{{ Lock = $true; RestorePending = $false; UndoPending = $false; UnprovenReplacement = $null;
    UnprovenReplacementUnchanged = $false }}
$script:running = ${str(gateway_running).lower()}
$script:stops = 0; $script:closes = 0; $script:starts = 0; $script:warnings = @()
function Write-Warn([string]$Message) {{ $script:warnings += $Message; Write-Host "WARN: $Message" }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Write-Err([string]$Message) {{ Write-Host "ERR: $Message" }}
function Find-SetupInstall {{ return $null }}
function Die([string]$Message) {{ throw $Message }}
function Invoke-Quietly([scriptblock]$Action) {{ try {{ & $Action }} catch {{ Write-Warn $_.Exception.Message }} }}
function Clear-StagedRelease {{ }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Stop-Gateway {{ $script:stops++; $script:running = $false; return $true }}
function Stop-UnprovenGateway {{ $script:stops++; $script:running = $false }}
function Start-RecoveredGateway {{ $script:starts++; throw 'The recovered gateway did not become healthy' }}
function Restore-Slot {{ throw 'the snapshot was restored before the refusal' }}
function Start-HookFailModeHold {{ return $true }}
function Get-NativeProbe {{
    param($FilePath, $Arguments)
    if (($Arguments -join ' ') -eq 'connector refresh-fail-modes --help') {{ return [pscustomobject]@{{ Exit = 0; Output = '--closed' }} }}
    return [pscustomobject]@{{ Exit = 1; Output = '' }}
}}
function Invoke-Native {{
    param($FilePath, $Arguments, [switch]$Quiet)
    if (($Arguments -join ' ') -like 'connector refresh-fail-modes --closed*') {{ $script:closes++; return 0 }}
    return 1
}}
{_resume_functions("Read-Text", "Get-InstallGatewayState", "Stop-UnprovenRecoveryGateway", "Test-RecoveryPending",
                   "Close-InstallLock", "Finish-InstallLock", "Close-UnfinishedInstallHooks", "Resume-InterruptedRun")}
function Get-ProcessesUnder {{ return @() }}
{_txn_real_functions()}
{_TXN_PRELUDE}
function Get-GatewayProcess {{
    if (-not $script:running) {{ return $null }}
    return [pscustomobject]@{{ Id = 4242; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
}}
# The running gateway does not pass its health check: the proof fails.
function Get-GatewayHealthReport {{ if (Get-GatewayProcess) {{ return [pscustomobject]@{{ running = $false; health = $null }} }}; return $null }}
$code = 0
try {{ Resume-InterruptedRun; Write-Output 'CONTINUED' }} catch {{
    Write-Output "REFUSED: $($_.Exception.Message)"
    # Invoke-Install's catch around Resume-InterruptedRun.
    if (-not $Run.UnprovenReplacementUnchanged) {{ Set-RecoveryPending }}
    $code = 1
}}
Finish-InstallLock $code
Write-Output "LOCK=$(Test-Path -LiteralPath $LockDir) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) RUNNING=$script:running STOPS=$script:stops CLOSES=$script:closes"
Write-Output "LAST_WARNING=$(if ($script:warnings.Count) {{ $script:warnings[-1] }})"
"""
    # A file, not -Command: the script is longer than a Windows command line.
    path = tmp_path / "refusal.ps1"
    path.write_text(script, encoding="utf-8-sig")
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "REFUSED:" in out and "CONTINUED" not in out, out
    assert "RECORD=True" in out, out
    assert "the snapshot was restored before the refusal" not in out, out
    if gateway_running:
        # The refusal left the running gateway alone, and it does not keep
        # a lock over that gateway's unclosed hooks.
        assert "RUNNING=True STOPS=0" in out, out
        assert "LOCK=False" in out, out
        if changed:
            assert "the install lock is released" in out.split("LAST_WARNING=")[1], out
            assert "-Version '1.0.4' -Yes" in out.split("LAST_WARNING=")[1], out
    elif changed:
        # The install is down and unfinished: the lock stays only with every
        # hook closed by this run.
        assert "LOCK=True" in out, out
        assert "CLOSES=0" not in out, out
    else:
        # Nothing was changed: no lock, no closing of the other install's hooks.
        assert "LOCK=False" in out and "CLOSES=0" in out and "STOPS=0" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("gateway", ["running", "running-without-id", "down"])
def test_a_failed_run_never_keeps_the_lock_over_a_running_gateway(tmp_path: Path, gateway: str) -> None:
    # Finish-InstallLock is the one place a failed run decides the lock. A
    # gateway that still runs at the end renders its own hooks again, whatever
    # this run closed before (no closed hold outlives the run), so the lock
    # goes and the record stays. Only a gateway that is down keeps the lock,
    # with every hook closed.
    image = "(Join-Path $BinDir 'defenseclaw-gateway.exe')"
    process = {"running": f"[pscustomobject]@{{ Id = 4242; Path = {image} }}",
               "running-without-id": f"[pscustomobject]@{{ Path = {image} }}", "down": "$null"}[gateway]
    result = _txn_harness(tmp_path, _ps1_function("Close-InstallLock") + _ps1_function("Finish-InstallLock") + f"""
$Run.Lock = $true
$Run.RestorePending = $true
$Run.UnprovenReplacement = $true
$Run.UnprovenReplacementUnchanged = $false
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
[IO.File]::WriteAllText($LifecycleManifest, '{{"Schema":1,"Bins":{{}}}}')
$Ver = '1.0.4'
$script:gateway = {process}
$script:warnings = @()
$script:cleanupCloses = 0
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Invoke-Quietly {{ param([scriptblock]$Action) & $Action }}
function Close-UnfinishedInstallHooks {{ $script:cleanupCloses++; return $true }}
function Clear-StagedRelease {{ }}
function Test-RecoveryPending {{ return [bool]($Run.UndoPending -or $Run.RestorePending) }}
function Remove-Tree {{ param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }}
Finish-InstallLock 1
"LOCK=$(Test-Path -LiteralPath $LockDir) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) CLEANUP=$script:cleanupCloses"
"LAST_WARNING=$($script:warnings[-1])"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "RECORD=True" in out and "CLEANUP=1" in out, out
    if gateway == "down":
        assert "LOCK=True" in out, out
    else:
        assert "LOCK=False" in out, out
        warning = out.split("LAST_WARNING=")[1]
        assert "the install lock is released" in warning and "-AcceptCurrentInstall" in warning, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    "case",
    ["down", "stale-pid", "image-without-pid", "renamed-aside", "setup-image", "started-after-close",
     "pid-unreadable", "process-list-fails", "pid-image-unreadable", "close-fails", "nothing-unfinished"],
)
def test_a_failed_run_keeps_the_lock_only_on_proof_its_gateway_is_down_and_hooks_closed(
    tmp_path: Path, case: str
) -> None:
    # r104 Windows loop round 3: a failed stop or recovery can leave this
    # install's gateway (or its watchdog) running with gateway.pid gone or
    # unreadable. The lock used to stay then, and once that gateway exited
    # the hooks followed their outage mode (open, if the config says so)
    # instead of cold-starting it. The lock now stays only when the run
    # closed every hook and, afterwards, no process of this install's
    # gateway image runs; an unknown state releases it, like a running one.
    result = _txn_harness(tmp_path, _resume_functions("Get-InstallGatewayState", "Test-RecoveryPending", "Close-InstallLock",
                                                      "Finish-InstallLock", "Close-UnfinishedInstallHooks") + f"""
$Previous = Join-Path $DataDir 'previous'
$Staging = Join-Path $DataDir '.staging'
$Run.Lock = $true
$Run.RestorePending = $true
$Run.UnprovenReplacement = $null
$Run.UnprovenReplacementUnchanged = $false
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
if ('{case}' -ne 'nothing-unfinished') {{
    [void][IO.Directory]::CreateDirectory((Join-Path $DataDir 'previous.new'))
    [IO.File]::WriteAllText($LifecycleManifest, '{{"Schema":1,"Bins":{{}}}}')
}}
$gatewayImage = Join-Path $BinDir 'defenseclaw-gateway.exe'
[IO.File]::WriteAllText($gatewayImage, 'new gateway')
$Ver = '1.0.4'
$script:warnings = @()
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Write-Err {{ param($Message) $script:warnings += "ERR $Message" }}
function Invoke-Quietly {{ param([scriptblock]$Action) try {{ & $Action }} catch {{ Write-Warn $_.Exception.Message }} }}
function Clear-StagedRelease {{ }}
function Remove-Tree {{ param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }}
$pidFile = Join-Path $DataDir 'gateway.pid'
switch ('{case}') {{
    'stale-pid' {{ [IO.File]::WriteAllText($pidFile, 'not a pid') }}
    'image-without-pid' {{ $script:images = @([pscustomobject]@{{ ProcessId = 77; Name = 'defenseclaw-gateway.exe'; ExecutablePath = $gatewayImage }}) }}
    'renamed-aside' {{ $script:images = @([pscustomobject]@{{ ProcessId = 78; Name = 'defenseclaw-gateway.exe.old-20261023T000000000'; ExecutablePath = "$gatewayImage.old-20261023T000000000" }}) }}
    'setup-image' {{
        $Setup = [pscustomobject]@{{ Root = (Join-Path $DataDir 'Setup') }}
        $script:images = @([pscustomobject]@{{ ProcessId = 79; ExecutablePath = (Join-Path $Setup.Root 'bin\\defenseclaw-gateway.exe') }})
    }}
    'started-after-close' {{
        # The watchdog starts the gateway again once the hooks are closed.
        function Invoke-Native {{ param($FilePath, $Arguments, [switch]$Quiet)
            $script:closes++
            $script:images = @([pscustomobject]@{{ ProcessId = 80; ExecutablePath = $gatewayImage }})
            return 0
        }}
    }}
    'pid-unreadable' {{ function Get-GatewayProcess {{ throw 'gateway.pid is in use by another process' }} }}
    'process-list-fails' {{ function Get-ProcessesUnder {{ throw 'Access denied' }} }}
    'pid-image-unreadable' {{
        [IO.File]::WriteAllText($pidFile, '{{"pid": 4242, "executable": "elsewhere"}}')
        function Get-Process {{ return [pscustomobject]@{{ Id = 4242; ProcessName = 'defenseclaw-gateway'; Path = $null }} }}
    }}
    'close-fails' {{ function Invoke-Native {{ param($FilePath, $Arguments, [switch]$Quiet) $script:closes++; return 1 }} }}
}}
Finish-InstallLock 1
"LOCK=$(Test-Path -LiteralPath $LockDir) PENDING=$([bool]$Run.RestorePending) CLOSES=$script:closes"
"LAST_WARNING=$(if ($script:warnings.Count) {{ $script:warnings[-1] }})"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    warning = out.split("LAST_WARNING=")[1]
    if case in ("down", "stale-pid"):
        assert "LOCK=True PENDING=True CLOSES=1" in out, out
        assert "The install stays locked" in warning, out
        return
    if case == "close-fails":
        # GAP-1403: the record is still pending with the gateway down, so the
        # lock stays although the hooks could not be closed.
        assert "LOCK=True PENDING=True" in out and "CLOSES=0" not in out, out
        assert "The install stays locked" in warning, out
        return
    assert "LOCK=False PENDING=False" in out, out
    assert "the install lock is released" in warning, out
    if case in ("image-without-pid", "renamed-aside", "setup-image", "started-after-close"):
        assert "its gateway is still running" in warning, out
    elif case in ("pid-unreadable", "process-list-fails", "pid-image-unreadable"):
        assert "cannot tell whether its gateway is still running" in warning, out
    else:
        assert "could not prove every agent hook closed" in warning, out
    if case in ("image-without-pid", "renamed-aside", "setup-image", "pid-unreadable", "process-list-fails",
                "pid-image-unreadable", "nothing-unfinished"):
        # No hook is closed under a gateway that may still render them.
        assert "CLOSES=0" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["journal-held-gateway", "journal-held-gateway-accept", "no-journal-close-fails",
                                  "journal-gateway-running"])
def test_a_held_gateway_retry_keeps_the_lock_while_the_lifecycle_record_is_pending(tmp_path: Path, case: str) -> None:
    # GAP-1403 (T11 L7-win-W2 e): a published 1.0.2 -> 1.0.4 upgrade stopped
    # at "Stopping the gateway"; the account's gateway executable is held open
    # with FileShare.None, so neither it nor a saved copy can run
    # 'connector refresh-fail-modes --closed'. Both retries failed and named
    # the next step, but each released the install lock while the lifecycle
    # record (journal) stayed: hooks could cold-start a gateway for the
    # unfinished install. The lock now stays, retry after retry, until the
    # record is settled. Without a record, or with a gateway still running,
    # the lock goes as before.
    result = _txn_harness(tmp_path, _resume_functions("Get-InstallGatewayState", "Test-RecoveryPending", "Close-InstallLock",
                                                      "Finish-InstallLock", "Close-UnfinishedInstallHooks") + f"""
$Previous = Join-Path $DataDir 'previous'
$Staging = Join-Path $DataDir '.staging'
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory((Join-Path $DataDir 'hooks'))
[void][IO.Directory]::CreateDirectory((Join-Path $DataDir 'previous.new'))
if ('{case}' -ne 'no-journal-close-fails') {{
    [IO.File]::WriteAllText($LifecycleManifest, '{{"Schema":1,"Bins":{{}},"GatewayWasRunning":true}}')
}}
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'held gateway')
$Ver = '1.0.4'
$script:warnings = @()
$script:closes = 0
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Write-Err {{ param($Message) $script:warnings += "ERR $Message" }}
function Invoke-Quietly {{ param([scriptblock]$Action) try {{ & $Action }} catch {{ Write-Warn $_.Exception.Message }} }}
function Clear-StagedRelease {{ }}
function Remove-Tree {{ param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }}
# The held executable: every closer the run tries fails to start.
function Invoke-Native {{ param($FilePath, $Arguments, [switch]$Quiet) $script:closes++; return 1 }}
if ('{case}' -eq 'journal-gateway-running') {{
    $script:images = @([pscustomobject]@{{ ProcessId = 81; ExecutablePath = (Join-Path $BinDir 'defenseclaw-gateway.exe') }})
}}
foreach ($retry in 1, 2) {{
    # Each retry of the documented install command takes the lock again.
    [void][IO.Directory]::CreateDirectory($LockDir)
    $Run.Lock = $true
    # Without a record, an unfinished restore (previous.new) is still pending.
    $Run.RestorePending = [bool]('{case}' -eq 'no-journal-close-fails')
    $Run.UndoPending = $false
    $Run.UnprovenReplacement = $(if ('{case}' -eq 'journal-held-gateway-accept') {{ $true }} else {{ $null }})
    $Run.UnprovenReplacementUnchanged = $false
    $script:warnings = @()
    Finish-InstallLock 1
    "RETRY$retry LOCK=$(Test-Path -LiteralPath $LockDir) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) PENDING=$([bool]$Run.RestorePending)"
    "RETRY$retry WARNINGS=$($script:warnings -join ' | ')"
}}
"CLOSES=$script:closes"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    if case == "no-journal-close-fails":
        # Unchanged: nothing pending to settle, so no lock over unclosed hooks.
        assert "RETRY1 LOCK=False" in out and "RETRY2 LOCK=False" in out, out
        assert "the install lock is released" in out, out
        return
    if case == "journal-gateway-running":
        # Unchanged: a running gateway renders its own hooks; the record stays.
        assert "RETRY1 LOCK=False RECORD=True" in out and "RETRY2 LOCK=False RECORD=True" in out, out
        assert "its gateway is still running" in out, out
        return
    for retry in ("RETRY1", "RETRY2"):
        assert f"{retry} LOCK=True RECORD=True PENDING=True" in out, out
        warnings = out.split(f"{retry} WARNINGS=")[1].splitlines()[0]
        assert "the install lock is released" not in warnings, out
        assert "stays locked until its lifecycle record is settled" in warnings, out
        assert "-Version '1.0.4' -Yes" in warnings, out
        assert ("-AcceptCurrentInstall" in warnings) == (case == "journal-held-gateway-accept"), out
    assert "CLOSES=0" not in out and "could not be closed" in out, out



@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("new_binaries", ["gateway", "hook", "both"])
@pytest.mark.parametrize("gateway_running", [False, True])
def test_empty_first_install_record_requires_acceptance_without_stopping_a_working_gateway(
    tmp_path: Path, new_binaries: str, gateway_running: bool
) -> None:
    # A 1.0.4 first install stopped after recording Bins={} but before its
    # snapshot. A 1.0.3 installer then installed some or all managed binaries
    # without reading that record. Recovery must not start or silently adopt
    # them, and explicit acceptance must keep the record through staging.
    result = _txn_harness(tmp_path, _ps1_function("Resume-InterruptedRun") + _ps1_function("Close-InstallLock")
                          + _ps1_function("Finish-InstallLock") + f"""
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$Ver = '1.0.4'
$ReleaseBase = 'https://github.com/cisco-ai-defense/defenseclaw'
function Read-Text {{ param($Path) return '' }}
function Remove-Tree {{ param($Path) if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Find-SetupInstall {{ return $null }}
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Write-Info {{ param($Message) }}
function Invoke-Quietly {{ param([scriptblock]$Block) & $Block }}
function Clear-StagedRelease {{ }}
function Close-UnfinishedInstallHooks {{ throw 'the unchanged install tried to close hooks' }}
function Test-RecoveryPending {{ return $Run.RestorePending }}
function Start-RecoveredGateway {{ $script:starts++ }}
function Stop-UnprovenGateway {{ $script:stops++; $script:gateway = $null }}
$script:starts = 0; $script:stops = 0; $script:warnings = @()
$Run.Lock = $true
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
$original = @{{ Schema = 1; Operation = 'install'; From = ''; To = '1.0.4'; Slot = '';
    SetupRoot = ''; Bins = @{{}}; GatewayWasRunning = $false; Connectors = @(); Config = '';
    ExternalConfig = ''; ExternalConfigSha256 = ''; HookFailModes = ''; BinDirProtected = $false;
    Committed = $false }}
Write-DurableText $LifecycleManifest ($original | ConvertTo-Json -Depth 4)
if ('{new_binaries}' -in @('gateway', 'both')) {{ [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway') }}
if ('{new_binaries}' -in @('hook', 'both')) {{ [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'older hook') }}
if (${str(gateway_running).lower()}) {{ $script:gateway = [pscustomobject]@{{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
$AcceptCurrentInstall = $false; $Rollback = $false
try {{ Resume-InterruptedRun; throw 'unproven binaries were accepted' }} catch {{
    if ($_.Exception.Message -notlike '*-AcceptCurrentInstall*') {{ throw }}
}}
Finish-InstallLock 1
if (-not (Test-Path -LiteralPath $LifecycleManifest) -or $Run.RestorePending -or (Test-Path -LiteralPath $LockDir)) {{
    throw 'refusal did not keep the record and release the lock'
}}
if (${str(gateway_running).lower()} -and -not $script:gateway) {{ throw 'refusal stopped the working gateway' }}
if ($script:stops -ne 0) {{ throw 'refusal stopped the working gateway before acceptance' }}
$Run.RestorePending = $false; $AcceptCurrentInstall = $true; $Rollback = $true
try {{ Resume-InterruptedRun; throw 'rollback of unproven binaries was accepted' }} catch {{
    if ($_.Exception.Message -notlike '*-AcceptCurrentInstall*') {{ throw }}
}}
if (-not (Test-Path -LiteralPath $LifecycleManifest)) {{ throw 'rollback retired the record' }}
$Run.RestorePending = $false; $Rollback = $false
Resume-InterruptedRun
if (-not $Run.UnprovenReplacement -or -not (Test-Path -LiteralPath $LifecycleManifest)) {{ throw 'acceptance retired the record before staging' }}
if ($script:stops -ne 0) {{ throw 'acceptance stopped the gateway before the release was staged and checked' }}
# A staging failure still leaves the earlier install and its record in place.
[void][IO.Directory]::CreateDirectory($LockDir)
Finish-InstallLock 1
if ((Test-Path -LiteralPath $LockDir) -or -not (Test-Path -LiteralPath $LifecycleManifest)) {{ throw 'staging failure did not release the lock and keep the record' }}
$Run.RestorePending = $false
# A staging failure makes no new journal entry and cannot retire the record.
if ((Read-LifecycleManifest).Committed) {{ throw 'staging alone committed the record' }}
function Get-LifecycleState {{ throw 'the unproven gateway was queried while writing the journal' }}
$checked = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
[void][IO.Directory]::CreateDirectory($LifecycleCloser)
[IO.File]::WriteAllText($checked, 'checked 1.0.4 gateway')
$Run.UnprovenCloserSha256 = Get-Sha256 $checked
# Programs changed after acceptance are never recorded as the accepted ones.
$late = Join-Path $BinDir 'defenseclaw-acp.exe'
[IO.File]::WriteAllText($late, 'added after acceptance')
try {{ [void](Write-LifecycleManifest 'install' '' '1.0.4' (Join-Path $DataDir 'previous.new')); throw 'changed programs were recorded as accepted' }} catch {{
    if ($_.Exception.Message -notlike '*changed after -AcceptCurrentInstall accepted them*') {{ throw }}
}}
Remove-Item -LiteralPath $late -Force
$state = Write-LifecycleManifest 'install' '' '1.0.4' (Join-Path $DataDir 'previous.new')
# The accepted programs, as hashed when accepted, and whether their gateway
# ran are the journal's rollback preimage.
if ((ConvertTo-Map $state.Bins).Count -eq 0 -or -not (Test-SameBinaries $state.Bins (Get-BinariesState $BinDir)) -or
    $state.GatewayWasRunning -ne ${str(gateway_running).lower()} -or -not $state.UnprovenReplacement -or
    $state.ReplacementCloserSha256 -ne $Run.UnprovenCloserSha256) {{ throw 'the journal did not record the accepted install as its preimage, or forgot the checked closer' }}
$target = @{{}}
foreach ($name in @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')) {{
    [IO.File]::WriteAllText((Join-Path $BinDir $name), "1.0.4 $name")
    $target[$name] = Get-Sha256 (Join-Path $BinDir $name)
}}
if (@(Test-LifecycleProof $target $false).Count) {{ throw 'the staged replacement was not proven' }}
Complete-LifecycleManifest
if (-not (Read-LifecycleManifest).Committed) {{ throw 'proven replacement was not committed' }}
Remove-LifecycleManifest
if (Test-Path -LiteralPath $LifecycleManifest) {{ throw 'proven replacement kept the record' }}
"STOPS=$script:stops STARTS=$script:starts"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "STOPS=" in out and "STARTS=0" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    "failure", ["staged-changed", "closer-cannot-close", "hold-failed", "stop-failed", "stop-failed-pid-gone", "hold-incomplete"]
)
def test_unproven_replacement_keeps_the_lock_only_with_its_gateway_down_and_hooks_closed(
    tmp_path: Path, failure: str
) -> None:
    # An accepted retry over a running older install closes every hook with
    # the checked gateway, holds them closed, and stops that gateway. While
    # the gateway still runs (the hold or the stop failed) it can render its
    # hooks open again once the hold is let go, so the lock goes and only the
    # record stays. A gateway that did stop leaves the hooks closed: the lock
    # stays for the retry.
    result = _txn_harness(tmp_path, _ps1_function("Prepare-UnprovenReplacement") + _ps1_function("Close-InstallLock")
                          + _ps1_function("Finish-InstallLock") + f"""
$Staging = Join-Path $DataDir '.staging'
$stagedBin = Join-Path $Staging 'bin'
[void][IO.Directory]::CreateDirectory($stagedBin)
$stagedGateway = Join-Path $stagedBin 'defenseclaw-gateway.exe'
[IO.File]::WriteAllText($stagedGateway, 'checked gateway')
[IO.File]::WriteAllText((Join-Path $stagedBin 'defenseclaw-hook.exe'), 'checked hook')
$expected = Get-BinariesState $stagedBin
$script:gateway = [pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
$Run.UnprovenReplacement = $true
$Run.UnprovenReplacementUnchanged = $true
$Run.Lock = $true
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
[IO.File]::WriteAllText($LifecycleManifest, '{{"Schema":1,"Bins":{{}}}}')
$Ver = '1.0.4'
$script:warnings = @()
$script:cleanupCloses = 0; $script:holds = 0; $script:released = 0; $script:stops = 0
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Invoke-Quietly {{ param([scriptblock]$Action) & $Action }}
function Close-UnfinishedInstallHooks {{ $script:cleanupCloses++; return $true }}
function Clear-StagedRelease {{ }}
function Test-RecoveryPending {{ return $Run.RestorePending }}
function Remove-Tree {{ param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }}
function Start-HookFailModeHold {{ param($Gateway, $GatewayId, [switch]$Closed)
    if (-not $Closed -or $GatewayId -ne 123) {{ throw 'the hold was not closed for the running gateway' }}
    if ('{failure}' -eq 'hold-failed') {{ return $false }}
    $script:holds++; return $true
}}
function Stop-HookFailModeHold {{ $script:released++ }}
function Complete-HookFailModeHold {{ return ('{failure}' -ne 'hold-incomplete') }}
function Stop-UnprovenGateway {{
    if ('{failure}' -eq 'stop-failed-pid-gone') {{
        $script:images = @([pscustomobject]@{{ ProcessId = 123; ExecutablePath = $script:gateway.Path }})
        $script:gateway = $null
    }}
    if ('{failure}' -like 'stop-failed*') {{ throw 'The unproven gateway or watchdog is still running' }}
    $script:stops++; $script:gateway = $null
}}
if ('{failure}' -eq 'staged-changed') {{ [IO.File]::WriteAllText($stagedGateway, 'changed after checking') }}
if ('{failure}' -eq 'closer-cannot-close') {{
    function Invoke-Native {{ param($FilePath, $Arguments, [switch]$Quiet) return 1 }}
}}
try {{ Prepare-UnprovenReplacement $stagedGateway $expected; throw 'failure was accepted' }} catch {{
    if ($_.Exception.Message -notlike '*staged release changed*' -and
        $_.Exception.Message -notlike '*Could not close the older install*' -and
        $_.Exception.Message -notlike '*Could not hold the older install*' -and
        $_.Exception.Message -notlike '*still running*' -and
        $_.Exception.Message -notlike '*Could not keep the older install*') {{ throw }}
}}
Finish-InstallLock 1
"LOCK=$(Test-Path -LiteralPath $LockDir) PENDING=$([bool]$Run.RestorePending) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) RUNNING=$([bool]$script:gateway -or [bool]@($script:images).Count)"
"CLOSES=$script:closes CLEANUP=$script:cleanupCloses HOLDS=$script:holds RELEASED=$script:released STOPS=$script:stops"
"LAST_WARNING=$(if ($script:warnings.Count) {{ $script:warnings[-1] }})"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "RECORD=True" in out, out
    closed = failure in ("hold-failed", "stop-failed", "stop-failed-pid-gone", "hold-incomplete")
    if not closed:
        # Nothing changed before the checked closure point: the gateway
        # keeps running, no hook was closed and the lock goes.
        assert "LOCK=False PENDING=False" in out and "RUNNING=True" in out, out
        assert "CLOSES=0 CLEANUP=0 HOLDS=0 RELEASED=0 STOPS=0" in out, out
    elif failure == "hold-incomplete":
        # The gateway stopped with every hook closed: the lock stays.
        assert "LOCK=True PENDING=True" in out and "RUNNING=False" in out, out
        assert "CLOSES=1 CLEANUP=1 HOLDS=1 RELEASED=0 STOPS=1" in out, out
        assert "programs stopped" not in out.split("LAST_WARNING=")[1], out
    else:
        # The older gateway still runs and can reopen its hooks: no lock.
        assert "LOCK=False PENDING=False" in out and "RUNNING=True" in out, out
        assert "CLOSES=1 CLEANUP=1" in out and "STOPS=0" in out, out
        if failure.startswith("stop-failed"):
            assert "HOLDS=1 RELEASED=1" in out, out
        warning = out.split("LAST_WARNING=")[1]
        assert "the install lock is released" in warning and "-AcceptCurrentInstall" in warning, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("failure", ["hold-failed", "stop-failed", "stop-failed-pid-gone", "hold-incomplete"])
def test_interrupted_replacement_recovery_keeps_the_lock_only_with_its_gateway_down(
    tmp_path: Path, failure: str
) -> None:
    # The interrupted-replacement recovery closes the hooks with the recorded
    # closer, then holds them closed and stops the restored gateway. If that
    # gateway keeps running, the lock goes (it can reopen its hooks); if it
    # stopped, the lock stays with every hook closed.
    result = _txn_harness(tmp_path, _ps1_function("Stop-UnprovenRecoveryGateway") + _ps1_function("Close-InstallLock")
                          + _ps1_function("Finish-InstallLock") + f"""
$Staging = Join-Path $DataDir '.staging'
$checked = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
[void][IO.Directory]::CreateDirectory($LifecycleCloser)
[IO.File]::WriteAllText($checked, 'checked 1.0.4 gateway')
$manifest = [pscustomobject]@{{ ReplacementCloserSha256 = (Get-Sha256 $checked) }}
$script:gateway = [pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
$Run.UnprovenReplacement = $true
$Run.UnprovenReplacementUnchanged = $false
$Run.Lock = $true
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
[IO.File]::WriteAllText($LifecycleManifest, '{{"Schema":1,"Bins":{{}}}}')
$Ver = '1.0.4'
$script:warnings = @()
$script:cleanupCloses = 0; $script:holds = 0; $script:released = 0; $script:stops = 0
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Invoke-Quietly {{ param([scriptblock]$Action) & $Action }}
function Close-UnfinishedInstallHooks {{ $script:cleanupCloses++; return $true }}
function Clear-StagedRelease {{ }}
function Test-RecoveryPending {{ return $Run.RestorePending }}
function Remove-Tree {{ param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }}
function Start-HookFailModeHold {{ param($Gateway, $GatewayId, [switch]$Closed)
    if (-not $Closed -or $GatewayId -ne 123 -or $Gateway -ne $checked) {{ throw 'the hold was not closed with the checked closer' }}
    if ('{failure}' -eq 'hold-failed') {{ return $false }}
    $script:holds++; return $true
}}
function Stop-HookFailModeHold {{ $script:released++ }}
function Complete-HookFailModeHold {{ return ('{failure}' -ne 'hold-incomplete') }}
function Stop-UnprovenGateway {{
    if ('{failure}' -eq 'stop-failed-pid-gone') {{
        $script:images = @([pscustomobject]@{{ ProcessId = 123; ExecutablePath = $script:gateway.Path }})
        $script:gateway = $null
    }}
    if ('{failure}' -like 'stop-failed*') {{ throw 'The unproven gateway or watchdog is still running' }}
    $script:stops++; $script:gateway = $null
}}
try {{ Stop-UnprovenRecoveryGateway $manifest (Join-Path $DataDir 'previous.new'); throw 'failure was accepted' }} catch {{
    if ($_.Exception.Message -notlike '*Could not hold the interrupted install*' -and
        $_.Exception.Message -notlike '*still running*' -and
        $_.Exception.Message -notlike '*Could not keep the interrupted install*') {{ throw }}
}}
# Invoke-Install's catch around Resume-InterruptedRun.
Set-RecoveryPending
Finish-InstallLock 1
"LOCK=$(Test-Path -LiteralPath $LockDir) PENDING=$([bool]$Run.RestorePending) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) RUNNING=$([bool]$script:gateway -or [bool]@($script:images).Count)"
"CLOSES=$script:closes HOLDS=$script:holds RELEASED=$script:released STOPS=$script:stops"
"LAST_WARNING=$(if ($script:warnings.Count) {{ $script:warnings[-1] }})"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    assert "RECORD=True" in out and "CLOSES=1" in out, out
    if failure == "hold-incomplete":
        assert "LOCK=True PENDING=True RECORD=True RUNNING=False" in out and "STOPS=1" in out, out
    else:
        assert "LOCK=False PENDING=False RECORD=True RUNNING=True" in out and "STOPS=0" in out, out
        if failure.startswith("stop-failed"):
            assert "HOLDS=1 RELEASED=1" in out, out
        warning = out.split("LAST_WARNING=")[1]
        assert "the install lock is released" in warning and "-AcceptCurrentInstall" in warning, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_unproven_lock_warning_does_not_claim_a_running_gateway_was_stopped(tmp_path: Path) -> None:
    result = _txn_harness(tmp_path, _ps1_function("Close-InstallLock") + """
$Run.UnprovenReplacement = $true
$Run.RestorePending = $true
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
$script:gateway = [pscustomobject]@{ Id = 123 }
$script:warnings = @()
function Write-Warn { param($Message) $script:warnings += [string]$Message }
function Invoke-Quietly { param([scriptblock]$Action) & $Action }
function Clear-StagedRelease { }
function Test-RecoveryPending { return $Run.RestorePending }
function Get-LifecycleNextStep { return 'retry with -AcceptCurrentInstall' }
Close-InstallLock
if (-not (Test-Path -LiteralPath $LockDir) -or $script:warnings.Count -ne 1 -or
    $script:warnings[0] -like '*programs stopped*' -or $script:warnings[0] -notlike '*-AcceptCurrentInstall*') {
    throw 'the lock warning was inaccurate or omitted the retry command'
}
'OK'
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0 and "OK" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_accepted_empty_record_stops_only_after_checked_closer_and_closed_hold(tmp_path: Path) -> None:
    result = _txn_harness(tmp_path, _ps1_function("Prepare-UnprovenReplacement") + """
$Staging = Join-Path $DataDir '.staging'
$stagedBin = Join-Path $Staging 'bin'
[void][IO.Directory]::CreateDirectory($stagedBin)
$stagedGateway = Join-Path $stagedBin 'defenseclaw-gateway.exe'
[IO.File]::WriteAllText($stagedGateway, 'checked 1.0.4 gateway')
[IO.File]::WriteAllText((Join-Path $stagedBin 'defenseclaw-hook.exe'), 'checked hook')
$expected = Get-BinariesState $stagedBin
$script:gateway = [pscustomobject]@{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:stops = 0; $script:holds = 0; $script:completes = 0
function Start-HookFailModeHold { param($Gateway, $GatewayId, [switch]$Closed)
    if (-not $Closed -or $GatewayId -ne 123 -or $script:closes -ne 1) { throw 'hooks were not closed before the hold' }
    $script:holds++; return $true
}
function Stop-UnprovenGateway {
    if ($script:closes -ne 1 -or $script:holds -ne 1) { throw 'the older gateway stopped before hooks were closed and held' }
    $script:stops++; $script:gateway = $null
}
function Stop-HookFailModeHold { throw 'the held closure was abandoned' }
function Complete-HookFailModeHold {
    if ($script:gateway) { throw 'the hold completed before the gateway stopped' }
    $script:completes++; return $true
}
Prepare-UnprovenReplacement $stagedGateway $expected
$closer = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
if ($script:stops -ne 1 -or $script:completes -ne 1 -or (Get-Sha256 $closer) -ne (Get-Sha256 $stagedGateway)) {
    throw 'the checked closer or stop order was lost'
}
$script:gateway = [pscustomobject]@{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
[IO.File]::WriteAllText($stagedGateway, 'changed after release verification')
try { Prepare-UnprovenReplacement $stagedGateway $expected; throw 'changed staged gateway was accepted' } catch {
    if ($_.Exception.Message -notlike '*staged release changed*') { throw }
}
if ($script:stops -ne 1 -or $script:closes -ne 1 -or (Get-Sha256 $closer) -eq (Get-Sha256 $stagedGateway)) {
    throw 'the changed release touched the working gateway or replaced the checked closer'
}
'OK'
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0 and "OK" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_unproven_replacement_refuses_a_closer_without_closed_hold_support(tmp_path: Path) -> None:
    (tmp_path / "hooks").mkdir()
    quoted_data_dir = str(tmp_path).replace("'", "''")
    script = _ps1_function("Start-HookFailModeHold") + f"\n$DataDir = '{quoted_data_dir}'\n" + """
function Test-HookFailModeRefresh { param($Gateway) return 1 }
if (Start-HookFailModeHold 'checked-gateway.exe' 123 -Closed) {
    throw 'the unsupported gateway was accepted as a closed hold'
}
'OK'
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("snapshot", ["complete", "complete-down", "incomplete"])
def test_an_interrupted_accepted_retry_restores_and_proves_the_install_it_accepted(
    tmp_path: Path, snapshot: str
) -> None:
    # An accepted retry may be interrupted after it writes its journal. The
    # journal holds the install -AcceptCurrentInstall accepted (its hashes
    # and that its gateway ran), so the next run, with or without the switch,
    # restores those programs, starts their gateway again and proves them
    # before it does anything else. A gateway running at that point (the new
    # release's, or the accepted one) is stopped only with the recorded
    # closer, never by its own stop command.
    expected_stops = 1 if snapshot == "complete" else 0
    expected_closes = 1 if snapshot.startswith("complete") else 0
    result = _txn_harness(tmp_path, _ps1_function("Read-Text") +
        _ps1_function("Stop-UnprovenRecoveryGateway") + _ps1_function("Resume-InterruptedRun") + f"""
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$Ver = '1.0.4'
function Remove-Tree {{ param($Path) if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Find-SetupInstall {{ return $null }}
function Write-Warn {{ param($Message) }}
function Write-Info {{ param($Message) }}
function Stop-Gateway {{ throw 'a gateway was asked to run its stop command' }}
function Start-Gateway {{
    $script:starts++
    $script:gateway = [pscustomobject]@{{ Id = 200; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
    return 0
}}
function Stop-UnprovenGateway {{
    if ($script:gateway) {{
        if ($script:closes -ne 1 -or $script:holds -ne 1) {{ throw 'recovery stopped before closing and holding hooks' }}
        $script:stops++
    }}
    $script:gateway = $null
}}
function Close-AllHooks {{ param($Gateways)
    if ((Get-Sha256 $Gateways[0]) -ne $script:closerSha) {{ throw 'the recovery closer was not checked' }}
    $script:closes++; return $true
}}
function Start-HookFailModeHold {{ param($Gateway, $GatewayId, [switch]$Closed)
    if (-not $Closed -or $GatewayId -ne 123 -or $script:closes -ne 1) {{ throw 'recovery hold was not closed' }}
    $script:holds++; return $true
}}
function Complete-HookFailModeHold {{ if ($script:gateway) {{ throw 'recovery hold ended before the stop' }}; return $true }}
function Stop-HookFailModeHold {{ throw 'recovery abandoned the hook hold' }}
function Restore-Slot {{ param($Slot)
    [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
    Remove-Tree $Slot; return (Join-Path $DataDir '.failed')
}}
function Undo-Snapshot {{ param($Slot) Remove-Tree $Slot }}
$script:starts = 0; $script:stops = 0; $script:closes = 0; $script:holds = 0
$script:health = '{{"running": true, "health": {{"connectors": []}}}}'; $script:digestHelp = $false
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'older hook')
$checked = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
[void][IO.Directory]::CreateDirectory($LifecycleCloser)
[IO.File]::WriteAllText($checked, 'checked 1.0.4 gateway')
$script:closerSha = Get-Sha256 $checked
# The interrupted run: it accepted the older programs with their gateway
# running, stopped that gateway and wrote its journal.
$Run.UnprovenCloserSha256 = $script:closerSha
$Run.UnprovenReplacement = [pscustomobject]@{{ Bins = @{{}}; SetupRoot = '' }}
$Run.UnprovenGatewayWasRunning = $true
$Run.UnprovenAcceptedBins = Get-BinariesState $BinDir
$accepted = $Run.UnprovenAcceptedBins
$slot = Join-Path $DataDir 'previous.new'
[void](Write-LifecycleManifest 'upgrade' '1.0.3' '1.0.4' $slot)
# The next run is a new process.
$Run.UnprovenReplacement = $null; $Run.UnprovenGatewayWasRunning = $false; $Run.UnprovenAcceptedBins = $null; $Run.UnprovenCloserSha256 = ''
[void][IO.Directory]::CreateDirectory($slot)
[IO.File]::WriteAllText((Join-Path $slot 'VERSION'), '1.0.3')
if ('{snapshot}' -like 'complete*') {{
    [IO.File]::WriteAllText((Join-Path $slot 'COMPLETE'), '')
    # The swap had put the new gateway in place.
    [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'new 1.0.4 gateway')
}}
if ('{snapshot}' -eq 'complete') {{ $script:gateway = [pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
$AcceptCurrentInstall = $false; $Rollback = $false
Resume-InterruptedRun
if ($Run.UnprovenReplacement -or (Test-Path -LiteralPath $LifecycleManifest) -or (Test-Path -LiteralPath $slot)) {{
    throw 'recovery did not prove the accepted install and retire its journal'
}}
if (-not (Test-SameBinaries (Get-BinariesState $BinDir) $accepted)) {{ throw 'the accepted programs are not back' }}
if (-not $script:gateway -or $script:gateway.Id -ne 200 -or $script:starts -ne 1) {{ throw 'the accepted gateway was not started again' }}
if ($script:stops -ne {expected_stops} -or $script:closes -ne {expected_closes} -or $script:holds -ne {expected_stops}) {{
    throw "recovery did not close and hold the hooks before stopping (stops $script:stops, closes $script:closes, holds $script:holds)"
}}
'OK'
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0 and "OK" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_interrupted_replacement_refuses_to_stop_without_its_recorded_closer(tmp_path: Path) -> None:
    result = _txn_harness(tmp_path, _ps1_function("Stop-UnprovenRecoveryGateway") + """
$Staging = Join-Path $DataDir '.staging'
$script:gateway = [pscustomobject]@{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:stops = 0
function Stop-UnprovenGateway { $script:stops++; $script:gateway = $null }
$manifest = [pscustomobject]@{ ReplacementCloserSha256 = ('a' * 64) }
try {
    Stop-UnprovenRecoveryGateway $manifest (Join-Path $DataDir 'previous.new')
    throw 'a missing checked closer was accepted'
} catch {
    if ($_.Exception.Message -notlike '*checked release hook closer is missing or changed*') { throw }
}
if (-not $script:gateway -or $script:stops -ne 0 -or $script:closes -ne 0) {
    throw 'recovery stopped the working gateway before proving a closer'
}
'OK'
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0 and "OK" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["gateway-and-renamed-watchdog", "renamed-watchdog-only", "renamed-survives"])
def test_unproven_gateway_is_stopped_without_executing_its_binary(case: str) -> None:
    # Neither the gateway nor a watchdog of an unproven install is asked to
    # stop itself. Every process whose image is this install's gateway is
    # terminated, by prefix, so one run from a copy an earlier swap renamed
    # aside (.old-*) cannot keep its watchdog lock with no gateway.pid, and
    # the stop is verified. Another program in the folder is left alone.
    script = f"""
$ErrorActionPreference = 'Stop'
$BinDir = Join-Path ([IO.Path]::GetTempPath()) 'defenseclaw-unproven-bin'
$gateway = Join-Path $BinDir 'defenseclaw-gateway.exe'
$script:table = @{{}}
if ('{case}' -eq 'gateway-and-renamed-watchdog') {{ $script:table[123] = $gateway }}
$script:table[124] = "$gateway.old-20261023"
$script:table[125] = (Join-Path $BinDir 'defenseclaw-hook.exe')
function Get-ProcessesUnder {{ param([string[]]$Prefixes)
    @(@($script:table.Keys) | ForEach-Object {{ [pscustomobject]@{{ ProcessId = $_; ExecutablePath = $script:table[$_] }} }} |
        Where-Object {{ $image = $_.ExecutablePath; @($Prefixes | Where-Object {{ $image.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }}).Count }})
}}
function Get-GatewayProcess {{ if ($script:table.ContainsKey(123)) {{ return [pscustomobject]@{{ Id = 123 }} }} }}
function Get-Process {{ param($Id, $ErrorAction)
    if ($script:table.ContainsKey([int]$Id)) {{ return [pscustomobject]@{{ Id = [int]$Id; Path = $script:table[[int]$Id] }} }}
}}
function Stop-Process {{ param($Id, [switch]$Force, $ErrorAction)
    if ('{case}' -eq 'renamed-survives' -and [int]$Id -eq 124) {{ return }}
    $script:table.Remove([int]$Id)
}}
function Start-Sleep {{ param($Seconds) }}
function Invoke-Native {{ throw 'an unproven program was executed' }}
function Get-LifecycleNextStep {{ param([switch]$Accept) return 'the retry with -AcceptCurrentInstall' }}
{_ps1_function('Stop-UnprovenGateway')}
try {{ $stopped = Stop-UnprovenGateway; "STOPPED=$stopped" }} catch {{ "THROWN=$($_.Exception.Message)" }}
"LEFT=$(@($script:table.Keys | Sort-Object) -join ',')"
"""
    result = _run_powershell(script)
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    if case == "renamed-survives":
        assert "THROWN=" in out and "still running" in out and "-AcceptCurrentInstall" in out, out
        assert "LEFT=124,125" in out, out
    else:
        assert "LEFT=125" in out, out
        assert ("STOPPED=2" if case == "gateway-and-renamed-watchdog" else "STOPPED=1") in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("where", ["accepted-retry", "interrupted-recovery", "interrupted-recovery-no-hooks"])
def test_a_renamed_watchdog_of_the_accepted_install_is_stopped_and_its_hooks_closed_again(tmp_path: Path, where: str) -> None:
    # A Bins={} record, an older install, no gateway.pid, and a watchdog
    # running from defenseclaw-gateway.exe.old-*. Both accepted paths (the
    # retry and the recovery of an interrupted one) terminate it without
    # running it and verify nothing of the install runs. With no gateway.pid
    # there was no hold, so the hooks are closed once more after it exited.
    result = _txn_harness(tmp_path, _resume_functions("Stop-UnprovenGateway", "Prepare-UnprovenReplacement",
                                                      "Stop-UnprovenRecoveryGateway") + f"""
$Staging = Join-Path $DataDir '.staging'
$Ver = '1.0.4'
$script:images = @([pscustomobject]@{{ ProcessId = 124; ExecutablePath = (Join-Path $BinDir 'defenseclaw-gateway.exe.old-20261023') }})
function Get-Process {{ param($Id, $ErrorAction)
    @($script:images | Where-Object {{ $_.ProcessId -eq $Id }} | ForEach-Object {{ [pscustomobject]@{{ Id = $_.ProcessId; Path = $_.ExecutablePath }} }}) | Select-Object -First 1
}}
function Stop-Process {{ param($Id, [switch]$Force, $ErrorAction) $script:images = @($script:images | Where-Object {{ $_.ProcessId -ne $Id }}) }}
function Start-Sleep {{ param($Seconds) }}
function Start-HookFailModeHold {{ throw 'a hold was started for a gateway gateway.pid does not name' }}
function Complete-HookFailModeHold {{ return $true }}
function Stop-HookFailModeHold {{ }}
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
if ('{where}' -eq 'interrupted-recovery-no-hooks') {{ Remove-Item -LiteralPath (Join-Path $DataDir 'hooks') -Recurse -Force }}
if ('{where}' -eq 'accepted-retry') {{
    $stagedBin = Join-Path $Staging 'bin'
    [void][IO.Directory]::CreateDirectory($stagedBin)
    $stagedGateway = Join-Path $stagedBin 'defenseclaw-gateway.exe'
    [IO.File]::WriteAllText($stagedGateway, 'checked 1.0.4 gateway')
    Prepare-UnprovenReplacement $stagedGateway (Get-BinariesState $stagedBin)
}} else {{
    $checked = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
    [void][IO.Directory]::CreateDirectory($LifecycleCloser)
    [IO.File]::WriteAllText($checked, 'checked 1.0.4 gateway')
    Stop-UnprovenRecoveryGateway ([pscustomobject]@{{ ReplacementCloserSha256 = (Get-Sha256 $checked) }}) (Join-Path $DataDir 'previous.new')
}}
"LEFT=$(@($script:images).Count) STATE=$(Get-InstallGatewayState) CLOSES=$script:closes"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    closes = 0 if where == "interrupted-recovery-no-hooks" else 2
    assert f"LEFT=0 STATE=down CLOSES={closes}" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["running", "stopped", "start-fails", "keep-stopped", "changed",
                                  "connector-down", "connector-unreported", "early-connector-down",
                                  "connector-omitted", "early-connector-omitted"])
def test_a_failed_accepted_retry_restores_and_proves_the_install_it_accepted(tmp_path: Path, case: str) -> None:
    # An interrupted first install left Bins={}; an older installer then put
    # a working install in its place. An accepted retry (-AcceptCurrentInstall)
    # stops that gateway (Prepare-UnprovenReplacement) before $WasRunning is
    # read, then its apply fails. The restore brings back the accepted
    # programs, starts their gateway when it ran and proves them, so the
    # record and the install lock go. A new start that was unproven keeps the
    # restored gateway stopped with every hook closed (GAP-0407); a gateway
    # that cannot start keeps the record. Programs changed after acceptance
    # are never recorded or started. Every connector the accepted gateway
    # guarded before its stop, and every connector the effective config
    # enables that it did not report unhealthy (one its health omits, or
    # every one when it does not answer), must be guarded again, on the
    # journal path and before the journal: otherwise the restore fails, the
    # record stays, and the printed next step finishes it.
    result = _txn_harness(tmp_path, _resume_functions(
        "Read-Text", "Prepare-UnprovenReplacement", "Restart-Old", "Start-AcceptedReplacement",
        "Restore-AcceptedReplacement", "Test-RecoveryPending", "Close-InstallLock", "Finish-InstallLock",
        "Restore-Snapshot", "Resume-InterruptedRun") + f"""
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$Ver = '1.0.4'; $PrevVersion = '1.0.3'; $previousLabel = '1.0.3'
$ReleaseBase = 'https://github.com/cisco-ai-defense/defenseclaw'
function Die {{ param([string]$Message) throw $Message }}
function Remove-Tree {{ param($Path) if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Find-SetupInstall {{ return $null }}
function Write-Warn {{ param($Message) $script:warnings += [string]$Message }}
function Write-Info {{ param($Message) }}
function Write-Err {{ param($Message) $script:errors += [string]$Message }}
function Invoke-Quietly {{ param([scriptblock]$Action) & $Action }}
function Clear-StagedRelease {{ }}
function Close-UnfinishedInstallHooks {{ return $true }}
function Remove-FailedInstall {{ param($Failed) }}
function Get-TreeSize {{ param($Path) return 0 }}
function Write-KeptUvCache {{ }}
function Start-HookFailModeHold {{ param($Gateway, $GatewayId, [switch]$Closed) return $true }}
function Complete-HookFailModeHold {{ return $true }}
function Stop-HookFailModeHold {{ }}
function Stop-UnprovenGateway {{ $script:gateway = $null }}
function Start-Gateway {{
    $script:starts++
    if ('{case}' -eq 'start-fails') {{ return 1 }}
    $script:gateway = [pscustomobject]@{{ Id = 200; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
    return 0
}}
function Restore-Slot {{ param($Slot)
    foreach ($name in $script:older.Keys) {{ [IO.File]::WriteAllText((Join-Path $BinDir $name), $script:older[$name]) }}
    Remove-Tree $Slot
    return (Join-Path $DataDir '.failed')
}}
$script:starts = 0; $script:warnings = @(); $script:errors = @()
$script:health = '{{"running": true, "health": {{"connectors": []}}}}'; $script:digestHelp = $false
$guarded = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "running"}}]}}}}'
$admissionError = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "error"}}]}}}}'
if (@('running', 'connector-down', 'early-connector-down') -contains '{case}') {{ $script:health = $guarded }}
if ('{case}' -eq 'connector-unreported') {{
    # A gateway that does not report its connectors: the config's are held.
    $script:health = ''
    $script:enabled = @('claudecode')
}}
if (@('connector-omitted', 'early-connector-omitted') -contains '{case}') {{
    # An older gateway that answers but leaves an enabled connector out of
    # its health, before its stop and again after its restore.
    $script:enabled = @('claudecode')
}}
$Run.Lock = $true; $Run.Log = 'install.log'
$Run.UnprovenReplacement = $null; $Run.UnprovenReplacementUnchanged = $false; $Run.UnprovenGatewayWasRunning = $false
$Run.UnprovenAcceptedBins = $null; $Run.UnprovenConnectors = @(); $Run.UnprovenCloserSha256 = ''; $Run.OldGatewayDown = $false
$LockDir = Join-Path $DataDir '.install.lock'
[void][IO.Directory]::CreateDirectory($LockDir)
$original = @{{ Schema = 1; Operation = 'install'; From = ''; To = '1.0.4'; Slot = ''; SetupRoot = ''; Bins = @{{}};
    GatewayWasRunning = $false; Connectors = @(); Config = ''; ExternalConfig = ''; ExternalConfigSha256 = '';
    HookFailModes = ''; BinDirProtected = $false; Committed = $false }}
Write-DurableText $LifecycleManifest ($original | ConvertTo-Json -Depth 4)
$script:older = @{{ 'defenseclaw-gateway.exe' = 'older 1.0.3 gateway'; 'defenseclaw-hook.exe' = 'older 1.0.3 hook' }}
foreach ($name in $script:older.Keys) {{ [IO.File]::WriteAllText((Join-Path $BinDir $name), $script:older[$name]) }}
if ('{case}' -ne 'stopped') {{ $script:gateway = [pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}
$AcceptCurrentInstall = $true; $Rollback = $false
Resume-InterruptedRun
# Invoke-Install: the checked release is staged, then the accepted stop.
$stagedBin = Join-Path $Staging 'bin'
[void][IO.Directory]::CreateDirectory($stagedBin)
$stagedGateway = Join-Path $stagedBin 'defenseclaw-gateway.exe'
[IO.File]::WriteAllText($stagedGateway, 'checked 1.0.4 gateway')
[IO.File]::WriteAllText((Join-Path $stagedBin 'defenseclaw-hook.exe'), 'checked 1.0.4 hook')
Prepare-UnprovenReplacement $stagedGateway (Get-BinariesState $stagedBin)
"SAVED=$(@(Get-Field (Read-LifecycleManifest) 'ReplacementConnectors') -join ',')"
# The accepted gateway comes back with a connector admission error.
if (@('connector-down', 'connector-unreported', 'early-connector-down') -contains '{case}') {{ $script:health = $admissionError }}
$WasRunning = [bool](Get-GatewayProcess)
if ($WasRunning) {{ throw 'the accepted gateway still ran after its stop' }}
$Snap = Join-Path $DataDir 'previous.new'
if (@('early-connector-down', 'early-connector-omitted') -contains '{case}') {{
    # A failure before the journal (Prepare-UnprovenReplacement or the
    # journal write): the record is still the empty first-install one.
    "NOTE=$(Restore-AcceptedReplacement)"
}} elseif ('{case}' -eq 'changed') {{
    [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-acp.exe'), 'added after acceptance')
    try {{ $Manifest = Write-LifecycleManifest 'upgrade' $PrevVersion $Ver $Snap; throw 'changed programs were recorded' }} catch {{
        if ($_.Exception.Message -notlike '*changed after -AcceptCurrentInstall accepted them*') {{ throw }}
    }}
    "NOTE=$(Restore-AcceptedReplacement)"
}} else {{
    $Manifest = Write-LifecycleManifest 'upgrade' $PrevVersion $Ver $Snap
    [void][IO.Directory]::CreateDirectory($Snap)
    [IO.File]::WriteAllText((Join-Path $Snap 'COMPLETE'), '')
    if ('{case}' -eq 'keep-stopped') {{ [IO.File]::WriteAllText((Join-Path $Snap 'GATEWAY_RESTART_UNPROVEN'), '') }}
    # Install-New replaced a program, then failed.
    [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'partial 1.0.4 gateway')
    try {{ Restore-Snapshot; 'RESTORE=ok' }} catch {{ "RESTORE=failed $($_.Exception.Message)" }}
}}
$closes = $script:closes
Finish-InstallLock 1
"STARTS=$script:starts RUNNING=$([bool]$script:gateway) RECORD=$(Test-Path -LiteralPath $LifecycleManifest) LOCK=$(Test-Path -LiteralPath $LockDir) CLOSES=$closes"
"OLDER=$([IO.File]::ReadAllText((Join-Path $BinDir 'defenseclaw-gateway.exe')) -eq $script:older['defenseclaw-gateway.exe'])"
"ERRORS=$($script:errors -join ' | ')"
"WARNINGS=$($script:warnings -join ' | ')"
if ('{case}' -eq 'connector-down') {{
    # The next run, a new process: the printed step, then the one it prints.
    $Run.Lock = $false; $Run.UnprovenReplacement = $null; $Run.UnprovenGatewayWasRunning = $false
    $Run.UnprovenAcceptedBins = $null; $Run.UnprovenConnectors = @(); $Run.UnprovenCloserSha256 = ''
    $Run.RestorePending = $false; $Run.UndoPending = $false
    $AcceptCurrentInstall = $false
    try {{ Resume-InterruptedRun; 'NEXT=proven' }} catch {{ "NEXT=refused $($_.Exception.Message)" }}
    $AcceptCurrentInstall = $true
    try {{ Resume-InterruptedRun; "ACCEPTED=RECORD=$(Test-Path -LiteralPath $LifecycleManifest)" }} catch {{ "ACCEPTED=failed $($_.Exception.Message)" }}
}}
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    if case in ("running", "connector-down", "early-connector-down", "connector-unreported",
                "connector-omitted", "early-connector-omitted"):
        assert "SAVED=claudecode\n" in out, out
    if case == "running":
        assert "RESTORE=ok" in out and "STARTS=1 RUNNING=True RECORD=False LOCK=False CLOSES=1" in out, out
    elif case in ("connector-down", "connector-unreported", "connector-omitted"):
        # The journal holds the connector, so the restore is not proven and
        # the record stays. The gateway runs and renders its own hooks, so the
        # lock goes (Finish-InstallLock).
        assert "RESTORE=failed" in out and "connector claudecode is not guarded again" in out, out
        assert "STARTS=1 RUNNING=True RECORD=True LOCK=False" in out, out
        if case == "connector-down":
            # Without the switch the record stays and names the switch; with
            # it, the install as it is now is accepted and the record goes.
            assert "NEXT=refused" in out and "-AcceptCurrentInstall" in out.split("NEXT=refused", 1)[1], out
            assert "ACCEPTED=RECORD=False" in out, out
    elif case in ("early-connector-down", "early-connector-omitted"):
        assert "not proven running" in out and "connector claudecode is not guarded again" in out, out
        assert "STARTS=1 RUNNING=True RECORD=True" in out, out
    elif case == "stopped":
        assert "RESTORE=ok" in out and "STARTS=0 RUNNING=False RECORD=False LOCK=False CLOSES=1" in out, out
    elif case == "keep-stopped":
        # Closed by the accepted stop, and again because the gateway stays stopped.
        assert "RESTORE=ok" in out and "STARTS=0 RUNNING=False RECORD=False LOCK=False CLOSES=2" in out, out
    elif case == "start-fails":
        # The record stays with the hooks closed and the gateway down; the
        # next run restarts and proves it from the record (no switch needed).
        assert "RESTORE=failed" in out and "STARTS=1 RUNNING=False RECORD=True LOCK=True" in out, out
        assert "the gateway is not running" in out, out
    else:
        assert "STARTS=0 RUNNING=False RECORD=True" in out, out
        assert "not the ones -AcceptCurrentInstall accepted" in out and "not proven running" in out, out
    if case != "changed":
        # The accepted programs are back in place.
        assert "OLDER=True" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["reported", "not-answering", "interrupted", "interrupted-unrecorded", "merged",
                                  "omitted", "empty-roster", "starting", "no-json"])
def test_the_connectors_the_accepted_gateway_guarded_are_recorded_before_its_stop(tmp_path: Path, case: str) -> None:
    # Save-AcceptedConnectors asks the running accepted gateway for its
    # guarded connectors with the checked closer (never the accepted
    # programs) and adds every connector the effective config enables that
    # the gateway does not explicitly report unhealthy: one its health
    # omits, an empty roster, one still starting, or all of them when it
    # does not answer. A stale active_connector.json adds nothing. It keeps
    # them in the record before the stop, and a later run (the gateway down
    # by then) still proves them: the journal it writes names them.
    result = _txn_harness(tmp_path, f"""
$closer = Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'
[void][IO.Directory]::CreateDirectory($LifecycleCloser)
[IO.File]::WriteAllText($closer, 'checked 1.0.4 gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'older gateway')
# A stale active_connector.json; the effective config enables codex.
[IO.File]::WriteAllText((Join-Path $DataDir 'active_connector.json'), '{{"names": ["cursor"]}}')
$script:enabled = @('codex')
$probe = ${{function:Get-NativeProbe}}
function Get-NativeProbe {{ param($FilePath, $Arguments)
    if ($FilePath -ne $closer) {{ throw "the accepted program $FilePath was run before its stop" }}
    & $probe $FilePath $Arguments
}}
$original = @{{ Schema = 1; Operation = 'install'; From = ''; To = '1.0.4'; Slot = ''; SetupRoot = ''; Bins = @{{}};
    GatewayWasRunning = $false; Connectors = @(); Config = ''; ExternalConfig = ''; ExternalConfigSha256 = '';
    HookFailModes = ''; BinDirProtected = $false; Committed = $false; ReplacementGatewayWasRunning = $true }}
if ('{case}' -eq 'interrupted') {{ $original.ReplacementConnectors = @('claudecode') }}
Write-DurableText $LifecycleManifest ($original | ConvertTo-Json -Depth 4)
$Run.UnprovenConnectors = @(); $Run.UnprovenGatewayWasRunning = $true
$running = [pscustomobject]@{{ Id = 123; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }}
switch ('{case}') {{
    'reported' {{ $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "running"}}, {{"name": "codex", "state": "error"}}]}}}}' }}
    'not-answering' {{ $script:health = '{{"running": false}}' }}
    'merged' {{ $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "running"}}]}}}}' }}
    'omitted' {{ $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "running"}}]}}}}' }}
    'empty-roster' {{ $script:health = '{{"running": true, "health": {{"connectors": []}}}}' }}
    'starting' {{ $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "codex", "state": "starting"}}]}}}}' }}
    'no-json' {{ $script:health = '' }}
    default {{ $running = $null }}
}}
if ('{case}' -eq 'merged') {{
    # An earlier Prepare-UnprovenReplacement of this run (the gateway
    # restarted before the second one) recorded codex.
    Save-AcceptedConnectors $closer ([pscustomobject]@{{ Id = 1 }}) | Out-Null
    $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "codex", "state": "running"}}]}}}}'
    Save-AcceptedConnectors $closer ([pscustomobject]@{{ Id = 1 }})
    $script:health = '{{"running": true, "health": {{"connectors": [{{"name": "claudecode", "state": "running"}}]}}}}'
}}
Save-AcceptedConnectors $closer $running
"SAVED=$(@(Get-Field (Read-LifecycleManifest) 'ReplacementConnectors') -join ',')"
# The journal this run writes holds them.
$Run.UnprovenReplacement = Read-LifecycleManifest
$Run.UnprovenAcceptedBins = Get-BinariesState $BinDir
$Run.UnprovenCloserSha256 = Get-Sha256 $closer
$journal = Write-LifecycleManifest 'upgrade' '1.0.3' '1.0.4' (Join-Path $DataDir 'previous.new')
"JOURNAL=$(@(Get-Field $journal 'Connectors') -join ',')"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    want = {
        "reported": "claudecode",
        "not-answering": "codex",
        "interrupted": "claudecode",
        "interrupted-unrecorded": "codex",
        "merged": "claudecode,codex",
        "omitted": "claudecode,codex",
        "empty-roster": "codex",
        "starting": "codex",
        "no-json": "codex",
    }[case]
    assert f"SAVED={want}\n" in out and f"JOURNAL={want}\n" in out, out


def test_an_accepted_retry_proves_nothing_of_the_older_install_runs_and_restores_it_on_an_early_failure() -> None:
    install = _ps1_function("Invoke-Install")
    swap = install[install.index("Prepare-UnprovenReplacement $stagedGateway $stagedBinaries\n        } else { Stop-Watchdog }"):]
    # A same-version repair skips the version-change check: an accepted retry
    # asserts quiescence before the snapshot anyway.
    assert swap.index('Assert-GatewayQuiescent "Installing $Ver over the accepted install"') < swap.index("Save-Snapshot")
    # Each failure between the accepted stop and the journal (the two
    # Prepare-UnprovenReplacement calls, the journal write) starts the
    # accepted gateway again and proves it; so does an undone early snapshot.
    assert install.count("$(Restore-AcceptedReplacement)") == 3
    early = install[install.index("try { Save-BinarySnapshot }"):]
    assert early.index("Undo-EarlySnapshot $Snap") < early.index("Start-AcceptedReplacement") < early.index("Assert-LifecycleRestored $Manifest")
    assert "Start-AcceptedReplacement" in _ps1_function("Restart-Old")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_unproven_install_discovers_its_version_without_executing_its_gateway(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    info = tmp_path / "venv" / "Lib" / "site-packages" / "defenseclaw-1.0.3.dist-info"
    bin_dir.mkdir()
    info.mkdir(parents=True)
    (bin_dir / "defenseclaw-gateway.exe").write_text("unproven", encoding="ascii")
    result = _run_powershell(f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{bin_dir}'
$Venv = '{tmp_path / 'venv'}'
$Run = @{{ UnprovenReplacement = $true }}
function Get-NativeOutput {{ throw 'the unproven gateway was executed' }}
{_ps1_function('Get-InstalledVersion')}
if ((Get-InstalledVersion) -ne '1.0.3') {{ throw 'the passive version lookup failed' }}
Write-Output 'OK'
""")
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("isolated", [False, True])
def test_checked_uv_install_uses_its_requested_destination_without_claiming_an_older_uv(
    tmp_path: Path, isolated: bool
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if isolated:
        (bin_dir / "uv.exe").write_text("older uv", encoding="ascii")
    result = _run_powershell(f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{bin_dir}'
$UvVersion = 'test'
$UvZipSha256 = 'verified'
function Save-Url {{ param($Url, $To) [IO.File]::WriteAllText($To, 'zip'); return $true }}
function Get-Sha256 {{ return 'verified' }}
function Expand-Archive {{
    param($LiteralPath, $DestinationPath, [switch]$Force)
    [void][IO.Directory]::CreateDirectory($DestinationPath)
    [IO.File]::WriteAllText((Join-Path $DestinationPath 'uv.exe'), 'checked uv')
}}
function Test-SamePath {{ param($A, $B) return $A -eq $B }}
function Invoke-Quietly {{ param([scriptblock]$Block) & $Block }}
function Remove-Tree {{ param($Path) if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Write-Err {{ param($Message) throw $Message }}
{_ps1_function('Install-Uv')}
$isolated = Join-Path '{tmp_path}' 'checked-uv'
$uv = if (${str(isolated).lower()}) {{ Install-Uv $isolated }} else {{ Install-Uv }}
if (-not (Test-Path -LiteralPath $uv) -or [IO.File]::ReadAllText($uv) -ne 'checked uv') {{ throw 'the checked uv was not installed' }}
if (${str(isolated).lower()}) {{
    if ([IO.File]::ReadAllText((Join-Path $BinDir 'uv.exe')) -ne 'older uv') {{ throw 'the older uv was overwritten' }}
    if (Test-Path -LiteralPath (Join-Path $BinDir 'defenseclaw-uv.sha256')) {{ throw 'the older uv was claimed' }}
}} elseif (-not (Test-Path -LiteralPath (Join-Path $BinDir 'defenseclaw-uv.sha256'))) {{ throw 'the new uv was not recorded' }}
Write-Output 'OK'
""")
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("child", ["reads-record", "legacy", "other-value"])
@pytest.mark.parametrize("record", [True, False])
def test_a_version_change_is_not_handed_to_an_installer_that_does_not_read_a_pending_lifecycle_record(
    tmp_path: Path, child: str, record: bool
) -> None:
    # `defenseclaw upgrade --version 1.0.2` (or -Version 1.0.2) while a
    # lifecycle record is pending: 1.0.3 and earlier do not read it, clear
    # the stale lock and install over the install it still has to prove.
    marker = {"reads-record": "\n$DcLifecycleRecord = 1", "legacy": "", "other-value": "\n$DcLifecycleRecord = 2"}[child]
    installer = f'$DcVersion = "1.0.2"\n$DcVersionChangeGuard = 1{marker}'
    if record:
        _lifecycle_record(tmp_path / ".lifecycle-txn.json")
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$LifecycleManifest = Join-Path $DataDir '.lifecycle-txn.json'
$ReleaseBase = 'https://release.invalid'
$OfficialReleaseBase = $ReleaseBase
$Ver = '1.0.4'
$Local = ''
$script:children = 0
{_ps1_function("Test-Version")}
{_ps1_function("Get-LifecycleNextStep")}
{_ps1_function("Invoke-ReleaseInstaller")}
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Die([string]$Message) {{ throw $Message }}
function Invoke-Quietly([scriptblock]$Block) {{ & $Block }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Get-InstalledVersion {{ return '1.0.3' }}
function Assert-NoLoadedPluginAgents {{ }}
function Assert-NoActiveConnectorRecovery {{ }}
function Save-Url([string]$Url, [string]$To) {{ [IO.File]::WriteAllText($To.Replace([char]92, [IO.Path]::DirectorySeparatorChar), '{installer.replace("'", "''")}'); return $true }}
function Get-ListedSha256 {{ return 'verified' }}
function Get-Sha256 {{ return 'verified' }}
function Get-Cosign {{ return '' }}
function Wait-VenvFree {{ }}
function Get-GatewayProcess {{ return $null }}
function Stop-Gateway {{ return $true }}
function Stop-Watchdog {{ }}
function Assert-GatewayQuiescent {{ }}
function Start-Gateway {{ return 0 }}
function ConvertTo-ProcessArgument([string]$Value) {{ return $Value }}
function Start-Process {{
    $script:children++
    $child = [PSCustomObject]@{{ Handle = [IntPtr]::Zero; ExitCode = 0 }}
    $child | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {{}}
    return $child
}}
try {{ $code = Invoke-ReleaseInstaller '1.0.2' @('-Yes'); Write-Output "HANDED code=$code" }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
Write-Output "CHILDREN=$script:children"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    if record and child != "reads-record":
        assert "REFUSED: An earlier install step is not finished" in out and "CHILDREN=0" in out, out
        assert "releases/download/1.0.4/install.ps1" in out, out
    else:
        assert "HANDED" in out and "CHILDREN=1" in out, out
    assert (tmp_path / ".lifecycle-txn.json").exists() == record


def test_this_installer_declares_that_it_reads_the_lifecycle_record() -> None:
    # Invoke-ReleaseInstaller hands a pending record only to an installer
    # that declares this; the next releases inherit the line.
    assert re.findall(r"^\s*\$DcLifecycleRecord\b.*$", _text(), re.M) == ["$DcLifecycleRecord = 1"]


def _resume_functions(*names: str) -> str:
    # The listed install.ps1 functions this file has, in file order.
    return "\n".join(
        _ps1_function(name) for name in re.findall(r"^function ([\w-]+)[ (]", _text(), re.M) if name in names
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("snapshot", ["complete", "incomplete", "no-snapshot"])
def test_interrupted_setup_upgrade_recovery_starts_the_setup_gateway_on_every_retry(
    tmp_path: Path, snapshot: str
) -> None:
    # A DefenseClaw Setup install has no ~\.local\bin gateway. Recovery ran
    # that missing binary and kept its record, so every retry failed at the
    # same check before staging; a restored Setup snapshot started Setup's
    # gateway without checking it answered. Each retry must start Setup's own
    # gateway, prove it answers, and keep the lifecycle record until it does.
    data = tmp_path / "data"
    setup_root = tmp_path / "Setup"
    (setup_root / "bin").mkdir(parents=True)
    (setup_root / "bin" / "defenseclaw-startup.exe").touch()
    (setup_root / "bin" / "defenseclaw-gateway.exe").touch()
    staged_state = data / ".staging" / "hook-runtime-state.json"
    staged_state.parent.mkdir(parents=True)
    staged_state.write_text("{}", encoding="ascii")
    hook_state = tmp_path / "HookRuntime" / "hook-runtime-state.json"
    hook_state.parent.mkdir()
    if snapshot == "no-snapshot":
        _lifecycle_record(data / ".lifecycle-txn.json")
    else:
        slot = data / "previous.new"
        slot.mkdir()
        (slot / "GATEWAY_WAS_RUNNING").write_text("true", encoding="ascii")
        (slot / "VERSION").write_text("0.8.10", encoding="ascii")
        if snapshot == "complete":
            (slot / "COMPLETE").touch()
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = Join-Path $DataDir 'bin'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = '{hook_state}'
$setupGateway = Join-Path '{setup_root}' 'bin\\defenseclaw-gateway.exe'
$script:setupStarts = 0
$script:setupWorks = $false
$script:up = $false
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Write-Ok([string]$Message) {{ Write-Host $Message }}
function Get-UtcClock {{ return 'now' }}
function Start-Sleep {{ param([int]$Seconds) }}
function Stop-Gateway {{ $script:up = $false; return $true }}
function Get-GatewayProcess {{ if ($script:up) {{ return [pscustomobject]@{{ Id = 1 }} }}; return $null }}
function Invoke-Native([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet) {{
    if ($script:up -and $FilePath -eq $setupGateway -and $Arguments[0] -eq 'status') {{ return 0 }}
    return 1
}}
function Find-SetupInstall {{ return [pscustomobject]@{{ Root = '{setup_root}' }} }}
function Start-SetupGateway([string]$Root) {{ $script:setupStarts++; $script:up = $script:setupWorks }}
function Clear-SetupDataDir {{ }}
function Remove-FailedInstall {{ }}
function Invoke-Quietly([scriptblock]$Action) {{ & $Action }}
function Die([string]$Message) {{ throw $Message }}
function Undo-HookFirst {{ }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Restore-Slot([string]$Slot) {{ Remove-Tree $Slot; return (Join-Path $DataDir '.failed-test') }}
{_resume_functions("Read-Text", "Undo-Snapshot", "Remove-Hold", "Start-Gateway", "Start-RecoveredGateway", "Resume-InterruptedRun")}
{_txn_real_functions()}
{_TXN_PRELUDE}
foreach ($attempt in 1..2) {{
    try {{ Resume-InterruptedRun; Write-Output 'CONTINUED' }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
    Write-Output "MARKER=$(Test-Path -LiteralPath $LifecycleManifest)"
}}
$script:setupWorks = $true
try {{ Resume-InterruptedRun; Write-Output 'RECOVERED' }} catch {{ Write-Output "STILL-REFUSED: $($_.Exception.Message)" }}
Write-Output "FINAL-MARKER=$(Test-Path -LiteralPath $LifecycleManifest)"
Write-Output "SETUP_STARTS=$script:setupStarts"
Write-Output "HOOK_STATE=$(Test-Path -LiteralPath $SetupHookState)"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "CONTINUED" not in out and out.count("REFUSED: ") == 2, out
    assert out.count("MARKER=True") == 2, out
    assert "gateway of DefenseClaw Setup did not become healthy" in out and "defenseclaw-startup.exe" in out, out
    assert "is missing, so the gateway was not started" not in out, out
    assert "RECOVERED" in out and "STILL-REFUSED" not in out and "FINAL-MARKER=False" in out, out
    assert "SETUP_STARTS=3" in out, out
    assert "HOOK_STATE=True" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    "case",
    [
        "legacy-incomplete",
        "legacy-complete",
        "legacy-incomplete-setup",
        "stopped-incomplete",
        "stopped-complete",
        "restarted-after-failure",
    ],
)
def test_interrupted_recovery_never_starts_a_gateway_nothing_proves_was_running(tmp_path: Path, case: str) -> None:
    # A 1.0.3 or earlier installer wrote GATEWAY_WAS_RUNNING last, so its cut
    # off snapshot has none. Recovery read an installed gateway binary (or a
    # Setup install) as "it was running" and started a gateway the user had
    # stopped on purpose. Neither a recorded "false", nor the lifecycle record
    # of a failed run that started its old gateway again, may start one.
    setup = case.endswith("-setup")
    if not setup:
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "defenseclaw-gateway.exe").touch()
    if case != "restarted-after-failure":
        slot = tmp_path / "previous.new"
        slot.mkdir()
        (slot / "VERSION").write_text("1.0.3", encoding="ascii")
        if case.startswith("stopped-"):
            (slot / "GATEWAY_WAS_RUNNING").write_text("false", encoding="ascii")
        if case.endswith("-complete"):
            (slot / "COMPLETE").touch()
    find_setup = f"[pscustomobject]@{{ Root = '{tmp_path / 'Setup'}' }}" if setup else "$null"
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{tmp_path}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$BinDir = Join-Path $DataDir 'bin'
$Staging = Join-Path $DataDir '.staging'
$Previous = Join-Path $DataDir 'previous'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$script:starts = 0
$script:up = $false
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Start-Sleep {{ param([int]$Seconds) }}
function Stop-Gateway {{ $script:up = $false; return $true }}
function Get-GatewayProcess {{ if ($script:up) {{ return [pscustomobject]@{{ Id = 1; Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }} }}; return $null }}
function Invoke-Native([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet) {{ if ($script:up) {{ return 0 }}; return 1 }}
function Start-Gateway {{ $script:starts++; $script:up = $true; return 0 }}
function Start-SetupGateway([string]$Root) {{ $script:starts++; $script:up = $true }}
function Find-SetupInstall {{ return {find_setup} }}
function Clear-SetupDataDir {{ }}
function Remove-FailedInstall {{ }}
function Invoke-Quietly([scriptblock]$Action) {{ & $Action }}
function Die([string]$Message) {{ throw $Message }}
function Undo-HookFirst {{ }}
function Move-Path([string]$From, [string]$To) {{ Move-Item -LiteralPath $From -Destination $To }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Restore-Slot([string]$Slot) {{ Remove-Tree $Slot; return (Join-Path $DataDir '.failed-test') }}
{_resume_functions("Read-Text", "Undo-Snapshot", "Remove-Hold", "Restart-Old", "Start-RecoveredGateway", "Resume-InterruptedRun")}
{_txn_real_functions()}
{_TXN_PRELUDE}
if ('{case}' -eq 'restarted-after-failure') {{
    # The failed run wrote its record, stopped its gateway, then put it back
    # and proved it (Assert-LifecycleRestored), which drops the record.
    Set-Content -LiteralPath $LifecycleManifest -Value '{{"Schema": 1, "Bins": {{}}, "GatewayWasRunning": true, "Connectors": [], "Config": "", "HookFailModes": "", "ExternalConfig": "", "BinDirProtected": false, "SetupRoot": "", "Committed": false}}' -Encoding Ascii
    $WasRunning = $true
    $Setup = $null
    $Run = @{{ RestorePending = $false; UndoPending = $false }}
    $record = Read-LifecycleManifest
    $record.Bins = Get-BinariesState $BinDir
    Restart-Old
    Assert-LifecycleRestored $record
    # The user then stops it on purpose before running the installer again.
    $script:up = $false
    $script:starts = 0
}}
Resume-InterruptedRun
Write-Output "STARTS=$script:starts"
Write-Output "MARKER=$(Test-Path -LiteralPath $LifecycleManifest)"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "STARTS=0" in out and "MARKER=False" in out, out
    unknown = "did not record whether the gateway was running, so it is not started"
    if case.startswith("legacy-"):
        assert unknown in out and "defenseclaw-gateway start" in out, out
    else:
        assert unknown not in out, out


def test_a_failed_stop_whose_old_gateway_still_runs_owes_the_next_run_no_start() -> None:
    # The lifecycle record is written before the stop. If the stop fails and
    # the old gateway still runs, the run proves that install back, which
    # drops the record, so a later run does not start the gateway after the
    # user stops it on purpose.
    install = _ps1_function("Invoke-Install")
    refused = install[install.index("        if ($stopRefused) {") :]
    refused = refused[: refused.index('Die "${reason}; $(Get-UnchangedNote)"')]
    assert "if (-not (Test-RecoveryPending)) { Assert-LifecycleRestored $Manifest }" in refused
    assert "Remove-LifecycleManifest" in _ps1_function("Assert-LifecycleRestored")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_external_config_is_saved_beside_its_copy_and_put_back(tmp_path: Path) -> None:
    # A snapshot keeps an external DEFENSECLAW_CONFIG in config\ and its path
    # in a marker. NTFS names are case-insensitive: a CONFIG marker could not
    # be written next to the config folder, so on Windows every snapshot of
    # such an install failed and the upgrade was refused.
    data, slot, external = tmp_path / "data", tmp_path / "data" / "previous.new", tmp_path / "external.yaml"
    slot.mkdir(parents=True)
    external.write_text("saved external config", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$env:DEFENSECLAW_CONFIG = '{external}'
function Copy-Kept([string]$Source, [string]$DestinationDir) {{ Copy-Item -LiteralPath $Source -Destination $DestinationDir -Force }}
{"".join(_ps1_function(name) for name in ("Read-Text", "Get-Sha256", "Get-ExternalConfig", "Save-ExternalConfig", "Restore-ExternalConfig"))}
Save-ExternalConfig '{slot}'
[IO.File]::WriteAllText('{external}', 'migrated external config')
Restore-ExternalConfig '{slot}'
Write-Output 'RESTORED'
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0 and "RESTORED" in out, out
    assert external.read_text(encoding="ascii") == "saved external config"
    assert (slot / "config" / external.name).read_text(encoding="ascii") == "saved external config"


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("failure", ["live-data", "saved-venv", "external-config", "after-data", "unproven-data"])
def test_snapshot_restore_preserves_failed_moves_and_can_resume(tmp_path: Path, failure: str) -> None:
    # GAP-0450: required moves and external-config restoration must all
    # succeed before the snapshot is consumed or recovery is announced.
    data = tmp_path / "data"
    slot = data / "previous.new"
    external = tmp_path / "external.yaml"
    for path, body in {
        data / "config.yaml": "new data",
        slot / "data" / "config.yaml": "old data",
        data / ".venv" / "runtime.txt": "new environment",
        slot / "venv" / "runtime.txt": "old environment",
        data / ".defenseclaw-cas-intent": "new receipt",
        slot / "data" / ".defenseclaw-cas-intent": "old receipt",
        external: "new external config",
        slot / "config" / external.name: "old external config",
        slot / "CONFIG_PATH": str(external),
        slot / "COMPLETE": "",
    }.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="ascii")
    move = _ps1_function("Move-Path").replace("function Move-Path(", "function Move-PathReal(", 1)
    functions = "\n".join(
        _ps1_function(name)
        for name in re.findall(r"^function ([\w-]+)[ (]", _text(), re.M)
        if name in {
            "Get-Sha256", "Get-DataEntries", "Read-Text", "Restore-ExternalConfig",
            "Test-ConnectorRecoveryArtifactName", "Restore-Slot", "Invoke-Quietly", "Get-LifecycleNextStep",
        }
    )
    script = f"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$Slot = '{slot}'
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$NotData = @('.venv', 'installer', 'previous.new', '.failed-*')
$Ver = '1.0.4'
$Local = ''
$script:inject = $true
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Remove-Tree([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Recurse -Force }} }}
function Remove-FailedInstall([string]$Path) {{ Remove-Tree $Path }}
function Restore-BinDir {{ }}
function Assert-BinDirRestored {{ }}
function New-FailedInstallDirectory {{
    $path = Join-Path $DataDir ('.failed-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    return $path
}}
function Copy-Kept([string]$From, [string]$To) {{
    if ($script:inject -and '{failure}' -eq 'external-config') {{ throw 'injected external config refusal' }}
    Copy-Item -LiteralPath $From -Destination $To -Force
}}
{move}
function Move-Path([string]$From, [string]$To, [int]$Seconds = 0) {{
    if ($script:inject) {{
        if (('{failure}' -eq 'live-data' -and $From -eq (Join-Path $DataDir 'config.yaml')) -or
            ('{failure}' -eq 'saved-venv' -and $From -eq (Join-Path $Slot 'venv'))) {{ throw 'injected move refusal' }}
        if ('{failure}' -eq 'unproven-data' -and $From -eq (Join-Path $Slot 'data/config.yaml')) {{ return }}
    }}
    Move-PathReal $From $To 0
    if ($script:inject -and '{failure}' -eq 'after-data' -and $From -eq (Join-Path $Slot 'data/config.yaml')) {{
        throw 'injected interruption after rename'
    }}
}}
{functions}
try {{ Restore-Slot $Slot | Out-Null; Write-Output 'RESTORED-EARLY' }} catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
if (-not (Test-Path -LiteralPath (Join-Path $Slot 'COMPLETE'))) {{ throw 'snapshot was discarded before recovery' }}
$script:inject = $false
Restore-Slot $Slot | Out-Null
Write-Output 'RESTORED'
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "REFUSED:" in out and "RESTORED-EARLY" not in out, out
    if failure != "unproven-data":
        assert "injected" in out, out
    assert not slot.exists()
    assert (data / "config.yaml").read_text(encoding="ascii") == "old data"
    assert (data / ".venv" / "runtime.txt").read_text(encoding="ascii") == "old environment"
    assert (data / ".defenseclaw-cas-intent").read_text(encoding="ascii") == "old receipt"
    assert external.read_text(encoding="ascii") == "old external config"
    failed = list(data.glob(".failed-*"))
    assert len(failed) == 1
    assert (failed[0] / "data" / "config.yaml").read_text(encoding="ascii") == "new data"
    assert (failed[0] / "venv" / "runtime.txt").read_text(encoding="ascii") == "new environment"
    assert (failed[0] / "data" / ".defenseclaw-cas-intent").read_text(encoding="ascii") == "new receipt"


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_rollback_and_upgrade_prune_hook_entries_of_connectors_no_longer_configured(tmp_path: Path) -> None:
    # rel-1-0-1:GAP-0009 on Windows: the newer gateway of the two removes the
    # DefenseClaw hook entries of a connector the live install does not
    # configure; an older gateway prints its connector help instead.
    calls = tmp_path / "calls.txt"
    gateways = []
    for name, usage in (("older", "defenseclaw-gateway connector [command]"), ("newer", "defenseclaw-gateway connector prune-orphans [flags]")):
        body = (
            f"param()\nAdd-Content -LiteralPath '{calls}' -Value ('{name} ' + ($args -join ' '))\n"
            f"if ($args -contains '--help') {{ Write-Output 'Usage:'; Write-Output '  {usage}' }}\nexit 0\n"
        )
        path = tmp_path / f"{name}.ps1"
        path.write_text(body, encoding="utf-8")
        gateways.append(path)
    data_dir = tmp_path / "dc"
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\nfunction Write-Warn([string]$m) {{ 'warn: ' + $m }}\n"
        f"{_ps1_function('Invoke-Native')}\n{_ps1_function('Get-NativeOutput')}\n{_ps1_function('Invoke-PruneOrphanedHooks')}\n"
        f"Invoke-PruneOrphanedHooks @('{tmp_path / 'missing.exe'}', '{gateways[0]}', '{gateways[1]}')\n"
    )
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "older connector prune-orphans --help",
        "newer connector prune-orphans --help",
        f"newer connector prune-orphans --data-dir {data_dir}",
    ]


def test_windows_rollback_and_upgrade_run_the_hook_entry_prune() -> None:
    # rel-1-0-1:GAP-0009: after the swap of a 1.x rollback (live gateway, then
    # the one just left in previous\bin), and in the upgrade after the migration.
    rollback = _ps1_function("Invoke-Rollback")
    prune = (
        'Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"), '
        '(Join-Path $Previous "bin\\defenseclaw-gateway.exe"))'
    )
    assert rollback.index("Switch-WithPrevious $current") < rollback.index(prune)
    assert "if (-not $toLegacy) {\n        " + prune in rollback
    install = _ps1_function("Install-New")
    assert install.index('"migrate"') < install.index('Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"))')


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_unreadable_file_is_named_once_without_the_raw_hash_error(tmp_path: Path) -> None:
    # rel-1-0-1:GAP-0007: a rollback over an unreadable previous gateway printed
    # PowerShell's ReadError record and "The property 'Hash' cannot be found".
    missing = tmp_path / "previous" / "bin" / "defenseclaw-gateway.exe"
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"{_ps1_function('Get-Sha256')}\n"
        f"try {{ Get-Sha256 '{missing}' }} catch {{ 'caught: ' + $_.Exception.Message }}\n"
    )
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    out = completed.stdout + completed.stderr
    assert f"caught: Could not read {missing}; restore read access to it, then try again" in out
    assert "Hash" not in out and "CategoryInfo" not in out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("arguments", [["-Local="], ["-Local", ""]])
def test_an_empty_local_stops_with_exit_2(tmp_path: Path, arguments: list[str]) -> None:
    # #1096/GAP-1336: an empty -Local was taken as no -Local, so the install
    # went online instead of using the assets folder that was meant.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "-Local needs the folder that holds the release assets" in completed.stdout + completed.stderr
    assert not (tmp_path / "home").exists()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["-Version="], "-Version needs a value such as 1.2.3"),
        (["-Version", ""], "-Version needs a value such as 1.2.3"),
        (["-Version", "w0-invalid-version"], "-Version must look like 1.2.3, got 'w0-invalid-version'"),
    ],
)
def test_an_empty_or_malformed_version_stops_with_exit_2(tmp_path: Path, arguments: list[str], message: str) -> None:
    # GAP-0069: a malformed -Version exited 1, and an empty one installed the
    # latest release; both are usage errors before anything changes.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 2, out
    assert message in out and "nothing was changed" in out
    assert not (tmp_path / "home").exists()


# ── 1.0.2 (DELTA-11): the rollback moves an audit store as one unit ─────────

_POWERSHELLS = sorted({p for p in (shutil.which("powershell.exe"), shutil.which("pwsh.exe") or shutil.which("pwsh")) if p})


def _run_audit_store_case(shell: str, tmp_path: Path, call: str, fail: str = "", fail_back: str = "") -> str:
    # The functions of the shipped installer, with Move-Path made to fail at
    # one step (the injection of the wave's windows-audit-injection.ps1).
    move_path = _ps1_function("Move-Path").replace("function Move-Path(", "function Move-PathReal(", 1)
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path / 'live'}'\n$Previous = '{tmp_path / 'previous'}'\n$BinDir = '{tmp_path / 'bin'}'\n"
        "$Run = [pscustomobject]@{ Log = 'install.log' }\n"
        f"$fail = '{fail}'\n$failBack = '{fail_back}'\n"
        + move_path
        + "function Move-Path([string]$From, [string]$To) {\n"
        "    if ($fail -and $From -eq $fail) { throw 'injected move failure' }\n"
        "    if ($failBack -and $To -eq $failBack) { throw 'injected move-back failure' }\n"
        "    Move-PathReal $From $To 0\n}\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Ok([string]$m) { Write-Host \"ok: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Stop-Gateway { return $true }\nfunction Switch-WithPrevious { return 0 }\nfunction Start-Gateway { return 0 }\n"
        # The rollback's lifecycle proof has its own tests; here it passes.
        "function Assert-LifecycleRestored { param($Manifest, [switch]$KeepStopped) }\n"
        + _ps1_function("Move-AuditStore")
        + _ps1_function("Move-DamagedAuditStore")
        + _ps1_function("Undo-Rollback")
        + f"try {{ $r = {call}; Write-Host \"result: $r\" }} catch {{ Write-Host \"thrown: $($_.Exception.Message)\" }}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout


def _audit_store(path: Path, label: str) -> dict[str, str]:
    store = {"": f"{label} db", "-wal": f"{label} wal", "-shm": f"{label} shm"}
    for suffix, body in store.items():
        Path(f"{path}{suffix}").write_text(body, encoding="utf-8")
    return store


def _assert_store_at(path: Path, store: dict[str, str]) -> None:
    for suffix, body in store.items():
        assert Path(f"{path}{suffix}").read_text(encoding="utf-8") == body, f"{path}{suffix}"


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("failing", ["", "audit.db", "audit.db-wal", "audit.db-shm"])
def test_the_damaged_audit_store_moves_aside_as_one_unit(tmp_path: Path, shell: str, failing: str) -> None:
    # rel-1-0-2:GAP-0491: Move-DamagedAuditStore moved audit.db-wal first, and
    # a database that then did not move stayed behind without its WAL.
    live = tmp_path / "live"
    live.mkdir()
    store = _audit_store(live / "audit.db", "saved")
    out = _run_audit_store_case(shell, tmp_path, "Move-DamagedAuditStore '0.8.10'", str(live / failing) if failing else "")
    aside = sorted(live.glob("audit.db.corrupt-*"))
    if not failing:
        assert "result: " + str(live / "audit.db.corrupt-") in out, out
        assert "warn: The saved 0.8.10 audit store failed SQLite's integrity check" in out
        _assert_store_at(Path(str(aside[0])), store)
        assert len(aside) == 3 and not (live / "audit.db").exists()
        return
    assert "thrown: injected move failure" in out, out
    _assert_store_at(live / "audit.db", store)
    assert aside == []


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
def test_a_store_that_cannot_move_back_is_named(tmp_path: Path, shell: str) -> None:
    live = tmp_path / "live"
    live.mkdir()
    _audit_store(live / "audit.db", "saved")
    out = _run_audit_store_case(
        shell, tmp_path, "Move-DamagedAuditStore '0.8.10'", str(live / "audit.db-shm"), str(live / "audit.db")
    )
    assert "thrown: injected move failure; " in out and ".corrupt-" in out and f"could not be moved back to {live / 'audit.db'}" in out, out
    # The WAL went back; only the database that refused is aside, and named.
    assert (live / "audit.db-wal").read_text(encoding="utf-8") == "saved wal"
    aside = list(live.glob("audit.db.corrupt-*"))
    assert len(aside) == 1 and aside[0].read_text(encoding="utf-8") == "saved db", aside
    assert (live / "audit.db-shm").read_text(encoding="utf-8") == "saved shm"


@pytest.mark.skipif(sys.platform != "win32" or not _POWERSHELLS, reason="Windows paths (previous\\data)")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize(
    "failing",
    ["", "audit.db", "audit.db-wal", "audit.db.corrupt-fixture", "audit.db.corrupt-fixture-wal", "audit.db.corrupt-fixture-shm"],
)
def test_an_undone_legacy_rollback_puts_the_saved_store_back_over_a_new_one(tmp_path: Path, shell: str, failing: str) -> None:
    # rel-1-0-2:GAP-0492: the failed start of the 0.x gateway made a new, empty
    # audit.db, and the undo left it there while the saved store and its WAL
    # stayed aside, so the next rollback used the empty one without a word.
    data = tmp_path / "previous" / "data"
    data.mkdir(parents=True)
    (tmp_path / "live").mkdir()
    kept = data / "audit.db.corrupt-fixture"
    saved = _audit_store(kept, "saved")
    Path(f"{data / 'audit.db'}").write_text("", encoding="utf-8")
    Path(f"{data / 'audit.db'}-wal").write_text("new wal", encoding="utf-8")
    new = {"": "", "-wal": "new wal"}
    out = _run_audit_store_case(
        shell,
        tmp_path,
        f"Undo-Rollback 'The gateway of DefenseClaw 0.8.10 did not start' '1.0.2' '0.8.10' 'true' '{tmp_path / 'live' / kept.name}'",
        str(data / failing) if failing else "",
    )
    assert "result: 1" in out, out
    assert "ok: DefenseClaw 1.0.2 is back" in out
    fresh = sorted(p for p in data.glob("audit.db.failed-start-*") if not p.name.endswith(("-wal", "-shm")))
    if not failing:
        _assert_store_at(data / "audit.db", saved)
        assert len(fresh) == 1
        _assert_store_at(fresh[0], new)
        assert not list(data.glob("audit.db.corrupt-*")) and "is still" not in out
        return
    # Nothing is mixed: each store is whole at one place, and the warning says
    # where the saved one is.
    _assert_store_at(kept, saved)
    assert f"warn: The saved 0.8.10 audit store is still {kept}" in out, out
    if failing.startswith("audit.db.corrupt-"):
        assert not (data / "audit.db").exists() and not Path(f"{data / 'audit.db'}-wal").exists()
        _assert_store_at(fresh[0], new)
    else:
        _assert_store_at(data / "audit.db", new)
        assert fresh == []


# ── 1.0.3 (B-01, GAP-0196): the new hook answers during the install ─────────


def test_the_new_hook_goes_in_before_the_data_copy() -> None:
    # GAP-0196: the 1.0.2 hook answered the whole data copy and environment
    # build with the operator-stop notice and cold starts. The new hook goes
    # in once the rollback copy holds the old one, before the slow copies.
    binary = _ps1_function("Save-BinarySnapshot")
    assert binary.index('Copy-BinDir (Join-Path $Snap "bin")') < binary.index("Install-HookFirst $Snap")
    save = _ps1_function("Save-Snapshot")
    order = [
        'Save-BinarySnapshot',
        "foreach ($entry in $entries) { Copy-Kept",
        'Move-Path $Venv (Join-Path $Snap "venv")',
        'Join-Path $Snap "COMPLETE"',
    ]
    positions = [save.index(step) for step in order]
    assert positions == sorted(positions), save
    first = _ps1_function("Install-HookFirst")
    assert first.index("Save-HookCloser $Slot $gateway") < first.index('(Join-Path $Slot "HOOK_FIRST")') < first.index("Install-File $staged $live")
    # A rollback keeps the checked hook at the registered path until the
    # restored gateway has passed its readiness and connector proof.
    undo = _ps1_function("Undo-Snapshot")
    assert undo.index("Save-LifecycleHookTransition $Slot") < undo.index("Move-Path")
    install = _ps1_function("Invoke-Install")
    assert install.index("Save-BinarySnapshot") < install.index("if (-not (Stop-Gateway))")
    restore = _ps1_function("Restore-Slot")
    assert restore.index("Save-LifecycleHookTransition $Slot") < restore.index('Restore-BinDir (Join-Path $Slot "bin")')
    proof = _ps1_function("Assert-LifecycleRestored")
    assert proof.index("Wait-LifecycleProof") < proof.index("Restore-PriorHookAfterProof")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("prior_version", ["0.8.10", "1.0.0", "1.0.2", "1.0.3"])
def test_windows_rollback_holds_checked_hook_until_prior_gateway_is_proven(tmp_path: Path, prior_version: str) -> None:
    # The registered 1.0.2 hook answered open while Restore-BinDir copied it
    # back ahead of the gateway. This exercises the real binary restore and
    # lifecycle proof with all supported prior-release families. A failed
    # proof must leave the checked new hook and durable record for a retry.
    transition_names = (
        "Get-LifecycleHookTransition", "Save-LifecycleHookTransition", "Restore-PriorHookAfterProof",
        "Ensure-LifecycleHookGuard",
    )
    optional_transition = "\n".join(
        _ps1_function(name) for name in transition_names if f"function {name}(" in _text()
    )
    body = (
        _ps1_function("Read-Text")
        + _ps1_function("Restore-BinDir")
        + _ps1_function("Assert-BinDirRestored")
        + _ps1_function("Undo-HookFirst")
        + _ps1_function("Undo-Snapshot")
        + optional_transition
        + r"""
$ManagedFiles = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')
$Slot = Join-Path $DataDir 'previous.new'
New-Item -ItemType Directory -Path (Join-Path $Slot 'bin'), (Join-Path $Slot 'closer') -Force | Out-Null
function Install-File { param($Source, $Destination) Copy-Item -LiteralPath $Source -Destination $Destination -Force }
function Remove-Aside { param($Path) Remove-Item -LiteralPath $Path -Force }
[IO.File]::WriteAllText((Join-Path $Slot 'bin\defenseclaw-gateway.exe'), 'old gateway')
[IO.File]::WriteAllText((Join-Path $Slot 'bin\defenseclaw-hook.exe'), 'old hook')
[IO.File]::WriteAllText((Join-Path $Slot 'closer\defenseclaw-hook.exe'), 'checked new hook')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'failed new gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'checked new hook')
$priorSHA = Get-Sha256 (Join-Path $Slot 'bin\defenseclaw-hook.exe')
$guardSHA = Get-Sha256 (Join-Path $Slot 'closer\defenseclaw-hook.exe')
$gatewaySHA = Get-Sha256 (Join-Path $Slot 'bin\defenseclaw-gateway.exe')
[IO.File]::WriteAllText((Join-Path $Slot 'HOOK_FIRST'), $priorSHA)
[IO.File]::WriteAllText((Join-Path $Slot 'HOOK_GUARD'), $guardSHA)
$state = [ordered]@{ Schema = 1; Operation = 'upgrade'; From = '__PRIOR__'; To = '1.0.4'; Slot = $Slot
    Bins = [ordered]@{ 'defenseclaw-gateway.exe' = $gatewaySHA
        'defenseclaw-hook.exe' = $priorSHA }; GatewayWasRunning = $true; Connectors = @(); Config = ''
    ExternalConfig = ''; ExternalConfigSha256 = ''; HookFailModes = ''; BinDirProtected = $false; SetupRoot = ''; Committed = $false }
Write-DurableText $LifecycleManifest ($state | ConvertTo-Json -Depth 4)
$recordBeforeRestore = Read-LifecycleManifest
$transitionCommand = Get-Command Save-LifecycleHookTransition -ErrorAction SilentlyContinue
$guardForRestore = if ($transitionCommand) { Save-LifecycleHookTransition $Slot } else { '' }
Restore-BinDir (Join-Path $Slot 'bin') $guardForRestore
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA) {
    throw 'the registered prior hook ran before gateway readiness'
}
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-gateway.exe')) -ne $gatewaySHA) { throw 'prior gateway not restored' }
$failed = $false
try { Assert-LifecycleRestored $recordBeforeRestore } catch { $failed = $true }
if (-not $failed -or -not (Test-Path -LiteralPath $LifecycleManifest) -or
    (Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA) {
    throw 'unproven restore released the registered prior hook or lifecycle record'
}
# Model a process stop immediately after prior-hook publication, before the
# record is retired. The retry must put the checked guard back before proof.
Copy-Item -LiteralPath (Join-Path $Slot 'bin\defenseclaw-hook.exe') -Destination (Join-Path $BinDir 'defenseclaw-hook.exe') -Force
try { Assert-LifecycleRestored $recordBeforeRestore } catch { }
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA -or
    -not (Test-Path -LiteralPath $LifecycleManifest)) { throw 'interrupted publication did not restore the guard' }
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:digestHelp = $false
function Invoke-Native { param($FilePath, $Arguments, [switch]$Quiet) if ($script:gateway) { return 0 }; return 1 }
Assert-LifecycleRestored $recordBeforeRestore
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $priorSHA -or
    (Test-Path -LiteralPath $LifecycleManifest)) { throw 'proved rollback did not finish the hook transition' }
# The unfinished-snapshot undo follows the same transition. Its snapshot is
# consumed before the caller proves the prior gateway, so the record and both
# hook copies must survive in .lifecycle-closer.
$early = Join-Path $DataDir 'early.new'
New-Item -ItemType Directory -Path (Join-Path $early 'bin'), (Join-Path $early 'closer') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $Slot 'bin\defenseclaw-hook.exe') -Destination (Join-Path $early 'bin\defenseclaw-hook.exe')
Copy-Item -LiteralPath (Join-Path $Slot 'closer\defenseclaw-hook.exe') -Destination (Join-Path $early 'closer\defenseclaw-hook.exe')
Copy-Item -LiteralPath (Join-Path $early 'closer\defenseclaw-hook.exe') -Destination (Join-Path $BinDir 'defenseclaw-hook.exe') -Force
[IO.File]::WriteAllText((Join-Path $early 'HOOK_FIRST'), $priorSHA)
[IO.File]::WriteAllText((Join-Path $early 'HOOK_GUARD'), $guardSHA)
$state['Slot'] = $early
Write-DurableText $LifecycleManifest ($state | ConvertTo-Json -Depth 4)
$earlyRecord = Read-LifecycleManifest
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
function Remove-Tree { param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }
$script:gateway = $null
Undo-Snapshot $early
if ((Test-Path -LiteralPath $early) -or (Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA -or
    -not (Test-Path -LiteralPath $LifecycleManifest)) { throw 'early undo released the prior hook before gateway proof' }
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
Assert-LifecycleRestored $earlyRecord
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $priorSHA -or
    (Test-Path -LiteralPath $LifecycleManifest)) { throw 'proved early undo did not finish the hook transition' }
'OK'
"""
    ).replace("__PRIOR__", prior_version)
    result = _txn_harness(tmp_path, body)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_windows_undo_of_a_refused_hook_first_swap_leaves_the_install_unchanged(tmp_path: Path) -> None:
    # Install-HookFirst records HOOK_FIRST and HOOK_GUARD, then a running hook
    # keeps the old image mapped and the publish is refused (the Windows
    # files-in-use lane). The prior hook never left its path, so the undo must
    # not try to publish the checked hook (the same running hook refuses it
    # again): it finishes, consumes the slot and records no hook transition,
    # so the unchanged install is neither locked nor left with a record.
    body = (
        _ps1_function("Read-Text")
        + _ps1_function("Undo-HookFirst")
        + _ps1_function("Undo-Snapshot")
        + "\n".join(_ps1_function(name) for name in ("Get-LifecycleHookTransition", "Save-LifecycleHookTransition"))
        + r"""
$Slot = Join-Path $DataDir '.repair'
New-Item -ItemType Directory -Path (Join-Path $Slot 'bin'), (Join-Path $Slot 'closer') -Force | Out-Null
$live = Join-Path $BinDir 'defenseclaw-hook.exe'
function Install-File {
    param($Source, $Destination)
    if ((Test-Path -LiteralPath $Destination) -and (Get-Sha256 $Source) -eq (Get-Sha256 $Destination)) { return }
    if ($Destination -eq $live) { throw "Could not replace $live in place (Access is denied); it was left as it was" }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
function Remove-Tree { param($Path) Remove-Item -LiteralPath $Path -Recurse -Force }
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
[IO.File]::WriteAllText((Join-Path $Slot 'bin\defenseclaw-hook.exe'), 'old hook')
[IO.File]::WriteAllText((Join-Path $Slot 'closer\defenseclaw-hook.exe'), 'checked new hook')
[IO.File]::WriteAllText($live, 'old hook')
$priorSHA = Get-Sha256 (Join-Path $Slot 'bin\defenseclaw-hook.exe')
$guardSHA = Get-Sha256 (Join-Path $Slot 'closer\defenseclaw-hook.exe')
[IO.File]::WriteAllText((Join-Path $Slot 'HOOK_FIRST'), $priorSHA)
[IO.File]::WriteAllText((Join-Path $Slot 'HOOK_GUARD'), $guardSHA)
$state = [ordered]@{ Schema = 1; Operation = 'repair'; From = '1.0.4'; To = '1.0.4'; Slot = $Slot
    Bins = [ordered]@{ 'defenseclaw-hook.exe' = $priorSHA }; GatewayWasRunning = $true; Connectors = @(); Config = ''
    ExternalConfig = ''; ExternalConfigSha256 = ''; HookFailModes = ''; BinDirProtected = $false; SetupRoot = ''; Committed = $false }
Write-DurableText $LifecycleManifest ($state | ConvertTo-Json -Depth 4)
Undo-Snapshot $Slot
if (Test-Path -LiteralPath $Slot) { throw 'the undo kept the slot of an unchanged install' }
if ((Get-Sha256 $live) -ne $priorSHA) { throw 'the undo changed the prior hook' }
$record = Read-LifecycleManifest
if ($record -and (Get-Field $record 'TransitionHookSHA256')) { throw 'the undo recorded a hook transition that never happened' }
'OK'
"""
    )
    result = _txn_harness(tmp_path, body)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("prior_version", ["0.8.10", "1.0.0", "1.0.2", "1.0.3"])
def test_windows_rollback_finishes_for_a_previously_stopped_gateway(tmp_path: Path, prior_version: str) -> None:
    # A stopped prior gateway has no readiness to prove. Its restored bytes
    # and closed hooks must be proven before the old hook and lock return.
    body = (
        _ps1_function("Read-Text")
        + _ps1_function("Restore-BinDir")
        + _ps1_function("Assert-BinDirRestored")
        + "\n".join(_ps1_function(name) for name in (
            "Get-LifecycleHookTransition", "Save-LifecycleHookTransition",
            "Restore-PriorHookAfterProof", "Ensure-LifecycleHookGuard",
        ))
        + r"""
$ManagedFiles = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')
$slot = Join-Path $DataDir 'previous.new'
New-Item -ItemType Directory -Path (Join-Path $slot 'bin'), (Join-Path $slot 'closer') -Force | Out-Null
function Write-Warn { param($Message) }
function Install-File { param($Source, $Destination) Copy-Item -LiteralPath $Source -Destination $Destination -Force }
function Remove-Aside { param($Path) Remove-Item -LiteralPath $Path -Force }
[IO.File]::WriteAllText((Join-Path $slot 'bin\defenseclaw-gateway.exe'), 'old gateway')
[IO.File]::WriteAllText((Join-Path $slot 'bin\defenseclaw-hook.exe'), 'old hook')
[IO.File]::WriteAllText((Join-Path $slot 'closer\defenseclaw-hook.exe'), 'checked new hook')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'failed new gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'checked new hook')
$sidecar = Join-Path $DataDir 'hooks\.hookcfg'
[IO.File]::WriteAllText($sidecar, '{"fail_modes":{"codex":"open"}}')
$priorSHA = Get-Sha256 (Join-Path $slot 'bin\defenseclaw-hook.exe')
$guardSHA = Get-Sha256 (Join-Path $slot 'closer\defenseclaw-hook.exe')
$gatewaySHA = Get-Sha256 (Join-Path $slot 'bin\defenseclaw-gateway.exe')
[IO.File]::WriteAllText((Join-Path $slot 'HOOK_FIRST'), $priorSHA)
[IO.File]::WriteAllText((Join-Path $slot 'HOOK_GUARD'), $guardSHA)
$record = [ordered]@{ Schema = 1; Operation = 'upgrade'; From = '__PRIOR__'; To = '1.0.4'; Slot = $slot
    Bins = [ordered]@{ 'defenseclaw-gateway.exe' = $gatewaySHA; 'defenseclaw-hook.exe' = $priorSHA }
    GatewayWasRunning = $false; Connectors = @('codex'); Config = ''; ExternalConfig = ''
    ExternalConfigSha256 = ''; HookFailModes = ''; BinDirProtected = $false; SetupRoot = ''; Committed = $false }
Write-DurableText $LifecycleManifest ($record | ConvertTo-Json -Depth 4)
$guardForRestore = Save-LifecycleHookTransition $slot
[IO.File]::WriteAllText((Join-Path $LifecycleCloser 'defenseclaw-gateway.exe'), 'checked closer')
Restore-BinDir (Join-Path $slot 'bin') $guardForRestore
$script:closeFails = $true
function Invoke-Native {
    param($FilePath, $Arguments, [switch]$Quiet)
    if ($script:closeFails) { return 1 }
    if (($Arguments -join ' ') -like 'connector refresh-fail-modes --closed*') {
        if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA) {
            throw 'old hook was published before closure'
        }
        [IO.File]::WriteAllText($sidecar, '{"fail_modes":{"codex":"closed"}}')
        $script:closes++
        return 0
    }
    throw 'a stopped gateway was probed for readiness'
}
try { Assert-LifecycleRestored (Read-LifecycleManifest); throw 'hook closure failure was accepted' }
catch { if ($_.Exception.Message -eq 'hook closure failure was accepted') { throw } }
if ((Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $guardSHA -or
    -not (Test-Path -LiteralPath $LifecycleManifest) -or
    [IO.File]::ReadAllText($sidecar) -notmatch '"open"') { throw 'failed closure released the guard' }
$script:closeFails = $false
Assert-LifecycleRestored (Read-LifecycleManifest)
if ($script:closes -ne 1 -or (Test-Path -LiteralPath $LifecycleManifest) -or
    [IO.File]::ReadAllText($sidecar) -notmatch '"closed"' -or
    (Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe')) -ne $priorSHA -or
    (Get-Sha256 (Join-Path $BinDir 'defenseclaw-gateway.exe')) -ne $gatewaySHA -or $script:gateway) {
    throw 'stopped prior install was not proven and retired'
}
'OK'
"""
    ).replace("__PRIOR__", prior_version)
    result = _txn_harness(tmp_path, body)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


def test_hook_fail_modes_are_held_from_before_the_gateway_stops_until_it_exits() -> None:
    # An earlier release's sidecar can hold an open nobody chose. For a
    # running gateway the new one sets the modes from the config and holds
    # the lock every release's hook writer takes until the old gateway has
    # exited, then sets them again (r104 W3 G3-upg round 3: the old gateway
    # could render its open again between two separate refreshes). Hooks it
    # cannot make safe refuse the swap: before the stop nothing changed,
    # after it the old gateway comes back. With no gateway running, one
    # refresh.
    install = _ps1_function("Invoke-Install")
    call = install.index("$gatewayProcess = Start-SwapHookFailModes $stagedGateway $gatewayProcess")
    swap = install.index("try { Save-BinarySnapshot }")
    stop = install.index("if (-not (Stop-Gateway))")
    finish = install.index("if (-not (Complete-HookFailModeHold))")
    assert call < swap < stop < finish < install.index("$saved = Save-Snapshot"), install
    assert install.index("$stagedGateway = Join-Path $Staging") < call
    handoff = _ps1_function("Start-SwapHookFailModes")
    plain = handoff.index("if (-not (Update-HookFailModes $StagedGateway))")
    hold = handoff.index("if (-not (Start-HookFailModeHold $StagedGateway $GatewayProcess.Id))")
    assert plain < hold, handoff
    assert handoff.count("nothing was changed (see above)") == 2, handoff
    # A hook swap that fails lets go of the hold before it undoes the swap.
    failed_swap = install[swap : install.index("$stopRefused = $false", swap)]
    assert failed_swap.index("Stop-HookFailModeHold") < failed_swap.index("Undo-EarlySnapshot $Snap"), failed_swap
    # The refusal after the stop throws into the catch that undoes every
    # step after the hook swap (r104 W4 review, loop round 1); that catch
    # lets go of a hold that still waits for a gateway that did not stop.
    after = install[finish : install.index("$saved = Save-Snapshot", finish)]
    assert after.index("Stop-HookFailModeHold") < after.index("Undo-EarlySnapshot $Snap"), after
    assert after.index("Clear-StagedRelease") < after.index("Restart-Old") < after.index("$(Get-RestoredNote)"), after
    start = _ps1_function("Start-HookFailModeHold")
    assert '--hold-until-exit $GatewayId' in start and 'Contains("Holding the hook fail modes")' in start, start
    assert "Test-InstalledHookRuntime" in start, start
    assert "Stop-HookFailModeHold" in start and start.rstrip().endswith("return $false\n}"), start
    assert "$hold.Process.ExitCode -eq 0" in _ps1_function("Complete-HookFailModeHold")
    update = _ps1_function("Update-HookFailModes")
    assert '@("connector", "refresh-fail-modes", "--data-dir", $DataDir)) -eq 0' in update, update
    assert "Test-InstalledHookRuntime" in update, update
    # A downgrade's older gateway prints the connector help instead; any other
    # probe answer refuses the swap.
    probe = _ps1_function("Test-HookFailModeRefresh")
    assert '-match "defenseclaw-gateway connector \\[command\\]") { return 1 }' in probe, probe
    assert probe.rstrip().endswith("return 2\n}"), probe


def test_setup_hooks_are_disabled_only_once_the_fail_modes_are_ready() -> None:
    # r104 Guard follow-up 4 (loop round 2): Disable-SetupHooks ran before the
    # fail-mode refresh and its hold, so DefenseClaw Setup's hook launcher,
    # which agents keep at its cached path, answered every call with exit 0
    # and no decision while the staged gateway took up to a minute to hold the
    # modes. Every refresh and the hold now run with the launcher enabled; it
    # is disabled right before the stop, or, with no gateway running, right
    # after the refresh, and put back when a gateway it started turns up.
    handoff = _ps1_function("Start-SwapHookFailModes")
    disables = [m.start() for m in re.finditer(r"^ +Disable-SetupHooks", handoff, re.M)]
    assert len(disables) == 1, handoff
    plain = handoff.index("if (-not (Update-HookFailModes $StagedGateway))")
    hold = handoff.index("if (-not (Start-HookFailModeHold $StagedGateway $GatewayProcess.Id))")
    assert plain < disables[0] < handoff.index("Enable-SetupHooks") < hold, handoff
    install = _ps1_function("Invoke-Install")
    call = install.index("$gatewayProcess = Start-SwapHookFailModes $stagedGateway $gatewayProcess")
    quiet = install.index("            if ($Setup) { Disable-SetupHooks }\n            Write-Info \"Stopping the gateway")
    assert call < install.index("try { Save-BinarySnapshot }") < quiet < install.index("if (-not (Stop-Gateway))"), install
    assert "Start-HookFailModeHold" not in install and "Update-HookFailModes" not in install, install
    assert "Enable-SetupHooks" in _ps1_function("Restore-SetupInstall")


_HANDOFF_STUBS = """
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Staging = '{staging}'
$SetupHookState = '{state}'
$SetupDelegatedHooks = Join-Path '{staging}' 'delegated'
$Setup = {setup}
$events = New-Object System.Collections.Generic.List[string]
$script:looks = @({looks})
$script:look = 0
function Mark([string]$step) {{ $events.Add("$step=$(if (Test-Path -LiteralPath $SetupHookState) {{ 'enabled' }} else {{ 'disabled' }})") }}
function Get-GatewayProcess {{
    $i = [Math]::Min($script:look, $script:looks.Count - 1); $script:look++
    if ($script:looks[$i]) {{ return [pscustomobject]@{{ Id = 4242 }} }}
    return $null
}}
function Update-HookFailModes([string]$Gateway) {{ Mark 'refresh'; return {refresh} }}
function Start-HookFailModeHold([string]$Gateway, [int]$GatewayId) {{ Mark "hold:$GatewayId"; return {hold} }}
function Stop-HookFailModeHold {{ Mark 'release' }}
function Complete-HookFailModeHold {{ Mark 'complete'; return {complete} }}
function Stop-Gateway {{ Mark 'stop'; return {stop} }}
function Clear-StagedRelease {{ Mark 'clear' }}
function Restart-Old {{ if ($Setup) {{ Restore-SetupInstall }} }}
function Start-SetupGateway([string]$Root) {{ Mark 'start-setup' }}
function Get-RestoredNote {{ return 'restored' }}
function Get-UtcClock {{ return 'T' }}
function Write-Info([string]$m) {{ }}
function Die([string]$m) {{ throw $m }}
function Write-Warn([string]$m) {{ $events.Add("warn") }}
function Protect-SetupLauncherFile([string]$Path) {{ }}
"""


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize(
    ("case", "setup", "looks", "results", "want_events", "want_out"),
    [
        # A running Setup gateway: the launcher answers through it while the hold is taken.
        ("running", True, ["1"], {}, ["hold:4242=enabled"], "was=True"),
        # None running: enabled through the refresh, then disabled.
        ("stopped", True, ["0", "0"], {}, ["refresh=enabled"], "was=False"),
        # The enabled launcher started Setup's gateway during the refresh: held like a running one.
        ("started-by-launcher", True, ["0", "1"], {}, ["refresh=enabled", "hold:4242=enabled"], "was=True"),
        # Refusals leave the launcher enabled.
        ("hold-fails", True, ["1"], {"hold": "$false"}, ["hold:4242=enabled"], "thrown=Could not set"),
        ("refresh-fails", True, ["0"], {"refresh": "$false"}, ["refresh=enabled"], "thrown=Could not set"),
        # No Setup install: its state is never touched.
        ("plain-running", False, ["1"], {}, ["hold:4242=enabled"], "was=True"),
        ("plain-stopped", False, ["0"], {}, ["refresh=enabled"], "was=False"),
    ],
)
def test_setup_hook_launcher_answers_until_the_fail_mode_hold_is_ready(
    tmp_path: Path,
    shell: str,
    case: str,
    setup: bool,
    looks: list[str],
    results: dict[str, str],
    want_events: list[str],
    want_out: str,
) -> None:
    # The handoff of the shipped installer with its steps stubbed: each step
    # records whether Setup's launcher state was in place when it ran.
    staging, runtime = tmp_path / "staging", tmp_path / "HookRuntime"
    staging.mkdir()
    runtime.mkdir()
    state = runtime / "hook-runtime-state.json"
    state.write_text('{"status":"active"}', encoding="utf-8")
    values = {"refresh": "$true", "hold": "$true", "complete": "$true", "stop": "$true", **results}
    stubs = _HANDOFF_STUBS.format(
        staging=staging,
        state=state,
        setup="[pscustomobject]@{ Root = 'C:\\Setup' }" if setup else "$null",
        looks=", ".join(f"${'true' if look == '1' else 'false'}" for look in looks),
        **values,
    )
    script = tmp_path / "handoff.ps1"
    script.write_text(
        stubs
        + _ps1_function("Move-Path")
        + _ps1_function("Get-Field")
        + _ps1_function("Read-Json")
        + _ps1_function("Invoke-Quietly")
        + _ps1_function("Test-SetupLauncherTrampoline")
        + _ps1_function("Publish-SetupLauncherTrampoline")
        + _ps1_function("Disable-SetupHooks")
        + _ps1_function("Enable-SetupHooks")
        + _ps1_function("Restore-SetupInstall")
        + _ps1_function("Start-SwapHookFailModes")
        # This test exercises handoff timing; the publisher's byte and digest
        # contract has its own test below. Model a valid atomic publisher.
        + "function Publish-SetupLauncherTrampoline { [IO.File]::WriteAllText($SetupHookState, 'delegated'); return $true }\n"
        + "function Test-SetupLauncherTrampoline { return (Test-Path -LiteralPath $SetupHookState) -and ([IO.File]::ReadAllText($SetupHookState) -eq 'delegated') }\n"
        + "try { $was = [bool](Start-SwapHookFailModes 'staged-gateway.exe' (Get-GatewayProcess)); Write-Host \"was=$was\" } "
        + "catch { Write-Host \"thrown=$($_.Exception.Message)\" }\n"
        + "foreach ($e in $events) { Write-Host \"event $e\" }\n"
        + "Write-Host \"end=$(if (Test-Path -LiteralPath $SetupHookState) { 'enabled' } else { 'disabled' })\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = completed.stdout.splitlines()
    assert [line[len("event ") :] for line in lines if line.startswith("event ")] == want_events, (case, completed.stdout)
    assert any(line.startswith(want_out) for line in lines), (case, completed.stdout)
    # With no gateway running, the launcher delegates to the staged hook;
    # its state remains present throughout the swap.
    assert "end=enabled" in lines, (case, completed.stdout)
    assert not (staging / "hook-runtime-state.json").exists() or setup, (case, completed.stdout)


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_hook_fail_mode_refresh_refuses_a_probe_that_fails(tmp_path: Path) -> None:
    # r104 W3 G3-upg: a staged gateway whose help probe failed or printed
    # nothing was taken for an older one and the swap went on, so the gateway
    # could stop with a stale open in hooks\.hookcfg. Only the newer
    # gateway's help runs the refresh and only an older one's connector help
    # skips it; every other answer is false.
    data_dir = tmp_path / "dc"
    (data_dir / "hooks").mkdir(parents=True)
    (data_dir / "hooks" / ".hookcfg").write_text("{}", encoding="utf-8")
    calls = tmp_path / "calls.txt"
    cases = {
        "newer": ("Write-Output '  defenseclaw-gateway connector refresh-fail-modes [flags]'; exit 0", True),
        "older": ("Write-Output '  defenseclaw-gateway connector [command]'; exit 0", True),
        "fails": ("[Console]::Error.WriteLine('cannot run'); exit 1", False),
        "silent": ("exit 0", False),
    }
    for name, (help_body, want) in cases.items():
        gateway = tmp_path / f"{name}.ps1"
        gateway.write_text(
            f"Add-Content -LiteralPath '{calls}' -Value ('{name} ' + ($args -join ' '))\n"
            f"if ($args -contains '--help') {{ {help_body} }}\nexit 0\n",
            encoding="utf-8",
        )
        script = (
            "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
            f"$DataDir = '{data_dir}'\nfunction Write-Warn([string]$m) {{ [Console]::Error.WriteLine('warn: ' + $m) }}\n"
            f"{_ps1_function('Invoke-Native')}\n{_ps1_function('Get-NativeProbe')}\n"
            f"{_ps1_function('Test-HookFailModeRefresh')}\n{_ps1_function('Test-InstalledHookRuntime')}\n{_ps1_function('Update-HookFailModes')}\n"
            f"if (Update-HookFailModes '{gateway}') {{ 'refresh=true' }} else {{ 'refresh=false' }}\n"
        )
        completed = _run_powershell(script)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert f"refresh={str(want).lower()}" in completed.stdout, (name, completed.stdout, completed.stderr)
    ran = [line for line in calls.read_text(encoding="utf-8").splitlines() if "--data-dir" in line]
    assert ran == [f"newer connector refresh-fail-modes --data-dir {data_dir}"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_hook_fail_mode_refresh_runs_without_json_sidecar(tmp_path: Path) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    helper = _ps1_function("Test-InstalledHookRuntime") if "function Test-InstalledHookRuntime " in _text() else ""
    for name in ("cursor-hook.ps1", ".hookcfg.cursor"):
        installed = hooks / name
        installed.write_text("retained open adapter or record", encoding="utf-8")
        script = (
            "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
            f"$DataDir = '{tmp_path}'\n$script:refreshes = 0\n"
            "function Test-HookFailModeRefresh([string]$g) { return 0 }\n"
            "function Invoke-Native($g, $a) { $script:refreshes++; return 0 }\n"
            + helper + "\n" + _ps1_function("Update-HookFailModes")
            + "\nif (-not (Update-HookFailModes 'staged-gateway')) { throw 'refresh refused' }\n"
            + "if ($script:refreshes -ne 1) { throw 'installed hooks were not refreshed' }\n"
        )
        completed = _run_powershell(script)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        installed.unlink()


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize(
    "case", ["upgrade", "first-install", "interrupted-before-marker", "copy-lost", "copy-changed", "legacy-marker"]
)
def test_install_hook_first_swaps_the_hook_and_undo_puts_it_back(tmp_path: Path, shell: str, case: str) -> None:
    # r104 W4 loop 2: the rollback copy is the only old hook once the new one
    # is in, so the new hook goes in only over a copy with the old hook's
    # bytes (copy-lost, copy-changed refuse with nothing changed). HOOK_FIRST
    # records that SHA-256; a 1.0.3 marker (empty) still undoes from the copy.
    bin_dir, staging, slot = tmp_path / "bin", tmp_path / "staging", tmp_path / "slot"
    (staging / "bin").mkdir(parents=True)
    (staging / "bin" / "defenseclaw-hook.exe").write_text("new", encoding="utf-8")
    (staging / "bin" / "defenseclaw-gateway.exe").write_text("new gateway", encoding="utf-8")
    if case != "first-install":
        bin_dir.mkdir()
        (bin_dir / "defenseclaw-hook.exe").write_text("old", encoding="utf-8")
    saved_copy = "(Join-Path (Join-Path $Slot bin) 'defenseclaw-hook.exe')"
    refuse = "try { Install-HookFirst $Slot } catch { Write-Host \"refused: $($_.Exception.Message)\" }"
    steps = {
        "interrupted-before-marker": "Copy-BinDir (Join-Path $Slot bin); Undo-HookFirst $Slot",
        "copy-lost": f"Copy-BinDir (Join-Path $Slot bin); Remove-Item -LiteralPath {saved_copy}; {refuse}",
        "copy-changed": f"Copy-BinDir (Join-Path $Slot bin); Set-Content -LiteralPath {saved_copy} -Value 'tampered'; {refuse}",
        "legacy-marker": (
            "Copy-BinDir (Join-Path $Slot bin); Set-Content -LiteralPath (Join-Path $Slot HOOK_FIRST) -Value '' -Encoding Ascii; "
            "Copy-Item -LiteralPath (Join-Path (Join-Path $Staging bin) 'defenseclaw-hook.exe') -Destination (Join-Path $BinDir 'defenseclaw-hook.exe') -Force; "
            "Undo-HookFirst $Slot"
        ),
    }.get(
        case,
        "Copy-BinDir (Join-Path $Slot bin); Install-HookFirst $Slot; Write-Host \"after: $(Get-Content -Raw (Join-Path $BinDir 'defenseclaw-hook.exe') -ErrorAction SilentlyContinue)\"; Undo-HookFirst $Slot",
    )
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$BinDir = '{bin_dir}'\n$Staging = '{staging}'\n$Slot = '{slot}'\n"
        "$ManagedFiles = @('defenseclaw-hook.exe')\n"
        "function Install-File([string]$From, [string]$To) { Copy-Item -LiteralPath $From -Destination $To -Force }\n"
        "function Wait-PreviousHookExit([DateTime]$PublishedAt) {}\n"
        "function Remove-Aside([string]$Path) { Remove-Item -LiteralPath $Path -Force }\n"
        + _bin_dir_functions()
        + _ps1_function("Read-Text")
        + _ps1_function("Get-Sha256")
        + _ps1_function("Write-DurableText")
        + _ps1_function("Install-HookFirst")
        + _ps1_function("Save-HookCloser")
        + _ps1_function("Undo-HookFirst")
        + steps
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    live = bin_dir / "defenseclaw-hook.exe"
    if case == "first-install":
        # Nothing ran a hook before: nothing to swap, no marker, no hook yet.
        assert not live.exists() and not (slot / "HOOK_FIRST").exists(), out
        return
    if case == "upgrade":
        assert "after: new" in out, out
        assert (slot / "HOOK_FIRST").read_text(encoding="ascii").strip() == hashlib.sha256(b"old").hexdigest()
        assert (slot / "bin" / "defenseclaw-hook.exe").read_text(encoding="utf-8") == "old"
        # The staged gateway is kept beside it, a hard link where the volume allows.
        closer = slot / "closer" / "defenseclaw-gateway.exe"
        assert closer.read_text(encoding="utf-8") == "new gateway"
    elif case in ("copy-lost", "copy-changed"):
        assert "refused: Could not keep a whole rollback copy" in out and "nothing was changed" in out, out
        assert not (slot / "HOOK_FIRST").exists() and not (slot / "closer").exists(), out
    elif case == "interrupted-before-marker":
        assert not (slot / "HOOK_FIRST").exists() and not (slot / "closer").exists()
    # Undo leaves the old hook live.
    assert live.read_text(encoding="utf-8").strip() == "old", out


_EARLY_UNDO_SITES = ["hook-drain", "stop", "fail-modes", "quiescence", "save"]


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("block", ["none", "once", "always", "silent", "copy-lost", "copy-changed"])
@pytest.mark.parametrize("site", _EARLY_UNDO_SITES)
def test_a_blocked_early_hook_restore_keeps_the_install_locked(tmp_path: Path, shell: str, block: str, site: str) -> None:
    # r104 W4 loop 3: the new hook goes in before the gateway stops. A later
    # step that refused the upgrade put the old hook back through
    # Invoke-Quietly; a hook reader or a scanner holding the file hid that
    # failure, Restart-Old's retry threw before the old gateway started, and
    # the lock went with the new hook live and the gateway stopped. Every
    # refusal after the swap runs here with the restore blocked once, always,
    # or "copied" without the bytes changing. A restore that is not verified
    # keeps .install.lock and the slot for the next run, never says nothing
    # was changed, and the old gateway runs either way.
    # r104 W4 loop 2: the same holds when the rollback copy of the old hook
    # is quarantined (copy-lost) or changed (copy-changed) after the swap:
    # the undo skipped a missing copy and removed the slot. The next run
    # stays locked until the copy is back, then finishes the undo.
    data_dir, bin_dir, staging = tmp_path / "dc", tmp_path / "bin", tmp_path / "staging"
    (staging / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    data_dir.mkdir()
    (staging / "bin" / "defenseclaw-hook.exe").write_text("new", encoding="utf-8")
    # The staged gateway the slot keeps as the hook closer (W4b).
    (staging / "bin" / "defenseclaw-gateway.exe").write_text("new gateway", encoding="utf-8")
    (bin_dir / "defenseclaw-hook.exe").write_text("old", encoding="utf-8")
    (bin_dir / "defenseclaw-gateway.exe").write_text("old gateway", encoding="utf-8")
    install = _ps1_function("Invoke-Install")
    phase = install[install.index("    $gatewayProcess = Get-GatewayProcess\n") : install.index("    $previousLabel =")]
    blocks = {"none": 0, "once": 1, "always": 99, "silent": 99}.get(block, 0)
    real = "".join(
        _ps1_function(name)
        for name in (
            "Invoke-Quietly", "Start-SwapHookFailModes", "Read-Text", "Get-Sha256", "Copy-BinDir", "Save-BinarySnapshot", "Install-HookFirst", "Save-HookCloser",
            "Undo-HookFirst", "Undo-Snapshot", "Undo-EarlySnapshot", "Restart-Old", "Test-RecoveryPending",
            "Get-UnchangedNote", "Close-InstallLock", "Get-RestoredNote", "Resume-InterruptedRun",
            "Start-AcceptedReplacement", "Finish-EarlySnapshotRestore",
        )
    )
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\n$BinDir = '{bin_dir}'\n$Staging = '{staging}'\n$Previous = Join-Path $DataDir 'previous'\n"
        "$LockDir = Join-Path $DataDir '.install.lock'\n"
        "$ManagedFiles = @('defenseclaw-hook.exe', 'defenseclaw-gateway.exe')\n"
        "$Run = @{ Lock = $true; OldGatewayDown = $false; UndoPending = $false; RestorePending = $false }\n"
        "$Setup = $null; $PrevVersion = '1.0.2'; $Ver = '1.0.4'; $versionChange = $true; $Repair = $false; $stagedGateway = 'staged'\n"
        f"$script:site = '{site}'; $script:blocks = {blocks}; $script:silent = ${str(block == 'silent').lower()}; $script:lose = '{block}'\n"
        "$script:running = $true; $script:starts = 0; $script:modeCalls = 0\n"
        "function Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Ok([string]$m) { Write-Host \"ok: $m\" }\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Die([string]$m) { throw $m }\n"
        "function Get-UtcClock { 'clock' }\n"
        "function New-InstallDirectory([string]$Path) { Remove-Tree $Path; New-Item -ItemType Directory -Path $Path | Out-Null }\n"
        "function Remove-Tree([string]$Path) { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }\n"
        "function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) { Move-Item -LiteralPath $From -Destination $To }\n"
        "function Install-File([string]$Source, [string]$Destination) {\n"
        "    if ($Destination -eq (Join-Path $BinDir 'defenseclaw-hook.exe') -and (Get-Content -Raw -LiteralPath $Source) -eq 'old' -and $script:blocks -gt 0) {\n"
        "        $script:blocks--\n"
        "        if ($script:silent) { return }\n"
        "        throw 'The process cannot access the file because it is being used by another process'\n"
        "    }\n"
        "    Copy-Item -LiteralPath $Source -Destination $Destination -Force\n"
        "}\n"
        "function Wait-PreviousHookExit([DateTime]$PublishedAt) {\n"
        "    $copy = Join-Path (Join-Path $Snap bin) 'defenseclaw-hook.exe'\n"
        "    if ($script:lose -eq 'copy-lost') { Remove-Item -LiteralPath $copy }\n"
        "    if ($script:lose -eq 'copy-changed') { Set-Content -LiteralPath $copy -Value 'tampered' -NoNewline }\n"
        "    if ($script:site -eq 'hook-drain') { throw 'Previous hook calls did not finish within 30 seconds' }\n"
        "}\n"
        "function Get-GatewayProcess { if ($script:running) { return [pscustomobject]@{ Id = 1 } }; return $null }\n"
        "function Update-HookFailModes([string]$Gateway) { $script:modeCalls++; return $true }\n"
        + _NO_TXN
        + "function Complete-HookFailModeHold { return $script:site -ne 'fail-modes' }\n"
        "function Stop-Gateway { if ($script:site -eq 'stop') { return $false }; $script:running = $false; return $true }\n"
        "function Start-Gateway { $script:starts++; $script:running = $true; return 0 }\n"
        "function Stop-Watchdog {}\n"
        "function Assert-GatewayQuiescent([string]$Operation) { if ($script:site -eq 'quiescence') { throw \"$Operation refused: a hook is still running\" } }\n"
        "function Assert-NoActiveConnectorRecovery([string]$Operation) {}\n"
        "function Clear-StagedRelease {}\n"
        "function Save-Snapshot { return $false }\n"
        "function Test-DiskFull { return $false }\n"
        "function Stop-ProcessesUnder {}\n"
        + real
        + "New-Item -ItemType Directory -Path $LockDir -Force | Out-Null\n"
        "$message = ''\n"
        "try {\n" + phase + "    throw 'the refusal did not happen'\n} catch { $message = $_.Exception.Message }\n"
        "Close-InstallLock\n"
        "Write-Host \"message: $message\"\n"
        "Write-Host \"pending: $(Test-RecoveryPending)\"\n"
        "Write-Host \"running: $script:running starts: $script:starts\"\n"
        "Write-Host \"hook: $(Get-Content -Raw -LiteralPath (Join-Path $BinDir 'defenseclaw-hook.exe'))\"\n"
        "# The next run, with the file free again, finishes the undo.\n"
        "$script:blocks = 0\n"
        "try { Resume-InterruptedRun; Write-Host 'resume: ok' } catch { Write-Host \"resume: failed $($_.Exception.Message)\" }\n"
        "Write-Host \"resumed hook: $(Get-Content -Raw -LiteralPath (Join-Path $BinDir 'defenseclaw-hook.exe'))\"\n"
        "Write-Host \"resumed slot: $(Test-Path -LiteralPath $Snap)\"\n"
        "# The copy is back (out of quarantine): the run after that finishes the undo.\n"
        "if (Test-Path -LiteralPath $Snap) { Set-Content -LiteralPath (Join-Path (Join-Path $Snap bin) 'defenseclaw-hook.exe') -Value 'old' -NoNewline }\n"
        "Resume-InterruptedRun\n"
        "Write-Host \"final hook: $(Get-Content -Raw -LiteralPath (Join-Path $BinDir 'defenseclaw-hook.exe'))\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "the refusal did not happen" not in out, out
    # Only Restart-Old retries; the two refusals before the gateway stopped
    # have no second try.
    lost = block in ("copy-lost", "copy-changed")
    pending = lost or block in ("always", "silent") or (block == "once" and site in ("hook-drain", "stop"))
    slot = data_dir / "previous.new"
    lock = data_dir / ".install.lock"
    assert f"pending: {pending}" in out, out
    # The old gateway runs whether or not the old hook is back.
    assert "running: True" in out, out
    if site in ("fail-modes", "quiescence", "save"):
        assert "starts: 1" in out, out
    if pending:
        assert lock.is_dir(), out
        assert "The install stays locked" in out, out
        assert "nothing was changed" not in out and "Your previous install is back" not in out, out
        if site in ("stop", "fail-modes", "save"):
            assert "not fully back" in out, out
        assert "hook: new" in out, out
    else:
        assert not lock.exists(), out
        assert "hook: old" in out, out
    if lost:
        # No copy of the old hook, no restore: the next run refuses, keeps
        # the slot and the new hook, until the copy is back.
        assert "is missing or changed" in out, out
        assert "resume: failed" in out and "resumed hook: new" in out and "resumed slot: True" in out, out
    else:
        # Either way the next run leaves the old hook live and no slot.
        assert "resume: ok" in out and "resumed hook: old" in out, out
    assert "final hook: old" in out, out
    assert not slot.exists(), out


_EARLY_THROW_SITES = ["stop", "fail-modes", "watchdog", "quiescence", "recovery", "restart"]


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("block", ["none", "always"])
@pytest.mark.parametrize("site", _EARLY_THROW_SITES)
def test_a_step_that_throws_after_the_hook_swap_restores_the_old_install(
    tmp_path: Path, shell: str, block: str, site: str
) -> None:
    # r104 W4 review, loop round 1: after the new hook went in, Stop-Gateway
    # stopped the old gateway and then threw on its last gateway.pid read.
    # The error skipped the undo and the restart, and the lock went with the
    # new hook live and the gateway stopped. Every step between the hook swap
    # and the rollback copy throws here once (the stop after the process
    # exited, the second fail-mode refresh, the watchdog stop, each refusal);
    # "restart" also makes the old gateway's restart throw. The old hook goes
    # back, the old gateway runs again (or the message says it does not),
    # and an undo that did not finish keeps .install.lock.
    data_dir, bin_dir, staging = tmp_path / "dc", tmp_path / "bin", tmp_path / "staging"
    (staging / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    data_dir.mkdir()
    (staging / "bin" / "defenseclaw-hook.exe").write_text("new", encoding="utf-8")
    # The staged gateway the slot keeps as the hook closer (W4b).
    (staging / "bin" / "defenseclaw-gateway.exe").write_text("new gateway", encoding="utf-8")
    (bin_dir / "defenseclaw-hook.exe").write_text("old", encoding="utf-8")
    (bin_dir / "defenseclaw-gateway.exe").write_text("old gateway", encoding="utf-8")
    install = _ps1_function("Invoke-Install")
    phase = install[install.index("    $gatewayProcess = Get-GatewayProcess\n") : install.index("    $previousLabel =")]
    real = "".join(
        _ps1_function(name)
        for name in (
            "Invoke-Quietly", "Start-SwapHookFailModes", "Read-Text", "Get-Sha256", "Copy-BinDir", "Save-BinarySnapshot", "Install-HookFirst", "Save-HookCloser",
            "Undo-HookFirst", "Undo-Snapshot", "Undo-EarlySnapshot", "Restart-Old", "Test-RecoveryPending",
            "Get-UnchangedNote", "Close-InstallLock", "Get-RestoredNote",
            "Start-AcceptedReplacement", "Finish-EarlySnapshotRestore",
        )
    )
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\n$BinDir = '{bin_dir}'\n$Staging = '{staging}'\n$Previous = Join-Path $DataDir 'previous'\n"
        "$LockDir = Join-Path $DataDir '.install.lock'\n"
        "$ManagedFiles = @('defenseclaw-hook.exe', 'defenseclaw-gateway.exe')\n"
        "$Run = @{ Lock = $true; OldGatewayDown = $false; UndoPending = $false; RestorePending = $false }\n"
        "$Setup = $null; $PrevVersion = '1.0.3'; $Ver = '1.0.4'; $versionChange = $true; $Repair = $false; $stagedGateway = 'staged'\n"
        f"$script:site = '{site}'; $script:blocked = ${str(block == 'always').lower()}\n"
        "$script:running = $true; $script:starts = 0; $script:modeCalls = 0\n"
        "function Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Ok([string]$m) { Write-Host \"ok: $m\" }\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Die([string]$m) { throw $m }\n"
        "function Get-UtcClock { 'clock' }\n"
        "function New-InstallDirectory([string]$Path) { Remove-Tree $Path; New-Item -ItemType Directory -Path $Path | Out-Null }\n"
        "function Remove-Tree([string]$Path) { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }\n"
        "function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) { Move-Item -LiteralPath $From -Destination $To }\n"
        "function Install-File([string]$Source, [string]$Destination) {\n"
        "    if ($script:blocked -and $Destination -eq (Join-Path $BinDir 'defenseclaw-hook.exe') -and (Get-Content -Raw -LiteralPath $Source) -eq 'old') {\n"
        "        throw 'The process cannot access the file because it is being used by another process'\n"
        "    }\n"
        "    Copy-Item -LiteralPath $Source -Destination $Destination -Force\n"
        "}\n"
        "function Wait-PreviousHookExit([DateTime]$PublishedAt) {}\n"
        "function Get-GatewayProcess {\n"
        "    if ($script:site -eq 'restart' -and $script:starts -gt 0) { throw 'Exception calling ReadAllText: gateway.pid is being used by another process' }\n"
        "    if ($script:running) { return [pscustomobject]@{ Id = 1 } }; return $null\n"
        "}\n"
        "function Update-HookFailModes([string]$Gateway) { return $true }\n"
        + _NO_TXN
        + "function Complete-HookFailModeHold { if ($script:site -eq 'fail-modes') { throw 'connector refresh-fail-modes crashed' }; return $true }\n"
        "function Stop-Gateway {\n"
        "    # The old process exits; the last pid-file read then fails.\n"
        "    $script:running = $false\n"
        "    if ($script:site -in @('stop', 'restart')) { throw 'Exception calling ReadAllText: gateway.pid is being used by another process' }\n"
        "    return $true\n"
        "}\n"
        "function Start-Gateway { $script:starts++; if ($script:site -eq 'restart') { throw 'Exception calling ReadAllText: gateway.pid is being used by another process' }; $script:running = $true; return 0 }\n"
        "function Stop-Watchdog { if ($script:site -eq 'watchdog') { throw 'watchdog stop crashed' } }\n"
        "function Assert-GatewayQuiescent([string]$Operation) { if ($script:site -eq 'quiescence') { throw \"$Operation refused: a hook is still running\" } }\n"
        "function Assert-NoActiveConnectorRecovery([string]$Operation) { if ($script:site -eq 'recovery') { throw \"$Operation refused: a connector recovery is active\" } }\n"
        "function Clear-StagedRelease {}\n"
        "function Save-Snapshot { throw 'the step that throws did not stop the install' }\n"
        "function Test-DiskFull { return $false }\n"
        "function Stop-ProcessesUnder {}\n"
        + real
        + "New-Item -ItemType Directory -Path $LockDir -Force | Out-Null\n"
        "$message = ''\n"
        "try {\n" + phase + "    throw 'the step did not fail'\n} catch { $message = $_.Exception.Message }\n"
        "Close-InstallLock\n"
        "Write-Host \"message: $message\"\n"
        "Write-Host \"pending: $(Test-RecoveryPending)\"\n"
        "Write-Host \"running: $script:running starts: $script:starts\"\n"
        "Write-Host \"hook: $(Get-Content -Raw -LiteralPath (Join-Path $BinDir 'defenseclaw-hook.exe'))\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "the step did not fail" not in out and "did not stop the install" not in out, out
    lock = data_dir / ".install.lock"
    # The step's own error is named.
    reason = {
        "stop": "gateway.pid is being used",
        "restart": "gateway.pid is being used",
        "fail-modes": "connector refresh-fail-modes crashed",
        "watchdog": "watchdog stop crashed",
        "quiescence": "a hook is still running",
        "recovery": "a connector recovery is active",
    }[site]
    assert reason in out, out
    # The old gateway is started again once, after the step failed.
    assert "starts: 1" in out, out
    if site == "restart":
        assert "running: False" in out, out
        assert "did not start again" in out, out
    else:
        assert "running: True" in out, out
    if block == "always":
        assert "pending: True" in out, out
        assert lock.is_dir(), out
        assert "The install stays locked" in out and "not fully back" in out, out
        assert "Your previous install is back" not in out and "nothing was changed" not in out, out
        assert "hook: new" in out, out
    else:
        assert "pending: False" in out, out
        assert not lock.exists(), out
        assert "hook: old" in out, out
        if site == "restart":
            assert "Your previous install is back, but its gateway is not running" in out, out
        else:
            assert "Your previous install is back." in out, out


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("site", ["start", "stop"])
def test_a_new_gateway_start_that_throws_restores_the_previous_install(tmp_path: Path, shell: str, site: str) -> None:
    # The same class after the swap: a start of the new gateway (or the
    # stop after its failed start) that throws instead of returning an exit
    # code skipped Restore-Snapshot, so the new install stayed live with no
    # gateway. A throw is a failed start: the previous install is restored
    # and the swap is never completed.
    install = _ps1_function("Invoke-Install")
    phase = install[install.index("    $startRc = 0\n") : install.index("    Complete-Swap\n")]
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path}'\n"
        "$Run = @{ Log = 'install.log' }\n"
        "$Snap = (New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'previous.new')).FullName\n"
        "$Manifest = $null; $stagedBinaries = @{}\n"
        + _NO_TXN
        + "function Get-Field($Object, [string]$Name) { return $null }\n"
        "$Setup = $null; $PrevVersion = '1.0.3'; $Ver = '1.0.4'; $WasRunning = $true; $previousLabel = '1.0.3'\n"
        "$env:DEFENSECLAW_CONFIG = 'config.yaml'\n"
        f"$script:site = '{site}'; $script:restored = 0\n"
        "function Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Die([string]$m) { throw $m }\n"
        "function Get-UtcClock { 'clock' }\n"
        "function Test-ConnectorConfigured { return $true }\n"
        "function Start-Gateway { if ($script:site -eq 'start') { throw 'Exception calling ReadAllText: gateway.pid' }; return 1 }\n"
        "function Stop-Gateway { if ($script:site -eq 'stop') { throw 'Exception calling ReadAllText: gateway.pid' }; return $true }\n"
        "function Restore-Snapshot { $script:restored++ }\n"
        "function Get-RestoredNote { 'Your previous install is back.' }\n"
        "$message = ''\n"
        "try {\n" + phase + "    throw 'the swap would complete'\n} catch { $message = $_.Exception.Message }\n"
        "Write-Host \"message: $message\"\n"
        "Write-Host \"restored: $script:restored\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "the swap would complete" not in out, out
    assert "restored: 1" in out, out
    assert "message: DefenseClaw 1.0.4 was not installed. Your previous install is back." in out, out
    assert "gateway.pid" in out, out


# ── 1.0.4 (GAP-0004) ────────────────────────────────────────────────────────


def _ps_functions(*names: str) -> str:
    text = _text()
    out = []
    for name in names:
        start = text.index(f"function {name}(")
        out.append(text[start : text.index("\n}\n", start) + 3])
    return "\n".join(out)


def test_an_upgrade_replaces_an_installed_binary_in_place() -> None:
    assert "Publish-File" in _ps_functions("Install-File")
    publish = _ps_functions("Publish-File")
    assert publish.index("Switch-InPlace") < publish.index("Remove-Aside")
    switch = _ps_functions("Switch-InPlace")
    assert "Remove-Aside" not in switch and "Move-Path" not in switch
    assert "Invoke-AtomicReplace $New $Destination" in switch
    assert "FileRenameInfoEx" in _ps_functions("Invoke-AtomicReplace")
    assert "FILE_RENAME_FLAG_POSIX_SEMANTICS" in _ps_functions("Invoke-AtomicReplace")
    assert "function Invoke-FileReplace" not in _text()
    install = _ps_functions("Install-File")
    assert install.index('(Get-Sha256 "$Destination.new") -ne (Get-Sha256 $Source)') < install.index("Publish-File")
    hook_state = _text().split("function Write-HookState {", 1)[1].split("\n}\n", 1)[0]
    for body in (_ps_functions("Write-PosixShim"), _ps_functions("Write-Shim"), hook_state):
        assert 'Publish-File "$path.new" $path' in body and "Remove-Aside" not in body


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_atomic_replacement_native_helper_compiles() -> None:
    # The Windows API call itself needs a Windows runner, but C# compilation
    # also catches signature and layout mistakes on a cross-platform runner.
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        + _ps1_function("Invoke-AtomicReplace")
        + "\ntry { Invoke-AtomicReplace 'missing.new' 'missing.exe' } catch { }\n"
        + "if (-not ('DefenseClawInstall.Rename' -as [type])) { throw 'native helper did not compile' }\n"
        + "'OK'\n"
    )
    result = _run_powershell(script)
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_idle_installed_file_switches_by_one_atomic_rename(tmp_path: Path) -> None:
    # The publication mock uses an overload available in PowerShell 5.1 and 7.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:atomic = 0
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{
    $script:atomic++
    if ([IO.File]::ReadAllText($Destination) -cne 'old') {{ throw 'old launcher unavailable' }}
    [IO.File]::Replace($New, $Destination, "$Destination.test-backup", $true)
    Remove-Item -LiteralPath "$Destination.test-backup"
}}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Switch-InPlace")}
Install-File '{source}' '{dest}'
Write-Output "ATOMIC=$script:atomic"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0 and "ATOMIC=1" in out, out
    assert dest.read_text(encoding="ascii") == "new"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(sys.platform != "win32" or POWERSHELL is None, reason="requires a running Windows executable")
def test_native_running_hook_refusal_preserves_canonical_path_for_retry(tmp_path: Path) -> None:
    # Windows retains an executable image section while it runs. A refusal
    # leaves the canonical name and staged copy intact for the next retry.
    system32 = Path(os.environ["SystemRoot"]) / "System32"
    hook = tmp_path / "defenseclaw-hook.exe"
    staged = tmp_path / "defenseclaw-hook.exe.new"
    shutil.copyfile(system32 / "cmd.exe", hook)
    shutil.copyfile(system32 / "ping.exe", staged)
    old = hook.read_bytes()
    new = staged.read_bytes()
    running = subprocess.Popen([str(hook), "/c", "ping -n 120 127.0.0.1 >nul"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        script = (
            "$ErrorActionPreference = 'Stop'\n" + _ps_functions("Invoke-AtomicReplace")
            + f"\ntry {{ Invoke-AtomicReplace '{staged}' '{hook}'; 'REPLACED' }} catch {{ 'REFUSED' }}\n"
        )
        result = _run_powershell(script)
        assert result.returncode == 0 and "REFUSED" in result.stdout, result.stdout + result.stderr
        assert running.poll() is None
        assert hook.read_bytes() == old and staged.read_bytes() == new
    finally:
        running.kill()
        running.wait(timeout=30)
    script = "$ErrorActionPreference = 'Stop'\n" + _ps_functions("Invoke-AtomicReplace") + f"\nInvoke-AtomicReplace '{staged}' '{hook}'\n"
    result = _run_powershell(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert hook.read_bytes() == new and not staged.exists()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_copy_that_is_not_whole_is_never_switched_in(tmp_path: Path) -> None:
    # 1.0.4 lead directive: the old launcher stays until the new one is
    # verified. A staged copy that does not match the source (cut short by a
    # full disk or a scanner) is removed and nothing is switched.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new launcher", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:switches = 0
function Copy-Item {{ param([string]$LiteralPath, [string]$Destination, [switch]$Force) [IO.File]::WriteAllText($Destination, "new") }}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{ $script:switches++; throw "switched" }}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{ $script:switches++; throw "switched" }}
function Remove-Aside([string]$Path) {{ $script:switches++; throw "switched" }}
function Move-Path([string]$From, [string]$To) {{ $script:switches++; throw "switched" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Switch-InPlace")}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "SWITCHES=$script:switches"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "FAILED: The copy of" in out and "was left as it was" in out, out
    assert "SWITCHES=0" in out, out
    assert dest.read_text(encoding="ascii") == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("held", [False, True])
def test_a_busy_launcher_is_never_opened_for_replace(tmp_path: Path, held: bool) -> None:
    # GAP-0352: ReplaceFile can deny execution of the registered hook while
    # it opens the destination. A busy atomic rename must only be retried.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:attempts = 0
$script:replaces = 0
$script:checks = 0
function Start-Sleep {{
    if ([IO.File]::ReadAllText('{dest}') -cne 'old') {{ throw 'registered launcher changed during retry' }}
    $script:checks++
}}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Switch-InPlace")}
function Invoke-FileReplace {{ $script:replaces++; throw 'sharing violation' }}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{
    $script:attempts++
    if ({'$true' if held else '$script:attempts -lt 3'}) {{ throw 'Access is denied.' }}
    [IO.File]::Replace($New, $Destination, "$Destination.test-backup", $true)
    Remove-Item -LiteralPath "$Destination.test-backup"
}}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }}
catch {{ Write-Output "REFUSED: $($_.Exception.Message)" }}
Write-Output "REPLACES=$script:replaces CHECKS=$script:checks"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "REPLACES=0" in out and "CHECKS=0" not in out, out
    assert ("REFUSED:" if held else "INSTALLED") in out, out
    assert dest.read_text(encoding="ascii") == ("old" if held else "new")
    assert not list(tmp_path.glob("*.new"))


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_one_per_second_hook_traffic_leaves_a_short_safe_swap_window(tmp_path: Path) -> None:
    # GAP-0732: each registered hook call holds its image for 900 ms of every
    # second. A 500 ms retry stays in phase with busy intervals forever.
    staged, hook = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    staged.write_text("new", encoding="ascii")
    hook.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:elapsedMs = 0
$script:attempts = 0
function Start-Sleep {{
    param([int]$Milliseconds)
    if ([IO.File]::ReadAllText('{hook}') -cne 'old') {{ throw 'canonical hook changed during retry' }}
    $script:elapsedMs += $Milliseconds
}}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{
    $script:attempts++
    if (($script:elapsedMs % 1000) -lt 900) {{ throw 'image is mapped' }}
    [IO.File]::Copy($New, $Destination, $true)
    Remove-Item -LiteralPath $New -Force
}}
{_ps1_function('Switch-InPlace')}
try {{ Switch-InPlace '{staged}' '{hook}'; 'SWAPPED' }} catch {{ 'REFUSED' }}
"""
    result = _run_powershell(script)
    assert result.returncode == 0 and "SWAPPED" in result.stdout, result.stdout + result.stderr
    assert hook.read_text(encoding="ascii") == "new" and not staged.exists()


# ── 1.0.4 (W4b loop round 1) ────────────────────────────────────────────────


def _restore_case_functions() -> str:
    names = (
        "Get-Sha256", "Install-File", "Publish-File", "Switch-InPlace", "Copy-BinDir", "Restore-BinDir",
        "Assert-BinDirRestored", "Move-Path", "Get-DataEntries", "Test-ConnectorRecoveryArtifactName",
        "Restore-Slot", "Invoke-Quietly",
        "Read-Text", "Restore-ExternalConfig", "Undo-HookFirst", "Undo-Snapshot",
        "Install-HookFirst", "Save-HookCloser", "Clear-StagedRelease", "Resume-InterruptedRun",
        "Remove-Hold", "Restore-Live", "Restore-LiveTree", "Move-LiveTo", "Set-RecoveryPending",
    )
    return "\n".join(_ps1_function(name) for name in names)


def _restore_case(tmp_path: Path, body: str) -> str:
    # The shipped functions against disposable paths. A running hook refuses
    # the in-place switch of its file, as Windows refuses MoveFileEx over a
    # running program; Start-Sleep returns at once.
    data, bin_dir = tmp_path / "data", tmp_path / "bin"
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data}'\n$BinDir = '{bin_dir}'\n"
        f"$Venv = '{data / '.venv'}'\n$InstallerDir = '{data / 'installer'}'\n"
        f"$Staging = '{data / '.staging'}'\n$SetupHookState = '{tmp_path / 'setup-hook-state.json'}'\n"
        "$NotData = @('.venv', 'installer', 'previous.new', '.staging', '.failed-*')\n"
        "$ManagedFiles = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')\n"
        "$script:busy = $true\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Start-Sleep { }\n"
        "function Remove-Tree([string]$Path) { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }\n"
        "function Remove-Aside([string]$Path) { Remove-Item -LiteralPath $Path -Force }\n"
        "function Remove-FailedInstall([string]$Failed) { Remove-Tree $Failed }\n"
        "function New-FailedInstallDirectory {\n"
        "    $failed = Join-Path $DataDir ('.failed-' + [Guid]::NewGuid().ToString('N'))\n"
        "    New-Item -ItemType Directory -Path $failed | Out-Null\n    return $failed\n}\n"
        "function Invoke-AtomicReplace([string]$New, [string]$Destination) {\n"
        "    if ($script:busy -and $Destination -like '*defenseclaw-hook.exe') { throw 'Access is denied.' }\n"
        "    [IO.File]::Copy($New, $Destination, $true); Remove-Item -LiteralPath $New -Force\n}\n"
        + _restore_case_functions()
        + "\n"
        + _NO_TXN
        # The drain of the previous hook (Wait-PreviousHookExit) has its own tests.
        + "function Wait-PreviousHookExit { param([DateTime]$PublishedAt) }\n"
        + body
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    return out


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_restore_a_running_hook_refuses_keeps_the_snapshot_and_never_claims_recovery(tmp_path: Path) -> None:
    # W4b loop round 1: after Install-HookFirst published the new hook, a
    # later failure restores the snapshot while that hook runs. Its in-place
    # switch is refused; the restore used to warn, delete the snapshot and
    # report the previous install back over the new programs.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        _write(bin_dir / name, "new " + name)
        _write(slot / "bin" / name, "old " + name)
    _write(slot / "COMPLETE", "")
    _write(data / "config.yaml", "new data")
    _write(slot / "data" / "config.yaml", "old data")
    receipt = ".defenseclaw-cas-v2-" + "a" * 24 + ".intent"
    _write(data / receipt, "new receipt")
    _write(slot / "data" / receipt, "old receipt")
    _write(data / ".venv" / "runtime.txt", "new runtime")
    _write(slot / "venv" / "runtime.txt", "old runtime")
    out = _restore_case(
        tmp_path,
        f"try {{ Restore-Slot '{slot}' | Out-Null; Write-Output 'RESTORED' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}",
    )
    assert "RESTORED" not in out and "REFUSED:" in out, out
    assert "defenseclaw-hook.exe" in out and f"kept in {slot}" in out and "Run the installer again" in out, out
    # Nothing but the idle programs moved: the snapshot, its marker, the data,
    # the environment and both receipts are where they were.
    assert (slot / "COMPLETE").exists()
    assert (bin_dir / "defenseclaw-hook.exe").read_text(encoding="ascii") == "new defenseclaw-hook.exe"
    assert (slot / "bin" / "defenseclaw-hook.exe").read_text(encoding="ascii") == "old defenseclaw-hook.exe"
    assert (data / "config.yaml").read_text(encoding="ascii") == "new data"
    assert (slot / "data" / "config.yaml").read_text(encoding="ascii") == "old data"
    assert (data / ".venv" / "runtime.txt").read_text(encoding="ascii") == "new runtime"
    assert (slot / "venv" / "runtime.txt").read_text(encoding="ascii") == "old runtime"
    assert (data / receipt).read_text(encoding="ascii") == "new receipt"
    assert (slot / "data" / receipt).read_text(encoding="ascii") == "old receipt"
    assert not list(data.glob(".failed-*"))
    # Once the hook has finished, running the restore again finishes it.
    out = _restore_case(tmp_path, f"$script:busy = $false\nRestore-Slot '{slot}' | Out-Null\nWrite-Output 'RESTORED'")
    assert "RESTORED" in out, out
    assert not slot.exists()
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        assert (bin_dir / name).read_text(encoding="ascii") == "old " + name
    assert (data / "config.yaml").read_text(encoding="ascii") == "old data"
    assert (data / ".venv" / "runtime.txt").read_text(encoding="ascii") == "old runtime"
    assert (data / receipt).read_text(encoding="ascii") == "old receipt"
    failed = list(data.glob(".failed-*"))
    assert len(failed) == 1
    assert (failed[0] / "data" / "config.yaml").read_text(encoding="ascii") == "new data"


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["switch-left-new-bytes", "extra-file-stays"])
def test_restore_bin_dir_proves_the_saved_bytes_before_it_returns(tmp_path: Path, case: str) -> None:
    # A switch that reports success but leaves other bytes, or a file the
    # snapshot did not hold that is still there, is not a restored install.
    bin_dir, saved = tmp_path / "bin", tmp_path / "data" / "previous.new" / "bin"
    _write(bin_dir / "defenseclaw-hook.exe", "new hook")
    _write(saved / "defenseclaw-hook.exe", "old hook")
    _write(bin_dir / "defenseclaw-gateway.exe", "new gateway")
    if case == "switch-left-new-bytes":
        _write(saved / "defenseclaw-gateway.exe", "old gateway")
        override = "function Invoke-AtomicReplace([string]$New, [string]$Destination) { Remove-Item -LiteralPath $New -Force }"
    else:
        override = "function Remove-Aside([string]$Path) { }"
    out = _restore_case(
        tmp_path,
        f"$script:busy = $false\n{override}\n"
        f"try {{ Restore-BinDir '{saved}'; Write-Output 'RESTORED' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}",
    )
    assert "RESTORED" not in out and "does not hold the saved copy of" in out, out
    assert "defenseclaw-gateway.exe" in out, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_unfinished_snapshot_keeps_the_old_hook_copy_when_the_new_hook_is_running(tmp_path: Path) -> None:
    # Save-Snapshot failed after Install-HookFirst: the slot holds the only
    # copy of the previous hook. A refused switch keeps the slot (no COMPLETE
    # marker, so the next run undoes it again) and says so; the environment
    # it moved goes back either way.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    _write(bin_dir / "defenseclaw-hook.exe", "new hook")
    _write(slot / "bin" / "defenseclaw-hook.exe", "old hook")
    _write(slot / "HOOK_FIRST", "")
    _write(slot / "venv" / "runtime.txt", "old runtime")
    out = _restore_case(
        tmp_path,
        f"try {{ Undo-Snapshot '{slot}'; Write-Output 'UNDONE' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}",
    )
    assert "UNDONE" not in out and "Could not put the previous hook back" in out and f"kept in {slot}" in out, out
    assert (slot / "bin" / "defenseclaw-hook.exe").read_text(encoding="ascii") == "old hook"
    assert (bin_dir / "defenseclaw-hook.exe").read_text(encoding="ascii") == "new hook"
    assert (data / ".venv" / "runtime.txt").read_text(encoding="ascii") == "old runtime"
    out = _restore_case(tmp_path, f"$script:busy = $false\nUndo-Snapshot '{slot}'\nWrite-Output 'UNDONE'")
    assert "UNDONE" in out, out
    assert not slot.exists()
    assert (bin_dir / "defenseclaw-hook.exe").read_text(encoding="ascii") == "old hook"


def test_no_restore_or_undo_hides_a_refused_program_switch() -> None:
    # Every path that puts programs back propagates the refusal: none runs
    # under Invoke-Quietly, and a failed Save-Snapshot whose undo is
    # unfinished never says that nothing was changed.
    text = _text()
    assert not re.search(r"Invoke-Quietly \{[^}]*(Restore-BinDir|Undo-Snapshot|Undo-HookFirst|Restore-Live)", text)
    install = _ps1_function("Invoke-Install")
    failed_save = install[install.index("if (-not $saved) {") :]
    failed_save = failed_save[: failed_save.index("Die \"Could not save the current install; $(Get-UnchangedNote)\"")]
    # Undo-EarlySnapshot reports a refused undo and keeps the install locked
    # (UndoPending); a finished one is proven against the lifecycle record.
    assert "Undo-EarlySnapshot $Snap" in failed_save
    assert failed_save.index("if (-not (Test-RecoveryPending)) {") < failed_save.index("Assert-LifecycleRestored $Manifest")
    assert "try { Undo-Snapshot $Slot } catch" in _ps1_function("Undo-EarlySnapshot")
    restore = _ps1_function("Restore-BinDir")
    assert restore.count("Assert-BinDirRestored $From") == 2


# ── 1.0.4 (W4b loop round 2) ────────────────────────────────────────────────


def _close_mocks(capable: str = "new ", close_rc: int = 0, running: bool = False) -> str:
    # The gateway probe and run: a gateway file whose text starts with
    # $capable has 'refresh-fail-modes --closed' (this release); any other
    # (an older release) prints the help without it.
    return (
        "$Previous = Join-Path $DataDir 'previous'\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        f"function Get-GatewayProcess {{ if (${str(running).lower()}) {{ return 'pid' }}; return $null }}\n"
        "function Get-ProcessesUnder { return @() }\n"
        "function Get-NativeProbe([string]$FilePath, [string[]]$Arguments = @()) {\n"
        f"    $help = if ([IO.File]::ReadAllText($FilePath).StartsWith('{capable}')) {{ '--closed  close every installed hook' }} else {{ '--hold-until-exit int' }}\n"
        "    return [pscustomobject]@{ Exit = 0; Output = $help }\n}\n"
        "function Invoke-Native([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet) {\n"
        "    Write-Host \"RAN: $FilePath $($Arguments -join ' ')\"\n"
        f"    return {close_rc}\n}}\n"
        + _resume_functions("Get-InstallGatewayState")
        + _ps1_function("Close-UnfinishedInstallHooks")
        + _ps1_function("Close-AllHooks")
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_refused_restore_keeps_its_gateway_and_closes_the_hooks_before_the_lock_goes(tmp_path: Path) -> None:
    # W4b loop round 2: the installer stopped the old gateway and published
    # the new hook; a later failure restores the snapshot while that hook
    # runs, and its switch back is refused. The run used to exit with the
    # gateway down, the previous gateway put back beside the failed install's
    # data, and the hooks on their configured outage mode, an open included.
    # Now the gateway in place stays until every other program is back, and
    # before the lock goes it closes every hook.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        _write(bin_dir / name, "new " + name)
        _write(slot / "bin" / name, "old " + name)
    _write(slot / "COMPLETE", "")
    _write(data / "hooks" / ".hookcfg", '{"fail_modes":{"codex":"open"}}')
    _write(data / "config.yaml", "new data")
    _write(slot / "data" / "config.yaml", "old data")
    out = _restore_case(
        tmp_path,
        _close_mocks()
        + f"\ntry {{ Restore-Slot '{slot}' | Out-Null; Write-Output 'RESTORED' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}\n"
        "Close-UnfinishedInstallHooks\n",
    )
    assert "RESTORED" not in out and "REFUSED:" in out, out
    assert (bin_dir / "defenseclaw-gateway.exe").read_text(encoding="ascii") == "new defenseclaw-gateway.exe"
    assert (slot / "COMPLETE").exists()
    gateway = bin_dir / "defenseclaw-gateway.exe"
    assert f"RAN: {gateway} connector refresh-fail-modes --closed --data-dir {data}" in out, out
    assert "every agent hook blocks tool calls until the gateway runs again" in out, out
    assert "err:" not in out, out
    # Once the hook has finished, running the restore again finishes it,
    # gateway included, and nothing is left unfinished to close.
    out = _restore_case(
        tmp_path,
        _close_mocks() + f"\n$script:busy = $false\nRestore-Slot '{slot}' | Out-Null\nWrite-Output 'RESTORED'\nClose-UnfinishedInstallHooks\n",
    )
    assert "RESTORED" in out and "RAN:" not in out, out
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        assert (bin_dir / name).read_text(encoding="ascii") == "old " + name


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    "case",
    ["bin-gateway", "saved-gateway", "staged-closer", "rollback-hold", "none-can-close", "close-fails", "gateway-running", "finished"],
)
def test_an_unfinished_install_never_leaves_the_hooks_on_an_outage_open(tmp_path: Path, case: str) -> None:
    # Whichever restore was refused (an upgrade's snapshot, a repair, a
    # rollback hold), the gateway in place or a saved one closes the hooks;
    # when none can, the run says so and never claims they are closed. A
    # running gateway guards the hooks, and a finished install has nothing
    # to close.
    data, bin_dir = tmp_path / "data", tmp_path / "bin"
    slot = data / (".rollback-hold" if case == "rollback-hold" else "previous.new")
    _write(data / "hooks" / ".hookcfg", "{}")
    _write(bin_dir / "defenseclaw-gateway.exe", "old gateway" if case in ("saved-gateway", "staged-closer", "none-can-close") else "new gateway")
    if case != "finished":
        _write(slot / "bin" / "defenseclaw-gateway.exe", "new gateway" if case == "saved-gateway" else "old gateway")
    if case == "staged-closer":
        _write(slot / "closer" / "defenseclaw-gateway.exe", "new gateway")
    mocks = _close_mocks(close_rc=1 if case == "close-fails" else 0, running=case == "gateway-running")
    out = _restore_case(tmp_path, mocks + "\nClose-UnfinishedInstallHooks\n")
    closed = "every agent hook blocks tool calls" in out
    if case in ("gateway-running", "finished"):
        assert "RAN:" not in out and not closed and "err:" not in out, out
        return
    if case in ("none-can-close", "close-fails"):
        assert not closed and "err: The install is not finished and the agent hooks could not be closed" in out, out
        assert ("RAN:" in out) == (case == "close-fails"), out
        return
    used = {
        "saved-gateway": slot / "bin" / "defenseclaw-gateway.exe",
        "staged-closer": slot / "closer" / "defenseclaw-gateway.exe",
    }.get(case, bin_dir / "defenseclaw-gateway.exe")
    assert f"RAN: {used} connector refresh-fail-modes --closed --data-dir {data}" in out and closed, out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_failure_before_the_new_gateway_is_published_still_closes_the_hooks(tmp_path: Path) -> None:
    # Install-HookFirst put the new hook in; the install failed before the new
    # gateway was published, so the gateway in place and the saved one are
    # both the previous release's, which cannot close the hooks. The staged
    # gateway kept in the snapshot before the hook switched closes them after
    # the staged release is cleared; the finished restore removes it.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    _interrupted_fixture(data, bin_dir, slot)
    out = _restore_case(
        tmp_path,
        _close_mocks()
        + _first_run(slot, complete=True)
        + "Clear-StagedRelease\n"
        f"try {{ Restore-Slot '{slot}' | Out-Null; Write-Output 'RESTORED' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}\n"
        "Close-UnfinishedInstallHooks\n",
    )
    assert "RESTORED" not in out and "REFUSED:" in out, out
    closer = slot / "closer" / "defenseclaw-gateway.exe"
    assert f"RAN: {closer} connector refresh-fail-modes --closed --data-dir {data}" in out, out
    assert "every agent hook blocks tool calls" in out and "err:" not in out, out
    out = _restore_case(tmp_path, _close_mocks() + f"\n$script:busy = $false\nRestore-Slot '{slot}' | Out-Null\nWrite-Output 'RESTORED'\n")
    assert "RESTORED" in out and not slot.exists(), out
    assert (bin_dir / "defenseclaw-hook.exe").read_text(encoding="ascii") == "old defenseclaw-hook.exe"



def test_a_failed_run_closes_unfinished_hooks_while_it_still_holds_the_lock() -> None:
    # After a failed run changed the install, close its hooks while the
    # lock is still held. An untouched empty-record refusal leaves them alone.
    text = _text()
    tail = text[text.index("$code = 1\ntry {") :]
    final = tail[tail.index("} finally {") :]
    assert final.index("Finish-InstallLock $code") < final.index("Stop-Transcript")
    finish = _ps1_function("Finish-InstallLock")
    assert finish.index("Close-UnfinishedInstallHooks") < finish.index("Close-InstallLock")
    assert "-not $Run.UnprovenReplacementUnchanged" in finish
    assert "Remove-Tree $LockDir" in _ps1_function("Close-InstallLock")
    restore = _ps1_function("Restore-BinDir")
    assert "if ($name -eq $gatewayName -and $refused.Count) { continue }" in restore
    assert "Save-HookCloser" not in _ps1_function("Restore-Snapshot")
    swap = _ps1_function("Complete-Swap")
    assert swap.index('Remove-Tree (Join-Path $Snap "closer")') < swap.index("Move-Path $Snap $Previous")


@pytest.mark.skipif(sys.platform != "win32" or POWERSHELL is None, reason="requires Windows executable replacement")
def test_native_running_hook_keeps_snapshot_until_restore_can_retry(tmp_path: Path) -> None:
    # A mapped image cannot be replaced on Windows. Keep its snapshot and
    # closed hook state so the same restoration can finish after it exits.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    hook = bin_dir / "defenseclaw-hook.exe"
    hook.parent.mkdir(parents=True)
    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", hook)
    _write(bin_dir / "defenseclaw-gateway.exe", "new defenseclaw-gateway.exe")
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        _write(slot / "bin" / name, "old " + name)
    _write(slot / "COMPLETE", "")
    _write(data / "config.yaml", "new data")
    _write(slot / "data" / "config.yaml", "old data")
    _write(data / "hooks" / ".hookcfg", '{"fail_modes":{"codex":"open"}}')
    running = subprocess.Popen([str(hook), "/c", "ping -n 120 127.0.0.1 >nul"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    body = (
        _NATIVE_RESTORE_HASH + _ps1_function("Invoke-AtomicReplace")
        + _close_mocks()
        + f"\ntry {{ Restore-Slot '{slot}' | Out-Null; Write-Output 'RESTORED' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}\n"
        "Close-UnfinishedInstallHooks\n"
    )
    try:
        out = _restore_case(tmp_path, body)
        still_running = running.poll() is None
        assert still_running and "REFUSED:" in out and "RAN:" in out, out
        assert slot.exists() and hook.read_bytes() == (Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe").read_bytes()
    finally:
        running.kill()
        running.wait(timeout=30)
    out = _restore_case(tmp_path, body)
    assert "RESTORED" in out and "REFUSED:" not in out, out
    assert not slot.exists()
    assert (bin_dir / "defenseclaw-gateway.exe").read_text(encoding="ascii") == "old defenseclaw-gateway.exe"
    assert hook.read_text(encoding="ascii") == "old defenseclaw-hook.exe"



# ── 1.0.4 (W4b loop round 3) ────────────────────────────────────────────────


def _interrupted_fixture(data: Path, bin_dir: Path, slot: Path, hook: Path | None = None) -> None:
    # The previous release is installed and this release is staged, its
    # hooks on a configured outage open.
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        _write(bin_dir / name, "old " + name)
        _write(data / ".staging" / "bin" / name, "new " + name)
    if hook is not None:
        shutil.copyfile(hook, data / ".staging" / "bin" / "defenseclaw-hook.exe")
    _write(data / "hooks" / ".hookcfg", '{"fail_modes":{"codex":"open"}}')
    _write(data / "config.yaml", "old data")


# The restore harness isolates the native rename and lifecycle ordering from
# Get-FileHash's Windows provider behavior on synthetic text .exe fixtures.
_NATIVE_RESTORE_HASH = """
function Get-Sha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
"""


def _first_run(slot: Path, complete: bool) -> str:
    # The first run's Save-Snapshot up to Install-HookFirst, and its marker
    # when the snapshot was whole. Nothing after it runs: the run was killed
    # (or failed) before the new gateway was published.
    steps = f"\n$script:busy = $false\nCopy-BinDir '{slot / 'bin'}'\nInstall-HookFirst '{slot}'\n"
    if complete:
        steps += (
            f"New-Item -ItemType Directory -Path '{slot / 'data'}' -Force | Out-Null\n"
            f"Copy-Item -LiteralPath (Join-Path $DataDir 'config.yaml') -Destination '{slot / 'data'}'\n"
            f"Set-Content -LiteralPath '{slot / 'VERSION'}' -Value '1.0.3' -Encoding Ascii\n"
            f"Set-Content -LiteralPath '{slot / 'COMPLETE'}' -Value '' -Encoding Ascii\n"
        )
    return steps + "$script:busy = $true\n"


_RESUME_MOCKS = (
    "function Stop-Gateway { return 0 }\n"
    "function Start-Gateway { Write-Host 'STARTED'; return 0 }\n"
    "function Find-SetupInstall { return $null }\n"
)


def _resume_and_finish() -> str:
    # The retry: the recovery at the top of Invoke-Install, then what the
    # top-level finally does for a failed run that took the lock.
    return (
        "try { Resume-InterruptedRun; Write-Output 'RESUMED' } catch { Write-Output \"REFUSED: $($_.Exception.Message)\" }\n"
        "Close-UnfinishedInstallHooks\nClear-StagedRelease\n"
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["killed-after-complete", "killed-before-complete", "failed-run-cleared-staging"])
def test_an_interrupted_upgrade_resumed_with_a_busy_hook_closes_the_hooks(tmp_path: Path, case: str) -> None:
    # W4b loop round 3: the first run put the new hook in (HOOK_FIRST) and
    # stopped before it published the new gateway: killed after or before
    # COMPLETE, or failed with its finally clearing the staged release. The
    # retry's Resume-InterruptedRun restores (or undoes) the snapshot while
    # the new hook runs, and its switch back is refused. Only the previous
    # release's gateways were in place and saved, none could close the
    # hooks, and the run ended with the gateway down and the hooks on the
    # configured open. The gateway the first run kept in the slot before the
    # hook switched closes them, and stays until the recovery finishes.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    _interrupted_fixture(data, bin_dir, slot)
    first = _close_mocks() + _RESUME_MOCKS + _first_run(slot, complete=case != "killed-before-complete")
    if case == "failed-run-cleared-staging":
        first += "Close-UnfinishedInstallHooks\nClear-StagedRelease\n"
    out = _restore_case(tmp_path, first)
    closer = slot / "closer" / "defenseclaw-gateway.exe"
    closed = f"RAN: {closer} connector refresh-fail-modes --closed --data-dir {data}"
    if case == "failed-run-cleared-staging":
        assert closed in out and "err:" not in out, out
    assert (bin_dir / "defenseclaw-hook.exe").read_text(encoding="ascii") == "new defenseclaw-hook.exe"
    out = _restore_case(tmp_path, _close_mocks() + _RESUME_MOCKS + "\n" + _resume_and_finish())
    assert "RESUMED" not in out and "REFUSED:" in out and f"kept in {slot}" in out, out
    assert closed in out, out
    assert "every agent hook blocks tool calls until the gateway runs again" in out and "err:" not in out, out
    assert "STARTED" not in out, out
    # The staged release is gone; the closer is not, and neither is the
    # previous install's copy or its marker.
    assert not (data / ".staging").exists() and closer.read_text(encoding="ascii") == "new defenseclaw-gateway.exe"
    assert (slot / "bin" / "defenseclaw-hook.exe").read_text(encoding="ascii") == "old defenseclaw-hook.exe"
    assert (slot / "COMPLETE").exists() == (case != "killed-before-complete")
    assert (bin_dir / "defenseclaw-gateway.exe").read_text(encoding="ascii") == "old defenseclaw-gateway.exe"
    # Busy again on the next retry: closed again, with the same kept gateway.
    out = _restore_case(tmp_path, _close_mocks() + _RESUME_MOCKS + "\n" + _resume_and_finish())
    assert "REFUSED:" in out and closed in out and "err:" not in out, out
    # Once the hook is idle the recovery finishes: the previous programs are
    # back, the closer goes with the slot, and nothing is left to close.
    out = _restore_case(tmp_path, _close_mocks() + _RESUME_MOCKS + "\n$script:busy = $false\n" + _resume_and_finish())
    assert "RESUMED" in out and "RAN:" not in out and "err:" not in out, out
    assert not slot.exists()
    for name in ("defenseclaw-gateway.exe", "defenseclaw-hook.exe"):
        assert (bin_dir / name).read_text(encoding="ascii") == "old " + name


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["linked", "copied", "in-the-way"])
def test_the_new_hook_goes_first_only_once_its_closer_is_kept(tmp_path: Path, case: str) -> None:
    # The closer is a hard link (no room), a proven copy where the volume
    # cannot link, and when neither can be kept the switch stops before the
    # marker and the hook change, and says why.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    _interrupted_fixture(data, bin_dir, slot)
    staged = data / ".staging" / "bin" / "defenseclaw-gateway.exe"
    body = f"Copy-BinDir '{slot / 'bin'}'\n"
    if case == "copied":
        body += (
            "function New-Item { [CmdletBinding()] param([string]$ItemType, [string]$Path, [string]$Target, [switch]$Force)\n"
            "    if ($ItemType -eq 'HardLink') { throw 'this volume cannot link' }\n"
            "    Microsoft.PowerShell.Management\\New-Item -ItemType $ItemType -Path $Path -Force:$Force\n}\n"
        )
    if case == "in-the-way":
        body += f"Set-Content -LiteralPath '{slot / 'closer'}' -Value 'a file' -Encoding Ascii\n"
    body += f"$script:busy = $false\ntry {{ Install-HookFirst '{slot}'; Write-Output 'FIRST' }} catch {{ Write-Output \"REFUSED: $($_.Exception.Message)\" }}\n"
    out = _restore_case(tmp_path, body)
    closer = slot / "closer" / "defenseclaw-gateway.exe"
    live = bin_dir / "defenseclaw-hook.exe"
    if case == "in-the-way":
        assert "FIRST" not in out and "Could not keep the new gateway in" in out and "the installed hook was left as it was" in out, out
        assert not (slot / "HOOK_FIRST").exists()
        assert live.read_text(encoding="ascii") == "old defenseclaw-hook.exe"
        return
    assert "FIRST" in out and (slot / "HOOK_FIRST").exists(), out
    assert live.read_text(encoding="ascii") == "new defenseclaw-hook.exe"
    assert closer.read_text(encoding="ascii") == "new defenseclaw-gateway.exe"
    assert os.path.samefile(closer, staged) == (case == "linked")


def test_a_closer_that_cannot_be_kept_is_never_hidden() -> None:
    # The snapshot save that runs Install-HookFirst propagates its error (a
    # closer that could not be kept stops the run as "nothing was changed"),
    # and a finished swap removes the closer before the slot becomes previous.
    save = _ps1_function("Save-BinarySnapshot")
    assert "Install-HookFirst $Snap" in save and "Invoke-Quietly" not in save
    assert "if (-not (Test-Path -LiteralPath (Join-Path $Snap \"BIN_SAVED\"))) { Save-BinarySnapshot }" in _ps1_function("Save-Snapshot")
    assert not re.search(r"Invoke-Quietly \{[^}]*(Install-HookFirst|Save-HookCloser)", _text())
    install = _ps1_function("Invoke-Install")
    assert "try { Save-BinarySnapshot } catch {" in install
    assert "try { $saved = Save-Snapshot } catch { Write-Err $_.Exception.Message" in install


@pytest.mark.skipif(sys.platform != "win32" or POWERSHELL is None, reason="requires Windows executable replacement")
def test_native_running_hook_during_interrupted_resume_keeps_a_retry(tmp_path: Path) -> None:
    # Recovery cannot replace a mapped executable. Its slot and closer stay
    # until a later run can put the old canonical hook back.
    data, bin_dir, slot = tmp_path / "data", tmp_path / "bin", tmp_path / "data" / "previous.new"
    _interrupted_fixture(data, bin_dir, slot, hook=Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe")
    real = _ps1_function("Invoke-AtomicReplace")
    _restore_case(tmp_path, _NATIVE_RESTORE_HASH + real + _close_mocks() + _RESUME_MOCKS + _first_run(slot, complete=True))
    hook = bin_dir / "defenseclaw-hook.exe"
    running = subprocess.Popen([str(hook), "/c", "ping -n 120 127.0.0.1 >nul"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    body = _NATIVE_RESTORE_HASH + real + _close_mocks() + _RESUME_MOCKS + "\n" + _resume_and_finish()
    try:
        out = _restore_case(tmp_path, body)
        still_running = running.poll() is None
        assert still_running and "REFUSED:" in out and "RAN:" in out, out
        assert slot.exists()
    finally:
        running.kill()
        running.wait(timeout=30)
    out = _restore_case(tmp_path, body)
    assert "RESUMED" in out and "REFUSED:" not in out and "RAN:" not in out, out
    assert not slot.exists()
    assert hook.read_text(encoding="ascii") == "old defenseclaw-hook.exe"


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_previous_hook_calls_drain_while_new_hook_traffic_continues() -> None:
    script = _ps1_function("Wait-PreviousHookExit") + r"""
$ErrorActionPreference = 'Stop'
$BinDir = '.'
$script:passes = 0
$published = [DateTime]::UtcNow
function Get-ProcessesUnder {
    $script:passes++
    if ($script:passes -le 2) { [pscustomobject]@{ ProcessId = 10 } }
    [pscustomobject]@{ ProcessId = 20 }
}
function Get-Process {
    param($Id, $ErrorAction)
    return [pscustomobject]@{ StartTime = $(if ($Id -eq 10) { $published.AddSeconds(-1) } else { $published.AddSeconds(1) }) }
}
Wait-PreviousHookExit $published
if ($script:passes -ne 3) { throw 'did not drain only the old calls' }
"""
    result = _run_powershell(script)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_unproven_previous_hook_refuses_with_the_checked_local_retry() -> None:
    script = _ps1_function("Wait-PreviousHookExit") + r"""
$ErrorActionPreference = 'Stop'
$BinDir = '.'
$blocked = [pscustomobject]@{}
$blocked | Add-Member -MemberType ScriptProperty -Name StartTime -Value { throw 'Access is denied' }
function Get-ProcessesUnder { [pscustomobject]@{ ProcessId = 10 } }
function Get-Process { return $blocked }
$refused = $false
try { Wait-PreviousHookExit ([DateTime]::UtcNow) } catch {
    if (-not $_.Exception.Message.Contains('Cannot prove that previous hook calls finished')) { throw }
    if (-not $_.Exception.Message.Contains("& '<checked install.ps1>' -Local '<checked release assets directory>' -Yes")) {
        throw 'refusal omitted the checked local retry command'
    }
    $refused = $true
}
if (-not $refused) { throw 'an unproven previous hook was accepted' }
"""
    result = _run_powershell(script)
    assert result.returncode == 0, result.stdout + result.stderr


# ── fix/r104-windows: one lifecycle transaction for every step ──────────────
# Write-LifecycleManifest records the working state before the first change,
# Test-LifecycleProof proves the result from the live install, and the
# record goes only once the result (or the restore) is proven.

_TXN_FUNCTIONS = (
    "Write-DurableText", "ConvertTo-Map", "Get-BinariesState", "Get-OptionalSha256", "Get-GatewayHealthReport",
    "Get-GuardedConnectors", "Get-GatewayDigestProblem", "Get-LifecycleState", "Write-LifecycleManifest",
    "Read-LifecycleManifest", "Complete-LifecycleManifest", "Remove-LifecycleManifest", "Test-LifecycleProof",
    "Set-RecoveryPending", "Wait-LifecycleProof", "Get-LifecycleNextStep", "Assert-LifecycleRestored", "Get-Field", "Get-Sha256", "New-RecoveryManifest",
    "Close-AllHooks", "Save-LifecycleCloser", "Test-SameBinaries",
    "Set-RecoverySetupRoot", "Start-RecoveredGateway", "Read-Json", "Get-HeldConnectors", "Get-ManifestAcceptedConnectors", "Get-RecordedAcceptedConnectors",
    "Save-AcceptedConnectors",
)


def _txn_harness(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    """Run the real transaction functions with the OS boundaries stubbed.

    $script:gateway (a process-like object or $null), $script:health (status
    --json text or ""), $script:digest (policy digest JSON or ""),
    $script:digestHelp (whether policy digest has --check-gateway),
    $script:protected and $script:enabled (the effective config's connector
    roster) drive the stubs.
    """
    data, bin_dir = tmp_path / "data", tmp_path / "bin"
    (data / "hooks").mkdir(parents=True)
    bin_dir.mkdir()
    script = tmp_path / "txn.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        "if ($PSVersionTable.PSVersion.Major -lt 6) { Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1') -Force -ErrorAction Stop }\n"
        f"$DataDir = '{data}'\n$BinDir = '{bin_dir}'\n$Local = ''\n$Setup = $null\n"
        "$ManagedBinaries = @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe', 'defenseclaw-acp.exe')\n"
        "$LifecycleManifest = Join-Path $DataDir '.lifecycle-txn.json'\n"
        "$LifecycleCloser = Join-Path $DataDir '.lifecycle-closer'\n"
        "$Run = @{ RestorePending = $false; UndoPending = $false }\n"
        "$LifecycleProofSeconds = 0\n"
        "$script:gateway = $null; $script:health = ''; $script:digest = ''; $script:digestHelp = $true; $script:protected = $true\n"
        "function Get-GatewayProcess { return $script:gateway }\n"
        "function Get-ExternalConfig { return '' }\n"
        "function Get-ConfiguredConnectors { return @() }\n"
        "$script:enabled = @()\n"
        "function Get-EffectiveConfigConnectors { return @($script:enabled) }\n"
        "function Test-BinDirProtected { return $script:protected }\n"
        "$script:closes = 0\n"
        "function Invoke-Native { param($FilePath, $Arguments, [switch]$Quiet) if (($Arguments -join ' ') -like 'connector refresh-fail-modes --closed*') { $script:closes++; return 0 }; if ($script:health) { return 0 } return 1 }\n"
        "function Get-NativeProbe {\n"
        "    param($FilePath, $Arguments)\n"
        "    $line = $Arguments -join ' '\n"
        "    if ($line -eq 'status --json') { return [pscustomobject]@{ Exit = 0; Output = $script:health } }\n"
        "    if ($line -eq 'policy digest --help') { return [pscustomobject]@{ Exit = 0; Output = $(if ($script:digestHelp) { '--check-gateway' } else { 'usage' }) } }\n"
        "    if ($line -eq 'policy digest --json --check-gateway') { return [pscustomobject]@{ Exit = 0; Output = $script:digest } }\n"
        "    if ($line -eq 'connector refresh-fail-modes --help') { return [pscustomobject]@{ Exit = 0; Output = '--closed  close every installed hook' } }\n"
        "    throw \"unexpected probe $line\"\n"
        "}\n"
        + "\n".join(_ps1_function(name) for name in _TXN_FUNCTIONS)
        + "\n$script:images = @()\n"
        "function Get-ProcessesUnder([string[]]$Prefixes) {\n"
        "    return @($script:images | Where-Object { $image = $_.ExecutablePath\n"
        "        @($Prefixes | Where-Object { $image.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count })\n"
        "}\n"
        + _resume_functions("Get-InstallGatewayState")
        + "\n"
        + body,
        encoding="utf-8",
    )
    return subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
    )


_HEALTHY = '{"running": true, "health": {"connectors": [{"name": "claudecode", "state": "running"}, {"name": "codex", "state": "running"}]}}'
_DIGEST_OK = '{"effective_digest": "sha256:aa", "gateway_reported_digest": "sha256:aa"}'


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_the_lifecycle_record_is_written_durably_before_the_first_change(tmp_path: Path) -> None:
    result = _txn_harness(tmp_path, r"""
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'old gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'old hook')
[IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'config_version: 9')
[IO.File]::WriteAllText((Join-Path $DataDir 'hooks\.hookcfg'), '{}')
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:health = '__HEALTHY__'
# An earlier record of this run is replaced whole, never appended to.
[IO.File]::WriteAllText($LifecycleManifest, 'stale')
# The record a run proves its own restore against (Restore-Snapshot,
# Restart-Old, a rollback's target) is read with Get-Field, as recovery reads it.
$rollback = Write-LifecycleManifest 'rollback' '1.0.4' '1.0.2' '' @{ TargetBins = (Get-BinariesState $BinDir); StartAfter = $true }
if ((ConvertTo-Map (Get-Field $rollback 'TargetBins')).Count -ne 2 -or -not (Get-Field $rollback 'StartAfter')) { throw 'the rollback target cannot be proven' }
$state = Write-LifecycleManifest 'upgrade' '1.0.2' '1.0.4' (Join-Path $DataDir 'previous.new')
if (Test-Path -LiteralPath "$LifecycleManifest.new") { throw 'the temporary record was left behind' }
if ((ConvertTo-Map (Get-Field $state 'Bins')).Count -ne 2 -or -not (Get-Field $state 'GatewayWasRunning') -or
    @(Test-LifecycleProof (Get-Field $state 'Bins') $false).Count) { throw 'the returned record cannot prove the install it recorded' }
$read = Read-LifecycleManifest
if ($read.Operation -ne 'upgrade' -or $read.From -ne '1.0.2' -or $read.To -ne '1.0.4' -or $read.Committed) { throw "header: $($read | ConvertTo-Json)" }
if (-not $read.GatewayWasRunning -or (@($read.Connectors) -join ',') -ne 'claudecode,codex') { throw "gateway: $($read | ConvertTo-Json)" }
if ($read.Bins.'defenseclaw-hook.exe' -ne (Get-Sha256 (Join-Path $BinDir 'defenseclaw-hook.exe'))) { throw 'hook sha' }
if ($read.Bins.PSObject.Properties['defenseclaw-acp.exe']) { throw 'a binary that is not installed was recorded' }
if ($read.Config -ne (Get-Sha256 (Join-Path $DataDir 'config.yaml')) -or -not $read.HookFailModes -or -not $read.BinDirProtected) { throw 'state' }
Complete-LifecycleManifest
if (-not (Read-LifecycleManifest).Committed) { throw 'not committed' }
Remove-LifecycleManifest
if (Test-Path -LiteralPath $LifecycleManifest) { throw 'not removed' }
# A record this installer cannot read is never taken for "nothing to restore".
[IO.File]::WriteAllText($LifecycleManifest, '{"Schema": 2}')
try { [void](Read-LifecycleManifest); throw 'a newer record was accepted' } catch { if ($_.Exception.Message -notlike '*newer installer*') { throw } }
[IO.File]::WriteAllText($LifecycleManifest, '{broken')
try { [void](Read-LifecycleManifest); throw 'a broken record was accepted' } catch { if ($_.Exception.Message -notlike '*cannot be read*') { throw } }
'OK'
""".replace("__HEALTHY__", _HEALTHY))
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


_PROOF_CASES = {
    # case: (setup, expected problem fragment or "" for proven)
    "proven": ("", ""),
    "binary-differs": ("[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'other hook')", "is not the expected defenseclaw-hook.exe"),
    "binary-missing": ("Remove-Item -LiteralPath (Join-Path $BinDir 'defenseclaw-hook.exe')", "defenseclaw-hook.exe is missing"),
    "extra-binary": ("[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-acp.exe'), 'stray')", "does not belong to this install"),
    "folder-writable": ("$script:protected = $false", "can be written by another account"),
    "gateway-down": ("$script:gateway = $null", "the gateway is not running"),
    "gateway-other-image": ("$script:gateway = [pscustomobject]@{ Path = (Join-Path $DataDir 'other.exe') }", "the running gateway is"),
    "health-not-running": ("$script:health = '{\"running\": false, \"health\": {\"connectors\": []}}'", "does not answer its health check"),
    "connector-not-guarded": (
        "$script:health = '{\"running\": true, \"health\": {\"connectors\": [{\"name\": \"claudecode\", \"state\": \"error\"}]}}'",
        "connector claudecode is not guarded again",
    ),
    "digest-differs": ("$script:digest = '{\"effective_digest\": \"sha256:aa\", \"gateway_reported_digest\": \"sha256:bb\"}'", "does not enforce the live config"),
    "reload-rejected": (
        "$script:digest = '{\"effective_digest\": \"sha256:aa\", \"gateway_reported_digest\": \"sha256:aa\", \"gateway_last_reload_error\": \"bad rule\"}'",
        "rejected the live config",
    ),
    "digest-unreadable": ("$script:digest = 'not json'", "could not be read"),
    "digest-not-reported": ("$script:digest = '{\"effective_digest\": \"sha256:aa\"}'", "does not report the policy digest"),
    "older-gateway-without-digest": ("$script:digestHelp = $false", "does not report the policy digest"),
}


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", sorted(_PROOF_CASES))
def test_the_lifecycle_proof_names_every_part_it_cannot_prove(tmp_path: Path, case: str) -> None:
    setup, want = _PROOF_CASES[case]
    result = _txn_harness(tmp_path, r"""
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'new gateway')
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-hook.exe'), 'new hook')
$bins = Get-BinariesState $BinDir
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:health = '__HEALTHY__'
$script:digest = '__DIGEST__'
__SETUP__
$problems = @(Test-LifecycleProof $bins $true @('claudecode') -RequireDigest)
"PROBLEMS=$($problems -join ' | ')"
""".replace("__HEALTHY__", _HEALTHY).replace("__DIGEST__", _DIGEST_OK).replace("__SETUP__", setup))
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    line = [row for row in result.stdout.splitlines() if row.startswith("PROBLEMS=")][-1]
    if want:
        assert want in line, out
    else:
        assert line == "PROBLEMS=", out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_restore_proof_does_not_require_what_the_older_install_could_not_report(tmp_path: Path) -> None:
    # An older restored gateway (0.8.10, 1.0.0) may have no policy digest and
    # no --json health: the restore is proven by its bytes, its config and a
    # gateway that answers status. A folder the old install left writable is
    # not made a refusal, as the restore never loosens it either.
    result = _txn_harness(tmp_path, r"""
[IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'old gateway')
[IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'old config')
$manifest = [pscustomobject]@{ From = '0.8.10'; Bins = (Get-BinariesState $BinDir); GatewayWasRunning = $true; Connectors = @(); BinDirProtected = $false
    Config = (Get-Sha256 (Join-Path $DataDir 'config.yaml')); ExternalConfig = ''; ExternalConfigSha256 = ''; HookFailModes = ''; SetupRoot = '' }
[IO.File]::WriteAllText($LifecycleManifest, '{}')
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
$script:health = ''
$script:digestHelp = $false
$script:protected = $false
function Invoke-Native { param($FilePath, $Arguments, [switch]$Quiet) return 0 }
Assert-LifecycleRestored $manifest
if (Test-Path -LiteralPath $LifecycleManifest) { throw 'a proven restore kept its record' }
# The same restore with the config changed is not proven: the record stays,
# the install stays locked (RestorePending) and the error names the retry.
[IO.File]::WriteAllText($LifecycleManifest, '{}')
[IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'migrated config')
try { Assert-LifecycleRestored $manifest; throw 'accepted' } catch {
    if ($_.Exception.Message -notlike '*is not the config the previous install ran with*' -or $_.Exception.Message -notlike '*then run: *') { throw }
}
if (-not (Test-Path -LiteralPath $LifecycleManifest) -or -not $Run.RestorePending) { throw 'an unproven restore dropped its record or the lock' }
# Hooks are never left weaker: outage modes that were there must be back.
$Run.RestorePending = $false
[IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'old config')
$manifest.HookFailModes = 'abc'
try { Assert-LifecycleRestored $manifest; throw 'accepted' } catch { if ($_.Exception.Message -notlike "*outage modes*") { throw } }
'OK'
""")
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr


_RESUME_STUBS = r"""
$Staging = Join-Path $DataDir '.staging'
$SetupHookState = Join-Path $DataDir 'hook-runtime-state.json'
$Previous = Join-Path $DataDir 'previous'
$script:calls = [Collections.Generic.List[string]]::new()
$script:startRc = 0
function Write-Warn { param($Message) }
function Write-Info { param($Message) }
function Write-Err { param($Message) }
function Die { param($Message) throw $Message }
function Invoke-Quietly { param([scriptblock]$Action) try { & $Action } catch { } }
function Remove-Tree { param($Path) if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }
function Move-Path { param($From, $To, $Seconds) Move-Item -LiteralPath $From -Destination $To }
function Find-SetupInstall { return $null }
function Clear-SetupDataDir { param($Failed) }
function Remove-FailedInstall { param($Failed) }
function Remove-Hold { param($Hold) Remove-Tree $Hold }
function Read-Text { param($Path) if (Test-Path -LiteralPath $Path -PathType Leaf) { return ([IO.File]::ReadAllText($Path)).Trim() } return '' }
function Stop-Gateway { $script:calls.Add('stop'); $script:gateway = $null; return $true }
function Start-Gateway {
    $script:calls.Add('start')
    if ($script:startRc -eq 0) { $script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') } }
    return $script:startRc
}
function Invoke-Native { param($FilePath, $Arguments, [switch]$Quiet) if (($Arguments -join ' ') -like 'connector refresh-fail-modes --closed*') { $script:closes++; return 0 }; if ($script:gateway) { return 0 } return 1 }
function Put-Bins([string]$Kind) {
    foreach ($name in @('defenseclaw-gateway.exe', 'defenseclaw-hook.exe')) { [IO.File]::WriteAllText((Join-Path $BinDir $name), "$Kind $name") }
}
function Restore-Slot { param($Slot) $script:calls.Add('restore-slot'); if (-not $script:restoreLeavesNewHook) { Put-Bins 'old' } else { [IO.File]::WriteAllText((Join-Path $BinDir 'defenseclaw-gateway.exe'), 'old defenseclaw-gateway.exe') }; Remove-Tree $Slot; return (Join-Path $DataDir '.failed-x') }
function Undo-Snapshot { param($Slot) $script:calls.Add('undo-snapshot'); Put-Bins 'old'; Remove-Tree $Slot }
function Move-LiveTo { param($Slot) $script:calls.Add('move-live-to') }
function Restore-Live { param($Slot) $script:calls.Add('restore-live'); Put-Bins 'old' }
function Restore-LiveTree { param($Slot) $script:calls.Add('restore-live-tree'); Put-Bins 'old' }
$script:restoreLeavesNewHook = $false
$script:digestHelp = $false
[IO.File]::WriteAllText((Join-Path $DataDir 'config.yaml'), 'config_version: 9')
Put-Bins 'old'
$script:gateway = [pscustomobject]@{ Path = (Join-Path $BinDir 'defenseclaw-gateway.exe') }
# Step 1 of every lifecycle step: the record of the working install.
[void](Write-LifecycleManifest 'upgrade' '1.0.2' '1.0.4' (Join-Path $DataDir 'previous.new') @{ TargetBins = @{} })
$slot = Join-Path $DataDir 'previous.new'
function New-Slot([string[]]$Markers) {
    [void][IO.Directory]::CreateDirectory($slot)
    Set-Content -LiteralPath (Join-Path $slot 'VERSION') -Value '1.0.2'
    Set-Content -LiteralPath (Join-Path $slot 'GATEWAY_WAS_RUNNING') -Value 'true'
    foreach ($marker in $Markers) { Set-Content -LiteralPath (Join-Path $slot $marker) -Value '' }
}
"""

_BOUNDARIES = {
    # boundary: (setup after the record, want: "proven" | "kept", calls that must and must not appear)
    "after-record-before-any-change": ("$script:gateway = $null", "proven", ["start"], ["restore-slot", "undo-snapshot"]),
    "after-hook-swap": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST'); Put-Bins 'new'; $script:gateway = $null", "proven", ["undo-snapshot", "start"], ["restore-slot"]),
    "after-gateway-stop": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST'); $script:gateway = $null", "proven", ["undo-snapshot", "start"], ["restore-slot"]),
    "after-snapshot": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST', 'COMPLETE'); $script:gateway = $null", "proven", ["restore-slot", "start"], ["undo-snapshot"]),
    "after-install-new": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST', 'COMPLETE'); Put-Bins 'new'; $script:gateway = $null", "proven", ["restore-slot", "start"], []),
    # GAP-0407: an unproven new start keeps the restored gateway stopped (hooks closed), on purpose.
    "after-unproven-new-start": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST', 'COMPLETE', 'GATEWAY_RESTART_UNPROVEN'); Put-Bins 'new'", "proven", ["restore-slot"], ["start"]),
    # The new install was proven, then the run stopped while it cleaned up:
    # it is kept, never undone back to the old hook.
    "after-commit": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST'); Put-Bins 'new'; Complete-LifecycleManifest", "committed", [], ["undo-snapshot", "restore-slot"]),
    "restore-not-proven": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST', 'COMPLETE'); Put-Bins 'new'; $script:restoreLeavesNewHook = $true; $script:gateway = $null", "kept", ["restore-slot"], []),
    "restored-gateway-does-not-start": ("New-Slot @('BIN_SAVED', 'HOOK_FIRST', 'COMPLETE'); $script:startRc = 1; $script:gateway = $null", "kept", ["restore-slot", "start"], []),
    # The install the record names was uninstalled since: nothing to restore
    # or start, so the record goes instead of blocking every later install.
    "uninstalled-since": ("Remove-Item -LiteralPath (Join-Path $BinDir 'defenseclaw-gateway.exe'), (Join-Path $BinDir 'defenseclaw-hook.exe'); $script:gateway = $null", "dropped", [], ["start"]),
}


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("boundary", sorted(_BOUNDARIES))
def test_an_upgrade_interrupted_at_every_step_boundary_is_restored_and_proven(tmp_path: Path, boundary: str) -> None:
    setup, want, must, never = _BOUNDARIES[boundary]
    result = _txn_harness(tmp_path, _ps1_function("Resume-InterruptedRun") + _RESUME_STUBS + setup + r"""
$failure = ''
try { Resume-InterruptedRun } catch { $failure = $_.Exception.Message }
"FAILURE=$failure"
"CALLS=$($script:calls -join ',')"
"RECORD=$(Test-Path -LiteralPath $LifecycleManifest)"
"PENDING=$($Run.RestorePending)"
$hookPath = Join-Path $BinDir 'defenseclaw-hook.exe'
"HOOK=$(if (Test-Path -LiteralPath $hookPath) { [IO.File]::ReadAllText($hookPath) })"
"SLOT=$(Test-Path -LiteralPath $slot)"
"CLOSES=$script:closes"
""")
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    rows = dict(row.split("=", 1) for row in result.stdout.splitlines() if "=" in row and row.split("=", 1)[0].isupper())
    calls = rows["CALLS"].split(",") if rows["CALLS"] else []
    for call in must:
        assert call in calls, out
    for call in never:
        assert call not in calls, out
    assert rows["SLOT"] == "False", out
    if want == "proven":
        assert rows["FAILURE"] == "" and rows["RECORD"] == "False", out
        assert rows["HOOK"] == "old defenseclaw-hook.exe", out
        # A restore that keeps its gateway stopped (GAP-0407) closes every
        # hook before its record goes; one whose gateway runs does not.
        assert rows["CLOSES"] == ("1" if boundary == "after-unproven-new-start" else "0"), out
    elif want == "dropped":
        assert rows["FAILURE"] == "" and rows["RECORD"] == "False", out
    elif want == "committed":
        assert rows["FAILURE"] == "" and rows["RECORD"] == "False", out
        assert rows["HOOK"] == "new defenseclaw-hook.exe", out
        assert (tmp_path / "data" / "previous" / "VERSION").exists(), out
    else:
        # The record stays until a run proves the restore; that run is named.
        assert rows["FAILURE"] and rows["RECORD"] == "True", out
        if boundary == "restore-not-proven":
            assert "not proven back" in rows["FAILURE"] and rows["PENDING"] == "True", out


_ROLLBACK_BOUNDARIES = {
    # The swap finished and its hold was renamed into previous\ before the
    # run stopped: the live install is the target, proven like a finished one.
    "swapped-before-proof": ("", "target", "proven"),
    # An interrupted rollback that had set the live install aside goes back to it.
    "stashed": ("STASHED", "old", "proven"),
    # A rollback that had finished is proven against its target.
    "rolled-back": ("ROLLED_BACK", "target", "proven"),
    "rolled-back-wrong-bytes": ("ROLLED_BACK", "other", "kept"),
}


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("boundary", sorted(_ROLLBACK_BOUNDARIES))
def test_an_interrupted_rollback_is_finished_or_undone_and_proven(tmp_path: Path, boundary: str) -> None:
    marker, live, want = _ROLLBACK_BOUNDARIES[boundary]
    result = _txn_harness(tmp_path, _ps1_function("Resume-InterruptedRun") + _RESUME_STUBS + r"""
Remove-LifecycleManifest
Put-Bins 'target'
$target = Get-BinariesState $BinDir
Put-Bins 'old'
$script:health = '__HEALTHY__'
[void](Write-LifecycleManifest 'rollback' '1.0.4' '1.0.3' '' @{ TargetBins = $target; StartAfter = $true })
$script:health = $(if ('__MARKER__' -eq 'STASHED') { '__HEALTHY__' } else { '' })
$hold = Join-Path $DataDir '.rollback-hold'
[void][IO.Directory]::CreateDirectory($hold)
Set-Content -LiteralPath (Join-Path $hold 'GATEWAY_WAS_RUNNING') -Value 'true'
Set-Content -LiteralPath (Join-Path $hold 'START_AFTER') -Value 'true'
if ('__MARKER__') { Set-Content -LiteralPath (Join-Path $hold '__MARKER__') -Value '' } else { Remove-Item -LiteralPath $hold -Recurse -Force }
if ('__LIVE__' -ne 'old') { Put-Bins '__LIVE__' }
$script:gateway = $null
$failure = ''
try { Resume-InterruptedRun } catch { $failure = $_.Exception.Message }
"FAILURE=$failure"
"RECORD=$(Test-Path -LiteralPath $LifecycleManifest)"
"HOOK=$([IO.File]::ReadAllText((Join-Path $BinDir 'defenseclaw-hook.exe')))"
""".replace("__MARKER__", marker).replace("__LIVE__", live).replace("__HEALTHY__", _HEALTHY))
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    rows = dict(row.split("=", 1) for row in result.stdout.splitlines() if "=" in row and row.split("=", 1)[0].isupper())
    if want == "proven":
        assert rows["FAILURE"] == "" and rows["RECORD"] == "False", out
    else:
        assert "not proven" in rows["FAILURE"] and rows["RECORD"] == "True", out


def test_every_lifecycle_step_proves_its_result_before_it_reports_success() -> None:
    # The upgrade proves the new install before Complete-Swap drops the
    # previous one, and drops its record only after; a proof that fails
    # restores the previous install. The restore proves itself too.
    install = _ps1_function("Invoke-Install")
    record = install.index("$Manifest = Write-LifecycleManifest $operation")
    assert record < install.index("try { Save-BinarySnapshot }") < install.index("if (-not (Stop-Gateway))")
    proof = install.index("$problems = @(Wait-LifecycleProof $stagedBinaries $provenGateway $guardedBefore -RequireDigest:$provenGateway)")
    committed = install.index("Complete-LifecycleManifest", proof)
    swap = install.index("Complete-Swap", committed)
    assert proof < committed < swap < install.index("Remove-LifecycleManifest", swap)
    failed = install[proof:committed]
    assert failed.index("Stop-Gateway") < failed.index("Restore-Snapshot") < failed.index("Die "), failed
    restore = _ps1_function("Restore-Snapshot")
    assert restore.index("Restart-Old -KeepStopped:$keepStopped") < restore.index("Assert-LifecycleRestored") < restore.index("Write-KeptUvCache")
    # The early failures before the data copy prove the old install back too.
    early = install[install.index("$stopRefused = $false") : install.index("try { [Console]::TreatControlCAsInput = $true }")]
    assert early.count("Assert-LifecycleRestored $Manifest") == 2, early
    # The special-case .gateway-recovery marker is gone: the record replaces it.
    assert ".gateway-recovery" not in INSTALL_PS1.read_text(encoding="utf-8")
    # GAP-0486: a rollback whose gateway does not start (or is not proven) is
    # undone for a 1.x release as for a 0.x one, and never says "Now running".
    rollback = _ps1_function("Invoke-Rollback")
    proven = rollback.index("$problems = @(Wait-LifecycleProof (Get-Field $Manifest \"TargetBins\") $startAfter -AllowLegacyStatus:$legacyTarget)")
    assert rollback.index("Write-LifecycleManifest \"rollback\"") < rollback.index("if (-not (Stop-Gateway))")
    assert proven < rollback.index("return Undo-Rollback \"DefenseClaw $backTo is not proven running") < rollback.index("Now running DefenseClaw")
    assert "The gateway did not start; run 'defenseclaw-gateway start' and check its log" not in rollback
    undo = _ps1_function("Undo-Rollback")
    assert undo.index("[void](Start-Gateway)") < undo.index("Assert-LifecycleRestored") < undo.index('Write-Ok "DefenseClaw $forward is back')


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("case", ["start-fails-1x", "start-fails-0x", "not-proven", "proven"])
def test_a_rollback_is_done_only_once_its_gateway_runs_and_is_proven(tmp_path: Path, case: str) -> None:
    # GAP-0486: a rollback to a 1.x release whose gateway did not start
    # warned, printed "Now running" and returned 0. It is now undone, as a
    # rollback to 0.x always was, and only a proven rollback says "Now
    # running"; its record goes only then.
    back_to = "0.8.10" if case == "start-fails-0x" else "1.0.3"
    previous = tmp_path / "previous"
    (previous / "data").mkdir(parents=True)
    (previous / "VERSION").write_text(back_to, encoding="ascii")
    script = tmp_path / "rollback.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path}'\n$Previous = '{previous}'\n$BinDir = '{tmp_path / 'bin'}'\n$ReleaseBase = 'https://example.invalid'\n"
        "$Run = @{ Log = 'install.log'; RestorePending = $false }\n"
        f"$script:case = '{case}'; $script:undone = 0; $script:removed = 0; $script:starts = 0\n"
        "function Write-Step([string]$m) {}\nfunction Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Ok([string]$m) { Write-Host \"ok: $m\" }\nfunction Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Die([string]$m) { throw $m }\n"
        "function Get-InstalledVersion { return '1.0.4' }\n"
        "function Assert-NoLoadedPluginAgents { }\n"
        "function Assert-NoActiveConnectorRecovery { }\nfunction Confirm-Step { return $true }\n"
        "function Test-HookRollbackRestoreAvailable { return $false }\nfunction Wait-VenvFree { }\n"
        "function Test-RollbackData { return $false }\nfunction Get-GatewayProcess { return $true }\n"
        "function Stop-Gateway { return $true }\nfunction Stop-Watchdog { }\nfunction Assert-GatewayQuiescent { }\n"
        "function Switch-WithPrevious { return 0 }\nfunction Protect-UvDirectory { }\nfunction Invoke-PruneOrphanedHooks { }\n"
        "function Write-LifecycleManifest { return [pscustomobject]@{ TargetBins = @{} } }\nfunction Get-BinariesState { return @{} }\n"
        "function Remove-LifecycleManifest { $script:removed++ }\n"
        "function Start-Gateway { $script:starts++; if ($script:case -like 'start-fails*') { return 1 }; return 0 }\n"
        "function Wait-LifecycleProof { if ($script:case -eq 'not-proven') { return @('the gateway is not running') }; return @() }\n"
        "function Undo-Rollback { param($Reason) $script:undone++; Write-Host \"undo: $Reason\"; return 1 }\n"
        + _ps1_function("Get-Field") + _ps1_function("Read-Text") + _ps1_function("Test-Version") + _ps1_function("Invoke-Rollback")
        + "\n$rc = Invoke-Rollback\nWrite-Host \"rc: $rc undone: $script:undone removed: $script:removed\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    if case == "proven":
        assert "rc: 0 undone: 0 removed: 1" in out and "ok: Now running DefenseClaw 1.0.3" in out, out
    else:
        assert "rc: 1 undone: 1 removed: 0" in out and "Now running" not in out, out
        assert ("did not start" in out) if case.startswith("start-fails") else ("not proven running" in out), out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_pending_lifecycle_record_closes_the_hooks_with_the_kept_closer(tmp_path: Path) -> None:
    # fix/r104-windows review: a restore that consumed its snapshot and then
    # failed its proof keeps the lifecycle record and the lock, but nothing
    # counted as unfinished, so no hook was closed and an older restored hook
    # followed a configured open while the gateway was down. The record is
    # unfinished too, and the closer kept beside it (the checked staged
    # gateway) closes the hooks first.
    data, bin_dir = tmp_path / "data", tmp_path / "bin"
    (data / "hooks").mkdir(parents=True)
    (data / ".lifecycle-txn.json").write_text("{}", encoding="utf-8")
    (data / ".lifecycle-closer").mkdir()
    (data / ".lifecycle-closer" / "defenseclaw-gateway.exe").write_text("new closer", encoding="ascii")
    bin_dir.mkdir()
    (bin_dir / "defenseclaw-gateway.exe").write_text("old gateway", encoding="ascii")
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data}'\n$BinDir = '{bin_dir}'\n"
        "$LifecycleManifest = Join-Path $DataDir '.lifecycle-txn.json'\n$LifecycleCloser = Join-Path $DataDir '.lifecycle-closer'\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        + _close_mocks(capable="new ")
        + "\nClose-UnfinishedInstallHooks\n"
    )
    out = _run_powershell(script)
    text = out.stdout + out.stderr
    assert out.returncode == 0, text
    assert "RAN: " in text and ".lifecycle-closer" in text.split("RAN: ", 1)[1].splitlines()[0], text
    assert "every agent hook blocks tool calls" in text, text


_TRAMPOLINE_STUBS = """
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Staging = '{staging}'
$SetupHookState = '{state}'
$SetupDelegatedHooks = '{delegated}'
$BinDir = '{bin}'
$DataDir = '{data}'
$protected = New-Object System.Collections.Generic.List[string]
function Protect-SetupLauncherFile([string]$Path) {{ $protected.Add($Path) }}
function Write-Warn([string]$m) {{ Write-Host "warn $m" }}
"""


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("publication", ["success", "refused", "throws"])
def test_setup_launcher_state_stays_active_until_atomic_handoff(tmp_path: Path, publication: str) -> None:
    # GAP-1071: a cached Setup launcher must never observe a missing state
    # while the installer prepares the replacement, including on errors.
    state = tmp_path / "hook-runtime-state.json"
    state.write_text("original", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    publish = {
        "success": "[IO.File]::WriteAllText($SetupHookState, 'delegated'); return $true",
        "refused": "return $false",
        "throws": "throw 'publication failed'",
    }[publication]
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$SetupHookState = '{state}'\n$Staging = '{staging}'\n"
        "function Move-Path([string]$From, [string]$To) { [IO.File]::Move($From, $To) }\n"
        "function Protect-SetupLauncherFile([string]$Path) { }\n"
        "function Invoke-Quietly([scriptblock]$Action) { try { & $Action } catch { } }\n"
        "function Publish-SetupLauncherTrampoline([string]$Template, [string]$Hook, [string]$Gateway) {\n"
        "  if (-not (Test-Path -LiteralPath $SetupHookState)) { throw 'cached launcher saw missing state' }\n"
        f"  {publish}\n"
        "}\n"
        + _ps1_function("Disable-SetupHooks")
        + "try { Disable-SetupHooks; Write-Host 'result=ok' } catch { Write-Host \"result=error:$($_.Exception.Message)\" }\n"
        + "Write-Host \"state=$(if (Test-Path -LiteralPath $SetupHookState) { [IO.File]::ReadAllText($SetupHookState) } else { 'missing' })\"\n"
    )
    result = _run_powershell(script)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    if publication == "success":
        assert "result=ok" in output and "state=delegated" in output, output
        assert (staging / "hook-runtime-state.json").read_text(encoding="utf-8") == "original"
    else:
        assert "result=error:" in output and "state=original" in output, output


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("case", ["trampoline", "full-launcher", "launcher-changed", "refresh", "enable"])
def test_setup_launcher_delegates_to_this_releases_hook(tmp_path: Path, shell: str, case: str) -> None:
    # GAP-1000: an agent session started before a Setup -> 1.0.x upgrade keeps
    # running Setup's stable launcher, which answered every call with exit 0
    # and no decision once its state was set aside. Setup 0.8.10's launcher is
    # a trampoline: the installer points it at a private copy of this
    # release's hook (closed during the install, the gateway's verdict after),
    # keeps Setup's own state to put back, and refreshes the copy on every
    # later install. A launcher it cannot point elsewhere keeps the no-op.
    runtime, staging, bin_dir, data = tmp_path / "HookRuntime", tmp_path / "staging", tmp_path / "bin", tmp_path / "data"
    for folder in (runtime, staging / "bin", bin_dir, data):
        folder.mkdir(parents=True)
    launcher = runtime / "defenseclaw-hook.exe"
    launcher.write_bytes(b"setup-0.8.10-trampoline")
    state = runtime / "hook-runtime-state.json"
    original = {
        "schema_version": 2,
        "status": "active",
        "runtime_root": str(runtime),
        "launcher_path": str(launcher),
        "launcher_sha256": _sha256(launcher) if case != "launcher-changed" else "0" * 64,
        "launcher_kind": "trampoline",
        "hook_path": str(tmp_path / "Programs" / "DefenseClaw" / "bin" / "defenseclaw-hook.exe"),
        "hook_sha256": "1" * 64,
        "data_root": str(data),
        "gateway_path": str(tmp_path / "Programs" / "DefenseClaw" / "bin" / "defenseclaw-gateway.exe"),
        "gateway_sha256": "2" * 64,
        "transaction_id": "3" * 32,
    }
    if case == "full-launcher":
        for key in ("launcher_kind", "hook_path", "hook_sha256"):
            del original[key]
    original_text = json.dumps(original)
    state.write_text(original_text, encoding="utf-8")
    for folder, label in ((staging / "bin", "staged"), (bin_dir, "live")):
        (folder / "defenseclaw-hook.exe").write_bytes(f"{label}-1.0.4-hook".encode())
        (folder / "defenseclaw-gateway.exe").write_bytes(f"{label}-1.0.4-gateway".encode())
    delegated = runtime / "delegated"
    actions = {
        "trampoline": "Disable-SetupHooks",
        "full-launcher": "Disable-SetupHooks",
        "launcher-changed": "Disable-SetupHooks",
        "refresh": (
            "Disable-SetupHooks; $first = (Get-Content -LiteralPath $SetupHookState -Raw | ConvertFrom-Json).hook_path; "
            "Write-Host \"first=$first\"; "
            "[void](Publish-SetupLauncherTrampoline $SetupHookState (Join-Path $BinDir 'defenseclaw-hook.exe') (Join-Path $BinDir 'defenseclaw-gateway.exe'))"
        ),
        "enable": "Disable-SetupHooks; Enable-SetupHooks",
    }
    script = tmp_path / "trampoline.ps1"
    script.write_text(
        _TRAMPOLINE_STUBS.format(staging=staging, state=state, delegated=delegated, bin=bin_dir, data=data)
        + "".join(
            _ps1_function(name)
            for name in (
                "Get-Field",
                "Read-Json",
                "Move-Path",
                "Invoke-Quietly",
                "Test-SetupLauncherTrampoline",
                "Publish-SetupLauncherTrampoline",
                "Disable-SetupHooks",
                "Enable-SetupHooks",
            )
        )
        + actions[case]
        + "\nforeach ($p in $protected) { Write-Host \"protected $p\" }\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
    )
    kept = staging / "hook-runtime-state.json"
    if case in ("full-launcher", "launcher-changed"):
        # An old or changed launcher cannot be delegated. Abort with its
        # original state still active, before the gateway is stopped.
        assert completed.returncode != 0, completed.stdout + completed.stderr
        assert state.read_text(encoding="utf-8") == original_text, completed.stdout
        assert kept.read_text(encoding="utf-8") == original_text, completed.stdout
        assert not delegated.exists() or not any(delegated.iterdir()), completed.stdout
        return
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "warn" not in completed.stdout, completed.stdout
    if case == "enable":
        assert state.read_text(encoding="utf-8") == original_text, completed.stdout
        assert not kept.exists(), completed.stdout
        return
    assert kept.read_text(encoding="utf-8") == original_text, completed.stdout
    live = json.loads(state.read_text(encoding="utf-8-sig"))
    copy = Path(live["hook_path"])
    source = (bin_dir if case == "refresh" else staging / "bin") / "defenseclaw-hook.exe"
    assert copy.parent.parent == delegated and copy.name == "defenseclaw-hook.exe", live
    assert copy.read_bytes() == source.read_bytes() and live["hook_sha256"] == _sha256(copy), live
    assert live["transaction_id"] == copy.parent.name and re.fullmatch(r"[0-9a-f]{32}", live["transaction_id"]), live
    for key in ("runtime_root", "launcher_path", "launcher_sha256"):
        assert live[key] == original[key], (key, live)
    assert (live["schema_version"], live["status"], live["launcher_kind"]) == (2, "active", "trampoline"), live
    assert live["data_root"] == str(data) and live["gateway_path"] == str(bin_dir / "defenseclaw-gateway.exe"), live
    assert live["gateway_sha256"] == _sha256(source.parent / "defenseclaw-gateway.exe"), live
    assert f"protected {copy}" in completed.stdout, completed.stdout
    # Exactly one copy is left: an earlier one goes once a newer one is live.
    assert [p.name for p in delegated.iterdir()] == [copy.parent.name], list(delegated.iterdir())
    if case == "refresh":
        assert f"first={copy}" not in completed.stdout, completed.stdout


def test_the_installer_keeps_setups_launcher_pointed_at_its_own_hook() -> None:
    # GAP-1000: every place that sets Setup's launcher state aside or puts it
    # back goes through the trampoline helpers.
    assert "Publish-SetupLauncherTrampoline $state (Join-Path $Staging" in _ps1_function("Disable-SetupHooks")
    assert "Test-SetupLauncherTrampoline" in _ps1_function("Enable-SetupHooks")
    assert "Publish-SetupLauncherTrampoline" in _ps1_function("Remove-SetupInstall")
    assert "Test-SetupLauncherTrampoline" in _ps1_function("Complete-Swap")
    assert "Enable-SetupHooks" in _ps1_function("Resume-InterruptedRun")


# ── GAP-1063 / GAP-1067: same-version builds and the saved installer ────────


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_windows_names_another_build_of_the_installed_version(tmp_path: Path) -> None:
    # GAP-1063: two 1.0.4 builds were a same-version repair that kept no
    # rollback copy and said nothing before the swap.
    cases = [
        ("defenseclaw-gateway version 1.0.4 (commit=16d085f75a, built=a)", "OTHER commit 16d085f75a | commit 78c01d5c88"),
        ("defenseclaw-gateway version 1.0.4 (commit=78c01d5c88, built=b)", "SAME"),
        ("", "SAME"),
        ("defenseclaw-gateway version 1.0.3 (commit=aaaa, built=c)", "SAME"),
    ]
    rows = ", ".join(f"'{installed}'" for installed, _ in cases)
    script = f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{tmp_path}'
$Ver = '1.0.4'
New-Item -ItemType File -Path (Join-Path $BinDir 'defenseclaw-gateway.exe') -Force | Out-Null
$script:installed = ''
function Get-NativeOutput([string]$FilePath, [string[]]$Arguments = @()) {{
    if ((Split-Path -Leaf $FilePath) -eq 'defenseclaw-gateway.exe') {{ return "$script:installed`r`n" }}
    return "defenseclaw-gateway version 1.0.4 (commit=78c01d5c88, built=b)`r`n"
}}
{_ps_functions("Get-OtherBuildInstalled")}
foreach ($row in @({rows})) {{
    $script:installed = $row
    $other = Get-OtherBuildInstalled (Join-Path $BinDir 'staged-gateway.exe')
    if ($other) {{ Write-Output "OTHER $($other.Installed) | $($other.Staged)" }} else {{ Write-Output 'SAME' }}
}}
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert completed.stdout.split() == " ".join(expected for _, expected in cases).split(), out
    text = _text()
    swap = text[text.index("    # Swap. A same-version run") : text.index("$operation = if ($Repair)")]
    assert "$Repair = $PrevVersion -and $PrevVersion -eq $Ver -and -not $otherBuild" in swap
    assert "it is kept in $Previous, so 'defenseclaw rollback' returns to it" in swap
    assert swap.index("$otherBuild = ") < swap.index("Confirm-Step") < swap.index("$Snap = if ($Repair)")
    assert '$Snap = if ($Repair) { Join-Path $DataDir ".repair" }' in text
    assert 'if ($PrevVersion -eq $Ver) { $changed = "Replaced the other build of $Ver" }' in text


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("saved", [True, False])
def test_windows_records_the_saved_installer_in_the_form_rollback_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, saved: bool
) -> None:
    # GAP-1067: rollback ran a saved installer an agent had changed.
    data = tmp_path / "dc"
    (data / "installer").mkdir(parents=True)
    (data / "receipts").mkdir()
    (data / "receipts" / "installer.sha256").write_text("stale\n", encoding="ascii")
    installer = data / "installer" / "install.ps1"
    if saved:
        installer.write_bytes(b'$DcVersion = "1.0.4"\r\n')
    text = _text()
    body = text.split("function Save-InstallerDigest {", 1)[1].split("\n}\n", 1)[0]
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = '{data}'
$InstallerDir = '{data / "installer"}'
$Ver = '1.0.4'
function Write-Warn([string]$Message) {{ Write-Output "WARN $Message" }}
{_ps_functions("Get-Sha256")}
function Save-InstallerDigest {{{body}
}}
Save-InstallerDigest
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0 and "WARN" not in out, out
    record = data / "receipts" / "installer.sha256"
    if not saved:
        assert not record.exists()
        return
    assert record.read_bytes() == f"{hashlib.sha256(installer.read_bytes()).hexdigest()}  install.ps1\n".encode()
    monkeypatch.setattr(upgrade_shim, "_installer_name", lambda: "install.ps1")
    upgrade_shim._check_saved_installer(str(installer), str(installer), str(data), "1.0.4")
    installer.write_bytes(installer.read_bytes() + b"# r28sa note\r\n")
    with pytest.raises(upgrade_shim.ShimError, match="is not the one DefenseClaw saved"):
        upgrade_shim._check_saved_installer(str(installer), str(installer), str(data), "1.0.4")
    save = text.split("function Save-Installer {", 1)[1].split("\n}\n", 1)[0]
    assert save.rstrip().endswith("Save-InstallerDigest")
    assert "    Save-Installer\n" in text.split("function Complete-Swap {", 1)[1].split("\n}\n", 1)[0]


def test_the_windows_installer_asks_for_every_connector_to_be_guarded() -> None:
    # GAP-0878: Start-Gateway took exit 0 from a gateway whose boot skipped a
    # configured connector. A gateway that has --require-every-connector is
    # asked for it (an older one refuses the flag), also after a slow first
    # start, and its 3 keeps the install with "a connector needs attention".
    body = _ps1_function("Start-Gateway")
    probe = 'if ((Invoke-Native $gateway @("start", "--require-every-connector", "--help") -Quiet) -eq 0) { $startArgs += "--require-every-connector" }'
    assert body.index('$startArgs = @("start")') < body.index(probe) < body.index("$rc = Invoke-Native $gateway $startArgs")
    slow = body[body.index('Write-Ok "The gateway finished starting"') :]
    assert slow.index("if ($startArgs.Count -gt 1 -and (Invoke-Native $gateway $startArgs) -ne 0) { return 3 }") < slow.index(
        "return 0"
    )
    assert 'if ($startRc -eq 3) { Write-Warn "A connector needs attention before it is guarded again' in _text()


@pytest.mark.skipif(POWERSHELL is None or os.name == "nt", reason="needs pwsh running a shebang fake gateway")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("supports_flag", "every_rc", "want_rc", "want_last"),
    [
        (True, 3, 3, "start --require-every-connector"),
        (True, 0, 0, "start --require-every-connector"),
        (False, 0, 0, "start"),
    ],
)
def test_start_gateway_passes_the_every_connector_flag_only_to_a_gateway_that_has_it(
    tmp_path: Path, supports_flag: bool, every_rc: int, want_rc: int, want_last: str
) -> None:
    # GAP-0878: Start-Gateway's exit 0 from a gateway that skipped a
    # configured connector ended the upgrade with it unprotected.
    bin_dir, calls = tmp_path / "bin", tmp_path / "calls"
    bin_dir.mkdir()
    gateway = bin_dir / "defenseclaw-gateway.exe"
    gateway.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        f'  "start --require-every-connector --help") exit {0 if supports_flag else 1} ;;\n'
        f'  "start --require-every-connector") exit {every_rc} ;;\n'
        f"  start) exit {0 if not supports_flag else 9} ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$BinDir = '{bin_dir}'\n"
        'function Write-Info([string]$m) { Write-Host "info: $m" }\n'
        'function Write-Warn([string]$m) { Write-Host "warn: $m" }\n'
        'function Write-Ok([string]$m) { Write-Host "ok: $m" }\n'
        'function Get-UtcClock { "now" }\nfunction Get-InstalledVersion { "1.0.4" }\n'
        "function Test-Version($v) { $true }\nfunction Reset-AuditJournalMode { }\nfunction Get-GatewayProcess { $null }\n"
        + _ps1_function("Invoke-Native")
        + _ps1_function("Start-Gateway")
        + '$rc = Start-Gateway\nWrite-Host "rc=$rc"\n'
    )

    out = _run_powershell(script)

    assert f"rc={want_rc}" in out.stdout, out.stdout + out.stderr
    assert calls.read_text(encoding="utf-8").splitlines()[-1] == want_last


# ── 1.0.4 (T8 smoke review loop round 2 of the Hermes/upgrade class) ────────


def test_every_windows_upgrade_checks_the_removed_connectors_whatever_the_gateway_state() -> None:
    # The Windows installer never checked the removed connectors (OpenHands,
    # OmniGent) itself, and an upgrade of a stopped gateway does not start it,
    # so a 1.0.3 registration could stay unsealed with exit 0. The check runs
    # on every upgrade or repair once the swap is done, outside the gateway
    # start, and its failure is the install's exit 3.
    body = _ps1_function("Invoke-Install")
    call = "if ($PrevVersion -and -not (Complete-RetiredConnectorCleanup)) { $startRc = 3 }"
    assert body.count(call) == 1
    assert body.index("Complete-Swap\n") < body.index(call) < body.index("if ($startRc -eq 3) { Write-Warn")
    assert body.index("    if ($startNew) {\n") < body.index("    if ($startNew) { Remove-Item") < body.index(call)


@pytest.mark.skipif(POWERSHELL is None or os.name == "nt", reason="needs pwsh running a shebang fake gateway")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("dirty", "configured", "binary", "want", "want_calls"),
    [
        ({}, True, True, "True", ["verify openhands", "verify omnigent"]),
        (
            {"omnigent": "once"},
            True,
            True,
            "True",
            ["verify openhands", "verify omnigent", "teardown omnigent", "verify omnigent"],
        ),
        (
            {"openhands": "always"},
            True,
            True,
            "False",
            ["verify openhands", "teardown openhands", "verify openhands", "verify omnigent"],
        ),
        ({}, True, False, "False", []),
        ({"openhands": "always"}, False, True, "True", []),
    ],
)
def test_the_windows_removed_connector_check_seals_or_names_the_cause(
    tmp_path: Path, dirty: dict[str, str], configured: bool, binary: bool, want: str, want_calls: list[str]
) -> None:
    data_dir, bin_dir, state, calls = tmp_path / "dc", tmp_path / "bin", tmp_path / "state", tmp_path / "calls"
    for folder in (data_dir, bin_dir, state):
        folder.mkdir()
    if configured:
        (data_dir / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    for name, how in dirty.items():
        (state / name).write_text(how, encoding="utf-8")
    if binary:
        gateway = bin_dir / "defenseclaw-gateway.exe"
        gateway.write_text(
            "#!/bin/sh\n"
            f'[ "$5" = --data-dir ] && [ "$6" = "{data_dir}" ] || exit 9\n'
            f'echo "$2 $4" >> "{calls}"\n'
            f'state="{state}/$4"\n'
            '[ -f "$state" ] || exit 0\n'
            'if [ "$2" = teardown ]; then [ "$(cat "$state")" = once ] && rm -f "$state"; exit 1; fi\n'
            'echo "  X $4: $4 cleanup incomplete: C:/h/hook.ps1 is gone, but C:/w/.openhands/hooks.json still runs it. To finish: run defenseclaw-gateway connector teardown --connector $4" >&2\n'
            "exit 1\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\n$BinDir = '{bin_dir}'\n$Ver = '1.0.4'\n"
        "Remove-Item Env:DEFENSECLAW_CONFIG -ErrorAction SilentlyContinue\n"
        'function Write-Err([string]$m) { Write-Host "err: $m" }\n'
        + _ps1_function("Invoke-Native")
        + _ps1_function("Complete-RetiredConnectorCleanup")
        + "$clean = @(Complete-RetiredConnectorCleanup)\nWrite-Host \"clean=$($clean -join ',')\"\n"
    )

    out = _run_powershell(script)
    text = out.stdout + out.stderr

    assert out.returncode == 0, text
    assert f"clean={want}" in out.stdout, text
    assert (calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []) == want_calls
    if dirty.get("openhands") == "always" and configured:
        assert (
            "could not finish removing the openhands connector, so its agent may not be blocked: openhands: openhands cleanup incomplete"
            in text
        )
        assert (
            "C:/w/.openhands/hooks.json still runs it. To finish: run defenseclaw-gateway connector teardown --connector openhands"
            in text
        )
        assert "omnigent connector" not in text
    if not binary:
        assert (
            "could not check that the removed OpenHands and OmniGent connectors are blocked" in text
            and "is missing" in text
        )


# ── 1.0.4 (T8 smoke review loop round 3 of the Hermes/upgrade class) ────────


def test_a_stopped_windows_upgrade_puts_every_connector_on_its_current_hook() -> None:
    # An upgrade of a stopped per-user install does not start the gateway, so
    # nothing rendered this release's hooks (a 1.0.3 Hermes hook cannot answer
    # the execution probe) and it exited 0. Once the swap is done, a gateway
    # that was not started is reconciled, and a failure is the exit 3.
    body = _ps1_function("Invoke-Install")
    call = "if ($PrevVersion -and -not $startNew -and -not (Complete-StoppedConnectorReconcile)) { $startRc = 3 }"
    assert body.count(call) == 1
    assert (
        body.index("Complete-Swap\n")
        < body.index("if ($PrevVersion -and -not (Complete-RetiredConnectorCleanup))")
        < body.index(call)
        < body.index("if ($startRc -eq 3) { Write-Warn")
    )


@pytest.mark.skipif(POWERSHELL is None or os.name == "nt", reason="needs pwsh running a shebang fake gateway")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("configured", "binary", "help_rc", "reconcile_rc", "want", "want_calls"),
    [
        (False, True, 0, 0, "True", []),
        (True, False, 0, 0, "False", []),
        (True, True, 1, 0, "True", ["help"]),
        (True, True, 0, 0, "True", ["help", "reconcile"]),
        (True, True, 0, 3, "False", ["help", "reconcile"]),
    ],
)
def test_the_windows_stopped_upgrade_reconcile_names_the_cause(
    tmp_path: Path,
    configured: bool,
    binary: bool,
    help_rc: int,
    reconcile_rc: int,
    want: str,
    want_calls: list[str],
) -> None:
    data_dir, bin_dir, calls = tmp_path / "dc", tmp_path / "bin", tmp_path / "calls"
    data_dir.mkdir()
    bin_dir.mkdir()
    if configured:
        (data_dir / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    if binary:
        gateway = bin_dir / "defenseclaw-gateway.exe"
        gateway.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            f'  "connector reconcile --every-connector --help") echo help >> "{calls}"; exit {help_rc} ;;\n'
            f'  "connector reconcile --every-connector --data-dir {data_dir}")\n'
            f'    echo reconcile >> "{calls}"\n'
            f'    [ "$DEFENSECLAW_CONFIG" = "{data_dir}/config.yaml" ] || exit 9\n'
            '    echo "  OK claudecode is on its current hook"\n'
            f"    [ {reconcile_rc} -eq 0 ] && exit 0\n"
            '    echo "Error: not every connector is on its current hook: hermes: its current hook is not in place" >&2\n'
            f"    exit {reconcile_rc} ;;\n"
            "  *) exit 8 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\n$BinDir = '{bin_dir}'\n$Ver = '1.0.4'\n"
        "Remove-Item Env:DEFENSECLAW_CONFIG -ErrorAction SilentlyContinue\n"
        'function Write-Err([string]$m) { Write-Host "err: $m" }\n'
        + _ps1_function("Invoke-Native")
        + _ps1_function("Complete-StoppedConnectorReconcile")
        + "$ok = @(Complete-StoppedConnectorReconcile)\n"
        + "Write-Host \"ok=$($ok -join ',')\"\n"
        + 'Write-Host "config-after=[$env:DEFENSECLAW_CONFIG]"\n'
    )

    out = _run_powershell(script)
    text = out.stdout + out.stderr

    assert out.returncode == 0, text
    assert f"ok={want}" in out.stdout, text
    assert "config-after=[]" in out.stdout, text
    assert (calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []) == want_calls
    if reconcile_rc:
        assert (
            "err: DefenseClaw 1.0.4 could not put every connector on its current hook while the gateway is stopped: "
            "not every connector is on its current hook: hermes: its current hook is not in place" in text
        ), text
    if not binary:
        assert "defenseclaw-gateway.exe is missing" in text, text


# Win32_Process rows (ExecutablePath, CommandLine) and whether each is an
# agent. The agent is told by its executable, never by a name (GAP-1128).
_WINDOWS_AGENT_ROWS = [
    (r"C:\Users\u\.opencode\bin\opencode.exe", "opencode.exe", "opencode"),
    (r"C:\Tools\opencode.exe", "opencode.exe", ""),
    (r"C:\work\node_modules\opencode-ai\bin\opencode.exe", "opencode.exe", ""),
    (r"C:\Program Files\nodejs\node.exe", r'node "C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode"', "opencode"),
    (r"C:\Program Files\nodejs\node.exe", r"node C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\worker.js", ""),
    (r"C:\Program Files\nodejs\node.exe", r"node --conditions C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode C:\work\worker.js", ""),
    (r"C:\Program Files\nodejs\node.exe", r'node --conditions="dev C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode" C:\work\worker.js', ""),
    (r"C:\Program Files\nodejs\node.exe", r"node C:\work\worker.js C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode", ""),
    (r"C:\Program Files\nodejs\node.exe", r"node node_modules\opencode-ai\bin\opencode", ""),
    (r"C:\Program Files\nodejs\node.exe", r"node C:\Users\u\AppData\Roaming\npm\node_modules\@sourcegraph\amp\dist\main.js", "amp"),
    (r"C:\Users\u\.bun\bin\bun.exe", r"bun C:\Users\u\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode", ""),
    (r"C:\Users\u\.amp\bin\amp.exe", "amp.exe", "amp"),
    ("", "opencode.exe", ""),
]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_a_windows_agent_is_told_only_by_its_recorded_entry() -> None:
    # Fake WMI rows retain exact Windows command-line boundaries. The map is
    # what the agent installer recorded, independent of names and manifests.
    installed = (
        "$script:InstalledAgentPrograms = @{ "
        "'c:\\users\\u\\.opencode\\bin\\opencode.exe' = 'opencode'; "
        "'c:\\users\\u\\.amp\\bin\\amp.exe' = 'amp'; "
        "'c:\\users\\u\\appdata\\roaming\\npm\\node_modules\\opencode-ai\\bin\\opencode' = 'opencode'; "
        "'c:\\users\\u\\appdata\\roaming\\npm\\node_modules\\@sourcegraph\\amp\\dist\\main.js' = 'amp' }\n"
    )
    rows = "\n".join(
        "$p = [pscustomobject]@{{ ProcessId = {}; ExecutablePath = '{}'; CommandLine = '{}' }}; "
        "'[' + (Get-LoadedPluginAgent $p) + ']'".format(
            index + 1, program.replace("'", "''"), command.replace("'", "''")
        )
        for index, (program, command, _) in enumerate(_WINDOWS_AGENT_ROWS)
    )
    resolver = (
        "function Resolve-AgentPath([string]$Path) { if (-not $Path) { return '' }; "
        "return $Path.Replace('/', '\\').ToLowerInvariant() }\n"
        "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Host \"audit: PID $ProcessId $Reason\" }\n"
    )
    script = ("Set-StrictMode -Version Latest\n" + resolver + _ps1_function("Get-LoadedPluginAgent")
              + _ps1_function("Split-CommandLine") + installed + rows)
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    got = [line for line in result.stdout.splitlines() if line.startswith("[")]
    assert got == [f"[{agent}]" for _, _, agent in _WINDOWS_AGENT_ROWS], list(zip(_WINDOWS_AGENT_ROWS, got))
    assert "audit: PID 13" not in result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_windows_agent_scan_with_no_installed_entry_skips_process_rows() -> None:
    script = (
        "function Get-InstalledAgentPrograms { return @{} }\n"
        "function Get-CimInstance { param($Class, $ErrorAction) "
        "return @([pscustomobject]@{ ProcessId = 1; ExecutablePath = $null; CommandLine = '' }, "
        "[pscustomobject]@{ ProcessId = 2; ExecutablePath = 'C:\\Windows\\notepad.exe'; CommandLine = '' }) }\n"
        "function Get-LoadedPluginAgent($Process) { Write-Host 'scanned'; return '' }\n"
        "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Host \"audit: $Reason\" }\n"
        "function Die([string]$Message) { throw $Message }\n"
        + _ps1_function("Assert-NoLoadedPluginAgents")
        + "Assert-NoLoadedPluginAgents\n'scan-passed'\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "scan-passed", result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_windows_unrelated_executable_needs_no_path_resolution() -> None:
    script = (
        "function Resolve-AgentPath([string]$Path) { Write-Host 'resolved'; return $Path }\n"
        "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Host \"audit: $Reason\" }\n"
        + _ps1_function("Get-LoadedPluginAgent") + _ps1_function("Split-CommandLine")
        + "$script:InstalledAgentPrograms = @{ 'c:\\users\\u\\.opencode\\bin\\opencode.exe' = 'opencode' }\n"
        + "$p = [pscustomobject]@{ ProcessId = 1; ExecutablePath = 'C:\\Windows\\notepad.exe'; CommandLine = 'notepad.exe' }\n"
        + "'[' + (Get-LoadedPluginAgent $p) + ']'\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(("name", "package", "entry_name", "shim", "want"), [
    ("opencode", "opencode-ai", "bin/opencode", True, "opencode"),
    ("amp", "@sourcegraph/amp", "dist/main.js", True, "amp"),
    ("opencode", "opencode-ai", "bin/opencode", False, ""),
    ("opencode", "opencode-ai", "bin/worker.js", True, ""),
])
def test_windows_node_adjacent_npm_entry_counts_without_appdata(
    tmp_path: Path, name: str, package: str, entry_name: str, shim: bool, want: str,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    node = runtime / "node.exe"
    node.write_bytes(b"MZ")
    if shim:
        (runtime / f"{name}.cmd").write_text("@echo off", encoding="utf-8")
    entry = runtime / "node_modules" / package / entry_name
    entry.parent.mkdir(parents=True)
    entry.write_text("entry", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    script = (
        _ps1_function("Resolve-AgentPath") + _ps1_function("Get-InstalledAgentPrograms")
        + _ps1_function("Get-LoadedPluginAgent") + _ps1_function("Split-CommandLine")
        + "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Host \"audit: $Reason\" }\n"
        + f"$env:USERPROFILE = '{tmp_path / 'profile'}'\n$env:APPDATA = '{tmp_path / 'roaming'}'\n"
        + f"$env:LOCALAPPDATA = '{tmp_path / 'local'}'\n$DataDir = '{data}'\n"
        + f"$p = [pscustomobject]@{{ ProcessId = 1; ExecutablePath = '{node}'; CommandLine = 'node " +
          f'"{entry}"' + "' }\n"
        + "$script:InstalledAgentPrograms = Get-InstalledAgentPrograms @($p)\n"
        + f"$script:InstalledAgentPrograms.ContainsKey((Resolve-AgentPath '{entry}').ToLowerInvariant())\n"
        + ("'[' + (Get-LoadedPluginAgent $p) + ']'\n" if os.name == "nt" else "")
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    expected = [str(bool(want))] + ([f"[{want}]"] if os.name == "nt" else [])
    assert result.stdout.strip().splitlines() == expected, (result.stdout, result.stderr)


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_windows_installed_entries_are_exact_files(tmp_path: Path) -> None:
    profile, roaming, local, data = (tmp_path / name for name in ("profile", "roaming", "local", "data"))
    data.mkdir()
    native = profile / ".amp" / "bin" / "amp.exe"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"MZ")
    entry = roaming / "npm" / "node_modules" / "opencode-ai" / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("node entry", encoding="utf-8")
    (roaming / "npm" / "opencode.cmd").write_text("@echo off", encoding="utf-8")
    unrecorded = roaming / "npm" / "node_modules" / "opencode-ai" / "bin" / "worker.js"
    unrecorded.write_text("worker", encoding="utf-8")
    (entry.parent.parent / "package.json").write_text('{"author":{"name":"opencode-ai"},"name":"other"}', encoding="utf-8")
    on_path = tmp_path / "tools" / "opencode.exe"
    on_path.parent.mkdir()
    on_path.write_bytes(b"MZ")
    script = (
        "Set-StrictMode -Version Latest\n"
        + _ps1_function("Resolve-AgentPath") + _ps1_function("Get-InstalledAgentPrograms")
        + f"$env:USERPROFILE = '{profile}'\n$env:APPDATA = '{roaming}'\n$env:LOCALAPPDATA = '{local}'\n$env:PATH = '{on_path.parent}'\n$DataDir = '{data}'\n"
        + "$i = Get-InstalledAgentPrograms\nforeach ($k in @($i.Keys | Sort-Object)) { '{0}={1}' -f $k, $i[$k] }\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    lines = sorted(line for line in result.stdout.splitlines() if "=" in line)
    assert lines == sorted([f"{str(native).lower()}=amp", f"{str(entry).lower()}=opencode"]), result.stdout
    assert str(on_path).lower() not in result.stdout and str(unrecorded).lower() not in result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(("selected", "want"), [
    ("relative/opencode.exe", "0"),
    ("C:/scratch/opencode.exe", "1"),
])
def test_windows_hook_lock_entry_requires_an_absolute_path(tmp_path: Path, selected: str, want: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "hook_contract_lock.json").write_text(json.dumps({"connectors": {
        "opencode": {"agent_executable_source": "setup-selected", "agent_executable": selected},
        "amp": {},
    }}), encoding="utf-8")
    script = (
        "Set-StrictMode -Version Latest\n"
        "function Resolve-AgentPath([string]$Path) { "
        "if ($Path -eq 'relative\\opencode.exe' -or $Path -eq 'C:\\scratch\\opencode.exe') { "
        "return 'C:\\scratch\\opencode.exe' }; return '' }\n"
        + _ps1_function("Get-InstalledAgentPrograms")
        + f"$DataDir = '{data}'\n"
        + f"$env:USERPROFILE = '{tmp_path / 'profile'}'\n"
        + f"$env:APPDATA = '{tmp_path / 'roaming'}'\n"
        + f"$env:LOCALAPPDATA = '{tmp_path / 'local'}'\n"
        + "(Get-InstalledAgentPrograms).Count\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and result.stdout.strip() == want, (result.stdout, result.stderr)


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_windows_entry_resolution_follows_a_parent_link(tmp_path: Path) -> None:
    real = tmp_path / "real"
    entry = real / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("entry", encoding="utf-8")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory links require a Windows developer token")
    script = (_ps1_function("Resolve-AgentPath")
              + f"Resolve-AgentPath '{alias / 'bin' / 'opencode'}'")
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().lower() == str(entry.resolve()).lower(), result.stdout


@pytest.mark.skipif(os.name != "nt" or POWERSHELL is None or shutil.which("node") is None, reason="native Windows Node required")
@pytest.mark.allow_subprocess
def test_windows_relative_node_entry_does_not_use_the_installers_cwd(tmp_path: Path) -> None:
    entry = tmp_path / "node_modules" / "opencode-ai" / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("entry", encoding="utf-8")
    node = Path(shutil.which("node")).resolve()
    script = (
        "Set-StrictMode -Version Latest\n"
        + _ps1_function("Resolve-AgentPath") + _ps1_function("Get-LoadedPluginAgent")
        + _ps1_function("Split-CommandLine")
        + "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Host \"audit: $Reason\" }\n"
        + f"$script:InstalledAgentPrograms = @{{ '{str(entry).lower()}' = 'opencode' }}\n"
        + f"$p = [pscustomobject]@{{ ProcessId = 1; ExecutablePath = '{node}'; CommandLine = 'node node_modules\\opencode-ai\\bin\\opencode' }}\n"
        + "'[' + (Get-LoadedPluginAgent $p) + ']'\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "[]" in result.stdout and "audit: relative Node script cwd unreadable" in result.stdout


@pytest.mark.skipif(os.name != "nt" or POWERSHELL is None, reason="native Windows identity required")
@pytest.mark.allow_subprocess
def test_windows_vanished_agent_process_is_audited_without_refusal() -> None:
    # A PID can exit between the first WMI enumeration and the ownership
    # check. Its old row cannot establish that an agent is still live.
    script = (
        "Set-StrictMode -Version Latest\n"
        "function Get-InstalledAgentPrograms { return @{ 'c:\\agent.exe' = 'opencode' } }\n"
        "function Get-CimInstance { param($Class, $Filter, $ErrorAction) "
        "if ($Filter) { return $null }; "
        "return [pscustomobject]@{ ProcessId = 123; ExecutablePath = 'C:\\agent.exe'; CommandLine = 'agent' } }\n"
        "function Get-LoadedPluginAgent($Process) { return 'opencode' }\n"
        "function Invoke-CimMethod { throw 'owner query must not run for a vanished PID' }\n"
        "function Write-AgentIdentityAudit([int]$ProcessId, [string]$Reason) { Write-Output \"audit: $Reason\" }\n"
        "function Die([string]$Message) { throw $Message }\n"
        + _ps1_function("Assert-NoLoadedPluginAgents")
        + "Assert-NoLoadedPluginAgents\n'scan-passed'\n"
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "audit: process vanished or changed during lookup" in result.stdout
    assert "scan-passed" in result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.allow_subprocess
def test_a_windows_command_line_splits_as_node_reads_it() -> None:
    # Review loop 2: Split-CommandLine follows CommandLineToArgvW and the C
    # runtime, which Node and Bun use for their arguments.
    rows = [
        (r'"C:\Program Files\nodejs\node.exe" a "b c" d', [r"C:\Program Files\nodejs\node.exe", "a", "b c", "d"]),
        (r'node --x="a b" c', ["node", "--x=a b", "c"]),
        (r'node a\\\"b "c\\" d', ["node", 'a\\"b', "c\\", "d"]),
        (r'node "a""b" c', ["node", 'a"b', "c"]),
        (r"node a\b\\c	 x", ["node", r"a\b\\c", "x"]),
        (r'node "" x', ["node", "", "x"]),
        (r'C:\a"b c', ['C:\\a"b', "c"]),
        ("", []),
    ]
    script = "Set-StrictMode -Version Latest\n" + _ps1_function("Split-CommandLine") + "\n".join(
        "ConvertTo-Json -Compress -InputObject @(Split-CommandLine '{}')".format(line.replace("'", "''")) for line, _ in rows
    )
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in result.stdout.splitlines() if line.strip()] == [words for _, words in rows]


@pytest.mark.skipif(os.name != "nt" or POWERSHELL is None, reason="native Windows PowerShell required")
@pytest.mark.allow_subprocess
def test_windows_process_rows_carry_the_executable_the_agent_check_reads() -> None:
    # Get-LoadedPluginAgent reads Win32_Process.ExecutablePath: this
    # account's own processes carry it.
    script = "(Get-CimInstance Win32_Process -Filter \"ProcessId=$PID\").ExecutablePath"
    result = subprocess.run([POWERSHELL, "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().lower().endswith(".exe"), result.stdout


# oss-outage-open rounds j and k: install.ps1 records its own identity (its
# creation FILETIME, proc-start) beside the pid, and takes over a lock whose
# pid names another process than that record (a reused pid), as every hook
# does (hookexec installLockStale). No clock is read: a live installer keeps
# its lock for as long as it runs (no renewer, no deadline, no pid file age).
def test_install_ps1_takes_over_a_lock_whose_pid_was_reused() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    owner = text[text.index("function Get-InstallLockLiveOwner([string]$Lock) {") :]
    owner = owner[: owner.index("\n}\n")]
    assert '(Join-Path $Lock "proc-start")' in owner
    assert "[string]$process.StartTime.ToFileTimeUtc() -ne $recorded" in owner
    # A lock without the record (1.0.2, 1.0.3) reads as "", never $null: a
    # method call on the missing record stopped the install (round k native run).
    assert '$recorded = "$(Get-Content -LiteralPath (Join-Path $Lock "proc-start")' in owner and ".Trim()" in owner
    assert "$recorded.Trim()" not in owner
    assert "$process = $null" in owner
    # An exited installer whose process object a handle keeps is gone (round l).
    assert "$process.HasExited" in owner
    assert "LastWriteTime" not in owner and "AddSeconds" not in owner
    write = text.index('Set-Content -LiteralPath (Join-Path $LockDir "pid") -Value $PID -Encoding Ascii')
    take = text.rindex("    $taken = $false\n", 0, write)
    block = text[take:write]
    # The identity goes first and the pid last (a lock taken over in place).
    assert 'Set-Content -LiteralPath (Join-Path $LockDir "proc-start") -Value $identity' in block
    assert "(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToFileTimeUtc()" in text[text.rindex("$identity = ", 0, take) : take]
    assert "LockRenewer" not in text and "InstallLockMaxAge" not in text


# oss-outage-open round l loop 1 (P2): two installers that both read an old
# lock as stale each removed the canonical path and made it again, so the
# slower one deleted the live lock of the faster. A takeover is now in place
# and serialized by a claim in the folder (install.sh take_lock, doctor).
def test_install_ps1_takes_a_stale_lock_over_in_place_behind_a_claim() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    write = text.index('Set-Content -LiteralPath (Join-Path $LockDir "pid") -Value $PID -Encoding Ascii')
    take = text.rindex("    $taken = $false\n", 0, write)
    block = text[take:write]
    assert "Remove-Tree" not in block and "Remove-Item -LiteralPath $LockDir" not in block
    claim = block.index("[IO.File]::Move($part, (Join-Path $LockDir $claim))")
    check = block.index("Test-InstallLockClaimLive $_.FullName", claim)
    owner = block.index("$holder = Get-InstallLockLiveOwner $LockDir", check)
    assert claim < check < owner < block.index("$taken = $true", owner)
    assert 'Remove-Item -LiteralPath (Join-Path $LockDir $claim)' in block
    live = text[text.index("function Test-InstallLockClaimLive([string]$Path) {") :]
    live = live[: live.index("\n}\n")]
    assert "[int]$claimer -eq $PID" in live and "StartTime.ToFileTimeUtc() -eq $recorded" in live
    assert "$process.HasExited" in live
