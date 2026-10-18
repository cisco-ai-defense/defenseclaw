# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Installer version changes must preserve external connector recovery evidence."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install.ps1"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")
WINDOWS_POWERSHELL = pytest.mark.skipif(
    os.name != "nt" or POWERSHELL is None, reason="requires native Windows directory ACLs and PowerShell"
)


def _function(name: str) -> str:
    source = INSTALLER.read_text(encoding="utf-8")
    match = re.search(rf"^function {re.escape(name)}[ (]", source, re.M)
    assert match is not None, name
    start = match.start()
    return source[start : source.index("\n}\n", start) + 3]


def _literal(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _helpers() -> str:
    names = (
        "Set-DirectoryAcl",
        "Move-Path",
        "Test-ConnectorRecoveryArtifactName",
        "Save-FailedConnectorRecovery",
        "Remove-FailedInstall",
        "New-FailedInstallDirectory",
        "Get-DataEntries",
        "Move-RestoreConnectorRecovery",
        "Restore-Slot",
        "Clear-SetupDataDir",
        "Invoke-Quietly",
        "Assert-NoActiveConnectorRecovery",
        "Assert-GatewayQuiescent",
    )
    return "\n".join(_function(name) for name in names)


def _run(data_dir: Path, body: str) -> str:
    # Only extracted functions run, against explicit disposable paths. No
    # installer entry point, config discovery, daemon or real profile is used.
    script = f"""
$ErrorActionPreference = 'Stop'
$DataDir = {_literal(data_dir)}
function Write-Warn([string]$Message) {{ Write-Host $Message }}
function Write-Info([string]$Message) {{ Write-Host $Message }}
function Remove-Tree([string]$Path) {{
    if (Test-Path -LiteralPath $Path) {{ [IO.Directory]::Delete($Path, $true) }}
}}
{_helpers()}
{body}
exit 0
"""
    # A real function integration case can exceed Windows' command-line limit.
    # Keep the script outside DataDir so it cannot become installer data.
    with tempfile.TemporaryDirectory(prefix="dc-cas-test-") as case:
        script_path = Path(case) / "case.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        result = subprocess.run(
            [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
            env={key: value for key, value in os.environ.items() if key.lower() != "psmodulepath"},
        )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture
def recovery_dirs(tmp_path_factory):
    # Short names also exercise real GC receipt names on Windows PowerShell
    # 5.1 without making the test's own path exceed MAX_PATH.
    base = tmp_path_factory.mktemp("cas")
    data = base / "d"
    failed = data / ".failed-x"
    (failed / "data").mkdir(parents=True)
    (failed / "venv").mkdir()
    (failed / "venv" / "runtime.txt").write_bytes(b"failed runtime")
    external = base / "agent"
    external.mkdir()
    (external / "settings.json").write_bytes(b'{"unchanged":"external"}')
    (external / ".tmp-cas-v2-old-external").write_bytes(b"external old config")
    active = data / (".defenseclaw-cas-v2-" + "a" * 24 + ".intent")
    active.write_bytes(b"restored active receipt")
    return data, failed, external, active


def _assert_active_unchanged(external: Path, active: Path) -> None:
    assert active.read_bytes() == b"restored active receipt"
    assert (external / "settings.json").read_bytes() == b'{"unchanged":"external"}'
    assert (external / ".tmp-cas-v2-old-external").read_bytes() == b"external old config"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    "name",
    [
        ".defenseclaw-cas-v2-",
        ".DEFENSECLAW-CAS-V2-malformed",
        ".defenseclaw-cas-v2-transaction.intent.complete",
        ".defenseclaw-cas-v2-transaction.prepared.gc-retired",
    ],
)
def test_downgrade_guard_refuses_all_immediate_v2_receipt_names(tmp_path, name: str) -> None:
    receipt = tmp_path / name
    receipt.write_bytes(b"opaque active recovery")
    identity = receipt.stat().st_ino
    _run(
        tmp_path,
        """
try { Assert-NoActiveConnectorRecovery 'Downgrade'; throw 'guard unexpectedly passed' } catch {
    if ($_.Exception.Message -notlike '*active connector recovery*') { throw }
}
""",
    )
    assert receipt.read_bytes() == b"opaque active recovery"
    assert receipt.stat().st_ino == identity


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_downgrade_guard_ignores_protocol_lock_publication_temps_and_archived_receipts(tmp_path) -> None:
    for name in (".defenseclaw-v2-protocol.lock", ".tmp-cas-v2-unpublished", ".defenseclaw-cas-v1-old"):
        (tmp_path / name).write_bytes(b"not active v2 recovery")
    for name in ("previous", "backups", ".failed-retained"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / ".defenseclaw-cas-v2-retained").write_bytes(b"inactive evidence")
    _run(tmp_path, "Assert-NoActiveConnectorRecovery 'Downgrade'")


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("kind", ["missing", "file", "junction", "ancestor_junction", "unreadable", "reserved_directory"])
def test_downgrade_guard_fails_closed_on_uninspectable_roots_and_reserved_directories(tmp_path, kind: str) -> None:
    root = tmp_path / "root"
    setup = ""
    expected = "cannot inspect connector recovery"
    if kind == "file":
        root.write_bytes(b"not a directory")
    elif kind in ("junction", "ancestor_junction"):
        external = tmp_path / "external"
        external.mkdir()
        (external / "unchanged").write_bytes(b"external")
        setup = f"New-Item -ItemType Junction -Path {_literal(root)} -Target {_literal(external)} | Out-Null"
        if kind == "ancestor_junction":
            (external / "data").mkdir()
            root = root / "data"
    elif kind in ("unreadable", "reserved_directory"):
        root.mkdir()
        if kind == "unreadable":
            setup = "function Get-ChildItem { throw 'injected directory enumeration denial' }"
        else:
            (root / ".defenseclaw-cas-v2-malformed").mkdir()
            expected = "active connector recovery"
    _run(
        tmp_path,
        f"""
{setup}
try {{ Assert-NoActiveConnectorRecovery 'Downgrade' {_literal(root)}; throw 'guard unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*{expected}*') {{ throw }}
}}
""",
    )
    if kind in ("junction", "ancestor_junction"):
        assert (external / "unchanged").read_bytes() == b"external"


def _handoff_stubs(version: str, exit_code: int, marker: str | None = "1") -> str:
    installer = '$DcVersion = "1.0.1"'
    if marker is not None:
        installer += f"\n$DcVersionChangeGuard = {marker}"
    installer_literal = "'" + installer.replace("'", "''") + "'"
    return f"""
{_function('Test-Version')}
{_function('Invoke-ReleaseInstaller')}
$ReleaseBase = 'https://release.invalid'
$OfficialReleaseBase = $ReleaseBase
$BinDir = Join-Path $DataDir 'bin'
$script:events = @()
$script:running = $true
$script:starts = 0
$script:children = 0
function Die([string]$Message) {{ throw $Message }}
function Get-InstalledVersion {{ return '{version}' }}
function Save-Url([string]$Url, [string]$To) {{
    $script:events += 'fetch'
    [IO.File]::WriteAllText($To, {installer_literal})
    return $true
}}
function Get-ListedSha256 {{ return 'verified' }}
function Get-Sha256 {{ return 'verified' }}
function Get-Cosign {{ return '' }}
function Wait-VenvFree {{ $script:events += 'wait' }}
function Get-GatewayProcess {{ return $script:running }}
function Get-ProcessesUnder {{ return @() }}
function Stop-Gateway {{ $script:events += 'stop'; $script:running = $false; return $true }}
function Stop-Watchdog {{ $script:events += 'watchdog' }}
function Start-Gateway {{ $script:events += 'restart'; $script:starts++; $script:running = $true; return 0 }}
function ConvertTo-ProcessArgument([string]$Value) {{ return $Value }}
function Start-Process {{
    $script:events += 'child'
    $script:children++
    $child = [PSCustomObject]@{{ Handle = [IntPtr]::Zero; ExitCode = {exit_code} }}
    $child | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {{}}
    return $child
}}
"""


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("exit_code", [0, 1, 3])
@pytest.mark.parametrize("restart", [0, 3, 1, "throw"])
@pytest.mark.parametrize("installed", ["1.0.0", "1.0.2"])
def test_wrapped_installer_handoff_combines_child_and_restart_results_after_verified_quiescence(
    tmp_path, exit_code, restart, installed
) -> None:
    expected = exit_code if exit_code else (1 if restart in (1, "throw") else restart)
    result = "throw 'injected restart failure'" if restart == "throw" else f"return {restart}"
    output = _run(
        tmp_path,
        f"""
{_handoff_stubs(installed, exit_code, None if installed == '1.0.0' else '1')}
function Start-Gateway {{
    $script:events += 'restart'
    $script:starts++
    $script:running = ${str(restart in (0, 3)).lower()}
    {result}
}}
$code = Invoke-ReleaseInstaller '1.0.1' @('-Yes')
if ($code -ne {expected}) {{ throw ('Wrong handoff exit: ' + $code) }}
if ($script:starts -ne 1 -or $script:children -ne 1) {{ throw 'Current runtime was not restarted once' }}
if (($script:events -join ',') -ne 'fetch,fetch,wait,stop,watchdog,child,restart') {{
    throw ('Unsafe handoff order: ' + ($script:events -join ','))
}}
""",
    )
    if restart in (1, "throw"):
        assert "The installed gateway could not restart" in output
        assert "Retry the installed version with 'defenseclaw-gateway start'" in output
        assert "'defenseclaw rollback', then 'defenseclaw-gateway start'" in output
    else:
        assert "could not restart" not in output


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("restart", [1, "throw"])
def test_handoff_restart_failure_does_not_replace_the_original_recovery_guard_exception(tmp_path, restart) -> None:
    receipt = tmp_path / ".defenseclaw-cas-v2-during-stop"
    result = "throw 'injected restart failure'" if restart == "throw" else "return 1"
    output = _run(
        tmp_path,
        f"""
{_handoff_stubs('1.0.2', 0)}
function Stop-Gateway {{
    $script:running = $false
    [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery')
    return $true
}}
function Start-Gateway {{ $script:starts++; {result} }}
try {{ Invoke-ReleaseInstaller '1.0.1' @('-Yes'); throw 'handoff unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:children -ne 0 -or $script:starts -ne 1) {{ throw 'Refused handoff changed dispatch or restart' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"
    assert "could not restart" in output
    assert "Retry the installed version with 'defenseclaw-gateway start'" in output
    assert "To undo a completed version change" not in output


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_handoff_restart_failure_is_local_to_one_invocation(tmp_path) -> None:
    _run(
        tmp_path,
        f"""
{_handoff_stubs('1.0.2', 0)}
function Start-Gateway {{
    $script:starts++
    if ($script:starts -eq 1) {{ return 1 }}
    $script:running = $true
    return 0
}}
if ((Invoke-ReleaseInstaller '1.0.1' @('-Yes')) -ne 1) {{ throw 'Failed restart was reported as success' }}
$script:running = $true
if ((Invoke-ReleaseInstaller '1.0.1' @('-Yes')) -ne 0) {{ throw 'Prior restart failure leaked into later handoff' }}
if ($script:children -ne 2 -or $script:starts -ne 2) {{ throw 'Repeated handoff did not run independently' }}
""",
    )


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_older_installer_handoff_keeps_a_previously_stopped_gateway_stopped(tmp_path) -> None:
    _run(
        tmp_path,
        f"""
{_handoff_stubs('1.0.2', 3)}
$script:running = $false
if ((Invoke-ReleaseInstaller '1.0.1' @('-Yes')) -ne 3) {{ throw 'Child exit code changed' }}
if ($script:starts -ne 0 -or $script:children -ne 1) {{ throw 'Stopped gateway was started' }}
""",
    )


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize(
    ("installed", "phase"),
    [("1.0.0", "early"), ("1.0.2", "early"), ("1.0.2", "stop"), ("1.0.2", "watchdog")],
)
def test_version_change_handoff_never_launches_after_recovery_is_pending(tmp_path, phase: str, installed: str) -> None:
    receipt = tmp_path / ".defenseclaw-cas-v2-injected.intent"
    if phase == "early":
        receipt.write_bytes(b"pending recovery")
    injection = ""
    if phase == "stop":
        injection = f"""
function Stop-Gateway {{
    $script:running = $false
    [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery')
    return $true
}}
"""
    elif phase == "watchdog":
        injection = f"function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery') }}"
    _run(
        tmp_path,
        f"""
{_handoff_stubs(installed, 0)}
{injection}
try {{ Invoke-ReleaseInstaller '1.0.1' @('-Yes'); throw 'handoff unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:children -ne 0) {{ throw 'Release installer launched' }}
if ($script:starts -ne {0 if phase == 'early' else 1}) {{ throw 'Wrong restart behavior' }}
if ('{phase}' -eq 'early' -and $script:events.Count -ne 0) {{ throw 'Early refusal fetched or stopped anything' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("installed", ["1.0.0", "1.0.1"])
def test_clean_forward_handoff_and_same_version_repair_remain_allowed(tmp_path, installed: str) -> None:
    receipt = tmp_path / ".defenseclaw-cas-v2-active"
    if installed == "1.0.1":
        receipt.write_bytes(b"keep current protocol recovery")
    _run(
        tmp_path,
        f"""
{_handoff_stubs(installed, 3)}
if ((Invoke-ReleaseInstaller '1.0.1' @('-Yes')) -ne 3) {{ throw 'Child exit code changed' }}
if ($script:children -ne 1 -or $script:starts -ne 0) {{ throw 'Upgrade or repair routing changed' }}
if (-not $script:running) {{ throw 'Forward installer lost the running gateway state needed for startup rollback' }}
if (($script:events -join ',') -ne 'fetch,fetch,child') {{ throw 'Forward or same-version handoff was quiesced' }}
""",
    )
    if installed == "1.0.1":
        assert receipt.read_bytes() == b"keep current protocol recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("marker", [None, "2", '"1"', "1\n$DcVersionChangeGuard = 2", "1\n  $DcVersionChangeGuard = 2"])
@pytest.mark.parametrize("phase", ["fetch", "watchdog"])
def test_legacy_or_unknown_forward_installer_cannot_snapshot_late_recovery(tmp_path, marker, phase) -> None:
    receipt = tmp_path / ".defenseclaw-cas-v2-during-fetch.intent"
    injection = f"function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery') }}"
    if phase == "fetch":
        injection = f"""
$script:saveUrl = (Get-Item Function:Save-Url).ScriptBlock
function Save-Url([string]$Url, [string]$To) {{
    $saved = & $script:saveUrl $Url $To
    [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery')
    return $saved
}}
"""
    _run(
        tmp_path,
        f"""
{_handoff_stubs('1.0.0', 0, marker)}
{injection}
try {{ Invoke-ReleaseInstaller '1.0.1' @('-Yes'); throw 'legacy forward handoff unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:children -ne 0 -or $script:starts -ne 1) {{ throw 'Legacy forward dispatch or restart was unsafe' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("failure", ["none", "checksum", "signature", "stamp"])
def test_forward_capability_is_read_only_after_checksum_signature_and_stamp_verification(tmp_path, failure) -> None:
    _run(
        tmp_path,
        f"""
{_handoff_stubs('1.0.0', 0)}
$script:capabilityReads = 0
function Get-ListedSha256 {{ $script:events += 'checksum'; return 'verified' }}
function Get-Sha256 {{ return '{'wrong' if failure == 'checksum' else 'verified'}' }}
function Get-Cosign {{ return 'fixture-cosign' }}
function Test-ReleaseSignature {{ $script:events += 'signature'; return {1 if failure == 'signature' else 0} }}
function Select-String([string]$LiteralPath, [string]$Pattern) {{
    if ($Pattern -like '*DcVersionChangeGuard*') {{
        $script:events += 'capability'
        $script:capabilityReads++
    }} else {{
        $script:events += 'stamp'
        if ('{failure}' -eq 'stamp') {{
            return [pscustomobject]@{{ Matches = @([pscustomobject]@{{ Groups = @($null, [pscustomobject]@{{ Value = '9.9.9' }}) }}) }}
        }}
    }}
    & (Get-Command Select-String -CommandType Cmdlet) -LiteralPath $LiteralPath -Pattern $Pattern
}}
try {{
    $code = Invoke-ReleaseInstaller '1.0.1' @('-Yes')
    if ('{failure}' -ne 'none') {{ throw 'Unverified forward child unexpectedly launched' }}
    if ($code -ne 0) {{ throw 'Verified marked forward child failed' }}
}} catch {{
    if ('{failure}' -eq 'none' -or $_.Exception.Message -notmatch 'does not match|did not verify|mismatched release') {{ throw }}
}}
if ($script:capabilityReads -ne {1 if failure == 'none' else 0}) {{ throw 'Trusted capability before verification' }}
if ($script:children -ne {1 if failure == 'none' else 0} -or $script:starts -ne 0) {{
    throw 'Verification changed dispatch or gateway state'
}}
if ('{failure}' -eq 'none') {{
    $trace = $script:events -join ','
    if ($trace -notlike '*checksum*signature*stamp*capability*child') {{ throw ('Wrong verification order: ' + $trace) }}
    if (-not $script:running) {{ throw 'Marked forward child lost its startup/rollback state' }}
}}
""",
    )


def _rollback_stubs(data: Path, current: str = "1.0.2") -> str:
    return f"""
{_function('Test-Version')}
{_function('Invoke-Rollback')}
$Previous = {_literal(data / 'previous')}
$BinDir = {_literal(data / 'bin')}
$script:stops = 0
$script:starts = 0
$script:swaps = 0
$script:conversions = 0
$script:running = $true
function Read-Text([string]$Path) {{ if (Test-Path -LiteralPath $Path) {{ return [IO.File]::ReadAllText($Path).Trim() }}; return '' }}
function Get-InstalledVersion {{ return '{current}' }}
function Write-Step([string]$Message) {{}}
function Write-Ok([string]$Message) {{}}
function Confirm-Step {{ return $true }}
function Die([string]$Message) {{ throw $Message }}
function Wait-VenvFree {{}}
function Get-GatewayProcess {{ return $script:running }}
function Get-ProcessesUnder {{ return @() }}
function Stop-Gateway {{ $script:stops++; $script:running = $false; return $true }}
function Stop-Watchdog {{}}
function Start-Gateway {{ $script:starts++; $script:running = $true; return 0 }}
function Convert-HooksForRollback {{ $script:conversions++ }}
function Switch-WithPrevious {{ $script:swaps++; return 0 }}
function Protect-UvDirectory {{}}
function Invoke-PruneOrphanedHooks {{}}
"""


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("phase", ["early", "stop", "watchdog", "conversion"])
@pytest.mark.parametrize("location", ["active", "incoming"])
def test_rollback_refuses_pending_recovery_before_any_swap_and_restarts_on_late_refusal(tmp_path, phase, location) -> None:
    previous = tmp_path / "previous"
    (previous / "data").mkdir(parents=True)
    (previous / "VERSION").write_text("1.0.1", encoding="ascii")
    (tmp_path / "config.yaml").write_bytes(b"current config")
    (previous / "data" / "config.yaml").write_bytes(b"prior config")
    root = tmp_path if location == "active" else previous / "data"
    receipt = root / ".defenseclaw-cas-v2-injected.complete"
    injection = ""
    if phase == "early":
        receipt.write_bytes(b"pending recovery")
    elif phase == "stop":
        injection = f"""
function Stop-Gateway {{
    $script:stops++
    $script:running = $false
    [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery')
    return $true
}}
"""
    elif phase == "watchdog":
        injection = f"function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery') }}"
    else:
        injection = f"""
function Convert-HooksForRollback {{
    $script:conversions++
    [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery')
    Write-Warn 'conversion reported pending recovery'
}}
"""
    _run(
        tmp_path,
        f"""
{_rollback_stubs(tmp_path)}
{injection}
try {{ Invoke-Rollback; throw 'rollback unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:swaps -ne 0) {{ throw 'Rollback exchanged runtime or data' }}
if ($script:starts -ne {0 if phase == 'early' else 1}) {{ throw 'Current gateway was not restored' }}
if ($script:stops -ne {0 if phase == 'early' else 1}) {{ throw 'Early refusal stopped current runtime' }}
if ($script:conversions -ne {1 if phase == 'conversion' else 0}) {{ throw 'Recovery refusal ran hook conversion' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"
    assert (tmp_path / "config.yaml").read_bytes() == b"current config"
    assert (previous / "data" / "config.yaml").read_bytes() == b"prior config"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("phase", ["early", "watchdog"])
def test_roll_forward_refuses_current_recovery_without_stranding_it_in_previous(tmp_path, phase) -> None:
    previous = tmp_path / "previous"
    (previous / "data").mkdir(parents=True)
    (previous / "VERSION").write_text("1.0.2", encoding="ascii")
    receipt = tmp_path / ".defenseclaw-cas-v2-current"
    incoming = previous / "data" / ".defenseclaw-cas-v2-incoming"
    incoming.write_bytes(b"newer reader recovery")
    if phase == "early":
        receipt.write_bytes(b"current recovery")
    injection = "" if phase == "early" else (
        f"function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'current recovery') }}"
    )
    _run(
        tmp_path,
        f"""
{_rollback_stubs(tmp_path, '1.0.1')}
{injection}
try {{ Invoke-Rollback; throw 'roll forward unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:swaps -ne 0 -or $script:conversions -ne 0) {{ throw 'Roll forward moved pending recovery' }}
if ($script:starts -ne {0 if phase == 'early' else 1}) {{ throw 'Wrong current runtime restart behavior' }}
""",
    )
    assert receipt.read_bytes() == b"current recovery"
    assert incoming.read_bytes() == b"newer reader recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_roll_forward_allows_incoming_recovery_for_the_newer_reader(tmp_path) -> None:
    previous = tmp_path / "previous"
    (previous / "data").mkdir(parents=True)
    (previous / "VERSION").write_text("1.0.2", encoding="ascii")
    receipt = previous / "data" / ".defenseclaw-cas-v2-active"
    receipt.write_bytes(b"incoming protocol")
    _run(
        tmp_path,
        f"""
{_rollback_stubs(tmp_path, '1.0.1')}
if ((Invoke-Rollback) -ne 0) {{ throw 'Roll forward failed' }}
if ($script:swaps -ne 1 -or $script:conversions -ne 0) {{ throw 'Roll forward routing changed' }}
""",
    )
    assert receipt.read_bytes() == b"incoming protocol"


def test_direct_installer_guards_version_changes_before_staging_and_after_quiescence() -> None:
    install = _function("Invoke-Install")
    early = install.index('if ($versionChange) { Assert-NoActiveConnectorRecovery "Version change to $Ver" }')
    late = install.index('            Assert-NoActiveConnectorRecovery "Version change to $Ver"')
    assert early < install.index('Assert-InstallRoom $InstallRoom') < install.index('New-InstallDirectory $Staging')
    assert install.index('Wait-VenvFree', early) < install.index('Stop-Watchdog', early) < late
    assert late < install.index('Save-Snapshot')
    assert 'Restart-Old\n            throw' in install[late:]


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("version_change", [False, True])
def test_direct_installer_late_guard_runs_after_watchdog_and_before_snapshot(tmp_path, version_change: bool) -> None:
    install = _function("Invoke-Install")
    start = install.index('    Assert-InstallRoom $FinalEnvRoom')
    end = install.index('    $Snap =', start)
    phase = install[start:end]
    receipt = tmp_path / ".defenseclaw-cas-v2-late"
    _run(
        tmp_path,
        f"""
$versionChange = ${str(version_change).lower()}
$Setup = $null
$Ver = '1.0.1'
$script:starts = 0
$script:snapshots = 0
$script:running = $true
$BinDir = Join-Path $DataDir 'bin'
function Assert-InstallRoom {{}}
function Wait-VenvFree {{}}
function Get-GatewayProcess {{ return $script:running }}
function Get-ProcessesUnder {{ return @() }}
function Get-UtcClock {{ return 'test-clock' }}
function Stop-Gateway {{ $script:running = $false; return $true }}
function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery') }}
function Restart-Old {{ $script:starts++ }}
function Save-Snapshot {{ $script:snapshots++ }}
try {{
{phase}
    Save-Snapshot
    if ($versionChange) {{ throw 'version change unexpectedly passed' }}
}} catch {{
    if (-not $versionChange -or $_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:starts -ne {1 if version_change else 0}) {{ throw 'Wrong current gateway restart behavior' }}
if ($script:snapshots -ne {0 if version_change else 1}) {{ throw 'Wrong snapshot behavior' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("route", ["handoff", "rollback", "local"])
def test_a_surviving_watchdog_refuses_older_readers_and_restarts_the_current_gateway(tmp_path, route) -> None:
    if route == "handoff":
        stubs = _handoff_stubs("1.0.2", 0)
        call = "Invoke-ReleaseInstaller '1.0.1' @('-Yes')"
        unchanged = "$script:children -eq 0"
    elif route == "rollback":
        previous = tmp_path / "previous"
        (previous / "data").mkdir(parents=True)
        (previous / "VERSION").write_text("1.0.1", encoding="ascii")
        stubs = _rollback_stubs(tmp_path)
        call = "Invoke-Rollback"
        unchanged = "$script:swaps -eq 0 -and $script:conversions -eq 0"
    else:
        install = _function("Invoke-Install")
        start = install.index("    Assert-InstallRoom $FinalEnvRoom")
        end = install.index("    $Snap =", start)
        call = install[start:end] + "\n$script:snapshots++"
        stubs = """
$versionChange = $true
$Setup = $null
$Ver = '1.0.1'
$BinDir = Join-Path $DataDir 'bin'
$script:starts = 0
$script:snapshots = 0
$script:running = $true
function Assert-InstallRoom {}
function Wait-VenvFree {}
function Get-GatewayProcess { return $script:running }
function Get-UtcClock { return 'test-clock' }
function Stop-Gateway { $script:running = $false; return $true }
function Stop-Watchdog {}
function Restart-Old { $script:starts++ }
"""
        unchanged = "$script:snapshots -eq 0"
    _run(
        tmp_path,
        f"""
{stubs}
function Get-ProcessesUnder {{ return @([pscustomobject]@{{ Name = 'defenseclaw-gateway.exe' }}) }}
try {{
    {call}
    throw 'older reader unexpectedly started'
}} catch {{
    if ($_.Exception.Message -notlike '*gateway or watchdog is still running*') {{ throw }}
}}
if (-not ({unchanged})) {{ throw 'Refusal changed the current installation' }}
if ($script:starts -ne 1) {{ throw 'Current gateway was not restarted' }}
""",
    )


def _local_install_stubs(data: Path, assets: Path, target: str, installed: str = "1.0.2") -> str:
    functions = (
        "Test-Version",
        "Test-SamePath",
        "New-InstallDirectory",
        "Get-Sha256",
        "Get-ListedSha256",
        "Test-Checksum",
        "Get-Asset",
        "Invoke-Install",
    )
    # The C# here-string has its own column-zero braces; retain the complete
    # real native helper rather than the short function slicer's first brace.
    source = INSTALLER.read_text(encoding="utf-8")
    native = source[source.index("function Initialize-Native") : source.index("function Update-UserPath")]
    return native + "\n".join(_function(name) for name in functions) + f"""
$Help = $false
$UnknownArguments = @()
$Connector = 'none'
$QuickstartMode = ''
$Quickstart = $false
$NoOpenclaw = $false
$Rollback = $false
$Yes = $true
$NoPersistPath = $true
$CosignPath = ''
$RunAsFile = $false
$RunByUpgrade = $false
$Run = @{{ Owner = [IntPtr]::Zero; Lock = $false; Transcript = $false; Log = '' }}
$Version = '{target}'
$DcVersion = '1.0.2'
$Local = {_literal(assets)}
$LocalGiven = $true
$BinDir = {_literal(data / 'bin')}
$Venv = {_literal(data / '.venv')}
$Previous = {_literal(data / 'previous')}
$Staging = {_literal(data / '.staging')}
$LockDir = {_literal(data / '.install.lock')}
$InstallRoom = 0
$FinalEnvRoom = 0
$ConnectorChoices = @('none')
$script:gatewayChecks = 0
$script:cliChecks = 0
$script:migrations = 0
function Die([string]$Message) {{ throw $Message }}
function Stop-Usage([string]$Message) {{ throw $Message }}
function Get-OSArchitectureName {{ return 'X64' }}
function Get-InstalledVersion {{ return '{installed}' }}
function Find-SetupInstall {{ return $null }}
function Write-Step([string]$Message) {{}}
function Write-Ok([string]$Message) {{}}
function Confirm-Step {{ return $true }}
function Start-Transcript {{}}
function Wait-UninstallCleanup {{}}
function Resume-InterruptedRun {{}}
function Protect-UvDirectory {{}}
function Get-Cosign {{ return '' }}
function Assert-InstallRoom([long]$Bytes, [string]$Purpose) {{
    if ($Purpose -eq 'the final Python environment') {{ throw 'verified local target ready' }}
}}
function Get-NativeOutput([string]$Path, [string[]]$Arguments) {{
    if ($Path -like '*gateway.exe') {{ $script:gatewayChecks++ }}
    elseif ($Path -like '*defenseclaw.exe') {{ $script:cliChecks++ }}
    else {{ throw 'Unexpected runtime version check' }}
    return 'DefenseClaw {target}'
}}
function New-Venv([string]$Path, [string]$Purpose) {{
    New-Item -ItemType Directory -Path (Join-Path $Path 'Scripts') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $Path 'Scripts/defenseclaw.exe'), 'fixture CLI')
    return $true
}}
function Invoke-Native([string]$Path, [string[]]$Arguments) {{
    if ($Arguments[0] -ne 'migrate' -or $Arguments -notcontains '--check') {{ throw 'Unexpected runtime invocation' }}
    $script:migrations++
    return 0
}}
"""


def _local_assets(assets: Path, target: str) -> Path:
    assets.mkdir()
    archive = assets / f"defenseclaw-{target}-windows-amd64.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("defenseclaw-gateway.exe", b"fixture gateway; never executed")
    wheel = assets / f"defenseclaw-{target}-py3-none-any.whl"
    wheel.write_bytes(b"fixture wheel")
    requirements = assets / f"defenseclaw-{target}-requirements.txt"
    requirements.write_bytes(b"fixture requirements")
    (assets / "checksums.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in (archive, wheel, requirements)),
        encoding="ascii",
    )
    return wheel


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("case", ["verified", "missing", "mismatched", "tampered", "pending", "newer_target"])
def test_current_stamped_controller_verifies_explicit_older_local_assets_before_downgrade(tmp_path, case) -> None:
    data = tmp_path / "home"
    (data / "bin").mkdir(parents=True)
    (data / "bin" / "uv.exe").write_bytes(b"fixture UV; never executed")
    assets = tmp_path / "assets"
    target = "1.0.3" if case == "newer_target" else "1.0.1"
    wheel = _local_assets(assets, target)
    expected = "verified local target ready"
    if case == "missing":
        wheel.unlink()
        expected = "has no wheel for the requested DefenseClaw"
    elif case == "mismatched":
        wheel.rename(assets / "defenseclaw-1.0.0-py3-none-any.whl")
        expected = "has no wheel for the requested DefenseClaw"
    elif case == "tampered":
        wheel.write_bytes(b"tampered wheel")
        expected = "does not match checksums.txt"
    elif case == "pending":
        (data / ".defenseclaw-cas-v2-pending").write_bytes(b"pending recovery")
        expected = "active connector recovery"
    elif case == "newer_target":
        expected = "holds 1.0.2, not 1.0.3"
    _run(
        data,
        f"""
{_local_install_stubs(data, assets, target)}
try {{ Invoke-Install; throw 'installer unexpectedly proceeded' }} catch {{
    if ($_.Exception.Message -notlike '*{expected}*') {{ throw }}
}}
if ($script:gatewayChecks -ne {1 if case == 'verified' else 0} -or
    $script:cliChecks -ne {1 if case == 'verified' else 0} -or
    $script:migrations -ne {1 if case == 'verified' else 0}) {{
    throw 'Local target did not follow checksum, native, CLI and migration verification'
}}
""",
    )
    if case in ("missing", "mismatched", "pending", "newer_target"):
        assert not (data / ".staging").exists()
    if case == "pending":
        assert (data / ".defenseclaw-cas-v2-pending").read_bytes() == b"pending recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("phase", ["early", "watchdog"])
def test_forward_upgrade_refuses_active_recovery_before_a_snapshot_can_copy_it(tmp_path, phase) -> None:
    data = tmp_path / "home"
    (data / "bin").mkdir(parents=True)
    (data / "bin" / "uv.exe").write_bytes(b"fixture UV; never executed")
    assets = tmp_path / "assets"
    _local_assets(assets, "1.0.2")
    receipt = data / ".defenseclaw-cas-v2-forward.intent"
    if phase == "early":
        receipt.write_bytes(b"pending recovery")
    injection = "" if phase == "early" else (
        f"function Stop-Watchdog {{ [IO.File]::WriteAllText({_literal(receipt)}, 'pending recovery') }}"
    )
    _run(
        data,
        f"""
{_local_install_stubs(data, assets, '1.0.2', '1.0.1')}
$script:snapshots = 0
$script:starts = 0
$script:running = $true
function Assert-InstallRoom {{}}
function Get-UtcClock {{ return 'test-clock' }}
function Wait-VenvFree {{}}
function Get-GatewayProcess {{ return $script:running }}
function Get-ProcessesUnder {{ return @() }}
function Stop-Gateway {{ $script:running = $false; return $true }}
function Stop-Watchdog {{}}
function Restart-Old {{ $script:starts++; $script:running = $true }}
function Save-Snapshot {{ $script:snapshots++; throw 'regression: copied active recovery into previous' }}
function Write-Err([string]$Message) {{ throw $Message }}
{injection}
try {{ Invoke-Install; throw 'forward upgrade unexpectedly passed' }} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
if ($script:snapshots -ne 0) {{ throw 'Upgrade copied a receipt that the new gateway could consume only in live data' }}
if ($script:starts -ne {0 if phase == 'early' else 1}) {{ throw 'Wrong current runtime restart behavior' }}
""",
    )
    assert receipt.read_bytes() == b"pending recovery"
    assert not (data / "previous.new").exists()
    assert not (data / "previous").exists()
    assert (data / ".staging").exists() == (phase != "early")


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_snapshot_receipt_copy_would_block_rollback_after_live_recovery(tmp_path) -> None:
    receipt = tmp_path / ".defenseclaw-cas-v2-forward.intent"
    receipt.write_bytes(b"opaque recovery")
    _run(
        tmp_path,
        f"""
{_function('New-InstallDirectory')}
{_function('Save-Snapshot')}
$Previous = Join-Path $DataDir 'previous'
$Snap = $Previous
$PrevVersion = '1.0.1'
$WasRunning = $true
$Venv = Join-Path $DataDir '.venv'
$InstallerDir = Join-Path $DataDir 'installer'
$NotData = @('previous')
function Get-TreeSize {{ return 0 }}
function Copy-BinDir {{}}
function Save-ExternalConfig {{}}
function Copy-Kept([string]$Source, [string]$To) {{ Copy-Item -LiteralPath $Source -Destination $To }}
if (-not (Save-Snapshot)) {{ throw 'Fixture snapshot failed' }}
# Model the newer gateway finishing live recovery after an unguarded copy.
[IO.File]::Delete({_literal(receipt)})
Assert-NoActiveConnectorRecovery 'Current live state'
try {{
    Assert-NoActiveConnectorRecovery 'Rollback' (Join-Path $Previous 'data')
    throw 'Stale snapshot receipt was not recognized'
}} catch {{
    if ($_.Exception.Message -notlike '*active connector recovery*') {{ throw }}
}}
""",
    )
    assert not receipt.exists()
    assert (tmp_path / "previous" / "data" / receipt.name).read_bytes() == b"opaque recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("installed", ["1.0.1", "1.0.2"])
def test_clean_forward_install_and_active_same_version_repair_pass_preflight(tmp_path, installed) -> None:
    data = tmp_path / "home"
    (data / "bin").mkdir(parents=True)
    (data / "bin" / "uv.exe").write_bytes(b"fixture UV; never executed")
    assets = tmp_path / "assets"
    _local_assets(assets, "1.0.2")
    receipt = data / ".defenseclaw-cas-v2-repair.intent"
    if installed == "1.0.2":
        receipt.write_bytes(b"same protocol recovery")
    _run(
        data,
        f"""
{_local_install_stubs(data, assets, '1.0.2', installed)}
try {{ Invoke-Install; throw 'fixture ran past preflight' }} catch {{
    if ($_.Exception.Message -ne 'verified local target ready') {{ throw }}
}}
if ($script:gatewayChecks -ne 1 -or $script:cliChecks -ne 1 -or $script:migrations -ne 1) {{
    throw 'Permitted install did not finish verification'
}}
""",
    )
    if installed == "1.0.2":
        assert receipt.read_bytes() == b"same protocol recovery"


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_setup_cleanup_archives_opaque_receipts_with_file_identity_and_private_acl(recovery_dirs) -> None:
    data, failed, external, active = recovery_dirs
    receipt = ".defenseclaw-cas-v2-" + "b" * 24 + ".intent"
    names = [
        ".defenseclaw-cas-" + "c" * 24 + ".intent",
        ".defenseclaw-cas-" + "c" * 24 + ".intent.complete",
        receipt,
        receipt + ".allocation",
        receipt + ".prepared",
        receipt + ".terminal",
        receipt + ".complete",
        receipt + ".prepared.gc-" + "d" * 48,
        ".defenseclaw-cas-unrecognized-future-receipt",
        ".tmp-cas-receipt-publication",
    ]
    before = {}
    for index, name in enumerate(names):
        path = failed / "data" / name
        content = bytes([index, 0, 255]) + b"opaque evidence; never parse or replay"
        path.write_bytes(content)
        before[name] = (content, path.stat().st_ino)
    (data / ".uv").mkdir()
    (data / ".uv" / "cache.txt").write_bytes(b"discardable cache")

    output = _run(
        data,
        f"""
Clear-SetupDataDir {_literal(failed)}
$keep = @(Get-ChildItem -LiteralPath (Join-Path $DataDir 'backups') -Directory)[0].FullName
$acl = (New-Object IO.DirectoryInfo $keep).GetAccessControl()
$expected = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
if (-not $acl.AreAccessRulesProtected) {{ throw 'Recovery archive inherits its DACL' }}
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $expected[0]) {{ throw 'Wrong recovery archive owner' }}
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 2) {{ throw 'Unexpected recovery archive access rules' }}
foreach ($rule in $rules) {{
    if ($expected -notcontains $rule.IdentityReference.Value -or $rule.AccessControlType -ne 'Allow') {{
        throw 'Recovery archive grants unexpected access'
    }}
}}
""",
    )

    assert not failed.exists()
    assert not (data / ".uv").exists()
    archives = list((data / "backups").glob("connector-recovery-*"))
    assert len(archives) == 1
    archive = archives[0]
    assert {path.name for path in archive.iterdir()} == set(names) | {"README.txt"}
    for name, (content, identity) in before.items():
        path = archive / name
        assert path.read_bytes() == content
        assert path.stat().st_ino == identity
    note = (archive / "README.txt").read_text(encoding="utf-8")
    assert "not active recovery state" in note
    assert "Do not copy these receipts" in note
    assert "external agent settings may still need recovery" in output
    _assert_active_unchanged(external, active)


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_failed_cleanup_without_receipts_keeps_the_existing_small_cleanup(recovery_dirs) -> None:
    data, failed, external, active = recovery_dirs
    _run(data, f"Remove-FailedInstall {_literal(failed)}")
    assert not failed.exists()
    assert not (data / "backups").exists()
    _assert_active_unchanged(external, active)


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_an_archive_move_failure_keeps_all_evidence_and_the_failed_runtime(recovery_dirs) -> None:
    data, failed, external, active = recovery_dirs
    names = [".defenseclaw-cas-first.intent", ".defenseclaw-cas-second.intent"]
    for name in names:
        (failed / "data" / name).write_bytes(name.encode())
    output = _run(
        data,
        f"""
$script:moves = 0
function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) {{
    $script:moves++
    if ($script:moves -eq 2) {{ throw 'injected archive move failure' }}
    [IO.File]::Move($From, $To)
}}
try {{ Remove-FailedInstall {_literal(failed)}; throw 'cleanup unexpectedly succeeded' }} catch {{
    if ($_.Exception.Message -notlike '*injected archive move failure*') {{ throw }}
    Write-Output $_.Exception.Message
}}
""",
    )
    assert failed.exists()
    assert (failed / "venv" / "runtime.txt").read_bytes() == b"failed runtime"
    archives = list((data / "backups").glob("connector-recovery-*"))
    assert len(archives) == 1
    for name in names:
        locations = [path for path in (failed / "data" / name, archives[0] / name) if path.exists()]
        assert len(locations) == 1
        assert locations[0].read_bytes() == name.encode()
    assert "keep that archive and" in output
    _assert_active_unchanged(external, active)


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("junction", [False, True])
def test_nonregular_reserved_evidence_retains_the_tree_without_following_it(recovery_dirs, junction: bool) -> None:
    data, failed, external, active = recovery_dirs
    candidate = failed / "data" / ".defenseclaw-cas-unknown.intent"
    setup = ""
    if junction:
        setup = f"New-Item -ItemType Junction -Path {_literal(candidate)} -Target {_literal(external)} | Out-Null"
    else:
        candidate.mkdir()
        (candidate / "unknown.txt").write_bytes(b"do not discard unknown evidence")
    _run(
        data,
        f"""
{setup}
try {{ Remove-FailedInstall {_literal(failed)}; throw 'cleanup unexpectedly succeeded' }} catch {{
    if ($_.Exception.Message -notlike '*not a regular file*') {{ throw }}
}}
""",
    )
    assert failed.exists()
    assert candidate.exists()
    assert not (data / "backups").exists()
    if not junction:
        assert (candidate / "unknown.txt").read_bytes() == b"do not discard unknown evidence"
    _assert_active_unchanged(external, active)


def test_every_automatic_failed_tree_removal_preserves_receipts_first() -> None:
    clear = _function("Clear-SetupDataDir")
    assert "Remove-FailedInstall $Failed" in clear
    restore = _function("Restore-Snapshot")
    assert "Remove-FailedInstall $failed" in restore
    resume = _function("Resume-InterruptedRun")
    assert "Remove-FailedInstall $failed" in resume
    slot = _function("Restore-Slot")
    assert "Remove-FailedInstall $old.FullName" in slot
    assert "Remove-Tree $old.FullName" not in slot
    cleanup = _function("Remove-FailedInstall")
    assert cleanup.index("Save-FailedConnectorRecovery $Failed") < cleanup.index("Remove-Tree $Failed")
    # Both strict receipt directions precede all live runtime/data exchange.
    phase = slot.index("Move-RestoreConnectorRecovery $Slot $failed")
    assert phase < slot.index("Restore-BinDir") < slot.index("foreach ($part")
    assert slot.count("-not (Test-ConnectorRecoveryArtifactName $_.Name)") == 2
    receipts = _function("Move-RestoreConnectorRecovery")
    assert "Remove-Tree" not in receipts
    assert "Move-Path $entry.To $entry.From" in receipts


def _restore_stubs(data: Path, slot: Path) -> str:
    return f"""
$Venv = {_literal(data / '.venv')}
$InstallerDir = {_literal(data / 'installer')}
$NotData = @('.venv', 'installer', 'backups', 'previous.new', '.failed-*')
function Restore-BinDir([string]$From) {{}}
function Restore-ExternalConfig([string]$Slot) {{}}
"""


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
def test_same_second_restore_never_reuses_a_failed_tree_retained_after_archive_failure(recovery_dirs) -> None:
    data, failed, external, active = recovery_dirs
    retained = data / ".failed-20000101T000000"
    (retained / "data").mkdir(parents=True)
    evidence = retained / "data" / ".defenseclaw-cas-retained.intent"
    evidence.write_bytes(b"only retained evidence")
    identity = evidence.stat().st_ino
    slot = data / "previous.new"
    (slot / "data").mkdir(parents=True)
    (slot / "data" / "config.yaml").write_bytes(b"restored configuration")
    _run(
        data,
        f"""
{_restore_stubs(data, slot)}
function Get-Date([string]$Format) {{ return '20000101T000000' }}
function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) {{
    if ($From -eq {_literal(evidence)}) {{ throw 'injected retention failure' }}
    if (Test-Path -LiteralPath $From -PathType Container) {{ [IO.Directory]::Move($From, $To) }}
    else {{ [IO.File]::Move($From, $To) }}
}}
$fresh = Restore-Slot {_literal(slot)}
if ($fresh -eq {_literal(retained)}) {{ throw 'Reused retained failure directory' }}
if (-not (Test-Path -LiteralPath $fresh -PathType Container)) {{ throw 'New failed copy missing' }}
""",
    )
    assert evidence.read_bytes() == b"only retained evidence"
    assert evidence.stat().st_ino == identity
    assert not slot.exists()
    assert (data / "config.yaml").read_bytes() == b"restored configuration"
    fresh = [path for path in data.glob(".failed-20000101T000000-*") if path != retained]
    assert len(fresh) == 1
    assert (fresh[0] / "data" / active.name).read_bytes() == b"restored active receipt"
    assert (external / "settings.json").read_bytes() == b'{"unchanged":"external"}'


@WINDOWS_POWERSHELL
@pytest.mark.allow_subprocess
@pytest.mark.parametrize("direction", ["live", "prior"])
def test_receipt_move_failure_keeps_the_exact_receipt_and_marked_rollback_slot(recovery_dirs, direction: str) -> None:
    data, failed, external, active = recovery_dirs
    slot = data / "previous.new"
    (slot / "data").mkdir(parents=True)
    marker = slot / "COMPLETE"
    marker.write_bytes(b"complete snapshot")
    # The two generations may use the same deterministic receipt filename.
    prior = slot / "data" / active.name
    prior.write_bytes(b"prior receipt")
    (data / ".venv").mkdir()
    (data / ".venv" / "runtime.txt").write_bytes(b"current runtime")
    (slot / "venv").mkdir()
    (slot / "venv" / "runtime.txt").write_bytes(b"prior runtime")
    (data / "config.yaml").write_bytes(b"current config")
    (slot / "data" / "config.yaml").write_bytes(b"prior config")
    blocked = active if direction == "live" else prior
    contents = blocked.read_bytes()
    identity = blocked.stat().st_ino
    _run(
        data,
        f"""
{_restore_stubs(data, slot)}
$script:binRestores = 0
function Restore-BinDir([string]$From) {{ $script:binRestores++ }}
function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) {{
    if ($From -eq {_literal(blocked)}) {{ throw 'injected receipt move failure' }}
    if (Test-Path -LiteralPath $From -PathType Container) {{ [IO.Directory]::Move($From, $To) }}
    else {{ [IO.File]::Move($From, $To) }}
}}
try {{ Restore-Slot {_literal(slot)}; throw 'restore unexpectedly succeeded' }} catch {{
    if ($_.Exception.Message -notlike '*injected receipt move failure*') {{ throw }}
}}
if ($script:binRestores -ne 0) {{ throw 'Live binaries changed before receipt refusal' }}
""",
    )
    assert blocked.read_bytes() == contents
    assert blocked.stat().st_ino == identity
    assert marker.read_bytes() == b"complete snapshot"
    assert prior.read_bytes() == b"prior receipt"
    assert active.read_bytes() == b"restored active receipt"
    assert (data / ".venv" / "runtime.txt").read_bytes() == b"current runtime"
    assert (slot / "venv" / "runtime.txt").read_bytes() == b"prior runtime"
    assert (data / "config.yaml").read_bytes() == b"current config"
    assert (slot / "data" / "config.yaml").read_bytes() == b"prior config"
    # A clean retry applies the snapshot exactly once. In particular, the
    # ordinary-data loop must not move the just-restored receipt away again.
    _run(data, f"{_restore_stubs(data, slot)}\nRestore-Slot {_literal(slot)} | Out-Null")
    assert not slot.exists()
    assert (data / ".venv" / "runtime.txt").read_bytes() == b"prior runtime"
    assert (data / "config.yaml").read_bytes() == b"prior config"
    assert active.read_bytes() == b"prior receipt"
    copies = list(data.glob(".failed-*"))
    assert len(copies) == 1
    assert (copies[0] / "venv" / "runtime.txt").read_bytes() == b"current runtime"
    assert (copies[0] / "data" / "config.yaml").read_bytes() == b"current config"
    assert (copies[0] / "data" / active.name).read_bytes() == b"restored active receipt"
    assert (external / "settings.json").read_bytes() == b'{"unchanged":"external"}'
