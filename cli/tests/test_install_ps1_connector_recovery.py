# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Failed installer cleanup must keep evidence of external connector writes."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
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
        "Restore-Slot",
        "Clear-SetupDataDir",
        "Invoke-Quietly",
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
    result = subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
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
    # Receipt moves out of active state cannot use the ordinary catch/delete
    # fallback; a failed move leaves the rollback slot and evidence intact.
    start = slot.index("if (Test-ConnectorRecoveryArtifactName $entry.Name)")
    receipt_move = slot[start : slot.index("} else {", start)]
    assert "Move-Path $entry.FullName" in receipt_move
    assert "Remove-Tree" not in receipt_move


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
    prior = slot / "data" / ".defenseclaw-cas-prior.intent"
    prior.write_bytes(b"prior receipt")
    blocked = active if direction == "live" else prior
    contents = blocked.read_bytes()
    identity = blocked.stat().st_ino
    _run(
        data,
        f"""
{_restore_stubs(data, slot)}
function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) {{
    if ($From -eq {_literal(blocked)}) {{ throw 'injected receipt move failure' }}
    if (Test-Path -LiteralPath $From -PathType Container) {{ [IO.Directory]::Move($From, $To) }}
    else {{ [IO.File]::Move($From, $To) }}
}}
try {{ Restore-Slot {_literal(slot)}; throw 'restore unexpectedly succeeded' }} catch {{
    if ($_.Exception.Message -notlike '*injected receipt move failure*') {{ throw }}
}}
""",
    )
    assert blocked.read_bytes() == contents
    assert blocked.stat().st_ino == identity
    assert marker.read_bytes() == b"complete snapshot"
    assert prior.read_bytes() == b"prior receipt"
    assert (external / "settings.json").read_bytes() == b'{"unchanged":"external"}'
