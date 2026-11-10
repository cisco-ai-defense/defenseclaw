# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1048 / GAP-1049: Setup keeps the replaced config.yaml and targets.yaml
when it restores them from its approved copies, and never re-stamps an
untrusted targets.yaml in place.

The smoke has its own file because the standalone smoke shard is at its time
budget (scripts/test-timings/python-windows.json carries this file's timing).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-policy-rejected-copy-smoke.ps1"
STANDALONE_GO = ROOT / "internal" / "cli" / "windows_enterprise_standalone.go"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _function(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.index("\nfunction ", start + 1)
    return source[start:end]


def test_every_approved_policy_restore_keeps_the_replaced_file_first() -> None:
    recovery = _function(_text(MODULE), "Invoke-DefenseClawRepairApprovedPolicyRecovery")
    installs = [m.start() for m in re.finditer(r"Install-DefenseClawSourceDescriptor -Source \$(approved|handEditApproved)\b", recovery)]
    saves = [m.start() for m in re.finditer(r"Save-DefenseClawRejectedStandalonePolicy\b", recovery)]
    assert len(installs) == 2, "the recovery restores from an approved copy in exactly two places"
    assert len(saves) == 2
    for install in installs:
        assert any(save < install and install - save < 400 for save in saves), (
            "an approved copy replaces config.yaml or targets.yaml without keeping the replaced file first"
        )


def test_the_kept_file_is_administrator_only_and_reported() -> None:
    helper = _function(_text(MODULE), "Save-DefenseClawRejectedStandalonePolicy")
    assert "Set-DefenseClawPathAcl -Path $kept -Kind AdminFile" in helper
    # The note and the event follow the restore, never precede it.
    assert "Write-DefenseClawResilienceEvent" not in helper
    reporter = _function(_text(MODULE), "Add-DefenseClawRestoredPolicyNote")
    assert "Write-DefenseClawResilienceEvent -Marker defenseclaw_repair" in reporter
    assert "$script:DefenseClawRestoredPolicyNotes +=" in reporter
    recovery = _function(_text(MODULE), "Invoke-DefenseClawRepairApprovedPolicyRecovery")
    assert recovery.count("Add-DefenseClawRestoredPolicyNote -Kept $keptPolicy") == 2
    module = _text(MODULE)
    assert module.count("$script:DefenseClawRestoredPolicyNotes = @()") == 2
    assert "$status['restored_policy_sources']" in module
    go = _text(STANDALONE_GO)
    assert 'json:"restored_policy_sources"' in go
    assert "addWindowsEnterpriseRestoredPolicyChanges(result, report)" in go


def test_setup_process_reads_of_the_manifest_never_restamp_it() -> None:
    policy = _text(ROOT / "internal" / "cli" / "enterprise_policy_platform_windows.go")
    body = policy[policy.index("func standaloneClaudeMachineHookContract") :]
    body = body[: body.index("\n}\n")]
    assert body.index("pinWindowsStandaloneTrustScope()") < body.index("enterpriseHookManifestFileTrustCheck(path)")
    repair = _text(ROOT / "internal" / "cli" / "enterprise_hooks_protected_file_windows.go")
    body = repair[repair.index("func repairEnterpriseHookManifestACL") :]
    body = body[: body.index("\n}\n")]
    assert body.index("pinWindowsStandaloneTrustScope()") < body.index("managed.RefuseStandaloneInPlaceRepair")
    assert body.index("managed.RefuseStandaloneInPlaceRepair") < body.index("ProtectWindowsManagedRuntimeAdminFile(path)")
    hot = _text(ROOT / "internal" / "cli" / "windows_enterprise_hot_config.go")
    record = hot[hot.index("var windowsEnterpriseHotConfigTargetsRecord") :]
    record = record[: record.index("\n}\n")]
    assert record.index("managed.StandaloneFileLeafDrift") < record.index("enterprisehooks.LoadManifest")
    assert record.index("pinWindowsStandaloneTrustScope()") < record.index("WriteTargetsManifestAtomic")


def _engines() -> list[str]:
    found = [shutil.which("pwsh"), shutil.which("powershell.exe")]
    return [engine for engine in found if engine]


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("engine", _engines() or (None,), ids=lambda engine: Path(engine).stem if engine else "missing")
def test_rejected_policy_smoke_runs(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SMOKE)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "enterprise-policy-rejected-copy-smoke: OK" in completed.stdout
