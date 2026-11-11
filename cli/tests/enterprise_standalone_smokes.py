"""The standalone PowerShell smokes and the runner Windows CI uses for them.

Each smoke runs in a disposable scratch directory and never touches a service or a
real machine root, so Windows CI runs every one of them on each installed engine
(Windows PowerShell 5.1 and 7). They run from three test files (the groups below) so the
Python shards can carry them apart from the contract checks of
test_windows_enterprise_standalone_contract.py; together they are every smoke, on
both engines.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE_DIR = ROOT / "packaging" / "windows" / "tests"

STANDALONE_SMOKES = (
    "enterprise-profile-lifecycle-lock-smoke.ps1",
    "enterprise-profile-deployment-record-smoke.ps1",
    "enterprise-standalone-claude-policy-binding-smoke.ps1",
    "enterprise-standalone-codex-vendor-folder-smoke.ps1",
    "enterprise-standalone-config-acl-repair-smoke.ps1",
    "enterprise-standalone-held-file-restamp-smoke.ps1",
    "enterprise-standalone-codex-writer-stuck-smoke.ps1",
    "enterprise-standalone-cowork-delivery-smoke.ps1",
    "enterprise-standalone-enumerator-environment-smoke.ps1",
    "enterprise-standalone-forced-uninstall-residue-smoke.ps1",
    "enterprise-standalone-guardian-first-reconcile-wait-smoke.ps1",
    "enterprise-standalone-guardian-readiness-older-gateway-smoke.ps1",
    "enterprise-standalone-guardian-state-held-smoke.ps1",
    "enterprise-standalone-guardian-state-identity-smoke.ps1",
    "enterprise-standalone-hook-keep-smoke.ps1",
    "enterprise-standalone-hook-swap-launch-smoke.ps1",
    "enterprise-standalone-install-tree-smoke.ps1",
    "enterprise-standalone-machine-leftovers-purge-smoke.ps1",
    "enterprise-standalone-manifest-adoption-smoke.ps1",
    "enterprise-standalone-mdm-rotation-journal-smoke.ps1",
    "enterprise-standalone-native-otlp-rollback-smoke.ps1",
    "enterprise-standalone-pretransaction-bundle-classification-smoke.ps1",
    "enterprise-standalone-recorded-trust-smoke.ps1",
    "enterprise-standalone-recovery-activation-deferral-smoke.ps1",
    "enterprise-standalone-recovery-gateway-smoke.ps1",
    "enterprise-standalone-rollback-sensor-helper-smoke.ps1",
    "enterprise-standalone-root-squat-smoke.ps1",
    "enterprise-standalone-runtime-env-acl-smoke.ps1",
    "enterprise-standalone-w2b-lifecycle-smoke.ps1",
    "enterprise-standalone-secrets-acl-smoke.ps1",
    "enterprise-standalone-service-logged-error-smoke.ps1",
    "enterprise-standalone-stale-lifecycle-journal-smoke.ps1",
    "enterprise-standalone-state-files-in-use-smoke.ps1",
    "enterprise-standalone-uninstall-hook-commit-smoke.ps1",
    "enterprise-standalone-uninstall-lifecycle-lock-smoke.ps1",
    "enterprise-standalone-purge-bundle-lock-smoke.ps1",
    "enterprise-standalone-uninstall-cleanup-trust-smoke.ps1",
    "enterprise-standalone-user-cleanup-report-smoke.ps1",
)

# The three groups, balanced by the run time on the Windows CI runners (about 930 s for all
# of them on both engines, measured from the JUnit of a full run): held-file-restamp and
# the w2b lifecycle smoke; the install-tree, state-files-in-use and guardian first-reconcile
# smokes; everything else.
SMOKES_A = (
    "enterprise-standalone-held-file-restamp-smoke.ps1",
    "enterprise-standalone-w2b-lifecycle-smoke.ps1",
)
SMOKES_B = (
    "enterprise-standalone-install-tree-smoke.ps1",
    "enterprise-standalone-state-files-in-use-smoke.ps1",
    "enterprise-standalone-guardian-first-reconcile-wait-smoke.ps1",
)
SMOKES_C = tuple(name for name in STANDALONE_SMOKES if name not in SMOKES_A and name not in SMOKES_B)


def standalone_smoke_engines() -> list[str]:
    if sys.platform != "win32":
        return []
    import winreg

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as current_version:
        program_files_raw, _ = winreg.QueryValueEx(current_version, "ProgramFilesDir")
    candidates = (
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(str(program_files_raw)) / "PowerShell" / "7" / "pwsh.exe",
    )
    return [str(path) for path in candidates if path.is_file()]


def engine_id(engine: str | None) -> str:
    return Path(engine).stem if engine else "missing"


def run_standalone_smoke(engine: str | None, smoke: str) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    script = SMOKE_DIR / smoke
    if "#Requires -Version 7" in script.read_text(encoding="utf-8-sig") and Path(engine).stem.lower() != "pwsh":
        pytest.skip(f"{smoke} requires PowerShell 7")
    # Each smoke creates, and removes, its own uniquely named scratch tree
    # under the engine's temporary directory. Keep that prefix short: the IPC
    # smoke binds AF_UNIX sockets, whose paths are limited to 108 characters.
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, (
        f"{smoke} failed under {engine}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    marker = smoke.removesuffix(".ps1")
    if f"{marker}: SKIP" in completed.stdout:
        pytest.skip(completed.stdout.strip())
    assert f"{marker}: OK" in completed.stdout
