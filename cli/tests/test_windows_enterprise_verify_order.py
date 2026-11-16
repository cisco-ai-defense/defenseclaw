# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1061: /verify names an untrusted account on targets.yaml before it says
to wait for the guardian. Own file: the standalone smoke shard is at its budget."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-policy-verify-order-smoke.ps1"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _function(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    return source[start : source.index("\nfunction ", start + 1)]


def test_the_binding_refusal_names_the_untrusted_account_first() -> None:
    module = _text(MODULE)
    deployment = _function(module, "Assert-DefenseClawEnterpriseDeployment")
    check = deployment.index("Assert-DefenseClawManifestNotUntrustedBeforeBinding -Layout $Layout")
    adoption = deployment.index("Get-DefenseClawStandaloneManifestAdoption")
    refusal = deployment.index("activation evidence does not bind installed targets.yaml")
    assert check < adoption < refusal
    helper = _function(module, "Assert-DefenseClawManifestNotUntrustedBeforeBinding")
    assert "Test-DefenseClawStandaloneProfile" in helper
    assert "guardian" not in helper.split("#>", 1)[1]
    # No other /verify path throws the binding text without that check first.
    for name in ("Get-DefenseClawStandaloneManifestAdoption",):
        assert "does not bind installed targets.yaml" not in _function(module, name)


def _engines() -> list[str]:
    return [engine for engine in (shutil.which("pwsh"), shutil.which("powershell.exe")) if engine]


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("engine", _engines() or (None,), ids=lambda engine: Path(engine).stem if engine else "missing")
def test_verify_order_smoke_runs(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SMOKE)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "enterprise-policy-verify-order-smoke: OK" in completed.stdout
