# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Source contract for the Windows-only hot-config undo safety boundary.

The native Windows suite exercises the state and failure paths. This check
also runs on Linux CI, where the Windows package can only be compiled.
"""

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")


def test_unproven_undo_closes_managed_hooks_before_stopping_gateway() -> None:
    source = (ROOT / "internal/cli/windows_enterprise_hot_config.go").read_text(encoding="utf-8")
    undo = source.split("undo := func() {", 1)[1].split("if err := windowsEnterpriseHotConfigWrite", 1)[0]
    assert undo.index("windowsEnterpriseHotConfigCloseHooks(layout)") < undo.index(
        "windowsEnterpriseHotConfigFailClosed()"
    )


def test_standalone_hook_checks_durable_closure_before_accepting_open() -> None:
    source = (ROOT / "internal/cli/hook_trusted_state_windows.go").read_text(encoding="utf-8")
    prepare = source.split("func prepareEnterpriseManagedHookRuntime", 1)[1].split(
        "func validEnterpriseManagedRuntimeGenerationID", 1
    )[0]
    assert "windowsStandaloneHooksHeldClosed()" in prepare


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_purge_keeps_closed_marker_until_the_hook_runtime_is_empty(tmp_path: Path) -> None:
    module = (ROOT / "packaging/windows/DefenseClawEnterprise.psm1").read_text(encoding="utf-8")
    function = module.split("function Remove-DefenseClawStandaloneHookRuntimeLeftovers {", 1)[1]
    function = "function Remove-DefenseClawStandaloneHookRuntimeLeftovers {" + function.split("\n}\n", 1)[0] + "\n}\n"
    root = tmp_path / "hook-runtime"
    root.mkdir()
    (root / "machine-policy.json").write_text("summary", encoding="ascii")
    (root / ".defenseclaw-hot-config-undo-closed").write_text("hot-config-undo-unproven-v1\n", encoding="ascii")
    (root / "codex").mkdir()
    script = f"""
$ErrorActionPreference = 'Stop'
function Test-DefenseClawStandaloneProfile {{ return $true }}
function Remove-DefenseClawManagedHooksSerializationLock {{ param($Path, $Label)
    if (Test-Path -LiteralPath $Path) {{ Remove-Item -LiteralPath $Path -Force }}
}}
{function}
$root = '{str(root).replace("'", "''")}'
$first = @(Remove-DefenseClawStandaloneHookRuntimeLeftovers -Directory $root)
if (-not (Test-Path -LiteralPath (Join-Path $root '.defenseclaw-hot-config-undo-closed'))) {{ throw 'purge opened hooks while a runtime remained' }}
if ($first.Count -ne 1) {{ throw 'incomplete purge did not report the kept runtime' }}
Remove-Item -LiteralPath (Join-Path $root 'codex')
$second = @(Remove-DefenseClawStandaloneHookRuntimeLeftovers -Directory $root)
if ($second.Count -ne 0 -or (Test-Path -LiteralPath $root)) {{ throw 'completed purge kept the closure or runtime root' }}
'OK'
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr
