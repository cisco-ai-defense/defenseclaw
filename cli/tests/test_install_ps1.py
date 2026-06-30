# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Windows PowerShell regression tests for ``scripts/install.ps1``."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw.platform_support import (
    WINDOWS_PREVIEW_CONNECTORS,
    WINDOWS_SUPPORTED_CONNECTORS,
)

ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"


def test_all_uv_calls_use_explicit_exit_status_wrapper() -> None:
    text = INSTALL_PS1.read_text()

    assert "function Invoke-Uv" in text
    assert "& uv python install" not in text
    assert "& uv venv" not in text
    assert "& uv pip install" not in text
    assert 'Invoke-Uv -Arguments @("python", "install", "3.12")' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv' in text
    assert 'Invoke-Uv -Arguments @("pip", "install"' in text


def test_windows_installer_offers_only_native_connector_surface() -> None:
    text = INSTALL_PS1.read_text()

    choices_block = text.split("$ConnectorChoices = @(", 1)[1].split(")", 1)[0]
    choices = set(re.findall(r'"([a-z]+)"', choices_block))
    assert choices == WINDOWS_SUPPORTED_CONNECTORS | WINDOWS_PREVIEW_CONNECTORS | {"none"}

    assert "Hermes native hooks (preview)" in text
    assert "Cursor IDE native hooks (CLI remains WSL-only)" in text
    assert "function Install-OpenClaw" not in text


@pytest.mark.skipif(os.name != "nt", reason="requires Windows PowerShell native stderr semantics")
@pytest.mark.parametrize(
    ("native_exit", "expected"),
    [(0, "RESULT=continued native_exit=0"), (7, "RESULT=failed native_exit=7")],
)
def test_powershell_51_uses_uv_exit_status(tmp_path: Path, native_exit: int, expected: str) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    fake_uv = tmp_path / "uv.cmd"
    fake_uv.write_text(
        f"@echo uv diagnostic on stderr 1>&2\r\n@exit /b {native_exit}\r\n",
        encoding="ascii",
    )
    command = rf"""
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    "{INSTALL_PS1}", [ref]$tokens, [ref]$errors
)
foreach ($name in @("Invoke-Uv", "Ensure-Python")) {{
    $fn = $ast.Find({{
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }}, $true)
    Invoke-Expression $fn.Extent.Text
}}
function Write-Step {{ param([string]$Message) }}
function Write-Ok {{ param([string]$Message) }}
function Die {{ param([string]$Message) throw $Message }}
try {{
    Ensure-Python
    Write-Output "RESULT=continued native_exit=$LASTEXITCODE"
}} catch {{
    Write-Output "RESULT=failed native_exit=$LASTEXITCODE"
}}
"""
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}{os.pathsep}{env.get('PATH', '')}"

    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )

    assert completed.returncode == 0, completed.stderr
    assert expected in completed.stdout
