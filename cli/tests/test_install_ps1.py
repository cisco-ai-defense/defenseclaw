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


def _ps_quote(path: Path) -> str:
    return str(path).replace("'", "''")


def _extract_powershell_function(name: str) -> str:
    return rf"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{_ps_quote(INSTALL_PS1)}', [ref]$tokens, [ref]$errors
)
$fn = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq '{name}'
}}, $true)
if ($null -eq $fn) {{ throw 'Function {name} not found' }}
Invoke-Expression $fn.Extent.Text
"""


def test_all_uv_calls_use_explicit_exit_status_wrapper() -> None:
    text = INSTALL_PS1.read_text()

    assert "function Invoke-Uv" in text
    assert "& uv python install" not in text
    assert "& uv venv" not in text
    assert "& uv pip install" not in text
    assert 'Invoke-Uv -Arguments @("python", "install", "3.12")' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv, "--allow-existing", "--quiet")' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv, "--clear"' not in text
    assert 'Invoke-Uv -Arguments @("pip", "install"' in text


def test_windows_installer_offers_only_native_connector_surface() -> None:
    text = INSTALL_PS1.read_text()

    choices_block = text.split("$ConnectorChoices = @(", 1)[1].split(")", 1)[0]
    choices = set(re.findall(r'"([a-z]+)"', choices_block))
    assert choices == WINDOWS_SUPPORTED_CONNECTORS | WINDOWS_PREVIEW_CONNECTORS | {"none"}

    assert "Hermes native hooks (preview)" in text
    assert "Cursor IDE native hooks (CLI remains WSL-only)" in text
    assert "function Install-OpenClaw" not in text


def test_windows_installer_requires_and_installs_no_console_hook_launcher() -> None:
    text = INSTALL_PS1.read_text()

    assert 'Join-Path $tmp "defenseclaw-hook.exe"' in text
    assert 'Die "defenseclaw-hook.exe missing from archive"' in text
    assert 'Join-Path $InstallDir "defenseclaw-hook.exe"' in text


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows command resolution")
def test_windows_launcher_removes_exe_shadow_and_publishes_managed_cmd(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    install_dir = tmp_path / ".local" / "bin"
    cli_exe = tmp_path / ".defenseclaw" / ".venv" / "Scripts" / "defenseclaw.exe"
    install_dir.mkdir(parents=True)
    cli_exe.parent.mkdir(parents=True)
    cli_exe.write_text("managed test launcher; never executed")
    (install_dir / "defenseclaw.exe").write_text("untrusted test launcher; never executed")
    (install_dir / "defenseclaw.cmd").write_text("@exit /b 99\r\n")

    command = _extract_powershell_function("Publish-CliLauncher") + rf"""
$env:PATH = '{_ps_quote(install_dir)}'
$env:PATHEXT = '.EXE;.CMD'
$before = (Get-Command defenseclaw -CommandType Application).Source
$null = Publish-CliLauncher -CliExe '{_ps_quote(cli_exe)}' -InstallDir '{_ps_quote(install_dir)}'
$after = (Get-Command defenseclaw -CommandType Application).Source
Write-Output "BEFORE=$before"
Write-Output "AFTER=$after"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"BEFORE={install_dir / 'defenseclaw.exe'}" in completed.stdout
    assert f"AFTER={install_dir / 'defenseclaw.cmd'}" in completed.stdout
    assert not (install_dir / "defenseclaw.exe").exists()
    assert str(cli_exe) in (install_dir / "defenseclaw.cmd").read_text(encoding="ascii")


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_windows_launcher_fails_when_exe_shadow_cannot_be_removed(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    install_dir = tmp_path / ".local" / "bin"
    cli_exe = tmp_path / ".defenseclaw" / ".venv" / "Scripts" / "defenseclaw.exe"
    shadow = install_dir / "defenseclaw.exe"
    shim = install_dir / "defenseclaw.cmd"
    install_dir.mkdir(parents=True)
    cli_exe.parent.mkdir(parents=True)
    cli_exe.write_text("managed test launcher; never executed")
    shadow.write_text("untrusted test launcher; never executed")
    shim.write_text("existing shim")

    command = _extract_powershell_function("Publish-CliLauncher") + rf"""
function Remove-Item {{
    param([string]$LiteralPath, [switch]$Force, [object]$ErrorAction)
    if ($LiteralPath -eq '{_ps_quote(shadow)}') {{ throw 'launcher is locked' }}
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force -ErrorAction $ErrorAction
}}
$null = Publish-CliLauncher -CliExe '{_ps_quote(cli_exe)}' -InstallDir '{_ps_quote(install_dir)}'
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert "Cannot remove shadowing CLI launcher" in completed.stderr
    assert shadow.exists()
    assert shim.read_text() == "existing shim"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_windows_launcher_is_idempotent_without_exe_shadow(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    install_dir = tmp_path / ".local" / "bin"
    cli_exe = tmp_path / ".defenseclaw" / ".venv" / "Scripts" / "defenseclaw.exe"
    install_dir.mkdir(parents=True)
    cli_exe.parent.mkdir(parents=True)
    cli_exe.write_text("managed test launcher; never executed")

    command = _extract_powershell_function("Publish-CliLauncher") + rf"""
$null = Publish-CliLauncher -CliExe '{_ps_quote(cli_exe)}' -InstallDir '{_ps_quote(install_dir)}'
$null = Publish-CliLauncher -CliExe '{_ps_quote(cli_exe)}' -InstallDir '{_ps_quote(install_dir)}'
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert (install_dir / "defenseclaw.cmd").is_file()
    assert not (install_dir / "defenseclaw.exe").exists()


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
