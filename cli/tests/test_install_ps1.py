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

import os
import re
import shutil
import subprocess
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


def _text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


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
    written = set(_list("ManagedBinaries")) | {f"{shim}.cmd" for shim in _list("ManagedShims")}
    _root, targets = cmd_uninstall._owned_binary_targets("win32")
    assert written == {re.split(r"[\\/]", target)[-1] for target in targets}
    assert written == windows_uninstall_helper._ALLOWED_BINARIES


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
