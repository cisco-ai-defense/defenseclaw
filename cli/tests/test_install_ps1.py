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
import textwrap
import zipfile
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


def _fixture_wheel(
    directory: Path,
    distribution: str,
    version: str,
    package_files: dict[str, str],
    *,
    dependencies: tuple[str, ...] = (),
    scripts: dict[str, str] | None = None,
) -> Path:
    wheel_name = distribution.replace("-", "_")
    wheel = directory / f"{wheel_name}-{version}-py3-none-any.whl"
    dist_info = f"{wheel_name}-{version}.dist-info"
    members = dict(package_files)
    requires = "".join(f"Requires-Dist: {dependency}\n" for dependency in dependencies)
    members[f"{dist_info}/METADATA"] = (
        "Metadata-Version: 2.1\n"
        f"Name: {distribution}\n"
        f"Version: {version}\n"
        f"{requires}\n"
    )
    members[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: defenseclaw-test\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )
    if scripts:
        entries = "".join(f"{name} = {target}\n" for name, target in scripts.items())
        members[f"{dist_info}/entry_points.txt"] = f"[console_scripts]\n{entries}"
    members[f"{dist_info}/RECORD"] = "".join(f"{name},,\n" for name in members)

    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)
    return wheel


def test_all_uv_calls_use_explicit_exit_status_wrapper() -> None:
    text = INSTALL_PS1.read_text()

    assert "function Invoke-Uv" in text
    assert "& uv --no-config @Arguments" in text
    assert "& uv python install" not in text
    assert "& uv venv" not in text
    assert "& uv pip install" not in text
    assert 'Invoke-Uv -Arguments @("python", "install", "3.12")' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv, "--allow-existing", "--quiet")' in text
    assert 'Invoke-Uv -Arguments @("venv", $Venv, "--clear"' not in text
    assert '"pip", "install", "--python", $venvPython, "--quiet"' in text
    assert '"--reinstall", "--no-cache", "--strict", $whlPath' in text


def test_cli_smoke_precedes_launcher_publication() -> None:
    text = INSTALL_PS1.read_text()
    install_cli = text.split("function Install-Cli", 1)[1].split("function Select-Connector", 1)[0]

    assert install_cli.index("Test-ManagedCli") < install_cli.index("Publish-CliLauncher")
    assert install_cli.index("Publish-CliLauncher") < install_cli.index('Write-Ok "CLI installed')
    assert 'set `"PYTHONPATH=`"' in text
    assert 'set `"PYTHONHOME=`"' in text
    assert "setlocal" in text
    assert "endlocal & exit /b %defenseclawExit%" in text


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


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_managed_command_sanitizes_and_restores_python_environment(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    child = tmp_path / "show-python-env.cmd"
    child.write_text(
        "@echo PYTHONPATH=[%PYTHONPATH%]\r\n"
        "@echo PYTHONHOME=[%PYTHONHOME%]\r\n"
        "@exit /b 7\r\n",
        encoding="ascii",
    )
    command = _extract_powershell_function("Invoke-ManagedCommand") + rf"""
$env:PYTHONPATH = 'parent-path'
$env:PYTHONHOME = 'parent-home'
$result = Invoke-ManagedCommand -Executable '{_ps_quote(child)}'
Write-Output "EXIT=$($result.ExitCode)"
$result.Output | ForEach-Object {{ Write-Output "CHILD=$_" }}
Write-Output "PARENT_PATH=$env:PYTHONPATH"
Write-Output "PARENT_HOME=$env:PYTHONHOME"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "EXIT=7" in completed.stdout
    assert "CHILD=PYTHONPATH=[]" in completed.stdout
    assert "CHILD=PYTHONHOME=[]" in completed.stdout
    assert "PARENT_PATH=parent-path" in completed.stdout
    assert "PARENT_HOME=parent-home" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell and uv")
def test_same_version_reinstall_repairs_managed_venv_and_ignores_checkout_pythonpath(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe")
    uv = shutil.which("uv.exe") or shutil.which("uv")
    if not powershell or not uv:
        pytest.skip("Windows PowerShell and uv are required")

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    dependency_wheel = _fixture_wheel(
        fixtures,
        "dc-certifi-fixture",
        "1.0.0",
        {"certifi_fixture/__init__.py": "def where():\n    return 'fixture-ca.pem'\n"},
    )
    cli_source = textwrap.dedent(
        """
        import shutil
        import sys
        from pathlib import Path

        from certifi_fixture import where


        def scanner():
            print("scanner fixture")
            return 0


        def main():
            where()
            if "--version" in sys.argv:
                print("defenseclaw 1.0.0")
                return 0
            if len(sys.argv) > 1 and sys.argv[1] == "doctor":
                scripts = Path(sys.executable).resolve().parent
                for name in ("skill-scanner", "mcp-scanner"):
                    resolved = shutil.which(name, path=str(scripts))
                    if not resolved:
                        return 5
                    print(f"SCANNER={Path(resolved).resolve()}")
            return 0
        """
    )
    cli_wheel = _fixture_wheel(
        fixtures,
        "defenseclaw",
        "1.0.0",
        {
            "defenseclaw/__init__.py": "__version__ = '1.0.0'\n",
            "defenseclaw/cli.py": cli_source,
        },
        dependencies=("dc-certifi-fixture==1.0.0",),
        scripts={
            "defenseclaw": "defenseclaw.cli:main",
            "skill-scanner": "defenseclaw.cli:scanner",
            "mcp-scanner": "defenseclaw.cli:scanner",
        },
    )
    assert dependency_wheel.is_file() and cli_wheel.is_file()

    profile = tmp_path / "profile"
    defenseclaw_home = profile / ".defenseclaw"
    venv = defenseclaw_home / ".venv"
    scripts = venv / "Scripts"
    install_dir = profile / ".local" / "bin"
    install_dir.mkdir(parents=True)
    fake_checkout = tmp_path / "fake-checkout"
    (fake_checkout / "defenseclaw").mkdir(parents=True)
    (fake_checkout / "defenseclaw" / "__init__.py").write_text(
        "raise RuntimeError('checkout contamination')\n"
    )

    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)
    clean_env.pop("PYTHONHOME", None)
    subprocess.run(
        [uv, "--no-config", "venv", str(venv), "--python", "3.12"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env=clean_env,
    )
    subprocess.run(
        [
            uv,
            "--no-config",
            "pip",
            "install",
            "--python",
            str(scripts / "python.exe"),
            "--no-index",
            "--find-links",
            str(fixtures),
            str(cli_wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env=clean_env,
    )
    damaged_file = venv / "Lib" / "site-packages" / "certifi_fixture" / "__init__.py"
    assert damaged_file.is_file()
    damaged_file.unlink()
    assert not damaged_file.exists()

    functions = "".join(
        _extract_powershell_function(name)
        for name in (
            "Invoke-Uv",
            "Invoke-ManagedCommand",
            "Test-ManagedCli",
            "Publish-CliLauncher",
            "Install-Cli",
        )
    )
    command = functions + rf"""
$ErrorActionPreference = 'Stop'
$Local = '{_ps_quote(fixtures)}'
$Venv = '{_ps_quote(venv)}'
$InstallDir = '{_ps_quote(install_dir)}'
function Write-Step {{ param([string]$Msg) }}
function Write-Info {{ param([string]$Msg) }}
function Write-Ok {{ param([string]$Msg) Write-Output "OK=$Msg" }}
function Die {{ param([string]$Msg) throw $Msg }}
Install-Cli
Install-Cli
"""
    install_env = clean_env.copy()
    install_env.update(
        {
            "USERPROFILE": str(profile),
            "DEFENSECLAW_HOME": str(defenseclaw_home),
            "PYTHONPATH": str(fake_checkout),
            "UV_FIND_LINKS": str(fixtures),
            "UV_NO_INDEX": "1",
        }
    )
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=install_env,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.count("OK=CLI installed") == 2
    assert damaged_file.is_file()
    assert not (install_dir / "defenseclaw.exe").exists()
    shim = install_dir / "defenseclaw.cmd"
    assert shim.is_file()
    shim_text = shim.read_text(encoding="ascii")
    assert str(scripts / "defenseclaw.exe") in shim_text
    assert 'set "PYTHONPATH="' in shim_text
    assert 'set "PYTHONHOME="' in shim_text

    contaminated_env = install_env.copy()
    contaminated_env["PYTHONHOME"] = str(fake_checkout)
    version = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", f"& '{_ps_quote(shim)}' --version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=contaminated_env,
    )
    assert version.returncode == 0, version.stderr
    assert "defenseclaw 1.0.0" in version.stdout

    imported = subprocess.run(
        [
            scripts / "python.exe",
            "-I",
            "-c",
            "import pathlib, defenseclaw; print(pathlib.Path(defenseclaw.__file__).resolve())",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=install_env,
    )
    assert imported.returncode == 0, imported.stderr
    assert str(venv / "Lib" / "site-packages") in imported.stdout.strip()

    doctor = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", f"& '{_ps_quote(shim)}' doctor"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=contaminated_env,
    )
    assert doctor.returncode == 0, doctor.stderr
    scanner_lines = [line.removeprefix("SCANNER=").strip() for line in doctor.stdout.splitlines() if "SCANNER=" in line]
    assert len(scanner_lines) == 2
    assert all(Path(line).is_relative_to(scripts) for line in scanner_lines)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_failed_managed_smoke_prevents_launcher_publication_and_success(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    local = tmp_path / "dist"
    venv = tmp_path / ".defenseclaw" / ".venv"
    install_dir = tmp_path / ".local" / "bin"
    local.mkdir()
    install_dir.mkdir(parents=True)
    (local / "defenseclaw-1.0.0-py3-none-any.whl").write_text("fixture")
    existing_shim = install_dir / "defenseclaw.cmd"
    existing_shim.write_text("existing launcher")
    publish_marker = tmp_path / "published"
    success_marker = tmp_path / "success"

    command = _extract_powershell_function("Install-Cli") + rf"""
$ErrorActionPreference = 'Stop'
$Local = '{_ps_quote(local)}'
$Venv = '{_ps_quote(venv)}'
$InstallDir = '{_ps_quote(install_dir)}'
function Write-Step {{ param([string]$Msg) }}
function Write-Info {{ param([string]$Msg) }}
function Write-Ok {{
    param([string]$Msg)
    if ($Msg -like 'CLI installed*') {{ Set-Content -LiteralPath '{_ps_quote(success_marker)}' -Value 'success' }}
}}
function Invoke-Uv {{ return 0 }}
function Test-ManagedCli {{ throw 'managed smoke failed' }}
function Publish-CliLauncher {{ Set-Content -LiteralPath '{_ps_quote(publish_marker)}' -Value 'published' }}
function Die {{ param([string]$Msg) throw $Msg }}
Install-Cli
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode != 0
    assert "managed smoke failed" in completed.stderr
    assert not publish_marker.exists()
    assert not success_marker.exists()
    assert existing_shim.read_text() == "existing launcher"


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
