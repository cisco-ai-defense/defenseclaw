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


def _transaction_functions() -> str:
    return "".join(
        _extract_powershell_function(name)
        for name in (
            "Assert-ManagedDirectoryPath",
            "Remove-ManagedDirectory",
            "Assert-ManagedInstallFile",
            "Copy-VerifiedDirectory",
            "Test-StagedReleaseFile",
            "Test-ManagedFileRenameRoundTrip",
            "New-PairedInstallBackup",
            "Restore-PairedInstallBackup",
            "Replace-ManagedInstallFile",
            "Invoke-PairedInstallTransaction",
        )
    )


def test_all_uv_calls_use_explicit_exit_status_wrapper() -> None:
    text = INSTALL_PS1.read_text()

    assert "function Invoke-Uv" in text
    assert "& uv --no-config @Arguments" in text
    assert "& uv python install" not in text
    assert "& uv venv" not in text
    assert "& uv pip install" not in text
    assert 'Invoke-Uv -Arguments @("python", "install", "3.12")' in text
    assert 'Invoke-Uv -Arguments @("venv", $TargetVenv' in text
    assert (
        '"venv", $TargetVenv, "--python", "3.12", "--allow-existing", "--quiet"'
        in text
    )
    assert 'Invoke-Uv -Arguments @("venv", $Venv, "--clear"' not in text
    assert '"pip", "install", "--python", $venvPython, "--quiet"' in text
    assert '"--reinstall", "--no-cache", "--strict", $WheelPath' in text


def test_cli_smoke_precedes_launcher_publication() -> None:
    text = INSTALL_PS1.read_text()
    install_cli = text.split("function Install-Cli", 1)[1].split("function Select-Connector", 1)[0]

    assert install_cli.index("Test-ManagedEnvironment") < install_cli.index("Publish-CliLauncher")
    assert install_cli.index("Publish-CliLauncher") < install_cli.index('Write-Ok "CLI installed')
    assert 'set `"PYTHONPATH=`"' in text
    assert 'set `"PYTHONHOME=`"' in text
    assert "setlocal" in text
    assert "endlocal & exit /b %defenseclawExit%" in text


def test_release_staging_precedes_gateway_stop_and_mutation() -> None:
    text = INSTALL_PS1.read_text()
    main = text.split("function Main", 1)[1]
    transaction = text.split("function Invoke-PairedInstallTransaction", 1)[1].split(
        "function Install-Gateway", 1
    )[0]

    assert main.index("Stage-ReleaseArtifacts") < main.index("Invoke-PairedInstallTransaction")
    assert transaction.index("Stop-ManagedGateway") < transaction.index("New-PairedInstallBackup")
    assert transaction.index("New-PairedInstallBackup") < transaction.index("Replace-ManagedInstallFile")
    assert transaction.index("Test-PairedInstalledState") < transaction.index('$phase = "restart-new-gateway"')
    assert '$headers["Authorization"]' in text
    assert "resolved_token()" in text
    assert "@(Get-Command defenseclaw -CommandType Application -ErrorAction Stop)[0]" in text


def test_windows_installer_offers_only_native_connector_surface() -> None:
    text = INSTALL_PS1.read_text()

    choices_block = text.split("$ConnectorChoices = @(", 1)[1].split(")", 1)[0]
    choices = set(re.findall(r'"([a-z]+)"', choices_block))
    assert choices == WINDOWS_SUPPORTED_CONNECTORS | {"none"}
    assert "Windows ARM64 is not certified" in text
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
    installed_dist_info = next((venv / "Lib" / "site-packages").glob("dc_certifi_fixture-*.dist-info"))
    (installed_dist_info / "RECORD").unlink()
    damaged_file.unlink()
    assert not damaged_file.exists()
    duplicate_dist_info = venv / "Lib" / "site-packages" / "dc.certifi_fixture-0.9.0.dist-info"
    duplicate_dist_info.mkdir()
    (duplicate_dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: dc.certifi_fixture\nVersion: 0.9.0\n"
    )
    corrupt_marker = venv / "corrupt-environment-marker"
    corrupt_marker.write_text("old venv")
    healthy_marker = venv / "healthy-reinstall-marker"

    functions = "".join(
        _extract_powershell_function(name)
        for name in (
            "Invoke-Uv",
            "Invoke-ManagedCommand",
            "Test-ManagedCli",
            "Test-ManagedEnvironment",
            "Assert-ManagedDirectoryPath",
            "Remove-ManagedDirectory",
            "Install-ManagedWheel",
            "Invoke-ManagedVenvRebuild",
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
function Write-Info {{ param([string]$Msg) Write-Output "INFO=$Msg" }}
function Write-Ok {{ param([string]$Msg) Write-Output "OK=$Msg" }}
function Write-Warn2 {{ param([string]$Msg) Write-Output "WARN=$Msg" }}
function Die {{ param([string]$Msg) throw $Msg }}
Install-Cli
Set-Content -LiteralPath '{_ps_quote(healthy_marker)}' -Value 'healthy venv retained'
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
    assert "WARN=Managed environment reconciliation failed:" in completed.stdout
    assert completed.stdout.count("INFO=Rebuilding managed Python environment safely...") == 1
    assert damaged_file.is_file()
    assert not corrupt_marker.exists()
    assert healthy_marker.read_text().strip() == "healthy venv retained"
    assert not duplicate_dist_info.exists()
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

    pip_check = subprocess.run(
        [uv, "--no-config", "pip", "check", "--python", str(scripts / "python.exe")],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=clean_env,
    )
    assert pip_check.returncode == 0, pip_check.stderr

    distributions = subprocess.run(
        [
            scripts / "python.exe",
            "-I",
            "-c",
            textwrap.dedent(
                """
                import importlib.metadata as metadata
                import re
                from collections import Counter

                names = [re.sub(r"[-_.]+", "-", d.metadata["Name"]).lower() for d in metadata.distributions()]
                print(metadata.version("defenseclaw"))
                print(",".join(sorted(name for name, count in Counter(names).items() if count != 1)))
                """
            ),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=clean_env,
    )
    assert distributions.returncode == 0, distributions.stderr
    distribution_lines = distributions.stdout.splitlines()
    assert distribution_lines[0] == "1.0.0"
    assert len(distribution_lines) == 1 or distribution_lines[1] == ""


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
function Write-Warn2 {{ param([string]$Msg) }}
function Write-Ok {{
    param([string]$Msg)
    if ($Msg -like 'CLI installed*') {{ Set-Content -LiteralPath '{_ps_quote(success_marker)}' -Value 'success' }}
}}
function Invoke-Uv {{ return 0 }}
function Install-ManagedWheel {{}}
function Test-ManagedEnvironment {{ throw 'managed smoke failed' }}
function Invoke-ManagedVenvRebuild {{ throw 'managed smoke failed' }}
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


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_rebuild_final_validation_failure_restores_prior_venv(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    managed_home = tmp_path / ".defenseclaw"
    venv = managed_home / ".venv"
    venv.mkdir(parents=True)
    old_marker = venv / "old-marker"
    old_marker.write_text("prior environment")
    wheel = tmp_path / "defenseclaw.whl"
    wheel.write_text("fixture")
    functions = "".join(
        _extract_powershell_function(name)
        for name in ("Assert-ManagedDirectoryPath", "Remove-ManagedDirectory", "Invoke-ManagedVenvRebuild")
    )
    command = functions + rf"""
$ErrorActionPreference = 'Stop'
$finalVenv = '{_ps_quote(venv)}'
function Write-Warn2 {{ param([string]$Msg) }}
function Install-ManagedWheel {{
    param([string]$TargetVenv, [string]$WheelPath)
    New-Item -ItemType Directory -Force -Path $TargetVenv | Out-Null
    Set-Content -LiteralPath (Join-Path $TargetVenv 'new-marker') -Value 'replacement'
}}
function Test-ManagedEnvironment {{
    param([string]$Venv)
    if ($Venv -eq $finalVenv) {{ throw 'final smoke failed' }}
}}
try {{
    Invoke-ManagedVenvRebuild -Venv $finalVenv -WheelPath '{_ps_quote(wheel)}'
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "ERROR=Managed venv rebuild failed; prior environment restored: final smoke failed" in completed.stdout
    assert old_marker.read_text() == "prior environment"
    assert not (venv / "new-marker").exists()
    assert not list(managed_home.glob(".venv.backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_rebuild_install_failure_leaves_prior_venv(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    managed_home = tmp_path / ".defenseclaw"
    venv = managed_home / ".venv"
    venv.mkdir(parents=True)
    marker = venv / "old-marker"
    marker.write_text("prior environment")
    functions = "".join(
        _extract_powershell_function(name)
        for name in ("Assert-ManagedDirectoryPath", "Invoke-ManagedVenvRebuild")
    )
    command = functions + rf"""
$ErrorActionPreference = 'Stop'
function Write-Warn2 {{ param([string]$Msg) }}
function Install-ManagedWheel {{ throw 'rebuild install failed' }}
try {{
    Invoke-ManagedVenvRebuild -Venv '{_ps_quote(venv)}' -WheelPath '{_ps_quote(tmp_path / 'wheel.whl')}'
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "rebuild install failed" in completed.stdout
    assert marker.read_text() == "prior environment"
    assert not list(managed_home.glob(".venv.backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_rebuild_locked_rename_fails_without_moving_prior_venv(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    managed_home = tmp_path / ".defenseclaw"
    venv = managed_home / ".venv"
    venv.mkdir(parents=True)
    marker = venv / "old-marker"
    marker.write_text("prior environment")
    functions = "".join(
        _extract_powershell_function(name)
        for name in ("Assert-ManagedDirectoryPath", "Remove-ManagedDirectory", "Invoke-ManagedVenvRebuild")
    )
    command = functions + rf"""
$ErrorActionPreference = 'Stop'
$finalVenv = '{_ps_quote(venv)}'
function Write-Warn2 {{ param([string]$Msg) }}
function Install-ManagedWheel {{
    param([string]$TargetVenv, [string]$WheelPath)
    New-Item -ItemType Directory -Force -Path $TargetVenv | Out-Null
}}
function Test-ManagedEnvironment {{ param([string]$Venv) }}
function Move-Item {{
    param([string]$LiteralPath, [string]$Destination, [object]$ErrorAction)
    if ($LiteralPath -eq $finalVenv) {{ throw 'venv is locked' }}
    Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -ErrorAction $ErrorAction
}}
try {{
    Invoke-ManagedVenvRebuild -Venv $finalVenv -WheelPath '{_ps_quote(tmp_path / 'wheel.whl')}'
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "venv is locked" in completed.stdout
    assert marker.read_text() == "prior environment"
    assert not list(managed_home.glob(".venv.backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_rebuild_locked_rollback_removal_retains_backup_path(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    managed_home = tmp_path / ".defenseclaw"
    venv = managed_home / ".venv"
    venv.mkdir(parents=True)
    (venv / "old-marker").write_text("prior environment")
    functions = "".join(
        _extract_powershell_function(name)
        for name in ("Assert-ManagedDirectoryPath", "Invoke-ManagedVenvRebuild")
    )
    command = functions + rf"""
$ErrorActionPreference = 'Stop'
$finalVenv = '{_ps_quote(venv)}'
function Write-Warn2 {{ param([string]$Msg) }}
function Install-ManagedWheel {{
    param([string]$TargetVenv, [string]$WheelPath)
    New-Item -ItemType Directory -Force -Path $TargetVenv | Out-Null
    Set-Content -LiteralPath (Join-Path $TargetVenv 'new-marker') -Value 'replacement'
}}
function Test-ManagedEnvironment {{
    param([string]$Venv)
    if ($Venv -eq $finalVenv) {{ throw 'final smoke failed' }}
}}
function Remove-ManagedDirectory {{ throw 'replacement is locked' }}
try {{
    Invoke-ManagedVenvRebuild -Venv $finalVenv -WheelPath '{_ps_quote(tmp_path / 'wheel.whl')}'
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Rollback failed: replacement is locked" in completed.stdout
    assert "Prior environment retained at" in completed.stdout
    backups = list(managed_home.glob(".venv.backup.*"))
    assert len(backups) == 1
    assert (backups[0] / "old-marker").read_text() == "prior environment"
    assert (venv / "new-marker").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_managed_directory_validation_rejects_escape_and_reparse_root(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    managed_home = tmp_path / ".defenseclaw"
    managed_home.mkdir()
    expected = managed_home / ".venv"
    escaped = tmp_path / "escaped"
    command = _extract_powershell_function("Assert-ManagedDirectoryPath") + rf"""
$ErrorActionPreference = 'Stop'
try {{
    Assert-ManagedDirectoryPath -Path '{_ps_quote(escaped)}' -ExpectedPath '{_ps_quote(expected)}' `
        -ManagedHome '{_ps_quote(managed_home)}' -AllowMissing
}} catch {{
    Write-Output "ESCAPE=$($_.Exception.Message)"
}}
function Get-Item {{
    param([string]$LiteralPath, [switch]$Force, [object]$ErrorAction)
    return [pscustomobject]@{{
        PSIsContainer = $true
        Attributes = [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint
    }}
}}
try {{
    Assert-ManagedDirectoryPath -Path '{_ps_quote(expected)}' -ExpectedPath '{_ps_quote(expected)}' `
        -ManagedHome '{_ps_quote(managed_home)}' -AllowMissing
}} catch {{
    Write-Output "REPARSE=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "ESCAPE=Refusing unverified managed directory path" in completed.stdout
    assert "REPARSE=Managed install root must be a real directory" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file sharing")
def test_gateway_lock_waits_for_process_exit_and_handle_release(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    gateway = tmp_path / "defenseclaw-gateway.exe"
    gateway.write_bytes(b"old gateway")
    ready = tmp_path / "ready"
    child_command = rf"""
$stream = [System.IO.File]::Open(
    '{_ps_quote(gateway)}',
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
)
Set-Content -LiteralPath '{_ps_quote(ready)}' -Value 'ready'
Start-Sleep -Milliseconds 750
$stream.Dispose()
"""
    child = subprocess.Popen(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", child_command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(50):
            if ready.exists():
                break
            import time

            time.sleep(0.02)
        assert ready.exists()
        command = _extract_powershell_function("Test-ManagedFileRenameRoundTrip") + _extract_powershell_function("Wait-GatewayFileRelease") + rf"""
Wait-GatewayFileRelease -GatewayPath '{_ps_quote(gateway)}' -ProcessId {child.pid} `
    -Attempts 30 -DelayMilliseconds 100
Write-Output 'RELEASED=true'
"""
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert "RELEASED=true" in completed.stdout
    finally:
        child.communicate(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_gateway_lock_timeout_preserves_installed_artifact(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    gateway = tmp_path / "defenseclaw-gateway.exe"
    gateway.write_bytes(b"unchanged gateway")
    command = _extract_powershell_function("Test-ManagedFileRenameRoundTrip") + _extract_powershell_function("Wait-GatewayFileRelease") + rf"""
$before = (Get-FileHash -LiteralPath '{_ps_quote(gateway)}' -Algorithm SHA256).Hash
$stream = [System.IO.File]::Open(
    '{_ps_quote(gateway)}',
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
)
try {{
    Wait-GatewayFileRelease -GatewayPath '{_ps_quote(gateway)}' -Attempts 2 -DelayMilliseconds 0
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}} finally {{
    $stream.Dispose()
}}
$after = (Get-FileHash -LiteralPath '{_ps_quote(gateway)}' -Algorithm SHA256).Hash
Write-Output "UNCHANGED=$($before -eq $after)"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "did not exit and release" in completed.stdout
    assert "UNCHANGED=True" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_unrelated_pid_evidence_is_never_stopped(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_text("managed")
    (data_dir / "gateway.pid").write_text(
        '{"pid":4242,"executable":"' + str(gateway).replace("\\", "\\\\") + '"}'
    )
    unrelated = tmp_path / "unrelated.exe"
    command = "".join(
        _extract_powershell_function(name)
        for name in (
            "Get-ManagedGatewayProcess",
            "Get-ManagedWatchdogProcess",
            "Stop-ManagedGateway",
        )
    ) + rf"""
$script:invoked = $false
function Get-CimInstance {{
    return [pscustomobject]@{{ ExecutablePath = '{_ps_quote(unrelated)}' }}
}}
function Invoke-ManagedCommand {{ $script:invoked = $true }}
$stopped = Stop-ManagedGateway -GatewayPath '{_ps_quote(gateway)}' -DataDir '{_ps_quote(data_dir)}'
Write-Output "STOPPED=$stopped"
Write-Output "INVOKED=$script:invoked"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "STOPPED=False" in completed.stdout
    assert "INVOKED=False" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process identity")
def test_managed_gateway_pid_contract_is_strict_and_does_not_collide_with_pid(
    tmp_path: Path,
) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")
    data_dir = tmp_path / ".defenseclaw"
    data_dir.mkdir()
    command = _extract_powershell_function("Get-ManagedGatewayProcess") + rf"""
$gateway = (Get-Process -Id $PID).Path
$epoch = [datetime]::SpecifyKind([datetime]'1970-01-01', 'Utc')
$identity = (((Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks - $epoch.Ticks) * 100).ToString()
@{{ pid = $PID; executable = $gateway; start_identity = $identity }} |
    ConvertTo-Json -Compress | Set-Content -LiteralPath '{_ps_quote(data_dir / 'gateway.pid')}'
$managed = Get-ManagedGatewayProcess -GatewayPath $gateway -DataDir '{_ps_quote(data_dir)}'
Write-Output "MATCH=$($managed.PID -eq $PID)"
Set-Content -LiteralPath '{_ps_quote(data_dir / 'gateway.pid')}' -Value '{{not-json'
try {{
    $null = Get-ManagedGatewayProcess -GatewayPath $gateway -DataDir '{_ps_quote(data_dir)}'
}} catch {{
    Write-Output "STRICT=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "MATCH=True" in completed.stdout
    assert "STRICT=Invalid managed gateway PID file" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows replacement semantics")
def test_existing_managed_file_is_atomically_replaced_without_residue(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")
    install = tmp_path / "bin"
    install.mkdir()
    source = tmp_path / "new.exe"
    target = install / "defenseclaw-gateway.exe"
    source.write_text("new")
    target.write_text("old")
    command = (
        _extract_powershell_function("Test-StagedReleaseFile")
        + _extract_powershell_function("Assert-ManagedInstallFile")
        + _extract_powershell_function("Replace-ManagedInstallFile")
        + rf"""
$ErrorActionPreference = 'Stop'
Replace-ManagedInstallFile -Source '{_ps_quote(source)}' -Target '{_ps_quote(target)}' `
    -InstallRoot '{_ps_quote(install)}'
"""
    )
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert target.read_text() == "new"
    assert not list(install.glob("*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_gateway_install_path_rejects_reparse_artifact(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    install = tmp_path / "bin"
    install.mkdir()
    gateway = install / "defenseclaw-gateway.exe"
    command = _extract_powershell_function("Assert-ManagedInstallFile") + rf"""
$root = '{_ps_quote(install)}'
$target = '{_ps_quote(gateway)}'
function Get-Item {{
    param([string]$LiteralPath, [switch]$Force, [object]$ErrorAction)
    if ($LiteralPath -eq $root) {{
        return [pscustomobject]@{{ PSIsContainer = $true; Attributes = [System.IO.FileAttributes]::Directory }}
    }}
    return [pscustomobject]@{{
        PSIsContainer = $false
        Attributes = [System.IO.FileAttributes]::ReparsePoint
    }}
}}
try {{
    Assert-ManagedInstallFile -Path $target -ExpectedPath $target -InstallRoot $root
}} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "ERROR=Managed install artifact must be a regular file" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_stop_failure_mutates_nothing_and_keeps_prior_gateway_running(tmp_path: Path) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")
    home = tmp_path / ".defenseclaw"
    venv = home / ".venv"
    install = tmp_path / "bin"
    staged = tmp_path / "staged"
    venv.mkdir(parents=True)
    install.mkdir()
    staged.mkdir()
    old_values = {
        "defenseclaw-gateway.exe": "old-gateway",
        "defenseclaw-hook.exe": "old-hook",
        "defenseclaw.cmd": "old-shim",
    }
    for name, value in old_values.items():
        (install / name).write_text(value)
    new_gateway = staged / "gateway.exe"
    new_hook = staged / "hook.exe"
    new_gateway.write_text("new-gateway")
    new_hook.write_text("new-hook")
    command = _transaction_functions() + rf"""
$ErrorActionPreference = 'Stop'
$DefenseClawHome = '{_ps_quote(home)}'
$Venv = '{_ps_quote(venv)}'
$InstallDir = '{_ps_quote(install)}'
$script:running = $true
$artifacts = [pscustomobject]@{{ Gateway = '{_ps_quote(new_gateway)}'; Hook = '{_ps_quote(new_hook)}'; Wheel = 'fixture.whl' }}
function Get-ManagedGatewayProcess {{
    if ($script:running) {{ return [pscustomobject]@{{ PID = 44 }} }}
    return $null
}}
function Stop-ManagedGateway {{ throw 'graceful stop failed' }}
function Start-ManagedGateway {{ throw 'must not restart an unstopped gateway' }}
function Write-Ok {{ param([string]$Msg) Write-Output "SUCCESS=$Msg" }}
try {{ Invoke-PairedInstallTransaction -Artifacts $artifacts }} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
Write-Output "RUNNING=$script:running"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ERROR=Preflight stop failed before artifact mutation" in completed.stdout
    assert "RUNNING=True" in completed.stdout
    assert "SUCCESS=" not in completed.stdout
    for name, value in old_values.items():
        assert (install / name).read_text() == value
    assert not list(home.glob(".install-backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("was_running", [False, True])
def test_paired_transaction_success_replaces_all_artifacts_and_restarts_conditionally(
    tmp_path: Path, was_running: bool
) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    home = tmp_path / ".defenseclaw"
    venv = home / ".venv"
    install = tmp_path / "bin"
    staged = tmp_path / "staged"
    venv.mkdir(parents=True)
    install.mkdir()
    staged.mkdir()
    (venv / "cli-state").write_text("old-cli")
    for name, value in (
        ("defenseclaw-gateway.exe", "old-gateway"),
        ("defenseclaw-hook.exe", "old-hook"),
        ("defenseclaw.cmd", "old-shim"),
    ):
        (install / name).write_text(value)
    new_gateway = staged / "gateway.exe"
    new_hook = staged / "hook.exe"
    new_gateway.write_text("new-gateway")
    new_hook.write_text("new-hook")
    command = _transaction_functions() + rf"""
$ErrorActionPreference = 'Stop'
$DefenseClawHome = '{_ps_quote(home)}'
$Venv = '{_ps_quote(venv)}'
$InstallDir = '{_ps_quote(install)}'
$script:running = ${str(was_running).lower()}
$script:stops = 0
$script:starts = 0
$artifacts = [pscustomobject]@{{
    Gateway = '{_ps_quote(new_gateway)}'
    Hook = '{_ps_quote(new_hook)}'
    Wheel = '{_ps_quote(staged / 'cli.whl')}'
    GatewayVersion = 'fixture'
}}
function Get-ManagedGatewayProcess {{
    if ($script:running) {{ return [pscustomobject]@{{ PID = 44 }} }}
    return $null
}}
function Stop-ManagedGateway {{ $script:stops++; $script:running = $false; return $true }}
function Wait-GatewayFileRelease {{}}
function Install-Cli {{
    Set-Content -LiteralPath (Join-Path $Venv 'cli-state') -Value 'new-cli'
}}
function Publish-CliLauncher {{
    Set-Content -LiteralPath (Join-Path $InstallDir 'defenseclaw.cmd') -Value 'new-shim'
}}
function Test-PairedInstalledState {{}}
function Start-ManagedGateway {{ $script:starts++; $script:running = $true }}
function Write-Warn2 {{ param([string]$Msg) }}
function Write-Ok {{ param([string]$Msg) Write-Output "SUCCESS=$Msg" }}
Invoke-PairedInstallTransaction -Artifacts $artifacts
Write-Output "STOPS=$script:stops"
Write-Output "STARTS=$script:starts"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "SUCCESS=Paired gateway, hook, and CLI installation validated" in completed.stdout
    assert (install / "defenseclaw-gateway.exe").read_text() == "new-gateway"
    assert (install / "defenseclaw-hook.exe").read_text() == "new-hook"
    assert (install / "defenseclaw.cmd").read_text().strip() == "new-shim"
    assert (venv / "cli-state").read_text().strip() == "new-cli"
    assert f"STOPS={1 if was_running else 0}" in completed.stdout
    assert f"STARTS={1 if was_running else 0}" in completed.stdout
    assert not list(home.glob(".install-backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "failure_phase", ["gateway-replace", "hook-replace", "cli", "validation", "restart"]
)
def test_paired_transaction_failure_restores_all_artifacts(
    tmp_path: Path, failure_phase: str
) -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    home = tmp_path / ".defenseclaw"
    venv = home / ".venv"
    install = tmp_path / "bin"
    staged = tmp_path / "staged"
    venv.mkdir(parents=True)
    install.mkdir()
    staged.mkdir()
    (venv / "cli-state").write_text("old-cli")
    old_values = {
        "defenseclaw-gateway.exe": "old-gateway",
        "defenseclaw-hook.exe": "old-hook",
        "defenseclaw.cmd": "old-shim",
    }
    for name, value in old_values.items():
        (install / name).write_text(value)
    new_gateway = staged / "gateway.exe"
    new_hook = staged / "hook.exe"
    new_gateway.write_text("new-gateway")
    new_hook.write_text("new-hook")
    command = _transaction_functions() + rf"""
$ErrorActionPreference = 'Stop'
$DefenseClawHome = '{_ps_quote(home)}'
$Venv = '{_ps_quote(venv)}'
$InstallDir = '{_ps_quote(install)}'
$failPhase = '{failure_phase}'
$script:running = $true
$script:replaceCount = 0
$script:startCount = 0
$artifacts = [pscustomobject]@{{
    Gateway = '{_ps_quote(new_gateway)}'
    Hook = '{_ps_quote(new_hook)}'
    Wheel = '{_ps_quote(staged / 'cli.whl')}'
    GatewayVersion = 'fixture'
}}
function Get-ManagedGatewayProcess {{
    if ($script:running) {{ return [pscustomobject]@{{ PID = 44 }} }}
    return $null
}}
function Stop-ManagedGateway {{ $script:running = $false; return $true }}
function Wait-GatewayFileRelease {{}}
function Replace-ManagedInstallFile {{
    param([string]$Source, [string]$Target, [string]$InstallRoot)
    if ($failPhase -eq 'gateway-replace' -and $Source -eq $artifacts.Gateway) {{
        throw 'gateway replace failed'
    }}
    if ($failPhase -eq 'hook-replace' -and $Source -eq $artifacts.Hook) {{
        throw 'hook replace failed'
    }}
    [System.IO.File]::Copy($Source, $Target, $true)
    $script:replaceCount++
}}
function Install-Cli {{
    Set-Content -LiteralPath (Join-Path $Venv 'cli-state') -Value 'new-cli'
    if ($failPhase -eq 'cli') {{ throw 'cli failed' }}
}}
function Publish-CliLauncher {{
    Set-Content -LiteralPath (Join-Path $InstallDir 'defenseclaw.cmd') -Value 'new-shim'
}}
function Test-PairedInstalledState {{
    if ($failPhase -eq 'validation') {{ throw 'validation failed' }}
}}
function Start-ManagedGateway {{
    $script:startCount++
    $script:running = $true
    if ($failPhase -eq 'restart' -and $script:startCount -eq 1) {{ throw 'restart failed' }}
}}
function Write-Warn2 {{ param([string]$Msg) }}
function Write-Ok {{ param([string]$Msg) Write-Output "SUCCESS=$Msg" }}
try {{ Invoke-PairedInstallTransaction -Artifacts $artifacts }} catch {{
    Write-Output "ERROR=$($_.Exception.Message)"
}}
Write-Output "STARTS=$script:startCount"
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "ERROR=Install failed during" in completed.stdout
    assert "SUCCESS=" not in completed.stdout
    for name, value in old_values.items():
        assert (install / name).read_text().strip() == value
    assert (venv / "cli-state").read_text().strip() == "old-cli"
    assert "STARTS=1" in completed.stdout or "STARTS=2" in completed.stdout
    assert not list(home.glob(".install-backup.*"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
def test_call_operator_reports_success_with_question_mark_and_failure_by_exception() -> None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        pytest.skip("Windows PowerShell is not installed")

    success = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"& '{_ps_quote(INSTALL_PS1)}' -Help; Write-Output \"SUCCESS=$?\"",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert success.returncode == 0, success.stderr
    assert "SUCCESS=True" in success.stdout

    failure_command = rf"""
try {{
    & '{_ps_quote(INSTALL_PS1)}' -Connector invalid
    Write-Output "UNEXPECTED_SUCCESS=$?"
}} catch {{
    Write-Output 'CAUGHT=true'
}}
"""
    failure = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", failure_command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert failure.returncode == 0, failure.stderr
    assert "CAUGHT=true" in failure.stdout
    assert "UNEXPECTED_SUCCESS=" not in failure.stdout


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
