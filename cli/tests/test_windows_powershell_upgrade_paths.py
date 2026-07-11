# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install.ps1"
RESOLVER = ROOT / "scripts" / "upgrade.ps1"
RELEASE_HARNESS = ROOT / "scripts" / "test-upgrade-release-windows.ps1"


def _main_body(source: str) -> str:
    marker = "function Main {"
    assert marker in source
    return source[source.index(marker) :]


def test_windows_installer_refuses_existing_install_before_any_dependency_or_artifact_work() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    main = _main_body(source)

    assert "function Assert-FreshInstall" in source
    assert "function Test-InstallMarker" in source
    assert "Get-ChildItem -LiteralPath $parent -Force" in source
    assert "$DefenseClawHome," in source
    assert 'Join-Path $Venv "Scripts\\defenseclaw.exe"' in source
    assert 'Join-Path $InstallDir "defenseclaw.cmd"' in source
    assert 'Join-Path $InstallDir "defenseclaw-gateway.exe"' in source
    assert "$markers | Where-Object { Test-InstallMarker -Path $_ }" in source
    assert "No changes were made" in source
    assert "upgrade.ps1" in source
    guard = main.index("\n    Assert-FreshInstall\n")
    assert guard < main.index("\n    $arch = Get-Arch\n")
    assert guard < main.index("\n    Install-Uv\n")
    assert guard < main.index("\n    Ensure-Python\n")
    assert guard < main.index("\n    $script:ReleaseVersion = Resolve-Version\n")
    assert guard < main.index("\n    Install-Gateway -Arch $arch\n")
    assert guard < main.index("\n    Install-Cli\n")


def test_windows_resolver_has_fail_closed_bridge_and_fresh_controller_contract() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    main = _main_body(source)

    for required in (
        "minimum_source_version",
        "required_bridge_version",
        "auto_bridge_from",
        "controller_upgrade_protocol",
        "migration_failure_policy",
        "required_cli_migrations",
        "DEFENSECLAW_STAGED_UPGRADE",
        "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR",
        "_prepare_hard_cut_rollback_plan",
        "_execute_hard_cut_rollback",
        "No installed state changed",
    ):
        assert required in source
    assert "Invoke-FreshHardCut" in source
    assert "-I -m defenseclaw.main upgrade" in source
    assert "Set-PrivateDirectoryAcl" in source
    assert "AreAccessRulesProtected" in source
    assert "ReparsePoint" in source
    assert 'Fail "cosign is required' in source
    assert "--certificate-identity" in source
    assert "/.github/workflows/release.yaml@refs/heads/main" in source
    assert "[IO.FileSystemAclExtensions]::Create" in source
    assert "Invoke-BridgeTransaction" in source
    assert "Restore-PhaseOneSource" in source
    assert "InjectPhaseOneFailureAfterMutation" in source
    assert "InjectPhaseOneCrashAfterMutation" in source
    assert "InjectPhaseOneCrashDuringRecovery" in source
    assert "phase-one-active.json" in source
    assert "Register-PhaseOneJournal" in source
    assert "Recover-InterruptedPhaseOne" in source
    assert "Recover-InterruptedPhaseTwo" in source
    assert "phase-two-active.json" in source
    assert "phase-two-mutator.lease" in source
    assert "Enter-PhaseTwoMutatorLease" in source
    assert "_recover_interrupted_hard_cut" in source
    assert "pip install --python (Get-Python) --quiet --no-deps --reinstall" in source
    assert "--force-reinstall" not in source
    assert main.index("[void](Recover-InterruptedPhaseOne)") < main.index("[void](Recover-InterruptedPhaseTwo)")
    assert main.index("[void](Recover-InterruptedPhaseTwo)") < main.index("$installed=Get-InstalledVersion")
    assert '$displaced=Join-Path $parent' in source
    assert '$createdQuarantine=Join-Path $createdParent' in source
    assert '$sourceStream=[IO.File]::OpenRead($Source)' in source
    assert '[IO.Directory]::CreateDirectory($Path, $acl)' in source


def test_native_windows_release_harness_proves_refusal_bridge_and_exact_rollback() -> None:
    source = RELEASE_HARNESS.read_text(encoding="utf-8")

    assert "--force-reinstall" not in source
    assert "[Parameter(Mandatory = $true)]\n    [ValidateNotNullOrEmpty()]\n    [string]$ReleaseDir" in source
    assert "[ValidatePattern('^(0|[1-9]\\d*)" in source
    assert "[string]$TargetVersion" in source
    assert "[string]$SourceVersion" in source
    assert "release\\upgrade-baselines.json" in source
    assert "$values -notcontains $SourceVersion" in source
    assert "SourceVersion must be a pre-bridge release" in source
    assert '$PSBoundParameters.ContainsKey("SourceVersion")' in source
    assert "SourceVersion cannot be empty when explicitly supplied" in source
    assert "$script:PublishedPreBridgeBaselines" in source
    assert "auto_bridge_from must exactly match the reviewed pre-bridge baseline policy" in source
    assert 'Join-Path $PSScriptRoot "upgrade.ps1"' in source
    assert 'Join-Path $PSScriptRoot "install.ps1"' in source
    assert "Explicit hard-cut refusal" in source
    assert "-LatestVersionOverride" in source
    assert "post-v8-port-blocker.bound" in source
    assert "Test-PhaseOneRollback" in source
    assert "Test-PhaseOneCrashRecovery" in source
    assert "InjectPhaseOneFailureAfterMutation" in source
    assert "InjectPhaseOneCrashAfterMutation" in source
    assert "InjectPhaseOneCrashDuringRecovery" in source
    assert "phase-one-active.json" in source
    assert "Test-PhaseTwoWheelInstallCrashRecovery" in source
    assert "target-wheel-install.blocked" in source
    assert "phase-two-active.json" in source
    assert 'failure_code -ne "interrupted"' in source
    assert 'status -eq "rolled_back"' in source
    assert 'failure_code -eq "health_check_failed"' in source
    assert "dacl_sddl" in source
    assert "owner_sid" in source
    assert "Assert-SnapshotsEqual" in source
    assert "Assert-RetainedBridgeArtifacts" in source
    assert "--certificate-identity" in source
    assert "/.github/workflows/release.yaml@refs/heads/main" in source


@pytest.mark.skipif(
    not (shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")),
    reason="PowerShell parser is unavailable on this host",
)
@pytest.mark.parametrize("path", [INSTALLER, RESOLVER, RELEASE_HARNESS])
def test_windows_powershell_scripts_parse_without_errors(path: Path) -> None:
    executable = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
    assert executable is not None
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors) | Out-Null; "
        "if($errors.Count){$errors | ForEach-Object {$_.ToString()}; exit 1}"
    )
    completed = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command, str(path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
