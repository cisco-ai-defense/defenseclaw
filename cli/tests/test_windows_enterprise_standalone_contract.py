# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Windows standalone enterprise profile.

The standalone profile shares the lifecycle module and installer with the
production Cisco Secure Client deployment. These checks keep the Secure
Client roots in one place, keep the two profile-root helpers in lockstep,
and pin the standalone-only guards, pins, and per-user refusals.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
PER_USER_INSTALLER = ROOT / "scripts" / "install.ps1"
WINPATH_LAYOUT = ROOT / "internal" / "winpath" / "enterprise_layout.go"
HOOK_CONTRACTS = ROOT / "internal" / "gateway" / "connector" / "hook_contract.go"

SECURE_CLIENT = "Cisco Secure Client"

# Code (not comments) may name the Secure Client vendor directory only in
# these functions: the two profile-root helpers, the CMID provider root the
# Secure Client credential broker loads from, and the cross-profile refusal
# message.
ALLOWED_MODULE_FUNCTIONS = {
    "Get-DefenseClawProfileRoots",
    "Assert-DefenseClawExactScopeService",
    "Assert-DefenseClawNoOtherProfileDeployment",
}
ALLOWED_INSTALLER_FUNCTIONS = {"Get-DefenseClawBootstrapProfileRoots"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def _code_lines_by_function(text: str) -> list[tuple[str | None, int, str]]:
    """Yield (enclosing top-level function, line number, code) for every line
    that is not a comment. Here-strings are treated as code."""

    rows: list[tuple[str | None, int, str]] = []
    current: str | None = None
    in_block_comment = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if in_block_comment:
            if "#>" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("<#"):
            in_block_comment = "#>" not in stripped
            continue
        match = re.match(r"^function ([A-Za-z0-9-]+) \{", line)
        if match:
            current = match.group(1)
        elif line.startswith("}"):
            rows.append((current, number, line))
            current = None
            continue
        if stripped.startswith("#"):
            continue
        rows.append((current, number, line))
    return rows


def _functions_naming(text: str, literal: str) -> dict[str | None, list[int]]:
    found: dict[str | None, list[int]] = {}
    for function, number, line in _code_lines_by_function(text):
        if literal in line:
            found.setdefault(function, []).append(number)
    return found


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_profile_roots_are_named_in_one_place_and_agree() -> None:
    module = _functions_naming(_text(MODULE), SECURE_CLIENT)
    assert set(module) <= ALLOWED_MODULE_FUNCTIONS, {
        name: lines for name, lines in module.items() if name not in ALLOWED_MODULE_FUNCTIONS
    }
    installer = _functions_naming(_text(INSTALLER), SECURE_CLIENT)
    assert set(installer) <= ALLOWED_INSTALLER_FUNCTIONS, {
        name: lines for name, lines in installer.items() if name not in ALLOWED_INSTALLER_FUNCTIONS
    }
    # The module, the bootstrap and internal/winpath name the same vendor
    # roots for each profile.
    for body in (
        _function_body(_text(MODULE), "Get-DefenseClawProfileRoots"),
        _function_body(_text(INSTALLER), "Get-DefenseClawBootstrapProfileRoots"),
    ):
        assert "'Cisco\\Cisco Secure Client'" in body and "'Cisco'" in body
    layout = _text(WINPATH_LAYOUT)
    assert 'vendor, powerShell = `Cisco\\Cisco Secure Client`, "SecureClient"' in layout
    assert 'vendor, powerShell = `Cisco`, "Standalone"' in layout


def test_standalone_host_guards_run_before_the_bootstrap() -> None:
    text = _text(INSTALLER)
    guard = text.index("if ($EnterpriseProfile -ceq 'Standalone') {")
    assert text.index("Microsoft.PowerShell.Core\\Set-StrictMode -Version Latest") < guard
    first_function = text.index("\nfunction ")
    assert guard < first_function
    block = text[guard:first_function]
    for code in (
        "powershell7_required:",
        "powershell_32bit_host:",
        "unsupported_architecture:",
        "powershell_constrained_language:",
    ):
        assert code in block, code
    assert "$PSVersionTable.PSVersion.Major -lt 7" in block
    assert "[Environment]::Is64BitProcess" in block
    assert "OSArchitecture" in block
    assert "[Management.Automation.PSLanguageMode]::FullLanguage" in block
    # The Secure Client path refuses the standalone-only arguments instead of
    # silently ignoring them.
    assert "apply only to -EnterpriseProfile Standalone" in block


def test_profile_pin_is_written_only_for_standalone_services() -> None:
    text = _text(MODULE)
    pin = "DEFENSECLAW_ENTERPRISE_PROFILE=standalone"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if pin not in line:
            continue
        window = "\n".join(lines[max(0, index - 12) : index + 1])
        assert (
            "Test-DefenseClawStandaloneProfile" in window
            or "-not [bool]$Layout.BrokerEnabled" in window
            or "Test-DefenseClawLayoutBrokerEnabled" in window
        ), f"profile pin at line {index + 1} is not gated to the standalone profile"


def test_secure_client_layout_keeps_its_historical_shape() -> None:
    layout = _function_body(_text(MODULE), "Get-DefenseClawLayout")
    # Only standalone layouts carry profile keys.
    assert "$layout['Profile'] = 'Standalone'" in layout
    assert "$layout['BrokerEnabled'] = $false" in layout
    assert "Profile = " not in layout.split("$layout = @{", 1)[1].split("\n    }\n", 1)[0]


def test_per_user_installer_refuses_a_managed_host_before_any_change() -> None:
    text = _text(PER_USER_INSTALLER)
    check = text.index('OpenSubKey("SOFTWARE\\Cisco\\DefenseClaw\\Enterprise")')
    assert "A managed DefenseClaw enterprise deployment" in text
    assert check < text.index("return Invoke-ReleaseInstaller") < text.index("# Lock and log.")
    assert check < text.index("if ($Rollback) { return Invoke-Rollback }")


def test_hash_pinned_manifest_contract_is_shared() -> None:
    module = _text(MODULE)
    installer = _text(INSTALLER)
    for text in (module, installer):
        assert "schema_version" in text and "PayloadManifest" in text
    assert "'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'" in module
    go = _text(ROOT / "internal" / "cli" / "windows_enterprise_profile.go")
    assert "`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`" in go
    setup = _text(ROOT / "cmd" / "defenseclaw-enterprise-setup" / "platform_windows.go")
    assert '"schema_version": 1, "files": files' in setup


def test_standalone_fresh_install_rollback_removes_its_sensor_helper() -> None:
    # Transaction snapshots do not record the sensor helper, which a fresh
    # install registers first. A failed standalone first install must remove
    # that owned service before the service-absence gate, or root cleanup
    # refuses and every later ensure/uninstall is wedged.
    module = _text(MODULE)
    body = module[
        module.index("function Publish-DefenseClawInstallRollbackIntent") : module.index(
            "function Assert-DefenseClawInstallRollbackRootDescriptor"
        )
    ]
    no_authority = body.index("if (-not $createdAny -and $null -eq $existing)")
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {", no_authority)
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", gate)
    remove = body.index("Remove-DefenseClawService -Name $sensorHelperName", owned)
    absence = body.index("Get-DefenseClawManagedServiceNames `", remove)
    assert no_authority < gate < owned < remove < absence


def test_standalone_rollback_quiesces_the_sensor_helper_before_restoring_files() -> None:
    module = _text(MODULE)
    start = module.index("function Restore-DefenseClawTransaction {")
    body = module[start : module.index("\nfunction ", start + 10)]
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {")
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", gate)
    disabled = body.index("Set-DefenseClawServiceStartMode -Name $standaloneSensorHelper -StartMode 4", owned)
    # The standalone gateway depends on the sensor helper, and Stop-Service
    # without -Force refuses to stop a service with a running dependent. The
    # helper therefore stops only after the loop that stops the gateway, or
    # every rollback with a running gateway aborts before restoring anything.
    service_stops = body.index("Stop-DefenseClawService -Name $name", disabled)
    gateway_in_stop_loop = body.rindex("[string]$snapshot.gateway_service,", disabled, service_stops)
    stop = body.index("Stop-DefenseClawService -Name $standaloneSensorHelper", disabled)
    assert body.count("Stop-DefenseClawService -Name $standaloneSensorHelper") == 1
    ready = body.index("Assert-DefenseClawRestoredTransactionReadyForActivation", stop)
    restart = body.index("Start-DefenseClawService -Name $standaloneSensorHelper", ready)
    services_restart = body.index("Start-DefenseClawTransactionServices `", restart)
    boot_policy = body.index("-Name $standaloneSensorHelper `", services_restart)
    assert gate < owned < disabled < gateway_in_stop_loop < service_stops < stop
    assert stop < ready < restart < services_restart < boot_policy


def test_standalone_uninstall_removes_the_ipc_directory_before_retiring_the_tree() -> None:
    # Removal happens after the sensor helper service is gone and before the
    # install tree is retired.
    uninstall = _function_body(_text(MODULE), "Invoke-DefenseClawUninstallLifecycle")
    helper = uninstall.index("Remove-DefenseClawService -Name $Layout.SensorHelperServiceName")
    removal = uninstall.index("Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $Layout", helper)
    retire = uninstall.index("Set-DefenseClawInstallTreeRetirementAcls -Layout $Layout", removal)
    assert helper < removal < retire


def test_standalone_default_uninstall_removes_the_machine_state() -> None:
    # GAP-1277 (owner decision 2026-10-01): a standalone uninstall removes the
    # machine state; -Purge adds the per-user data. The user-state flag reads
    # the caller's -Purge first, and the Secure Client profile is unchanged.
    entry = _function_body(_text(MODULE), "Invoke-DefenseClawEnterpriseLifecycle")
    user_state = entry.index("$script:DefenseClawUninstallPurgeUserState = (")
    machine = entry.index(
        "if ($Action -eq 'Uninstall' -and (Test-DefenseClawStandaloneProfile)) {\n        $Purge = [switch]$true\n    }"
    )
    first_use = min(entry.index(":$Purge"), entry.index("if ($Purge -and $Action -ne 'Uninstall')"))
    assert user_state < machine < first_use
    assert entry.count("$Purge = ") == 1


def test_lifecycles_retire_a_stale_committed_journal_through_the_fallback() -> None:
    # GAP-1322: a journal the installed gateway cannot retire no longer
    # blocks every later upgrade, ensure and uninstall (behaviour in
    # enterprise-standalone-stale-lifecycle-journal-smoke.ps1).
    module = _text(MODULE)
    for name in ("Invoke-DefenseClawInstallLikeLifecycle", "Invoke-DefenseClawUninstallLifecycle"):
        assert "Invoke-DefenseClawCommittedManagedHooksLifecycleRetire" in _function_body(module, name)


# The standalone PowerShell smokes run inside disposable scratch directories
# and never touch a service or a real machine root, so Windows CI runs every
# one of them on each installed engine (Windows PowerShell 5.1 and 7).
STANDALONE_SMOKES = (
    "enterprise-profile-lifecycle-lock-smoke.ps1",
    "enterprise-profile-deployment-record-smoke.ps1",
    "enterprise-standalone-claude-policy-binding-smoke.ps1",
    "enterprise-standalone-enumerator-environment-smoke.ps1",
    "enterprise-standalone-install-tree-smoke.ps1",
    "enterprise-standalone-manifest-adoption-smoke.ps1",
    "enterprise-standalone-recorded-trust-smoke.ps1",
    "enterprise-standalone-recovery-activation-deferral-smoke.ps1",
    "enterprise-standalone-recovery-gateway-smoke.ps1",
    "enterprise-standalone-rollback-sensor-helper-smoke.ps1",
    "enterprise-standalone-root-squat-smoke.ps1",
    "enterprise-standalone-secrets-acl-smoke.ps1",
    "enterprise-standalone-service-logged-error-smoke.ps1",
    "enterprise-standalone-stale-lifecycle-journal-smoke.ps1",
    "enterprise-standalone-user-cleanup-report-smoke.ps1",
)


def _standalone_smoke_engines() -> list[str]:
    import os

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


def test_every_standalone_smoke_is_wired() -> None:
    tests = MODULE.parent / "tests"
    present = {
        path.name
        for path in tests.glob("enterprise-*-smoke.ps1")
        if path.name.startswith(("enterprise-standalone-", "enterprise-profile-"))
    }
    assert present == set(STANDALONE_SMOKES)
    for name in STANDALONE_SMOKES:
        assert f"{name.removesuffix('.ps1')}: OK" in _text(tests / name)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("smoke", STANDALONE_SMOKES)
@pytest.mark.parametrize(
    "engine",
    _standalone_smoke_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_standalone_smokes_run_on_every_engine(engine: str | None, smoke: str) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    script = MODULE.parent / "tests" / smoke
    if "#Requires -Version 7" in _text(script) and Path(engine).stem.lower() != "pwsh":
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


# The standalone Claude client floor the module records equals the lowest
# Claude hook contract (the Go guardian enforces the same floor).


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _lowest_contract(connector: str) -> str:
    text = HOOK_CONTRACTS.read_text(encoding="utf-8")
    start = text.index(f'\t"{connector}": {{')
    following = re.search(r'\n\t"[a-z]+": \{', text[start + 1 :])
    block = text[start : start + 1 + following.start()] if following else text[start:]
    versions = re.findall(r'MinAgentVersion:\s+"([0-9.]+)"', block)
    assert versions, f"no {connector} hook contracts found"
    return min(versions, key=_version_key)


def _floor_function() -> str:
    text = MODULE.read_text(encoding="utf-8-sig")
    match = re.search(
        r"^function Get-DefenseClawClaudeMinimumClientVersion \{\n(.*?)^\}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "Get-DefenseClawClaudeMinimumClientVersion is missing"
    return match.group(1)


def test_standalone_claude_floor_is_the_lowest_claude_hook_contract() -> None:
    body = _floor_function()
    standalone = re.search(
        r"if \(Test-DefenseClawStandaloneProfile\) \{\s*return '([0-9.]+)'", body
    )
    assert standalone, body
    assert standalone.group(1) == _lowest_contract("claudecode")


def test_secure_client_claude_floor_is_unchanged() -> None:
    body = _floor_function()
    returns = re.findall(r"return '([0-9.]+)'", body)
    assert returns[-1] == "2.1.152"
