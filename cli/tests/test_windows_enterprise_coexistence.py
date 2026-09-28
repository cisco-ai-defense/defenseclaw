# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Coexistence of the Windows enterprise deployment and the per-user product.

The enterprise gateway service and a per-user gateway serve hooks on the same
local port, and the enterprise managed hooks accept only the SCM service as the
listener. The enterprise lifecycle therefore owns the DisableSelfUpdate machine
policy, and every per-user install and gateway start path refuses while the
enterprise gateway service exists.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-self-update-policy-smoke.ps1"
DAEMON = ROOT / "internal" / "cli" / "daemon.go"
MANAGED_HOST_GUARD = ROOT / "internal" / "cli" / "managed_host_guard.go"
ROOT_COMMAND = ROOT / "internal" / "cli" / "root.go"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
SETUP_MAIN = ROOT / "cmd" / "defenseclaw-setup" / "main.go"
PRESENCE_WINDOWS = ROOT / "internal" / "winenterprise" / "presence_windows.go"


def read(path: Path) -> str:
    assert path.is_file(), f"required artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.find("\nfunction ", start + 1)
    return source[start : end if end != -1 else len(source)]


def go_function(source: str, signature: str) -> str:
    start = source.index(signature)
    end = source.find("\nfunc ", start + 1)
    return source[start : end if end != -1 else len(source)]


def test_lifecycle_owns_the_self_update_policy_without_taking_over() -> None:
    module = read(MODULE)
    assert "$script:DefenseClawSelfUpdatePolicyKeyPath = 'SOFTWARE\\Policies\\Cisco\\DefenseClaw'" in module
    assert "$script:DefenseClawSelfUpdatePolicyValueName = 'DisableSelfUpdate'" in module
    assert "[Microsoft.Win32.RegistryView]::Registry64" in function_body(
        module, "Open-DefenseClawMachinePolicyRoot"
    )

    set_policy = function_body(module, "Set-DefenseClawOwnedSelfUpdatePolicy")
    # A pre-existing value without the marker belongs to someone else.
    assert "return 'foreign'" in set_policy
    assert "return 'relinquished'" in set_policy
    # The marker is written before the value, so ownership is never lost.
    assert set_policy.index("$script:DefenseClawSelfUpdatePolicyOwnerValueName,\n") < set_policy.index(
        "$script:DefenseClawSelfUpdatePolicyValueName,\n                1,"
    )

    remove_policy = function_body(module, "Remove-DefenseClawOwnedSelfUpdatePolicy")
    assert remove_policy.index("Test-DefenseClawOwnedSelfUpdateMarker") < remove_policy.index("DeleteValue")
    assert remove_policy.index(
        "DeleteValue($script:DefenseClawSelfUpdatePolicyValueName"
    ) < remove_policy.index("DeleteValue($script:DefenseClawSelfUpdatePolicyOwnerValueName")

    install = function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    apply_at = install.index("Set-DefenseClawOwnedSelfUpdatePolicy")
    assert install.index("Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout") < apply_at
    assert apply_at < install.rindex("Get-DefenseClawLifecycleStatus")
    assert "Test-DefenseClawProductionGatewayService -GatewayServiceName $GatewayServiceName" in install

    cleanup = function_body(module, "Invoke-DefenseClawCommittedUninstallCleanup")
    remove_at = cleanup.index("Remove-DefenseClawOwnedSelfUpdatePolicy")
    assert cleanup.index("committed-uninstall cleanup refused while service exists") < remove_at
    assert remove_at < cleanup.index("Remove-DefenseClawManagedTree")
    assert "Test-DefenseClawProductionGatewayService -GatewayServiceName $GatewayServiceName" in cleanup


def test_every_per_user_gateway_start_path_refuses_beside_enterprise() -> None:
    daemon = read(DAEMON)
    for signature in (
        "func runStart(cmd *cobra.Command, _ []string) error {",
        "func runRestart(cmd *cobra.Command, _ []string) error {",
    ):
        body = go_function(daemon, signature)
        first_statement = body.split("\n", 2)[1].strip()
        assert first_statement == "if err := refuseGatewayLifecycleOnManagedHost(); err != nil {", signature

    root = read(ROOT_COMMAND)
    run = root[root.index("RunE: func(cmd *cobra.Command, args []string) error {") :]
    assert run.index("refuseGatewayLifecycleOnManagedHost()") < run.index("return runSidecar(cmd, args)")
    guard = go_function(
        read(MANAGED_HOST_GUARD), "func refusePerUserGatewayOnManagedHost() error {"
    )
    assert guard.index("refusePerUserGatewayBesideEnterprise()") < guard.index(
        "managed.IsManagedEnterprise"
    )

    installer = read(INSTALL_PS1)
    assert "function Assert-NoEnterpriseDeployment {" in installer
    assert "Get-Service -Name $ServiceName" in installer
    assert "Assert-NoEnterpriseDeployment" in function_body(installer, "Invoke-Install")
    assert "Assert-NoEnterpriseDeployment" in function_body(installer, "Invoke-Rollback")

    setup = go_function(
        read(SETUP_MAIN),
        "func runInstallContext(ctx context.Context, opts options, installRoot, dataRoot string) (int, error) {",
    )
    assert setup.index("refuseSetupBesideEnterprise()") < setup.index("defaultMaintenancePath()")


def test_enterprise_detection_is_read_only_and_standard_user_capable() -> None:
    presence = read(PRESENCE_WINDOWS)
    assert "windows.SC_MANAGER_CONNECT" in presence
    assert "windows.SERVICE_QUERY_CONFIG" in presence
    assert "ERROR_SERVICE_DOES_NOT_EXIST" in presence
    for mutation in ("CreateService", "DeleteService", "ChangeServiceConfig", "RegSetValue"):
        assert mutation not in presence


def windows_powershell_engines() -> list[str]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = [
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "PowerShell" / "7" / "pwsh.exe",
    ]
    engines = [str(candidate) for candidate in candidates if candidate.is_file()]
    if not engines:
        fallback = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if fallback:
            engines.append(fallback)
    return engines


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_self_update_policy_smoke_runs_on_every_engine(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SMOKE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, (
        f"self-update policy smoke failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    for field in (
        "ok",
        "absent_policy_owned",
        "foreign_policy_untouched",
        "changed_policy_relinquished",
        "unrelated_policy_preserved",
        "interrupted_transitions_completed",
    ):
        assert report[field] is True, field
