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


def test_fresh_install_rollback_removes_its_sensor_helper_on_every_profile() -> None:
    # Transaction snapshots do not record the sensor helper, which a fresh
    # install registers first on both profiles. A failed first install must
    # remove that owned service before the service-absence gate, or root
    # cleanup refuses ("rollback also failed and pending recovery was
    # retained") and every later ensure/uninstall is wedged. Secure Client
    # registers it too, so the removal is not gated on the standalone profile.
    module = _text(MODULE)
    body = module[
        module.index("function Publish-DefenseClawInstallRollbackIntent") : module.index(
            "function Assert-DefenseClawInstallRollbackRootDescriptor"
        )
    ]
    no_authority = body.index("if (-not $createdAny -and $null -eq $existing)")
    helper = body.index("$sensorHelperName = Get-DefenseClawSensorHelperServiceName `", no_authority)
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", helper)
    remove = body.index("Remove-DefenseClawService -Name $sensorHelperName", owned)
    absence = body.index("Get-DefenseClawManagedServiceNames `", remove)
    assert no_authority < helper < owned < remove < absence
    assert "Test-DefenseClawStandaloneProfile" not in body[no_authority:helper]


def test_rollback_quiesces_the_sensor_helper_before_restoring_files_on_every_profile() -> None:
    module = _text(MODULE)
    start = module.index("function Restore-DefenseClawTransaction {")
    body = module[start : module.index("\nfunction ", start + 10)]
    # Both profiles register the sensor helper, so the quiesce is not gated on
    # the standalone profile (a Secure Client rollback found it running).
    gate = body.index("$standaloneSensorHelper = Get-DefenseClawSensorHelperServiceName `")
    assert "Test-DefenseClawStandaloneProfile" not in body[:gate]
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


def test_standalone_setup_uninstall_docs_say_it_removes_the_machine_state() -> None:
    # GAP-2647: the standalone Setup pages describe the GAP-1277 behavior
    # above (machine state always removed; PURGE=1 adds the per-user data).
    # The Secure Client page keeps its own wording (state kept unless
    # PURGE=1) and says how the standalone profile differs.
    standalone = {
        "windows": ROOT / "docs-site" / "content" / "docs" / "enterprise" / "install" / "windows.mdx",
        "cli": ROOT / "docs-site" / "content" / "docs" / "reference" / "commands" / "cli.mdx",
        "setup-design": ROOT / "docs" / "WINDOWS-ENTERPRISE-SETUP.md",
        "intune": ROOT / "docs-site" / "content" / "docs" / "enterprise" / "mdm" / "intune" / "windows.mdx",
    }
    for name, page in standalone.items():
        text = " ".join(_text(page).split())
        assert "PURGE=1` to also remove the config" not in text, name
        assert "`/uninstall`, also remove managed state." not in text, name
        assert "remove state on uninstall" not in text, name
    # The Secure Client page moved from setup/enterprise-deployment.mdx to
    # enterprise/install/secure-client.mdx in the 1.0 docs-site layout.
    docs = ROOT / "docs-site" / "content" / "docs"
    secure_client_page = next(
        page
        for page in (docs / "enterprise" / "install" / "secure-client.mdx", docs / "setup" / "enterprise-deployment.mdx")
        if page.exists()
    )
    secure_client = " ".join(_text(secure_client_page).split())
    assert "It keeps runtime state, logs and guardian evidence." in secure_client
    assert "the standalone Setup's `/uninstall` always removes its machine state" in secure_client


def test_standalone_uninstall_retry_binds_the_receipt_to_the_retrying_cli() -> None:
    # GAP-1684/GAP-1679: when the first self-uninstall could not rename
    # InstallRoot aside, its retry by the installed CLI runs from InstallRoot.
    # The recovery binds the prepared receipt to that caller (same CLI file)
    # before the rename, so the detached finalizer waits for it, and the
    # retry finishes the committed cleanup and machine-state purge. Secure
    # Client recovery is unchanged.
    module = _text(MODULE)
    recovery = _function_body(module, "Invoke-DefenseClawSelfUninstallRecovery")
    rebind = recovery.index("$receipt = Set-DefenseClawSelfUninstallReceiptCaller")
    guard = recovery.rindex("if ($SelfUninstallCallerPID -gt 0 -and", 0, rebind)
    assert "(Test-DefenseClawStandaloneProfile)" in recovery[guard:rebind]
    move = recovery.index(
        "Move-DefenseClawInstallRootForRetirement -Source $Layout.InstallRoot -Destination $retiredRoot"
    )
    cleanup = recovery.index("$result = Invoke-DefenseClawCommittedUninstallCleanup")
    assert rebind < move < cleanup
    assert recovery.rindex("if ($reboundCaller) {", 0, cleanup) > move
    caller = _function_body(module, "Set-DefenseClawSelfUninstallReceiptCaller")
    assert "Get-DefenseClawSelfUninstallCallerIdentity" in caller
    assert "caller_file_identity" in caller and "caller_sha256" in caller
    assert "'prepared_install_retirement'" in caller
    prelayout = _function_body(module, "Invoke-DefenseClawPreLayoutRecovery")
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in prelayout
    entry = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    call = entry[entry.index("$preLayoutRecovery = Invoke-DefenseClawPreLayoutRecovery") :]
    call = call[: call.index("if ([bool]$preLayoutRecovery.handled)")]
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in call


def test_lifecycles_retire_a_stale_committed_journal_through_the_fallback() -> None:
    # GAP-1322: a journal the installed gateway cannot retire no longer
    # blocks every later upgrade, ensure and uninstall (behaviour in
    # enterprise-standalone-stale-lifecycle-journal-smoke.ps1).
    module = _text(MODULE)
    for name in ("Invoke-DefenseClawInstallLikeLifecycle", "Invoke-DefenseClawUninstallLifecycle"):
        assert "Invoke-DefenseClawCommittedManagedHooksLifecycleRetire" in _function_body(module, name)


def test_standalone_purge_keeps_the_launching_cli_powershell_temp() -> None:
    """GAP-1853: install-enterprise.ps1 moves TEMP into its bootstrap folder,
    so the stale-temp sweep learns the launching CLI's protected folder from
    -LauncherTemp, which only the standalone profile passes."""

    installer = _text(INSTALLER)
    standalone = installer[installer.index("if ($EnterpriseProfile -ceq 'Standalone') {") :]
    standalone = standalone[: standalone.index("Invoke-DefenseClawEnterpriseLifecycle @arguments")]
    assert "$arguments['LauncherTemp'] = [string]$bootstrapEnvironment.OriginalEnvironment['TEMP']" in standalone
    module = _text(MODULE)
    assert "$script:DefenseClawLauncherTemp = [string]$LauncherTemp" in _function_body(
        module, "Invoke-DefenseClawEnterpriseLifecycle"
    )
    assert "$script:DefenseClawLauncherTemp" in _function_body(
        module, "Remove-DefenseClawStaleRunDirectories"
    )


def test_compliant_ensure_verify_collects_old_runtime_generations() -> None:
    """GAP-0211: a compliant ensure runs no retire, so its Verify collects the
    old runtime copies a retire left in a per-user folder it could not trust
    and names each folder still untrusted. The CLI asks through the strict
    environment (not a parameter of the Secure Client command line), only a
    standalone Verify accepts it, the collect runs under the lifecycle lock
    between transactions, and a failure is reported in the result instead of
    failing the Verify."""

    installer = _text(INSTALLER)
    standalone = installer[installer.index("if ($EnterpriseProfile -ceq 'Standalone') {") :]
    standalone = standalone[: standalone.index("Invoke-DefenseClawEnterpriseLifecycle @arguments")]
    variable = "DEFENSECLAW_STANDALONE_COLLECT_RUNTIME_GENERATIONS"
    assert f"[Environment]::SetEnvironmentVariable('{variable}', $null, 'Process')" in standalone
    assert "if ($Action -eq 'Verify' -and $collectRequest -ceq '1') {" in standalone
    assert "$arguments['CollectRuntimeGenerations'] = $true" in standalone

    module = _text(MODULE)
    lifecycle = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert "throw '-CollectRuntimeGenerations is valid only with a standalone Verify'" in lifecycle
    verify = lifecycle[lifecycle.index("if ($Action -eq 'Verify') {") :]
    verify = verify[: verify.index("return Get-DefenseClawLifecycleStatus")]
    assert "Invoke-DefenseClawStandaloneRuntimeGenerationCollect" in verify

    collect = _function_body(module, "Invoke-DefenseClawStandaloneRuntimeGenerationCollect")
    assert "Test-DefenseClawStandaloneProfile" in collect and "Test-DefenseClawAdministrator" in collect
    assert collect.index("Enter-DefenseClawLifecycleLock") < collect.index("-Action collect")
    assert "$Layout.PendingPath" in collect and "Exit-DefenseClawLifecycleLock" in collect
    assert "$script:DefenseClawRuntimeGenerationCollectError = ConvertTo-DefenseClawBoundedDiagnostic" in collect

    snapshot = _function_body(module, "Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand")
    assert "'collect'," in snapshot and "'collect' { 'collected' }" in snapshot
    assert "$report.PSObject.Properties['collected']" in snapshot

    status = _function_body(module, "Get-DefenseClawLifecycleStatus")
    assert "$status['lifecycle_retire_skipped']" in status
    assert "$status['lifecycle_generations_collected']" in status
    assert "$status['lifecycle_collect_error']" in status

    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert f'windowsEnterpriseCollectGenerationsVariable = "{variable}"' in go
    lifecycle_go = (ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go").read_text(encoding="utf-8")
    assert '"capture", "classify-activation", "collect", "restore", "retire", "retire-committed",' in lifecycle_go


def test_standalone_first_enumeration_has_a_longer_named_budget() -> None:
    """GAP-0561: the first run of a new gateway on a cold device took more
    than the default 300 seconds and the install failed with only "native
    process timed out". The standalone profile allows 900 seconds for the
    synchronous enumeration and names the step and the remedy; the Secure
    Client profile keeps 300."""

    module = _text(MODULE)
    assert "$script:StandaloneEnumeratorRefreshTimeoutSeconds = 900" in module
    body = _function_body(module, "Invoke-DefenseClawEnumeratorRefresh")
    assert "$timeoutSeconds = 300" in body
    assert "-TimeoutSeconds $timeoutSeconds" in body
    assert "run the install again" in body
    gateway = _function_body(module, "Invoke-DefenseClawGatewayCommand")
    assert "-TimeoutSeconds $TimeoutSeconds" in gateway


def test_standalone_purge_refuses_open_data_files_before_teardown() -> None:
    """GAP-0136: a read-only reader of runtime\\audit.db made the purge fail
    after it had removed the binaries and the hook wiring. The purge checks
    the files it deletes before the uninstall transaction starts, and the
    deletion after the services stopped retries a file in use before it
    refuses with uninstall_in_use (behaviour in
    enterprise-standalone-state-files-in-use-smoke.ps1)."""

    module = _text(MODULE)
    body = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    tree = body.index("Assert-DefenseClawStandaloneInstallTreeNotInUse")
    data = body.index("Assert-DefenseClawStandaloneStateFilesNotInUse")
    assert tree < data < body.index("$snapshot = New-DefenseClawTransaction")
    assert "if ($Purge) {" in body[tree:data]
    purge = _function_body(module, "Complete-DefenseClawStatePurge")
    assert "Remove-DefenseClawPurgedStateRoot -Layout $Layout" in purge
    assert "Remove-DefenseClawManagedTree" not in purge
    assert "$script:StateRootRemovalRetryMilliseconds = 15000" in module
    native = _function_body(module, "Initialize-DefenseClawNativeSecurity")
    for name in ("RmStartSession", "RmRegisterResources", "RmGetList", "RmEndSession"):
        assert 'DllImport("rstrtmgr.dll"' in native and name in native


# The standalone PowerShell smokes run inside disposable scratch directories
# and never touch a service or a real machine root, so Windows CI runs every
# one of them on each installed engine (Windows PowerShell 5.1 and 7).
STANDALONE_SMOKES = (
    "enterprise-profile-lifecycle-lock-smoke.ps1",
    "enterprise-profile-deployment-record-smoke.ps1",
    "enterprise-standalone-claude-policy-binding-smoke.ps1",
    "enterprise-standalone-config-acl-repair-smoke.ps1",
    "enterprise-standalone-enumerator-environment-smoke.ps1",
    "enterprise-standalone-guardian-first-reconcile-wait-smoke.ps1",
    "enterprise-standalone-install-tree-smoke.ps1",
    "enterprise-standalone-machine-leftovers-purge-smoke.ps1",
    "enterprise-standalone-manifest-adoption-smoke.ps1",
    "enterprise-standalone-recorded-trust-smoke.ps1",
    "enterprise-standalone-recovery-activation-deferral-smoke.ps1",
    "enterprise-standalone-recovery-gateway-smoke.ps1",
    "enterprise-standalone-rollback-sensor-helper-smoke.ps1",
    "enterprise-standalone-root-squat-smoke.ps1",
    "enterprise-standalone-w2b-lifecycle-smoke.ps1",
    "enterprise-standalone-secrets-acl-smoke.ps1",
    "enterprise-standalone-service-logged-error-smoke.ps1",
    "enterprise-standalone-stale-lifecycle-journal-smoke.ps1",
    "enterprise-standalone-state-files-in-use-smoke.ps1",
    "enterprise-standalone-uninstall-hook-commit-smoke.ps1",
    "enterprise-standalone-uninstall-cleanup-trust-smoke.ps1",
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


# GAP-0046: the installed CLI's self-uninstall retires InstallRoot to a
# receipt-bound sibling and a detached finalizer deletes it. The standalone
# tree also holds lib\defenseclaw\policy_compiler.py. Cleanup deleted the
# compiler but never the two compiler directories, so the final non-recursive
# Remove-Item of the retired root prompted ("has children"), which a
# -NonInteractive engine turns into a terminating error. The receipt survived
# and every later Setup recovery (1.0.2 included) failed the same way with
# lifecycle_error 1603. The cleanup must remove every allowlisted directory
# bottom-up, only when empty, and must never delete unexpected content.
_RETIRED_TREE_CLEANUP_HARNESS = r"""
param([string]$ModulePath, [string]$Scratch, [string]$Case)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "module parse failed: $($errors[0].Message)" }
foreach ($name in @(
    'Get-DefenseClawRetiredInstallTreeAllowlist',
    'Assert-DefenseClawNoReparsePath',
    'Remove-DefenseClawEmptyRetiredInstallDirectory',
    'Remove-DefenseClawRetiredInstallTree'
)) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true)
    if ($null -ne $definition) {
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }
}
# ACL and ownership validation is Windows-only and covered elsewhere; the
# allowlist itself stays the module's.
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawRetiredInstallTree {
    param([hashtable]$Layout, [string]$RetiredRoot, [switch]$SkipAclValidation)
}
$retired = Join-Path $Scratch 'DefenseClaw.retired-0123456789abcdef0123456789abcdef'
$allowlist = Get-DefenseClawRetiredInstallTreeAllowlist -Layout @{} -RetiredRoot $retired
foreach ($directory in $allowlist.directories) {
    [void](New-Item -ItemType Directory -Path $directory -Force)
}
$modulePathInTree = [IO.Path]::GetFullPath((Join-Path $retired 'libexec\DefenseClawEnterprise.psm1'))
switch ($Case) {
    'full' {
        foreach ($file in $allowlist.files) {
            if ($file -like '*defenseclaw_ipc.sock') { continue }
            [IO.File]::WriteAllText($file, "payload $file")
        }
    }
    'compiler-residue' {
        # What a 1.0.2 (or older candidate) self-uninstall left on dc-ent-win:
        # only the two empty compiler directories.
        $compilerDirectories = @(
            [IO.Path]::GetFullPath((Join-Path $retired 'lib')).TrimEnd('\'),
            [IO.Path]::GetFullPath((Join-Path $retired 'lib\defenseclaw')).TrimEnd('\')
        )
        foreach ($directory in $allowlist.directories) {
            if ($directory -notin $compilerDirectories) {
                [IO.Directory]::Delete($directory)
            }
        }
    }
    'unexpected' {
        [IO.File]::WriteAllText((Join-Path $retired 'lib\defenseclaw\operator-notes.txt'), 'keep me')
    }
}
$moduleHash = ''
if ([IO.File]::Exists($modulePathInTree)) {
    $moduleHash = (Get-FileHash -LiteralPath $modulePathInTree -Algorithm SHA256).Hash.ToLowerInvariant()
}
$receipt = [pscustomobject]@{
    retired_install_root = $retired
    retired_module_sha256 = $moduleHash
}
$threw = ''
try {
    Remove-DefenseClawRetiredInstallTree -Layout @{} -Receipt $receipt
}
catch {
    $threw = $_.Exception.Message
}
[pscustomobject]@{
    threw = $threw
    retired_exists = [IO.Directory]::Exists($retired)
    unexpected_kept = [IO.File]::Exists((Join-Path $retired 'lib\defenseclaw\operator-notes.txt'))
} | ConvertTo-Json -Compress
"""


def _portable_pwsh() -> str | None:
    import os
    import shutil

    return os.environ.get("DEFENSECLAW_TEST_PWSH") or shutil.which("pwsh") or shutil.which("pwsh.exe")


def test_installed_verifier_refuses_untrusted_redaction_key_before_compliance(tmp_path: Path) -> None:
    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "verify-redaction-key.ps1"
    harness.write_text(
        r"""
param([string]$ModulePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$null, [ref]$errors)
if ($errors.Count -gt 0) { throw $errors[0].Message }
$definition = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-DefenseClawEnterpriseDeployment'
}, $true)
. ([ScriptBlock]::Create($definition.Extent.Text))
$script:Standalone = $true
$script:KeyChecks = 0
function Test-DefenseClawStandaloneProfile { return $script:Standalone }
function Get-DefenseClawAcceptedGatewayServiceAccounts { return @('gateway') }
function Get-DefenseClawServiceSID { return 'service sid from OS' }
function Get-DefenseClawDeploymentMetadata { return [pscustomobject]@{} }
function Test-DefenseClawMetadataInstalled { return $true }
function Assert-DefenseClawMetadataIdentity {}
# Native capture/classification has a separate Windows ACL smoke. Model its
# refusal here and require the installed-host verifier to propagate it.
function Get-DefenseClawRedactionKeySecuritySnapshot {
    $script:KeyChecks++
    throw 'untrusted_key_reader'
}
try {
    Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName gateway -GuardianServiceName guardian
    throw 'verifier accepted the untrusted key'
}
catch {
    if ($_.Exception.Message -cne 'untrusted_key_reader') { throw }
}
$script:Standalone = $false
try {
    Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName gateway -GuardianServiceName guardian
}
catch {
    # The empty fixture has no activation metadata. Secure Client must reach
    # its existing validation without adding the standalone key check.
    if ($_.Exception.Message -ceq 'untrusted_key_reader') { throw }
}
if ($script:KeyChecks -ne 1) { throw 'standalone-only key validation was skipped or reached Secure Client' }
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness), "-ModulePath", str(MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("case", ["full", "compiler-residue", "unexpected"])
def test_standalone_retired_tree_cleanup_removes_empty_compiler_directories(
    tmp_path: Path, case: str
) -> None:
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    harness = tmp_path / "retired-tree-cleanup.ps1"
    harness.write_text(_RETIRED_TREE_CLEANUP_HARNESS, encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(harness),
            "-ModulePath",
            str(MODULE),
            "-Scratch",
            str(scratch),
            "-Case",
            case,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    if case == "unexpected":
        # Content outside the allowlist is never deleted, and the refusal
        # names it instead of surfacing a NonInteractive prompt error.
        assert result["unexpected_kept"] is True, result
        assert result["retired_exists"] is True, result
        assert "not empty" in result["threw"], result
        assert "NonInteractive" not in result["threw"], result
    else:
        assert result["threw"] == "", result
        assert result["retired_exists"] is False, result


def test_signed_out_untrusted_folder_is_classified_alike() -> None:
    """#1105, GAP-0211: the 1.0.2 -> 1.0.3 upgrade with a signed-out account
    whose hooks folder had one extra permission entry returned 1603. The
    manifest adoption (PowerShell) and the lifecycle's guardian check (Go)
    excuse exactly the same failure, report it, and nothing else."""

    module = _text(MODULE)
    block = module[module.index("$script:SignedOutUntrustedFolderPattern = [regex]::new(") :]
    block = block[: block.index("[Text.RegularExpressions.RegexOptions]::CultureInvariant")]
    powershell = "".join(part.replace("''", "'") for part in re.findall(r"'((?:[^']|'')*)'", block))
    go_source = (ROOT / "internal" / "cli" / "enterprise_hooks_signed_out_folder.go").read_text(encoding="utf-8")
    go_block = go_source[go_source.index("enterpriseHookSignedOutUntrustedFolderPattern = regexp.MustCompile(") :]
    go_block = go_block[: go_block.index("\n)\n")]
    go = "".join(re.findall(r"`([^`]*)`", go_block))
    assert powershell == go
    live = (
        "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable "
        "(verification: enterprise hooks: managed hook directory verification failed: enterprise hooks: "
        "managed Windows DACL on C:\\Users\\r103gb13-u1\\.defenseclaw\\hooks has 8 ACEs, expected 7)"
    )
    found = re.fullmatch(go, live)
    assert found and found.group(1) == "hook" and found.group(2) == "C:\\Users\\r103gb13-u1\\.defenseclaw\\hooks"
    assert not re.fullmatch(go, live + "; more")

    adoption = _function_body(module, "Get-DefenseClawStandaloneManifestAdoption")
    assert "Get-DefenseClawSignedOutUntrustedFolder -Row $row" in adoption
    assert "$excused = $folderRows + $waitingRows" in adoption
    for name in ("Assert-DefenseClawEnterpriseDeployment", "Sync-DefenseClawStandaloneManagedHooksActivationBinding"):
        assert "Add-DefenseClawSignedOutUntrustedFolders -Adoption $adoption" in _function_body(module, name)
    assert "$status['signed_out_untrusted_folders']" in _function_body(module, "Get-DefenseClawLifecycleStatus")

    lifecycle = (ROOT / "internal" / "cli" / "windows_managed_hooks_lifecycle.go").read_text(encoding="utf-8")
    assert "enterpriseHookSignedOutUntrustedFolder(row, target.DataDir)" in lifecycle
    standalone = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert 'json:"signed_out_untrusted_folders"' in standalone


def _run_lifecycle_functions(tmp_path, names, body, replacements=()) -> None:
    import shutil

    shell = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not shell:
        pytest.skip("PowerShell is unavailable")
    functions = "\n".join(_function_body(_text(MODULE), name) for name in names)
    for old, new in replacements:
        functions = functions.replace(old, new)
    script = tmp_path / "lifecycle.ps1"
    script.write_text("$ErrorActionPreference = 'Stop'\n" + functions + "\n" + body, encoding="utf-8")
    result = subprocess.run([shell, "-NoProfile", "-File", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr



_TIMEOUT_RECOVERY_HARNESS = r"""
class FakeTimeoutNative {
    static [object] GetRegularFileSecuritySnapshotNoFollowIfExists([string]$Path) {
        if ([IO.File]::Exists($Path)) { return 'file' }
        return $null
    }
    static [object] GetDirectorySecuritySnapshotNoFollowIfExists([string]$Path) {
        if ([IO.Directory]::Exists($Path)) { return 'directory' }
        return $null
    }
}
function Initialize-DefenseClawNativeSecurity { return [FakeTimeoutNative] }
# These cases are the shared record checks. The standalone committed-uninstall
# replay has its own smoke (enterprise-uninstall-postcommit-recovery-smoke.ps1).
function Test-DefenseClawStandaloneProfile { return $false }
$script:DefenseClawUnfinishedTransactionDirectory = 'unfinished transaction directory'
$root = '__ROOT__'
$layout = @{
    PendingPath = [IO.Path]::Combine($root, 'install', 'pending.json')
    ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($root, 'install', 'managed-hooks-lifecycle-journal.json')
    ManagedHooksTeardownJournalPath = [IO.Path]::Combine($root, 'install', 'managed-hooks-teardown-journal.json')
    PurgeIntentPath = [IO.Path]::Combine($root, 'lock', 'purge-scope.json')
    SelfUninstallReceiptPath = [IO.Path]::Combine($root, 'lock', 'self-uninstall.json')
    InstallRollbackIntentPath = [IO.Path]::Combine($root, 'lock', 'install-rollback-scope.json')
    ManagedHookContractCleanupReceiptPath = [IO.Path]::Combine($root, 'lock', 'managed-hook-contract-cleanup-scope.json')
    TransactionsDirectory = [IO.Path]::Combine($root, 'install', 'transactions')
}
function Recover-DefenseClawPendingTransaction {
    param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$AllowDeferredActivation)
    if ($AllowDeferredActivation) { throw 'timeout recovery must reactivate the restored release' }
    $global:Replays++
    if ($global:ReplayClears) { [IO.File]::Delete($Layout.PendingPath) }
}
function Get-DefenseClawLifecycleStatus {
    param($Action, $Layout, $GatewayServiceName, $GuardianServiceName)
    [pscustomobject]@{ action = $Action.ToLowerInvariant(); ok = $true; transaction_pending = [IO.File]::Exists($Layout.PendingPath) }
}
function Invoke-DefenseClawExactScopeRecoveryPurge { return 'purged' }
function Invoke-Case([string]$Name, [string[]]$Records, [bool]$Transaction, [bool]$ReplayClears) {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
    foreach ($folder in 'install', 'lock') { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($root, $folder)) }
    foreach ($record in $Records) { [IO.File]::WriteAllText($layout[$record], '{}') }
    if ($Transaction) { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($layout.TransactionsDirectory, 'txn-1')) }
    $global:Replays = 0
    $global:ReplayClears = $ReplayClears
    $outcome = 'settled'
    try {
        $status = Invoke-DefenseClawTimeoutRecovery -Layout $layout -GatewayServiceName gateway -GuardianServiceName guardian
        if ($status.action -cne 'recover' -or [bool]$status.transaction_pending) { $outcome = 'wrong status' }
    }
    catch { $outcome = $_.Exception.Message }
    $purge = 'purged'
    try {
        [void](Invoke-DefenseClawUntrustedMetadataRecoveryPurge -Layout $layout -Sources @{} -GatewayServiceName gateway -GuardianServiceName guardian -Reason test)
    }
    catch { $purge = $_.Exception.Message }
    $kept = @($Records | Where-Object { [IO.File]::Exists($layout[$_]) })
    [pscustomobject]@{ name = $Name; outcome = $outcome; replays = $global:Replays; kept = $kept; purge = $purge } |
        ConvertTo-Json -Compress
}
Invoke-Case 'replayed' @('PendingPath') $false $true
Invoke-Case 'replay kept pending' @('PendingPath') $false $false
Invoke-Case 'nothing left' @() $false $false
Invoke-Case 'purge intent' @('PurgeIntentPath') $false $false
Invoke-Case 'pending and rollback intent' @('PendingPath', 'InstallRollbackIntentPath') $false $true
Invoke-Case 'journals' @('ManagedHooksTeardownJournalPath', 'SelfUninstallReceiptPath') $false $false
Invoke-Case 'transaction directory' @() $true $false
"""


def test_timeout_recovery_reports_settled_only_when_no_lifecycle_record_remains(tmp_path: Path) -> None:
    """Finding 4 of the r104 Windows re-fix review, executed: Setup's timeout
    recovery replays only pending.json, so it reports a settled deployment only
    when neither that journal nor any other lifecycle record remains, keeps
    every record it cannot replay and names it. The untrusted-metadata purge
    refuses on the same records, from the same list."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    functions = "\n".join(
        _function_body(module, name)
        for name in (
            "Get-DefenseClawUnfinishedLifecycleEvidence",
            "Invoke-DefenseClawTimeoutRecovery",
            "Invoke-DefenseClawUntrustedMetadataRecoveryPurge",
        )
    )
    harness = tmp_path / "timeout-recovery.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + functions
        + "\n"
        + _TIMEOUT_RECOVERY_HARNESS.replace("__ROOT__", str(tmp_path / "state")),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}

    def kept(name: str) -> list[str]:
        value = cases[name]["kept"]
        return [value] if isinstance(value, str) else list(value or [])

    assert cases["replayed"]["outcome"] == "settled" and cases["replayed"]["replays"] == 1
    assert cases["nothing left"]["outcome"] == "settled" and cases["nothing left"]["replays"] == 0
    assert "still pending" in cases["replay kept pending"]["outcome"]
    assert kept("replay kept pending") == ["PendingPath"]
    assert cases["purge intent"]["outcome"].endswith("as LocalSystem: state-purge intent")
    assert cases["purge intent"]["replays"] == 0 and kept("purge intent") == ["PurgeIntentPath"]
    rollback = cases["pending and rollback intent"]
    assert rollback["replays"] == 1 and rollback["outcome"].endswith(": install-rollback intent")
    assert kept("pending and rollback intent") == ["InstallRollbackIntentPath"]
    assert cases["journals"]["outcome"].endswith(": managed-hook teardown journal, self-uninstall receipt")
    assert cases["transaction directory"]["outcome"].endswith(": unfinished transaction directory")
    for name in ("purge intent", "pending and rollback intent", "journals", "transaction directory"):
        assert "did not settle the deployment" in cases[name]["outcome"], name
    for name in ("nothing left", "replayed"):
        assert cases[name]["purge"] == "purged", cases[name]
    assert "requires authenticated recovery of the existing state-purge intent" in cases["purge intent"]["purge"]
    assert "unfinished transaction directory; exact-scope fallback" in cases["transaction directory"]["purge"]
    assert "existing pending transaction" in cases["replay kept pending"]["purge"]


_FAKE_RENAME_NATIVE = r"""
class FakeNative {
    static [object[]] GetFileHolders([string[]]$Paths) {
        if ($global:RmThrows) { throw 'Restart Manager session start failed' }
        return $global:RmHolders
    }
    static [int] GetDirectoryOpenError([string]$Path, [uint32]$Access) {
        if ($global:OpenThrows) { throw 'CreateFileW is unavailable' }
        $code = $global:OpenErrors[[int]$Access]
        if ($null -eq $code) { return 0 }
        return [int]$code
    }
}
$global:OpenErrors = @{}
$global:OpenThrows = $false
"""


def test_a_committed_retirement_defers_only_to_a_holder_it_finds(tmp_path) -> None:
    # W4 review, loop round 1: access denied is what both a program holding
    # a file in InstallRoot and an access list (a deny on InstallRoot or its
    # parent) answer to the rename. Every such refusal was deferred to the
    # finalizer, so a self-uninstall reported ok with InstallRoot in place
    # and a finalizer that could never finish. Only a holder found after the
    # refusal (an image run from InstallRoot or a Restart Manager holder,
    # other than this lifecycle and the calling CLI) defers now; any other
    # refusal fails the committed uninstall, and other errors are unchanged.
    source = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "Test-DefenseClawInstallRootInUseException",
            "Format-DefenseClawProcessInUse",
            "Get-DefenseClawInstallRootHolders",
            "Get-DefenseClawInstallRootRenameDenial",
            "Invoke-DefenseClawCommittedInstallRootRetirement",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
$script:StateFileInUseCheckLimit = 16384
$source = '""" + str(source) + r"""'
$destination = $source + '.retired'
function Get-DefenseClawProcessImages { return $global:Images }
function Move-DefenseClawInstallRootForRetirement([string]$Source, [string]$Destination) {
    switch ($global:Failure) {
        'denied' { throw [UnauthorizedAccessException]::new("Access to the path '$Source' is denied.") }
        'sharing' { throw [IO.IOException]::new('The process cannot access the file because it is being used by another process.', -2147024864) }
        'missing' { throw [IO.DirectoryNotFoundException]::new('Could not find a part of the path.') }
        default { [IO.Directory]::Move($Source, $Destination) }
    }
}
function Invoke-Case([string]$Name, [string]$Failure, $Images, $RmHolders, [bool]$RmThrows, [string]$Expect, [string]$Text,
    [hashtable]$OpenErrors = @{}, [bool]$OpenThrows = $false) {
    $global:OpenErrors = $OpenErrors
    $global:OpenThrows = $OpenThrows
    if ([IO.Directory]::Exists($destination)) { [IO.Directory]::Delete($destination, $true) }
    if ([IO.Directory]::Exists($source)) { [IO.Directory]::Delete($source, $true) }
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($source, 'bin'))
    [IO.File]::WriteAllText([IO.Path]::Combine($source, 'bin', 'defenseclaw-hook.exe'), 'stand-in')
    $global:Failure = $Failure
    $global:Images = @($Images)
    $global:RmHolders = [object[]]@($RmHolders)
    $global:RmThrows = $RmThrows
    $outcome = 'retired'
    $message = ''
    try {
        $message = Invoke-DefenseClawCommittedInstallRootRetirement -Source $source -Destination $destination -SelfUninstallCallerPID 777
        if (-not [string]::IsNullOrEmpty($message)) { $outcome = 'deferred' }
    }
    catch {
        $outcome = 'failed'
        $message = $_.Exception.Message
    }
    if ($outcome -ne $Expect -or ($Text -and $message -notlike "*$Text*")) {
        throw "${Name}: $outcome, '$message' (want $Expect, *$Text*)"
    }
    if ($outcome -ne 'retired' -and (-not [IO.Directory]::Exists($source) -or [IO.Directory]::Exists($destination))) {
        throw "${Name}: InstallRoot was not left in place"
    }
    Write-Host "${Name}: $outcome"
}
$hook = [pscustomobject]@{ Id = 4242; Path = ($source + '\bin\defenseclaw-hook.exe'); UserName = 'CORP\alice'; Parent = 'claude' }
$self = [pscustomobject]@{ Id = $PID; Path = ($source + '\bin\pwsh.exe'); UserName = ''; Parent = '' }
$caller = [pscustomobject]@{ Id = 777; Path = ($source + '\bin\defenseclaw.exe'); UserName = ''; Parent = '' }
$elsewhere = [pscustomobject]@{ Id = 31; Path = 'C:\Windows\explorer.exe'; UserName = ''; Parent = '' }
$scanner = [pscustomobject]@{ ProcessId = 5151; AppName = 'Scanner'; ServiceName = '' }
$callerHolder = [pscustomobject]@{ ProcessId = 777; AppName = 'defenseclaw'; ServiceName = '' }
$selfHolder = [pscustomobject]@{ ProcessId = $PID; AppName = 'pwsh'; ServiceName = '' }
Invoke-Case 'denied with no holder' 'denied' @($elsewhere) @() $false 'failed' 'no program holds a file in it'
Invoke-Case 'sharing with no holder' 'sharing' @() @() $false 'failed' 'no program holds a file in it'
Invoke-Case 'only this lifecycle and the caller' 'denied' @($self, $caller) @($callerHolder, $selfHolder) $false 'failed' 'run the uninstall again'
Invoke-Case 'Restart Manager failed' 'denied' @() @() $true 'failed' 'is denied'
Invoke-Case 'an image from InstallRoot' 'denied' @($hook, $caller) @() $false 'deferred' 'defenseclaw-hook.exe (pid 4242, account CORP\alice, started by claude)'
Invoke-Case 'a Restart Manager holder' 'sharing' @($elsewhere) @($scanner, $callerHolder) $false 'deferred' 'Scanner (pid 5151)'
Invoke-Case 'another error' 'missing' @($hook) @() $false 'failed' 'Could not find a part of the path'
Invoke-Case 'a free InstallRoot' 'none' @() @() $false 'retired' ''
# W4 review, loop round 2: a holder defers only a rename this account has
# the rights for. DELETE is 0x10000 on InstallRoot, add-subfolder 0x4 on
# its parent; 5 is access denied, 19 a read-only volume, 32 a sharing
# violation (a window on InstallRoot, which ends when it closes).
Invoke-Case 'a deny on InstallRoot with a holder' 'denied' @($hook) @() $false 'failed' 'may not rename' @{ 65536 = 5 }
Invoke-Case 'a deny in the parent with a holder' 'denied' @($hook) @($scanner) $false 'failed' 'may not create a folder in' @{ 4 = 5 }
Invoke-Case 'a deny in the parent with a sharing holder' 'sharing' @($elsewhere) @($scanner) $false 'failed' 'does not end when a program exits' @{ 4 = 5 }
Invoke-Case 'a read-only volume with a holder' 'denied' @($hook) @() $false 'failed' 'may not rename' @{ 65536 = 19 }
Invoke-Case 'the rights check fails with a holder' 'denied' @($hook) @() $false 'failed' 'could not be checked' @{} $true
Invoke-Case 'a window on InstallRoot with a holder' 'denied' @($hook) @() $false 'deferred' 'defenseclaw-hook.exe (pid 4242' @{ 65536 = 32 }
""",
    )
    module = _text(MODULE)
    uninstall = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    call = uninstall.index("$retirementDeferred = Invoke-DefenseClawCommittedInstallRootRetirement `")
    assert "-SelfUninstallCallerPID $SelfUninstallCallerPID" in uninstall[call : call + 300]


def test_the_deferred_retirement_stops_at_once_on_a_rename_this_account_may_not_do(tmp_path) -> None:
    # W4 review, loop round 2: the finalizer waited out its deadline on any
    # access denied, though a deny entry set after the deferral does not end
    # when the holder exits. It stops at once on a missing right; a holder
    # alone is still waited for, and a free InstallRoot is retired.
    install_root = tmp_path / "DefenseClaw"
    _run_lifecycle_functions(
        tmp_path,
        [
            "Test-DefenseClawInstallRootInUseException",
            "Get-DefenseClawInstallRootRenameDenial",
            "Complete-DefenseClawDeferredSelfUninstallRetirement",
        ],
        _FAKE_RENAME_NATIVE
        + r"""
function Initialize-DefenseClawNativeSecurity { return [FakeNative] }
function Enter-DefenseClawLifecycleLock($Layout) { return 'lock' }
function Exit-DefenseClawLifecycleLock($Lock) {}
function Test-DefenseClawSelfUninstallCallerRunning($Layout, $Receipt) { return $false }
function Assert-DefenseClawDeferredRetirementState($Layout, $Receipt) {}
function Complete-DefenseClawCommittedManagedHooksFinalization($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Purge) {}
function Assert-DefenseClawInstallRootNameReserved($InstallRoot) {}
function Complete-DefenseClawRetiredSelfUninstallCommit($Layout, $Receipt) {}
$installRoot = '""" + str(install_root) + r"""'
$retired = $installRoot + '.retired'
$layout = @{ InstallRoot = $installRoot }
$receipt = [pscustomobject]@{ phase = 'prepared_install_retirement'; retired_install_root = $retired; purge_requested = $false; gateway_service = 'g'; guardian_service = 'h' }
function Get-DefenseClawSelfUninstallReceipt($Layout, $GatewayServiceName, $GuardianServiceName) { return $receipt }
function Invoke-TestRename([string]$From, [string]$To) {
    $global:Renames++
    if ($global:Renames -le $global:Refusals) { throw [UnauthorizedAccessException]::new("Access to the path '$From' is denied.") }
    [IO.Directory]::Move($From, $To)
}
function Invoke-Case([string]$Name, [int]$Refusals, [hashtable]$OpenErrors, [int]$Seconds, [string]$Expect, [string]$Text) {
    if ([IO.Directory]::Exists($retired)) { [IO.Directory]::Delete($retired, $true) }
    [void][IO.Directory]::CreateDirectory($installRoot)
    $global:Renames = 0
    $global:Refusals = $Refusals
    $global:OpenErrors = $OpenErrors
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $outcome = Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $layout -Receipt $receipt `
            -Deadline ([DateTime]::UtcNow.AddSeconds($Seconds)) -RetryIntervalMilliseconds 50
        $message = ''
    }
    catch {
        $outcome = 'failed'
        $message = $_.Exception.Message
    }
    if ($outcome -ne $Expect -or ($Text -and $message -notlike "*$Text*")) {
        throw "${Name}: $outcome, '$message' (want $Expect, *$Text*)"
    }
    if ($Name -like 'a deny*' -and ($global:Renames -ne 1 -or $clock.Elapsed.TotalSeconds -ge 5)) {
        throw "${Name}: waited ($global:Renames renames, $($clock.Elapsed.TotalSeconds) s)"
    }
    Write-Host "${Name}: $outcome"
}
Invoke-Case 'a deny in the parent' 99 @{ 4 = 5 } 20 'failed' 'may not create a folder in'
Invoke-Case 'a deny on InstallRoot' 99 @{ 65536 = 5 } 20 'failed' 'may not rename'
Invoke-Case 'a holder past the deadline' 99 @{} 1 'failed' 'a program still holds a file in InstallRoot'
Invoke-Case 'a holder that lets go' 3 @{} 20 'retired' ''
""",
        replacements=[("[IO.Directory]::Move($Layout.InstallRoot, $retiredRoot)", "Invoke-TestRename $Layout.InstallRoot $retiredRoot")],
    )


def test_install_preparation_keeps_existing_service_read_access(tmp_path) -> None:
    _run_lifecycle_functions(tmp_path, ["Initialize-DefenseClawTransactionManagedRoot"], r"""
function Test-DefenseClawStandaloneProfile { return $true }
function Get-DefenseClawInstallRollbackIntent { return @{ install_root_marker_sid = '' } }
function Set-DefenseClawInstallPreparationRootIdentity {}
function Initialize-DefenseClawManagedRoot {
    param($Path, $Label, $RequiredBase, [switch]$AllowUsersRead, [switch]$PassThruCreationResult,
        $StagingMarkerSID, [switch]$DeferFinalAcl, [switch]$KeepProtectedAcl)
    if (-not $KeepProtectedAcl) { throw 'preparation removed the existing gateway read ACE' }
    return @{ created = $false }
}
Initialize-DefenseClawTransactionManagedRoot -Layout @{} -GatewayServiceName Gateway `
    -GuardianServiceName Guardian -Root install_root -Path existing -Label InstallRoot -RequiredBase base
""")



def test_standalone_replacement_retries_transient_hook_readers(tmp_path) -> None:
    # Holders come and go under registered hook traffic. Retry the atomic
    # operation while keeping the launcher present on every attempt.
    _run_lifecycle_functions(tmp_path, ["Install-DefenseClawFileAtomic"], r"""
function Test-DefenseClawStandaloneProfile { return $true }
function Assert-DefenseClawNoReparsePath {}
function New-DefenseClawDirectory { param($Path) [void][IO.Directory]::CreateDirectory($Path) }
function Remove-DefenseClawStaleReplacementBackups {}
function Remove-DefenseClawReplacementBackup { param($Path) [IO.File]::Delete($Path); return $true }
function ConvertTo-DefenseClawBoundedDiagnostic { param($Value, $MaxLength) return $Value }
$script:attempts = 0
function Invoke-TestMappedImageReplace {
    $script:attempts++
    if (-not [IO.File]::Exists($Destination)) { throw 'launcher missing during replacement' }
    if ($script:attempts -lt 3) { throw [IO.IOException]::new('transient hook reader', -2147024864) }
    [IO.File]::Replace($temporary, $Destination, $backup, $true)
}
$root = Split-Path -Parent $PSCommandPath
$source = Join-Path $root 'new.exe'
$destination = Join-Path $root 'hook.exe'
[IO.File]::WriteAllText($source, 'new verified executable')
[IO.File]::WriteAllText($destination, 'old mapped executable')
Install-DefenseClawFileAtomic -Source $source -Destination $destination
if ($script:attempts -ne 3) { throw 'hook reader was not retried' }
if ([IO.File]::ReadAllText($destination) -cne 'new verified executable') { throw 'replacement failed' }
if (@(Get-ChildItem $root -Filter 'hook.exe.backup.*').Count) { throw 'replacement left a backup' }
""", replacements=[("[IO.File]::Replace($temporary, $Destination, $backup, $true)", "Invoke-TestMappedImageReplace")])



def test_service_start_mode_refusal_names_the_modes(tmp_path) -> None:
    import shutil

    shell = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if not shell:
        pytest.skip("PowerShell is unavailable")
    module = _text(MODULE)
    body = _function_body(module, "Assert-DefenseClawServiceConfiguration")
    # Stub registry reads only; run the real configuration checker.
    body = body.replace("Microsoft.PowerShell.Management\\Get-ItemProperty", "Get-TestServiceProperties")
    helpers = _function_body(module, "ConvertTo-DefenseClawServiceStartModeName")
    script = tmp_path / "service-modes.ps1"
    script.write_text(helpers + "\n" + body + r"""
$ErrorActionPreference = 'Stop'
$script:ServiceDescription = 'test service'
function Test-DefenseClawServiceExists { return $true }
function Test-DefenseClawStandaloneProfile { return $true }
function Get-TestServiceProperties {
    return [pscustomobject]@{ ImagePath='image'; ObjectName='account'; DisplayName='test';
        Description='test service'; Type=16; Start=4 }
}
try {
    Assert-DefenseClawServiceConfiguration -Name test -ExpectedImage image -ExpectedAccount account `
        -ExpectedDisplayName test -ExpectedSidType 1 -ExpectedPrivileges @('priv') -ExpectedEnvironment @()
    throw 'disabled service passed verification'
} catch {
    if ($_.Exception.Message -notmatch 'startup mode drift: disabled, expected auto') { throw }
}
""", encoding="utf-8")
    result = subprocess.run([shell, "-NoProfile", "-File", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_snapshot_directory_left_after_the_commit_never_rolls_the_deployment_back(tmp_path) -> None:
    # fix/r104-windows: Complete-DefenseClawTransaction removed pending.json
    # (the commit) and then the snapshot directory; a removal that failed
    # part-way (a scanner holding one copy) threw into the lifecycle's catch,
    # which restored the proven deployment from the half-deleted snapshot
    # with no pending record left to recover it. Now the commit stands and
    # the directory left behind is named in a warning.
    state = tmp_path / "state"
    _run_lifecycle_functions(
        tmp_path,
        ["Complete-DefenseClawTransaction"],
        r"""
$state = '""" + str(state) + r"""'
$transaction = Join-Path (Join-Path $state 'transactions') 'abc'
[void][IO.Directory]::CreateDirectory($transaction)
$snapshot = Join-Path $transaction 'transaction.json'
[IO.File]::WriteAllText($snapshot, '{"gateway_service":"g","guardian_service":"h"}')
[IO.File]::WriteAllText((Join-Path $transaction 'copy.bin'), 'held')
$pending = Join-Path $state 'pending.json'
$Layout = @{ PendingPath = $pending; StateRoot = $state }
function Assert-DefenseClawNoReparsePath([string]$Path) {}
function Assert-DefenseClawDescendant { param($Path, $Root, $Label) return $Path }
function Set-DefenseClawInstallRollbackIntentCommitted { return $null }
function Publish-DefenseClawInstallRollbackIntent { return $null }
function Remove-Item {
    param([string]$LiteralPath, [switch]$Recurse, [switch]$Force, $ErrorAction)
    if ($Recurse) { throw 'The process cannot access the file copy.bin because it is being used by another process.' }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force
}
foreach ($rollback in @($false, $true)) {
    [IO.File]::WriteAllText($pending, '{}')
    $warnings = @()
    Complete-DefenseClawTransaction -SnapshotPath $snapshot -Layout $Layout -Rollback:$rollback -WarningVariable warnings -WarningAction SilentlyContinue
    if (Test-Path -LiteralPath $pending) { throw "rollback=${rollback}: the commit did not remove pending.json" }
    if (-not (Test-Path -LiteralPath $transaction)) { throw "rollback=${rollback}: the stub did not hold the directory" }
    if (-not ($warnings -join ' ').Contains($transaction)) { throw "rollback=${rollback}: the warning does not name the directory: $warnings" }
}
""",
        replacements=[
            ("Microsoft.PowerShell.Management\\Remove-Item -LiteralPath $directory", "Remove-Item -LiteralPath $directory"),
        ],
    )


_UNINSTALL_PRECHECK_HARNESS = r"""
$global:Calls = [Collections.Generic.List[string]]::new()
function Assert-DefenseClawAdministrator { $global:Calls.Add('admin') }
function Get-DefenseClawDeploymentMetadata {
    param([hashtable]$Layout)
    $global:Calls.Add('metadata')
    return $global:Metadata
}
function Test-DefenseClawMetadataInstalled {
    param($Metadata)
    return [bool]$Metadata.installed
}
function Assert-DefenseClawStandaloneInstallTreeNotInUse {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName, [int]$SelfUninstallCallerPID)
    $global:Calls.Add("install-tree:$SelfUninstallCallerPID")
    if ($global:TreeInUse) {
        throw 'uninstall_in_use: defenseclaw-acp.exe (pid 4) runs from C:\bin\, so DefenseClaw cannot remove its files; nothing was changed.'
    }
}
function Assert-DefenseClawStandaloneStateFilesNotInUse {
    param([hashtable]$Layout, [string]$GatewayServiceName, [string]$GuardianServiceName, [int]$SelfUninstallCallerPID)
    $global:Calls.Add("state-files:$SelfUninstallCallerPID")
    if ($global:StateInUse) {
        throw 'uninstall_in_use: a SIEM forwarder holds runtime\audit.db, which the purge deletes, so DefenseClaw cannot remove its data; nothing was changed.'
    }
}
$root = '__ROOT__'
$layout = @{ PendingPath = [IO.Path]::Combine($root, 'install', 'pending.json') }
function Invoke-Case([string]$Name, $Metadata, [bool]$Pending, [bool]$TreeInUse, [bool]$StateInUse) {
    $global:Calls.Clear()
    $global:Metadata = $Metadata
    $global:TreeInUse = $TreeInUse
    $global:StateInUse = $StateInUse
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($layout.PendingPath))
    if ($Pending) { [IO.File]::WriteAllText($layout.PendingPath, '{}') }
    elseif ([IO.File]::Exists($layout.PendingPath)) { [IO.File]::Delete($layout.PendingPath) }
    $outcome = ''
    $report = $null
    try {
        $report = Invoke-DefenseClawStandaloneUninstallPrecheck -Layout $layout `
            -GatewayServiceName 'DefenseClawGateway' -GuardianServiceName 'DefenseClawGuardian' -SelfUninstallCallerPID 4242
        $outcome = 'ok'
    }
    catch {
        $outcome = $_.Exception.Message
    }
    [pscustomobject]@{
        name = $Name
        outcome = $outcome
        calls = @($global:Calls)
        precheck = ($null -ne $report -and [bool]$report.uninstall_precheck -and [bool]$report.ok -and $report.schema_version -eq 1)
    } | ConvertTo-Json -Compress
}
Invoke-Case 'installed, nothing in use' ([pscustomobject]@{ installed = $true }) $false $false $false
Invoke-Case 'a program runs from the install folder' ([pscustomobject]@{ installed = $true }) $false $true $false
Invoke-Case 'a program holds a data file' ([pscustomobject]@{ installed = $true }) $false $false $true
Invoke-Case 'pending transaction' ([pscustomobject]@{ installed = $true }) $true $true $true
Invoke-Case 'tombstone' ([pscustomobject]@{ installed = $false }) $false $true $true
Invoke-Case 'no deployment record' $null $false $true $true
"""


def test_uninstall_precheck_reads_the_uninstall_refusals_and_changes_nothing(tmp_path: Path) -> None:
    """Review P2 (q-win-lifecycle loop round 3), executed: the read-only
    precheck the CLI runs before an uninstall removes the protected session
    keys throws exactly the uninstall's own refusals for an installed
    deployment (a program runs from or holds a file in the install folder, or
    holds a data file the purge deletes), naming the self-uninstall caller,
    and passes a pending transaction or a deployment that is not installed,
    which the uninstall recovers or finishes first. It reaches the module
    only as a standalone Status request carried in the environment, so the
    installer's parameter set is unchanged and an installer that does not
    know it answers a plain status."""
    import json

    engine = _portable_pwsh()
    if engine is None:
        pytest.skip("PowerShell 7 (pwsh) is not installed")
    module = _text(MODULE)
    harness = tmp_path / "uninstall-precheck.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        + _function_body(module, "Invoke-DefenseClawStandaloneUninstallPrecheck")
        + "\n"
        + _UNINSTALL_PRECHECK_HARNESS.replace("__ROOT__", str(tmp_path / "state")),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    cases = {case["name"]: case for case in map(json.loads, completed.stdout.strip().splitlines())}

    def calls(name: str) -> list[str]:
        value = cases[name]["calls"]
        return [value] if isinstance(value, str) else list(value or [])

    clean = cases["installed, nothing in use"]
    assert clean["outcome"] == "ok" and clean["precheck"], clean
    assert calls("installed, nothing in use") == ["admin", "metadata", "install-tree:4242", "state-files:4242"]
    tree = cases["a program runs from the install folder"]
    assert tree["outcome"].startswith("uninstall_in_use: ") and "nothing was changed" in tree["outcome"]
    assert calls("a program runs from the install folder") == ["admin", "metadata", "install-tree:4242"]
    state = cases["a program holds a data file"]
    assert state["outcome"].startswith("uninstall_in_use: ") and "audit.db" in state["outcome"]
    assert calls("a program holds a data file") == ["admin", "metadata", "install-tree:4242", "state-files:4242"]
    assert cases["pending transaction"]["outcome"] == "ok" and calls("pending transaction") == ["admin"]
    for name in ("tombstone", "no deployment record"):
        assert cases[name]["outcome"] == "ok" and cases[name]["precheck"], cases[name]
        assert calls(name) == ["admin", "metadata"], cases[name]

    # The module runs it only for a standalone Status, before the status
    # report; the installer maps the CLI's request onto it only for Status,
    # clears the variable, and takes only a pid.
    dispatcher = _function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    status = dispatcher[dispatcher.index("    if ($Action -eq 'Status') {") :]
    status = status[: status.index("\n    }\n")]
    assert status.index("Invoke-DefenseClawStandaloneUninstallPrecheck") < status.index("Get-DefenseClawLifecycleStatus")
    assert "throw '-UninstallPrecheck is valid only with a standalone Status'" in dispatcher
    installer = _text(INSTALLER)
    request = installer[installer.index("$uninstallPrecheckRequest = ") :]
    request = request[: request.index("\n        }\n")]
    assert "SetEnvironmentVariable('DEFENSECLAW_STANDALONE_UNINSTALL_PRECHECK', $null, 'Process')" in request
    assert "$Action -eq 'Status'" in request and "-cmatch '^[0-9]{1,9}$'" in request
    assert "$arguments['UninstallPrecheck'] = $true" in request
    go = (ROOT / "internal" / "cli" / "windows_enterprise_standalone.go").read_text(encoding="utf-8")
    assert 'windowsEnterpriseUninstallPrecheckVariable = "DEFENSECLAW_STANDALONE_UNINSTALL_PRECHECK"' in go
