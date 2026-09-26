# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""HKLM Claude Code policy composition contracts (#899).

Any non-empty HKLM\\SOFTWARE\\Policies\\ClaudeCode\\Settings used to refuse Claude
enrollment outright, with no way to produce the hook matrix the refusal asked
for. The gateway now admits a policy that merges managed sources on a client
that honors it, or that already carries the DefenseClaw matrix, and exports
that matrix.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-claude-hklm-policy-smoke.ps1"
MANAGED_POLICY = ROOT / "internal" / "enterprisehooks" / "managed_policy_windows.go"
CONNECTOR_POLICY = ROOT / "internal" / "gateway" / "connector" / "claudecode_policy.go"
CONNECTOR_MERGE = ROOT / "internal" / "gateway" / "connector" / "claudecode_policy_merge.go"
EXPORT = ROOT / "internal" / "cli" / "windows_claude_policy_export.go"


def _slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


def test_install_gate_authenticates_the_key_then_delegates_the_decision() -> None:
    gate = _slice(
        MANAGED_POLICY.read_text(encoding="utf-8"),
        "func defaultWindowsClaudeHigherPolicyCheck(opts connector.SetupOpts) error {",
        "func validateWindowsClaudeRegistryPolicyKey",
    )
    assert gate.index("validateWindowsClaudeRegistryPolicyKey(key)") < gate.index(
        "connector.ClaudeCodeOSAdminPolicyAdmitsManagedHooks("
    )
    assert "deploy the DefenseClaw hook matrix through the existing MDM/GPO source" not in gate


def test_connector_admits_only_merge_on_new_clients_or_the_carried_matrix() -> None:
    merge = CONNECTOR_MERGE.read_text(encoding="utf-8")
    assert 'ClaudeCodeManagedSourcesMergeMinimumVersion = "2.1.242"' in merge
    assert 'ClaudeCodeManagedPolicyExportCommand = "defenseclaw-gateway enterprise windows export-claude-policy"' in merge
    assert 'claudeCodeOSAdminPolicyComposition = runtime.GOOS == "windows"' in merge
    admits = _slice(merge, "func claudeCodeOSAdminAdmitsManagedHooks", "func ClaudeCodeOSAdminPolicyAdmitsManagedHooks")
    # Hook-defeating gates are checked before either admission path.
    assert admits.index("validateClaudeCodeManagedHookControls(source, true)") < admits.index(
        "claudeCodeSourceHasHookContract(source, opts, false)"
    )
    assert "claudeCodeClientHonorsManagedMerge(opts.AgentVersion)" in admits
    policy = CONNECTOR_POLICY.read_text(encoding="utf-8")
    destination = _slice(policy, "func validateClaudeCodeManagedFileDestination(opts SetupOpts) error {", "// Claude documents policyHelper")
    assert "claudeCodeOSAdminAdmitsManagedHooks(managed.osAdmin, opts)" in destination
    audit = _slice(policy, "func claudeCodeEffectiveHookContract", "type claudeCodeManagedSourceSet struct")
    assert "claudeCodeMergedManagedSource(managed.osAdmin, managed.file)" in audit


def test_export_is_hidden_read_only_and_pins_the_installed_hook() -> None:
    export = EXPORT.read_text(encoding="utf-8")
    assert 'Use:   "export-claude-policy"' in export
    assert "Hidden:       true" in export
    assert "connector.ClaudeCodeManagedHookPolicyDocument(" in export
    assert '"defenseclaw-hook.exe"' in export
    # No state, no elevation, no secrets: it renders from the installed layout.
    for forbidden in ("os.WriteFile", "LoadFromFile", "Token", "enterpriseHooksNativePlatformPreflight"):
        assert forbidden not in export


def test_status_reports_hklm_shadowing_with_the_fix() -> None:
    module = MODULE.read_text(encoding="utf-8")
    status = _slice(module, "function Get-DefenseClawLifecycleStatus", "function Test-DefenseClawGuardianCoverageReport")
    assert "claude_policy_shadowed_by_hklm = [bool]$claudeHKLMPolicy.shadowed" in status
    assert "claude_policy_hklm_detail = $claudeHKLMPolicy.detail" in status
    guard = status[status.index("if ($installed -and $claudeTargetEnabled) {") :]
    guard = guard[: guard.index("}\n    }") + 1]
    assert "$claudeEffectivePolicyVerified = $false" in guard
    view = _slice(module, "function Get-DefenseClawClaudeHKLMPolicyState", "function ConvertTo-DefenseClawBoundedDiagnostic")
    assert "[Microsoft.Win32.RegistryView]::Registry64" in view
    assert "SetValue" not in view and "CreateSubKey" not in view
    assert "export-claude-policy" in view
    catch = view[view.index("    catch {") :]
    assert "$state.shadowed = $true" in catch[: catch.index("finally")]


def _powershell_engines() -> list[str]:
    candidates: list[str | None] = [shutil.which("powershell.exe"), shutil.which("pwsh.exe")]
    windows_root = os.environ.get("SystemRoot")
    if windows_root:
        candidates.append(str(Path(windows_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"))
    engines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            resolved = str(Path(candidate).resolve())
            if os.path.normcase(resolved) not in seen:
                seen.add(os.path.normcase(resolved))
                engines.append(resolved)
    if not engines and os.name == "nt":
        return ["<no-powershell-engine-found>"]
    return engines


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell module smoke")
@pytest.mark.parametrize("engine", _powershell_engines())
def test_claude_hklm_policy_smoke(engine: str, tmp_path: Path) -> None:
    assert engine != "<no-powershell-engine-found>", "no PowerShell engine found on Windows"
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SMOKE), "-ScratchRoot", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Claude HKLM policy smoke passed" in completed.stdout
