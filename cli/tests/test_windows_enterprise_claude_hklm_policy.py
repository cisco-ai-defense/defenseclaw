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

import json
import os
import re
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


def test_connector_admits_merge_or_the_carried_matrix_without_trusting_recorded_versions() -> None:
    merge = CONNECTOR_MERGE.read_text(encoding="utf-8")
    assert 'ClaudeCodeManagedSourcesMergeMinimumVersion = "2.1.242"' in merge
    assert 'ClaudeCodeManagedPolicyExportCommand = "defenseclaw-gateway enterprise windows export-claude-policy"' in merge
    assert 'claudeCodeOSAdminPolicyComposition = runtime.GOOS == "windows"' in merge
    admits = _slice(merge, "func claudeCodeOSAdminAdmitsManagedHooks", "func ClaudeCodeOSAdminPolicyAdmitsManagedHooks")
    # Hook-defeating gates are checked before either admission path, and a
    # DefenseClaw hook outside the target contract is refused under both.
    assert admits.index("validateClaudeCodeManagedHookControls(source, true)") < admits.index(
        "claudeCodeOSAdminStrayManagedHookEvent(source, opts)"
    ) < admits.index("claudeCodeOSAdminCarriesManagedHooks(source, opts)")
    # #899 review: the recorded agent_version is written once, at discovery,
    # and is often the installer placeholder, so it must neither admit nor
    # refuse a target under merge; the floor is enforced host-wide.
    assert "opts.AgentVersion" not in admits
    assert "claudeCodeClientHonorsManagedMerge" not in merge
    assert "ErrClaudeCodeManagedMergeUnsupported" not in merge
    assert "claudeCodeMergedManagedSource(source, nil)" in admits
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
    guard = status[status.index("if ($installed -and $claudeTargetEnabled -and") :]
    assert "-not (Test-DefenseClawStandaloneProfile)" in guard[:150]
    guard = guard[: guard.index("}\n    }") + 1]
    assert "$claudeEffectivePolicyVerified = $false" in guard
    view = _slice(module, "function Get-DefenseClawClaudeHKLMPolicyState", "function ConvertTo-DefenseClawBoundedDiagnostic")
    assert "[Microsoft.Win32.RegistryView]::Registry64" in view
    assert "SetValue" not in view and "CreateSubKey" not in view
    assert "export-claude-policy" in view
    catch = view[view.index("    catch {") :]
    assert "shadowed = $true" in catch[: catch.index("finally")]
    assert "Get-DefenseClawClaudeHKLMPolicyVerdict -Raw $raw -Layout $Layout" in view
    verdict = _slice(module, "function Get-DefenseClawClaudeHKLMPolicyVerdict", "function Get-DefenseClawClaudeHKLMPolicyState")
    assert "export-claude-policy" in verdict and "allowManagedHooksOnly" in verdict
    catch = verdict[verdict.index("    catch {") :]
    assert "$state.shadowed = $true" in catch
    # #899 review: settings keys match by exact case, as Claude and the
    # gateway read them; PSObject.Properties[...] ignores case.
    for owner in (
        "function Get-DefenseClawClaudeHKLMPolicyVerdict",
        "function Get-DefenseClawClaudeHKLMHookCopies",
        "function Get-DefenseClawClaudeInstalledHookContract",
        "function Test-DefenseClawClaudeHandlerTargetsHook",
    ):
        body = _slice(module, owner, "\nfunction ")
        assert ".PSObject.Properties['" not in body, owner
        assert "Get-DefenseClawJsonMember" in body, owner


def test_status_reads_the_hklm_policy_as_strict_case_sensitive_json() -> None:
    # #899 review: ConvertFrom-Json accepts comments, trailing commas and
    # single quotes (differently on Windows PowerShell 5.1 and PowerShell 7)
    # and rejects keys that differ only in case, while Claude Code and the
    # gateway do the opposite.
    module = MODULE.read_text(encoding="utf-8")
    verdict = _slice(module, "function Get-DefenseClawClaudeHKLMPolicyVerdict", "function Get-DefenseClawClaudeHKLMPolicyState")
    assert "ConvertFrom-DefenseClawStrictJson -Text $Raw" in verdict
    begin = module.index("function ConvertFrom-DefenseClawStrictJsonString")
    helpers = module[begin : module.index("function Get-DefenseClawClaudeHKLMPolicyState", begin)]
    assert "ConvertFrom-Json" not in helpers.replace("ConvertFrom-Json differs", "")
    assert "PSCustomObject" not in helpers[: helpers.index("function Get-DefenseClawClaudeMergePendingTargets")]
    parser = _slice(module, "function ConvertFrom-DefenseClawStrictJson {", "\nfunction ")
    assert "[StringComparer]::Ordinal" in parser
    assert "JSON nesting exceeds 10000 levels" in parser
    # The remedy names the version the gate compares with: the target's
    # recorded contract, not the client the endpoints happen to run.
    assert "the agent_version recorded for the target" in verdict
    assert "the Claude Code version your endpoints run" not in module


def test_status_and_gate_share_the_hklm_admission_vectors() -> None:
    vectors = ROOT / "internal" / "gateway" / "connector" / "testdata" / "claude_hklm_admission_vectors.json"
    data = json.loads(vectors.read_text(encoding="utf-8"))
    wants = {case["want"] for case in data["cases"]}
    assert wants == {"inactive", "carry", "merge", "refuse"}
    smoke = SMOKE.read_text(encoding="utf-8")
    assert "claude_hklm_admission_vectors.json" in smoke
    assert "Get-DefenseClawClaudeHKLMPolicyVerdict" in smoke
    go_test = (ROOT / "internal" / "gateway" / "connector" / "claudecode_policy_merge_windows_test.go").read_text(
        encoding="utf-8"
    )
    assert "//go:embed testdata/claude_hklm_admission_vectors.json" in go_test
    assert "ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, caseOpts)" in go_test
    # #899 review: Claude Code runs one copy of a repeated DefenseClaw hook and
    # a changed copy can be the one that runs, so it is refused under carry
    # and merge.
    wanted = {case["name"]: case["want"] for case in data["cases"]}
    for name in (
        "merge with a shorter DefenseClaw copy",
        "exported hooks with a shorter PreToolUse copy after them",
        "exported hooks with an async PreToolUse copy after them",
        "merge with a shorter PreToolUse copy after the exported one",
        "merge with an async PreToolUse copy after the exported one",
        "single-quoted JSON",
        "block comment inside the object",
        "trailing comma in the object",
    ):
        assert wanted[name] == "refuse", name
    for name in ("keys that differ only in case", "event keys that differ only in case"):
        assert wanted[name] == "merge", name



def test_module_merge_client_floor_matches_the_connector_constant() -> None:
    module = MODULE.read_text(encoding="utf-8")
    merge = CONNECTOR_MERGE.read_text(encoding="utf-8")
    go = re.search(r"ClaudeCodeManagedSourcesMergeMinimumVersion = \"([0-9.]+)\"", merge)
    ps = re.search(r"\$script:ClaudeManagedSourcesMergeMinimumClientVersion = '([0-9.]+)'", module)
    assert go and ps and go.group(1) == ps.group(1)


def test_status_withholds_claude_verification_under_merge_until_the_floor_is_attested() -> None:
    module = MODULE.read_text(encoding="utf-8")
    view = _slice(module, "function Get-DefenseClawClaudeHKLMPolicyVerdict", "function Get-DefenseClawClaudeHKLMPolicyState")
    # A merge policy that carries the DefenseClaw hooks is effective on every
    # client; only one that relies on merge raises the approved-client floor.
    floor = view[view.index("$merge = [bool]") :]
    assert floor.index("Get-DefenseClawClaudeHKLMHookCopies") < floor.index(
        "$state.merge_client_floor_required = $true"
    )
    status = _slice(module, "function Get-DefenseClawLifecycleStatus", "function Test-DefenseClawGuardianCoverageReport")
    branch = status[status.index("elseif ([bool]$claudeHKLMPolicy.merge_client_floor_required) {") :]
    branch = branch[: branch.index("claude_target_enabled = ")]
    assert "$claudeMinimumClientVersion = $script:ClaudeManagedSourcesMergeMinimumClientVersion" in branch
    assert "Get-DefenseClawClaudeMergePendingTargets -Report $guardianReport" in branch
    assert branch.index("AgentApplicationControlClaudeMinimumVersion") < branch.index(
        "$claudeEffectivePolicyVerified = $false"
    )
    assert "claude_minimum_client_version = $claudeMinimumClientVersion" in status
    assert "claude_policy_hklm_merge_pending_targets = @($claudeMergePendingTargets)" in status
    # security_complete depends on the Claude effective-policy claim.
    external = status[status.index("$externalSecuritySatisfied = [bool](") :]
    assert "$claudeEffectivePolicyVerified" in external[: external.index("return [pscustomobject]")]


def test_attestation_records_the_floor_the_administrator_attested() -> None:
    module = MODULE.read_text(encoding="utf-8")
    requested = _slice(module, "function Set-DefenseClawRequestedAttestations", "function ")
    assert "Get-DefenseClawClaudeRequiredClientVersion -Layout $Layout" in requested
    writer = _slice(module, "function Write-DefenseClawAgentApplicationControlAttestation", "\nfunction ")
    assert "[string]$Layout.AgentApplicationControlClaudeMinimumVersion" in writer
    # Restored and re-read evidence keep the floor they recorded.
    for owner in ("function Restore-DefenseClawTransaction {", "function Assert-DefenseClawEnterpriseDeployment {"):
        body = _slice(module, owner, "\nfunction ")
        assert "$Layout.AgentApplicationControlClaudeMinimumVersion = [string](" in body

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
