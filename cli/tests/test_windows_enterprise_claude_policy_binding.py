# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Claude effective-policy evidence binding contracts (#895).

The evidence written by ``Repair -AttestClaudeEffectivePolicy`` used to be
bound to the SHA-256 of ``targets.yaml``. The enumerator rewrites that file on
every enrollment change, after which every administrator lifecycle action,
including the re-attesting Repair and Uninstall, threw before doing any work.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-claude-policy-binding-smoke.ps1"


def _slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


def test_evidence_is_bound_to_the_claude_policy_identity_not_the_manifest() -> None:
    module = MODULE.read_text(encoding="utf-8")
    assert "$script:AgentApplicationControlAttestationSchemaVersion = 3" in module
    assert "$script:LegacyAgentApplicationControlAttestationSchemaVersion = 2" in module

    binding = _slice(
        module,
        "function Get-DefenseClawClaudeEffectivePolicyBinding",
        "function Write-DefenseClawAgentApplicationControlAttestation",
    )
    assert "$Layout.ClaudeManagedPolicyPath" in binding
    assert "$Layout.ClaudeManagedPolicyStatePath" in binding
    assert "$Layout.HookPath" in binding
    assert '"sha256:$policySha256"' in binding
    # Enrollment churn must not change the identity.
    assert "ManifestPath" not in binding
    assert "target_sids" not in binding

    writer = _slice(
        module,
        "function Write-DefenseClawAgentApplicationControlAttestation",
        "function Initialize-DefenseClawCodexMachinePolicyParent",
    )
    assert "claude_effective_policy_managed_policy_sha256 = $claudePolicyHash" in writer
    assert "claude_effective_policy_hook_sha256 = $claudeHookHash" in writer
    assert "claude_effective_policy_manifest_sha256" not in writer
    assert "ManifestPath" not in writer
    assert "refusing to re-publish stale Claude effective-policy evidence" in writer

    layout = _slice(module, "function Get-DefenseClawLayout", "function Assert-DefenseClawLayoutVolumeIdentity")
    assert "'90-defenseclaw.json'" in layout
    assert "ClaudeEffectivePolicyStaleReason = ''" in layout


def test_stale_evidence_degrades_instead_of_throwing() -> None:
    module = MODULE.read_text(encoding="utf-8")
    reader = _slice(
        module,
        "function Get-DefenseClawAgentApplicationControlAttestation",
        "function Get-DefenseClawClaudeEffectivePolicyBinding",
    )
    assert "is stale for the installed manifest" not in reader
    assert "Get-FileHash" not in reader
    assert "$claudeStaleReason = ''" in reader
    assert "-NotePropertyName 'claude_effective_policy_stale_reason'" in reader
    # A binding lookup failure is a reason, not a lifecycle failure.
    lookup = reader[reader.index("Get-DefenseClawClaudeEffectivePolicyBinding `") :]
    handler = lookup[lookup.index("catch {") :]
    handler = handler[: handler.index("}")]
    assert "$claudeStaleReason = (" in handler
    assert "throw" not in handler

    status = _slice(module, "function Get-DefenseClawLifecycleStatus", "function Test-DefenseClawGuardianCoverageReport")
    assert "claude_effective_policy_stale_reason = $(" in status
    stale_at = status.index("if (-not [string]::IsNullOrEmpty($claudeEffectivePolicyStaleReason)) {")
    assert status.index("$claudeEffectivePolicyVerified = $false", stale_at) < status.index(
        "$externalSecuritySatisfied = [bool]("
    )


def test_lifecycle_retires_stale_evidence_and_never_rebinds_it() -> None:
    module = MODULE.read_text(encoding="utf-8")
    install_like = _slice(
        module,
        "function Invoke-DefenseClawInstallLikeLifecycle",
        "function Invoke-DefenseClawUninstallLifecycle",
    )
    retire = install_like[install_like.index("# Evidence recorded for another Claude policy identity is retired") :]
    retire = retire[: retire.index("if ($Action -ne 'Install') {")]
    assert "$Layout.ClaudeEffectivePolicyVerified = $false" in retire
    assert "$attestationNeedsRefresh = $true" in retire
    guard = install_like[: install_like.index("# Evidence recorded for another Claude policy identity is retired")]
    assert guard.rstrip().endswith("[string]$Layout.ClaudeEffectivePolicyStaleReason)) {")
    assert "-not $RefreshClaudeEffectivePolicyAttestation -and" in guard[guard.rindex("if (") :]
    # Retirement happens before the first protected inspect so the report and
    # the service environment agree with the degraded result.
    assert install_like.index("# Evidence recorded for another Claude policy identity is retired") < install_like.index(
        "$targetReport = Invoke-DefenseClawCodexRequirementsCommand"
    )

    entry = _slice(module, "function Invoke-DefenseClawEnterpriseLifecycle", "Export-ModuleMember")
    assert "$layout.ClaudeEffectivePolicyStaleReason = [string](" in entry
    requested = _slice(
        module,
        "function Set-DefenseClawRequestedAttestations",
        "function Get-DefenseClawAgentApplicationControlAttestation",
    )
    attest = requested[requested.index("if ($AttestClaudeEffectivePolicy) {") :]
    assert "$Layout.ClaudeEffectivePolicyVerified = $true" in attest
    assert "$Layout.ClaudeEffectivePolicyStaleReason = ''" in attest
    assert "-AttestClaudeEffectivePolicy is forbidden in core-hardening certification mode" in attest
    assert "$Layout.AgentApplicationControlAttested = $true" in requested
    call = "Set-DefenseClawRequestedAttestations `"
    assert entry.count(call) == 2
    assert entry.index(call) < entry.index("if ($Action -eq 'Status') {")


def test_explicit_attestations_survive_pending_recovery() -> None:
    # Review of #895: Restore-DefenseClawTransaction resets the layout to the
    # interrupted transaction's claim and the restored evidence's stale
    # reason, which made Repair -AttestClaudeEffectivePolicy throw
    # "refusing to re-publish stale Claude effective-policy evidence".
    module = MODULE.read_text(encoding="utf-8")
    entry = _slice(module, "function Invoke-DefenseClawEnterpriseLifecycle", "Export-ModuleMember")
    last_recovery = entry.rindex("Recover-DefenseClawPendingTransaction `")
    reapply = entry.rindex("Set-DefenseClawRequestedAttestations `")
    install_like = entry.index("return Invoke-DefenseClawInstallLikeLifecycle `")
    assert last_recovery < reapply < install_like
    # The pre-layout recovery also runs before the install-like lifecycle.
    assert entry.index("Invoke-DefenseClawPreLayoutRecovery `") < reapply
    restore = _slice(module, "function Restore-DefenseClawTransaction {", "function Assert-DefenseClawRestoredTransaction")
    assert "$Layout.ClaudeEffectivePolicyVerified = [bool](" in restore


def test_install_refuses_claude_effective_policy_attestation_up_front() -> None:
    module = MODULE.read_text(encoding="utf-8")
    entry = _slice(module, "function Invoke-DefenseClawEnterpriseLifecycle", "Export-ModuleMember")
    check = entry[entry.index("if ($AttestClaudeEffectivePolicy -and") :]
    check = check[: check.index("if ($CoreHardeningCertification -and")]
    assert "$Action -notin @('Upgrade', 'Repair')" in check
    assert "'-AttestClaudeEffectivePolicy is valid only with Upgrade or ' +" in check
    assert "-AttestClaudeEffectivePolicy is valid only with Install, Upgrade, or Repair" not in module
    # Refused before layout resolution, elevation and the lifecycle lock.
    assert entry.index("if ($AttestClaudeEffectivePolicy -and") < entry.index("Assert-DefenseClawAdministrator")
    assert entry.index("if ($AttestClaudeEffectivePolicy -and") < entry.index("$layout = Get-DefenseClawLayout `")

    deployment = _slice(
        module, "function Assert-DefenseClawEnterpriseDeployment", "function Get-DefenseClawLifecycleStatus"
    )
    assert "$Layout.ClaudeEffectivePolicyStaleReason = [string](" in deployment
    # Metadata and snapshot consistency still compare the recorded claim.
    assert "protected Claude effective-policy evidence disagrees with deployment metadata" in deployment
    restore = _slice(module, "function Restore-DefenseClawTransaction {", "function Assert-DefenseClawRestoredTransaction")
    assert "restored Claude effective-policy evidence does not match the transaction snapshot" in restore
    assert "$restoredAttestation.claude_effective_policy_stale_reason" in restore


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
def test_claude_policy_binding_smoke(engine: str, tmp_path: Path) -> None:
    assert engine != "<no-powershell-engine-found>", "no PowerShell engine found on Windows"
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SMOKE),
            "-ScratchRoot",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Claude effective-policy binding smoke passed" in completed.stdout
