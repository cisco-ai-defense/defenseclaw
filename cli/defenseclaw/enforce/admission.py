"""Shared admission evaluation helpers for Python CLI paths.

These helpers intentionally mirror the admission ordering used by the Go
gateway/watcher:

1. Explicit block list entries override everything.
2. Explicit allow list entries override policy and skip scan/enforcement.
3. Policy-managed allow entries (for example first-party bundles) may bypass
   scan depending on the active policy data.
4. If no scan result exists yet, the active policy decides whether scanning is
   required.
5. Once a scan result exists, the effective per-target action mapping decides
   whether the result is rejected or only warned.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from defenseclaw.config import SeverityAction


@dataclass(frozen=True)
class AdmissionDecision:
    verdict: str
    reason: str
    action: SeverityAction = field(default_factory=SeverityAction)
    source: str = ""


@dataclass(frozen=True)
class AdmissionPolicyData:
    allow_list_bypass_scan: bool = True
    scan_on_install: bool = True
    actions: dict[str, SeverityAction] = field(default_factory=dict)
    scanner_overrides: dict[str, dict[str, SeverityAction]] = field(default_factory=dict)
    first_party_allow: dict[tuple[str, str], tuple[str, list[str]]] = field(default_factory=dict)


def evaluate_admission(
    pe: Any,
    *,
    policy_dir: str,
    target_type: str,
    name: str,
    source_path: str = "",
    scan_result: Any | None = None,
    action_entry: Any | None = None,
    fallback_actions: Any | None = None,
    include_quarantine: bool = False,
) -> AdmissionDecision:
    """Evaluate admission for a target using active policy data when available.

    Explicit allow/block entries from the store are always treated as manual
    overrides. Policy-managed allow entries from ``first_party_allow_list`` are
    still subject to the policy's ``allow_list_bypass_scan`` setting.
    """
    blocked_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the block list")
    if pe.is_blocked(target_type, name):
        return AdmissionDecision("blocked", blocked_reason, source="manual-block")

    allowed_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the allow list — scan skipped")
    if pe.is_allowed(target_type, name):
        return AdmissionDecision("allowed", allowed_reason, source="manual-allow")

    if include_quarantine and pe.is_quarantined(target_type, name):
        reason = _action_reason(action_entry, default="quarantined")
        return AdmissionDecision("rejected", f"quarantined: {reason}", source="quarantine")

    policy = load_admission_policy(policy_dir)

    fp_entry = policy.first_party_allow.get((target_type, name))
    if fp_entry is not None and policy.allow_list_bypass_scan:
        fp_reason, fp_constraints = fp_entry
        if _matches_provenance(fp_constraints, source_path):
            return AdmissionDecision("allowed", fp_reason, source="policy-allow")

    if scan_result is None:
        if not policy.scan_on_install:
            return AdmissionDecision(
                "allowed",
                "scan_on_install disabled — allowed without scan",
                source="scan-disabled",
            )
        return AdmissionDecision("scan", "scan required", source="scan-required")

    finding_count, severity = _scan_summary(scan_result)
    action = effective_action_for(
        policy,
        target_type=target_type,
        severity=severity,
        fallback_actions=fallback_actions,
    )

    if finding_count <= 0:
        return AdmissionDecision("clean", "scan clean", action=action, source="scan-clean")

    detail = f"{finding_count} findings, max {severity}"
    if action.install == "block" or action.runtime == "disable":
        return AdmissionDecision("rejected", detail, action=action, source="scan-rejected")

    return AdmissionDecision("warning", detail, action=action, source="scan-warning")


def effective_action_for(
    policy: AdmissionPolicyData,
    *,
    target_type: str,
    severity: str,
    fallback_actions: Any | None = None,
) -> SeverityAction:
    sev = severity.upper()
    target_overrides = policy.scanner_overrides.get(target_type, {})
    if sev in target_overrides:
        return target_overrides[sev]
    if sev in policy.actions:
        return policy.actions[sev]
    if fallback_actions is not None:
        return fallback_actions.for_severity(sev)
    return SeverityAction()


def load_admission_policy(policy_dir: str) -> AdmissionPolicyData:
    data = _read_policy_data(policy_dir)
    if not data:
        return AdmissionPolicyData()

    cfg = data.get("config", {}) or {}
    raw_actions = data.get("actions", {}) or {}
    raw_overrides = data.get("scanner_overrides", {}) or {}
    first_party = data.get("first_party_allow_list", []) or []

    actions = {
        severity.upper(): _severity_action_from_policy(raw)
        for severity, raw in raw_actions.items()
        if isinstance(raw, dict)
    }

    scanner_overrides: dict[str, dict[str, SeverityAction]] = {}
    for target_type, overrides in raw_overrides.items():
        if not isinstance(overrides, dict):
            continue
        scanner_overrides[target_type] = {
            severity.upper(): _severity_action_from_policy(raw)
            for severity, raw in overrides.items()
            if isinstance(raw, dict)
        }

    first_party_allow: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for entry in first_party:
        if not isinstance(entry, dict):
            continue
        target_type = str(entry.get("target_type", ""))
        target_name = str(entry.get("target_name", ""))
        if target_type and target_name:
            reason = str(entry.get("reason", "first-party allow"))
            source_path_contains = entry.get("source_path_contains", [])
            if not isinstance(source_path_contains, list):
                source_path_contains = []
            first_party_allow[(target_type, target_name)] = (reason, source_path_contains)

    return AdmissionPolicyData(
        allow_list_bypass_scan=bool(cfg.get("allow_list_bypass_scan", True)),
        scan_on_install=bool(cfg.get("scan_on_install", True)),
        actions=actions,
        scanner_overrides=scanner_overrides,
        first_party_allow=first_party_allow,
    )


def _severity_action_from_policy(raw: dict[str, Any]) -> SeverityAction:
    runtime = "disable" if raw.get("runtime", "allow") == "block" else "enable"
    return SeverityAction(
        file=str(raw.get("file", "none")),
        runtime=runtime,
        install=str(raw.get("install", "none")),
    )


def _read_policy_data(policy_dir: str) -> dict[str, Any] | None:
    for candidate in _policy_data_candidates(policy_dir):
        try:
            with open(candidate) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _policy_data_candidates(policy_dir: str) -> list[str]:
    candidates: list[str] = []
    if policy_dir:
        candidates.append(os.path.join(policy_dir, "rego", "data.json"))
        candidates.append(os.path.join(policy_dir, "data.json"))
    return candidates


def _scan_summary(scan_result: Any) -> tuple[int, str]:
    if hasattr(scan_result, "findings") and hasattr(scan_result, "max_severity"):
        findings = getattr(scan_result, "findings", []) or []
        return len(findings), str(scan_result.max_severity())

    if isinstance(scan_result, dict):
        count = scan_result.get("total_findings")
        if count is None:
            count = scan_result.get("finding_count", 0)
        severity = scan_result.get("max_severity", "INFO")
        return int(count or 0), str(severity)

    return 0, "INFO"


def _matches_provenance(constraints: list[str], source_path: str) -> bool:
    """True if no constraints exist, or if source_path contains one of them."""
    if not constraints:
        return True
    if not source_path:
        return False
    normalised = source_path.replace("\\", "/").lower()
    return any(c.lower() in normalised for c in constraints)


def _action_reason(action_entry: Any | None, *, default: str) -> str:
    reason = getattr(action_entry, "reason", "") if action_entry is not None else ""
    return reason or default
