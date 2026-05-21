# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Render a ``Policy`` into the multiple files the gateway expects on disk.

Python port of ``docs-site/components/policy-creator/lib/emit.ts`` plus
``data-projection.ts``. The output mirrors the on-disk layout under
``~/.defenseclaw/policies/`` so the operator can drop the bundle
straight into their data dir (or the Creator can do it for them).

Two public entry points:

* ``emit(policy)`` returns a list of ``EmittedFile`` (path, contents,
  description). Suitable for previewing in the Playground or piping
  into ``defenseclaw policy import``.
* ``project_policy_to_data(policy)`` returns just the OPA ``data.json``
  projection (the only file Rego modules read at evaluation time).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import yaml

from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import (
    SCANNER_TYPES,
    SEVERITIES,
    SEVERITIES_UPPER,
    CorrelationClause,
    CorrelationPattern,
    Policy,
    SeverityActionTriple,
)

YAML_OPTS: dict[str, Any] = {
    "indent": 2,
    "width": 100,
    "sort_keys": False,
    "default_flow_style": False,
    "allow_unicode": True,
}


def _dump_yaml(value: Any) -> str:
    return yaml.safe_dump(value, **YAML_OPTS)


# --- data projection (data.json) -------------------------------------------


def _project_action(triple: SeverityActionTriple) -> dict[str, str]:
    """Translate a wizard-state action triple into the OPA ``data.json``
    shape the bundled Rego modules read.

    The mapping mirrors ``cmd_policy.py``'s ``_sync_opa_data``:
    ``runtime: enable`` -> ``allow``, ``runtime: disable`` -> ``block``.
    ``file`` and ``install`` pass through unchanged.
    """
    return {
        "runtime": "block" if triple.runtime == "disable" else "allow",
        "file": triple.file,
        "install": triple.install,
    }


def _project_clause(clause: CorrelationClause) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if clause.axis:
        out["axis"] = clause.axis
    if clause.tool_capability_class:
        out["tool_capability_class"] = clause.tool_capability_class
    if clause.with_rule_match:
        out["with_rule_match"] = list(clause.with_rule_match)
    if clause.min_severity:
        out["min_severity"] = clause.min_severity
    return out


def _project_correlator(patterns: list[CorrelationPattern]) -> dict[str, Any]:
    enabled = [p for p in patterns if p.enabled]
    out: list[dict[str, Any]] = []
    for pattern in enabled:
        block: dict[str, Any] = {
            "id": pattern.id,
            "window_events": pattern.window_events,
            "severity_on_match": pattern.severity_on_match,
        }
        if pattern.all_of:
            block["all_of"] = [_project_clause(c) for c in pattern.all_of]
        if pattern.sequence:
            block["sequence"] = [{"severity": s.severity} for s in pattern.sequence]
        if pattern.fingerprint_chain:
            block["fingerprint_chain"] = [_project_clause(c) for c in pattern.fingerprint_chain]
        out.append(block)
    return {"patterns": out}


def project_policy_to_data(policy: Policy) -> dict[str, Any]:
    """Build the OPA ``data.json`` projection for ``policy``.

    Single source of truth for what the Rego modules will see at
    evaluation time. Used both by ``emit()`` for the on-disk file
    and by ``opa_eval.evaluate`` (Phase 9) for live preview.
    """
    actions: dict[str, dict[str, str]] = {}
    for sev_upper in SEVERITIES_UPPER:
        lower = sev_upper.lower()
        actions[sev_upper] = _project_action(policy.skill_actions.get(lower))

    scanner_overrides: dict[str, dict[str, dict[str, str]]] = {}
    for scanner in SCANNER_TYPES:
        per_scanner = policy.scanner_overrides.get(scanner)
        if not per_scanner:
            continue
        projected: dict[str, dict[str, str]] = {}
        for sev_upper in SEVERITIES_UPPER:
            lower = sev_upper.lower()
            triple = per_scanner.get(lower)
            if triple is not None:
                projected[sev_upper] = _project_action(triple)
        if projected:
            scanner_overrides[scanner] = projected

    return {
        "config": {
            "policy_name": policy.name or "custom",
            "allow_list_bypass_scan": policy.admission.allow_list_bypass_scan,
            "scan_on_install": policy.admission.scan_on_install,
            "max_enforcement_delay_seconds": policy.enforcement.max_enforcement_delay_seconds,
        },
        "actions": actions,
        "scanner_overrides": scanner_overrides,
        "first_party_allow_list": [
            {
                "target_type": entry.target_type,
                "target_name": entry.target_name,
                "reason": entry.reason,
                "source_path_contains": list(entry.source_path_contains),
            }
            for entry in policy.first_party_allow_list
        ],
        "severity_ranking": {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        },
        "audit": {
            "retention_days": policy.audit.retention_days,
            "log_all_actions": policy.audit.log_all_actions,
            "log_scan_results": policy.audit.log_scan_results,
        },
        "guardrail": {
            "severity_rank": {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
            "block_threshold": policy.guardrail.block_threshold,
            "alert_threshold": policy.guardrail.alert_threshold,
            "cisco_trust_level": policy.guardrail.cisco_trust_level,
            "hilt": {
                "enabled": policy.guardrail.hilt.enabled,
                "min_severity": policy.guardrail.hilt.min_severity,
            },
            "patterns": {k: list(v) for k, v in policy.guardrail.patterns.items()},
            "severity_mappings": dict(policy.guardrail.severity_mappings),
        },
        "firewall": {
            "default_action": policy.firewall.default_action,
            "blocked_destinations": list(policy.firewall.blocked_destinations),
            "allowed_domains": list(policy.firewall.allowed_domains),
            "allowed_ports": list(policy.firewall.allowed_ports),
        },
        "correlator": _project_correlator(policy.correlator),
        "cisco_ai_defense": {
            "enabled": policy.cisco_ai_defense.enabled,
            "api_key_env": policy.cisco_ai_defense.api_key_env,
            "scan_hook_surface": policy.cisco_ai_defense.scan_hook_surface,
        },
    }


# --- multi-file emit -------------------------------------------------------


@dataclass(frozen=True)
class EmittedFile:
    """One file in the emit bundle.

    ``path`` is a tilde-prefixed user-relative path so the operator
    sees exactly where the file is meant to land. ``contents`` is the
    UTF-8 string to write. ``description`` is a one-line summary the
    Playground renders next to the path in the export panel.
    """

    path: str
    contents: str
    description: str


def _admission_block(policy: Policy) -> dict[str, Any]:
    return {
        "scan_on_install": policy.admission.scan_on_install,
        "allow_list_bypass_scan": policy.admission.allow_list_bypass_scan,
    }


def _skill_actions_block(policy: Policy) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for severity in SEVERITIES:
        triple = policy.skill_actions.get(severity)
        out[severity] = {
            "runtime": triple.runtime,
            "file": triple.file,
            "install": triple.install,
        }
    return out


def _scanner_overrides_block(policy: Policy) -> dict[str, dict[str, dict[str, str]]]:
    out: dict[str, dict[str, dict[str, str]]] = {}
    for scanner_type, per_scanner in policy.scanner_overrides.items():
        if not per_scanner:
            continue
        bucket: dict[str, dict[str, str]] = {}
        for severity, triple in per_scanner.items():
            bucket[severity] = {
                "runtime": triple.runtime,
                "file": triple.file,
                "install": triple.install,
            }
        if bucket:
            out[scanner_type] = bucket
    return out


def _correlator_canonical_signature(patterns: list[CorrelationPattern]) -> str:
    """Stable stringification of ``patterns`` for diff-vs-preset detection.

    Mirrors ``canonicalCorrelator`` in ``emit.ts``: sort by id, normalize
    optional fields, JSON-encode. Pattern reordering, optional empty
    arrays, and ``enabled: undefined`` won't trip a false "edited".
    """

    def canon_clause(c: CorrelationClause) -> dict[str, Any]:
        return {
            "axis": c.axis or "",
            "tool_capability_class": c.tool_capability_class or "",
            "with_rule_match": sorted(c.with_rule_match or []),
            "min_severity": c.min_severity or "",
        }

    sorted_patterns = sorted(
        (
            {
                "id": p.id,
                "enabled": p.enabled is not False,
                "description": p.description or "",
                "window_events": p.window_events,
                "severity_on_match": p.severity_on_match,
                "all_of": [canon_clause(c) for c in (p.all_of or [])],
                "sequence": [{"severity": s.severity} for s in (p.sequence or [])],
                "fingerprint_chain": [canon_clause(c) for c in (p.fingerprint_chain or [])],
            }
            for p in patterns
        ),
        key=lambda p: p["id"],
    )
    return json.dumps(sorted_patterns, sort_keys=False, separators=(",", ":"))


def _correlator_differs_from_default(policy: Policy) -> bool:
    """True iff ``policy.correlator`` differs from the bundled preset.

    We only emit a YAML override when the operator has actually
    changed something so future upstream pattern updates aren't
    shadowed by a stale wizard copy.
    """
    current = _correlator_canonical_signature(policy.correlator)
    baseline_policy = load_preset(policy.basedOn)
    baseline = _correlator_canonical_signature(baseline_policy.correlator)
    return current != baseline


def emit(policy: Policy) -> list[EmittedFile]:
    """Render ``policy`` into the gateway's on-disk bundle.

    Returns one ``EmittedFile`` per output file. Empty / no-op
    sections are skipped so the bundle stays minimal: no empty
    suppressions YAML, no zero-rule pack files, no judge file
    without a system prompt.
    """
    files: list[EmittedFile] = []
    pack_name = policy.rule_pack.name or policy.name or "custom"
    correlator = policy.correlator

    # 1) Top-level admission policy YAML.
    aid = policy.cisco_ai_defense
    aid_block: dict[str, Any] = {}
    if aid.enabled or aid.api_key_env or aid.endpoint:
        aid_inner: dict[str, Any] = {}
        if aid.endpoint:
            aid_inner["endpoint"] = aid.endpoint
        if aid.api_key_env:
            aid_inner["api_key_env"] = aid.api_key_env
        # Only emit ``scan_hook_surface`` when the operator changed
        # it from the True default; ``HookSurfaceEnabled()`` handles
        # the absent case server-side.
        if aid.scan_hook_surface is False:
            aid_inner["scan_hook_surface"] = False
        if aid_inner:
            aid_block["cisco_ai_defense"] = aid_inner

    policy_yaml: dict[str, Any] = {
        "name": policy.name,
        "description": policy.description,
        "admission": _admission_block(policy),
        "skill_actions": _skill_actions_block(policy),
        "scanner_overrides": _scanner_overrides_block(policy),
        "first_party_allow_list": [
            {
                "target_type": entry.target_type,
                "target_name": entry.target_name,
                "reason": entry.reason,
                "source_path_contains": list(entry.source_path_contains),
            }
            for entry in policy.first_party_allow_list
        ],
        "guardrail": {
            "block_threshold": policy.guardrail.block_threshold,
            "alert_threshold": policy.guardrail.alert_threshold,
            "cisco_trust_level": policy.guardrail.cisco_trust_level,
            "hilt": {
                "enabled": policy.guardrail.hilt.enabled,
                "min_severity": policy.guardrail.hilt.min_severity,
            },
            "patterns": {k: list(v) for k, v in policy.guardrail.patterns.items()},
            "severity_mappings": dict(policy.guardrail.severity_mappings),
        },
        "firewall": {
            "default_action": policy.firewall.default_action,
            "blocked_destinations": list(policy.firewall.blocked_destinations),
            "allowed_domains": list(policy.firewall.allowed_domains),
            "allowed_ports": list(policy.firewall.allowed_ports),
        },
        "watch": {
            "rescan_enabled": policy.watch.rescan_enabled,
            "rescan_interval_min": policy.watch.rescan_interval_min,
        },
        "enforcement": {
            "max_enforcement_delay_seconds": policy.enforcement.max_enforcement_delay_seconds,
        },
        "audit": {
            "log_all_actions": policy.audit.log_all_actions,
            "log_scan_results": policy.audit.log_scan_results,
            "retention_days": policy.audit.retention_days,
        },
        "webhooks": [
            {
                "url": w.url,
                "type": w.type,
                **({"secret_env": w.secret_env} if w.secret_env else {}),
                **({"room_id": w.room_id} if w.room_id else {}),
                "min_severity": w.min_severity,
                "events": list(w.events),
                "enabled": w.enabled,
            }
            for w in policy.webhooks
        ],
        "scanners": policy.scanners.to_yaml_keys(),
    }
    policy_yaml.update(aid_block)

    header = (
        f"# DefenseClaw policy: {policy.name}\n"
        f"# {policy.description}\n"
        "# Generated by defenseclaw policy creator. Edit by hand or regenerate.\n"
        f"# Activate with: defenseclaw policy activate {policy.name}\n\n"
    )
    files.append(
        EmittedFile(
            path=f"~/.defenseclaw/policies/{policy.name or 'custom'}.yaml",
            contents=header + _dump_yaml(policy_yaml),
            description="Top-level admission/severity/firewall/audit policy YAML",
        )
    )

    # 2) OPA data.json projection.
    opa_data = project_policy_to_data(policy)
    files.append(
        EmittedFile(
            path="~/.defenseclaw/policies/rego/data.json",
            contents=json.dumps(opa_data, indent=2, sort_keys=False) + "\n",
            description="OPA data.json - read by every Rego module at evaluation time",
        )
    )

    # 3) Per-file rule packs.
    for rules_file in policy.rule_pack.files:
        if not rules_file.rules:
            continue
        files.append(
            EmittedFile(
                path=(
                    f"~/.defenseclaw/policies/guardrail/{pack_name}/rules/"
                    f"{rules_file.filename}.yaml"
                ),
                contents=_dump_yaml(
                    {
                        "version": 1,
                        "category": rules_file.category,
                        "rules": [
                            {
                                "id": r.id,
                                **({"enabled": r.enabled} if r.enabled is not None else {}),
                                "pattern": r.pattern,
                                "title": r.title,
                                "severity": r.severity,
                                "confidence": r.confidence,
                                "tags": list(r.tags),
                            }
                            for r in rules_file.rules
                        ],
                    }
                ),
                description=(
                    f"Rule pack: {rules_file.filename}.yaml "
                    f"({len(rules_file.rules)} rule"
                    f"{'' if len(rules_file.rules) == 1 else 's'})"
                ),
            )
        )

    # 4) Suppressions.
    supp = policy.suppressions
    if supp.pre_judge_strips or supp.finding_suppressions or supp.tool_suppressions:
        files.append(
            EmittedFile(
                path=f"~/.defenseclaw/policies/guardrail/{pack_name}/suppressions.yaml",
                contents=_dump_yaml(
                    {
                        "version": 1,
                        "pre_judge_strips": [
                            {
                                "id": s.id,
                                "pattern": s.pattern,
                                "context": s.context,
                                "applies_to": list(s.applies_to),
                            }
                            for s in supp.pre_judge_strips
                        ],
                        "finding_suppressions": [
                            {
                                "id": fs.id,
                                "finding_pattern": fs.finding_pattern,
                                "entity_pattern": fs.entity_pattern,
                                **({"condition": fs.condition} if fs.condition else {}),
                                "reason": fs.reason,
                            }
                            for fs in supp.finding_suppressions
                        ],
                        "tool_suppressions": [
                            {
                                "tool_pattern": ts.tool_pattern,
                                "suppress_findings": list(ts.suppress_findings),
                                "reason": ts.reason,
                            }
                            for ts in supp.tool_suppressions
                        ],
                    }
                ),
                description=(
                    f"Suppressions: {len(supp.pre_judge_strips)} pre-strip · "
                    f"{len(supp.finding_suppressions)} finding · "
                    f"{len(supp.tool_suppressions)} tool"
                ),
            )
        )

    # 5) Sensitive tools.
    if policy.sensitive_tools:
        files.append(
            EmittedFile(
                path=f"~/.defenseclaw/policies/guardrail/{pack_name}/sensitive-tools.yaml",
                contents=_dump_yaml(
                    {
                        "version": 1,
                        "tools": [
                            {
                                "name": t.name,
                                "result_inspection": t.result_inspection,
                                "judge_result": t.judge_result,
                                **(
                                    {"min_entities_for_alert": t.min_entities_for_alert}
                                    if t.min_entities_for_alert is not None
                                    else {}
                                ),
                            }
                            for t in policy.sensitive_tools
                        ],
                    }
                ),
                description=(
                    f"Sensitive tool inspection: {len(policy.sensitive_tools)} tool"
                    f"{'' if len(policy.sensitive_tools) == 1 else 's'}"
                ),
            )
        )

    # 6) Judge configs.
    for judge in policy.judges:
        if not judge.system_prompt:
            continue
        body: dict[str, Any] = {
            "version": 1,
            "name": judge.name,
            "enabled": judge.enabled,
            "system_prompt": judge.system_prompt,
        }
        if judge.adjudication_prompt:
            body["adjudication_prompt"] = judge.adjudication_prompt
        if judge.min_categories_for_high:
            body["min_categories_for_high"] = judge.min_categories_for_high
        if judge.min_categories_for_critical:
            body["min_categories_for_critical"] = judge.min_categories_for_critical
        if judge.single_category_max_severity:
            body["single_category_max_severity"] = judge.single_category_max_severity
        body["categories"] = {
            cat_name: {
                "finding_id": cat.finding_id,
                **({"severity": cat.severity} if cat.severity else {}),
                **({"severity_default": cat.severity_default} if cat.severity_default else {}),
                **({"severity_prompt": cat.severity_prompt} if cat.severity_prompt else {}),
                **(
                    {"severity_completion": cat.severity_completion}
                    if cat.severity_completion
                    else {}
                ),
                "enabled": cat.enabled,
            }
            for cat_name, cat in judge.categories.items()
        }
        files.append(
            EmittedFile(
                path=f"~/.defenseclaw/policies/guardrail/{pack_name}/judge/{judge.name}.yaml",
                contents=_dump_yaml(body),
                description=f"Judge config: {judge.name}",
            )
        )

    # 7) Custom Rego snippets.
    for snippet in policy.custom_rego:
        if not snippet.source.strip():
            continue
        body_rego = (
            f"# {snippet.description}\n"
            "# Generated by defenseclaw policy creator. "
            "Run `opa check` after install.\n"
            f"{snippet.source.rstrip()}\n"
        )
        files.append(
            EmittedFile(
                path=f"~/.defenseclaw/policies/rego/custom-{snippet.name}.rego",
                contents=body_rego,
                description=f"Custom Rego snippet: {snippet.name}",
            )
        )

    # 8) Layer-5 correlator overrides. Only emit when the operator
    # changed something vs the bundled preset baseline; otherwise
    # skip so future upstream pattern updates flow through.
    if _correlator_differs_from_default(policy):
        enabled_patterns = [p for p in correlator if p.enabled]
        body_corr: dict[str, Any] = {
            "patterns": [
                {
                    "id": p.id,
                    **({"description": p.description} if p.description else {}),
                    "window_events": p.window_events,
                    "severity_on_match": p.severity_on_match,
                    **(
                        {"all_of": [_project_clause(c) for c in p.all_of]}
                        if p.all_of
                        else {}
                    ),
                    **(
                        {"sequence": [{"severity": s.severity} for s in p.sequence]}
                        if p.sequence
                        else {}
                    ),
                    **(
                        {"fingerprint_chain": [_project_clause(c) for c in p.fingerprint_chain]}
                        if p.fingerprint_chain
                        else {}
                    ),
                }
                for p in enabled_patterns
            ]
        }
        header_corr = (
            f"# Sliding-window correlation patterns for pack {pack_name}.\n"
            "# Overrides the bundled defaults in internal/guardrail/defaults/.\n"
            "# See https://defenseclaw.dev/docs/policies#layer-5--session-correlator\n"
        )
        files.append(
            EmittedFile(
                path=f"~/.defenseclaw/policies/guardrail/{pack_name}/correlation-patterns.yaml",
                contents=header_corr + _dump_yaml(body_corr),
                description=(
                    f"Session correlator patterns ({len(enabled_patterns)} enabled)"
                ),
            )
        )

    return files


def policy_to_gateway_yaml(policy: Policy) -> str:
    """Return just the top-level admission YAML for ``policy``.

    Convenience wrapper around :func:`emit` that pulls out the single
    file the gateway loads via ``defenseclaw policy activate``. The
    Quick Start wizard's Save flow uses this to drop a single
    ``<name>.yaml`` into the user's policy_dir without having to
    materialize the full Rego/data/judge/rule-pack tree.
    """

    files = emit(policy)
    for emitted in files:
        if emitted.path.endswith(f"/policies/{policy.name or 'custom'}.yaml"):
            return emitted.contents
    # Defensive fallback: emit() always produces this file as index 0,
    # but if the schema ever changes we'd rather hand back an empty
    # YAML than crash the wizard's save flow.
    return ""
