# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 7 patch: project ``Policy`` into the ``data.json`` shape.

Mirrors ``docs-site/components/policy-creator/lib/data-projection.ts``
field-for-field. The bundled Rego modules under
``rego/`` (admission, audit, firewall, guardrail, sandbox,
skill_actions) all read ``data.defenseclaw.<sub>...`` and the only
upstream that produces that exact shape is this projector.

Keeping the projection in pure-Python (instead of shelling to a
``defenseclaw policy show --opa-data`` subprocess) lets the live-test
pane in the Quick Start wizard and the Playground sections refresh
on every keystroke without paying a fork+exec round-trip; the
subprocess call is only needed when we ask ``opa eval`` to run the
bundled Rego against the projected data (see ``opa_eval.py``).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from defenseclaw.tui.creator.types import (
    SCANNER_TYPES,
    SEVERITIES_UPPER,
    CorrelationClause,
    CorrelationPattern,
    Policy,
    SeverityActionTriple,
)


def _project_action(triple: SeverityActionTriple) -> dict[str, str]:
    """Map ``runtime=enable/disable`` to ``runtime=allow/block`` and
    pass through ``file``/``install`` verbatim. Matches the gateway
    interpretation: a ``disable`` runtime verdict denies the request,
    so the OPA module sees ``block``."""

    return {
        "runtime": "block" if triple.runtime == "disable" else "allow",
        "file": triple.file,
        "install": triple.install,
    }


def _project_clause(clause: CorrelationClause) -> dict[str, Any]:
    """Drop ``None`` / empty fields so the projected JSON stays
    minimal and matches the TS spread-only-when-set semantics. The
    Rego correlator module reads ``axis``, ``tool_capability_class``,
    etc. with explicit ``object.get`` calls and treats absent keys as
    "don't care", so omitting them keeps the rule semantics correct
    while shrinking the payload."""

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
    out_patterns: list[dict[str, Any]] = []
    for pattern in patterns:
        if not pattern.enabled:
            continue
        entry: dict[str, Any] = {
            "id": pattern.id,
            "window_events": pattern.window_events,
            "severity_on_match": pattern.severity_on_match,
        }
        if pattern.all_of:
            entry["all_of"] = [_project_clause(c) for c in pattern.all_of]
        if pattern.sequence:
            entry["sequence"] = [{"severity": s.severity} for s in pattern.sequence]
        if pattern.fingerprint_chain:
            entry["fingerprint_chain"] = [
                _project_clause(c) for c in pattern.fingerprint_chain
            ]
        out_patterns.append(entry)
    return {"patterns": out_patterns}


def project_policy_to_data(policy: Policy) -> dict[str, Any]:
    """Return the ``data.json`` mapping the bundled Rego modules
    consume. Suitable for ``json.dump(...)`` directly into the
    ``opa eval --data <path>`` flag.

    Top-level keys mirror the TS ``OpaData`` interface and the
    gateway's ``cmd_policy._sync_opa_data`` helper. The
    ``severity_ranking`` and ``guardrail.severity_rank`` constants are
    duplicated intentionally to mirror the existing data file shape:
    ``severity_ranking`` is INFO..CRITICAL = 1..5, while
    ``guardrail.severity_rank`` is NONE..CRITICAL = 0..4.
    """

    actions: dict[str, dict[str, str]] = {}
    for upper in SEVERITIES_UPPER:
        lower = upper.lower()
        actions[upper] = _project_action(policy.skill_actions.get(lower))

    scanner_overrides: dict[str, dict[str, dict[str, str]]] = {}
    for scanner in SCANNER_TYPES:
        override = policy.scanner_overrides.get(scanner)
        if not override:
            continue
        projected: dict[str, dict[str, str]] = {}
        for upper in SEVERITIES_UPPER:
            lower = upper.lower()
            triple = override.get(lower)
            if triple is not None:
                projected[upper] = _project_action(triple)
        if projected:
            scanner_overrides[scanner] = projected

    return {
        "config": {
            "policy_name": policy.name or "custom",
            "allow_list_bypass_scan": policy.admission.allow_list_bypass_scan,
            "scan_on_install": policy.admission.scan_on_install,
            "max_enforcement_delay_seconds": (
                policy.enforcement.max_enforcement_delay_seconds
            ),
        },
        "actions": actions,
        "scanner_overrides": scanner_overrides,
        "first_party_allow_list": [asdict(e) for e in policy.first_party_allow_list],
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
            "severity_rank": {
                "NONE": 0,
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            },
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
