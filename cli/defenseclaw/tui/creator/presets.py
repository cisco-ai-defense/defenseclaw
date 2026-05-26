# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Preset loading and ``Policy`` construction for the Creator.

The web Creator imports ``presets.json`` (generated at docs-site build
time). The TUI lives inside the wheel that *ships* the presets, so we
read them straight from disk via ``defenseclaw.paths.bundled_policies_dir``
and synthesize a ``Policy`` instance from the YAML.

This module is intentionally thin: ``load_preset()`` returns a fully
populated ``Policy`` for one of {default, strict, permissive}; richer
behavior (diffing, validation, emit) lives in dedicated modules so
each concern stays testable in isolation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

from defenseclaw.paths import bundled_policies_dir
from defenseclaw.tui.creator.types import (
    SEVERITIES,
    AdmissionConfig,
    AuditConfig,
    CiscoAIDefenseConfig,
    CorrelationClause,
    CorrelationPattern,
    CorrelationSequenceStep,
    CustomRegoSnippet,
    EnforcementConfig,
    FindingSuppressionDef,
    FirewallConfig,
    FirstPartyEntry,
    GuardrailConfig,
    GuardrailHilt,
    JudgeCategoryDef,
    JudgeConfig,
    Policy,
    PreJudgeStripDef,
    PresetName,
    RuleDef,
    RulePackBundle,
    RulesFile,
    ScannerProfileSelection,
    SensitiveTool,
    SeverityActionMatrix,
    SeverityActionTriple,
    SuppressionsBundle,
    ToolSuppressionDef,
    WatchConfig,
    WebhookEntry,
)

PRESET_NAMES: tuple[PresetName, ...] = ("default", "strict", "permissive")


def _load_yaml_or_empty(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    return []


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return {}


def _coerce_str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _coerce_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default  # bools are int subclass; reject explicitly
    if isinstance(value, int):
        return value
    return default


def _action_triple_from_yaml(value: Any) -> SeverityActionTriple:
    """Parse a ``{install, file, runtime}`` block into a triple.

    The bundled YAML omits fields it doesn't override, so we apply
    sensible defaults that match the engine's "no-op" interpretation.
    """
    if not isinstance(value, dict):
        return SeverityActionTriple()
    return SeverityActionTriple(
        runtime=cast("Any", _coerce_str(value.get("runtime"), "enable")),
        file=cast("Any", _coerce_str(value.get("file"), "none")),
        install=cast("Any", _coerce_str(value.get("install"), "none")),
    )


def _matrix_from_yaml(value: Any) -> SeverityActionMatrix:
    """Build a ``SeverityActionMatrix`` from the YAML's
    ``skill_actions`` block. Missing severities default to no-op.
    """
    matrix = SeverityActionMatrix()
    if not isinstance(value, dict):
        return matrix
    for severity in SEVERITIES:
        triple = _action_triple_from_yaml(value.get(severity))
        matrix.set(severity, triple)
    return matrix


def _scanner_overrides_from_yaml(value: Any) -> dict[str, dict[str, SeverityActionTriple]]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, dict[str, SeverityActionTriple]] = {}
    for scanner_type, severity_map in value.items():
        if not isinstance(severity_map, dict):
            continue
        per_scanner: dict[str, SeverityActionTriple] = {}
        for severity, triple in severity_map.items():
            if severity in SEVERITIES:
                per_scanner[severity] = _action_triple_from_yaml(triple)
        if per_scanner:
            out[str(scanner_type)] = per_scanner
    return out


def _first_party_from_yaml(value: Any) -> list[FirstPartyEntry]:
    if not isinstance(value, list):
        return []
    out: list[FirstPartyEntry] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        out.append(
            FirstPartyEntry(
                target_type=cast("Any", _coerce_str(entry.get("target_type"), "skill")),
                target_name=_coerce_str(entry.get("target_name")),
                reason=_coerce_str(entry.get("reason")),
                source_path_contains=[
                    str(item) for item in _coerce_list(entry.get("source_path_contains"))
                ],
            )
        )
    return out


def _guardrail_from_yaml(value: Any) -> GuardrailConfig:
    if not isinstance(value, dict):
        return GuardrailConfig()
    hilt_data = value.get("hilt") if isinstance(value.get("hilt"), dict) else {}
    hilt = GuardrailHilt(
        enabled=_coerce_bool(hilt_data.get("enabled"), False),
        min_severity=cast("Any", _coerce_str(hilt_data.get("min_severity"), "MEDIUM")),
    )
    patterns: dict[str, list[str]] = {}
    raw_patterns = value.get("patterns")
    if isinstance(raw_patterns, dict):
        for category, items in raw_patterns.items():
            patterns[str(category)] = [str(item) for item in _coerce_list(items)]
    severity_mappings: dict[str, str] = {}
    raw_mappings = value.get("severity_mappings")
    if isinstance(raw_mappings, dict):
        for category, severity in raw_mappings.items():
            severity_mappings[str(category)] = str(severity)
    return GuardrailConfig(
        block_threshold=_coerce_int(value.get("block_threshold"), 4),
        alert_threshold=_coerce_int(value.get("alert_threshold"), 2),
        cisco_trust_level=cast(
            "Any", _coerce_str(value.get("cisco_trust_level"), "full")
        ),
        hilt=hilt,
        patterns=patterns,
        severity_mappings=cast("Any", severity_mappings),
    )


def _firewall_from_yaml(value: Any) -> FirewallConfig:
    if not isinstance(value, dict):
        return FirewallConfig()
    return FirewallConfig(
        default_action=cast("Any", _coerce_str(value.get("default_action"), "allow")),
        blocked_destinations=[str(item) for item in _coerce_list(value.get("blocked_destinations"))],
        allowed_domains=[str(item) for item in _coerce_list(value.get("allowed_domains"))],
        allowed_ports=[
            int(item) for item in _coerce_list(value.get("allowed_ports")) if isinstance(item, int)
        ],
    )


def _webhooks_from_yaml(value: Any) -> list[WebhookEntry]:
    if not isinstance(value, list):
        return []
    out: list[WebhookEntry] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        out.append(
            WebhookEntry(
                url=_coerce_str(entry.get("url")),
                type=cast("Any", _coerce_str(entry.get("type"), "slack")),
                secret_env=_coerce_str(entry.get("secret_env")),
                room_id=_coerce_str(entry.get("room_id")),
                min_severity=cast("Any", _coerce_str(entry.get("min_severity"), "HIGH")),
                events=[
                    cast("Any", str(item))
                    for item in _coerce_list(entry.get("events"))
                    if isinstance(item, str) and item in {"block", "drift", "guardrail"}
                ],
                enabled=_coerce_bool(entry.get("enabled"), True),
            )
        )
    return out


def _watch_from_yaml(value: Any) -> WatchConfig:
    if not isinstance(value, dict):
        return WatchConfig()
    return WatchConfig(
        rescan_enabled=_coerce_bool(value.get("rescan_enabled"), False),
        rescan_interval_min=_coerce_int(value.get("rescan_interval_min"), 60),
    )


def _enforcement_from_yaml(value: Any) -> EnforcementConfig:
    if not isinstance(value, dict):
        return EnforcementConfig()
    return EnforcementConfig(
        max_enforcement_delay_seconds=_coerce_int(
            value.get("max_enforcement_delay_seconds"), 5
        ),
    )


def _audit_from_yaml(value: Any) -> AuditConfig:
    if not isinstance(value, dict):
        return AuditConfig()
    return AuditConfig(
        log_all_actions=_coerce_bool(value.get("log_all_actions"), True),
        log_scan_results=_coerce_bool(value.get("log_scan_results"), True),
        retention_days=_coerce_int(value.get("retention_days"), 30),
    )


def _scanners_from_yaml(value: Any) -> ScannerProfileSelection:
    if not isinstance(value, dict):
        return ScannerProfileSelection()
    return ScannerProfileSelection(
        codeguard=_coerce_str(value.get("codeguard")),
        plugin_scanner=_coerce_str(value.get("plugin-scanner")),
        skill_scanner=_coerce_str(value.get("skill-scanner")),
    )


def _custom_rego_from_yaml(value: Any) -> list[CustomRegoSnippet]:
    if not isinstance(value, list):
        return []
    out: list[CustomRegoSnippet] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        out.append(
            CustomRegoSnippet(
                name=_coerce_str(entry.get("name")),
                package=_coerce_str(entry.get("package")),
                source=_coerce_str(entry.get("source")),
                description=_coerce_str(entry.get("description")),
            )
        )
    return out


def _correlator_from_yaml(value: Any) -> list[CorrelationPattern]:
    if not isinstance(value, list):
        return []
    out: list[CorrelationPattern] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        out.append(
            CorrelationPattern(
                id=_coerce_str(entry.get("id")),
                description=_coerce_str(entry.get("description")),
                window_events=_coerce_int(entry.get("window_events"), 100),
                severity_on_match=cast(
                    "Any", _coerce_str(entry.get("severity_on_match"), "HIGH")
                ),
                all_of=[_clause_from_yaml(item) for item in _coerce_list(entry.get("all_of"))],
                sequence=[
                    CorrelationSequenceStep(
                        severity=cast("Any", _coerce_str(step.get("severity"), "MEDIUM"))
                    )
                    for step in _coerce_list(entry.get("sequence"))
                    if isinstance(step, dict)
                ],
                fingerprint_chain=[
                    _clause_from_yaml(item) for item in _coerce_list(entry.get("fingerprint_chain"))
                ],
                enabled=_coerce_bool(entry.get("enabled"), True),
            )
        )
    return out


def _clause_from_yaml(value: Any) -> CorrelationClause:
    if not isinstance(value, dict):
        return CorrelationClause()
    return CorrelationClause(
        axis=cast("Any", value.get("axis")) if isinstance(value.get("axis"), str) else None,
        tool_capability_class=(
            cast("Any", value.get("tool_capability_class"))
            if isinstance(value.get("tool_capability_class"), str)
            else None
        ),
        with_rule_match=[str(item) for item in _coerce_list(value.get("with_rule_match"))],
        min_severity=(
            cast("Any", value.get("min_severity"))
            if isinstance(value.get("min_severity"), str)
            else None
        ),
    )


def _aid_from_yaml(value: Any) -> CiscoAIDefenseConfig:
    if not isinstance(value, dict):
        return CiscoAIDefenseConfig()
    return CiscoAIDefenseConfig(
        enabled=_coerce_bool(value.get("enabled"), False),
        endpoint=_coerce_str(value.get("endpoint")),
        api_key_env=_coerce_str(value.get("api_key_env")),
        scan_hook_surface=_coerce_bool(value.get("scan_hook_surface"), True),
    )


def policy_from_yaml(name: str, data: dict[str, Any]) -> Policy:
    """Translate a YAML mapping into a populated ``Policy``.

    Anything missing from the YAML stays at the dataclass default,
    matching the engine's "no override" behavior.
    """
    based_on = data.get("based_on") or data.get("basedOn") or "default"
    if based_on not in {"default", "strict", "permissive"}:
        based_on = "default"

    return Policy(
        name=_coerce_str(data.get("name"), name),
        description=_coerce_str(data.get("description")),
        basedOn=cast("PresetName", based_on),
        admission=AdmissionConfig(
            scan_on_install=_coerce_bool(
                _coerce_dict(data.get("admission")).get("scan_on_install"), True
            ),
            allow_list_bypass_scan=_coerce_bool(
                _coerce_dict(data.get("admission")).get("allow_list_bypass_scan"), True
            ),
        ),
        skill_actions=_matrix_from_yaml(data.get("skill_actions")),
        scanner_overrides=cast("Any", _scanner_overrides_from_yaml(data.get("scanner_overrides"))),
        first_party_allow_list=_first_party_from_yaml(data.get("first_party_allow_list")),
        guardrail=_guardrail_from_yaml(data.get("guardrail")),
        rule_pack=RulePackBundle(
            name=_coerce_str(_coerce_dict(data.get("rule_pack")).get("name"), name),
            files=[],  # populated separately from guardrail/<pack>/rules/*.yaml
        ),
        suppressions=SuppressionsBundle(),
        sensitive_tools=[],
        judges=[],
        firewall=_firewall_from_yaml(data.get("firewall")),
        webhooks=_webhooks_from_yaml(data.get("webhooks")),
        watch=_watch_from_yaml(data.get("watch")),
        enforcement=_enforcement_from_yaml(data.get("enforcement")),
        audit=_audit_from_yaml(data.get("audit")),
        scanners=_scanners_from_yaml(data.get("scanners")),
        custom_rego=_custom_rego_from_yaml(data.get("custom_rego")),
        correlator=_correlator_from_yaml(data.get("correlator")),
        cisco_ai_defense=_aid_from_yaml(data.get("cisco_ai_defense")),
    )


def load_preset(name: PresetName, *, root: Path | None = None) -> Policy:
    """Load one bundled preset YAML and return a populated ``Policy``.

    The web Creator pulls preset bundles from a build-time generated
    ``presets.json``; the TUI lives in the wheel that ships those
    YAMLs and reads them directly from disk. ``root`` lets tests
    inject a tmp dir.
    """
    base = root if root is not None else bundled_policies_dir()
    yaml_path = base / f"{name}.yaml"
    data = _load_yaml_or_empty(yaml_path)
    return policy_from_yaml(name, data)


def load_preset_with_pack(
    name: PresetName, *, root: Path | None = None
) -> tuple[Policy, list[RulesFile]]:
    """``load_preset`` plus the matching ``guardrail/<pack>/rules/`` files.

    Returns the rule files separately so the wizard can populate the
    Rules section without forcing an awkward "Policy.rule_pack.files
    is partially loaded" invariant on the rest of the schema.
    """
    base = root if root is not None else bundled_policies_dir()
    policy = load_preset(name, root=base)

    rules_dir = base / "guardrail" / name / "rules"
    files: list[RulesFile] = []
    if rules_dir.is_dir():
        for path in sorted(rules_dir.iterdir(), key=lambda p: p.name):
            if not path.is_file() or path.suffix not in {".yaml", ".yml"}:
                continue
            data = _load_yaml_or_empty(path)
            rules_raw = _coerce_list(data.get("rules"))
            rules: list[RuleDef] = []
            for item in rules_raw:
                if not isinstance(item, dict):
                    continue
                rules.append(
                    RuleDef(
                        id=_coerce_str(item.get("id")),
                        pattern=_coerce_str(item.get("pattern")),
                        title=_coerce_str(item.get("title")),
                        severity=cast("Any", _coerce_str(item.get("severity"), "MEDIUM")),
                        confidence=float(item.get("confidence", 0.5))
                        if isinstance(item.get("confidence"), int | float)
                        else 0.5,
                        tags=[str(tag) for tag in _coerce_list(item.get("tags"))],
                        enabled=item.get("enabled") if isinstance(item.get("enabled"), bool) else None,
                    )
                )
            files.append(
                RulesFile(
                    filename=path.stem,
                    category=_coerce_str(data.get("category"), path.stem),
                    rules=rules,
                )
            )

    # Suppressions live as a single ``guardrail/<pack>/suppressions.yaml``.
    supp_path = base / "guardrail" / name / "suppressions.yaml"
    if supp_path.is_file():
        supp_data = _load_yaml_or_empty(supp_path)
        policy.suppressions = SuppressionsBundle(
            pre_judge_strips=[
                PreJudgeStripDef(
                    id=_coerce_str(item.get("id")),
                    pattern=_coerce_str(item.get("pattern")),
                    context=_coerce_str(item.get("context")),
                    applies_to=[
                        cast("Any", str(t))
                        for t in _coerce_list(item.get("applies_to"))
                        if isinstance(t, str)
                        and t in {"pii", "injection", "tool-injection", "exfil"}
                    ],
                )
                for item in _coerce_list(supp_data.get("pre_judge_strips"))
                if isinstance(item, dict)
            ],
            finding_suppressions=[
                FindingSuppressionDef(
                    id=_coerce_str(item.get("id")),
                    finding_pattern=_coerce_str(item.get("finding_pattern")),
                    entity_pattern=_coerce_str(item.get("entity_pattern")),
                    condition=cast("Any", _coerce_str(item.get("condition"))),
                    reason=_coerce_str(item.get("reason")),
                )
                for item in _coerce_list(supp_data.get("finding_suppressions"))
                if isinstance(item, dict)
            ],
            tool_suppressions=[
                ToolSuppressionDef(
                    tool_pattern=_coerce_str(item.get("tool_pattern")),
                    suppress_findings=[
                        str(s) for s in _coerce_list(item.get("suppress_findings"))
                    ],
                    reason=_coerce_str(item.get("reason")),
                )
                for item in _coerce_list(supp_data.get("tool_suppressions"))
                if isinstance(item, dict)
            ],
        )

    # Sensitive tools, if present.
    tools_path = base / "guardrail" / name / "sensitive-tools.yaml"
    if tools_path.is_file():
        tools_data = _load_yaml_or_empty(tools_path)
        policy.sensitive_tools = [
            SensitiveTool(
                name=_coerce_str(item.get("name")),
                result_inspection=_coerce_bool(item.get("result_inspection"), False),
                judge_result=_coerce_bool(item.get("judge_result"), False),
                min_entities_for_alert=(
                    int(item.get("min_entities_for_alert"))
                    if isinstance(item.get("min_entities_for_alert"), int)
                    else None
                ),
            )
            for item in _coerce_list(tools_data.get("tools"))
            if isinstance(item, dict)
        ]

    # Judge prompts: each ``guardrail/<pack>/judge/<name>.yaml``.
    judge_dir = base / "guardrail" / name / "judge"
    if judge_dir.is_dir():
        for jpath in sorted(judge_dir.iterdir(), key=lambda p: p.name):
            if jpath.suffix not in {".yaml", ".yml"}:
                continue
            jdata = _load_yaml_or_empty(jpath)
            categories: dict[str, JudgeCategoryDef] = {}
            raw_cats = _coerce_dict(jdata.get("categories"))
            for cat_name, cat_data in raw_cats.items():
                if not isinstance(cat_data, dict):
                    continue
                categories[cat_name] = JudgeCategoryDef(
                    finding_id=_coerce_str(cat_data.get("finding_id")),
                    severity=cast("Any", cat_data.get("severity")) if cat_data.get("severity") else None,
                    severity_default=cast("Any", cat_data.get("severity_default")) if cat_data.get("severity_default") else None,
                    severity_prompt=cast("Any", cat_data.get("severity_prompt")) if cat_data.get("severity_prompt") else None,
                    severity_completion=cast("Any", cat_data.get("severity_completion")) if cat_data.get("severity_completion") else None,
                    enabled=_coerce_bool(cat_data.get("enabled"), True),
                )
            judge_name = _coerce_str(jdata.get("name"), jpath.stem)
            policy.judges.append(
                JudgeConfig(
                    name=cast("Any", judge_name) if judge_name in {"pii", "injection", "tool-injection", "exfil"} else "injection",
                    enabled=_coerce_bool(jdata.get("enabled"), False),
                    system_prompt=_coerce_str(jdata.get("system_prompt")),
                    adjudication_prompt=_coerce_str(jdata.get("adjudication_prompt")),
                    min_categories_for_high=(
                        int(jdata.get("min_categories_for_high"))
                        if isinstance(jdata.get("min_categories_for_high"), int)
                        else None
                    ),
                    min_categories_for_critical=(
                        int(jdata.get("min_categories_for_critical"))
                        if isinstance(jdata.get("min_categories_for_critical"), int)
                        else None
                    ),
                    single_category_max_severity=(
                        cast("Any", jdata.get("single_category_max_severity"))
                        if jdata.get("single_category_max_severity")
                        else None
                    ),
                    categories=categories,
                )
            )

    return policy, files
