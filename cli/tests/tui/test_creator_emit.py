# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 7: emit + data-projection tests.

These exercise ``project_policy_to_data`` and ``emit`` against minimal
``Policy`` instances. The shape contract is the source of truth for
the Rego modules that read ``data.json`` at evaluation time, so
behavior changes here must move in lock-step with the engine side.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import yaml

from defenseclaw.tui.creator import emit, presets, types


def _make_policy() -> types.Policy:
    """Build a Policy with one of every kind of sub-block populated.
    Used as the reference shape for the emit tests so each assert
    targets a single concern.
    """
    matrix = types.SeverityActionMatrix()
    matrix.set("critical", types.SeverityActionTriple(runtime="disable", file="quarantine", install="block"))
    matrix.set("high", types.SeverityActionTriple(runtime="disable", file="quarantine", install="block"))

    return types.Policy(
        name="prod-tight",
        description="Production tight",
        basedOn="strict",
        admission=types.AdmissionConfig(scan_on_install=True, allow_list_bypass_scan=False),
        skill_actions=matrix,
        scanner_overrides=cast(
            "dict[types.ScannerType, dict[types.Severity, types.SeverityActionTriple]]",
            {
                "skill": {
                    "high": types.SeverityActionTriple(
                        runtime="disable", file="quarantine", install="block"
                    )
                }
            },
        ),
        first_party_allow_list=[
            types.FirstPartyEntry(
                target_type="skill",
                target_name="defenseclaw",
                reason="first-party",
                source_path_contains=["defenseclaw"],
            )
        ],
        guardrail=types.GuardrailConfig(
            block_threshold=4,
            alert_threshold=2,
            cisco_trust_level="full",
            hilt=types.GuardrailHilt(enabled=True, min_severity="HIGH"),
            patterns={"injection": ["ignore previous"], "secrets": ["sk-"]},
            severity_mappings={"injection": "HIGH"},
        ),
        rule_pack=types.RulePackBundle(
            name="prod-tight",
            files=[
                types.RulesFile(
                    filename="secrets",
                    category="secrets",
                    rules=[
                        types.RuleDef(
                            id="aws-akid",
                            pattern="AKIA[0-9A-Z]{16}",
                            title="AWS Access Key",
                            severity="HIGH",
                            confidence=0.9,
                            tags=["aws", "iam"],
                        )
                    ],
                ),
                types.RulesFile(filename="empty", category="empty", rules=[]),
            ],
        ),
        suppressions=types.SuppressionsBundle(
            pre_judge_strips=[
                types.PreJudgeStripDef(
                    id="strip-iso-ts",
                    pattern=r"\b\d{4}-\d{2}-\d{2}T\d{2}",
                    context="log",
                    applies_to=["pii", "injection"],
                )
            ],
            tool_suppressions=[
                types.ToolSuppressionDef(
                    tool_pattern="shell.*",
                    suppress_findings=["aws-akid"],
                    reason="sandbox",
                )
            ],
        ),
        sensitive_tools=[
            types.SensitiveTool(
                name="send_email",
                result_inspection=True,
                judge_result=True,
                min_entities_for_alert=2,
            )
        ],
        judges=[
            types.JudgeConfig(
                name="injection",
                enabled=True,
                system_prompt="Detect prompt injection.",
                min_categories_for_critical=2,
                categories={
                    "ignore_prev": types.JudgeCategoryDef(
                        finding_id="injection-ignore-previous",
                        severity_default="HIGH",
                        enabled=True,
                    )
                },
            ),
            types.JudgeConfig(name="pii", enabled=False, system_prompt=""),  # skipped on emit
        ],
        firewall=types.FirewallConfig(
            default_action="deny",
            blocked_destinations=["169.254.169.254"],
            allowed_domains=["api.github.com"],
            allowed_ports=[443],
        ),
        webhooks=[
            types.WebhookEntry(
                url="https://hooks.slack.example/T0/B0/abc",
                type="slack",
                secret_env="SLACK_WEBHOOK_TOKEN",
                min_severity="HIGH",
                events=["block", "drift"],
                enabled=True,
            )
        ],
        custom_rego=[
            types.CustomRegoSnippet(
                name="my_rule",
                package="defenseclaw.custom.my_rule",
                source="package defenseclaw.custom.my_rule\n\ndeny[msg] { msg := \"x\" }",
                description="custom rule",
            )
        ],
        cisco_ai_defense=types.CiscoAIDefenseConfig(
            enabled=True,
            endpoint="https://aid.example",
            api_key_env="AID_KEY",
            scan_hook_surface=False,
        ),
    )


# --- data projection -------------------------------------------------------


def test_project_policy_to_data_remaps_runtime_disable_to_block() -> None:
    policy = types.Policy()
    policy.skill_actions.set(
        "critical",
        types.SeverityActionTriple(runtime="disable", file="quarantine", install="block"),
    )
    policy.skill_actions.set(
        "low",
        types.SeverityActionTriple(runtime="enable", file="none", install="none"),
    )

    data = emit.project_policy_to_data(policy)

    assert data["actions"]["CRITICAL"] == {
        "runtime": "block",
        "file": "quarantine",
        "install": "block",
    }
    assert data["actions"]["LOW"] == {
        "runtime": "allow",
        "file": "none",
        "install": "none",
    }


def test_project_policy_to_data_preserves_severity_ranking_and_aid() -> None:
    """The static severity ranking + Cisco AI Defense block must be
    present even on a default Policy so Rego modules can branch
    consistently."""
    policy = types.Policy(name="my-policy")
    data = emit.project_policy_to_data(policy)

    assert data["config"]["policy_name"] == "my-policy"
    assert data["severity_ranking"] == {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    assert data["guardrail"]["severity_rank"] == {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    assert data["cisco_ai_defense"]["scan_hook_surface"] is True
    assert data["cisco_ai_defense"]["enabled"] is False


def test_project_policy_to_data_skips_empty_scanner_overrides() -> None:
    policy = types.Policy()
    policy.scanner_overrides = cast(
        "dict[types.ScannerType, dict[types.Severity, types.SeverityActionTriple]]",
        {
            "mcp": {},  # empty bucket, should be omitted
            "plugin": {
                "high": types.SeverityActionTriple(
                    runtime="disable", file="quarantine", install="block"
                )
            },
        },
    )

    data = emit.project_policy_to_data(policy)
    assert "mcp" not in data["scanner_overrides"]
    assert data["scanner_overrides"]["plugin"]["HIGH"]["runtime"] == "block"


def test_project_policy_correlator_drops_disabled_patterns() -> None:
    pattern_enabled = types.CorrelationPattern(
        id="lethal-trifecta",
        window_events=50,
        severity_on_match="CRITICAL",
        all_of=[
            types.CorrelationClause(axis="ingress_untrusted", min_severity="MEDIUM"),
            types.CorrelationClause(axis="egress_external"),
        ],
        enabled=True,
    )
    pattern_disabled = types.CorrelationPattern(
        id="dormant", window_events=10, severity_on_match="LOW", enabled=False
    )
    policy = types.Policy(correlator=[pattern_enabled, pattern_disabled])

    data = emit.project_policy_to_data(policy)
    ids = [p["id"] for p in data["correlator"]["patterns"]]
    assert ids == ["lethal-trifecta"]
    assert data["correlator"]["patterns"][0]["all_of"] == [
        {"axis": "ingress_untrusted", "min_severity": "MEDIUM"},
        {"axis": "egress_external"},
    ]


# --- emit ------------------------------------------------------------------


def test_emit_returns_top_level_yaml_and_data_json(tmp_path: Path, monkeypatch) -> None:
    """The first two emit outputs are always the top-level policy
    YAML and the OPA ``data.json``. We pin both shapes here so any
    future schema drift surfaces as a test failure.
    """
    # Stub the bundled preset path so the correlator-diff step
    # doesn't try to read the wheel's real ``policies/`` tree.
    preset_root = tmp_path / "bundled" / "policies"
    preset_root.mkdir(parents=True)
    (preset_root / "strict.yaml").write_text("name: strict\n", encoding="utf-8")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    policy = _make_policy()
    files = emit.emit(policy)
    by_path = {f.path: f for f in files}

    top = by_path["~/.defenseclaw/policies/prod-tight.yaml"]
    assert top.contents.startswith("# DefenseClaw policy: prod-tight")
    body = yaml.safe_load(top.contents)
    assert body["name"] == "prod-tight"
    assert body["admission"]["allow_list_bypass_scan"] is False
    assert body["skill_actions"]["critical"]["install"] == "block"
    assert body["firewall"]["default_action"] == "deny"
    assert body["scanners"] == {
        "codeguard": "",
        "plugin-scanner": "",
        "skill-scanner": "",
    }
    # AID block emitted because endpoint + api_key_env are set.
    assert body["cisco_ai_defense"]["endpoint"] == "https://aid.example"
    assert body["cisco_ai_defense"]["api_key_env"] == "AID_KEY"
    assert body["cisco_ai_defense"]["scan_hook_surface"] is False

    data_file = by_path["~/.defenseclaw/policies/rego/data.json"]
    parsed = json.loads(data_file.contents)
    assert parsed["config"]["policy_name"] == "prod-tight"
    assert parsed["actions"]["HIGH"]["runtime"] == "block"


def test_emit_skips_zero_rule_pack_files_and_empty_judges(
    tmp_path: Path, monkeypatch
) -> None:
    """Files with zero rules and judges with no system_prompt must be
    skipped to keep the bundle minimal."""
    preset_root = tmp_path / "bundled" / "policies"
    preset_root.mkdir(parents=True)
    (preset_root / "strict.yaml").write_text("name: strict\n", encoding="utf-8")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    policy = _make_policy()
    files = emit.emit(policy)
    paths = {f.path for f in files}

    assert (
        "~/.defenseclaw/policies/guardrail/prod-tight/rules/secrets.yaml"
        in paths
    )
    assert (
        "~/.defenseclaw/policies/guardrail/prod-tight/rules/empty.yaml"
        not in paths
    )
    assert (
        "~/.defenseclaw/policies/guardrail/prod-tight/judge/injection.yaml"
        in paths
    )
    assert (
        "~/.defenseclaw/policies/guardrail/prod-tight/judge/pii.yaml"
        not in paths
    )


def test_emit_only_writes_correlator_when_diff_from_preset(
    tmp_path: Path, monkeypatch
) -> None:
    """``correlation-patterns.yaml`` is only emitted when the operator
    actually edited the correlator vs the bundled preset; otherwise
    we let the gateway pick up upstream defaults."""
    preset_root = tmp_path / "bundled" / "policies"
    preset_root.mkdir(parents=True)
    # Preset ships with ONE pattern; if the operator's wizard state
    # matches, no override file should land in the bundle.
    (preset_root / "default.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "default",
                "correlator": [
                    {
                        "id": "x",
                        "window_events": 10,
                        "severity_on_match": "MEDIUM",
                        "enabled": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    matching_policy = types.Policy(
        name="p",
        basedOn="default",
        correlator=[
            types.CorrelationPattern(
                id="x", window_events=10, severity_on_match="MEDIUM", enabled=True
            )
        ],
    )
    matching_paths = {f.path for f in emit.emit(matching_policy)}
    assert (
        "~/.defenseclaw/policies/guardrail/p/correlation-patterns.yaml"
        not in matching_paths
    )

    # Edit one window -> override file appears.
    edited_policy = types.Policy(
        name="p",
        basedOn="default",
        correlator=[
            types.CorrelationPattern(
                id="x", window_events=42, severity_on_match="MEDIUM", enabled=True
            )
        ],
    )
    edited_paths = {f.path for f in emit.emit(edited_policy)}
    assert (
        "~/.defenseclaw/policies/guardrail/p/correlation-patterns.yaml"
        in edited_paths
    )


def test_emit_renders_custom_rego_with_header(tmp_path: Path, monkeypatch) -> None:
    preset_root = tmp_path / "bundled" / "policies"
    preset_root.mkdir(parents=True)
    (preset_root / "strict.yaml").write_text("name: strict\n", encoding="utf-8")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    policy = _make_policy()
    rego = next(
        f for f in emit.emit(policy)
        if f.path == "~/.defenseclaw/policies/rego/custom-my_rule.rego"
    )
    assert rego.contents.startswith("# custom rule\n")
    assert "package defenseclaw.custom.my_rule" in rego.contents
