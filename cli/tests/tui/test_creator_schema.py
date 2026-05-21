# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 6 of the Policy tab overhaul: tests for the Creator schema,
preset loader, and ``PolicyDraftModel``.

These tests stay below the Textual layer - no ``App`` is booted, no
modal screens are mounted - so they run in milliseconds and stay
deterministic on CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from defenseclaw.tui.creator import draft, presets, types


def _write_minimal_preset(root: Path, name: str, *, scan_on_install: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "name": name,
                "description": f"{name} preset",
                "based_on": name if name in {"default", "strict", "permissive"} else "default",
                "admission": {
                    "scan_on_install": scan_on_install,
                    "allow_list_bypass_scan": True,
                },
                "skill_actions": {
                    "critical": {"runtime": "disable", "file": "quarantine", "install": "block"},
                    "high": {"runtime": "disable", "file": "quarantine", "install": "block"},
                    "medium": {"runtime": "enable", "file": "none", "install": "none"},
                    "low": {"runtime": "enable", "file": "none", "install": "none"},
                    "info": {"runtime": "enable", "file": "none", "install": "none"},
                },
                "guardrail": {
                    "block_threshold": 4,
                    "alert_threshold": 2,
                    "cisco_trust_level": "full",
                    "hilt": {"enabled": False, "min_severity": "MEDIUM"},
                    "patterns": {"injection": ["ignore previous"], "secrets": ["sk-"]},
                    "severity_mappings": {"injection": "HIGH"},
                },
                "firewall": {
                    "default_action": "allow",
                    "allowed_domains": ["api.github.com"],
                    "blocked_destinations": ["169.254.169.254"],
                    "allowed_ports": [443, 80],
                },
                "webhooks": [
                    {
                        "url": "https://hooks.slack.example/T0/B0/abc",
                        "type": "slack",
                        "secret_env": "SLACK_WEBHOOK_TOKEN",
                        "min_severity": "HIGH",
                        "events": ["block", "drift"],
                        "enabled": True,
                    }
                ],
                "audit": {
                    "log_all_actions": True,
                    "log_scan_results": True,
                    "retention_days": 30,
                },
                "scanners": {
                    "codeguard": "default",
                    "plugin-scanner": "default",
                    "skill-scanner": "default",
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


# --- types ------------------------------------------------------------------


def test_severity_action_matrix_get_set_items() -> None:
    """The matrix exposes ``get`` / ``set`` / ``items`` helpers so the
    wizard can iterate severities without reflection or hardcoded
    attribute lists."""
    matrix = types.SeverityActionMatrix()
    assert matrix.get("critical").runtime == "enable"

    matrix.set("critical", types.SeverityActionTriple(runtime="disable", file="quarantine", install="block"))
    assert matrix.get("critical").install == "block"

    items = dict(matrix.items())
    assert set(items) == set(types.SEVERITIES)
    assert items["critical"].install == "block"


def test_default_policy_is_a_valid_no_op_configuration() -> None:
    """A bare ``Policy()`` carries valid defaults - the engine treats
    every field as a no-op override. This is a contract test:
    constructing ``Policy()`` from scratch must never raise and must
    populate every required nested dataclass.
    """
    policy = types.Policy()
    assert policy.name == ""
    assert policy.basedOn == "default"
    assert isinstance(policy.admission, types.AdmissionConfig)
    assert isinstance(policy.skill_actions, types.SeverityActionMatrix)
    assert isinstance(policy.guardrail, types.GuardrailConfig)
    assert isinstance(policy.firewall, types.FirewallConfig)
    assert isinstance(policy.cisco_ai_defense, types.CiscoAIDefenseConfig)
    assert policy.first_party_allow_list == []
    assert policy.webhooks == []
    assert policy.custom_rego == []
    assert policy.correlator == []


def test_validation_finding_is_immutable_and_compares_by_value() -> None:
    """Validators dedupe findings by ``(code, location)`` and the UI
    uses them as ``set`` keys; verify hashability + equality.
    """
    a = types.ValidationFinding(level="error", code="REGEX_INVALID", message="boom", location="rule_pack.0.0")
    b = types.ValidationFinding(level="error", code="REGEX_INVALID", message="boom", location="rule_pack.0.0")
    assert a == b
    assert hash(a) == hash(b)
    bag: set[types.ValidationFinding] = {a, b}
    assert len(bag) == 1


# --- presets ----------------------------------------------------------------


def test_load_preset_parses_skill_actions_guardrail_firewall_webhooks(tmp_path: Path) -> None:
    """``load_preset`` builds a ``Policy`` from a YAML file with the
    same top-level keys ``defenseclaw policy activate`` consumes.
    """
    _write_minimal_preset(tmp_path, "default")
    policy = presets.load_preset("default", root=tmp_path)

    assert policy.name == "default"
    assert policy.basedOn == "default"
    assert policy.admission.scan_on_install is True
    assert policy.skill_actions.get("critical").install == "block"
    assert policy.skill_actions.get("medium").install == "none"

    assert policy.guardrail.block_threshold == 4
    assert "injection" in policy.guardrail.patterns
    assert policy.guardrail.severity_mappings["injection"] == "HIGH"

    assert policy.firewall.default_action == "allow"
    assert "api.github.com" in policy.firewall.allowed_domains

    assert len(policy.webhooks) == 1
    assert policy.webhooks[0].secret_env == "SLACK_WEBHOOK_TOKEN"
    assert "block" in policy.webhooks[0].events
    assert policy.scanners.codeguard == "default"


def test_load_preset_returns_defaults_for_missing_yaml(tmp_path: Path) -> None:
    """A preset name that doesn't exist on disk returns a fully-default
    ``Policy`` instead of raising. The Creator should never crash on
    a missing preset file - it falls back to the no-op baseline.
    """
    policy = presets.load_preset("default", root=tmp_path / "nonexistent")
    assert policy.name == "default"
    assert policy.skill_actions.get("critical").install == "none"


def test_load_preset_with_pack_assembles_rules_judges_suppressions(tmp_path: Path) -> None:
    """The richer ``load_preset_with_pack`` helper composes the
    policy YAML with its companion ``guardrail/<pack>/`` tree
    (rule files, judge prompts, suppressions, sensitive tools).
    """
    _write_minimal_preset(tmp_path, "default")

    pack_root = tmp_path / "guardrail" / "default"
    (pack_root / "rules").mkdir(parents=True)
    (pack_root / "judge").mkdir()

    (pack_root / "rules" / "secrets.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "category": "secrets",
                "rules": [
                    {
                        "id": "secret-aws-akid",
                        "pattern": "AKIA[0-9A-Z]{16}",
                        "title": "AWS Access Key ID",
                        "severity": "HIGH",
                        "confidence": 0.9,
                        "tags": ["aws", "iam"],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    (pack_root / "suppressions.yaml").write_text(
        yaml.safe_dump(
            {
                "pre_judge_strips": [
                    {
                        "id": "strip-iso-timestamp",
                        "pattern": r"\b\d{4}-\d{2}-\d{2}T\d{2}",
                        "context": "log line",
                        "applies_to": ["pii", "injection"],
                    }
                ],
                "finding_suppressions": [
                    {
                        "id": "noise-test-fixture",
                        "finding_pattern": "secret-aws",
                        "entity_pattern": "test-fixture",
                        "reason": "test data",
                    }
                ],
                "tool_suppressions": [
                    {
                        "tool_pattern": "shell.*",
                        "suppress_findings": ["secret-aws-akid"],
                        "reason": "shell sandbox",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    (pack_root / "sensitive-tools.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": [
                    {
                        "name": "send_email",
                        "result_inspection": True,
                        "judge_result": True,
                        "min_entities_for_alert": 2,
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    (pack_root / "judge" / "injection.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "injection",
                "enabled": True,
                "system_prompt": "Detect prompt injection attempts.",
                "min_categories_for_critical": 2,
                "categories": {
                    "ignore_previous": {
                        "finding_id": "injection-ignore-previous",
                        "severity_default": "HIGH",
                        "enabled": True,
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    policy, files = presets.load_preset_with_pack("default", root=tmp_path)

    assert len(files) == 1
    assert files[0].category == "secrets"
    assert files[0].rules[0].id == "secret-aws-akid"
    assert files[0].rules[0].severity == "HIGH"
    assert files[0].rules[0].confidence == 0.9

    assert len(policy.suppressions.pre_judge_strips) == 1
    assert "pii" in policy.suppressions.pre_judge_strips[0].applies_to
    assert len(policy.suppressions.finding_suppressions) == 1
    assert len(policy.suppressions.tool_suppressions) == 1

    assert len(policy.sensitive_tools) == 1
    assert policy.sensitive_tools[0].name == "send_email"
    assert policy.sensitive_tools[0].min_entities_for_alert == 2

    assert len(policy.judges) == 1
    assert policy.judges[0].name == "injection"
    assert policy.judges[0].min_categories_for_critical == 2
    assert "ignore_previous" in policy.judges[0].categories


# --- draft model ------------------------------------------------------------


def test_draft_new_from_preset_seeds_policy_with_metadata(tmp_path: Path, monkeypatch) -> None:
    """``new_from_preset`` clones the preset YAML, sets the policy
    name + slug, and prepares the metadata sidecar without touching
    disk yet."""
    preset_root = tmp_path / "bundled" / "policies"
    _write_minimal_preset(preset_root, "default")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    model = draft.PolicyDraftModel(tmp_path / "data")
    model.new_from_preset("My Tight Policy", preset="default")

    assert model.policy.name == "My Tight Policy"
    assert model.policy.basedOn == "default"
    assert model.policy.admission.scan_on_install is True
    assert model.metadata.slug == "my-tight-policy"
    # Disk untouched until ``save`` is called.
    assert not (tmp_path / "data" / "policy-creator").exists()


def test_draft_save_then_load_round_trips_through_disk(tmp_path: Path, monkeypatch) -> None:
    """Saving a draft to ``<data_dir>/policy-creator/drafts/<slug>.json``
    and re-loading it preserves every field plus the wizard step
    pointer + answers map.
    """
    preset_root = tmp_path / "bundled" / "policies"
    _write_minimal_preset(preset_root, "default")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    data_dir = tmp_path / "data"
    model = draft.PolicyDraftModel(data_dir)
    model.new_from_preset("prod-tight", preset="default")
    model.policy.firewall.default_action = "deny"
    model.metadata.quick_start_step = 4
    model.metadata.quick_start_answers = {"posture": "strict", "audience": "engineering"}
    model.metadata.last_section = "guardrail"
    written = model.save()

    assert written.exists()
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["policy"]["firewall"]["default_action"] == "deny"
    assert payload["metadata"]["quick_start_step"] == 4
    assert payload["metadata"]["quick_start_answers"]["posture"] == "strict"

    # Round-trip: a fresh model should load the same thing back.
    reopened = draft.PolicyDraftModel(data_dir)
    assert reopened.load("prod-tight") is True
    assert reopened.policy.firewall.default_action == "deny"
    assert reopened.metadata.quick_start_step == 4
    assert reopened.metadata.last_section == "guardrail"
    assert reopened.metadata.quick_start_answers["posture"] == "strict"


def test_draft_load_returns_false_for_missing_or_corrupt_files(tmp_path: Path) -> None:
    """Missing files and JSON garbage both return False instead of
    raising - the operator should never lose Creator access because
    of a bad disk byte.
    """
    model = draft.PolicyDraftModel(tmp_path / "data")
    assert model.load("does-not-exist") is False

    drafts = draft.drafts_dir(tmp_path / "data")
    (drafts / "broken.json").write_text("not-json-at-all{", encoding="utf-8")
    assert model.load("broken") is False


def test_draft_list_drafts_returns_alphabetic_slugs(tmp_path: Path, monkeypatch) -> None:
    preset_root = tmp_path / "bundled" / "policies"
    _write_minimal_preset(preset_root, "default")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    model = draft.PolicyDraftModel(tmp_path / "data")
    for name in ("zeta", "alpha", "mu"):
        model.new_from_preset(name)
        model.save()

    assert model.list_drafts() == ["alpha", "mu", "zeta"]


def test_draft_diff_vs_preset_flags_modified_sections(tmp_path: Path, monkeypatch) -> None:
    """``diff_vs_preset`` returns True for every section the operator
    has touched and False for everything else, ignoring the
    intentionally-overridden ``name`` / ``description`` / ``basedOn``.
    """
    preset_root = tmp_path / "bundled" / "policies"
    _write_minimal_preset(preset_root, "default")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)
    monkeypatch.setattr(draft, "load_preset", presets.load_preset)

    model = draft.PolicyDraftModel(tmp_path / "data")
    model.new_from_preset("prod", preset="default")

    diff = model.diff_vs_preset()
    assert "name" not in diff
    assert "basedOn" not in diff
    assert all(value is False for value in diff.values()), diff
    assert model.is_dirty is False

    # Mutate one section.
    model.policy.firewall.default_action = "deny"
    diff = model.diff_vs_preset()
    assert diff["firewall"] is True
    assert diff["admission"] is False
    assert model.is_dirty is True


def test_draft_discard_removes_file_but_keeps_in_memory_state(
    tmp_path: Path, monkeypatch
) -> None:
    """``discard`` deletes the on-disk draft file but leaves the
    in-memory policy alone so the operator can change their mind.
    """
    preset_root = tmp_path / "bundled" / "policies"
    _write_minimal_preset(preset_root, "default")
    monkeypatch.setattr(presets, "bundled_policies_dir", lambda: preset_root)

    model = draft.PolicyDraftModel(tmp_path / "data")
    model.new_from_preset("dropme")
    written = model.save()
    assert written.is_file()

    assert model.discard() is True
    assert written.is_file() is False
    # In-memory state survives.
    assert model.policy.name == "dropme"
    # Re-discard returns False without raising.
    assert model.discard() is False
