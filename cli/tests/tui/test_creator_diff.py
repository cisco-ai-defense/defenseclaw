# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dotted-path policy diff (Phase 6 patch).

Mirrors the behavior of ``docs-site/components/policy-creator/lib/diff.ts``
exercised through the Python port. The renderer in the Quick Start
``Review`` step displays this list verbatim, so each behavior we
assert here is also a behavior the operator sees in the UI.
"""

from __future__ import annotations

import dataclasses
import pytest

from defenseclaw.tui.creator.diff import (
    DiffEntry,
    diff_against_base,
    render_diff_lines,
)
from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import (
    CorrelationPattern,
    CustomRegoSnippet,
    FirstPartyEntry,
    SeverityActionTriple,
    WebhookEntry,
)


def _clone(policy):
    """Deep-copy via dataclasses to avoid coupling to ``copy.deepcopy``
    (the wizard mutates nested dataclasses, so we need a real clone
    rather than a shallow ``replace``)."""

    return dataclasses.replace(policy)


def test_diff_against_base_is_empty_for_unmodified_preset():
    policy = load_preset("default")
    assert diff_against_base(policy) == []


def test_diff_admission_changes_emit_changed_entries():
    policy = load_preset("default")
    base = load_preset("default")
    policy.admission.scan_on_install = not base.admission.scan_on_install
    policy.admission.allow_list_bypass_scan = not base.admission.allow_list_bypass_scan

    entries = diff_against_base(policy)
    paths = {e.path for e in entries}
    assert "admission.scan_on_install" in paths
    assert "admission.allow_list_bypass_scan" in paths
    for entry in entries:
        assert entry.kind == "changed"


def test_diff_skill_action_axis_is_dotted():
    policy = load_preset("default")
    policy.skill_actions.set("medium", SeverityActionTriple(runtime="disable"))

    entries = [e for e in diff_against_base(policy) if e.path.startswith("skill_actions.")]
    paths = sorted(e.path for e in entries)
    # Only the runtime axis flipped; file/install stayed as defaults.
    assert paths == ["skill_actions.medium.runtime"]


def test_diff_scanner_overrides_added_entries():
    policy = load_preset("default")
    policy.scanner_overrides["plugin"] = {
        "high": SeverityActionTriple(runtime="disable")
    }

    entries = diff_against_base(policy)
    added = [e for e in entries if e.kind == "added"]
    assert any(e.path == "scanner_overrides.plugin" for e in added)


def test_diff_first_party_allow_list_count_changes():
    policy = load_preset("default")
    policy.first_party_allow_list.append(
        FirstPartyEntry(target_type="skill", target_name="alpha", reason="trusted")
    )

    entries = diff_against_base(policy)
    by_path = {e.path: e for e in entries}
    assert "first_party_allow_list" in by_path
    assert "entries" in by_path["first_party_allow_list"].description


def test_diff_guardrail_thresholds_and_hilt():
    policy = load_preset("default")
    policy.guardrail.block_threshold = 1
    policy.guardrail.alert_threshold = 1
    policy.guardrail.hilt.enabled = not policy.guardrail.hilt.enabled

    paths = {e.path for e in diff_against_base(policy)}
    assert "guardrail.block_threshold" in paths
    assert "guardrail.alert_threshold" in paths
    assert "guardrail.hilt.enabled" in paths


def test_diff_rule_pack_change_reflects_total_rule_count():
    policy = load_preset("default")
    base_total = sum(len(f.rules) for f in policy.rule_pack.files)
    if policy.rule_pack.files and policy.rule_pack.files[0].rules:
        # Drop one rule so the count changes.
        policy.rule_pack.files[0].rules.pop()
        entry = next(e for e in diff_against_base(policy) if e.path == "rule_pack")
        assert f"{base_total} -> {base_total - 1} rules" == entry.description
    else:
        pytest.skip("preset ships zero rules; skip count-change assertion")


def test_diff_suppressions_layers_each_independently():
    policy = load_preset("default")
    base = load_preset("default")
    # Append an entry to each layer that the wizard would let the user
    # author. We use the first-class dataclasses so the count goes up
    # by exactly one.
    from defenseclaw.tui.creator.types import (
        FindingSuppressionDef,
        PreJudgeStripDef,
        ToolSuppressionDef,
    )

    policy.suppressions.pre_judge_strips.append(
        PreJudgeStripDef(id="s1", pattern=".+", context="prompt")
    )
    policy.suppressions.finding_suppressions.append(
        FindingSuppressionDef(id="s2", finding_pattern=".+", entity_pattern=".+")
    )
    policy.suppressions.tool_suppressions.append(
        ToolSuppressionDef(tool_pattern="exec", suppress_findings=["f1"])
    )

    paths = {e.path for e in diff_against_base(policy)}
    assert paths >= {
        "suppressions.pre_judge_strips",
        "suppressions.finding_suppressions",
        "suppressions.tool_suppressions",
    }


def test_diff_firewall_default_action_and_allowed_domains():
    policy = load_preset("default")
    base = load_preset("default")
    flipped = "deny" if base.firewall.default_action == "allow" else "allow"
    policy.firewall.default_action = flipped
    policy.firewall.allowed_domains = list(base.firewall.allowed_domains) + ["api.example.com"]

    paths = {e.path for e in diff_against_base(policy)}
    assert "firewall.default_action" in paths
    assert "firewall.allowed_domains" in paths


def test_diff_webhooks_count_change():
    policy = load_preset("default")
    policy.webhooks.append(
        WebhookEntry(url="https://example.com", type="slack", secret_env="SLACK_TOK")
    )
    entry = next(e for e in diff_against_base(policy) if e.path == "webhooks")
    assert "entries" in entry.description


def test_diff_audit_retention_change_uses_arrow_format():
    policy = load_preset("default")
    base = load_preset("default")
    policy.audit.retention_days = base.audit.retention_days + 60

    entry = next(e for e in diff_against_base(policy) if e.path == "audit.retention_days")
    assert " -> " in entry.description


def test_diff_custom_rego_added_singular_plural_grammar():
    policy = load_preset("default")
    policy.custom_rego.append(
        CustomRegoSnippet(name="s1", package="defenseclaw.custom.s1", source="package x")
    )
    entry = next(e for e in diff_against_base(policy) if e.path == "custom_rego")
    assert entry.kind == "added"
    assert entry.description == "1 custom Rego snippet"

    policy.custom_rego.append(
        CustomRegoSnippet(name="s2", package="defenseclaw.custom.s2", source="package y")
    )
    entry = next(e for e in diff_against_base(policy) if e.path == "custom_rego")
    assert entry.description == "2 custom Rego snippets"


def test_diff_correlator_pattern_preserves_existing_paths():
    policy = load_preset("default")
    # Adding a disabled pattern shouldn't appear as a diff entry
    # because the projector filters disabled patterns and the diff
    # function doesn't enumerate per-pattern entries (matches TS).
    policy.correlator.append(CorrelationPattern(id="probe", enabled=False))
    diff = diff_against_base(policy)
    # Should be empty; only the rule-pack and other knobs would surface.
    assert all(e.path != "correlator" for e in diff)


def test_render_diff_lines_uses_ascii_markers():
    entries = [
        DiffEntry(kind="added", path="foo.bar", description="a -> b"),
        DiffEntry(kind="removed", path="baz", description=""),
        DiffEntry(kind="changed", path="qux", description="1 -> 2"),
    ]
    rendered = render_diff_lines(entries)
    assert rendered == [
        "+ foo.bar: a -> b",
        "- baz: ",
        "~ qux: 1 -> 2",
    ]
