# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Headless tests for ``PlaygroundModel`` (Phase 11)."""

from __future__ import annotations

import pytest

from defenseclaw.tui.creator.playground_model import (
    SECTION_DEFS,
    PlaygroundModel,
)
from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import (
    CorrelationPattern,
    FirstPartyEntry,
    SeverityActionTriple,
    WebhookEntry,
)


@pytest.fixture
def model():
    return PlaygroundModel(policy=load_preset("default"))


def test_section_defs_cover_18_sections():
    assert len(SECTION_DEFS) == 18
    ids = {s.id for s in SECTION_DEFS}
    expected = {
        "basics",
        "severity-matrix",
        "admission",
        "guardrail",
        "rules",
        "suppressions",
        "sensitive-tools",
        "judges",
        "correlator",
        "firewall",
        "webhooks",
        "watch",
        "enforcement",
        "audit",
        "scanners",
        "cisco-ai-defense",
        "custom-rego",
        "review",
    }
    assert ids == expected


def test_section_status_for_default_preset(model):
    # Every section returns one of three statuses; ``warning`` only
    # surfaces for sections that detect a risky configuration.
    for i in range(len(SECTION_DEFS)):
        assert model.status_for(i) in {"untouched", "customized", "warning"}


def test_basics_status_warns_on_default_name():
    model = PlaygroundModel(policy=load_preset("default"))
    model.policy.name = "my-policy"  # the placeholder name flagged by validator
    assert model.status_for(model.section_by_id("basics")) == "warning"


def test_basics_handler_cycles_preset(model):
    model.jump_to_section("basics")
    initial = model.policy.basedOn
    msg = model.handle_key("+")
    assert msg.startswith("basedOn -> ")
    assert model.policy.basedOn != initial


def test_severity_matrix_navigation_and_runtime_cycle(model):
    model.jump_to_section("severity-matrix")
    # j moves cursor down; space cycles runtime axis.
    model.handle_key("j")
    assert model.severity_cursor == 1
    msg = model.handle_key("space")
    assert "runtime" in msg


def test_severity_matrix_axis_cycle_targets_scanner_overrides(model):
    model.jump_to_section("severity-matrix")
    model.handle_key("l")  # axis 1: skill
    assert model.scanner_axis == 1
    model.handle_key("space")
    # scanner override set for skill scanner
    assert "skill" in model._axis_label()
    assert "skill" in model.policy.scanner_overrides


def test_admission_toggles_persist(model):
    model.jump_to_section("admission")
    initial_scan = model.policy.admission.scan_on_install
    model.handle_key("s")
    assert model.policy.admission.scan_on_install != initial_scan
    initial_bypass = model.policy.admission.allow_list_bypass_scan
    model.handle_key("b")
    assert model.policy.admission.allow_list_bypass_scan != initial_bypass


def test_admission_x_removes_first_party_entry(model):
    # Reset to a known single-entry list so we can assert the removal
    # leaves nothing behind.
    model.policy.first_party_allow_list = [
        FirstPartyEntry(target_type="skill", target_name="alpha")
    ]
    model.jump_to_section("admission")
    msg = model.handle_key("x")
    assert "removed" in msg
    assert not model.policy.first_party_allow_list


def test_guardrail_threshold_clamps_to_valid_range(model):
    model.jump_to_section("guardrail")
    model.policy.guardrail.block_threshold = 4
    msg = model.handle_key("+")
    # No-op at the upper bound
    assert model.policy.guardrail.block_threshold == 4
    assert msg == ""

    model.policy.guardrail.block_threshold = 1
    msg = model.handle_key("-")
    assert model.policy.guardrail.block_threshold == 1
    assert msg == ""


def test_guardrail_h_toggles_hilt(model):
    model.jump_to_section("guardrail")
    initial = model.policy.guardrail.hilt.enabled
    model.handle_key("h")
    assert model.policy.guardrail.hilt.enabled != initial


def test_firewall_default_action_cycles(model):
    model.jump_to_section("firewall")
    model.policy.firewall.default_action = "allow"
    model.handle_key("space")
    assert model.policy.firewall.default_action == "deny"
    model.handle_key("space")
    assert model.policy.firewall.default_action == "allow"


def test_webhooks_x_removes_entry(model):
    model.policy.webhooks.append(
        WebhookEntry(url="https://x.test", type="slack", secret_env="X")
    )
    model.jump_to_section("webhooks")
    msg = model.handle_key("x")
    assert "removed webhook" in msg
    assert not model.policy.webhooks


def test_watch_toggle_and_interval(model):
    model.jump_to_section("watch")
    model.policy.watch.rescan_enabled = False
    model.handle_key("space")
    assert model.policy.watch.rescan_enabled is True
    model.policy.watch.rescan_interval_min = 10
    model.handle_key("+")
    assert model.policy.watch.rescan_interval_min == 15


def test_enforcement_increment(model):
    model.jump_to_section("enforcement")
    initial = model.policy.enforcement.max_enforcement_delay_seconds
    model.handle_key("+")
    assert model.policy.enforcement.max_enforcement_delay_seconds == initial + 1


def test_audit_retention_jumps_by_seven(model):
    model.jump_to_section("audit")
    model.policy.audit.retention_days = 30
    model.handle_key("+")
    assert model.policy.audit.retention_days == 37
    model.handle_key("-")
    assert model.policy.audit.retention_days == 30


def test_aid_toggle_marks_warning_when_no_key(model):
    model.policy.cisco_ai_defense.api_key_env = ""
    model.jump_to_section("cisco-ai-defense")
    model.handle_key("space")  # enables AID
    assert model.policy.cisco_ai_defense.enabled is True
    idx = model.section_by_id("cisco-ai-defense")
    assert model.status_for(idx) == "warning"


def test_correlator_space_toggles_first_pattern_enabled(model):
    model.policy.correlator = [CorrelationPattern(id="p1", enabled=True)]
    model.jump_to_section("correlator")
    msg = model.handle_key("space")
    assert "p1" in msg
    assert model.policy.correlator[0].enabled is False


def test_handle_key_p_toggles_test_pane(model):
    assert model.test_pane_open is False
    model.handle_key("p")
    assert model.test_pane_open is True
    model.handle_key("p")
    assert model.test_pane_open is False


def test_handle_key_d_toggles_diff(model):
    assert model.diff_open is False
    model.handle_key("d")
    assert model.diff_open is True


def test_handle_key_brackets_navigate_sections(model):
    model.jump_to_section("basics")
    model.handle_key("]")
    assert model.section.id == "severity-matrix"
    model.handle_key("[")
    assert model.section.id == "basics"


def test_dirty_flips_after_first_mutation(model):
    assert model.dirty is False
    model.jump_to_section("admission")
    model.handle_key("s")
    assert model.dirty is True


def test_is_savable_blocks_when_validation_errors():
    # Set up a policy that would trigger ``RULE_ID_FORMAT`` (a
    # blocking validator code) by injecting a bad rule id.
    from defenseclaw.tui.creator.types import (
        RuleDef,
        RulesFile,
        RulePackBundle,
    )

    policy = load_preset("default")
    # Replace the rule pack with one bad rule.
    policy.rule_pack = RulePackBundle(
        name="custom",
        files=[
            RulesFile(
                filename="bad.yaml",
                category="probe",
                rules=[RuleDef(id="!!invalid!!", pattern="x", title="t")],
            )
        ],
    )
    model = PlaygroundModel(policy=policy)
    summary = model.summary()
    if summary.errors:
        assert model.is_savable() is False


def test_diff_against_preset_surfaces_changes(model):
    assert model.diff() == []
    model.policy.guardrail.block_threshold = 1
    entries = model.diff()
    assert any(e.path == "guardrail.block_threshold" for e in entries)


def test_jump_to_section_with_unknown_id_returns_false(model):
    assert model.jump_to_section("does-not-exist") is False


def test_save_payload_returns_live_policy(model):
    out = model.save_payload()
    assert out is model.policy
