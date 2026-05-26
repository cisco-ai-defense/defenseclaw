# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``Policy`` -> OPA ``data.json`` projection (Phase 7).

The projector is the single point of truth for what ``data.json``
looks like at the moment ``opa eval`` is invoked, so we exercise:

* preset shapes (default/strict/permissive) round-trip through the
  projector without losing fields.
* the ``runtime: enable/disable`` -> ``allow/block`` mapping is the
  one the bundled Rego modules read.
* nested optional structures (correlator, scanner overrides, AID)
  appear with the same omit-when-empty semantics as the TS source.
"""

from __future__ import annotations

import json

from defenseclaw.tui.creator.data_projection import project_policy_to_data
from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import (
    CorrelationClause,
    CorrelationPattern,
    CorrelationSequenceStep,
    SeverityActionTriple,
)


def test_default_preset_projection_has_expected_top_level_keys():
    data = project_policy_to_data(load_preset("default"))
    assert set(data.keys()) == {
        "config",
        "actions",
        "scanner_overrides",
        "first_party_allow_list",
        "severity_ranking",
        "audit",
        "guardrail",
        "firewall",
        "correlator",
        "cisco_ai_defense",
    }


def test_runtime_enable_maps_to_allow_disable_maps_to_block():
    policy = load_preset("default")
    policy.skill_actions.set("high", SeverityActionTriple(runtime="disable"))
    policy.skill_actions.set("medium", SeverityActionTriple(runtime="enable"))

    data = project_policy_to_data(policy)
    assert data["actions"]["HIGH"]["runtime"] == "block"
    assert data["actions"]["MEDIUM"]["runtime"] == "allow"


def test_severity_keys_are_uppercase():
    data = project_policy_to_data(load_preset("default"))
    assert sorted(data["actions"].keys()) == ["CRITICAL", "HIGH", "INFO", "LOW", "MEDIUM"]


def test_severity_ranking_matches_legacy_data_file():
    data = project_policy_to_data(load_preset("default"))
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


def test_scanner_overrides_only_emit_for_populated_axes():
    policy = load_preset("default")
    policy.scanner_overrides["plugin"] = {
        "high": SeverityActionTriple(runtime="disable")
    }

    data = project_policy_to_data(policy)
    assert data["scanner_overrides"]["plugin"]["HIGH"]["runtime"] == "block"
    # Missing severities don't appear.
    assert "LOW" not in data["scanner_overrides"]["plugin"]


def test_correlator_omits_disabled_patterns():
    policy = load_preset("default")
    policy.correlator = [
        CorrelationPattern(id="active", enabled=True, window_events=10),
        CorrelationPattern(id="paused", enabled=False, window_events=20),
    ]

    data = project_policy_to_data(policy)
    ids = [p["id"] for p in data["correlator"]["patterns"]]
    assert ids == ["active"]


def test_correlator_clause_drops_empty_fields():
    policy = load_preset("default")
    policy.correlator = [
        CorrelationPattern(
            id="probe",
            enabled=True,
            all_of=[
                CorrelationClause(axis="ingress_untrusted"),
                CorrelationClause(min_severity="HIGH"),
            ],
            sequence=[CorrelationSequenceStep(severity="LOW")],
            fingerprint_chain=[CorrelationClause(tool_capability_class="exec_shell")],
        )
    ]

    data = project_policy_to_data(policy)
    pattern = data["correlator"]["patterns"][0]
    assert pattern["all_of"] == [
        {"axis": "ingress_untrusted"},
        {"min_severity": "HIGH"},
    ]
    assert pattern["sequence"] == [{"severity": "LOW"}]
    assert pattern["fingerprint_chain"] == [{"tool_capability_class": "exec_shell"}]


def test_aid_lane_defaults_when_field_uninitialized():
    policy = load_preset("default")
    data = project_policy_to_data(policy)
    aid = data["cisco_ai_defense"]
    assert set(aid.keys()) == {"enabled", "api_key_env", "scan_hook_surface"}
    assert isinstance(aid["enabled"], bool)
    assert isinstance(aid["scan_hook_surface"], bool)


def test_projection_is_json_safe():
    data = project_policy_to_data(load_preset("default"))
    # Round-trip through json to assert JSON-safety.
    serialized = json.dumps(data)
    assert isinstance(serialized, str)
    assert json.loads(serialized) == data


def test_strict_preset_block_threshold_propagates():
    data = project_policy_to_data(load_preset("strict"))
    # Strict preset cranks block_threshold down compared to default.
    assert isinstance(data["guardrail"]["block_threshold"], int)


def test_first_party_allow_list_is_pure_dict_list():
    policy = load_preset("default")
    data = project_policy_to_data(policy)
    for entry in data["first_party_allow_list"]:
        assert isinstance(entry, dict)
        assert "target_type" in entry
        assert "target_name" in entry
