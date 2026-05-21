# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the bundled scenario loader (Phase 9 patch)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from defenseclaw.tui.creator import scenarios


@pytest.fixture(autouse=True)
def _reset_cache():
    scenarios.load_bundled_scenarios.cache_clear()
    yield
    scenarios.load_bundled_scenarios.cache_clear()


def test_load_bundled_scenarios_returns_typed_records():
    loaded = scenarios.load_bundled_scenarios()
    assert loaded, "expected the docs-site scenarios JSON to ship at least one entry"
    for scenario in loaded:
        assert isinstance(scenario, scenarios.Scenario)
        assert scenario.id
        assert scenario.title
        assert scenario.description
        assert scenario.domain in {
            "admission",
            "audit",
            "firewall",
            "guardrail",
            "sandbox",
            "skill_actions",
        }
        # Verdict labels live in two casings ("allow"/"allowed",
        # "block"/"blocked", etc.) because each Rego entrypoint picks
        # whichever tense matches its own return type. We accept both
        # so the live-test pane never silently filters a real scenario.
        assert scenario.expected_verdict in {
            "allowed",
            "blocked",
            "rejected",
            "warned",
            "alerted",
            "allow",
            "block",
            "deny",
            "alert",
            "true",
        }
        assert isinstance(scenario.input, dict)


def test_scenarios_by_domain_filters():
    admission = scenarios.scenarios_by_domain("admission")
    for entry in admission:
        assert entry.domain == "admission"
    # Each bundled scenario lives under one domain so the filtered
    # view is a strict subset of the full list.
    assert len(admission) <= len(scenarios.load_bundled_scenarios())


def test_scenario_by_id_returns_match_or_none():
    loaded = scenarios.load_bundled_scenarios()
    if loaded:
        first = loaded[0]
        assert scenarios.scenario_by_id(first.id) is first
    assert scenarios.scenario_by_id("does-not-exist") is None


def test_loader_returns_empty_tuple_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        scenarios,
        "_bundled_scenarios_path",
        lambda: tmp_path / "missing.json",
    )
    scenarios.load_bundled_scenarios.cache_clear()
    assert scenarios.load_bundled_scenarios() == ()


def test_loader_skips_malformed_entries(monkeypatch, tmp_path):
    payload = {
        "scenarios": [
            {  # valid
                "id": "ok",
                "title": "ok",
                "description": "ok",
                "domain": "admission",
                "expectedVerdict": "allowed",
                "input": {"target_name": "foo"},
            },
            {"id": "missing-fields"},
            "not-a-dict",
            {
                "id": "bad-input",
                "title": "t",
                "description": "d",
                "domain": "admission",
                "expectedVerdict": "blocked",
                "input": "string-input-rejected",
            },
        ]
    }
    target = tmp_path / "policy-scenarios.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(scenarios, "_bundled_scenarios_path", lambda: target)
    scenarios.load_bundled_scenarios.cache_clear()

    loaded = scenarios.load_bundled_scenarios()
    assert [s.id for s in loaded] == ["ok"]


def test_loader_returns_empty_tuple_on_invalid_json(monkeypatch, tmp_path):
    target = tmp_path / "policy-scenarios.json"
    target.write_text("not a json", encoding="utf-8")
    monkeypatch.setattr(scenarios, "_bundled_scenarios_path", lambda: target)
    scenarios.load_bundled_scenarios.cache_clear()

    assert scenarios.load_bundled_scenarios() == ()
