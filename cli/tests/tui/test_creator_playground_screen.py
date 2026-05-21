# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Render-only smoke tests for ``PlaygroundScreen``.

We exercise the per-section detail renderers by spinning up a
``PlaygroundModel``, jumping to each section, and asking the
matching renderer to produce a non-empty ``Text`` instance. This
catches the easy regression: someone adds a section to
``SECTION_DEFS`` and forgets to register a renderer (or vice-versa).
A full ``App.run_test`` integration test is not in scope here -
those run too slowly for the per-section coverage we want.
"""

from __future__ import annotations

import pytest

from defenseclaw.tui.creator.playground_model import (
    SECTION_DEFS,
    PlaygroundModel,
)
from defenseclaw.tui.creator.presets import load_preset
from defenseclaw.tui.creator.types import (
    CorrelationPattern,
    CustomRegoSnippet,
    FirstPartyEntry,
    JudgeConfig,
    SensitiveTool,
    WebhookEntry,
)
from defenseclaw.tui.screens.playground import _SECTION_RENDERERS, _STATUS_GLYPH


@pytest.fixture
def populated_policy():
    """Return a policy with at least one entry in every list-shaped
    field so renderers exercise the "non-empty" branches.
    """

    policy = load_preset("default")
    policy.first_party_allow_list = [
        FirstPartyEntry(target_type="skill", target_name="alpha", reason="trusted")
    ]
    policy.judges = [
        JudgeConfig(name="injection", enabled=True, system_prompt="be safe")
    ]
    policy.webhooks = [
        WebhookEntry(url="https://example", type="slack", secret_env="X")
    ]
    policy.sensitive_tools = [SensitiveTool(name="exec", result_inspection=True)]
    policy.correlator = [CorrelationPattern(id="probe", enabled=True)]
    policy.custom_rego = [
        CustomRegoSnippet(name="s1", package="defenseclaw.custom.s1", source="package x")
    ]
    return policy


def test_every_section_has_a_registered_renderer():
    section_ids = {s.id for s in SECTION_DEFS}
    renderer_ids = set(_SECTION_RENDERERS.keys())
    assert section_ids == renderer_ids


def test_status_glyphs_cover_all_statuses():
    assert set(_STATUS_GLYPH.keys()) == {"untouched", "customized", "warning"}


@pytest.mark.parametrize("section_id", [s.id for s in SECTION_DEFS])
def test_section_renderers_produce_non_empty_output(populated_policy, section_id):
    model = PlaygroundModel(policy=populated_policy)
    assert model.jump_to_section(section_id)
    renderer = _SECTION_RENDERERS[section_id]
    text = renderer(model)
    assert text.plain, f"{section_id} produced empty Rich text"


def test_review_section_renders_yaml_preview(populated_policy):
    model = PlaygroundModel(policy=populated_policy)
    model.jump_to_section("review")
    renderer = _SECTION_RENDERERS["review"]
    text = renderer(model)
    assert "Generated YAML preview" in text.plain
    # The YAML emit should produce at least the policy header.
    assert "name:" in text.plain or "description:" in text.plain


def test_severity_matrix_renderer_shows_axis_label():
    model = PlaygroundModel(policy=load_preset("default"))
    model.jump_to_section("severity-matrix")
    text = _SECTION_RENDERERS["severity-matrix"](model)
    assert "skill_actions" in text.plain
    model.scanner_axis = 1
    text = _SECTION_RENDERERS["severity-matrix"](model)
    assert "scanner_overrides.skill" in text.plain


def test_aid_renderer_shows_warning_when_enabled_without_key():
    policy = load_preset("default")
    policy.cisco_ai_defense.enabled = True
    policy.cisco_ai_defense.api_key_env = ""
    model = PlaygroundModel(policy=policy)
    model.jump_to_section("cisco-ai-defense")
    text = _SECTION_RENDERERS["cisco-ai-defense"](model)
    assert "WARNING" in text.plain
