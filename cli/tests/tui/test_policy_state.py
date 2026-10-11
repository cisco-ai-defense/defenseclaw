# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel model: rows, keys, weakening checks, posture, validation."""

from __future__ import annotations

import json

from defenseclaw.policy_catalog import ConnectorPack, PolicySummary, RulePack
from defenseclaw.tui.app import _policy_posture
from defenseclaw.tui.policy_panel import policy_change_modal, rule_pack_change_modal
from defenseclaw.tui.screens.rule_pack_picker import RulePackChoice
from defenseclaw.tui.services.overview_state import OverviewConfig
from defenseclaw.tui.services.policy_state import (
    POLICY_VIEWS,
    PackValidation,
    PoliciesPanelModel,
    decode_sandbox_packs,
    pack_weakens,
    parse_validation,
    policy_weakenings,
)


def policy(
    name: str,
    *,
    active: bool = False,
    block: str = "CRITICAL",
    alert: str = "MEDIUM+",
    install: str = "HIGH+",
    firewall: str = "deny",
    hilt: bool | None = None,
) -> PolicySummary:
    return PolicySummary(
        name=name,
        description=f"{name} policy",
        builtin=name in {"default", "strict", "permissive"},
        active=active,
        path=f"/policies/{name}.yaml",
        block_at=block,
        alert_at=alert,
        install_block_at=install,
        firewall_default=firewall,
        hilt=hilt,
        scanner_overrides=0,
        adds_webhooks=False,
        sets_cisco=False,
    )


DEFAULT = policy("default", active=True)
STRICT = policy("strict", block="MEDIUM+", alert="LOW+", install="MEDIUM+")
PERMISSIVE = policy("permissive", alert="HIGH+", install="CRITICAL", firewall="allow")


def loaded_model() -> PoliciesPanelModel:
    model = PoliciesPanelModel(sandbox_supported=True)
    model.apply_policies([DEFAULT, PERMISSIVE, STRICT])
    model.apply_packs(
        ConnectorPack("global", "default", "/p/guardrail/default", "default"),
        [
            ConnectorPack("codex", "strict", "/p/guardrail/strict", "override"),
            ConnectorPack("claudecode", "default", "/p/guardrail/default", "default"),
        ],
        [RulePack("default", "/p/guardrail/default", "preset", ("global", "claudecode"))],
    )
    return model


def test_policy_rows_fit_80_columns_and_widen_at_120() -> None:
    model = loaded_model()
    assert model.select_view("policies").kind == "render"
    compact = model.data_table_rows(80)
    columns = model.data_table_columns(80)
    assert len(columns) == len(compact[0]) == 6
    assert compact[0][:2] == ("●", "default")
    # Six short cells plus the table's padding stay inside an 80-column body.
    widest = [max(len(c), *(len(r[i]) for r in compact)) for i, c in enumerate(columns)]
    assert sum(widest) + 2 * len(widest) <= 74
    wide = model.data_table_rows(120)
    assert len(model.data_table_columns(120)) == len(wide[0]) == 7
    assert wide[1][1] == "permissive"


def test_rule_pack_rows_put_global_first_and_name_the_source() -> None:
    model = loaded_model()
    assert model.select_view("packs").kind == "render"
    rows = model.data_table_rows(80)
    assert [row[0] for row in rows] == ["global", "codex", "claudecode"]
    assert rows[1][1:] == ("strict", "own pack")
    assert model.override_connectors() == ("codex",)
    assert len(model.data_table_rows(120)[0]) == 4


def test_enter_asks_for_the_right_picker_per_view() -> None:
    model = loaded_model()
    model.select_view("policies")
    model.handle_key("down")
    action = model.handle_key("enter")
    assert (action.kind, action.policy) == ("pick_policy", "permissive")
    model.select_view("packs")
    assert model.handle_key("enter") == model.handle_key("enter")
    assert model.handle_key("enter").connector == ""
    model.handle_key("j")
    assert model.handle_key("enter").connector == "codex"


def test_sandbox_view_loads_lazily_and_is_hidden_when_unsupported() -> None:
    model = loaded_model()
    assert model.select_view("sandbox_packs").kind == "load_sandbox_packs"
    model.apply_sandbox_json(
        json.dumps(
            {
                "packs": [
                    {"name": "open", "builtin": True, "profile": "open", "digest": "a" * 64},
                    {"name": "mine", "builtin": False, "error": "bad yaml"},
                ]
            }
        )
    )
    assert model.data_table_rows(80) == (
        ("●", "open", "built-in", "open", "a" * 12),
        ("", "mine", "custom", "-", "invalid"),
    )
    assert model.select_view("sandbox_packs").kind == "render"

    unsupported = PoliciesPanelModel(sandbox_supported=False)
    assert "sandbox_packs" not in unsupported.views()
    assert unsupported.select_view("sandbox_packs").kind == "hint"
    assert unsupported.view == "posture"
    assert "←/→ view" in unsupported.keys_hint()


def test_detail_toggles_and_escape_closes_it() -> None:
    model = loaded_model()
    model.select_view("policies")
    assert model.detail_text() == ""
    model.handle_key("i")
    assert "block CRITICAL · alert MEDIUM+" in model.detail_text()
    assert model.handle_key("escape").kind == "render"
    assert model.detail_text() == ""
    assert model.handle_key("escape").kind == "none"


def test_keys_hint_fits_one_line_at_80_columns() -> None:
    model = loaded_model()
    for view in POLICY_VIEWS:
        assert len(model.keys_hint(view)) <= 78


def test_weakening_covers_thresholds_and_approval() -> None:
    assert policy_weakenings(DEFAULT, STRICT) == ()
    reasons = policy_weakenings(DEFAULT, PERMISSIVE)
    assert len(reasons) == 2  # alert, install; the preset's firewall default is not enforced, so not compared
    assert policy_weakenings(STRICT, DEFAULT)  # block MEDIUM+ -> CRITICAL
    assert policy_weakenings(policy("a", hilt=True), policy("b", hilt=False)) == ("human approval is turned off",)
    assert policy_weakenings(None, PERMISSIVE) == ()
    assert policy_change_modal(DEFAULT, PERMISSIVE).actions[0].danger is True
    assert policy_change_modal(DEFAULT, STRICT).actions[0].danger is False


def test_rule_pack_modal_names_cleared_overrides_and_flags_looser_presets() -> None:
    model = loaded_model()
    assert pack_weakens(("strict",), "default") is True
    assert pack_weakens(("default",), "strict") is False
    assert pack_weakens(("mine",), "permissive") is False
    valid = PackValidation("valid", rule_count=3, enabled_rule_count=3, rule_file_count=1)
    global_choice = RulePackChoice("", "permissive", "permissive", "/p/guardrail/permissive", True, valid)
    modal = rule_pack_change_modal(model, global_choice)
    assert any("codex" in line for line in modal.details)
    assert modal.actions[0].danger is True
    one = RulePackChoice("claudecode", "strict", "strict", "/p/guardrail/strict", True, valid)
    assert rule_pack_change_modal(model, one).actions[0].danger is False


def test_validation_json_decodes_all_three_outcomes() -> None:
    ok = parse_validation(
        0,
        json.dumps(
            {
                "valid": True,
                "summary": {"rule_count": 40, "enabled_rule_count": 38, "rule_file_count": 5, "digest": "b" * 64},
            }
        ),
    )
    assert (ok.state, ok.enabled_rule_count, ok.rule_count, ok.digest[:4]) == ("valid", 38, 40, "bbbb")
    bad = parse_validation(
        1, json.dumps({"valid": False, "error": {"path": "rules/x.yaml", "code": "bad_pattern", "reason": "bad regex"}})
    )
    assert bad.state == "invalid"
    assert "rules/x.yaml" in bad.message
    assert parse_validation(2, "").state == "unavailable"
    assert parse_validation(0, "not json").state == "invalid"


def test_posture_names_the_active_policy_thresholds() -> None:
    cfg = OverviewConfig(guardrail_mode="action")
    active = policy("strict", active=True, block="MEDIUM+", alert="LOW+")
    assert _policy_posture(cfg, active) == "strict · block MEDIUM+ · alert LOW+"
    divergent = OverviewConfig(
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
        connector_packs=(("codex", "strict"), ("claudecode", "permissive")),
    )
    assert _policy_posture(divergent, active).endswith("per-connector packs (see roster)")
    assert _policy_posture(None, None) == "unknown"


def test_decode_sandbox_packs_rejects_a_payload_without_packs() -> None:
    try:
        decode_sandbox_packs("{}")
    except ValueError:
        pass
    else:  # pragma: no cover - the assertion documents the contract
        raise AssertionError("expected ValueError")
    model = PoliciesPanelModel()
    model.apply_sandbox_json("[]")
    assert model.sandbox_error
