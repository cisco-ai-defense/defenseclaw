# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tool-call levels: ``guardrail.block_at`` / ``alert_at`` in the policy catalog.

The cases mirror the gateway's ``guardrailLevelThresholds`` (decision.go):
connector value > global value > the rule pack's profile level, each level on
its own, then the alert rank is clamped to the block rank.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from defenseclaw import policy_catalog as pc
from defenseclaw.config import PerConnectorGuardrailConfig, default_config

DEFAULT, STRICT, PERMISSIVE = "/p/guardrail/default", "/p/guardrail/strict", "/p/guardrail/permissive"


@pytest.mark.parametrize(
    ("pack", "global_levels", "connector_levels", "want"),
    [
        # Empty everywhere: the profile's own levels.
        (DEFAULT, ("", ""), None, (4, 2, "pack", "pack")),
        (STRICT, ("", ""), ("", ""), (2, 1, "pack", "pack")),
        (PERMISSIVE, ("", ""), None, (4, 3, "pack", "pack")),
        ("/p/guardrail/protected-codex/strict", ("", ""), None, (2, 1, "pack", "pack")),
        # Default pack + global block_at HIGH: block 3, alert stays at the pack's 2.
        (DEFAULT, ("HIGH", ""), None, (3, 2, "global", "pack")),
        # Strict pack + connector block_at CRITICAL: block 4, alert keeps strict's 1.
        (STRICT, ("", ""), ("CRITICAL", ""), (4, 1, "override", "pack")),
        # The connector's own value beats the global one; any case is read.
        (DEFAULT, ("high", "low"), ("medium", ""), (2, 1, "override", "global")),
        # Clamp: an alert level above the block level alerts from the block level.
        (STRICT, ("", "CRITICAL"), None, (2, 2, "pack", "global")),
        (DEFAULT, ("MEDIUM", "HIGH"), ("", ""), (2, 2, "global", "global")),
        # A value the gateway ignores counts as unset.
        (PERMISSIVE, ("SEVERE", ""), ("", "3"), (4, 3, "pack", "pack")),
    ],
)
def test_resolve_levels_matches_the_gateway(pack, global_levels, connector_levels, want) -> None:
    levels = pc.resolve_levels(pack, global_levels, connector_levels)
    assert (levels.block_rank, levels.alert_rank, levels.block_source, levels.alert_source) == want
    assert levels.alert_rank <= levels.block_rank


def test_levels_labels_sources_and_clamp_flag() -> None:
    clamped = pc.resolve_levels(STRICT, ("", "CRITICAL"))
    assert (clamped.block_at, clamped.alert_at, clamped.alert_clamped) == ("MEDIUM+", "MEDIUM+", True)
    assert pc.level_label(clamped.wanted_alert_rank) == "CRITICAL"
    assert not pc.resolve_levels(DEFAULT).alert_clamped
    assert pc.resolve_levels(DEFAULT).source == "pack"
    assert pc.resolve_levels(DEFAULT, ("", "LOW")).source == "global"
    assert pc.resolve_levels(DEFAULT, ("HIGH", ""), ("", "LOW")).source == "override"
    assert [pc.level_name(rank) for rank in (4, 3, 2, 1, 0)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", ""]
    assert pc.level_value(" high ") == "HIGH" and pc.level_value("HIGH+") == "" and pc.level_value(None) == ""


def _cfg(tmp_path: Path):
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.policy_dir = str(tmp_path / "dc" / "policies")
    cfg.guardrail.rule_pack_dir = DEFAULT
    return cfg


def test_scope_postures_carry_the_resolved_levels_and_where_they_come_from(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.guardrail.block_at = "HIGH"
    cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(rule_pack_dir=STRICT, alert_at="CRITICAL"),
        "claudecode": PerConnectorGuardrailConfig(block_at="MEDIUM"),
        "hermes": PerConnectorGuardrailConfig(rule_pack_dir=STRICT),
    }
    rows = {row.scope: row for row in pc.scope_postures(cfg)}
    got = {
        scope: (row.block_at, row.alert_at, row.levels_source, row.own_block_at, row.own_alert_at)
        for scope, row in rows.items()
    }
    assert got == {
        "global": ("HIGH+", "MEDIUM+", "global", "HIGH", ""),
        # alert CRITICAL is clamped to the global block level HIGH.
        "codex": ("HIGH+", "HIGH+", "override", "", "CRITICAL"),
        "claudecode": ("MEDIUM+", "MEDIUM+", "override", "MEDIUM", ""),
        # A global value replaces the strict pack's MEDIUM+.
        "hermes": ("HIGH+", "LOW+", "global", "", ""),
    }
    assert rows["codex"].to_json()["own_alert_at"] == "CRITICAL"
    assert pc.scope_levels(cfg, "hermes") == pc.resolve_levels(STRICT, ("HIGH", ""), ("", ""))


def test_scope_postures_without_levels_keep_the_pack_levels(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig(rule_pack_dir=STRICT)}
    rows = {row.scope: row for row in pc.scope_postures(cfg)}
    assert (rows["global"].block_at, rows["global"].alert_at, rows["global"].levels_source) == (
        "CRITICAL",
        "MEDIUM+",
        "pack",
    )
    assert (rows["codex"].block_at, rows["codex"].alert_at) == ("MEDIUM+", "LOW+")
