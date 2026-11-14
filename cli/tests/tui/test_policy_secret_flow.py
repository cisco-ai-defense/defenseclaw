# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel: Secret flow tracking, folded into the read-only Chains view."""

from __future__ import annotations

from defenseclaw.config import default_config
from defenseclaw.tui.services.policy_state import (
    POLICY_VIEWS,
    PoliciesPanelModel,
    secret_flow_effective_mode,
)


def _model_with_config(**overrides) -> PoliciesPanelModel:
    cfg = default_config()
    sf = cfg.guardrail.secret_flow
    for key, value in overrides.items():
        setattr(sf, key, value)
    model = PoliciesPanelModel(sandbox_supported=True)
    model.set_config(cfg)
    return model


def test_secret_flow_is_not_a_separate_view() -> None:
    # Folded into Chains to keep the one-line switcher within the 80-col budget.
    assert "secret_flow" not in POLICY_VIEWS


def test_secret_flow_rows_render_defaults() -> None:
    model = _model_with_config()
    rows = dict(model.secret_flow_rows())
    assert "shadow" in rows["mode"]
    assert "credentials" in rows["label sets"]
    assert "default alert" in rows["sink action"]
    assert rows["re-encodings"] == "on"
    assert "512 paths" in rows["memory"]


def test_chains_view_carries_secret_flow_rows() -> None:
    model = _model_with_config()
    model.set_view("chains")
    labels = [label for label, chain in model.chain_rows() if chain is None]
    assert "Secret flow tracking" in labels
    assert any(lbl.startswith("mode:") for lbl in labels)
    # headline names the effective mode
    assert "secret flow" in model.headline(80)


def test_secret_flow_hits_render_redacted() -> None:
    model = _model_with_config()
    model.apply_secret_flow(
        [{"time": "2026-11-13T04:05:06Z", "action": "alert", "kind": "labeled_file",
          "program": "curl", "host": "evil.example", "sets": ["credentials"], "source": "env"}],
        tracked=3,
    )
    text = " ".join(v for _k, v in model.secret_flow_rows())
    assert "curl->evil.example" in text
    assert "credentials" in text
    assert dict(model.secret_flow_rows())["tracked sessions"] == "3"


def test_chain_rows_stay_within_80_columns() -> None:
    model = _model_with_config()
    model.set_view("chains")
    columns, rows = model.table(80)
    for row in rows:
        assert len(" ".join(row)) <= 80


def test_effective_mode_folding() -> None:
    assert secret_flow_effective_mode("off", "on") == "off"
    assert secret_flow_effective_mode("shadow", "on") == "shadow"
    assert secret_flow_effective_mode("on", "on") == "on"
    assert secret_flow_effective_mode("shadow", "off") == "off"
    assert secret_flow_effective_mode("shadow", "") == "shadow"
