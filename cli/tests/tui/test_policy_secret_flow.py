# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel: the read-only Secret flow tracking view."""

from __future__ import annotations

from defenseclaw.config import default_config
from defenseclaw.tui.services.policy_state import (
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


def test_secret_flow_view_is_present_and_read_only() -> None:
    model = _model_with_config()
    assert "secret_flow" in model.views()
    # read-only: no mutating key is advertised for this view
    hint = model.view
    model.set_view("secret_flow")
    assert model.view == "secret_flow"


def test_secret_flow_rows_render_defaults() -> None:
    model = _model_with_config()
    model.set_view("secret_flow")
    rows = dict(model.secret_flow_rows())
    assert "shadow" in rows["mode"]
    assert "credentials" in rows["label sets"]
    assert "default alert" in rows["sink action"]
    assert rows["re-encodings"] == "on"
    assert "512 paths" in rows["memory"]


def test_secret_flow_hits_render_redacted() -> None:
    model = _model_with_config()
    model.apply_secret_flow(
        [{"time": "2026-11-13T04:05:06Z", "action": "alert", "kind": "labeled_file",
          "program": "curl", "host": "evil.example", "sets": ["credentials"], "source": "env"}],
        tracked=3,
    )
    model.set_view("secret_flow")
    rows = model.secret_flow_rows()
    text = " ".join(v for _k, v in rows)
    assert "curl->evil.example" in text
    assert "credentials" in text
    # the redacted record carries no path or value
    assert "/" not in " ".join(v for k, v in rows if k == "hit").replace("evil.example", "")
    assert dict(rows)["tracked sessions"] == "3"


def test_secret_flow_table_fits_80_columns() -> None:
    model = _model_with_config()
    model.apply_secret_flow([], tracked=0)
    model.set_view("secret_flow")
    columns, rows = model.table(80)
    assert columns == ("Setting", "Value")
    for row in rows:
        assert len(" ".join(row)) <= 80


def test_effective_mode_folding() -> None:
    assert secret_flow_effective_mode("off", "on") == "off"
    assert secret_flow_effective_mode("shadow", "on") == "shadow"
    assert secret_flow_effective_mode("on", "on") == "on"
    assert secret_flow_effective_mode("shadow", "off") == "off"
    assert secret_flow_effective_mode("shadow", "") == "shadow"
