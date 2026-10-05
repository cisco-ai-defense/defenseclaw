# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI Setup UX batch 14: status line, connector default, readiness, card fit."""

from __future__ import annotations

import sys
from pathlib import Path

from textual.geometry import Region

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402
from defenseclaw.config import default_config  # noqa: E402
from defenseclaw.tui.panels.setup import SetupWizard, connector_setup_wizard_fields  # noqa: E402
from defenseclaw.tui.panels.setup_catalog import setup_detail_pairs  # noqa: E402

_RESULT = "Codex connector setup complete (mode observe) · next: press i for readiness"


def _row_text(widget) -> str:
    strip = widget.render_lines(Region(0, 0, widget.size.width, 1))[0]
    return "".join(segment.text for segment in strip).rstrip()


async def test_status_line_keeps_the_whole_next_step_80x24(tmp_path) -> None:
    # GAP-2133: the cut-off health strip's "…" took the last cell of the step.
    app = fixtures.snapshot_app(tmp_path, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        token = object()
        app._strip_state, app._strip_label, app._strip_summary = "success", "setup codex", _RESULT
        app._strip_auto_hide_token = token
        app._auto_hide_success_strip(token)
        await pilot.pause()
        assert _row_text(app.query_one("#status")).endswith("· next: press i for readiness")


async def test_setup_card_layout_survives_help_80x24(tmp_path) -> None:
    # GAP-2167: after ? and Esc the blank row above the card went and the card grew a row.
    app = fixtures.snapshot_app(tmp_path, setup_config=default_config())
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("0")
        await pilot.pause()
        await pilot.pause()

        def layout() -> tuple[object, ...]:
            body = app.query_one("#detail-panel-body").render()
            return app.query_one("#detail-panel").region, getattr(body, "plain", str(body))

        before = layout()
        for key in ("question_mark", "escape"):
            await pilot.press(key)
            await pilot.pause()
            await pilot.pause()
        assert layout() == before
        assert app.query_one("#detail-panel").region.y == app.query_one("#panel-table").region.bottom + 1


def test_connector_form_starts_on_codex_when_none_is_configured(monkeypatch) -> None:
    # GAP-2159: an install with no connector offered (and Ctrl+R ran) setup openclaw.
    # Pin Linux: Windows has no openclaw, so a stored openclaw falls back to codex.
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    for cfg in ({}, {"claw": {"mode": ""}, "guardrail": {"connector": ""}}):
        fields = connector_setup_wizard_fields(cfg)
        assert next(f.value for f in fields if f.label == "Connector") == "codex"
    fields = connector_setup_wizard_fields({"guardrail": {"connector": "openclaw"}})
    assert next(f.value for f in fields if f.label == "Connector") == "openclaw"


def test_protect_an_agent_details_name_the_command_it_runs() -> None:
    # GAP-2160: the details said "defenseclaw setup" for "setup <connector> --yes".
    from defenseclaw.tui.panels.setup import SetupPanelModel

    model = SetupPanelModel({})
    model.active_wizard = SetupWizard.CONNECTOR_SETUP
    assert dict(setup_detail_pairs(model))["Command"] == "defenseclaw setup <connector> --yes"
