# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Gateway stop confirm focus and the status bar after a panel switch (final-cert fix-only batch 3)."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.screens.command_preview import build_command_preview
from textual.geometry import Region

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402


def _gateway_preview(*args: str):
    command = ParsedCommand(binary="defenseclaw-gateway", args=args, display_name=" ".join(args), category="daemon")
    return build_command_preview(dataclasses.replace(command, risk="mutation"))


def test_gateway_stop_confirm_focuses_cancel() -> None:
    # GAP-2611: one Enter on the ": stop" confirm stopped the gateway.
    assert _gateway_preview("stop").cancel_by_default
    assert not _gateway_preview("start").cancel_by_default
    assert not _gateway_preview("status").cancel_by_default


def _row_text(widget) -> str:
    strip = widget.render_lines(Region(0, 0, widget.size.width, 1))[0]
    return "".join(segment.text for segment in strip).strip()


async def test_status_bar_keeps_health_segments_across_panel_switch(tmp_path) -> None:
    # GAP-2612: after 2 then 1 the bar read only "Ready." until a segment changed.
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        app._set_status(app._status_text())
        await pilot.pause()
        assert "Gateway" in _row_text(app.query_one("#status"))
        for panel in ("alerts", "overview"):
            app.action_switch_panel(panel)
            await pilot.pause()
            row = _row_text(app.query_one("#status"))
            assert row.startswith("Ready.") and "Gateway" in row, (panel, row)
            app._set_status(app._status_text())
            await pilot.pause()
            assert "Gateway" in _row_text(app.query_one("#status")), panel
