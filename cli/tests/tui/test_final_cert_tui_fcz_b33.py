# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registries sync copy, tab badge form and MCP "not loaded" colour (final-cert fix batch 33)."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.app import PANELS, _styled_cell  # noqa: E402
from defenseclaw.tui.command_line import ParsedCommand  # noqa: E402
from defenseclaw.tui.panels.registries import sync_all_intent, sync_source_intent  # noqa: E402
from defenseclaw.tui.screens.command_preview import build_command_preview  # noqa: E402
from defenseclaw.tui.theme import DEFAULT_TOKENS, state_color  # noqa: E402
from defenseclaw.tui.widgets import tab_fit  # noqa: E402
from fixtures import snapshot_app  # noqa: E402


def _preview(args: tuple[str, ...]):
    command = ParsedCommand(binary="defenseclaw", args=args, display_name=" ".join(args), category="registries")
    return build_command_preview(dataclasses.replace(command, risk="mutation"))


def test_registry_sync_confirms_name_every_source_and_a_conditional_restart() -> None:
    # GAP-2542: "sync --all" said "Fetches the source"; both syncs said the
    # command "then restarts a running gateway" though a no-op sync does not.
    assert "every enabled source" in sync_all_intent().consequence
    assert "per remote MCP entry" in sync_all_intent().consequence
    assert sync_source_intent("corp").consequence.startswith("Fetches the source,")
    for args in (sync_all_intent().args, sync_source_intent("corp").args):
        preview = _preview(args)
        assert preview.restart == "possible"
        assert "restarts a running gateway only if it changes policy" in preview.summary
        assert "and then restarts" not in preview.summary
    approve = _preview(("registry", "approve", "corp", "wiki", "--type", "mcp", "--json"))
    assert "restarts a running gateway so agent hooks" in approve.summary


def test_tab_badges_keep_the_bracket_form_once_shown_as_the_terminal_widens(tmp_path, monkeypatch) -> None:
    # GAP-2543: "Alerts (1)" at 207-214, "Alerts¹" at 215 when the brand
    # appeared, "(1)" at 219 and superscript again at 221 with the version.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 1, "logs": 376, "audit": 304}
    app = snapshot_app(tmp_path)
    app._panel_unread_count = lambda name: unread.get(name, 0)  # type: ignore[method-assign]
    bracketed = False
    titles = []
    for width in range(180, 261):
        monkeypatch.setattr(type(app), "size", property(lambda _self, width=width: Size(width, 45)))
        labels = tab_fit.fit_tab_labels(PANELS, "overview", unread, app._tab_strip_width())  # noqa: SLF001
        now = all(labels[name].endswith(f"({count})") for name, count in unread.items())
        assert now or not bracketed, (width, labels)
        bracketed = now
        titles.append(app._header_title())  # noqa: SLF001
    assert bracketed and titles[-1].startswith("DefenseClaw ")
    # The title never goes away again once shown, and the version never
    # gives way to the bare brand.
    shown = [bool(title) for title in titles]
    assert shown == sorted(shown)
    versioned = [" " in title for title in titles]
    assert versioned == sorted(versioned)


def test_mcps_list_colours_not_loaded_amber_like_the_detail_pane() -> None:
    # GAP-2544: the Status cell fell back to muted grey (disabled/offline).
    assert state_color("not loaded") == DEFAULT_TOKENS.accent_amber
    assert str(_styled_cell("Status", "not loaded").spans[0].style) == DEFAULT_TOKENS.accent_amber
