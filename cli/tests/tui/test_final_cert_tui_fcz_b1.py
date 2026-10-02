# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix batch fcz-b1: idle CPU, markup backslashes, alerts hint, skill unblock, stale status."""

from __future__ import annotations

import sys
from pathlib import Path
from time import monotonic

import pytest
from defenseclaw.tui.markup_safe import escape
from defenseclaw.tui.panels.alerts import AlertsPanelModel
from defenseclaw.tui.services.catalog_state import SkillsPanelModel, _format_skill_detail, skill_list_to_row
from rich.text import Text
from textual.markup import to_content

sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(Path(__file__).resolve().parents[3]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from fixtures import snapshot_app  # noqa: E402

_HOST_TEXT = (
    "C:\\work\\[/old] and C:\\dl\\[draft] notes",
    "a\\[/]b",
    "dir\\[/x]",
    "a\\[link=https://e.x]b",
    "a\\[@click=app.quit]b",
    "a\\\\[b]c",
    "C:\\tmp\\",
    "[90m a=b-c",
    "plain \\ back",
)


@pytest.mark.parametrize("wrap", ["{}", "[b]{}[/b]", "[#F87171]{}[/]", "x {} [dim]y[/dim]"])
def test_escape_keeps_backslashes_literal_in_textual_and_rich(wrap: str) -> None:
    # GAP-1675: a host backslash before "[" (or at the end, before our own
    # closing tag) made Rich raise MarkupError or open a link/click span, and
    # Textual eat the closing tag.
    for text in _HOST_TEXT:
        markup = wrap.replace("{}", escape(text))
        want = wrap.replace("{}", "\0")
        for parse in (lambda m: Text.from_markup(m, emoji=False).plain, lambda m: to_content(m).plain):
            assert parse(markup).replace("\u200b", "") == parse(want).replace("\0", text)
    assert not Text.from_markup(escape("a\\[link=https://e.x]b")).spans


def test_alerts_empty_state_names_the_l_key() -> None:
    # GAP-1815: since GAP-1708, 1 opens Overview and l steps the severity chips.
    assert AlertsPanelModel().empty_state() == "No actionable alerts. Press l to show all severities."


def test_watcher_blocked_skill_offers_unblock_not_block() -> None:
    # GAP-1820: the watcher block also disables the skill, so the row reads
    # "disabled"; u, the o menu and the detail must still offer Unblock.
    row = skill_list_to_row(
        {
            "name": "w3s1-review",
            "disabled": True,
            "actions": {"install": "block", "runtime": "disable"},
            "verdict": "blocked",
        }
    )
    assert row.status == "disabled"
    model = SkillsPanelModel()
    model.apply_loaded([row])
    keys = [action.key for action in model.menu_actions()]
    assert "u" in keys and "b" not in keys and "e" in keys
    action = model.direct_action("u", origin="key")
    assert action.intent is not None and action.intent.args[:3] == ("skill", "unblock", "w3s1-review")
    detail = Text.from_markup(_format_skill_detail(row)).plain
    assert "[u] Unblock" in detail and "[b] Block" not in detail


async def test_status_bar_drops_old_results_and_finished_ai_refresh(tmp_path) -> None:
    # GAP-1821: "Refreshing AI discovery snapshot..." stayed for minutes after
    # the snapshot was in, and "Done: ..." followed you to every panel.
    app = snapshot_app(tmp_path)

    async def polled(*, force_render: bool) -> bool:
        return True

    app._poll_ai_usage = polled  # type: ignore[method-assign]
    async with app.run_test(size=(80, 24)):
        await app._load_ai_discovery_model()  # noqa: SLF001
        assert app.status_text == "AI discovery refreshed."
        app._set_status("Done: defenseclaw agent discovery runtime scan.")  # noqa: SLF001
        await app._load_ai_discovery_model()  # noqa: SLF001
        assert app.status_text == "Done: defenseclaw agent discovery runtime scan."
        app.action_switch_panel("skills")
        assert app.status_text.startswith("Done:")
        app._status_set_at -= 60  # noqa: SLF001
        app.action_switch_panel("plugins")
        assert app.status_text == "Ready."


async def test_idle_refresh_does_not_rescan_the_audit_history(tmp_path) -> None:
    # GAP-1816: on a 1.29 GB audit.db the TUI kept two cores busy at idle. The
    # 15 s slow-component tick re-ran the full alert scan with no new rows, a
    # slow read was repeated back to back, and every health poll ran the same
    # scan again on a second thread.
    from defenseclaw.tui.services import read_repository
    from defenseclaw.tui.services.read_repository import TUIReadRepository

    from scripts.benchmark_tui_refresh import (
        SQLTrace,
        append_synthetic_v8_event,
        create_synthetic_v8_database,
        trace_repository_connections,
    )

    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 8)
    trace = SQLTrace()
    with trace_repository_connections(read_repository, trace):
        repository = TUIReadRepository(path)
        try:
            await repository.refresh()
            repository._slow_components_loaded_at -= 60  # noqa: SLF001
            before = len(trace.statements)
            await repository.refresh()
            slow_sql = trace.statements[before:]

            repository._next_history_at = monotonic() + 60  # noqa: SLF001 - the last read was slow
            append_synthetic_v8_event(path, 8)
            before = len(trace.statements)
            held = await repository.refresh()
            held_sql = trace.statements[before:]
            forced = await repository.refresh(force=True)
        finally:
            repository.close()

    assert any("FROM actions" in statement for statement in slow_sql)
    assert not any("FROM audit_events" in statement for statement in slow_sql)
    assert held.changed is False and not held_sql
    assert forced.changed is True

    (tmp_path / "app").mkdir()
    app = snapshot_app(tmp_path / "app")
    app._read_repository = object()  # noqa: SLF001

    def scanned() -> None:
        raise AssertionError("alerts re-read outside the repository")

    app._refresh_alerts = scanned  # type: ignore[method-assign]
    app._schedule_overview_disk_refresh()  # noqa: SLF001
