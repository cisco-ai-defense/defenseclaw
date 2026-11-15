"""The Skills table fits 80x24 and never cuts the Actions words (GAP-2642, GAP-0908)."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.services.catalog_state import SkillRow, SkillsPanelModel
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402


def _used(columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> int:
    return sum(max(len(columns[i]), *(len(row[i]) for row in rows)) + 2 for i in range(len(columns)))


def test_skills_table_fits_inside_80_columns_and_never_cuts_actions(monkeypatch) -> None:
    # GAP-0908: at 80x24 the Actions, Details and Source cells ended in an
    # ellipsis ("blocked, qu…", "quaran…", "…ude/skills"). The Actions words
    # now stay whole and the Details column goes before they are cut.
    monkeypatch.setenv("HOME", "/home/fcd-u3")
    monkeypatch.setenv("USERPROFILE", "/home/fcd-u3")
    body = 80 - 9  # app.py: the body less borders, padding and the scrollbar
    for with_connector in (False, True):
        panel = SkillsPanelModel()
        panel.apply_loaded(
            [
                SkillRow(
                    name="google-workspace-calendar-sync",
                    status="quarantined",
                    source="/home/fcd-u3/.claude/skills",
                    actions="blocked, quarantined, disabled",
                    connector="claudecode",
                    reason="quarantined by the watcher",
                ),
                SkillRow(name="imagegen", status="active", source="/home/fcd-u3/.codex/skills/.system", connector="codex"),
            ]
        )
        panel.show_connector_column = with_connector
        panel.refresh()

        columns = panel.data_table_columns(body)
        rows = panel.data_table_rows(body)
        assert len(columns) == len(rows[0])
        assert _used(columns, rows) <= body, "every column fits the 80-column body"
        actions = columns.index("Actions")
        assert rows[0][actions] == "blocked, quarantined, disabled", "Actions is never cut"
        assert "Details" not in columns, "Details goes before Actions is cut"
        # The full text stays in the detail pane's data.
        assert panel.selected().reason == "quarantined by the watcher"


def test_skills_table_keeps_a_readable_details_column_when_there_is_room(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/fcd-u3")
    monkeypatch.setenv("USERPROFILE", "/home/fcd-u3")
    panel = SkillsPanelModel()
    panel.apply_loaded(
        [
            SkillRow(
                name=name,
                status="quarantined",
                source="/home/fcd-u3/.codex/skills/.system",
                connector="claudecode",
                description="Generate or edit images for the current project",
            )
            for name in ("imagegen", "openai-docs", "skill-installer")
        ]
    )
    panel.show_connector_column = True
    panel.refresh()

    for body in (120 - 9, 80 - 9):
        columns = panel.data_table_columns(body)
        rows = panel.data_table_rows(body)
        assert _used(columns, rows) <= body
        if "Details" in columns:
            details = columns.index("Details")
            assert all(len(row[details]) >= 14 or not row[details].endswith("…") for row in rows)
    assert "Details" in panel.data_table_columns(120 - 9)
    assert panel.selected().description.startswith("Generate or edit images")


def test_plugins_table_keeps_verdict_before_source_when_columns_are_dropped(monkeypatch) -> None:
    from defenseclaw.tui.services.catalog_state import PluginRow, PluginsPanelModel

    monkeypatch.setenv("HOME", "/home/fcd-u3")
    monkeypatch.setenv("USERPROFILE", "/home/fcd-u3")
    panel = PluginsPanelModel()
    panel.apply_loaded(
        [
            PluginRow(
                id="p1",
                name="a-very-long-plugin-name-for-the-table",
                verdict="clean",
                origin="/home/fcd-u3/.claude/plugins/cache/some-marketplace/some-plugin",
                description="A plugin with a rather long description that the table cuts",
            )
        ]
    )
    for body in (80 - 9, 200):
        columns = panel.data_table_columns(body)
        rows = panel.data_table_rows(body)
        assert len(columns) == len(rows[0])
        if "Source" in columns:
            assert columns.index("Verdict") < columns.index("Source")
        assert rows[0][columns.index("Verdict")] == "clean"


async def test_refresh_after_the_rows_change_fits_the_columns_again(tmp_path, monkeypatch) -> None:
    # A refresh patched the new rows into the old table, and Textual's
    # auto-width columns never shrink: after a held copy was deleted and the
    # skill quarantined again, the Skills table was 4 cells wider than the
    # body and cut the Details header ("Detai"); reopening fitted (GAP-2642).
    monkeypatch.setenv("HOME", "/home/fcd-u3")
    monkeypatch.setenv("USERPROFILE", "/home/fcd-u3")
    system = "/home/fcd-u3/.codex/skills/.system"
    codex = [
        SkillRow(name=name, status="active", source=system, connector="codex", description="Generate images")
        for name in ("imagegen", "review-agent", "skill-installer")
    ]
    blocked = SkillRow(name="dvq2606", status="blocked", source="scan-history", actions="blocked")
    quarantined = SkillRow(
        name="dvq2606", status="disabled", source="enforcement", actions="blocked, quarantined, disabled"
    )
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("skills")
        await settle_panel(app, pilot)
        table = app.query_one("#panel-table", DataTable)
        body = 80 - 9

        async def show(row: SkillRow) -> int:
            app.skills_model.apply_loaded([row, *codex])
            app._render_chrome()  # noqa: SLF001
            await pilot.pause()
            return sum(column.get_render_width(table) for column in table.columns.values())

        await show(blocked)
        assert await show(quarantined) <= body, "a refresh with a long Actions value fits the body"
        assert "blocked, quarantined, disabled" in screen_text(app)
        assert await show(blocked) <= body
        assert "Actions" in screen_text(app)


async def test_setup_goal_header_is_not_cut_mid_word_at_80x24(tmp_path) -> None:
    # GAP-0908: the Semantic routing form's header ended "Use the models in…".
    from defenseclaw.tui.panels.setup import SetupWizard, wizard_goals

    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("setup")
        await settle_panel(app, pilot)
        goal = wizard_goals(SetupWizard.SEMANTIC_ROUTING, {})[0]
        app.setup_model.open_wizard_form(SetupWizard.SEMANTIC_ROUTING, goal=goal)
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        header = next(line for line in screen_text(app).splitlines() if "Semantic routing" in line)
        assert "Route by task with built-in rules." in header and "…" not in header
