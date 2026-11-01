"""The Skills table keeps the Details column on screen at 80x24 (GAP-2642)."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.services.catalog_state import SkillRow, SkillsPanelModel
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402


def test_skills_details_column_fits_inside_80_columns(monkeypatch) -> None:
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

    columns = panel.data_table_columns()
    body = 80 - 9  # app.py: the body less borders, padding and the scrollbar
    rows = panel.data_table_rows(body)
    used = sum(max(len(columns[i]), *(len(row[i]) for row in rows)) + 2 for i in range(len(columns)))
    assert used <= body, "every column, Details included, fits the 80-column body"
    details = columns.index("Details")
    # The header and the start of each value stay readable, and a cut value ends in an ellipsis.
    assert all(len(row[details]) >= len("Details") and row[details].endswith("…") for row in rows)
    # The full description stays in the detail pane's data.
    assert panel.selected().description.startswith("Generate or edit images")


def test_skills_details_header_fits_with_a_long_actions_value(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/fcd-u3")
    monkeypatch.setenv("USERPROFILE", "/home/fcd-u3")
    for with_connector in (False, True):
        panel = SkillsPanelModel()
        panel.apply_loaded(
            [
                SkillRow(
                    name="t106-risky-sample-skill",
                    status="disabled",
                    source="enforcement",
                    actions="blocked, quarantined, disabled",
                    connector="claudecode",
                    reason="quarantined by the watcher",
                ),
                SkillRow(name="clean-skill", status="removed", source="scan-history", connector="codex"),
            ]
        )
        panel.show_connector_column = with_connector
        panel.refresh()

        columns = panel.data_table_columns()
        body = 80 - 9
        rows = panel.data_table_rows(body)
        used = sum(max(len(columns[i]), *(len(row[i]) for row in rows)) + 2 for i in range(len(columns)))
        assert used <= body, "the Details header fits the body even when Actions is long"
        actions = columns.index("Actions")
        assert rows[0][actions].endswith("…")
        assert panel.selected().actions == "blocked, quarantined, disabled"


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
        assert "Details" in screen_text(app)
        assert await show(blocked) <= body
        assert "Details" in screen_text(app)
