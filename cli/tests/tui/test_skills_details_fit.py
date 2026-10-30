"""The Skills table keeps the Details column on screen at 80x24 (GAP-2642)."""

from __future__ import annotations

from defenseclaw.tui.services.catalog_state import SkillRow, SkillsPanelModel


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
