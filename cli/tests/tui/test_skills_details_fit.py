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
