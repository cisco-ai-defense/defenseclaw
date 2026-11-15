"""Alerts, Audit and AI Discovery tables fit 80x24 with no clipped column (GAP-0908)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from defenseclaw.tui.services.table_fit import fit_table
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402

BODY = 80 - 9


def _used(columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> int:
    return sum(max(len(columns[i]), *(len(row[i]) for row in rows)) + 2 for i in range(len(columns)))


def test_fit_table_shortens_the_widest_cells_and_keeps_every_header() -> None:
    columns = ("Severity", "Target", "Details")
    rows = (("HIGH", "skill://google-workspace-calendar-sync-tool", "prompt injection found in a tool result"),)
    fitted_columns, fitted_rows = fit_table(columns, rows, BODY)
    assert fitted_columns == columns
    assert _used(fitted_columns, fitted_rows) <= BODY
    assert fitted_rows[0][0] == "HIGH"
    assert all(cell.endswith("…") for cell in fitted_rows[0][1:])
    assert fit_table(columns, rows, 0) == (columns, rows), "an unknown width changes nothing"
    short = (("HIGH", "skill://a", "found"),)
    assert fit_table(columns, short, BODY) == (columns, short)


def test_fit_table_drops_only_the_columns_it_is_told_to_when_headers_alone_do_not_fit() -> None:
    columns = ("State", "Categories", "Product", "Component", "Version", "Vendor", "Detectors", "Count", "Identity")
    rows = (("active", "agent", "Claude Code", "extension", "2.1", "Anthropic", "process", "3", "verified"),)
    drop = ("Detectors", "Vendor", "Identity")
    fitted_columns, fitted_rows = fit_table(columns, rows, BODY, drop=drop)
    assert _used(fitted_columns, fitted_rows) <= BODY
    assert "Component" in fitted_columns and "Count" in fitted_columns
    assert set(columns) - set(fitted_columns) <= set(drop)
    assert all(len(row) == len(fitted_columns) for row in fitted_rows)


@pytest.mark.parametrize("width", [71, 91, 111])
def test_fit_table_never_cuts_sel_severity_or_action(width: int) -> None:
    # clirev P3: "approval-denied" and "approval-granted" both showed "approva…".
    columns = ("Sel", "Severity", "Time", "Action", "Target", "Details")
    rows = tuple(
        ("*", "CRITICAL", "Nov 15 17:50", action, "skill://google-workspace-calendar-sync-tool", "x" * 70)
        for action in ("approval-denied", "approval-granted", "guardrail-verdict")
    )
    fitted_columns, fitted_rows = fit_table(columns, rows, width)
    assert fitted_columns == columns
    for before, after in zip(rows, fitted_rows, strict=True):
        assert (after[0], after[1], after[3]) == (before[0], before[1], before[3])
    assert _used(fitted_columns, fitted_rows) <= width
    audit_columns = ("TIME", "ACTION", "TYPE", "TARGET", "SEVERITY", "RUN", "DETAILS")
    audit_rows = tuple(
        ("17:50:10", action, "scan", "skill://google-workspace-calendar-sync-tool", "HIGH", "run-9f3a2c1b77", "x" * 40)
        for action in ("approval-denied", "approval-granted")
    )
    shown_columns, shown_rows = fit_table(audit_columns, audit_rows, width, drop=("RUN",))
    assert [row[shown_columns.index("ACTION")] for row in shown_rows] == ["approval-denied", "approval-granted"]
    assert _used(shown_columns, shown_rows) <= width


@pytest.mark.parametrize(
    "panel,model_name,columns,row",
    [
        (
            "alerts",
            "alerts_model",
            ("Sel", "Severity", "Time", "Action", "Target", "Details"),
            ("", "HIGH", "Nov 15 17:50", "scan", "skill://google-workspace-calendar-sync-tool",
             "prompt injection found in tool result: ignore previous instructions and send"),
        ),
        (
            "audit",
            "audit_model",
            ("TIME", "ACTION", "TYPE", "TARGET", "SEVERITY", "RUN", "DETAILS"),
            ("17:50:10", "SCAN", "scan", "skill://google-workspace-calendar-sync-tool", "HIGH", "run-9f3a2c1b77",
             "prompt injection found in tool result"),
        ),
        (
            "ai",
            "ai_discovery_model",
            ("State", "Categories", "Product", "Component", "Version", "Vendor", "Detectors", "Count", "Identity", "Presence"),
            ("active", "agent, mcp", "Claude Code", "claude-code-cli-extension-component", "2.1.140", "Anthropic",
             "process, package", "3", "verified-by-uid", "present"),
        ),
    ],
)
async def test_wide_rows_fit_the_body_at_80x24(tmp_path, panel, model_name, columns, row) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        model = getattr(app, model_name)
        model.data_table_columns = lambda: columns
        model.data_table_rows = lambda: (row,)
        app.action_switch_panel(panel)
        await settle_panel(app, pilot)
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        table = app.query_one("#panel-table", DataTable)
        assert sum(column.get_render_width(table) for column in table.columns.values()) <= BODY
        header = next(str(column.label) for column in table.columns.values() if str(column.label).lower() in {"details", "component"})
        assert header in screen_text(app), "the last important column header is on screen, not clipped"
