"""Layout of the Blocked Events board's kernel denials table (#1246/GAP-0127)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-blocked-events.json"
TITLE = "Kernel denials by control, connector, user and process"


def _panels() -> list[dict]:
    board = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    out: list[dict] = []
    for panel in board["panels"]:
        out.append(panel)
        out.extend(panel.get("panels", []))
    return out


def _cells(grid: dict) -> set[tuple[int, int]]:
    return {(x, y) for x in range(grid["x"], grid["x"] + grid["w"]) for y in range(grid["y"], grid["y"] + grid["h"])}


def test_kernel_denials_table_spans_the_board_on_its_own_row() -> None:
    # At w=12 beside the two kernel stats the Control, Process and User
    # columns truncated long values such as kernel.ssh_private_key_read. The
    # table now has the full width, below the stats.
    panels = _panels()
    table = next(panel for panel in panels if panel.get("title") == TITLE)
    grid = table["gridPos"]
    assert table["type"] == "table"
    assert (grid["x"], grid["w"]) == (0, 24)
    stats = [p for p in panels if p.get("title") in ("Kernel denials", "Blocked by your Tetragon policies")]
    assert len(stats) == 2
    for stat in stats:
        assert grid["y"] >= stat["gridPos"]["y"] + stat["gridPos"]["h"], stat["title"]
    # The query and its columns are unchanged.
    assert [target["refId"] for target in table["targets"]] == ["DENIALS"]
    renames = next(t for t in table["transformations"] if t["id"] == "organize")["options"]["renameByName"]
    assert renames["control"] == "Control" and renames["process"] == "Process"


def test_blocked_events_panels_do_not_overlap() -> None:
    seen: dict[tuple[int, int], str] = {}
    for panel in _panels():
        grid = panel["gridPos"]
        assert 0 <= grid["x"] and grid["x"] + grid["w"] <= 24, panel.get("title")
        for cell in _cells(grid):
            assert cell not in seen, f"{panel.get('title')} overlaps {seen[cell]}"
            seen[cell] = panel.get("title", "")
