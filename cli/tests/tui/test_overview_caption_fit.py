"""Overview card captions at 80x24 keep whole items (GAP-0341)."""

from __future__ import annotations

from defenseclaw.tui.widgets.native_metrics import fit_metric_detail


def test_first_item_that_fits_is_kept_whole_without_a_marker() -> None:
    # "claudecode 59" is 13 cells; the " …" marker would not fit beside it.
    assert fit_metric_detail("claudecode 59 · codex 3", 13).plain == "claudecode 59"
    # With room for the marker the cut still falls between items.
    assert fit_metric_detail("claudecode 59 · codex 3", 16).plain == "claudecode 59 …"
