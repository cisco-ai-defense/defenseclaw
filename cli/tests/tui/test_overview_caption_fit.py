"""Overview card captions at 80x24 keep whole items (GAP-0341)."""

from __future__ import annotations

import pytest
from defenseclaw.tui.widgets.native_metrics import fit_metric_detail


def test_first_item_that_fits_is_kept_whole_without_a_marker() -> None:
    # "claudecode 59" is 13 cells; the " …" marker would not fit beside it.
    assert fit_metric_detail("claudecode 59 · codex 3", 13).plain == "claudecode 59"
    # With room for the marker the cut still falls between items.
    assert fit_metric_detail("claudecode 59 · codex 3", 16).plain == "claudecode 59 …"


@pytest.mark.parametrize("count", [7, 59, 160, 1234, 12345, 99999])
@pytest.mark.parametrize("width", [13, 14])
def test_the_first_label_stays_whole_for_counts_up_to_five_digits(count: int, width: int) -> None:
    # 13 and 14 cells are the Overview card captions at 80x24. With a 3-digit
    # count the label was cut ("claudeco… 160", DV18); the count gives way
    # instead, written short when that fits ("12k"), never cut.
    for detail in (f"claudecode {count} · codex 9", f"claudecode {count}", f"Critical {count} · High 3"):
        fitted = fit_metric_detail(detail, width).plain
        label = detail.split()[0]
        assert len(fitted) <= width
        assert fitted.split()[0] == label, (detail, width, fitted)
        rest = fitted[len(label) :].strip(" …")
        assert rest in ("", str(count)) or rest[-1] in "kM", (detail, width, fitted)


def test_a_leading_count_is_written_short_rather_than_cutting_its_label() -> None:
    assert fit_metric_detail("12345 inspected · 3 errors", 13).plain == "12k inspected"
    assert fit_metric_detail("1234 inspected", 13).plain == "1k inspected"
    assert fit_metric_detail("1234 inspected", 14).plain == "1234 inspected"


def test_a_phrase_keeps_whole_words() -> None:
    assert fit_metric_detail("skill+mcp scans · 3 plugins", 14).plain == "skill+mcp …"
    assert fit_metric_detail("ai discovery offline - run: defenseclaw agent discovery status", 14).plain == (
        "ai discovery …"
    )
    assert fit_metric_detail("most blocked: Bash x12", 14).plain == "most blocked:…"
