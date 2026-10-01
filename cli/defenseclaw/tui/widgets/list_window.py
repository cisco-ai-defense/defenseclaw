# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Keep the selected row of a picker list on screen.

The pickers draw their rows into one ``Static`` with a ``max-height``, so a
long list was simply cropped: moving past the last visible row left the
``>`` marker off-screen. ``window_lines`` returns the slice of rows to draw,
centred on the selection, with "N more" markers where rows are hidden.
"""

from __future__ import annotations

from collections.abc import Sequence

_MORE_OPEN = "[#94A3B8]"


def window_lines(lines: Sequence[str], selected: int, size: int) -> list[str]:
    """Return at most ``size`` lines of ``lines`` that include ``selected``.

    Hidden rows above/below are summarised in the first/last line of the
    window ("↑ 3 more" / "↓ 5 more"), so the result is never taller than
    ``size``. ``size`` below 3 is treated as 3 (room for both markers and
    the selection).
    """

    rows = list(lines)
    size = max(3, size)
    if len(rows) <= size:
        return rows
    selected = max(0, min(selected, len(rows) - 1))
    start = max(0, min(selected - size // 2, len(rows) - size))
    end = start + size
    window = rows[start:end]
    if start > 0:
        window[0] = f"{_MORE_OPEN}  ↑ {start + 1} more[/]"
    if end < len(rows):
        window[-1] = f"{_MORE_OPEN}  ↓ {len(rows) - end + 1} more[/]"
    return window


def rows_that_fit(screen_height: int, chrome_rows: int, *, cap: int) -> int:
    """How many list rows fit in a modal whose other parts take ``chrome_rows``."""

    if screen_height <= 0:
        return cap
    return max(3, min(cap, screen_height - chrome_rows))


__all__ = ["rows_that_fit", "window_lines"]
