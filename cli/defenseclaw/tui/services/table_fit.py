# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fit a panel table inside the terminal width (GAP-0908).

Textual's DataTable sizes each column to its widest cell and scrolls sideways
when the sum is wider than the screen, so the last columns are clipped at the
window edge with no sign that anything is missing (Windows 80x24: the Alerts
Details, the Audit Details and the AI Discovery Component columns). This pure
helper shortens the widest cells with an ellipsis, and drops the columns the
caller lists as least important, until the table fits. The detail views keep
every value in full.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.cells import cell_len

ELLIPSIS = "\u2026"
# A shortened cell keeps at least this many cells, or its header when shorter.
_MIN_CELLS = 8
# Textual pads each column by one cell on each side.
_PAD = 2


def _cut(value: str, cells: int) -> str:
    if cell_len(value) <= cells:
        return value
    out = ""
    for char in value:
        if cell_len(out + char) > cells - 1:
            break
        out += char
    return out + ELLIPSIS


def fit_table(
    columns: Sequence[str],
    rows: Sequence[Sequence[str]],
    width: int,
    *,
    drop: Sequence[str] = (),
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    """Return columns and rows that fit ``width`` cells (0 = unknown: unchanged).

    ``drop`` lists column names in the order they go when even the shortest
    cells would not fit. Only the cells are cut, never a header.
    """

    columns = tuple(columns)
    rows = tuple(tuple(row) for row in rows)
    if width <= 0 or not columns:
        return columns, rows

    def widths(cols: Sequence[int]) -> list[int]:
        return [max([cell_len(columns[i]), *(cell_len(row[i]) for row in rows)]) for i in cols]

    keep = list(range(len(columns)))

    def floor(i: int) -> int:
        return max(cell_len(columns[i]), _MIN_CELLS)

    def floors_total(cols: Sequence[int]) -> int:
        natural = dict(zip(cols, widths(cols), strict=True))
        return sum(min(natural[i], floor(i)) + _PAD for i in cols)

    for name in drop:
        if floors_total(keep) <= width:
            break
        if name in columns and columns.index(name) in keep:
            keep.remove(columns.index(name))
    natural = dict(zip(keep, widths(keep), strict=True))
    caps = dict(natural)
    over = sum(caps.values()) + _PAD * len(keep) - width
    while over > 0:
        i = max((k for k in keep if caps[k] > min(natural[k], floor(k))), key=lambda k: caps[k], default=None)
        if i is None:
            break
        caps[i] -= 1
        over -= 1
    fitted_columns = tuple(columns[i] for i in keep)
    fitted_rows = tuple(tuple(_cut(row[i], caps[i]) for i in keep) for row in rows)
    return fitted_columns, fitted_rows
