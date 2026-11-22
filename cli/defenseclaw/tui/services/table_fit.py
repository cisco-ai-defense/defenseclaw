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
# Columns whose words decide what the row means ("approval-denied" against
# "approval-granted") are never cut, and never dropped.
_PROTECTED = frozenset({"sel", "severity", "sev", "action", "time"})
# The narrowest a shortened cell gets when nothing else makes the table fit
# (GAP-1028): every column stays on screen, and the detail view has the value.
_TIGHT_CELLS = 4
# Severity words (and two headers) shortened one-for-one when the table is too wide (GAP-1028).
_SHORT_HEADERS = {"severity": "Sev", "connector": "Conn"}
_SEVERITY_SHORT = {"CRITICAL": "CRIT", "MEDIUM": "MED", "INFORMATIONAL": "INFO"}


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
    cells would not fit. Only the cells are cut, never a header, and the Sel,
    Severity, Action and Time columns are never cut (or dropped) at all.
    Without a ``drop`` list every column stays: the Severity words and
    the Connector header shorten (CRITICAL to CRIT, Conn) and the other cells shrink to a few cells each, so a
    table never scrolls sideways (GAP-1028).
    """

    columns = tuple(columns)
    rows = tuple(tuple(row) for row in rows)
    if width <= 0 or not columns:
        return columns, rows
    if not drop:
        short_columns, short_rows = _abbreviate(columns, rows)
        for stage_columns, stage_rows, min_cells in (
            (columns, rows, _MIN_CELLS),
            (short_columns, short_rows, _MIN_CELLS),
        ):
            if _floors_total(stage_columns, stage_rows, min_cells) <= width:
                return _fit(stage_columns, stage_rows, width, min_cells, ())
        return _fit(short_columns, short_rows, width, _TIGHT_CELLS, ())
    return _fit(columns, rows, width, _MIN_CELLS, tuple(drop))


def _abbreviate(
    columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...]
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    """Shorten the Severity words and the Severity and Connector headers (GAP-1028)."""

    def short(name: str) -> str:
        replacement = _SHORT_HEADERS.get(name.strip().lower())
        if replacement is None:
            return name
        return replacement.upper() if name.isupper() else replacement

    severity_at = next((i for i, name in enumerate(columns) if name.strip().lower() == "severity"), -1)
    new_columns = tuple(short(name) for name in columns)
    new_rows = tuple(
        tuple(_SEVERITY_SHORT.get(cell.upper(), cell) if i == severity_at else cell for i, cell in enumerate(row))
        for row in rows
    )
    return new_columns, new_rows


def _natural_widths(columns: Sequence[str], rows: Sequence[Sequence[str]], cols: Sequence[int]) -> list[int]:
    return [max([cell_len(columns[i]), *(cell_len(row[i]) for row in rows)]) for i in cols]


def _floors_total(columns: Sequence[str], rows: Sequence[Sequence[str]], min_cells: int) -> int:
    cols = range(len(columns))
    natural = _natural_widths(columns, rows, cols)
    total = 0
    for i in cols:
        floor = 10**6 if columns[i].strip().lower() in _PROTECTED else max(cell_len(columns[i]), min_cells)
        total += min(natural[i], floor) + _PAD
    return total


def _fit(
    columns: tuple[str, ...],
    rows: tuple[tuple[str, ...], ...],
    width: int,
    min_cells: int,
    drop: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:

    def widths(cols: Sequence[int]) -> list[int]:
        return _natural_widths(columns, rows, cols)

    keep = list(range(len(columns)))

    def floor(i: int) -> int:
        if columns[i].strip().lower() in _PROTECTED:
            return 10**6  # the natural width: it never shrinks
        return max(cell_len(columns[i]), min_cells)

    def floors_total(cols: Sequence[int]) -> int:
        natural = dict(zip(cols, widths(cols), strict=True))
        return sum(min(natural[i], floor(i)) + _PAD for i in cols)

    for name in drop:
        if floors_total(keep) <= width:
            break
        if name.lower() not in _PROTECTED and name in columns and columns.index(name) in keep:
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
