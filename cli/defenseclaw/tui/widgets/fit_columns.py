# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A Rich grid that drops its least useful columns when it does not fit.

Rich shrinks every ``no_wrap`` column of a grid that is too wide, so at
80 columns the Overview tables read "MO…", "C…" and "3…" (303 calls), or
lost their NAME column (GAP-2385). This grid measures its cells when it is
rendered, drops columns by priority until the rest fits, and lets one
``flex`` column take what is left (ending with "…").
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from rich.table import Table
from rich.text import Text


@dataclass(frozen=True)
class FitColumn:
    header: str
    # Lower numbers are dropped first; ``None`` keeps the column at any width.
    priority: int | None = None
    justify: Literal["left", "right"] = "left"
    # A flex column counts as ``flex_min`` cells while columns are dropped,
    # then takes the room that is left. 0 means "not flex".
    flex_min: int = 0


class FitColumnsTable:
    def __init__(
        self,
        columns: Sequence[FitColumn],
        rows: Iterable[Sequence[Text]],
        *,
        header_style: str = "",
        padding: int = 2,
    ) -> None:
        self.columns = tuple(columns)
        self.rows = tuple(tuple(row) for row in rows)
        self.header_style = header_style
        self.padding = padding

    def kept_columns(self, max_width: int) -> tuple[tuple[int, int | None], ...]:
        """``(column index, fixed width or None)`` for the columns that fit."""

        natural = [
            max([len(column.header), *(row[index].cell_len for row in self.rows)])
            for index, column in enumerate(self.columns)
        ]
        effective = [
            min(width, column.flex_min) if column.flex_min else width
            for width, column in zip(natural, self.columns, strict=True)
        ]

        def total(indexes: Sequence[int], widths: Sequence[int]) -> int:
            return sum(widths[index] for index in indexes) + self.padding * max(0, len(indexes) - 1)

        keep = list(range(len(self.columns)))
        droppable = sorted(
            (index for index, column in enumerate(self.columns) if column.priority is not None),
            key=lambda index: (self.columns[index].priority, -index),
        )
        for index in droppable:
            if total(keep, effective) <= max_width:
                break
            keep.remove(index)
        out: list[tuple[int, int | None]] = []
        for index in keep:
            width: int | None = None
            if self.columns[index].flex_min:
                others = total(keep, natural) - natural[index]
                room = max_width - others
                if room < natural[index]:
                    width = max(self.columns[index].flex_min, room)
            out.append((index, width))
        return tuple(out)

    def __rich_console__(self, console: Any, options: Any) -> Iterable[Table]:
        kept = self.kept_columns(options.max_width)
        table = Table.grid(padding=(0, self.padding), expand=True)
        for index, width in kept:
            column = self.columns[index]
            table.add_column(justify=column.justify, no_wrap=True, overflow="ellipsis", width=width)
        table.add_row(*(Text(self.columns[index].header, style=self.header_style) for index, _width in kept))
        for row in self.rows:
            table.add_row(*(row[index] for index, _width in kept))
        yield table
