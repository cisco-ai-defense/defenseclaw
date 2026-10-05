# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A DataTable that repaints its cells once it has measured its columns.

Textual's DataTable sizes auto-width columns when it next goes idle, after
``add_row`` or ``update_cell``, but caches each rendered cell without the
width it was drawn at. A paint that lands before that idle (a screen refresh
racing a table rebuild, which Windows hit on the Setup config editor) cached
header-wide cells, and the table kept showing "Confi" and "(unse" until the
next row change.
"""

from __future__ import annotations

from collections.abc import Iterable

from textual import events
from textual.widgets import DataTable
from textual.widgets.data_table import RowKey


class MeasuredDataTable(DataTable):
    """DataTable whose cells follow the column widths measured on idle."""

    def _update_dimensions(self, new_rows: Iterable[RowKey]) -> None:
        super()._update_dimensions(new_rows)
        # Every render cache is keyed on the update count, so this drops the
        # cells an earlier paint drew at the widths from before the measure.
        self._update_count += 1
        self.refresh()

    def _on_resize(self, event: events.Resize) -> None:
        super()._on_resize(event)
        # A shorter table kept its scroll offset, so the selected row (the one
        # Enter acts on) could sit below the bottom edge (GAP-2535).
        if self.row_count and self.show_cursor and self.cursor_type != "none":
            self.call_after_refresh(self._scroll_cursor_into_view)


__all__ = ["MeasuredDataTable"]
