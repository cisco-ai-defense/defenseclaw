# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 11 (ux2): GAP-2347."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.panels.registries import RegistrySourceRow
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import screen_text, settle_panel, snapshot_app  # noqa: E402

ERROR = "error: unsupported schema_version None (expected 1) in manifest.yaml"


def test_sources_table_cuts_a_sync_error_and_points_to_the_detail(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    model = app.registries_model
    model.sources = [RegistrySourceRow(id="sf1-local", last_status=ERROR)]
    row = dict(zip(model.data_table_columns(), model.data_table_rows()[0], strict=True))
    assert row["Status"] == "error"
    assert model.status_note() == "Enter on a source shows its full error."
    assert ("Status", ERROR) in model.selected_detail_info().fields
    cache = RegistrySourceRow(id="x", index_error="unsafe registry source id")
    assert cache.table_status_label == "cache error"
    model.sources = [RegistrySourceRow(id="sf1-local", last_status="ok")]
    assert model.data_table_rows()[0][4] == "ok" and model.status_note() == ""


def _status_width(table: DataTable) -> int:
    return table.columns[table.coordinate_to_cell_key((0, 4)).column_key].get_render_width(table)


async def test_sources_columns_fit_80x24_and_shrink_after_an_ok_sync(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("registries")
        await settle_panel(app, pilot)
        table = app.query_one("#panel-table", DataTable)
        # The rows below are set by hand; a periodic or config-poll refresh
        # on a slow runner reloaded the real (empty) sources between steps.
        app.registries_model.refresh = lambda *_args, **_kwargs: None

        async def show(status: str) -> int:
            app.registries_model.sources = [RegistrySourceRow(id="sf1-local", last_status=status)]
            app._render_chrome()  # noqa: SLF001
            await pilot.pause()
            return _status_width(table)

        await show(ERROR)
        assert "Last Sync" in screen_text(app) and "full error" in screen_text(app)
        ok_width = await show("ok")
        # A long status with no "error:" prefix still widens the column; the
        # next ok row must shrink it back instead of keeping the old width.
        assert await show("x" * 30) > ok_width
        assert await show("ok") == ok_width
        assert "Last Sync" in screen_text(app)
