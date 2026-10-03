# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fix-only batch 16: the Overview SERVICES column layout."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest
from defenseclaw.tui.app import DefenseClawTUI
from rich.console import Console
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402


def _service_rows(app: DefenseClawTUI, width: int) -> dict[str, str]:
    console = Console(width=width, record=True, color_system=None, file=io.StringIO())
    console.print(app._overview_renderable())  # noqa: SLF001
    rows = {}
    for line in console.export_text().splitlines():
        if line.startswith(("│ ●", "│ ○")):
            cell = line[1:].split("│")[0]
            rows[cell[1:].lstrip("●○ ").split("  ")[0].strip()] = cell
    return rows


@pytest.mark.parametrize("width", [160, 80])
def test_services_columns_stay_put_when_the_gateway_stops(tmp_path, width) -> None:
    # GAP-2391: with the gateway stopped the label column grew from 12 to 25
    # and the state moved right; "AI Discovery" touched its state.
    app = snapshot_app(tmp_path)
    with patch.object(DefenseClawTUI, "size", new_callable=PropertyMock, return_value=Size(width, 45)):
        app.overview_model.set_gateway_probe("running")
        running = _service_rows(app, width)
        app.overview_model.set_gateway_probe("stopped")
        stopped = _service_rows(app, width)
    for rows in (running, stopped):
        assert rows["Gateway"].index("Gateway") == 4, rows["Gateway"]
        state_col = rows["Gateway"].index("Gateway") + 14
        assert rows["AI Discovery"][state_col - 2 : state_col] == "  ", rows["AI Discovery"]
        assert rows["AI Discovery"][state_col] != " ", rows["AI Discovery"]
        assert rows["Gateway"][state_col] != " ", rows["Gateway"]
