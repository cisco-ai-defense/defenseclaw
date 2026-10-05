# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI batch 7: AI Discovery buttons have keys (GAP-2103)."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.models import HintState
from defenseclaw.tui.widgets.hint_bar import HintEngine

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


async def test_ai_discovery_export_and_on_off_have_keys(tmp_path) -> None:
    # GAP-2103: Export JSON and Disable AI Discovery were mouse-only.
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("ai")
        await pilot.pause()
        pressed: list[str] = []
        app._handle_ai_control = pressed.append  # type: ignore[method-assign]  # noqa: SLF001
        app.ai_discovery_model.snapshot = None
        await pilot.press("e")
        await pilot.press("d")
        assert pressed == ["ai-export", "ai-enable"]
        help_rows = [row for _, rows in app._help_sections() for row in rows]  # noqa: SLF001
        assert ("e", "Export the snapshot to JSON") in help_rows
        assert ("d", "Turn AI Discovery on / off") in help_rows
    hint = HintEngine().hint_for(HintState(active_panel="ai"))
    assert "e export" in hint and "d on/off" in hint
