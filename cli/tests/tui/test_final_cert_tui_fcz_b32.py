# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes, batch 32 (GAP-2533; GAP-2535 is in test_setup_layout)."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.runtime_state import RuntimePanelModel
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_EGRESS_LIMIT = (
    "egress attribution is limited to this process's own sockets; run the gateway elevated for machine-wide coverage"
)


def _standard_account_runtime() -> RuntimePanelModel:
    model = RuntimePanelModel()
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-10-03T12:00:00Z",
            "degraded": True,
            "degraded_reasons": [f"shadow egress partially covered: {_EGRESS_LIMIT}"],
            "processes_observed": 14,
            "connections_observed": 6,
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": True},
                {"plane": "b", "name": "shadow egress", "available": True, "running": True, "reason": _EGRESS_LIMIT},
            ],
            "findings": [],
        }
    )
    return model


def test_overview_runtime_notice_is_short_and_hangs_under_its_text(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-2533: a 2-3 line run-on sentence with "run the gateway elevated",
    # whose wrapped lines started under the icon.
    runtime = _standard_account_runtime()
    app = snapshot_app(tmp_path)
    app.overview_model.runtime = runtime.overview()
    notice = next(n.message for n in app.overview_model.build_notices() if n.message.startswith("Runtime is"))
    assert "(shadow egress partially covered)" in notice and "N for details" in notice
    assert "elevated" not in notice and len(notice) <= 110, notice
    assert "run the gateway elevated" in runtime.health_explanation()

    size = SimpleNamespace(width=90, height=40)
    monkeypatch.setattr(DefenseClawTUI, "size", property(lambda _self: size))
    console = Console(file=io.StringIO(), width=90, color_system=None)
    console.print(app._overview_renderable())  # noqa: SLF001
    lines = console.file.getvalue().splitlines()
    first = next(i for i, line in enumerate(lines) if "[>] Runtime is" in line)
    text_col = lines[first].index("Runtime is")
    continuation = lines[first + 1]
    assert continuation.strip() and len(continuation) - len(continuation.lstrip()) == text_col, lines[first : first + 2]
