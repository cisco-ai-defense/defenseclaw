# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Partial shadow-egress coverage is a note, not Runtime DEGRADED (GAP-1274)."""

from __future__ import annotations

import sys
from pathlib import Path

from defenseclaw.tui.services.runtime_state import RuntimePanelModel

sys.path.insert(0, str(Path(__file__).parent))

from test_final_cert_tui_fcz_b32 import _standard_account_runtime  # noqa: E402


def test_a_stated_coverage_limit_is_a_note() -> None:
    model = _standard_account_runtime()
    assert model.health_state() == "partial"
    assert model.health_title() == "WATCHING"
    assert model.health_explanation().startswith("Note: coverage is partial"), model.health_explanation()
    assert "run the gateway elevated" in model.health_explanation()
    assert model.overview().degraded_reason == "shadow egress partially covered"


def test_a_plane_that_is_not_running_is_still_degraded() -> None:
    model = RuntimePanelModel()
    model.set_snapshot(
        {
            "enabled": True,
            "scanned_at": "2026-10-25T12:00:00Z",
            "degraded": True,
            "degraded_reasons": [
                "shadow egress partially covered: egress attribution is limited",
                "inference heartbeat available but not running: stopped",
            ],
            "planes": [
                {"plane": "a", "name": "inference heartbeat", "available": True, "running": False},
                {"plane": "b", "name": "shadow egress", "available": True, "running": True, "reason": "limited"},
            ],
            "findings": [],
        }
    )
    assert model.health_title() == "DEGRADED"
    assert model.health_explanation().startswith("DEGRADED means coverage is partial")
