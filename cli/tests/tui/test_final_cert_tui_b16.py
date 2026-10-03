# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 16: AI discovery restart pending (GAP-2260)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from defenseclaw.tui import app as tui_app
from defenseclaw.tui.services.ai_discovery_state import AIDiscoveryPanelModel, AIUsageSnapshot

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402

_PENDING = {"enabled": False, "configured_enabled": True}


def test_restart_pending_says_restart_not_enable() -> None:
    # GAP-2260: on in config, gateway started before the change.
    model = AIDiscoveryPanelModel()
    model.set_snapshot(AIUsageSnapshot.from_mapping(_PENDING))
    assert "restart" in model.empty_state()
    assert "agent discovery enable" not in model.empty_state()
    action = model.handle_key("s")
    assert action.intent is None and "Press d to restart the gateway" in action.hint

    model.set_snapshot(AIUsageSnapshot.from_mapping({"enabled": False, "configured_enabled": False}))
    assert "agent discovery enable" in model.empty_state()


def test_fetch_ai_usage_adds_the_configured_state(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, **_kwargs):
            self._session = SimpleNamespace(headers={})

        def ai_usage(self):
            return {"enabled": False}

    import defenseclaw.gateway as gateway

    monkeypatch.setattr(gateway, "OrchestratorClient", FakeClient)
    monkeypatch.setattr(gateway, "gateway_api_client_host", lambda _cfg: "127.0.0.1")
    cfg = SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, token="t"),
        ai_discovery=SimpleNamespace(enabled=True),
    )
    snapshot = tui_app._fetch_ai_usage(cfg)  # noqa: SLF001
    assert snapshot is not None and snapshot.restart_pending


async def test_restart_pending_renders_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("ai")
        app.ai_discovery_model.set_snapshot(AIUsageSnapshot.from_mapping(_PENDING))
        await pilot.pause()
        body = app._body_text()  # noqa: SLF001
    assert "running gateway started before that change" in body
    assert "defenseclaw-gateway restart" in body
