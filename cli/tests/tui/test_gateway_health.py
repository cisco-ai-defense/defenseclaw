# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# SPDX-License-Identifier: Apache-2.0

"""Focused regressions for WIN-AUD-047 TUI gateway availability."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests
from defenseclaw.tui.app import (
    DefenseClawTUI,
    GatewayHealthResult,
    _fetch_gateway_health,
)
from defenseclaw.tui.models import HintState
from defenseclaw.tui.panels.overview import (
    ConnectorHealth,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)
from defenseclaw.tui.services.setup_state import build_readiness_checks
from defenseclaw.tui.widgets.hint_bar import HintEngine


def _config(*, api_bind: str = "127.0.0.7", platform: str = "windows") -> SimpleNamespace:
    return SimpleNamespace(
        environment=platform,
        gateway=SimpleNamespace(
            api_bind=api_bind,
            api_port=29870,
            # These are the intentionally unrelated fleet/proxy settings.
            host="fleet.invalid",
            port=4000,
            resolved_token=lambda: "runtime-fixture-token",
        ),
        guardrail=SimpleNamespace(port=4000),
    )


def _healthy_payload(*, gateway_state: str = "disabled") -> dict[str, object]:
    return {
        "started_at": "2026-07-07T12:00:00Z",
        "gateway": {
            "state": gateway_state,
            "details": {"summary": "no OpenClaw fleet configured (standalone mode)"},
        },
        "api": {"state": "running", "details": {"addr": "127.0.0.7:29870"}},
        "guardrail": {"state": "running"},
        "connectors": [
            {"name": "codex", "state": "running", "requests": 8},
            {"name": "claudecode", "state": "running", "requests": 5},
        ],
    }


def test_authenticated_sidecar_uses_api_bind_port_and_token_in_hook_only_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def health(self) -> dict[str, object]:
            return _healthy_payload()

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", FakeClient)

    result = _fetch_gateway_health(_config())

    assert result.state == "running"
    assert result.snapshot is not None
    assert [row.name for row in result.snapshot.connectors] == ["codex", "claudecode"]
    assert captured == {
        "host": "127.0.0.7",
        "port": 29870,
        "token": "runtime-fixture-token",
        "timeout": 3,
    }
    assert captured["port"] != 4000


@pytest.mark.parametrize(
    ("platform", "api_bind", "expected_host"),
    (
        ("darwin", "", "127.0.0.1"),
        ("linux", "0.0.0.0", "127.0.0.1"),
        ("linux", "::", "127.0.0.1"),
        ("darwin", "localhost", "localhost"),
    ),
)
def test_gateway_probe_preserves_macos_linux_api_bind_behavior(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    api_bind: str,
    expected_host: str,
) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def health(self) -> dict[str, object]:
            return _healthy_payload(gateway_state="running")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", FakeClient)

    result = _fetch_gateway_health(_config(api_bind=api_bind, platform=platform))

    assert result.state == "running"
    assert captured["host"] == expected_host


def test_gateway_probe_classifies_stopped_and_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnreachableClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def health(self) -> dict[str, object]:
            raise requests.ConnectionError("fixture connection refused")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", UnreachableClient)
    unreachable = _fetch_gateway_health(_config())
    assert unreachable.state == "offline"
    assert unreachable.snapshot is None

    class StoppedClient(UnreachableClient):
        def health(self) -> dict[str, object]:
            return _healthy_payload(gateway_state="stopped")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", StoppedClient)
    stopped = _fetch_gateway_health(_config())
    assert stopped.state == "offline"
    assert stopped.snapshot is not None


def test_gateway_probe_classifies_starting_and_authentication_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StartingClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def health(self) -> dict[str, object]:
            return _healthy_payload(gateway_state="reconnecting")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", StartingClient)
    starting = _fetch_gateway_health(_config())
    assert starting.state == "starting"
    assert "reconnecting" in starting.detail

    class UnauthorizedClient(StartingClient):
        def health(self) -> dict[str, object]:
            response = requests.Response()
            response.status_code = 401
            raise requests.HTTPError(response=response)

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", UnauthorizedClient)
    unauthorized = _fetch_gateway_health(_config())
    assert unauthorized.state == "error"
    assert "authentication error" in unauthorized.detail
    hint = HintEngine().hint_for(
        HintState(active_panel="overview"),
        SimpleNamespace(
            gateway=SimpleNamespace(state=unauthorized.state, detail=unauthorized.detail),
            guardrail=SimpleNamespace(state="running"),
        ),
    )
    assert hint == "Gateway authentication error. Check the configured sidecar API token."
    assert "offline" not in hint.lower()


def test_gateway_configuration_failure_is_not_classified_offline() -> None:
    config = _config()
    config.gateway.api_port = "invalid"

    result = _fetch_gateway_health(config)

    assert result.state == "error"
    assert result.detail == "sidecar API port is invalid"

    config.gateway.api_port = 0
    app = DefenseClawTUI(config=config)
    app._sync_setup_readiness = lambda: None  # type: ignore[method-assign]
    app._schedule_health_poll()
    assert app.overview_model.gateway_availability().state == "error"
    assert "not configured" in app.overview_model.gateway_availability().last_error


@pytest.mark.asyncio
async def test_transient_probe_failure_recovers_without_erasing_live_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_snapshot = HealthSnapshot(
        gateway=SubsystemHealth(state="disabled"),
        api=SubsystemHealth(state="running"),
        connectors=(ConnectorHealth(name="codex", state="running", requests=9),),
    )
    fresh_snapshot = HealthSnapshot(
        gateway=SubsystemHealth(state="disabled"),
        api=SubsystemHealth(state="running"),
        connectors=(ConnectorHealth(name="codex", state="running", requests=10),),
    )
    overview = OverviewPanelModel(OverviewConfig(claw_mode="codex"))
    overview.set_health(old_snapshot)
    app = DefenseClawTUI(config=_config(), overview_model=overview)
    results = iter(
        (
            GatewayHealthResult("offline", "sidecar API is unreachable"),
            GatewayHealthResult("running", snapshot=fresh_snapshot),
        ),
    )
    monkeypatch.setattr("defenseclaw.tui.app._fetch_gateway_health", lambda _cfg: next(results))
    monkeypatch.setattr(app, "_sync_setup_readiness", lambda: None)
    app.active_panel = "activity"

    await app._poll_health()
    assert overview.gateway_availability().state == "offline"
    assert overview.health is old_snapshot
    assert overview.health.connectors[0].requests == 9

    await app._poll_health()
    assert overview.gateway_availability().state == "running"
    assert overview.health is fresh_snapshot
    assert overview.health.connectors[0].requests == 10


def test_hook_only_footer_and_setup_readiness_are_online() -> None:
    snapshot = HealthSnapshot(
        gateway=SubsystemHealth(
            state="disabled",
            details={"summary": "no OpenClaw fleet configured (standalone mode)"},
        ),
        api=SubsystemHealth(state="running"),
        guardrail=SubsystemHealth(state="running"),
    )
    overview = OverviewPanelModel(OverviewConfig(claw_mode="codex"))
    overview.set_health(snapshot)
    overview.set_gateway_probe("running", "no OpenClaw fleet configured (standalone mode)")
    app = DefenseClawTUI(config=_config(), overview_model=overview)

    status = app._hint_status_model()
    hint = HintEngine().hint_for(HintState(active_panel="overview"), status)
    assert status.gateway.state == "running"
    assert "offline" not in hint.lower()

    readiness = build_readiness_checks({}, snapshot, None, ())
    gateway_check = next(check for check in readiness if check.title == "Gateway / API Health")
    assert gateway_check.status == "pass"


def test_disabled_gateway_availability_is_terminal_readiness() -> None:
    readiness = build_readiness_checks(
        {},
        None,
        None,
        (),
        gateway_status=SimpleNamespace(state="disabled", last_error=""),
    )

    gateway_check = next(check for check in readiness if check.title == "Gateway / API Health")
    assert gateway_check.status == "pass"


def test_overview_metrics_do_not_label_health_errors_offline() -> None:
    overview = OverviewPanelModel(OverviewConfig(claw_mode="codex"))
    overview.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="disabled"),
            api=SubsystemHealth(state="running"),
            connector=ConnectorHealth(name="codex", state="running"),
        ),
    )
    overview.set_gateway_probe("error", "authentication error")
    app = DefenseClawTUI(config=_config(), overview_model=overview)

    metrics = {metric.key: metric for metric in app._overview_metric_data()}

    assert "gateway health error" in metrics["hook_calls"].detail
    assert "gateway offline" not in metrics["hook_calls"].detail
