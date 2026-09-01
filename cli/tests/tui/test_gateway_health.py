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
    _project_omnigent_effective_readiness,
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

_DATA_DIR = "/tmp/defenseclaw-tui-runtime"


@pytest.fixture(autouse=True)
def _verified_managed_listener(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
        lambda _config: SimpleNamespace(trusted=True, pid=4242, detail=""),
    )


def _config(*, api_bind: str = "127.0.0.7", platform: str = "windows") -> SimpleNamespace:
    return SimpleNamespace(
        data_dir=_DATA_DIR,
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


def _status_payload(
    *,
    gateway_state: str = "disabled",
    data_dir: str = _DATA_DIR,
    runtime_pid: object = 4242,
) -> dict[str, object]:
    return {
        "runtime": {"pid": runtime_pid, "data_dir": data_dir},
        "health": _healthy_payload(gateway_state=gateway_state),
    }


def test_authenticated_sidecar_uses_api_bind_port_and_token_in_hook_only_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def status(self) -> dict[str, object]:
            return _status_payload()

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


def test_tui_projects_stale_omnigent_for_singular_and_plural_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detail = "server record is stale; effective policy config is unverified"
    calls: list[object] = []

    def readiness(config: object) -> tuple[str, str]:
        calls.append(config)
        return "warn", detail

    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
        readiness,
    )
    config = _config()
    opencode = ConnectorHealth(
        name="opencode",
        state="running",
        source="manual",
        load_heartbeat_at="2026-08-04T23:00:00Z",
    )
    snapshot = HealthSnapshot(
        connector=ConnectorHealth(name="omnigent", state="running", source="automatic"),
        connectors=(
            ConnectorHealth(name="omnigent", state="running", source="automatic"),
            ConnectorHealth(name="codex", state="running"),
            opencode,
        ),
    )

    projected = _project_omnigent_effective_readiness(config, snapshot)

    assert projected.connector is not None
    assert projected.connector.state == "degraded"
    assert projected.connector.source == "automatic"
    assert [(row.name, row.state) for row in projected.connectors] == [
        ("omnigent", "degraded"),
        ("codex", "running"),
        ("opencode", "running"),
    ]
    assert projected.connectors[2] is opencode
    assert projected.connectors[2].source == "manual"
    assert projected.connectors[2].load_heartbeat_at == "2026-08-04T23:00:00Z"
    assert calls == [config]

    single = OverviewPanelModel(OverviewConfig(claw_mode="omnigent"))
    single.set_health(projected)
    assert single.subsystem_state("agent") == "degraded"

    multi = OverviewPanelModel(
        OverviewConfig(
            claw_mode="omnigent",
            connector_modes=(("omnigent", "action"), ("codex", "observe")),
        )
    )
    multi.set_health(HealthSnapshot(connectors=projected.connectors[:2]))
    assert multi.subsystem_state("agent") == "degraded"


def test_tui_preserves_verified_omnigent_runtime_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
        lambda _config: ("pass", "live effective config verified through --config"),
    )
    snapshot = HealthSnapshot(
        connector=ConnectorHealth(name="omnigent", state="running"),
        connectors=(ConnectorHealth(name="omnigent", state="running"),),
    )

    projected = _project_omnigent_effective_readiness(_config(), snapshot)

    assert projected.connector is not None
    assert projected.connector.state == "running"
    assert projected.connectors[0].state == "running"


def test_tui_readiness_error_degrades_omnigent_without_failing_gateway_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health = _healthy_payload()
    health["connector"] = {"name": "omnigent", "state": "running", "source": "manual"}
    health["connectors"] = [{"name": "omnigent", "state": "running", "source": "manual"}]

    class FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def status(self) -> dict[str, object]:
            return {
                "runtime": {"pid": 4242, "data_dir": _DATA_DIR},
                "health": health,
            }

    def unavailable(_config: object) -> tuple[str, str]:
        raise OSError("evidence unavailable")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", FakeClient)
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._omnigent_runtime_readiness",
        unavailable,
    )

    result = _fetch_gateway_health(_config())

    assert result.state == "running"
    assert result.snapshot is not None
    assert result.snapshot.connector is not None
    assert result.snapshot.connector.state == "degraded"
    assert result.snapshot.connectors[0].state == "degraded"


def test_authenticated_sidecar_rejects_foreign_runtime_data_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForeignClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def status(self) -> dict[str, object]:
            return _status_payload(data_dir="/tmp/foreign-defenseclaw-runtime")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", ForeignClient)

    result = _fetch_gateway_health(_config())

    assert result.state == "error"
    assert result.snapshot is None
    assert "different canonical data home" in result.detail


@pytest.mark.parametrize(
    "runtime_pid",
    (
        4242.9,
        4242.0,
        True,
        None,
        {},
        [],
        "not-a-pid",
        0,
        -1,
        "4242",
        "004242",
        "+4242",
        " 4242 ",
        4241,
        9999,
    ),
)
def test_authenticated_sidecar_rejects_unverified_runtime_pid(
    monkeypatch: pytest.MonkeyPatch,
    runtime_pid: object,
) -> None:
    class SameHomeForeignProcessClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def status(self) -> dict[str, object]:
            return _status_payload(runtime_pid=runtime_pid)

    monkeypatch.setattr(
        "defenseclaw.gateway.OrchestratorClient",
        SameHomeForeignProcessClient,
    )

    result = _fetch_gateway_health(_config())

    assert result.state == "error"
    assert result.snapshot is None
    assert "runtime" in result.detail.lower()


def test_unverified_listener_is_rejected_before_tui_sends_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = False

    class UnusedClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def status(self) -> dict[str, object]:
            nonlocal requested
            requested = True
            return _status_payload()

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", UnusedClient)
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
        lambda _config: SimpleNamespace(trusted=False, pid=0, detail="foreign listener"),
    )

    result = _fetch_gateway_health(_config())

    assert result.state == "error"
    assert "unverified" in result.detail
    assert requested is False


@pytest.mark.parametrize(
    ("platform", "api_bind", "expected_host"),
    (
        ("darwin", "", "127.0.0.1"),
        ("linux", "0.0.0.0", "127.0.0.1"),
        ("linux", "::", "::1"),
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

        def status(self) -> dict[str, object]:
            return _status_payload(gateway_state="running")

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

        def status(self) -> dict[str, object]:
            raise requests.ConnectionError("fixture connection refused")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", UnreachableClient)
    unreachable = _fetch_gateway_health(_config())
    assert unreachable.state == "offline"
    assert unreachable.snapshot is None

    class StoppedClient(UnreachableClient):
        def status(self) -> dict[str, object]:
            return _status_payload(gateway_state="stopped")

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

        def status(self) -> dict[str, object]:
            return _status_payload(gateway_state="reconnecting")

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", StartingClient)
    starting = _fetch_gateway_health(_config())
    assert starting.state == "starting"
    assert "reconnecting" in starting.detail

    class UnauthorizedClient(StartingClient):
        def status(self) -> dict[str, object]:
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
