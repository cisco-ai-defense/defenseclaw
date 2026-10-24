# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the CLI status UX batch 12 (GAP-2065, 2075, 2080, 2081)."""

from __future__ import annotations

import contextlib
import io
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_registry, cmd_setup, cmd_status
from defenseclaw.config import AIDiscoveryConfig, ApplicationProtectionConfig
from defenseclaw.observability.custody_status import (
    NativeDeliveryStatus,
    NativeDeliverySummary,
    native_delivery_display_rows,
)

from tests.helpers import cleanup_app, make_app_context


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def _row(connector: str, default: bool, state: str = "no_evidence") -> NativeDeliveryStatus:
    return NativeDeliveryStatus(connector, default, state, 0, 0, "detail")


def test_idle_additional_instances_fold_into_one_line() -> None:
    # GAP-2065: one line per past sandbox run buried the real rows.
    connectors = [_row("claudecode", True, "accepted"), *[_row("claudecode", False)] * 11, _row("codex", True)]
    rows = native_delivery_display_rows(connectors)
    assert [(label, row.connector) for label, row in rows] == [
        ("", "claudecode"),
        ("11 additional instances", "claudecode"),
        ("", "codex"),
    ]
    out = _capture(
        cmd_status._print_native_delivery_status,
        NativeDeliverySummary("available", "", 24, connectors=tuple(connectors)),
    )
    assert out.count("additional instance") == 1
    assert "claudecode (11 additional instances)" in out and "nothing to do" in out


def test_status_names_a_gateway_that_is_alive_but_not_answering(tmp_path) -> None:
    # GAP-2081: "not running; start it" was a dead end for a hung gateway.
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text(str(os.getpid()))
    pid_file.chmod(0o600)
    assert cmd_status._live_gateway_pid(SimpleNamespace(data_dir=str(tmp_path))) == os.getpid()
    assert cmd_status._live_gateway_pid(SimpleNamespace(data_dir=str(tmp_path / "none"))) == 0

    cfg = MagicMock()
    cfg.active_connectors.return_value = ["codex", "claudecode"]
    cfg.guardrail.effective_mode.return_value = "action"
    cfg.guardrail.effective_enabled.return_value = True
    cfg.application_protection = ApplicationProtectionConfig()
    cfg.ai_discovery = AIDiscoveryConfig()
    cfg.data_dir = ""
    out = _capture(cmd_status._print_agents, cfg, sidecar_down=True, sidecar_hung=True)
    assert "2 configured, no hook verdicts while the sidecar is not answering" in out
    assert "Check it: defenseclaw-gateway status" in out
    assert "not enforced" not in out and "Start it" not in out


def test_setup_names_a_gateway_that_was_kept_starting(monkeypatch) -> None:
    # GAP-2080: restarting a slow gateway again would only stop it again.
    monkeypatch.setattr(cmd_setup, "_gateway_left_starting", True)
    with pytest.raises(click.ClickException) as exc:
        cmd_setup._fail_if_restart_failed(["defenseclaw-gateway"])
    message = exc.value.format_message()
    assert "still starting and was kept running" in message
    assert "defenseclaw-gateway status" in message and "restart failed" not in message
    assert cmd_setup._gateway_left_starting is False


@pytest.fixture
def registry_app(monkeypatch):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    monkeypatch.setattr(cmd_registry, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    yield app
    cleanup_app(app, db_path, tmp_dir)


def test_registry_wizard_asks_for_a_file_path_and_hints_sync_only_when_declined(registry_app) -> None:
    # GAP-2075
    answers = "local-mcp\nfile\nmcp\n~/registry.yaml\nn\nn\n"
    result = CliRunner().invoke(cmd_registry.registry, ["wizard"], input=answers, obj=registry_app)
    assert result.exit_code == 0, result.output
    assert "Manifest file path" in result.output and "Manifest URL" not in result.output
    assert result.output.count("defenseclaw registry sync local-mcp") == 1
    assert result.output.index("Sync now?") < result.output.index("defenseclaw registry sync local-mcp")
    source = next(s for s in registry_app.cfg.registries.sources if s.id == "local-mcp")
    assert source.url == os.path.expanduser("~/registry.yaml")


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_status_names_a_gateway_that_answers_health_but_not_this_account(tmp_path, monkeypatch, platform) -> None:
    # GAP-0150: a gateway that answers /health is not hung because this
    # account cannot read its .env.
    import requests
    from defenseclaw.commands import cmd_doctor

    client = MagicMock()
    public = MagicMock()
    public.health.return_value = {"status": "ok"}
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=SimpleNamespace(resolved_token=lambda: ""))
    dotenv = tmp_path / ".env"
    dotenv.write_text("X=1\n", encoding="utf-8")

    def refuse(path, *_args, **_kwargs):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(cmd_status, "open", refuse, raising=False)
    monkeypatch.setattr(cmd_status, "sys", SimpleNamespace(platform=platform), raising=False)
    detail = cmd_status._status_refused_detail(cfg, client, public)
    assert f"cannot read {dotenv}" in detail
    if platform == "win32":
        assert "defenseclaw doctor" in detail and "chmod" not in detail
    else:
        assert "chmod 600" in detail
    client.status.assert_not_called()
    monkeypatch.undo()

    cfg.gateway = SimpleNamespace(resolved_token=lambda: "test-token")
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: SimpleNamespace(trusted=True))
    response = requests.Response()
    response.status_code = 401
    client.status.side_effect = requests.HTTPError(response=response)
    assert "refused this account's gateway token (HTTP 401)" in cmd_status._status_refused_detail(cfg, client, public)

    # No /health answer either: starting or hung, as before.
    public.health.side_effect = requests.ConnectionError("refused")
    assert cmd_status._status_refused_detail(cfg, client, public) == ""
    client.health.assert_not_called()

    roster = MagicMock()
    roster.active_connectors.return_value = ["codex", "claudecode"]
    roster.guardrail.effective_mode.return_value = "action"
    roster.guardrail.effective_enabled.return_value = True
    roster.application_protection = ApplicationProtectionConfig()
    roster.ai_discovery = AIDiscoveryConfig()
    roster.data_dir = ""
    out = _capture(cmd_status._print_agents, roster, sidecar_down=True, sidecar_hung=True, sidecar_unread=True)
    assert "2 configured; live hook state not readable by this account" in out
    assert "not answering" not in out and "fall back" not in out


def test_status_never_sends_the_gateway_token_to_an_unverified_listener(monkeypatch) -> None:
    # Review fix: /health goes out without the token, and the authenticated
    # /status only after the listener is proven to be this account's gateway.
    from defenseclaw.commands import cmd_doctor
    from defenseclaw.gateway import OrchestratorClient

    assert not {"Authorization", "X-DC-Auth"} & set(OrchestratorClient(host="127.0.0.1", port=1)._session.headers)
    client = MagicMock()
    public = MagicMock()
    public.health.return_value = {"status": "ok"}
    cfg = SimpleNamespace(data_dir="", gateway=SimpleNamespace(resolved_token=lambda: "test-token"))

    def unproven(_cfg):
        raise OSError("listener ownership cannot be inspected")

    for trust in (lambda _cfg: SimpleNamespace(trusted=False), unproven):
        monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", trust)
        detail = cmd_status._status_refused_detail(cfg, client, public)
        assert "could not verify that the listener is its gateway" in detail
        assert "did not send the gateway token" in detail
    client.status.assert_not_called()
    client.health.assert_not_called()
