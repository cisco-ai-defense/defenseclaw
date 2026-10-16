# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""DAMAGE-678 A7: ``defenseclaw status`` asks Fleet only when Fleet is on."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.commands import cmd_status
from defenseclaw.config import FleetConfig


class _Response:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _Session:
    def __init__(self, body):
        self.calls = []
        self._body = body

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs.get("headers") or {}))
        return _Response(self._body)


def _client(body=None):
    session = _Session(body or {"fleet": {"total_devices": 2, "online": 1, "offline": 1, "lockdown": "x"}})
    return SimpleNamespace(_session=session, base_url="http://127.0.0.1:1", timeout=1)


def test_fleet_off_status_sends_no_fleet_request_and_prints_no_row(monkeypatch):
    monkeypatch.setenv("DCLAW_FLEET_API_TOKEN", "fleet-token-not-the-gateway-token")
    rows = []
    monkeypatch.setattr(cmd_status, "_status_row", lambda *args: rows.append(args))
    cfg = SimpleNamespace(fleet=FleetConfig())
    client = _client()

    cmd_status._print_fleet_health(cfg, client)
    payload = cmd_status._fleet_health_payload(cfg, client)

    assert client._session.calls == []
    assert rows == []
    assert payload == {"available": False}


def test_config_without_fleet_section_is_off(monkeypatch):
    client = _client()
    assert cmd_status._fetch_fleet_health(SimpleNamespace(), client) is None
    assert client._session.calls == []


def test_fleet_on_status_uses_the_configured_fleet_token(monkeypatch):
    monkeypatch.setenv("DCLAW_FLEET_TOKEN_CUSTOM", "custom-fleet-token")
    cfg = SimpleNamespace(fleet=FleetConfig(enabled=True, api_token_env="DCLAW_FLEET_TOKEN_CUSTOM"))
    client = _client()

    payload = cmd_status._fleet_health_payload(cfg, client)

    assert payload["available"] is True
    assert payload["total_devices"] == 2
    assert payload["lockdown"] == 0
    url, headers = client._session.calls[0]
    assert url.endswith("/api/v1/fleet/health")
    assert headers == {"Authorization": "Bearer custom-fleet-token"}
