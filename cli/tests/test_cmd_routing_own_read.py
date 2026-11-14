"""Own routing reads of a standard account on a managed device."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from defenseclaw.commands import cmd_routing


def test_managed_user_without_config_reads_through_the_gateway_binary(monkeypatch):
    calls = []
    monkeypatch.setattr(cmd_routing, "_managed", lambda: True)
    monkeypatch.setattr(cmd_routing, "_client", lambda app, timeout=5: (_ for _ in ()).throw(PermissionError("config.yaml")))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout='{"budgets": []}', stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    answer, error = cmd_routing._ask_gateway(SimpleNamespace(cfg=None), "GET", "/api/v1/routing/effective", params={"recent": 5})
    assert error == "" and answer == {"budgets": []}
    assert calls == [["/opt/dc/defenseclaw-gateway", "routing-read", "/api/v1/routing/effective?recent=5"]]


def test_refusal_and_writes_are_not_routed_to_the_own_read(monkeypatch):
    monkeypatch.setattr(cmd_routing, "_managed", lambda: True)
    monkeypatch.setattr(cmd_routing, "_client", lambda app, timeout=5: (_ for _ in ()).throw(PermissionError("config.yaml")))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: SimpleNamespace(returncode=1, stdout='{"error": "users may not read routing here"}', stderr=""),
    )
    answer, error = cmd_routing._ask_gateway(SimpleNamespace(cfg=None), "GET", "/api/v1/routing/budgets")
    assert answer is None and error == "users may not read routing here"
    answer, error = cmd_routing._ask_gateway(SimpleNamespace(cfg=None), "POST", "/api/v1/routing/test", json={})
    assert answer is None and error.startswith("cannot reach the gateway")
