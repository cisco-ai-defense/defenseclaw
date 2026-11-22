# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor warns about managed routed models keyed by api_key_env (S1 lead item 1)."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor


def _run(cfg) -> list[tuple]:
    seen: list[tuple] = []
    orig = cmd_doctor._emit
    cmd_doctor._emit = lambda status, label, detail="", **kw: seen.append((status, label, detail, kw.get("remediation")))
    try:
        cmd_doctor._check_routing_managed_key_env(cfg, r=None)
    finally:
        cmd_doctor._emit = orig
    return seen


def _cfg(mode: str, models: list[dict], *, enabled: bool = True, profile: str = "standalone") -> SimpleNamespace:
    return SimpleNamespace(
        deployment_mode=mode,
        enterprise=SimpleNamespace(profile=profile),
        routing=SimpleNamespace(enabled=enabled, models=models),
    )


def test_managed_api_key_env_warns() -> None:
    rows = _run(_cfg("managed_enterprise", [{"name": "fast", "api_key_env": "OPENAI_API_KEY"}, {"name": "local"}]))
    assert len(rows) == 1 and rows[0][0] == "warn" and "fast" in rows[0][2]
    assert "routing.models[].credential" in rows[0][3]


def test_credential_or_oss_does_not_warn() -> None:
    assert _run(_cfg("managed_enterprise", [{"name": "fast", "api_key_env": "K", "credential": "openai-org"}])) == []
    assert _run(_cfg("", [{"name": "fast", "api_key_env": "K"}])) == []


def test_routing_off_or_secure_client_does_not_warn() -> None:
    models = [{"name": "fast", "api_key_env": "K"}]
    assert _run(_cfg("managed_enterprise", models, enabled=False)) == []
    assert _run(_cfg("managed_enterprise", models, profile="secure_client")) == []
