# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw routing enable|disable --connector: the route-only helpers get the loaded config.

The routing group skips the root config load (a managed user cannot read
config.yaml), so these commands load it themselves and hand the config, not
the click context, to routing_route_only.enable/disable.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_routing

UPSTREAM = {"base_url": "https://llm.corp.example", "api": "messages"}


def _write_config(home: Path, route_only: dict | None = None) -> None:
    routing = {
        "enabled": True,
        "classifier": "rules",
        "models": [{"name": "haiku", "provider": "anthropic", "model": "claude-haiku-4-5"}],
    }
    if route_only:
        routing["route_only"] = route_only
    body = {"config_version": 9, "data_dir": str(home), "observability": {}, "routing": routing}
    (home / "config.yaml").write_text(yaml.safe_dump(body), encoding="utf-8")


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for key in list(os.environ):
        if key.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_", "DEFENSECLAW_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    claude = tmp_path / "claude"
    claude.mkdir()
    (tmp_path / "codex").mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    (claude / "settings.json").write_text(
        json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://llm.corp.example/"}}), encoding="utf-8"
    )

    # The gateway is down: the route-only path must never ask its API.
    def gateway_down(app, method, path, **kw):
        raise AssertionError(f"asked the stopped gateway {method} {path}")

    monkeypatch.setattr(cmd_routing, "_ask_gateway", gateway_down)
    # No gateway answers /health either: enable reports "not applied yet" at once.
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: {"state": "unreachable"})
    return tmp_path


def _run(*args: str):
    return CliRunner().invoke(cmd_routing.routing_cmd, list(args), catch_exceptions=False)


def _route_only(home: Path) -> dict | None:
    return yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))["routing"].get("route_only")


def test_enable_connector_records_the_upstream(home: Path) -> None:
    _write_config(home)
    result = _run("enable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert _route_only(home) == {"connectors": ["claudecode"], "upstreams": {"claudecode": UPSTREAM}}
    assert "not applied yet" in result.output
    assert "Routing claudecode model calls through DefenseClaw" not in result.output


def _live_health(problem: str = "", signing: dict | None = None, ready: bool = False) -> dict:
    state = {"connector": "claudecode", "ready": ready, "problem": problem}
    if signing:
        state["signing"] = signing
    return {"routing": {"state": "running", "details": {"route_only": [state]}}}


def _rendered(monkeypatch: pytest.MonkeyPatch, ok: bool) -> None:
    from defenseclaw import doctor_route_only as dro

    row = dro.Row("pass" if ok else "warn", "Route-only claudecode agent config", "not rendered", "restart it")
    monkeypatch.setattr(dro, "agent_config_row", lambda cfg, connector, upstream, **kw: row)


def test_enable_connector_success_line_only_once_the_gateway_rendered(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_config(home)
    _rendered(monkeypatch, True)
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: _live_health(ready=True)["routing"])
    result = _run("enable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert "Routing claudecode model calls through DefenseClaw (upstream https://llm.corp.example)." in result.output
    assert "Restart claudecode" in result.output


def test_enable_connector_names_the_cause_when_the_gateway_cannot_render(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_config(home)
    _rendered(monkeypatch, False)
    health = _live_health("gateway Bedrock signing is not ready")["routing"]
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: health)
    clock = iter(range(0, 1000))
    monkeypatch.setattr("time.monotonic", lambda: next(clock))
    monkeypatch.setattr("time.sleep", lambda s: None)
    result = _run("enable", "--connector", "claudecode")
    assert result.exit_code == 1
    assert "gateway Bedrock signing is not ready" in result.output
    assert "still calls its model directly" in result.output
    assert "routing disable --connector claudecode" in result.output
    assert "Routing claudecode model calls through DefenseClaw" not in result.output
    assert "Restart claudecode to pick it up." not in result.output


def test_enable_connector_does_not_report_the_not_ready_row_from_before_the_save(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # /health has no config generation: the first answers can still be the
    # failure of the previous config; the render that follows is a success.
    from defenseclaw import doctor_route_only as dro

    _write_config(home)
    answers = [_live_health("gateway Bedrock signing is not ready")["routing"]] * 2
    rows = iter([False, False, True, True, True])

    def row(cfg, connector, upstream, **kw):
        ok = next(rows)
        return dro.Row("pass" if ok else "warn", "Route-only claudecode agent config", "not rendered", "restart it")

    monkeypatch.setattr(dro, "agent_config_row", row)
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: answers.pop(0) if answers else _live_health(ready=True)["routing"])
    clock = iter(range(0, 1000))
    monkeypatch.setattr("time.monotonic", lambda: next(clock))
    monkeypatch.setattr("time.sleep", lambda s: None)
    result = _run("enable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert "Routing claudecode model calls through DefenseClaw" in result.output
    assert "still calls its model directly" not in result.output


def test_enable_connector_wait_is_bounded_when_the_gateway_never_renders(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_config(home)
    _rendered(monkeypatch, False)
    polls: list[int] = []

    def health(app):
        polls.append(1)
        return {"state": "running"}  # up, but reports no route-only state

    clock = iter(range(0, 1000, 4))
    monkeypatch.setattr(cmd_routing, "_health_routing", health)
    monkeypatch.setattr("time.monotonic", lambda: next(clock))
    monkeypatch.setattr("time.sleep", lambda s: None)
    result = _run("enable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert 1 < len(polls) <= 4
    assert "not applied yet" in result.output
    assert "Routing claudecode model calls through DefenseClaw" not in result.output


def test_enable_connector_refusal_is_a_plain_error(home: Path) -> None:
    _write_config(home)
    result = _run("enable", "--connector", "cursor")
    assert result.exit_code == 1
    assert "no route-only support" in result.output
    assert _route_only(home) is None


def test_disable_connector_with_the_gateway_down_restores_the_agent(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_config(home, {"connectors": ["claudecode"], "upstreams": {"claudecode": UPSTREAM}})
    calls: list[list[str]] = []

    real_run = subprocess.run

    def fake_run(args, **kwargs):
        if "route-restore" not in args:  # config load probes (nvidia-smi) run for real
            return real_run(args, **kwargs)
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("defenseclaw.gateway.path_gateway", lambda honor_override=False: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run("disable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert _route_only(home) in (None, {})
    assert calls == [["/opt/dc/defenseclaw-gateway", "connector", "route-restore", "--connector", "claudecode"]]
    assert "Stopped routing claudecode" in result.output
    assert "Restored the claudecode model settings" in result.output


def test_disable_connector_says_how_to_restore_when_it_cannot(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(home, {"connectors": ["claudecode"], "upstreams": {"claudecode": UPSTREAM}})
    monkeypatch.setattr("defenseclaw.gateway.path_gateway", lambda honor_override=False: None)
    result = _run("disable", "--connector", "claudecode")
    assert result.exit_code == 0, result.output
    assert _route_only(home) in (None, {})
    assert "no defenseclaw-gateway is installed" in result.output


def test_disable_unrouted_connector_still_reports_the_restore(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_config(home)
    real_run = subprocess.run

    def fake_run(args, **kwargs):
        if "route-restore" not in args:
            return real_run(args, **kwargs)
        return subprocess.CompletedProcess(args, 1, "", "")

    monkeypatch.setattr("defenseclaw.gateway.path_gateway", lambda honor_override=False: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _run("disable", "--connector", "codex")
    assert result.exit_code == 0, result.output
    assert "codex was not routed." in result.output
    assert "route-restore --connector codex" in result.output
