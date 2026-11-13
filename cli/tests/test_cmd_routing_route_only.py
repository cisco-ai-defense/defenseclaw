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
    assert "https://llm.corp.example" in result.output
    assert "Restart claudecode" in result.output


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
