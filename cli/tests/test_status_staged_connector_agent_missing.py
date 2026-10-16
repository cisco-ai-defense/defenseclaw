# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""A connector staged for an agent that is not installed is not RUNNING (GAP-0513).

`defenseclaw setup copilot --yes` on a host without the Copilot CLI warns and
writes the hooks for a later install. The gateway then registers the
connector, so `status` showed "Agents: 1 active" and "GitHub Copilot CLI ...
RUNNING" while doctor failed "Connector compatibility: copilot (agent
installation unavailable)". Status now uses doctor's rule.
"""

from __future__ import annotations

import contextlib
import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from defenseclaw import doctor_health, sandbox_images
from defenseclaw.commands import cmd_status
from defenseclaw.config import AIDiscoveryConfig, ApplicationProtectionConfig
from defenseclaw.inventory import agent_discovery


def _cfg(actives, data_dir="/nonexistent/defenseclaw-data"):
    cfg = MagicMock()
    cfg.active_connectors.return_value = list(actives)
    cfg.guardrail.effective_mode.side_effect = lambda c: "observe"
    cfg.guardrail.effective_enabled.side_effect = lambda c: True
    cfg.application_protection = ApplicationProtectionConfig()
    cfg.ai_discovery = AIDiscoveryConfig()
    cfg.data_dir = str(data_dir)
    return cfg


_SCANNED_AT = datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc)


def _write_scan(data_dir, installed: dict[str, bool]) -> None:
    """A real agent_discovery.json, written as `agent discover` writes it."""
    agents = {
        name: agent_discovery.AgentSignal(
            name=name,
            installed=installed.get(name, False),
            config_path="",
            binary_path=f"/usr/local/bin/{name}" if installed.get(name, False) else "",
            version="1.0.0" if installed.get(name, False) else "",
            error="",
        )
        for name in agent_discovery.DISCOVERABLE_CONNECTORS
    }
    disc = agent_discovery.AgentDiscovery(
        scanned_at=agent_discovery._format_rfc3339(_SCANNED_AT), agents=agents, cache_hit=False
    )
    assert agent_discovery._write_cache(disc, data_dir=data_dir)


@pytest.fixture
def copilot_not_installed(monkeypatch, tmp_path):
    """The last discovery scan found no Copilot CLI; Codex is installed.
    Returns the data directory and the executables on PATH now."""
    data_dir = tmp_path / "defenseclaw"
    data_dir.mkdir()
    _write_scan(data_dir, {"codex": True})
    monkeypatch.setattr(agent_discovery, "_now_utc", lambda: _SCANNED_AT + timedelta(hours=1))
    on_path: dict[str, str] = {}
    monkeypatch.setattr(agent_discovery, "binary_on_path", lambda connector: on_path.get(connector, ""))
    harness: dict[str, object] = {}
    monkeypatch.setattr(
        sandbox_images,
        "verified_harness_contract",
        lambda data_dir_arg, connector: harness.get(connector) if str(data_dir_arg) == str(data_dir) else None,
    )
    monkeypatch.setattr(cmd_status, "_hook_runtime_degraded_suffix", lambda cfg, connector: "")
    return SimpleNamespace(data_dir=data_dir, on_path=on_path, harness=harness)


def _render(cfg, health=None) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_status._print_agents(cfg, health=health)
    return buf.getvalue()


def _row(out: str, label: str) -> str:
    return next(line for line in out.splitlines() if label in line)


def test_doctor_rule_names_the_missing_agent(copilot_not_installed):
    data_dir = str(copilot_not_installed.data_dir)
    assert doctor_health.connector_agent_missing(data_dir, "copilot") is True
    assert doctor_health.connector_agent_missing(data_dir, "codex") is False
    # Installed after the last discovery scan: not missing (GAP-0052).
    copilot_not_installed.on_path["copilot"] = "/usr/local/bin/copilot"
    assert doctor_health.connector_agent_missing(data_dir, "copilot") is False


def test_no_discovery_scan_is_no_proof(tmp_path):
    assert doctor_health.connector_agent_missing(str(tmp_path), "copilot") is False
    (tmp_path / agent_discovery.CACHE_FILENAME).write_text("{", encoding="utf-8")
    assert doctor_health.connector_agent_missing(str(tmp_path), "copilot") is False


def test_an_expired_scan_still_proves_the_agent_missing(copilot_not_installed, monkeypatch):
    """Day two: the one-day cache has expired, nothing rescanned, and the
    staged connector must not turn RUNNING again."""
    monkeypatch.setattr(agent_discovery, "_now_utc", lambda: _SCANNED_AT + timedelta(hours=25))
    assert agent_discovery._read_cache(data_dir=copilot_not_installed.data_dir) is None
    cfg = _cfg(["copilot"], copilot_not_installed.data_dir)
    out = _render(cfg, {"connectors": [{"name": "copilot", "state": "running"}]})
    copilot = _row(out, "GitHub Copilot CLI (copilot)")
    assert "RUNNING" not in copilot and "OFF" in copilot
    assert "0 active, 1 not running" in _row(out, "Agents")
    rows = {row["name"]: row for row in cmd_status._connector_roster(cfg)}
    assert rows["copilot"]["state"] == "off"


def test_a_sandbox_only_connector_is_not_off(copilot_not_installed):
    """No agent on the host, the agent inside a verified harness image: setup
    and the gateway admit the connector, so status does not say install it."""
    copilot_not_installed.harness["copilot"] = SimpleNamespace(tag="defenseclaw/sandbox:copilot-u1000")
    data_dir = copilot_not_installed.data_dir
    assert doctor_health.connector_agent_missing(str(data_dir), "copilot") is False
    cfg = _cfg(["copilot"], data_dir)
    out = _render(cfg, {"connectors": [{"name": "copilot", "state": "running"}]})
    assert "RUNNING" in _row(out, "GitHub Copilot CLI (copilot)")
    assert "is not installed" not in out
    assert "1 active" in _row(out, "Agents")
    rows = {row["name"]: row for row in cmd_status._connector_roster(cfg)}
    assert rows["copilot"].get("state") != "off"


def test_status_does_not_call_a_staged_connector_running(copilot_not_installed):
    cfg = _cfg(["codex", "copilot"], copilot_not_installed.data_dir)
    health = {"connectors": [{"name": "codex", "state": "running"}, {"name": "copilot", "state": "running"}]}
    out = _render(cfg, health)
    copilot = _row(out, "GitHub Copilot CLI (copilot)")
    assert "RUNNING" not in copilot and "OFF" in copilot
    assert "is not installed" in out and "defenseclaw agent discover --refresh" in out
    assert "RUNNING" in _row(out, "Codex (codex)")
    assert "1 active, 1 not running" in _row(out, "Agents")


def test_status_without_the_gateway_names_the_missing_agent(copilot_not_installed):
    out = _render(_cfg(["copilot"], copilot_not_installed.data_dir))
    assert "OFF" in _row(out, "GitHub Copilot CLI (copilot)")
    assert "0 active, 1 not running" in _row(out, "Agents")


def test_an_installed_agent_still_runs(copilot_not_installed):
    copilot_not_installed.on_path["copilot"] = "/usr/local/bin/copilot"
    out = _render(
        _cfg(["copilot"], copilot_not_installed.data_dir),
        {"connectors": [{"name": "copilot", "state": "running"}]},
    )
    assert "RUNNING" in _row(out, "GitHub Copilot CLI (copilot)")
    assert "1 active" in _row(out, "Agents")


def test_status_json_agrees(copilot_not_installed):
    cfg = _cfg(["codex", "copilot"], copilot_not_installed.data_dir)
    rows = {row["name"]: row for row in cmd_status._connector_roster(cfg)}
    assert rows["copilot"]["state"] == "off"
    assert "is not installed" in rows["copilot"]["runtime_detail"]
    assert "state" not in rows["codex"]
