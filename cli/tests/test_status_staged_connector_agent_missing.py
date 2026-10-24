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
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_doctor import _DoctorResult
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
    # An executable on this shell's PATH after the scan is no proof that the
    # agent runs the hooks (1.0.4 review, loop round 4); GAP-0052 only names it.
    copilot_not_installed.on_path["copilot"] = "/usr/local/bin/copilot"
    assert doctor_health.connector_agent_missing(data_dir, "copilot") is True


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


@pytest.mark.parametrize("connector,label", [("copilot", "GitHub Copilot CLI (copilot)"), ("claudecode", "Claude Code (claudecode)")])
def test_a_path_only_agent_is_not_proof_that_it_runs(copilot_not_installed, monkeypatch, connector, label):
    """1.0.4 review (loop round 4): an executable named like the agent on the
    PATH of the shell that runs status flipped a negative scan into a
    RUNNING row and an active count, and doctor downgraded its failure to a
    warning, with no hook call after the scan. The PATH is a hint only."""
    copilot_not_installed.on_path[connector] = f"/home/user/bin/{connector}"
    data_dir = copilot_not_installed.data_dir
    assert doctor_health.connector_agent_missing(str(data_dir), connector) is True
    cfg = _cfg([connector], data_dir)
    health = {"connectors": [{"name": connector, "state": "running", "requests": 3}]}
    out = _render(cfg, health)
    row = _row(out, label)
    assert "RUNNING" not in row and "OFF" in row, out
    flat = " ".join(out.split())
    assert f"/home/user/bin/{connector} on this shell's PATH is unverified" in flat, out
    assert "defenseclaw agent discover --refresh" in flat, out
    assert "0 active, 1 not running" in _row(out, "Agents")
    roster = {r["name"]: r for r in cmd_status._connector_roster(cfg)}
    assert roster[connector]["state"] == "off"
    assert "unverified" in roster[connector]["runtime_detail"]
    doctor = _doctor_row(cfg, connector, health, monkeypatch)
    assert doctor["status"] == "fail", doctor
    assert f"/home/user/bin/{connector} is on this shell's PATH, unverified" in doctor["detail"], doctor
    assert doctor["remediation"].startswith("defenseclaw agent discover --refresh"), doctor
    assert "Install" not in doctor["remediation"], doctor
    # A hook call after the scan is the proof the PATH is not.
    health["connectors"][0]["last_activity_at"] = (_SCANNED_AT + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    assert "RUNNING" in _row(_render(cfg, health), label)
    assert _doctor_row(cfg, connector, health, monkeypatch)["status"] == "warn"


def test_status_json_agrees(copilot_not_installed):
    cfg = _cfg(["codex", "copilot"], copilot_not_installed.data_dir)
    rows = {row["name"]: row for row in cmd_status._connector_roster(cfg)}
    assert rows["copilot"]["state"] == "off"
    assert "is not installed" in rows["copilot"]["runtime_detail"]
    assert "state" not in rows["codex"]


def _doctor_row(cfg, connector: str, health, monkeypatch) -> dict:
    monkeypatch.setattr(cmd_doctor, "_doctor_component_evidence", lambda cfg: ())
    monkeypatch.setattr(cmd_doctor, "_connector_enabled", lambda cfg, connector: True)
    monkeypatch.setattr(cmd_doctor, "_unverified_executable_note", lambda cfg, connector: ("", ""))
    probes: list[object] = []

    def gateway_health(cfg_arg):
        probes.append(cfg_arg)
        return (health, "", True) if health is not None else (None, "the gateway is not running", False)

    monkeypatch.setattr(cmd_doctor, "_authenticated_gateway_health", gateway_health)
    r = _DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_component_connector_compatibility(cfg, [connector], r)
    row = next(c for c in r.checks if c["label"] == f"Connector compatibility: {connector}")
    row["probes"] = len(probes)
    return row


@pytest.mark.parametrize(
    "case,activity,missing",
    [
        # Claude Code started by absolute path or from an IDE after a scan that
        # missed it: the gateway took an authenticated hook call after the scan.
        ("call-after-scan", (_SCANNED_AT + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"), False),
        ("call-after-scan-go-nanoseconds", "2026-10-13T09:30:00.123456789Z", False),
        # The scan came after the last call: the agent was removed since.
        ("call-before-scan", (_SCANNED_AT - timedelta(minutes=30)).isoformat().replace("+00:00", "Z"), True),
        ("no-call", None, True),
        ("unreadable-call-time", "yesterday", True),
    ],
)
def test_status_and_doctor_agree_on_an_agent_the_scan_missed(copilot_not_installed, monkeypatch, case, activity, missing):
    """1.0.4 review (loop round 3): status accepted a hook call after a
    negative discovery scan as proof that Claude Code runs; doctor still
    failed it as connector-agent-unavailable from the scan and its own PATH."""
    data_dir = copilot_not_installed.data_dir
    cfg = _cfg(["claudecode"], data_dir)
    row = {"name": "claudecode", "state": "running"}
    if activity is not None:
        row["last_activity_at"] = activity
    health = {"connectors": [row]}
    claude = _row(_render(cfg, health), "Claude Code (claudecode)")
    doctor = _doctor_row(cfg, "claudecode", health, monkeypatch)
    assert doctor["probes"] == 1
    if missing:
        assert "RUNNING" not in claude and "OFF" in claude
        assert doctor["status"] == "fail", doctor
    else:
        assert "RUNNING" in claude and "is not installed" not in claude
        assert doctor["status"] == "warn", doctor
        assert "authenticated hook call from it at 2026-10-13T09:30:00" in doctor["detail"], doctor
        assert "after the last agent discovery" in doctor["detail"], doctor
        assert doctor["remediation"].startswith("defenseclaw agent discover --refresh"), doctor
        assert "Install" not in doctor["remediation"], doctor


def test_doctor_without_the_gateway_keeps_the_scan(copilot_not_installed, monkeypatch):
    cfg = _cfg(["claudecode"], copilot_not_installed.data_dir)
    assert _doctor_row(cfg, "claudecode", None, monkeypatch)["status"] == "fail"


def test_doctor_admits_a_sandbox_only_connector_as_status_does(copilot_not_installed, monkeypatch):
    copilot_not_installed.harness["copilot"] = SimpleNamespace(tag="defenseclaw/sandbox:copilot-u1000")
    cfg = _cfg(["copilot"], copilot_not_installed.data_dir)
    assert "RUNNING" in _row(_render(cfg, {"connectors": [{"name": "copilot", "state": "running"}]}), "(copilot)")
    doctor = _doctor_row(cfg, "copilot", {"connectors": [{"name": "copilot", "state": "running"}]}, monkeypatch)
    assert doctor["status"] == "pass", doctor
    assert "defenseclaw/sandbox:copilot-u1000" in doctor["detail"], doctor


def test_doctor_reads_the_gateway_only_for_an_agent_the_scan_missed(copilot_not_installed, monkeypatch):
    # The scan found Codex: no gateway read. It missed Copilot: an executable
    # on this shell's PATH is no proof, so the gateway's hook calls are read.
    copilot_not_installed.on_path["copilot"] = "/usr/local/bin/copilot"
    cfg = _cfg(["codex", "copilot"], copilot_not_installed.data_dir)
    assert _doctor_row(cfg, "codex", {"connectors": []}, monkeypatch)["probes"] == 0
    assert _doctor_row(cfg, "copilot", {"connectors": []}, monkeypatch)["probes"] == 1
