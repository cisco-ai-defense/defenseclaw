"""A same-home transient gateway remains visible in CLI status.

The proof is Linux-only by design (GAP-0591): a gateway started as a
transient ``systemd --user`` unit has no PID file, and only Linux lets the
CLI prove that no other account listens on the port (``/proc/net`` socket
owners). Elsewhere a PID-file-less holder stays reported as a port holder.
The proof and its refusals are exercised on every OS by running it as on
Linux (``platform_name``, or ``_as_on_linux`` for the status helpers); the
end-to-end status checks with the real platform run where the proof applies.
"""

from __future__ import annotations

import json
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import gateway
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.doctor_gateway import ListenerEvidence

from tests.helpers import cleanup_app, make_app_context

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the same-home transient gateway proof is Linux-only (GAP-0591)",
)


def _config(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    return SimpleNamespace(
        data_dir=str(home),
        deployment_mode="",
        gateway=SimpleNamespace(api_bind="127.0.0.1", api_port=18789),
    )


def _proof_patches(cfg, *, report: dict, foreign_accounts: str = "") -> ExitStack:
    report = {"endpoint": cmd_doctor._gateway_api_url(cfg, "/health"), **report}
    stack = ExitStack()
    stack.enter_context(
        patch.object(
            cmd_doctor,
            "_managed_gateway_process_trust",
            return_value=cmd_doctor._GatewayTrust("missing", "no PID file"),
        )
    )
    stack.enter_context(
        patch.object(cmd_doctor, "_managed_gateway_listener_evidence", return_value=ListenerEvidence("ok", pid=4242))
    )
    stack.enter_context(patch.object(cmd_doctor, "_linux_foreign_listener_accounts", return_value=foreign_accounts))
    stack.enter_context(patch.object(cmd_doctor, "_gateway_port_holder", return_value="PID 4242 (defenseclaw-gateway)"))
    stack.enter_context(
        patch.object(gateway, "resolve_trusted_gateway_binary", return_value="/opt/defenseclaw-gateway")
    )
    stack.enter_context(
        patch.object(
            cmd_doctor.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                ["defenseclaw-gateway", "status", "--json"], 0, json.dumps(report), ""
            ),
        )
    )
    return stack


def _as_on_linux() -> ExitStack:
    """Run the status helpers' listener proof as it runs on Linux, on any OS."""
    original = cmd_doctor._trusted_gateway_listener

    def linux_proof(cfg, **kwargs):
        kwargs["platform_name"] = kwargs.get("platform_name") or "linux"
        return original(cfg, **kwargs)

    stack = ExitStack()
    stack.enter_context(patch.object(cmd_doctor, "_trusted_gateway_listener", side_effect=linux_proof))
    return stack


def test_status_helpers_reach_the_linux_proof_on_every_os(tmp_path: Path) -> None:
    # The control for the refusal tests below: with the Linux proof, this
    # home's listener is trusted, so their refusals come from the proof.
    cfg = _config(tmp_path)
    client = MagicMock()
    client.status.return_value = {
        "runtime": {"pid": 4242, "data_dir": cfg.data_dir},
        "health": {"connectors": [{"name": "claudecode", "state": "running"}]},
    }
    with _proof_patches(cfg, report={"running": True, "health": {}}), _as_on_linux():
        assert cmd_doctor._foreign_gateway_port_holder(cfg) == ""
        health = cmd_status._fetch_runtime_bound_health(client, cfg)
    assert health is not None
    assert health["pid"] == 4242


@linux_only
def test_same_home_transient_gateway_status_has_live_health_and_agents(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    client = MagicMock()
    client.status.return_value = {
        "runtime": {"pid": 4242, "data_dir": cfg.data_dir},
        "health": {"connectors": [{"name": "claudecode", "state": "running"}]},
    }
    report = {"running": True, "health": {"connectors": [{"name": "claudecode"}]}}
    with _proof_patches(cfg, report=report), _as_on_linux():
        assert cmd_doctor._foreign_gateway_port_holder(cfg) == ""
        health = cmd_status._fetch_runtime_bound_health(client, cfg)
    assert health is not None
    assert health["pid"] == 4242
    assert health["connectors"][0]["state"] == "running"
    client.status.assert_called_once()


@linux_only
def test_status_cli_shows_same_home_transient_gateway_and_agent_running() -> None:
    app, tmp_dir, db_path = make_app_context()
    app.cfg.guardrail.connector = "claudecode"
    app.cfg.guardrail.enabled = True
    client = MagicMock()
    client.status.return_value = {
        "runtime": {"pid": 4242, "data_dir": app.cfg.data_dir},
        "health": {"connectors": [{"name": "claudecode", "state": "running", "source": "manual"}]},
    }
    try:
        with (
            _proof_patches(app.cfg, report={"running": True, "health": {}}),
            patch.object(gateway, "OrchestratorClient", return_value=client),
            _as_on_linux(),
        ):
            human = CliRunner().invoke(cmd_status.status, [], obj=app)
            machine = CliRunner().invoke(cmd_status.status, ["--json"], obj=app)
        assert human.exit_code == 0, human.output
        assert "Sidecar:      running (PID 4242" in human.output
        assert "Claude Code (claudecode)" in human.output
        assert "RUNNING" in human.output
        assert "not enforced while the sidecar is stopped" not in human.output
        assert machine.exit_code == 0, machine.output
        payload = json.loads(machine.output)
        assert payload["sidecar"]["running"] is True
        assert payload["connectors"][0]["state"] == "running"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_transient_gateway_proof_trusts_this_homes_listener(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    with _proof_patches(cfg, report={"running": True, "health": {}}):
        trust = cmd_doctor._trusted_gateway_listener(cfg, platform_name="linux")
    assert trust.trusted
    assert trust.pid == 4242


@pytest.mark.parametrize("platform_name", ["win32", "darwin"])
def test_transient_gateway_proof_is_not_used_off_linux(tmp_path: Path, platform_name: str) -> None:
    cfg = _config(tmp_path)
    with (
        _proof_patches(cfg, report={"running": True, "health": {}}),
        patch.object(cmd_doctor, "_transient_same_home_gateway_listener") as transient,
    ):
        trust = cmd_doctor._trusted_gateway_listener(cfg, platform_name=platform_name)
    assert not trust.trusted
    assert trust.code == "missing"
    transient.assert_not_called()


@pytest.mark.parametrize(
    ("report", "foreign_accounts"),
    [
        ({"running": False, "health": {}}, ""),
        ({"running": True, "health": {}}, "uid 5001"),
    ],
)
def test_foreign_or_unhealthy_port_holder_is_not_reported_running(
    tmp_path: Path, report: dict, foreign_accounts: str
) -> None:
    cfg = _config(tmp_path)
    client = MagicMock()
    with _proof_patches(cfg, report=report, foreign_accounts=foreign_accounts), _as_on_linux():
        assert "PID 4242" in cmd_doctor._foreign_gateway_port_holder(cfg)
        assert cmd_status._fetch_runtime_bound_health(client, cfg) is None
    client.status.assert_not_called()


def test_transient_gateway_authenticated_runtime_must_match_listener(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    client = MagicMock()
    client.status.return_value = {
        "runtime": {"pid": 4343, "data_dir": cfg.data_dir},
        "health": {"connectors": [{"name": "claudecode", "state": "running"}]},
    }
    with _proof_patches(cfg, report={"running": True, "health": {}}), _as_on_linux():
        assert cmd_status._fetch_runtime_bound_health(client, cfg) is None


@pytest.mark.parametrize("endpoint", [None, "http://127.0.0.1:18790/health"])
def test_transient_gateway_report_must_name_inspected_endpoint(tmp_path: Path, endpoint: str | None) -> None:
    cfg = _config(tmp_path)
    with _proof_patches(cfg, report={"running": True, "endpoint": endpoint, "health": {}}), _as_on_linux():
        assert "PID 4242" in cmd_doctor._foreign_gateway_port_holder(cfg)


def test_transient_gateway_listener_pid_must_remain_stable(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    with (
        _proof_patches(cfg, report={"running": True, "health": {}}),
        patch.object(
            cmd_doctor,
            "_managed_gateway_listener_evidence",
            side_effect=[ListenerEvidence("ok", pid=4242), ListenerEvidence("ok", pid=4343)],
        ),
    ):
        assert not cmd_doctor._trusted_gateway_listener(cfg, platform_name="linux").trusted
