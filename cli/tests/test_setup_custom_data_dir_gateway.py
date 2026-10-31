"""Setup finds the gateway of a custom data_dir (rel-1-0-6 GAP-0230).

``defenseclaw config set data_dir ~/dcdata`` leaves config.yaml and the
gateway's PID record in the install home; the gateway keeps its stores and
hooks in the new folder. Setup's restart and health wait joined config.yaml and
gateway.pid to the data folder, so it probed the default API port, saw no
running gateway and rolled the connector back while the gateway served.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_setup

API_PORT = 19883


def _install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, data_dir: Path | None = None) -> tuple[Path, Path]:
    home = tmp_path / "home" / ".defenseclaw"
    home.mkdir(parents=True)
    data = data_dir if data_dir is not None else tmp_path / "dcdata"
    data.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        f"config_version: 9\ndata_dir: {data}\ngateway:\n  api_bind: 127.0.0.1\n  api_port: {API_PORT}\n"
    )
    (home / "gateway.pid").write_text('{"pid": 4242, "generation": "new"}\n')
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    return home, data


def test_a_custom_data_dir_finds_the_gateway_pid_record_in_the_install_home(tmp_path, monkeypatch) -> None:
    home, data = _install(tmp_path, monkeypatch)
    other = tmp_path / "other"
    other.mkdir()

    assert config_module.gateway_pid_path(str(data)) == str(home / "gateway.pid")
    assert config_module.gateway_pid_path(str(home)) == str(home / "gateway.pid")
    assert config_module.gateway_pid_path(str(other)) == str(other / "gateway.pid")


def test_setup_health_wait_succeeds_with_a_custom_data_dir(tmp_path, monkeypatch) -> None:
    home, data = _install(tmp_path, monkeypatch)
    probed_ports: list[int] = []

    def health_once(cfg, *, timeout):
        probed_ports.append(int(cfg.gateway.api_port))
        if int(cfg.gateway.api_port) != API_PORT:
            return None
        return {"api": {"state": "running"}, "started_at": "2026-10-31T23:00:00Z"}

    monkeypatch.setattr(cmd_setup, "_read_defense_gateway_health_once", health_once)
    monkeypatch.setattr(
        cmd_setup,
        "_gateway_pid_file_identifies_gateway",
        lambda path: Path(path) == home / "gateway.pid",
    )
    prior = cmd_setup._GatewayRuntimeGeneration(b"retired", "2026-10-31T22:00:00Z", 0.0)

    assert cmd_setup._wait_for_defense_gateway_api(str(data), timeout=2.0, previous_generation=prior)
    assert probed_ports and set(probed_ports) == {API_PORT}


def test_setup_restarts_the_running_gateway_of_a_custom_data_dir(tmp_path, monkeypatch) -> None:
    home, data = _install(tmp_path, monkeypatch)
    commands: list[list[str]] = []
    waited: list[str] = []

    monkeypatch.setattr(cmd_setup, "_is_pid_alive", lambda path: Path(path) == home / "gateway.pid")
    monkeypatch.setattr(cmd_setup, "_gateway_pid_file_identifies_gateway", lambda path: True)
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda **_kw: sys.executable)
    monkeypatch.setattr(cmd_setup, "_audit_upgrade_note", lambda _data_dir: "")

    def run(cmd, **_kw):
        commands.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def wait(data_dir, **_kw):
        waited.append(data_dir)
        return True

    monkeypatch.setattr(cmd_setup, "run_pinned_executable", run)
    monkeypatch.setattr(cmd_setup, "_wait_for_defense_gateway_api", wait)
    prior = cmd_setup._GatewayRuntimeGeneration(b"retired", None, 0.0)

    assert cmd_setup._restart_defense_gateway(str(data), previous_generation=prior)
    assert [cmd[-1] for cmd in commands] == ["restart"]
    assert waited == [str(data)]
