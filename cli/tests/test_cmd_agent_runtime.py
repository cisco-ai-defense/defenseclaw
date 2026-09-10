# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw agent discovery runtime`` command surface."""

from __future__ import annotations

import json
from typing import Any

import pytest
import requests
from click.testing import CliRunner
from defenseclaw.commands import cmd_agent
from defenseclaw.main import cli


def _runtime_group() -> Any:
    return cli.commands["agent"].commands["discovery"].commands["runtime"]


def test_runtime_is_nested_under_discovery_not_under_agent() -> None:
    # The nesting is the point: presence and behaviour are two halves of one
    # question, and an operator who has just run `agent discovery status`
    # should find "and what actually ran" one level down.
    assert "runtime" not in cli.commands["agent"].commands
    assert sorted(_runtime_group().commands) == [
        "disable",
        "enable",
        "findings",
        "scan",
        "selftest",
        "status",
    ]


_DEGRADED_SNAPSHOT: dict[str, Any] = {
    "enabled": True,
    "scanned_at": "2026-09-09T12:00:00Z",
    "findings": [],
    "planes": [
        {"plane": "a", "name": "inference heartbeat", "available": True, "running": True,
         "mechanism": "ps(1)"},
        {"plane": "b", "name": "shadow egress", "available": True, "running": True,
         "mechanism": "lsof(8)"},
        {"plane": "c", "name": "agent actions", "available": False, "running": False,
         "reason": "eslogger not found"},
    ],
    "processes_observed": 400,
    "processes_skipped": 12,
    "connections_observed": 60,
    "connections_unattributed": 55,
    "degraded": True,
    "degraded_reasons": ["agent actions unavailable: eslogger not found"],
}


class _StubClient:
    def __init__(self, payload: dict[str, Any] | None = None, error: Exception | None = None):
        self.payload = payload if payload is not None else dict(_DEGRADED_SNAPSHOT)
        self.error = error
        self.scanned = False

    def ai_runtime(self) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return self.payload

    def scan_ai_runtime(self) -> dict[str, Any]:
        self.scanned = True
        if self.error is not None:
            raise self.error
        return self.payload


@pytest.fixture()
def stub_client(monkeypatch: pytest.MonkeyPatch) -> _StubClient:
    client = _StubClient()
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    return client


def _invoke(*args: str) -> Any:
    return CliRunner().invoke(cli, ["agent", "discovery", "runtime", *args])


def test_findings_reports_coverage_even_with_nothing_found(stub_client: _StubClient) -> None:
    # "Nothing found" and "nothing could be looked at" are different results,
    # so the coverage lines are printed either way.
    result = _invoke("findings")
    assert result.exit_code == 0, result.output
    assert "no findings at or above the reporting floor" in result.output
    assert "agent actions" in result.output
    assert "eslogger not found" in result.output
    assert "55 with no owner" in result.output


def test_findings_warns_when_most_egress_is_unattributable(stub_client: _StubClient) -> None:
    result = _invoke("findings")
    assert result.exit_code == 0, result.output
    assert "could not be attributed to a process" in result.output
    assert "elevated privilege" in result.output


def test_selftest_names_every_blind_plane_and_why(stub_client: _StubClient) -> None:
    result = _invoke("selftest")
    assert result.exit_code == 0, result.output
    assert "coverage is partial" in result.output
    assert "eslogger not found" in result.output


def test_selftest_json_is_a_capability_report(stub_client: _StubClient) -> None:
    result = _invoke("selftest", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["degraded"] is True
    assert payload["connections_unattributed"] == 55
    assert len(payload["planes"]) == 3


def test_findings_json_returns_the_complete_snapshot(stub_client: _StubClient) -> None:
    # Filtering is a rendering concern. Silently dropping rows from a
    # machine-readable export is how coverage gaps get hidden.
    result = _invoke("findings", "--json", "--severity", "critical")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connections_unattributed"] == 55
    assert payload["degraded_reasons"]


def test_scan_polls_rather_than_reading_the_last_snapshot(stub_client: _StubClient) -> None:
    result = _invoke("scan")
    assert result.exit_code == 0, result.output
    assert stub_client.scanned is True


def test_disabled_planes_are_reported_not_errored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cmd_agent, "_usage_client",
        lambda *a, **k: _StubClient(payload={"enabled": False, "findings": [], "planes": []}),
    )
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "disabled in config" in result.output


def test_service_unavailable_becomes_an_actionable_message(monkeypatch: pytest.MonkeyPatch) -> None:
    response = requests.Response()
    response.status_code = 503
    error = requests.HTTPError(response=response)
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: _StubClient(error=error))
    result = _invoke("status")
    assert result.exit_code == 1
    assert "runtime enable" in result.output


def test_limit_must_not_be_negative(stub_client: _StubClient) -> None:
    result = _invoke("findings", "--limit", "-1")
    assert result.exit_code == 2


class _RestartSpy:
    """Records whether the shared restart helper was actually invoked."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, data_dir: Any, host: Any, port: Any, **kwargs: Any) -> None:
        self.calls.append({"data_dir": data_dir, "host": host, "port": port, **kwargs})


@pytest.fixture()
def restart_spy(monkeypatch: pytest.MonkeyPatch) -> _RestartSpy:
    from defenseclaw.commands import cmd_setup

    spy = _RestartSpy()
    monkeypatch.setattr(cmd_setup, "_restart_services", spy)
    return spy


def _config_with_runtime(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Point the CLI at a throwaway config so a real save is harmless."""
    from defenseclaw import config as config_module

    cfg = config_module.default_config()
    cfg.data_dir = str(tmp_path)
    cfg.save = lambda *a, **k: None  # type: ignore[method-assign]
    monkeypatch.setattr(cmd_agent, "_require_loaded_config", lambda *a, **k: cfg)
    return cfg


@pytest.mark.parametrize(
    ("subcommand", "expected_state"),
    [("enable", True), ("disable", False)],
)
def test_runtime_restart_actually_restarts_the_gateway(
    subcommand: str,
    expected_state: bool,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    restart_spy: _RestartSpy,
) -> None:
    """--restart is on by default and must bounce the gateway, not print advice.

    Printing instructions instead makes the default silently mean
    --no-restart. Enabling then collects nothing until a second command, and
    -- the case that matters -- disabling leaves the planes reading argv and
    sockets on a host whose operator just switched them off.
    """
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    # Force a change so the command has something to apply.
    cfg.ai_discovery.runtime.enabled = not expected_state

    result = _invoke(subcommand, "--yes")

    assert result.exit_code == 0, result.output
    assert restart_spy.calls, (
        "the gateway was never restarted; --restart only printed instructions"
    )
    assert cfg.ai_discovery.runtime.enabled is expected_state


def test_runtime_no_restart_says_the_change_is_not_live(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    restart_spy: _RestartSpy,
) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = False

    result = _invoke("enable", "--yes", "--no-restart")

    assert result.exit_code == 0, result.output
    assert not restart_spy.calls
    assert "--no-restart" in result.output


def test_severity_filter_narrows_the_table_and_tolerates_unknown_bands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--severity must filter, and must not crash on a band it does not know.

    The severity of each finding arrives from the gateway over the wire, so
    the two vocabularies can drift. ``tuple.index`` raises on a value it does
    not hold, which ended the command in a traceback; an unrecognised band now
    ranks last, so it is excluded from a narrowing filter rather than
    silently promoted into one.
    """
    payload = {
        "enabled": True,
        "scanned_at": "2026-09-09T12:00:00Z",
        "planes": [],
        "findings": [
            {"finding_id": "a", "severity": "critical", "process": "critproc", "score": 90},
            {"finding_id": "b", "severity": "low", "process": "lowproc", "score": 10},
            # A band this CLI has never heard of.
            {"finding_id": "c", "severity": "catastrophic", "process": "weirdproc", "score": 99},
        ],
    }
    monkeypatch.setattr(
        cmd_agent, "_usage_client", lambda *a, **k: _StubClient(payload=payload)
    )

    result = _invoke("findings", "--severity", "critical")
    assert result.exit_code == 0, result.output
    assert "critproc" in result.output
    assert "lowproc" not in result.output
    assert "weirdproc" not in result.output, (
        "an unrecognised severity was promoted into the critical filter"
    )

    unfiltered = _invoke("findings")
    assert unfiltered.exit_code == 0, unfiltered.output
    for process in ("critproc", "lowproc", "weirdproc"):
        assert process in unfiltered.output
