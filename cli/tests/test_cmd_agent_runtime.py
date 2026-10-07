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
import sys
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
        "permissions",
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


def test_runtime_enable_defaults_to_user_level_planes(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    restart_spy: _RestartSpy,
) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = False
    cfg.ai_discovery.runtime.planes = []
    cfg.ai_discovery.runtime.enable_host_plane = False

    result = _invoke("enable", "--yes", "--no-restart")

    assert result.exit_code == 0, result.output
    assert cfg.ai_discovery.runtime.enabled is True
    assert cfg.ai_discovery.runtime.planes == ["a", "b"]
    assert cfg.ai_discovery.runtime.enable_host_plane is False
    assert not restart_spy.calls


def test_runtime_enable_preserves_existing_host_plane_when_flag_is_omitted(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    restart_spy: _RestartSpy,
) -> None:
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = True
    cfg.ai_discovery.runtime.planes = ["a", "b", "c"]
    cfg.ai_discovery.runtime.enable_host_plane = True

    result = _invoke("enable", "--yes", "--no-restart")

    assert result.exit_code == 0, result.output
    assert cfg.ai_discovery.runtime.planes == ["a", "b", "c"]
    assert cfg.ai_discovery.runtime.enable_host_plane is True
    assert not restart_spy.calls


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


def test_runtime_hints_name_a_command_that_exists(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    restart_spy: _RestartSpy,
) -> None:
    """GAP-2548: 'defenseclaw setup restart' does not exist."""
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = False

    result = _invoke("enable", "--yes", "--no-restart")

    assert "setup restart" not in result.output
    assert "defenseclaw-gateway restart" in result.output


def test_runtime_enable_with_only_openclaw_gateway_down_is_not_a_failure(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GAP-2548: defenseclaw-gateway restarted, so the planes are live."""
    from defenseclaw.commands import cmd_setup

    def openclaw_down(*_a: Any, **_k: Any) -> None:
        raise cmd_setup._OpenClawGatewayNotRunning("The OpenClaw gateway is not running.")

    monkeypatch.setattr(cmd_setup, "_restart_services", openclaw_down)
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = False

    result = _invoke("enable", "--yes", "--no-enable-host-plane")

    assert result.exit_code == 0, result.output
    assert "Gateway restart failed" not in result.output
    assert "openclaw gateway run" in result.output
    assert "runtime planes are live" in result.output


def test_runtime_enable_real_restart_failure_names_an_existing_command(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from defenseclaw.commands import cmd_setup

    def gateway_down(*_a: Any, **_k: Any) -> None:
        raise cmd_setup._GatewayRestartFailed("gateway restart/readiness failed")

    monkeypatch.setattr(cmd_setup, "_restart_services", gateway_down)
    monkeypatch.chdir(tmp_path)
    cfg = _config_with_runtime(tmp_path, monkeypatch)
    cfg.ai_discovery.runtime.enabled = False

    result = _invoke("enable", "--yes")

    assert result.exit_code == 1, result.output
    assert "Gateway restart failed" in result.output
    assert "setup restart" not in result.output
    assert "defenseclaw-gateway restart" in result.output


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


def test_runtime_permissions_covers_every_os_and_plane():
    """The install-time answer has to exist for every platform we ship.

    'runtime selftest' can only explain a gateway that is already running.
    An operator deciding what to grant before installing needs an answer
    that does not depend on anything being up, and a plane missing from
    that answer is a plane whose blindness nobody was warned about.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    for target in ("darwin", "linux", "windows"):
        result = CliRunner().invoke(runtime_permissions, ["--os", target, "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["os"] == target
        planes = " ".join(entry["plane"] for entry in payload["grants"])
        # All three planes must be represented, whatever the OS calls them.
        assert "(A)" in planes, target
        assert "(B)" in planes, target
        assert "(C)" in planes, target
        for entry in payload["grants"]:
            # A grant with no stated reason is one an operator cannot weigh.
            assert entry["needs"], entry
            assert entry["why"], entry
            # "how" may be absent only when nothing needs granting.
            if entry["needs"] != "nothing":
                assert entry["how"], entry


def test_runtime_permissions_names_the_macos_tcc_grant():
    """Full Disk Access is the grant people get wrong, twice over.

    It is required on top of root, and it applies to the responsible
    process rather than the gateway binary. Both were observed live: as
    root without it, Endpoint Security refused the client outright.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    result = CliRunner().invoke(runtime_permissions, ["--os", "darwin"])
    assert result.exit_code == 0
    assert "Full Disk Access" in result.output
    assert "responsible" in result.output


def test_runtime_permissions_names_the_windows_command_line_policy():
    """Argv on Windows is a second, separate policy from the audit itself.

    With only the audit subcategories enabled, lineage works and every
    argument-vector tactic silently does not.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    result = CliRunner().invoke(runtime_permissions, ["--os", "windows"])
    assert result.exit_code == 0
    assert "ProcessCreationIncludeCmdLine_Enabled" in result.output
    assert "auditpol" in result.output


def test_runtime_permissions_reports_state_not_just_requirements():
    """A list of requirements is not actionable; a list of gaps is.

    The unprivileged test process cannot hold root, so the grants that
    depend on it must read as missing rather than as unknown -- an
    [unknown] an operator cannot act on is the same as no answer.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    result = CliRunner().invoke(runtime_permissions, ["--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["checked_this_host"] is True

    by_state: dict[object, int] = {}
    for entry in payload["grants"]:
        by_state[entry["granted"]] = by_state.get(entry["granted"], 0) + 1
        # An entry needing nothing is settled, never unknown.
        if entry["needs"] == "nothing":
            assert entry["granted"] is True, entry
    # Something must have been decided either way; an all-unknown report is
    # indistinguishable from not having checked.
    assert by_state.get(True, 0) + by_state.get(False, 0) > 0, payload


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no DNS naming grant")
def test_runtime_permissions_marks_dns_naming_off_when_capture_is_off(monkeypatch):
    """With dns_capture off, the DNS naming grant is unused, not missing."""
    from types import SimpleNamespace

    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    cfg = SimpleNamespace(ai_discovery=SimpleNamespace(runtime=SimpleNamespace(dns_capture=False)))
    monkeypatch.setattr(cmd_agent, "_load_config_best_effort", lambda app: cfg)
    result = CliRunner().invoke(runtime_permissions, [])
    assert result.exit_code == 0, result.output
    assert "[off] shadow egress (B), DNS naming" in result.output
    assert "[MISSING] shadow egress (B), DNS naming" not in result.output
    assert "--dns-capture" in result.output


def test_runtime_permissions_does_not_probe_another_host_os():
    """Asking about a platform you are not on must not report its state.

    Probing this host and labelling the result as another OS's would be a
    confident wrong answer, which is worse than declining to answer.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    other = "windows" if sys.platform != "win32" else "linux"
    result = CliRunner().invoke(runtime_permissions, ["--os", other, "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["checked_this_host"] is False
    for entry in payload["grants"]:
        if entry["needs"] != "nothing":
            assert entry["granted"] is None, entry


def test_grant_commands_are_scoped_and_reversible():
    """These commands change privileged machine state, so pin their shape.

    Two properties matter more than the exact strings: every grant has an
    exact inverse, and nothing grants more than the requirement it names.
    A blanket filesystem SACL would satisfy the Windows file-event gap and
    is deliberately absent -- auditing every object to catch credential
    reads creates more exposure than the detection is worth.
    """
    from defenseclaw.commands.cmd_agent import (
        _linux_grant_commands,
        _windows_grant_commands,
    )

    granted = _linux_grant_commands("/opt/defenseclaw/bin/defenseclaw-gateway", False)
    reverted = _linux_grant_commands("/opt/defenseclaw/bin/defenseclaw-gateway", True)
    assert granted == [[
        "setcap", "cap_dac_read_search,cap_net_admin,cap_net_raw,cap_sys_admin+ep",
        "/opt/defenseclaw/bin/defenseclaw-gateway",
    ]]
    assert reverted == [["setcap", "-r", "/opt/defenseclaw/bin/defenseclaw-gateway"]]

    win_grant = _windows_grant_commands(False)
    win_revert = _windows_grant_commands(True)
    assert len(win_grant) == len(win_revert) == 4
    assert all("enable" in " ".join(c) or "/d 1" in " ".join(c)
               for c in win_grant if c[0] == "auditpol")
    assert all("disable" in " ".join(c)
               for c in win_revert if c[0] == "auditpol")
    # The registry value is set to 1 by grant and 0 by revert, never removed:
    # deleting the key would be indistinguishable from never having set it.
    assert win_grant[-1][-3:] == ["REG_DWORD", "/d", "1"] or "1" in win_grant[-1]
    assert "0" in win_revert[-1]
    # Nothing here touches an ACL.
    joined = " ".join(" ".join(c) for c in win_grant)
    assert "SACL" not in joined and "Set-Acl" not in joined and "icacls" not in joined


def test_linux_process_events_need_cap_net_admin(monkeypatch):
    """The cn_proc truth fix: the process connector is not unprivileged.

    An ordinary uid's bind to the cn_proc multicast group fails with EPERM
    (RHEL 9, kernel 5.14), so the row names CAP_NET_ADMIN, probes it, and
    --grant sets it; before the fix it read "needs: nothing" and even a
    granted gateway still could not subscribe.
    """
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    result = CliRunner().invoke(runtime_permissions, ["--os", "linux", "--json"])
    assert result.exit_code == 0, result.output
    rows = {entry["plane"]: entry for entry in json.loads(result.output)["grants"]}
    process = rows["agent actions (C), process events"]
    assert process["needs"] == "CAP_NET_ADMIN"
    assert process["probe"] == "cap_net_admin"
    assert process["how"]
    assert "cap_net_admin" in cmd_agent._LINUX_GRANT_CAPS.split("+")[0].split(",")
    assert cmd_agent._LINUX_CAPABILITY_BITS["CAP_NET_ADMIN"] == 12

    asked: list[str] = []
    monkeypatch.setattr(cmd_agent, "_probe_linux_capability", lambda name: asked.append(name) or False)
    assert cmd_agent._evaluate_grant("cap_net_admin", True) is False
    assert asked == ["CAP_NET_ADMIN"]


def test_linux_permissions_explain_tetragon_without_asking_for_it():
    """Per-user installs never connect to Tetragon; the row says so and why."""
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    as_json = CliRunner().invoke(runtime_permissions, ["--os", "linux", "--json"])
    assert as_json.exit_code == 0, as_json.output
    rows = {entry["plane"]: entry for entry in json.loads(as_json.output)["grants"]}
    tetragon = rows["agent actions (C), Tetragon"]
    assert tetragon["info"] is True
    assert tetragon["needs"] == "nothing" and tetragon["granted"] is True
    assert "root-only" in tetragon["why"] and "sensor helper" in tetragon["why"]

    text = CliRunner().invoke(runtime_permissions, ["--os", "linux"])
    assert text.exit_code == 0, text.output
    assert "[info] agent actions (C), Tetragon" in text.output
    assert "[granted] agent actions (C), Tetragon" not in text.output


def test_grant_refuses_to_act_on_another_host_os():
    """--grant must never run this host's commands under another OS's label."""
    from click.testing import CliRunner
    from defenseclaw.commands.cmd_agent import runtime_permissions

    other = "windows" if sys.platform != "win32" else "linux"
    result = CliRunner().invoke(runtime_permissions, ["--os", other, "--grant", "--yes"])
    assert result.exit_code != 0
    assert "host you are on" in result.output


def test_grant_declined_at_the_prompt_changes_nothing(monkeypatch):
    """Declining must not run a single command.

    The confirmation is the only thing standing between a curious operator
    and a machine-wide audit policy change, so it is asserted against the
    plan directly rather than through whichever OS the suite happens to run
    on -- macOS has no automatable commands at all, and would pass this
    vacuously.
    """
    import click
    from defenseclaw.commands import cmd_agent

    ran: list[list[str]] = []
    monkeypatch.setattr(
        cmd_agent, "_run_grant_commands",
        lambda commands, elevate: ran.extend(commands) or 0,
    )
    monkeypatch.setattr(
        "defenseclaw.gateway.resolve_gateway_binary", lambda: "/usr/bin/true",
    )
    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)

    with pytest.raises(SystemExit):
        cmd_agent._apply_grants("linux", revert=False, assume_yes=False)
    assert ran == [], ran


def test_grant_confirmed_runs_exactly_the_planned_commands(monkeypatch):
    """Confirming runs the plan, and only the plan."""
    import click
    from defenseclaw.commands import cmd_agent

    ran: list[list[str]] = []
    monkeypatch.setattr(
        cmd_agent, "_run_grant_commands",
        lambda commands, elevate: ran.extend(commands) or 0,
    )
    monkeypatch.setattr(
        "defenseclaw.gateway.resolve_gateway_binary", lambda: "/usr/bin/true",
    )
    monkeypatch.setattr(click, "confirm", lambda *a, **k: True)

    cmd_agent._apply_grants("linux", revert=False, assume_yes=False)
    assert ran == cmd_agent._linux_grant_commands("/usr/bin/true", False)


def test_runtime_dataclass_matches_the_closed_schema():
    """Every runtime key the CLI models is one a config can carry, and back.

    _merge_ai_runtime rebuilds the block from a whitelist, so a schema key the
    dataclass lacks is erased on the next save; a dataclass key the closed
    schema lacks (the retired acquisition and helper_socket) is a setting no
    config.yaml could ever hold.
    """
    from dataclasses import fields

    from defenseclaw.config import AIRuntimeConfig
    from defenseclaw.observability.v8_config import _schema_validator

    schema = _schema_validator().schema
    defs = schema["$defs"]

    def resolve(node: dict) -> dict:
        while "$ref" in node:
            node = defs[node["$ref"].rsplit("/", 1)[-1]]
        return node

    discovery = resolve(schema["properties"]["ai_discovery"])
    runtime = resolve(discovery["properties"]["runtime"])
    assert runtime.get("additionalProperties") is False
    assert {f.name for f in fields(AIRuntimeConfig)} == set(runtime["properties"])


def _snapshot_with_plane_c(backend: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(_DEGRADED_SNAPSHOT)
    plane_c: dict[str, Any] = {
        "plane": "c", "name": "agent actions", "available": True, "running": True,
        "mechanism": "Tetragon (exec, exit) + fanotify",
    }
    if backend is not None:
        plane_c["backend"] = backend
    payload["planes"] = [payload["planes"][0], plane_c]
    return payload


def test_status_names_the_kernel_sensor_and_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = {
        "kind": "tetragon", "version": "1.7.1", "mode": "enforce", "events_lost": 0, "loss_known": True,
        "kernel_floor": {
            "mode": "enforce", "enforced_users": 2, "enrolled_users": 3, "burn_in_users": 1,
            "paused_until": "14:05",
        },
    }
    client = _StubClient(_snapshot_with_plane_c(backend))
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "kernel sensor: Tetragon 1.7.1, enforce, 0 events lost" in result.output
    assert "kernel floor: enforce for 2 of 3 users (1 in burn-in); paused until 14:05" in result.output

    as_json = _invoke("status", "--json")
    planes = json.loads(as_json.output)["planes"]
    assert planes[1]["backend"] == backend


def test_status_says_why_tetragon_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    fallback = {"kind": "native", "fallback_reason": "tetragon_tcp_api", "loss_known": False}
    client = _StubClient(_snapshot_with_plane_c(fallback))
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "kernel sensor: cn_proc and fanotify (Tetragon not used: tetragon_tcp_api)" in result.output
    assert "kernel floor" not in result.output


def test_status_without_a_backend_prints_no_kernel_line(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every gateway but the managed Linux sensor helper's omits the field.
    client = _StubClient(_snapshot_with_plane_c(None))
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "kernel sensor" not in result.output
    assert "agent actions: running via Tetragon" in result.output


def test_kernel_sensor_summary_never_claims_unknown_loss_is_zero() -> None:
    assert cmd_agent.kernel_sensor_summary({"kind": "tetragon", "version": "1.7.1", "mode": "consume"}) == (
        "Tetragon 1.7.1, consume, events lost unknown"
    )
    assert cmd_agent.kernel_sensor_summary(
        {"kind": "tetragon", "mode": "observe", "events_lost": 12, "loss_known": True}
    ) == "Tetragon, observe, 12 events lost"


def test_status_marks_a_limited_running_plane_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-1377: a non-elevated Windows gateway runs Plane B on its own sockets
    # only; status and findings must not print a plain "running".
    payload = dict(_DEGRADED_SNAPSHOT)
    payload["planes"] = [
        {"plane": "b", "name": "shadow egress", "available": True, "running": True,
         "mechanism": "GetExtendedTcpTable and GetExtendedUdpTable",
         "reason": "egress attribution is limited to this process's own sockets; "
                   "run the gateway elevated for machine-wide coverage"},
    ]
    client = _StubClient(payload)
    monkeypatch.setattr(cmd_agent, "_usage_client", lambda *a, **k: client)
    result = _invoke("findings")
    assert result.exit_code == 0, result.output
    assert "shadow egress: partial, running via GetExtendedTcpTable" in result.output
    assert "limited to this process's own sockets" in result.output
