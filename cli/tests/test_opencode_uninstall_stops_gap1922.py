# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-1922: uninstall --all / --binaries stops OpenCode's background server.

The uninstall restarted the server so it dropped the DefenseClaw plugin. The
restarted server then kept running, and the next DefenseClaw install refused
to start ("Close OpenCode and Amp completely") until it was stopped by hand.
Lead ruling (07:50Z, owner confirm list): `uninstall --all` and `--binaries`
stop it (`opencode service stop`) and say so in one line; a plain uninstall,
which keeps DefenseClaw installed, keeps the restart.
"""

import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw import opencode_service

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell fake; Windows keeps the documented command")


def _fake_opencode(tmp_path, state):
    log = tmp_path / "calls"
    (tmp_path / "state").write_text(state)
    binary = tmp_path / "opencode"
    binary.write_text(
        "#!/bin/sh\n"
        f"echo \"$*\" >> {log}\n"
        f"state=$(cat {tmp_path / 'state'})\n"
        "case \"$2\" in\n"
        "  status) [ \"$state\" = broken ] && exit 3; [ \"$state\" = running ] && echo http://127.0.0.1:19798 || echo stopped ;;\n"
        f"  stop) [ \"$state\" = stuck ] && exit 4; echo stopped > {tmp_path / 'state'} ;;\n"
        "esac\n"
    )
    binary.chmod(0o755)
    return str(binary), log


@pytest.mark.parametrize(
    ("state", "outcome", "calls"),
    [
        ("running", "stopped", ["service status", "service stop"]),
        ("stopped", "", ["service status"]),
        ("broken", "not-stopped", ["service status"]),
    ],
)
def test_stop_if_running(tmp_path, state, outcome, calls):
    binary, log = _fake_opencode(tmp_path, state)
    assert opencode_service.stop_if_running(binary) == outcome
    assert log.read_text().split("\n")[:-1] == calls
    assert opencode_service.stop_if_running("") == ""


def _patched_uninstall(monkeypatch, order):
    from defenseclaw.commands import cmd_uninstall

    plan = SimpleNamespace(connectors=("opencode",), data_dir="", legacy_setup=None)
    monkeypatch.setattr(cmd_uninstall, "_build_plan", lambda **kwargs: plan)
    monkeypatch.setattr(cmd_uninstall, "_with_listed_sandboxes", lambda plan, stop: plan)
    monkeypatch.setattr(cmd_uninstall, "_render_plan", lambda plan, dry_run: None)
    monkeypatch.setattr(cmd_uninstall, "_refuse_running_sandboxes", lambda plan: None)
    monkeypatch.setattr(cmd_uninstall, "_execute_plan", lambda plan: order.append("teardown") or cmd_uninstall.ExecutionResult(()))
    monkeypatch.setattr(cmd_uninstall, "_remove_marked_native_otel_left", lambda gateway_ports=frozenset(): None)
    monkeypatch.setattr(cmd_uninstall, "_render_kept_and_next_steps", lambda plan: None)
    monkeypatch.setattr(opencode_service, "account_binary", lambda data_dir=None: "/u/bin/opencode")
    monkeypatch.setattr(opencode_service, "restart_if_running", lambda binary: order.append("restart") or opencode_service.RESTARTED)
    monkeypatch.setattr(opencode_service, "stop_if_running", lambda binary: order.append("stop") or "stopped", raising=False)
    return cmd_uninstall


@pytest.mark.parametrize("args", [["--all"], ["--binaries"], ["--all", "--binaries"]])
def test_a_full_uninstall_stops_the_background_server_and_says_so(monkeypatch, args):
    order = []
    cmd_uninstall = _patched_uninstall(monkeypatch, order)
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, [*args, "--yes"])
    assert result.exit_code == 0, result.output
    assert order == ["teardown", "stop"]
    text = " ".join(result.output.split())
    assert "Stopped OpenCode's background server (opencode service stop)" in text
    assert "Restarted OpenCode" not in text


def test_a_plain_uninstall_keeps_the_restart(monkeypatch):
    order = []
    cmd_uninstall = _patched_uninstall(monkeypatch, order)
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--yes"])
    assert result.exit_code == 0, result.output
    assert order == ["teardown", "restart"]


def test_a_failed_stop_names_the_command_before_the_next_install(monkeypatch):
    order = []
    cmd_uninstall = _patched_uninstall(monkeypatch, order)
    monkeypatch.setattr(opencode_service, "stop_if_running", lambda binary: "not-stopped", raising=False)
    text = " ".join(CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--yes"]).output.split())
    assert "run 'opencode service stop' before you install DefenseClaw again" in text
