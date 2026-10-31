# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""OpenCode V2's background server is restarted when DefenseClaw changes its plugin (rel-1-0-6 GAP-0026)."""

import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw import opencode_service

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell fake; Windows keeps the documented command")


def _fake_opencode(tmp_path, state):
    """An `opencode service status|restart` that keeps its state in a file."""
    log = tmp_path / "calls"
    (tmp_path / "state").write_text(state)
    binary = tmp_path / "opencode"
    binary.write_text(
        "#!/bin/sh\n"
        f"echo \"$*\" >> {log}\n"
        f"state=$(cat {tmp_path / 'state'})\n"
        "case \"$2\" in\n"
        "  status) [ \"$state\" = broken ] && exit 3; [ \"$state\" = running ] && echo http://127.0.0.1:19798 || echo stopped ;;\n"
        f"  restart) echo restarted > {tmp_path / 'state'}; echo http://127.0.0.1:19798 ;;\n"
        "esac\n"
    )
    binary.chmod(0o755)
    return str(binary), log


@pytest.mark.parametrize(
    ("state", "outcome", "calls"),
    [
        ("running", opencode_service.RESTARTED, ["service status", "service restart"]),
        ("stopped", "", ["service status"]),
        ("broken", opencode_service.NOT_RESTARTED, ["service status"]),
    ],
)
def test_restart_if_running(tmp_path, state, outcome, calls):
    binary, log = _fake_opencode(tmp_path, state)
    assert opencode_service.restart_if_running(binary) == outcome
    assert log.read_text().split("\n")[:-1] == calls
    assert opencode_service.restart_if_running("") == ""


@pytest.mark.parametrize(("version", "found"), [("opencode v2.2.5", True), ("1.18.34", False), ("", False)])
def test_account_binary_is_only_an_opencode_v2(monkeypatch, version, found):
    from defenseclaw.inventory import agent_discovery

    def discover(connectors, **kwargs):
        assert kwargs["persist_cache"] is False and kwargs["use_cache"] is False
        signal = SimpleNamespace(installed=True, version=version, binary_path="/u/.npm-global/bin/opencode")
        return SimpleNamespace(agents={"opencode": signal})

    monkeypatch.setattr(agent_discovery, "discover_with_probes", discover)
    assert opencode_service.account_binary() == ("/u/.npm-global/bin/opencode" if found else "")
    monkeypatch.setattr(opencode_service.os, "name", "nt")
    assert opencode_service.account_binary() == ""


def test_uninstall_restarts_the_running_background_server_and_says_so(monkeypatch):
    from defenseclaw.commands import cmd_uninstall

    order = []
    plan = SimpleNamespace(connectors=("opencode",))
    monkeypatch.setattr(cmd_uninstall, "_dispatch_native_windows_uninstall", lambda **kwargs: False)
    monkeypatch.setattr(cmd_uninstall, "_build_plan", lambda **kwargs: plan)
    monkeypatch.setattr(cmd_uninstall, "_with_listed_sandboxes", lambda plan, stop: plan)
    monkeypatch.setattr(cmd_uninstall, "_render_plan", lambda plan, dry_run: None)
    monkeypatch.setattr(cmd_uninstall, "_refuse_running_sandboxes", lambda plan: None)
    monkeypatch.setattr(cmd_uninstall, "_execute_plan", lambda plan: order.append("teardown"))
    monkeypatch.setattr(cmd_uninstall, "_remove_marked_native_otel_left", lambda: None)
    monkeypatch.setattr(cmd_uninstall, "_render_kept_and_next_steps", lambda plan: None)
    monkeypatch.setattr(opencode_service, "account_binary", lambda data_dir=None: order.append("probe") or "/u/bin/opencode")
    monkeypatch.setattr(
        opencode_service, "restart_if_running", lambda binary: order.append(f"restart {binary}") or opencode_service.RESTARTED
    )

    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    assert order == ["probe", "teardown", "restart /u/bin/opencode"]  # found before --binaries removes the CLI
    text = " ".join(result.output.split())
    assert "Restarted OpenCode's background server (opencode service restart), so it drops the DefenseClaw plugin" in text

    monkeypatch.setattr(opencode_service, "restart_if_running", lambda binary: opencode_service.NOT_RESTARTED)
    text = " ".join(CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"]).output.split())
    assert "run 'opencode service restart'" in text

    order.clear()
    plan.connectors = ("codex",)
    CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert order == ["teardown"]
