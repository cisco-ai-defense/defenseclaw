# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw audit export` runs `defenseclaw-gateway audit export` (SWEEP-6)."""

from __future__ import annotations

import subprocess
import sys

import pytest
from click.testing import CliRunner
from defenseclaw import main as main_module
from defenseclaw.commands import cmd_audit

GATEWAY = "/opt/dc/defenseclaw-gateway"


@pytest.fixture
def exec_capture(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setenv("DEFENSECLAW_DELEGATED_FROM", "")  # run_gateway sets it; undo removes it
    monkeypatch.setattr(cmd_audit, "_execv", lambda path, argv: calls.append([path, *argv]))
    monkeypatch.setattr("defenseclaw.gateway.resolve_trusted_gateway_binary", lambda: GATEWAY)
    monkeypatch.setattr(cmd_audit.os, "name", "posix")

    def no_config(*_args, **_kwargs):
        raise AssertionError("audit export loaded the CLI config or audit store")

    monkeypatch.setattr("defenseclaw.config.require_v8_config", no_config)
    monkeypatch.setattr("defenseclaw.config.load", no_config)
    return calls


@pytest.mark.parametrize(
    "args",
    [
        ["--connector", "claudecode", "--limit", "5", "--newest", "-o", "-"],
        ["--help"],
    ],
)
def test_alias_execs_the_gateway_export_without_loading_config(
    exec_capture: list[list[str]], monkeypatch: pytest.MonkeyPatch, args: list[str]
) -> None:
    argv = ["audit", "export", *args]
    monkeypatch.setattr(sys, "argv", ["defenseclaw", *argv])
    result = CliRunner().invoke(main_module.cli, argv, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert exec_capture == [[GATEWAY, GATEWAY, "audit", "export", *args]]


def test_windows_waits_for_the_gateway_and_keeps_its_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.gateway.resolve_trusted_gateway_binary", lambda: GATEWAY)
    monkeypatch.setattr(cmd_audit.os, "name", "nt")
    monkeypatch.setenv("DEFENSECLAW_DELEGATED_FROM", "")
    monkeypatch.setattr(cmd_audit, "_execv", lambda *_: pytest.fail("exec on Windows"))
    calls: list[list[str]] = []

    def fake_run(argv: list[str], check: bool) -> subprocess.CompletedProcess:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 3)

    monkeypatch.setattr(cmd_audit, "_run", fake_run)
    result = CliRunner().invoke(cmd_audit.audit, ["export", "--since", "30m"])
    assert result.exit_code == 3
    assert calls == [[GATEWAY, "audit", "export", "--since", "30m"]]


def test_a_missing_gateway_binary_is_a_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("defenseclaw.gateway.resolve_trusted_gateway_binary", lambda: None)
    result = CliRunner().invoke(cmd_audit.audit, ["export"])
    assert result.exit_code == 1
    assert "defenseclaw-gateway was not found on PATH, next to this defenseclaw or in ~/.local/bin" in result.output
    assert "Traceback" not in result.output


def test_findings_alias_execs_the_gateway_findings_without_loading_config(
    exec_capture: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["audit", "findings", "--scanner", "skill", "--limit", "5"]
    monkeypatch.setattr(sys, "argv", ["defenseclaw", *argv])
    result = CliRunner().invoke(main_module.cli, argv, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert exec_capture == [[GATEWAY, GATEWAY, *argv]]


def test_audit_help_names_findings_and_logs() -> None:
    result = CliRunner().invoke(cmd_audit.audit, ["--help"])
    assert result.exit_code == 0
    assert "findings" in result.output
    assert "logs" in result.output


def _logs_app(tmp_path):
    from types import SimpleNamespace

    from defenseclaw.context import AppContext

    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def test_logs_prints_the_newest_matching_lines(tmp_path) -> None:
    (tmp_path / "gateway.log").write_text(
        "".join(f"line {i} {'hook' if i % 2 else 'other'}\n" for i in range(10)),
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        cmd_audit.audit, ["logs", "-n", "2", "--grep", "HOOK"], obj=_logs_app(tmp_path)
    )
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == ["line 7 hook", "line 9 hook"]


def test_logs_without_a_log_file_says_what_to_do(tmp_path) -> None:
    result = CliRunner().invoke(cmd_audit.audit, ["logs", "--source", "watchdog"], obj=_logs_app(tmp_path))
    assert result.exit_code == 1
    assert "no watchdog log yet" in result.output
    assert "Traceback" not in result.output


def test_logs_grep_without_a_match_says_so(tmp_path) -> None:
    # GAP-1494: a --grep with no match must not be silent.
    (tmp_path / "gateway.log").write_text("line 1\nline 2\n", encoding="utf-8")
    result = CliRunner().invoke(
        cmd_audit.audit, ["logs", "--grep", "nosuchtext-zz"], obj=_logs_app(tmp_path)
    )
    assert result.exit_code == 0, result.output
    assert "No gateway log lines match 'nosuchtext-zz'" in result.output


def test_gateway_is_told_the_typed_command(exec_capture: list[list[str]], monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-1644: the gateway's usage errors name "defenseclaw audit findings".
    CliRunner().invoke(cmd_audit.audit, ["findings", "--bogus"])
    assert exec_capture == [[GATEWAY, GATEWAY, "audit", "findings", "--bogus"]]
    assert cmd_audit.os.environ["DEFENSECLAW_DELEGATED_FROM"] == "defenseclaw"
