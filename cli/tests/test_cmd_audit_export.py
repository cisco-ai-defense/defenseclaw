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
    assert "defenseclaw-gateway is not installed" in result.output
    assert "Traceback" not in result.output
