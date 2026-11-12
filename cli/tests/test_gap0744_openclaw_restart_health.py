# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0744: setup decides whether OpenClaw runs from its health probe.

``openclaw gateway restart`` needs a service manager (launchd GUI domain,
systemd --user, a Windows service). On an account without one it exits non-zero
while a gateway started with ``openclaw gateway run`` keeps answering. Setup
must keep the new configuration then, and still roll back when the gateway
really is down.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click import ClickException
from defenseclaw.commands import cmd_setup


def _run(tmp_path, *, restart_ok: bool, answers: bool) -> str:
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=restart_ok) as restart,
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=answers) as check,
        contextlib.redirect_stdout(buf),
    ):
        try:
            cmd_setup._restart_services(str(tmp_path), connector="openclaw")
        finally:
            restart.assert_called_once()
            check.assert_called_once()
    return buf.getvalue()


def test_failed_service_restart_with_answering_gateway_keeps_the_config(tmp_path) -> None:
    text = _run(tmp_path, restart_ok=False, answers=True)
    assert "could not restart its gateway through a service manager" in text
    assert "the new configuration is kept" in text
    assert "openclaw gateway run" in text


def test_service_restart_ok_with_answering_gateway_prints_no_note(tmp_path) -> None:
    text = _run(tmp_path, restart_ok=True, answers=True)
    assert "service manager" not in text
    assert "configuration is kept" not in text


@pytest.mark.parametrize("restart_ok", [False, True])
def test_gateway_that_does_not_answer_still_fails_and_rolls_back(tmp_path, restart_ok: bool) -> None:
    with pytest.raises(cmd_setup._OpenClawGatewayNotRunning):
        _run(tmp_path, restart_ok=restart_ok, answers=False)


def test_restart_command_failing_on_a_missing_service_manager_is_not_a_gateway_failure(tmp_path) -> None:
    """End to end through the real restart helper: the launchd GUI-domain failure."""
    failed = subprocess.CompletedProcess(
        ["openclaw"],
        1,
        stdout="",
        stderr="Gateway service check failed: ServiceInspectionError: The launchd GUI domain is unavailable for this account.\n",
    )
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup.subprocess, "run", return_value=failed),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=True),
        contextlib.redirect_stdout(buf),
    ):
        cmd_setup._restart_services(str(tmp_path), connector="openclaw")
    assert "the new configuration is kept" in buf.getvalue()


def test_defenseclaw_gateway_failure_still_fails_even_when_openclaw_answers(tmp_path) -> None:
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=False),
        patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=True),
        contextlib.redirect_stdout(buf),
        pytest.raises(ClickException),
    ):
        cmd_setup._restart_services(str(tmp_path), connector="openclaw")
    # The setup rolls back here, so it must not claim the configuration is kept.
    assert "configuration is kept" not in buf.getvalue()


_UNRUNNABLE = [
    PermissionError(13, "Permission denied"),
    OSError(8, "Exec format error"),
    FileNotFoundError(2, "No such file or directory"),
]


@pytest.mark.parametrize("exc", _UNRUNNABLE, ids=lambda e: type(e).__name__ + str(e.errno))
def test_openclaw_cli_that_cannot_run_is_decided_by_the_health_probe(tmp_path, exc: OSError) -> None:
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup.subprocess, "run", side_effect=exc),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=True) as check,
        contextlib.redirect_stdout(buf),
    ):
        cmd_setup._restart_services(str(tmp_path), connector="openclaw")
    check.assert_called_once()
    assert "the new configuration is kept" in buf.getvalue()


@pytest.mark.parametrize("exc", _UNRUNNABLE, ids=lambda e: type(e).__name__ + str(e.errno))
def test_openclaw_cli_that_cannot_run_with_a_down_gateway_still_rolls_back(tmp_path, exc: OSError) -> None:
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup.subprocess, "run", side_effect=exc),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=False) as check,
        contextlib.redirect_stdout(buf),
        pytest.raises(cmd_setup._OpenClawGatewayNotRunning),
    ):
        cmd_setup._restart_services(str(tmp_path), connector="openclaw")
    check.assert_called_once()
    assert "configuration is kept" not in buf.getvalue()


def _rollback_app(root) -> SimpleNamespace:
    cfg = SimpleNamespace(
        data_dir=str(root),
        gateway=SimpleNamespace(host="127.0.0.1", port=18789),
        active_connector=lambda: "openclaw",
        active_connectors=lambda: ["openclaw"],
    )
    return SimpleNamespace(cfg=cfg)


def test_rollback_restart_does_not_claim_the_new_configuration_is_kept(tmp_path) -> None:
    """The rollback caller restarts on the restored config; the attempted one is gone."""
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=True),
        contextlib.redirect_stdout(buf),
    ):
        cmd_setup._restart_restored_connector_runtime(
            _rollback_app(tmp_path),
            same_failure=cmd_setup._GatewayRestartFailed("defenseclaw-gateway restart failed"),
        )
    text = buf.getvalue()
    assert cmd_setup._ROLLBACK_RESTART_TITLE in text
    assert "the new configuration is kept" not in text
    assert "the previous configuration stays in place" in text


def test_rollback_restart_without_captured_failure_does_not_claim_the_new_configuration(tmp_path) -> None:
    buf = io.StringIO()
    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=True),
        contextlib.redirect_stdout(buf),
    ):
        cmd_setup._restart_restored_connector_runtime(_rollback_app(tmp_path))
    assert "the new configuration is kept" not in buf.getvalue()


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX shell script as the openclaw CLI")
@pytest.mark.parametrize("answers", [True, False])
def test_undecodable_openclaw_cli_output_is_decided_by_the_health_probe(tmp_path, answers: bool) -> None:
    cli = tmp_path / "openclaw"
    cli.write_bytes(b'#!/bin/sh\nprintf "\\377" 1>&2\nexit 1\n')
    cli.chmod(0o755)
    buf = io.StringIO()
    with (
        patch.dict(os.environ, {"PATH": str(tmp_path)}),
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_check_openclaw_gateway", return_value=answers) as check,
        contextlib.redirect_stdout(buf),
    ):
        if answers:
            cmd_setup._restart_services(str(tmp_path), connector="openclaw")
        else:
            with pytest.raises(cmd_setup._OpenClawGatewayNotRunning):
                cmd_setup._restart_services(str(tmp_path), connector="openclaw")
    check.assert_called_once()
    assert ("the new configuration is kept" in buf.getvalue()) is answers
