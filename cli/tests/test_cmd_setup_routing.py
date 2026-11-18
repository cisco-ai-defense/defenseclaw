# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host


@pytest.fixture
def routing_app():
    app, tmp_dir, db_path = make_app_context()
    saved: list[bool] = []
    app.cfg.save = lambda: saved.append(True)  # type: ignore[method-assign]
    # The rows below are the supported-host behaviour; the native Windows
    # refusal (GAP-2260) has its own rows that patch this to True.
    try:
        with patch("defenseclaw.commands.cmd_setup._routing_unsupported_on_host", return_value=False):
            yield app, saved
    finally:
        cleanup_app(app, db_path, tmp_dir)


def _local_model() -> dict[str, object]:
    return {
        "name": "fast",
        "provider": "ollama",
        "model": "qwen2.5:0.5b",
        "base_url": "http://127.0.0.1:11434",
    }


def test_routing_enable_requires_a_model_before_saving(routing_app) -> None:
    app, saved = routing_app
    result = CliRunner().invoke(setup, ["routing", "--enable"], obj=app)
    assert result.exit_code != 0
    assert "routing.models must contain at least one backend" in result.output
    assert saved == []


def test_managed_routing_requires_running_docker_before_saving(routing_app) -> None:
    app, saved = routing_app
    app.cfg.routing.models = [_local_model()]
    with (
        patch("defenseclaw.commands.cmd_setup.shutil.which", return_value="/usr/local/bin/docker"),
        patch(
            "defenseclaw.commands.cmd_setup.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout="", stderr="daemon unavailable"),
        ),
    ):
        result = CliRunner().invoke(setup, ["routing", "--enable"], obj=app)
    assert result.exit_code != 0
    assert "Docker is required for managed routing but is not running" in result.output
    assert saved == []


def test_remote_routing_skips_docker_and_reports_restart(routing_app) -> None:
    app, saved = routing_app
    app.cfg.routing.models = [_local_model()]
    app.cfg.routing.remote = {"endpoint": "https://router.example.test"}
    with (
        patch("defenseclaw.commands.cmd_setup.subprocess.run") as run,
        patch("defenseclaw.commands.cmd_setup._log_setup_action"),
    ):
        result = CliRunner().invoke(setup, ["routing", "--enable"], obj=app)
    assert result.exit_code == 0, result.output
    run.assert_not_called()
    assert saved == [True]
    assert "Mode:       remote" in result.output
    assert "gateway restart required" in result.output
    assert "/v1/chat/completions" not in result.output


def test_routing_status_separates_config_and_runtime(routing_app) -> None:
    app, _ = routing_app
    app.cfg.routing.enabled = True
    app.cfg.routing.models = [_local_model()]
    with patch("defenseclaw.commands.cmd_setup._routing_health_status", return_value="healthy"):
        result = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
    assert result.exit_code == 0, result.output
    assert "Configured: enabled" in result.output
    assert "Mode:       managed Docker" in result.output
    assert "Runtime:    healthy" in result.output
    assert "proxy-mode OpenAI chat-completions traffic" in result.output


def test_gap1252_rules_classifier_status_reports_in_process_gateway_state(routing_app) -> None:
    # rel-1-0-10 GAP-1252: with routing.classifier rules, --status printed
    # managed Docker, a Router API and "Runtime: unreachable" from a vLLM
    # router /health probe although routing runs inside the gateway.
    app, _ = routing_app
    app.cfg.routing.enabled = True
    app.cfg.routing.classifier = "rules"
    app.cfg.routing.models = [_local_model()]
    with (
        patch(
            "defenseclaw.commands.cmd_setup._routing_health_status",
            return_value="unreachable (gateway may need restart)",
        ),
        patch("defenseclaw.commands.cmd_routing._health_routing", return_value={"state": "running"}),
    ):
        result = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
    assert result.exit_code == 0, result.output
    assert "Classifier: rules (in process" in result.output
    assert "Runtime:    running" in result.output
    for stale in ("Docker", "Router API", "Version:", "unreachable"):
        assert stale not in result.output, result.output


def test_gap1252_rules_classifier_status_names_gateway_errors(routing_app) -> None:
    app, _ = routing_app
    app.cfg.routing.enabled = True
    app.cfg.routing.classifier = "rules"
    app.cfg.routing.models = [_local_model()]
    with patch(
        "defenseclaw.commands.cmd_routing._health_routing",
        return_value={"state": "error", "last_error": "routing.models[0] unknown provider"},
    ):
        failed = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
    with patch("defenseclaw.commands.cmd_routing._health_routing", return_value={"state": "unreachable"}):
        down = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
    assert "Runtime:    error: routing.models[0] unknown provider" in failed.output
    assert "Runtime:    gateway not reachable" in down.output


def test_routing_on_native_windows_says_unsupported_and_refuses_enable(routing_app) -> None:
    # rel-1-0-4 GAP-2260: the page says native Windows is not supported, but
    # --status offered --enable and --enable failed only on models or Docker.
    app, saved = routing_app
    app.cfg.routing.models = [_local_model()]
    app.cfg.routing.remote = {"endpoint": "https://router.example.test"}
    with patch("defenseclaw.commands.cmd_setup._routing_unsupported_on_host", return_value=True):
        status = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
        enable = CliRunner().invoke(setup, ["routing", "--enable"], obj=app)
    assert status.exit_code == 0, status.output
    assert "Semantic routing is not supported on native Windows" in status.output
    assert "Enable with" not in status.output
    assert enable.exit_code != 0
    assert "Semantic routing is not supported on native Windows" in enable.output
    assert saved == []
    assert app.cfg.routing.enabled is False


def test_routing_disable_still_works_on_native_windows(routing_app) -> None:
    app, saved = routing_app
    app.cfg.routing.enabled = True
    with (
        patch("defenseclaw.commands.cmd_setup._routing_unsupported_on_host", return_value=True),
        patch("defenseclaw.commands.cmd_setup._log_setup_action"),
    ):
        status = CliRunner().invoke(setup, ["routing", "--status"], obj=app)
        result = CliRunner().invoke(setup, ["routing", "--disable"], obj=app)
    assert "Turn it off with: defenseclaw setup routing --disable" in status.output
    assert result.exit_code == 0, result.output
    assert app.cfg.routing.enabled is False
    assert saved == [True]
