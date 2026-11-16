# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A refused local Splunk setup is a failure in scripts and at a terminal."""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup

from tests.test_setup_refresh_bundle_wiring import _make_app


@pytest.mark.parametrize("flags", [[], ["--non-interactive"]])
@pytest.mark.parametrize(
    "reason, detail",
    [
        ("docker_not_installed", "Docker is not installed"),
        ("docker_daemon_not_running", "Docker daemon is not running"),
        ("port_8000_in_use", "port 8000 is already in use"),
        ("port_8088_in_use", "port 8088 is already in use"),
    ],
)
def test_explicit_local_setup_refuses_each_failed_prerequisite(flags, reason, detail):
    app, _ = _make_app()
    config_path = Path(app.cfg.data_dir) / "config.yaml"
    before = config_path.read_bytes()
    try:
        with (
            patch("defenseclaw.commands.cmd_setup._native_windows_local_splunk", return_value=False),
            patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=(False, reason)),
            patch("defenseclaw.commands.cmd_setup._apply_logs_config") as apply,
        ):
            result = CliRunner().invoke(setup, ["splunk", "--logs", "--accept-splunk-license", *flags], obj=app)
        assert result.exit_code == 1, result.output
        assert detail in result.output
        assert config_path.read_bytes() == before
        assert not (config_path.parent / ".env").exists()
        apply.assert_not_called()
    finally:
        shutil.rmtree(app.cfg.data_dir)


def test_wizard_docker_failure_is_not_reported_as_cancellation():
    app, _ = _make_app()
    try:
        with (
            patch("defenseclaw.commands.cmd_setup._native_windows_local_splunk", return_value=False),
            patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=(False, "docker_not_installed")),
            patch("defenseclaw.commands.cmd_setup._accept_splunk_license_interactive", return_value=True),
            patch("defenseclaw.commands.cmd_setup._apply_logs_config") as apply,
        ):
            result = CliRunner().invoke(setup, ["splunk"], obj=app, input="n\ny\nn\n")
        assert result.exit_code == 1, result.output
        assert "Docker is not installed" in result.output
        assert "No Splunk pipelines enabled" not in result.output
        apply.assert_not_called()
    finally:
        shutil.rmtree(app.cfg.data_dir)


def test_actual_missing_docker_preflight_returns_nonzero():
    app, _ = _make_app()
    try:
        with (
            patch("defenseclaw.commands.cmd_setup._native_windows_local_splunk", return_value=False),
            patch("defenseclaw.commands.cmd_setup.shutil.which", return_value=None),
        ):
            result = CliRunner().invoke(setup, ["splunk", "--logs", "--accept-splunk-license"], obj=app)
        assert "Docker installed... NOT FOUND" in result.output
        assert result.exit_code == 1, result.output
    finally:
        shutil.rmtree(app.cfg.data_dir)


def test_docker_socket_permission_denied_is_not_reported_as_a_stopped_daemon():
    app, _ = _make_app()
    denied = subprocess.CompletedProcess(
        ["docker", "info"],
        1,
        "",
        "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock\n",
    )
    try:
        with (
            patch("defenseclaw.commands.cmd_setup._native_windows_local_splunk", return_value=False),
            patch("defenseclaw.commands.cmd_setup.shutil.which", return_value="/usr/bin/docker"),
            patch("defenseclaw.commands.cmd_setup.subprocess.run", return_value=denied),
            patch("defenseclaw.platform_support.host_os", return_value="linux"),
        ):
            result = CliRunner().invoke(setup, ["splunk", "--logs", "--accept-splunk-license"], obj=app)
        assert result.exit_code == 1, result.output
        assert "cannot use the Docker daemon socket (permission denied)" in result.output
        assert "docker group" in result.output
        assert "NOT RUNNING" not in result.output
        assert "Docker daemon is not running" not in result.output
    finally:
        shutil.rmtree(app.cfg.data_dir)
