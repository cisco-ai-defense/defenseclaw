# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Remediation regression tests for Avarice findings in the setup / init
gateway lifecycle.

One focused test per finding, each asserting the *fixed* (fail-closed)
behavior so a regression to the original vulnerable code re-fails the test:

* F-0101 / F-0121 — gateway PID identity must match the gateway binary name
  exactly (no generic ``defenseclaw`` prefix acceptance).
* F-0721 — a spoofed ``gateway.pid`` pointing at a live but unrelated process
  must not be treated as the running gateway.
* F-0142 / F-0143 — a failed gateway restart must propagate (fail closed),
  not be swallowed.
* F-0122 — first-run init must create operator-private directories 0700.

The legacy sandbox findings (F-0161, F-0162, F-0166, F-0421, F-0425) are
covered against ``defenseclaw sandbox legacy-cleanup`` in
``test_sandbox_legacy.py``.
"""

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import click
from click.testing import CliRunner

from tests.permissions import assert_owner_only_directory


class TestGatewayPidIdentity(unittest.TestCase):
    """F-0101 / F-0121 / F-0721: gateway PID identity must be an *exact*
    binary-name match and must fail closed for foreign processes."""

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0101_bootstrap_rejects_lookalike_name(self, mock_argv0):
        from defenseclaw.bootstrap import _pid_looks_like_gateway

        # The original bug accepted any argv0 starting with "defenseclaw".
        mock_argv0.return_value = "defenseclaw-not-gateway"
        self.assertFalse(_pid_looks_like_gateway(4242))

        # The real gateway binary name is still accepted.
        mock_argv0.return_value = "defenseclaw-gateway"
        self.assertTrue(_pid_looks_like_gateway(4242))

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0121_init_rejects_lookalike_name(self, mock_argv0):
        from defenseclaw.commands.cmd_init import _pid_looks_like_gateway

        mock_argv0.return_value = "defenseclaw-not-gateway"
        self.assertFalse(_pid_looks_like_gateway(4242))

        mock_argv0.return_value = "defenseclaw-gateway"
        self.assertTrue(_pid_looks_like_gateway(4242))

    @patch("defenseclaw.process_liveness.process_argv0_basename")
    def test_f0721_spoofed_pidfile_foreign_process_rejected(self, mock_argv0):
        from defenseclaw.commands.cmd_setup import (
            _gateway_pid_file_identifies_gateway,
        )
        from defenseclaw.process_liveness import process_is_gateway

        # A spoofed gateway.pid points at a live but unrelated process.
        mock_argv0.return_value = "sleep"
        self.assertFalse(process_is_gateway(1234))

        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "gateway.pid")
            with open(pid_file, "w") as fh:
                fh.write("1234")
            self.assertFalse(_gateway_pid_file_identifies_gateway(pid_file))

            # Same PID, but now it really is the gateway → accepted.
            mock_argv0.return_value = "defenseclaw-gateway"
            self.assertTrue(_gateway_pid_file_identifies_gateway(pid_file))


class TestRestartFailsClosed(unittest.TestCase):
    """F-0142 / F-0143: restart failures must propagate, not be swallowed."""

    @patch("defenseclaw.commands.cmd_setup._gateway_lifecycle_executable", return_value=None)
    def test_f0142_restart_defense_gateway_returns_false_on_failure(self, _mock_exe):
        # Patch the binary lookup, not subprocess.run: the start path runs the
        # pinned executable directly, so the old patch let a real gateway start.
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway

        with tempfile.TemporaryDirectory() as tmp:
            # No gateway.pid → start path; binary missing → must report failure
            # (the original code returned None and callers read it as success).
            self.assertIs(_restart_defense_gateway(tmp), False)

    def test_f0143_restart_services_fails_closed_when_gateway_down(self):
        from defenseclaw.commands import cmd_setup

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cmd_setup, "_restart_defense_gateway", return_value=False), \
                 patch.object(cmd_setup, "_restart_openclaw_gateway", return_value=False) as mock_oc, \
                 patch.object(cmd_setup, "_check_openclaw_gateway"):
                with self.assertRaises(click.ClickException):
                    cmd_setup._restart_services(tmp, connector="openclaw")
                # The OpenClaw gateway restart helper must also have been
                # consulted (F-0143) and reported failure.
                mock_oc.assert_called_once()

    @patch("defenseclaw.commands.cmd_setup.subprocess.run", side_effect=FileNotFoundError)
    def test_f0143_restart_openclaw_gateway_returns_false_on_failure(self, _mock_run):
        from defenseclaw.commands.cmd_setup import _restart_openclaw_gateway

        self.assertIs(_restart_openclaw_gateway(), False)

    @patch(
        "defenseclaw.commands.cmd_setup.subprocess.run",
        side_effect=subprocess.TimeoutExpired("openclaw", 60),
    )
    def test_f0143_restart_openclaw_gateway_returns_false_on_timeout(self, _mock_run):
        from defenseclaw.commands.cmd_setup import _restart_openclaw_gateway

        self.assertIs(_restart_openclaw_gateway(), False)

    def test_gap1408_openclaw_service_not_loaded_is_not_a_restart(self):
        import contextlib
        import io

        from defenseclaw.commands.cmd_setup import _restart_openclaw_gateway

        done = subprocess.CompletedProcess(
            ["openclaw"], 0, stdout="Gateway service not loaded. Start with: openclaw gateway install\n", stderr=""
        )
        with patch("defenseclaw.commands.cmd_setup.subprocess.run", return_value=done):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertIs(_restart_openclaw_gateway(), True)
            text = buf.getvalue()
        self.assertNotIn("✓", text)
        self.assertIn("no OpenClaw gateway service", text)

    def test_gap1470_rollback_to_empty_roster_skips_openclaw(self):
        from types import SimpleNamespace

        from defenseclaw.commands import cmd_setup

        cfg = SimpleNamespace(
            data_dir="/nonexistent",
            gateway=SimpleNamespace(host="127.0.0.1", port=18789),
            active_connectors=lambda: [],
            active_connector=lambda: "openclaw",
        )
        with patch.object(cmd_setup, "_restart_services") as restart:
            cmd_setup._restart_restored_connector_runtime(SimpleNamespace(cfg=cfg))
        self.assertEqual(restart.call_args.kwargs["connector"], "")


class TestInitDirPermissions(unittest.TestCase):
    """F-0122: first-run init must create operator-private dirs 0700."""

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_f0122_data_dirs_are_0700(
        self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which
    ):
        from pathlib import Path

        from defenseclaw.commands.cmd_init import init_cmd
        from defenseclaw.context import AppContext

        with tempfile.TemporaryDirectory() as tmp:
            mock_path.return_value = Path(tmp)
            # A permissive umask is the dangerous case: bare os.makedirs would
            # leave these 0755 (world-readable audit state).
            old_umask = os.umask(0o022)
            try:
                result = CliRunner().invoke(
                    init_cmd, ["--skip-install"], obj=AppContext()
                )
            finally:
                os.umask(old_umask)

            self.assertEqual(result.exit_code, 0, result.output)

            for sub in ("quarantine", "plugins"):
                path = os.path.join(tmp, sub)
                self.assertTrue(os.path.isdir(path), f"{sub} not created")
                assert_owner_only_directory(path)


if __name__ == "__main__":
    unittest.main()
