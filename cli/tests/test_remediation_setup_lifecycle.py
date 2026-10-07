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
        # Linux (systemd) words it differently (GAP-1408 on RHEL).
        done.stdout = "Gateway service not enabled.\n"
        with patch("defenseclaw.commands.cmd_setup.subprocess.run", return_value=done):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _restart_openclaw_gateway()
        self.assertNotIn("✓", buf.getvalue())
        # A foreground `openclaw gateway run` has no service: OpenClaw 2026.9 exits non-zero
        # while that gateway keeps running, and setup must not roll back (GAP-0191).
        foreground = subprocess.CompletedProcess(
            ["openclaw"], 1, stdout="", stderr="Gateway restart failed: Error: Foreground Gateway owner pid 7 no longer listens on port 18789\n"
        )
        with patch("defenseclaw.commands.cmd_setup.subprocess.run", return_value=foreground):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertIs(_restart_openclaw_gateway(), True)
        self.assertIn("no OpenClaw gateway service", buf.getvalue())
        self.assertNotIn("✗", buf.getvalue())

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

    def test_gap1702_openclaw_gateway_down_names_it_and_rollback_does_not_wait_again(self):
        from types import SimpleNamespace

        import click
        from defenseclaw.commands import cmd_setup

        with self.assertRaises(cmd_setup._OpenClawGatewayNotRunning) as raised:
            cmd_setup._fail_if_restart_failed(["openclaw-gateway"])
        cause = raised.exception
        self.assertIn("openclaw gateway run", cause.message)
        self.assertNotIn("defenseclaw-gateway start", cause.message)

        cfg = SimpleNamespace(
            data_dir="/nonexistent",
            gateway=SimpleNamespace(host="127.0.0.1", port=18789),
            active_connectors=lambda: ["openclaw"],
            active_connector=lambda: "openclaw",
        )
        app = SimpleNamespace(cfg=cfg)
        with patch.object(cmd_setup, "_restart_services") as restart:
            cmd_setup._restart_restored_connector_runtime(app, skip_openclaw=True)
        self.assertEqual(restart.call_args.kwargs["connector"], "")

        with (
            patch.object(cmd_setup, "_restore_setup_config_snapshot"),
            patch.object(cmd_setup, "_restart_restored_connector_runtime") as reconcile,
            self.assertRaises(click.ClickException) as final,
        ):
            cmd_setup._rollback_failed_connector_application(app, SimpleNamespace(applied_runtime=None), cause)
        reconcile.assert_called_once_with(app, skip_openclaw=True)
        message = final.exception.message
        self.assertIn("openclaw gateway run", message)
        self.assertIn("restored the prior connector configuration and runtime", message)
        self.assertNotIn("rollback was incomplete", message)
        self.assertNotIn("defenseclaw-gateway start", message)


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


def test_gap1826_rollback_keeps_the_failed_generation_lock_for_the_gateway() -> None:
    """The gateway needs the failed generation's lock entry to switch back."""
    import pytest
    from defenseclaw.commands import cmd_setup
    from defenseclaw.file_permissions import atomic_write_private_bytes

    from tests.helpers import cleanup_app, make_app_context

    app, tmp_dir, db_path = make_app_context()
    try:
        lock_path = os.path.join(app.cfg.data_dir, "hook_contract_lock.json")
        atomic_write_private_bytes(lock_path, b'{"version":2,"connectors":{"claudecode":{}}}\n')
        snapshot = cmd_setup._capture_setup_config_snapshot(app.cfg)
        failed_lock = b'{"version":2,"connectors":{"openclaw":{}}}\n'
        atomic_write_private_bytes(lock_path, failed_lock)
        seen: list[bytes] = []

        def restart(_app, **_kwargs):
            with open(lock_path, "rb") as handle:
                seen.append(handle.read())

        cause = cmd_setup._OpenClawGatewayNotRunning("The OpenClaw gateway is not running.")
        with (
            patch.object(cmd_setup, "_restart_restored_connector_runtime", side_effect=restart),
            pytest.raises(click.ClickException) as raised,
        ):
            cmd_setup._rollback_failed_connector_application(app, snapshot, cause)
        assert seen == [failed_lock]
        assert "rollback was incomplete" not in str(raised.value)
    finally:
        cleanup_app(app, db_path, tmp_dir)
