# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw uninstall`` runs ``defenseclaw-gateway sandbox teardown``."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import click

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402  (sys.path tweak above)


@contextlib.contextmanager
def capture_click_output():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


def _completed(returncode=0, stdout="", stderr=""):
    return type("Completed", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


class SandboxTeardownTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.gateway = os.path.join(self._tmp.name, "defenseclaw-gateway")
        Path(self.gateway).write_text("#!/bin/sh\n")

    def test_plan_includes_teardown_only_with_sandbox_state(self):
        with tempfile.TemporaryDirectory() as data_dir:
            self.assertFalse(cmd_uninstall._sandbox_state_present(None, data_dir, "linux"))
            os.mkdir(os.path.join(data_dir, "sandboxes"))
            self.assertTrue(cmd_uninstall._sandbox_state_present(None, data_dir, "linux"))
            self.assertFalse(cmd_uninstall._sandbox_state_present(None, data_dir, "win32"))
        enabled = type("Cfg", (), {"openshell": type("OS", (), {"enabled": True, "wrappers": []})()})()
        with tempfile.TemporaryDirectory() as data_dir:
            self.assertTrue(cmd_uninstall._sandbox_state_present(enabled, data_dir, "darwin"))

    def test_rendered_plan_names_the_teardown(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, data_dir=self._tmp.name)
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        self.assertIn("sandbox teardown:", buf.getvalue())
        self.assertIn("OpenShell itself is kept", buf.getvalue())
        # The teardown runs with --yes, so the plan warns about copy-mode work.
        self.assertIn("never pulled back is deleted with it", buf.getvalue())
        self.assertIn("sandbox teardown --dry-run", buf.getvalue())

    def test_teardown_runs_before_the_sidecar_stops(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway)
        order = []
        with (
            patch.object(cmd_uninstall, "_validate_plan", side_effect=lambda _: order.append("validate")),
            patch.object(cmd_uninstall, "_sandbox_teardown", side_effect=lambda _: order.append("sandbox")),
            patch.object(cmd_uninstall, "_stop_gateway", side_effect=lambda _: order.append("stop")),
            capture_click_output(),
        ):
            result = cmd_uninstall._execute_plan(plan)
        self.assertEqual(order, ["validate", "sandbox", "stop"])
        self.assertTrue(result.succeeded)

    def test_teardown_invokes_the_gateway(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway)
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(kwargs["encoding"], "utf-8")
            self.assertEqual(kwargs["errors"], "replace")
            if argv[-1] == "--help":
                return _completed(stdout="Flags:\n  --dry-run\n  --keep-images\n  -y, --yes\n")
            return _completed(stdout="✓ deleted sandbox dc-claude-proj-1a2b\n✓ teardown complete\n")

        with patch("subprocess.run", side_effect=fake_run), capture_click_output() as buf:
            cmd_uninstall._sandbox_teardown(plan)
        self.assertEqual(calls[-1], [self.gateway, "sandbox", "teardown", "--yes"])
        self.assertIn("deleted sandbox dc-claude-proj-1a2b", buf.getvalue())

    def test_teardown_failure_stops_the_uninstall(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway, stop_gateway=True)

        def fake_run(argv, **_kwargs):
            if argv[-1] == "--help":
                return _completed(stdout="--keep-images\n")
            return _completed(returncode=1, stderr="✗ restore the gateway configuration: restart failed\n")

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_stop_gateway") as stop,
            capture_click_output(),
        ):
            with self.assertRaises(click.ClickException) as ctx:
                cmd_uninstall._execute_plan(plan)
        self.assertIn("sandbox teardown failed", ctx.exception.message)
        self.assertIn("restart failed", ctx.exception.message)
        stop.assert_not_called()

    def test_teardown_failure_names_the_way_on(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway)

        def fake_run(argv, **_kwargs):
            if argv[-1] == "--help":
                return _completed(stdout="--keep-images\n")
            return _completed(returncode=1, stderr="✗ remove images: docker image rm: executable file not found\n")

        with patch("subprocess.run", side_effect=fake_run), capture_click_output():
            with self.assertRaises(click.ClickException) as ctx:
                cmd_uninstall._sandbox_teardown(plan)
        self.assertIn("--skip-sandbox-teardown", ctx.exception.message)

    def test_teardown_failure_names_the_failed_step_not_the_last_one(self):
        # GAP-0282: teardown goes on past a failed step, so the last line it
        # printed was a success and the abort named that as the reason.
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway)

        def fake_run(argv, **_kwargs):
            if argv[-1] == "--help":
                return _completed(stdout="--keep-images\n")
            return _completed(
                returncode=1,
                stdout=(
                    "  ✓ deleted provider profile dc-anthropic\n"
                    "  ✗ remove images: docker image rm t:1: docker image exited 1: Cannot connect to the Docker daemon\n"
                    "  ✓ openshell.enabled is off\n"
                ),
            )

        with patch("subprocess.run", side_effect=fake_run), capture_click_output():
            with self.assertRaises(click.ClickException) as ctx:
                cmd_uninstall._sandbox_teardown(plan)
        message = ctx.exception.message
        self.assertIn("(remove images: docker image rm t:1: docker image exited 1: Cannot connect to the Docker daemon)", message)
        self.assertNotIn("openshell.enabled is off)", message)
        self.assertIn("2 step(s) listed above already ran", message)
        self.assertIn("--skip-sandbox-teardown", message)

    def test_unsupported_sandboxes_skip_the_teardown(self):
        # A managed_enterprise deployment (or a platform without sandboxes):
        # teardown exits 3 and the uninstall goes on.
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway, stop_gateway=True)

        def fake_run(argv, **_kwargs):
            if argv[-1] == "--help":
                return _completed(stdout="--keep-images\n")
            return _completed(
                returncode=3,
                stderr="✗ OpenShell sandboxes are not supported here: sandboxes are not supported in managed_enterprise deployments\n",
            )

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_stop_gateway") as stop,
            capture_click_output() as buf,
        ):
            result = cmd_uninstall._execute_plan(plan)
        self.assertTrue(result.succeeded)
        stop.assert_called_once()
        self.assertIn("sandbox teardown skipped: OpenShell sandboxes are not supported here", buf.getvalue())

    def test_skip_sandbox_teardown(self):
        with tempfile.TemporaryDirectory() as data_dir:
            os.mkdir(os.path.join(data_dir, "sandboxes"))
            with (
                patch.object(cmd_uninstall.config_module, "default_data_path", return_value=Path(data_dir)),
                patch.object(
                    cmd_uninstall.config_module, "config_path_for_data_dir", return_value=Path(data_dir) / "absent.yaml"
                ),
            ):
                kept = cmd_uninstall._build_plan(
                    wipe_data=False, binaries=False, revert_openclaw=False, remove_plugin=False, platform_name="linux"
                )
                skipped = cmd_uninstall._build_plan(
                    wipe_data=False,
                    binaries=False,
                    revert_openclaw=False,
                    remove_plugin=False,
                    platform_name="linux",
                    skip_sandbox_teardown=True,
                )
        self.assertTrue(kept.sandbox_teardown)
        self.assertFalse(kept.sandbox_teardown_skipped)
        self.assertFalse(skipped.sandbox_teardown)
        self.assertTrue(skipped.sandbox_teardown_skipped)
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(skipped, dry_run=True)
        self.assertIn("skipped (--skip-sandbox-teardown)", buf.getvalue())
        self.assertIn("`defenseclaw-gateway sandbox teardown` removes them later", buf.getvalue())
        order = []
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_sandbox_teardown", side_effect=lambda _: order.append("sandbox")),
            patch.object(cmd_uninstall, "_stop_gateway", side_effect=lambda _: order.append("stop")),
            capture_click_output(),
        ):
            cmd_uninstall._execute_plan(skipped)
        self.assertEqual(order, ["stop"])

    def test_gateway_without_sandbox_support_is_skipped(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=self.gateway)
        with (
            patch("subprocess.run", return_value=_completed(returncode=1, stderr='unknown command "sandbox"')) as run,
            capture_click_output(),
        ):
            cmd_uninstall._sandbox_teardown(plan)
        self.assertEqual(run.call_count, 1)

    def test_missing_gateway_is_skipped(self):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=os.path.join(self._tmp.name, "absent"))
        with patch("subprocess.run") as run, capture_click_output():
            cmd_uninstall._sandbox_teardown(plan)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
