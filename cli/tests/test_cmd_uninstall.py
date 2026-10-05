# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw uninstall`` / ``reset``.

We focus on the planning surface (``_build_plan`` + ``--dry-run``) rather
than actual destructive removals — the latter are covered indirectly via
the helpers they call (gateway stop, openclaw revert), which have their
own tests elsewhere.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner


@contextlib.contextmanager
def capture_click_output():
    """Capture click.echo output for direct (non-CliRunner) calls.

    click.echo writes to ``sys.stdout`` by default unless an explicit file
    is given, so swapping the stream is enough for our render-only
    assertions and avoids the version-skew between CliRunner.isolation()
    return shapes (Click 8.0 returns (stdout, stderr); Click 8.1+ adds
    a third element).
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import legacy_connector
from defenseclaw.commands import cmd_uninstall  # noqa: E402  (sys.path tweak above)


class BuildPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        # Same isolation rationale as BuildPlanConnectorTests: keep
        # `_teardown_connectors` from picking up backup markers that
        # only exist on the developer's machine.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = patch(
            "defenseclaw.commands.cmd_uninstall.config_module.default_data_path",
            return_value=self._tmp.name,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_config_preserves_data_binaries_and_external_connectors(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=False,
            binaries=False,
            revert_openclaw=True,
            remove_plugin=True,
        )
        self.assertFalse(plan.remove_data_dir)
        self.assertFalse(plan.remove_binaries)
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)
        self.assertTrue(plan.data_dir)
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")
        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ())

    def test_keep_openclaw_leaves_plugin_alone(self):
        plan = cmd_uninstall._build_plan(
            wipe_data=True,
            binaries=True,
            revert_openclaw=False,
            remove_plugin=False,
        )
        self.assertTrue(plan.remove_data_dir)
        self.assertTrue(plan.remove_binaries)
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)
        self.assertNotIn("openclaw", plan.connectors)

    @unittest.skipIf(sys.platform == "win32", "POSIX launcher links")
    def test_full_uninstall_removes_launchers_into_data_dir_and_lists_installer_uv(self):
        bin_dir = Path(self._tmp.name) / "bin"
        venv_bin = Path(self._tmp.name) / ".venv" / "bin"
        bin_dir.mkdir()
        venv_bin.mkdir(parents=True)
        (venv_bin / "defenseclaw").write_text("cli", encoding="utf-8")
        (bin_dir / "defenseclaw").symlink_to(venv_bin / "defenseclaw")
        (bin_dir / "defenseclaw-gateway").write_text("gateway", encoding="utf-8")
        (bin_dir / "uv").write_bytes(b"uv")
        (bin_dir / "uvx").write_bytes(b"updated by the user")
        record = bin_dir / "defenseclaw-uv.sha256"
        record.write_text(
            f"{hashlib.sha256(b'uv').hexdigest()}  uv\n{hashlib.sha256(b'uvx').hexdigest()}  uvx\n",
            encoding="utf-8",
        )
        owned = (str(bin_dir), (str(bin_dir / "defenseclaw"), str(bin_dir / "defenseclaw-gateway")))
        with patch.object(cmd_uninstall, "_owned_binary_targets", return_value=owned):
            plan = cmd_uninstall._build_plan(
                wipe_data=True, binaries=False, revert_openclaw=False, remove_plugin=False, platform_name="linux"
            )

        self.assertEqual(plan.binary_targets[2:], (str(bin_dir / "uv"), str(record)))
        self.assertEqual(plan.data_bound_launchers, (str(bin_dir / "defenseclaw"),))
        cmd_uninstall._remove_data_bound_launchers(plan)
        self.assertFalse(os.path.lexists(bin_dir / "defenseclaw"))
        self.assertTrue((bin_dir / "defenseclaw-gateway").is_file())

    def test_windows_git_bash_launcher_is_bound_to_the_data_dir(self):
        data_dir = Path(self._tmp.name) / "data"
        launcher = Path(self._tmp.name) / "defenseclaw"
        exe = os.path.join(os.path.normcase(os.path.abspath(data_dir)), ".venv", "Scripts", "defenseclaw.exe")
        launcher.write_text(f'#!/bin/sh\nexec "{exe.replace(os.sep, "/")}" "$@"\n', encoding="utf-8")
        self.assertTrue(cmd_uninstall._is_data_bound_launcher(str(launcher), str(data_dir), "win32"))
        launcher.write_text('#!/bin/sh\nexec "/opt/other/defenseclaw" "$@"\n', encoding="utf-8")
        self.assertFalse(cmd_uninstall._is_data_bound_launcher(str(launcher), str(data_dir), "win32"))

    def test_non_windows_gateway_path_preserves_path_resolution(self):
        with patch.object(cmd_uninstall.shutil, "which", return_value="/usr/local/bin/defenseclaw-gateway"):
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                revert_openclaw=False,
                remove_plugin=False,
                platform_name="linux",
            )
        self.assertEqual(plan.gateway_path, "/usr/local/bin/defenseclaw-gateway")


class UninstallCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch(
            "defenseclaw.commands.windows_native_uninstall.prepare_native_windows_uninstall",
            return_value=None,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_dry_run_does_not_execute(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                ["--dry-run"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("dry-run", result.output)
            exec_mock.assert_not_called()

    def test_confirmation_declined_aborts(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                [],
                input="n\n",
            )
            self.assertNotEqual(result.exit_code, 0)
            exec_mock.assert_not_called()
            self.assertIn("Cancelled", result.output)

    def test_yes_flag_skips_prompt(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_uninstall._execute_plan") as exec_mock:
            result = runner.invoke(
                cmd_uninstall.uninstall_cmd,
                ["--yes"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            exec_mock.assert_called_once()


class KeptAndNextStepsTests(unittest.TestCase):
    """GAP-1093: a partial uninstall says what it kept and how to go on."""

    def test_default_uninstall_names_kept_data_and_next_steps(self):
        plan = cmd_uninstall.UninstallPlan(data_dir="/home/u/.defenseclaw", install_root="/home/u/.local/bin")
        with capture_click_output() as buf:
            cmd_uninstall._render_kept_and_next_steps(plan)
        text = buf.getvalue()
        self.assertIn("/home/u/.defenseclaw: config, audit log, policies and secrets", text)
        self.assertIn("/home/u/.local/bin: the DefenseClaw commands", text)
        self.assertIn("defenseclaw setup guardrail", text)
        self.assertIn("defenseclaw uninstall --all --binaries", text)

    def test_all_without_binaries_points_at_quickstart(self):
        plan = cmd_uninstall.UninstallPlan(
            data_dir="/home/u/.defenseclaw", install_root="/home/u/.local/bin", remove_data_dir=True
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_kept_and_next_steps(plan)
        text = buf.getvalue()
        self.assertNotIn("audit log", text)
        self.assertIn("defenseclaw quickstart", text)

    def test_windows_developer_install_next_step_is_remove_item(self):
        # GAP-1256: --binaries refuses a make-all developer install, so the
        # next step names the files instead.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bin"
            root.mkdir()
            for name in ("defenseclaw.exe", ".defenseclaw-source-root"):
                (root / name).write_text("dev", encoding="ascii")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32", data_dir=str(Path(tmp) / ".defenseclaw"), install_root=str(root),
                remove_data_dir=True,
            )
            with capture_click_output() as buf:
                cmd_uninstall._render_kept_and_next_steps(plan)
            text = buf.getvalue()
        self.assertNotIn("--binaries", text)
        self.assertIn("Remove-Item -LiteralPath", text)
        self.assertIn(f"'{root / 'defenseclaw.exe'}'", text)

    def test_binaries_only_next_steps_do_not_run_defenseclaw(self):
        # GAP-1745: --binaries removed the command the old next steps named.
        plan = cmd_uninstall.UninstallPlan(
            data_dir="/home/u/.defenseclaw", install_root="/home/u/.local/bin", remove_binaries=True
        )
        with patch("defenseclaw.upgrade_shim.managed_deployment", return_value=None), \
                capture_click_output() as buf:
            cmd_uninstall._render_kept_and_next_steps(plan)
        text = buf.getvalue()
        self.assertIn("/home/u/.defenseclaw: config, audit log, policies and secrets", text)
        self.assertIn("rm -rf /home/u/.defenseclaw", text)
        self.assertIn("install.sh | bash", text)
        self.assertNotIn("  • turn protection back on:   defenseclaw", text)
        self.assertNotIn("defenseclaw uninstall --all", text)

        with patch("defenseclaw.upgrade_shim.managed_deployment", return_value="/etc/x"), \
                capture_click_output() as buf:
            cmd_uninstall._render_kept_and_next_steps(plan)
        self.assertNotIn("reinstall", buf.getvalue())

    def test_full_uninstall_prints_nothing(self):
        plan = cmd_uninstall.UninstallPlan(data_dir="/d", install_root="/b", remove_data_dir=True, remove_binaries=True)
        with capture_click_output() as buf:
            cmd_uninstall._render_kept_and_next_steps(plan)
        self.assertEqual(buf.getvalue(), "")


class ResetCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        (Path(self._tmp.name) / ".venv").mkdir()
        patcher = patch(
            "defenseclaw.commands.cmd_uninstall.config_module.default_data_path",
            return_value=self._tmp.name,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_reset_yes_executes_plan_with_wipe_and_keep_plugin(self):
        runner = CliRunner()
        captured = {}

        def fake_execute(plan):
            captured["plan"] = plan

        with patch("defenseclaw.commands.cmd_uninstall._execute_plan", side_effect=fake_execute):
            result = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            plan = captured["plan"]
            # reset = wipe data + keep plugin, don't touch binaries.
            self.assertTrue(plan.remove_data_dir)
            self.assertFalse(plan.remove_plugin)
            self.assertFalse(plan.remove_binaries)
            self.assertEqual(plan.preserve_data_entries, (".venv", ".uv"))
            self.assertIn("preserve runtime:", result.output)

    def test_reset_failure_is_nonzero_and_never_reports_complete(self):
        runner = CliRunner()
        with (
            patch("defenseclaw.commands.cmd_uninstall._stop_gateway"),
            patch("defenseclaw.commands.cmd_uninstall._connector_teardown"),
            patch("defenseclaw.commands.cmd_uninstall._remove_data_dir", side_effect=OSError("locked native module")),
        ):
            result = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("gateway stop: succeeded", result.output)
        self.assertNotIn("connector teardown: succeeded", result.output)
        self.assertIn("data removal: failed", result.output)
        self.assertIn("locked native module", result.output)
        self.assertNotIn("Reset complete", result.output)


class WindowsOwnedCleanupTests(unittest.TestCase):
    def test_windows_plan_freezes_exact_owned_launchers(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"USERPROFILE": tmp}, clear=False),
            patch.object(cmd_uninstall.config_module, "default_data_path", return_value=Path(tmp) / ".defenseclaw"),
        ):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=True,
                revert_openclaw=False,
                remove_plugin=False,
                platform_name="win32",
            )

        self.assertEqual(
            tuple(Path(path).name for path in plan.binary_targets),
            (
                "defenseclaw.cmd",
                "defenseclaw.exe",
                "defenseclaw",
                "defenseclaw-gateway.exe",
                "defenseclaw-acp.exe",
                "defenseclaw-hook.exe",
                "skill-scanner.cmd",
                "mcp-scanner.cmd",
                "defenseclaw-hook-state.json",
            ),
        )
        self.assertEqual(plan.managed_venv, os.path.join(plan.data_dir, ".venv"))

    def test_binary_only_removes_exact_targets_and_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            # macOS exposes TemporaryDirectory through the /var -> /private/var
            # symlink. Canonicalize before simulating Windows so the test does
            # not trip the production reparse-ancestor guard on a POSIX alias.
            profile = Path(tmp).resolve() / "kévin profile"
            root = profile / "bin"
            root.mkdir(parents=True)
            targets = tuple(
                str(root / name)
                for name in (
                    "defenseclaw.cmd",
                    "defenseclaw-gateway.exe",
                    "defenseclaw-acp.exe",
                    "defenseclaw-hook.exe",
                )
            )
            for target in targets:
                Path(target).write_text("owned", encoding="utf-8")
            managed_venv = profile / ".defenseclaw" / ".venv"
            Path(targets[0]).write_text(
                f'@echo off\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\n',
                encoding="utf-8",
            )
            unrelated = root / "defenseclaw.exe"
            unrelated.write_text("foreign", encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                install_root=str(root),
                gateway_path=str(root / "defenseclaw-gateway.exe"),
                binary_targets=targets,
                remove_binaries=True,
                managed_venv=str(managed_venv),
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertTrue(unrelated.is_file())
            self.assertFalse(any(Path(path).exists() for path in targets))
            cmd_uninstall._remove_binaries(plan)
            self.assertTrue(unrelated.is_file())

    def test_binaries_removes_folders_a_replaced_windows_setup_left(self):
        # WIN-R1-17: after the installer replaces DefenseClaw Setup, its hook
        # launcher and transaction log stay under %LOCALAPPDATA%\DefenseClaw.
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp).resolve()
            hook = local / "DefenseClaw" / "HookRuntime" / "defenseclaw-hook.exe"
            hook.parent.mkdir(parents=True)
            hook.write_bytes(b"MZ")
            (local / "DefenseClaw" / "InstallerState").mkdir()
            with patch.object(cmd_uninstall.windows_native_uninstall, "_known_folder_path", return_value=str(local)):
                leftovers = cmd_uninstall._windows_setup_leftovers("win32")
                self.assertEqual(len(leftovers), 2)
                cmd_uninstall._remove_setup_leftovers(leftovers)
                self.assertFalse((local / "DefenseClaw").exists())
                # A live Setup hook runtime keeps its folders.
                (local / "DefenseClaw" / "HookRuntime").mkdir(parents=True)
                (local / "DefenseClaw" / "HookRuntime" / "hook-runtime-state.json").write_text("{}")
                self.assertEqual(cmd_uninstall._windows_setup_leftovers("win32"), ())

    def test_binary_removal_drops_install_bookkeeping_and_pip_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "bin"
            custody = root / ".defenseclaw-install-custody" / "retired"
            custody.mkdir(parents=True)
            (custody / "old").write_text("x", encoding="utf-8")
            (root / ".defenseclaw-source-root").write_text("checkout", encoding="utf-8")
            legacy_tmp = Path(tmp).resolve() / "tmp"
            (legacy_tmp / ".defenseclaw-install-custody-1-abc" / "retired-x").mkdir(parents=True)
            (legacy_tmp / "unrelated").mkdir()
            # MAC-U2-12: pre-1.0 installers also parked retired binaries beside DEFENSECLAW_HOME.
            home = Path(tmp).resolve() / "home"
            (home / ".defenseclaw-install-custody" / "retired-x").mkdir(parents=True)
            gateway = "defenseclaw-gateway.exe" if sys.platform == "win32" else "defenseclaw-gateway"
            plan = cmd_uninstall.UninstallPlan(
                platform_name=sys.platform,
                install_root=str(root),
                gateway_path=str(root / gateway),
                binary_targets=(),
                remove_binaries=True,
                data_dir=str(home / ".defenseclaw"),
            )
            with (
                patch.object(cmd_uninstall.shutil, "which", return_value=None),
                patch.object(cmd_uninstall, "_legacy_custody_parents", return_value=[str(legacy_tmp)]),
                patch.dict(os.environ, {"HOME": str(home)}),
                patch.object(cmd_uninstall.ux, "subhead") as subhead,
                patch.object(cmd_uninstall, "_remove_user_path_entry") as path_entry,
            ):
                cmd_uninstall._remove_binaries(plan)
            # The emptied install folder goes as well; Windows also drops its user Path entry.
            self.assertFalse(root.exists())
            if sys.platform == "win32":
                path_entry.assert_called_once_with(plan)
            else:
                path_entry.assert_not_called()
            self.assertEqual(os.listdir(legacy_tmp), ["unrelated"])
            if sys.platform != "win32":
                self.assertEqual(os.listdir(home), [])
            subhead.assert_not_called()

    def test_binary_failure_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "bin"
            root.mkdir()
            target = root / "defenseclaw.cmd"
            managed_venv = Path(tmp) / ".defenseclaw" / ".venv"
            target.write_text(
                f'@echo off\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\n',
                encoding="ascii",
            )
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                install_root=str(root),
                gateway_path=str(root / "defenseclaw-gateway.exe"),
                binary_targets=(str(target),),
                remove_binaries=True,
                managed_venv=str(managed_venv),
            )
            with patch.object(cmd_uninstall.os, "unlink", side_effect=PermissionError("locked")):
                with patch.object(cmd_uninstall.time, "sleep"), self.assertRaises(OSError):
                    cmd_uninstall._remove_binaries(plan)

    def test_failed_phase_prints_its_reason_once(self):
        plan = cmd_uninstall.UninstallPlan(platform_name="win32", remove_binaries=True)
        refusal = click.ClickException("refusing Windows binary removal:\n  Remove-Item -LiteralPath 'x'")
        buf = io.StringIO()
        with patch.object(cmd_uninstall, "_validate_plan", side_effect=refusal), contextlib.redirect_stdout(buf):
            with self.assertRaises(click.ClickException):
                cmd_uninstall._execute_plan(plan)
        self.assertIn("plan validation: failed", buf.getvalue())
        self.assertNotIn("Remove-Item", buf.getvalue())

    def test_windows_developer_install_refusal_names_the_files_to_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bin"
            root.mkdir()
            for name in ("defenseclaw.exe", "defenseclaw-gateway.exe", "litellm.exe", ".defenseclaw-source-root"):
                (root / name).write_text("dev", encoding="ascii")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                install_root=str(root),
                gateway_path=str(root / "defenseclaw-gateway.exe"),
                binary_targets=(str(root / "defenseclaw-gateway.exe"),),
                remove_binaries=True,
            )
            with self.assertRaises(click.ClickException) as raised:
                cmd_uninstall._validate_windows_binary_ownership(plan)
            message = raised.exception.message
            self.assertIn("developer install from 'make all'", message)
            self.assertIn(f"'{root / 'litellm.exe'}'", message)
            self.assertIn(f"'{root / '.defenseclaw-source-root'}'", message)
            self.assertTrue((root / "defenseclaw-gateway.exe").is_file())

    def test_same_named_unrelated_windows_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bin"
            root.mkdir()
            targets = tuple(
                str(root / name) for name in ("defenseclaw.cmd", "defenseclaw-gateway.exe", "defenseclaw-hook.exe")
            )
            for target in targets:
                Path(target).write_text("foreign", encoding="ascii")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                install_root=str(root),
                managed_venv=str(Path(tmp) / ".defenseclaw" / ".venv"),
                gateway_path=str(root / "defenseclaw-gateway.exe"),
                binary_targets=targets,
                remove_binaries=True,
            )

            with self.assertRaises(click.ClickException):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(all(Path(target).is_file() for target in targets))

    def test_reparse_binary_target_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bin"
            outside = Path(tmp) / "outside.cmd"
            root.mkdir()
            outside.write_text("foreign", encoding="utf-8")
            target = root / "defenseclaw.cmd"
            try:
                target.symlink_to(outside)
            except OSError:
                self.skipTest("file symlinks unavailable")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                install_root=str(root),
                gateway_path=str(root / "defenseclaw-gateway.exe"),
                binary_targets=(str(target),),
                remove_binaries=True,
            )
            with self.assertRaises(click.ClickException):
                cmd_uninstall._remove_binaries(plan)
            self.assertEqual(outside.read_text(encoding="utf-8"), "foreign")

    def test_reparse_connector_backup_is_rejected_before_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            marker = data_dir / "connector_backups" / "codex" / "config.toml.json"
            outside = Path(tmp) / "outside.json"
            marker.parent.mkdir(parents=True)
            outside.write_text("foreign", encoding="utf-8")
            try:
                marker.symlink_to(outside)
            except OSError:
                self.skipTest("file symlinks unavailable")
            plan = cmd_uninstall.UninstallPlan(data_dir=str(data_dir), connectors=("codex",))
            with self.assertRaises(click.ClickException):
                cmd_uninstall._validate_plan(plan)
            self.assertEqual(outside.read_text(encoding="utf-8"), "foreign")

    def test_deferred_cleanup_is_scheduled_only_after_teardown(self):
        plan = cmd_uninstall.UninstallPlan(
            platform_name="win32",
            install_root="C:\\Users\\test\\.local\\bin",
            gateway_path="C:\\Users\\test\\.local\\bin\\defenseclaw-gateway.exe",
            binary_targets=("C:\\Users\\test\\.local\\bin\\defenseclaw.cmd",),
            data_dir="C:\\Users\\test\\.defenseclaw",
            managed_venv="C:\\Users\\test\\.defenseclaw\\.venv",
            remove_data_dir=True,
            remove_binaries=True,
            connectors=("codex",),
        )
        order = []
        with (
            patch.object(cmd_uninstall, "_validate_plan", side_effect=lambda _: order.append("validate")),
            patch.object(cmd_uninstall, "_stop_gateway", side_effect=lambda _: order.append("stop")),
            patch.object(cmd_uninstall, "_connector_teardown", side_effect=lambda _: order.append("teardown")),
            patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True),
            patch.object(
                cmd_uninstall,
                "_schedule_deferred_cleanup",
                side_effect=lambda _: order.append("schedule") or "result.json",
            ),
        ):
            result = cmd_uninstall._execute_plan(plan)

        self.assertEqual(order, ["validate", "stop", "teardown", "schedule"])
        self.assertEqual(result.phases[-1].status, "scheduled")
        self.assertTrue(result.succeeded)

    def test_binaries_only_leaves_the_running_cli_shim_to_the_helper(self):
        root = "C:\\Users\\test\\.local\\bin"
        shim = root + "\\defenseclaw.cmd"
        gateway = root + "\\defenseclaw-gateway.exe"
        plan = cmd_uninstall.UninstallPlan(
            platform_name="win32",
            install_root=root,
            gateway_path=gateway,
            binary_targets=(shim, gateway),
            data_dir="C:\\Users\\test\\.defenseclaw",
            managed_venv="C:\\Users\\test\\.defenseclaw\\.venv",
            remove_binaries=True,
        )
        scheduled = []
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_running_from_managed_venv", return_value=True),
            patch.object(cmd_uninstall, "_schedule_deferred_cleanup", side_effect=scheduled.append),
            patch.object(cmd_uninstall.os.path, "lexists", return_value=True),
            patch.object(cmd_uninstall.os, "unlink") as unlink,
            patch.object(cmd_uninstall, "_remove_install_bookkeeping"),
            patch.object(cmd_uninstall.shutil, "which", return_value=None),
        ):
            cmd_uninstall._remove_binaries(plan)

        unlink.assert_called_once_with(gateway)
        self.assertEqual([p.binary_targets for p in scheduled], [(shim,)])
        self.assertFalse(scheduled[0].remove_data_dir)

    def test_binaries_only_leaves_the_running_cli_launchers_to_the_helper(self):
        # GAP-2237: PowerShell runs the installer's defenseclaw.exe, which
        # Windows keeps while it runs; it goes with the shim after the CLI exits.
        root = "C:\\Users\\test\\.local\\bin"
        shim, launcher, gateway = (root + "\\" + name for name in ("defenseclaw.cmd", "defenseclaw.exe", "defenseclaw-gateway.exe"))
        plan = cmd_uninstall.UninstallPlan(
            platform_name="win32",
            install_root=root,
            gateway_path=gateway,
            binary_targets=(shim, launcher, gateway),
            data_dir="C:\\Users\\test\\.defenseclaw",
            managed_venv="C:\\Users\\test\\.defenseclaw\\.venv",
            remove_binaries=True,
        )
        scheduled = []
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_running_from_managed_venv", return_value=True),
            patch.object(cmd_uninstall, "_schedule_deferred_cleanup", side_effect=scheduled.append),
            patch.object(cmd_uninstall.os.path, "lexists", return_value=True),
            patch.object(cmd_uninstall.os, "unlink") as unlink,
            patch.object(cmd_uninstall, "_remove_install_bookkeeping"),
            patch.object(cmd_uninstall.shutil, "which", return_value=launcher),
            capture_click_output() as output,
        ):
            cmd_uninstall._remove_binaries(plan)

        unlink.assert_called_once_with(gateway)
        self.assertEqual([p.binary_targets for p in scheduled], [(shim, launcher)])
        self.assertIn(f"{launcher} is removed right after this command exits", output.getvalue())
        self.assertNotIn("another defenseclaw remains", output.getvalue())

    def test_installer_cli_launcher_is_bound_to_the_data_dir_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, ".defenseclaw")
            launcher = Path(tmp) / "defenseclaw.exe"
            python = os.path.join(cmd_uninstall._normalized(os.path.join(data_dir, ".venv")), "Scripts", "python.exe")
            launcher.write_bytes(b"MZ\0trampoline" + python.upper().encode("utf-8") + b"PK\0script")
            self.assertTrue(cmd_uninstall._is_data_bound_launcher(str(launcher), data_dir, "win32"))
            launcher.write_bytes(b"MZ\0trampoline C:\\Other\\.venv\\Scripts\\python.exe")
            self.assertFalse(cmd_uninstall._is_data_bound_launcher(str(launcher), data_dir, "win32"))

    def test_deferred_scheduling_failure_is_nonzero_and_stops_cleanup(self):
        plan = cmd_uninstall.UninstallPlan(
            platform_name="win32",
            data_dir="C:\\Users\\test\\.defenseclaw",
            managed_venv="C:\\Users\\test\\.defenseclaw\\.venv",
            remove_data_dir=True,
        )
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_stop_gateway"),
            patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True),
            patch.object(
                cmd_uninstall,
                "_schedule_deferred_cleanup",
                side_effect=click.ClickException("helper rejected plan"),
            ),
            patch.object(cmd_uninstall, "_remove_data_dir") as remove_data,
        ):
            with self.assertRaises(click.ClickException):
                cmd_uninstall._execute_plan(plan)
        remove_data.assert_not_called()

    def test_windows_dry_run_renders_exact_targets_and_deferred_state(self):
        plan = cmd_uninstall.UninstallPlan(
            platform_name="win32",
            data_dir="C:\\Users\\test\\.defenseclaw",
            managed_venv=os.path.dirname(sys.executable),
            remove_data_dir=True,
            remove_binaries=True,
            binary_targets=(
                "C:\\Users\\test\\.local\\bin\\defenseclaw.cmd",
                "C:\\Users\\test\\.local\\bin\\defenseclaw-gateway.exe",
                "C:\\Users\\test\\.local\\bin\\defenseclaw-hook.exe",
            ),
        )
        present = set(plan.binary_targets[:2])
        with (
            patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True),
            patch.object(cmd_uninstall.os.path, "lexists", side_effect=present.__contains__),
            capture_click_output() as output,
        ):
            cmd_uninstall._render_plan(plan, dry_run=True)
        rendered = output.getvalue()
        for target in present:
            self.assertIn(target, rendered)
        # A launcher that was never installed is not in the plan.
        self.assertNotIn(plan.binary_targets[2], rendered)
        self.assertIn("deferred cleanup", rendered)

    def test_windows_stop_uses_exact_gateway_and_waits_for_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = Path(tmp) / "defenseclaw-gateway.exe"
            gateway.write_bytes(b"test")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="win32",
                gateway_path=str(gateway),
            )
            completed = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            with (
                patch.object(cmd_uninstall.subprocess, "run", return_value=completed) as run,
                patch.object(cmd_uninstall, "_capture_managed_processes", return_value=[]) as capture,
                patch.object(cmd_uninstall, "_wait_managed_processes") as wait,
            ):
                cmd_uninstall._stop_gateway(plan)
        self.assertEqual(run.call_args_list[0].args[0], [str(gateway), "watchdog", "stop"])
        self.assertEqual(run.call_args_list[1].args[0], [str(gateway), "stop"])
        capture.assert_called_once_with(plan)
        wait.assert_called_once_with([])

    def test_two_resets_do_not_invent_or_mutate_openclaw(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            data_dir = home / ".defenseclaw"
            openclaw_config = home / ".openclaw" / "openclaw.json"
            venv = data_dir / ".venv"
            venv.mkdir(parents=True)
            openclaw_config.parent.mkdir(parents=True)
            unrelated_bytes = b'{"owner":"unrelated","unique":"WIN-AUD-018"}\r\n'
            openclaw_config.write_bytes(unrelated_bytes)
            before_hash = hashlib.sha256(unrelated_bytes).hexdigest()

            (data_dir / "config.yaml").write_text(
                "guardrail:\n  enabled: true\n  connectors:\n    codex: {}\n    claudecode: {}\n",
                encoding="utf-8",
            )
            for marker in (
                "connector_backups/codex/config.toml.json",
                "connector_backups/claudecode/settings.json.json",
            ):
                target = data_dir / marker
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}", encoding="utf-8")

            teardown_plans = []

            def record_teardown(plan):
                teardown_plans.append(plan)

            isolated_env = {
                "DEFENSECLAW_HOME": str(data_dir),
                "HOME": str(home),
                "USERPROFILE": str(home),
            }
            with (
                patch.dict(os.environ, isolated_env, clear=False),
                patch.object(cmd_uninstall, "_stop_gateway"),
                patch.object(cmd_uninstall, "_connector_teardown", side_effect=record_teardown),
            ):
                first = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])
                second = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])

            self.assertEqual(first.exit_code, 0, first.output)
            self.assertEqual(second.exit_code, 0, second.output)
            self.assertEqual(len(teardown_plans), 1)
            self.assertEqual(set(teardown_plans[0].connectors), {"codex", "claudecode"})
            first_lower = first.output.lower()
            self.assertIn("active connectors:", first_lower)
            self.assertIn("codex", first_lower)
            self.assertIn("claudecode", first_lower)
            self.assertNotIn("openclaw", first_lower)
            self.assertTrue(venv.is_dir())
            self.assertEqual({path.name for path in data_dir.iterdir()}, {".venv"})
            self.assertEqual(openclaw_config.read_bytes(), unrelated_bytes)
            self.assertEqual(hashlib.sha256(openclaw_config.read_bytes()).hexdigest(), before_hash)

            second_lower = second.output.lower()
            self.assertIn("active connector:    none", second_lower)
            self.assertIn("connector teardown:  no", second_lower)
            self.assertNotIn("openclaw", second_lower)


class ResolveActiveConnectorTests(unittest.TestCase):
    def test_uses_active_connector_method(self):
        class Cfg:
            def active_connector(self):
                return "Codex"

        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "codex")

    def test_falls_back_to_guardrail_connector(self):
        class Guardrail:
            connector = "claudecode"

        class Cfg:
            guardrail = Guardrail()

        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "claudecode")

    def test_method_exception_falls_back(self):
        class Guardrail:
            connector = "zeptoclaw"

        class Cfg:
            guardrail = Guardrail()

            def active_connector(self):
                raise RuntimeError("boom")

        self.assertEqual(cmd_uninstall._resolve_active_connector(Cfg()), "zeptoclaw")

    def test_none_cfg_has_no_active_connector(self):
        self.assertEqual(cmd_uninstall._resolve_active_connector(None), "")


class BuildPlanConnectorTests(unittest.TestCase):
    """`_build_plan` connector resolution.

    These tests exercise the data-dir-walking branch of
    ``_teardown_connectors`` (it scans for backup-marker files like
    ``connector_backups/claudecode/settings.json.json`` to detect
    inactive connectors that DefenseClaw has touched in the past).
    Without an isolated ``data_dir`` the test inherits whatever the
    developer happens to have on disk under ``~/.defenseclaw`` —
    that's how the suite started failing on machines where claudecode
    had ever been wired up.

    setUp() therefore points ``default_data_path`` at a fresh tempdir
    so every test sees an empty marker tree and the assertions are
    deterministic regardless of the real home directory.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        (Path(self._tmp.name) / "config.yaml").write_text("configured", encoding="utf-8")
        patcher = patch(
            "defenseclaw.commands.cmd_uninstall.config_module.default_data_path",
            return_value=self._tmp.name,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_plan_records_active_connector(self):
        class Guardrail:
            connector = "codex"

        class Claw:
            home_dir = "~/.codex"
            config_file = "~/.codex/config.toml"

        class Cfg:
            guardrail = Guardrail()
            claw = Claw()

        with patch("defenseclaw.commands.cmd_uninstall.config_module.load", return_value=Cfg()):
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )
        self.assertEqual(plan.connector, "codex")
        self.assertIn("codex", plan.connectors)
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)

    def test_plan_tears_down_all_active_connectors_on_multi(self):
        # Regression: on a multi-connector install reset/uninstall must sweep
        # EVERY configured connector, not just the primary — even with no
        # backup markers on disk (setUp points data_dir at an empty tempdir).
        # Previously only the singular active connector + on-disk markers were
        # swept, so non-primary connectors kept their hook scripts after the
        # data dir was wiped.
        class Guardrail:
            connector = "antigravity"

        class Claw:
            home_dir = "~/.gemini"
            config_file = "~/.gemini/config/openclaw.json"

        class Cfg:
            guardrail = Guardrail()
            claw = Claw()

            def active_connectors(self):
                return ["antigravity", "claudecode", "codex"]

        with patch("defenseclaw.commands.cmd_uninstall.config_module.load", return_value=Cfg()):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=False,
                revert_openclaw=False,
                remove_plugin=False,
            )
        # Primary pointer unchanged; teardown set covers ALL active connectors.
        self.assertEqual(plan.connector, "antigravity")
        self.assertEqual(set(plan.connectors), {"antigravity", "claudecode", "codex"})

    def test_keep_openclaw_still_tears_down_non_openclaw_active_connector(self):
        class Guardrail:
            connector = "codex"

        class Claw:
            home_dir = "~/.openclaw"
            config_file = "~/.openclaw/openclaw.json"

        class Cfg:
            guardrail = Guardrail()
            claw = Claw()

        with (
            tempfile.TemporaryDirectory() as data_dir,
            patch("defenseclaw.commands.cmd_uninstall.config_module.default_data_path", return_value=data_dir),
            patch("defenseclaw.commands.cmd_uninstall.config_module.load", return_value=Cfg()),
        ):
            (Path(data_dir) / "config.yaml").write_text("configured", encoding="utf-8")
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                revert_openclaw=False,
                remove_plugin=False,
            )
        self.assertEqual(plan.connectors, ("codex",))

    def test_missing_config_without_markers_has_no_connectors_or_openclaw_paths(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        with patch("defenseclaw.commands.cmd_uninstall.config_module.load", side_effect=Exception("boom")):
            plan = cmd_uninstall._build_plan(
                wipe_data=False,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )
        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ())
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)

    def test_unreadable_config_without_markers_has_no_connectors(self):
        with patch("defenseclaw.commands.cmd_uninstall.config_module.load", side_effect=ValueError("bad yaml")):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )

        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ())
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")

    def test_missing_config_uses_only_non_openclaw_durable_marker(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        marker = Path(self._tmp.name) / "connector_backups" / "codex" / "config.toml.json"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}", encoding="utf-8")

        with patch("defenseclaw.commands.cmd_uninstall.config_module.load", side_effect=Exception("boom")):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )

        self.assertEqual(plan.connector, "")
        self.assertEqual(plan.connectors, ("codex",))
        self.assertEqual(plan.openclaw_config_file, "")
        self.assertEqual(plan.openclaw_home, "")
        self.assertFalse(plan.revert_openclaw)
        self.assertFalse(plan.remove_plugin)

    def test_missing_config_openclaw_marker_enables_owned_openclaw_path(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        marker = Path(self._tmp.name) / "connector_backups" / "openclaw" / "openclaw.json.json"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}", encoding="utf-8")

        with (
            patch("defenseclaw.commands.cmd_uninstall.config_module.load", side_effect=Exception("boom")),
            patch("defenseclaw.commands.cmd_uninstall.os.path.expanduser", return_value="/owned/.openclaw"),
        ):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )

        self.assertEqual(plan.connectors, ("openclaw",))
        self.assertEqual(plan.openclaw_config_file, os.path.join("/owned/.openclaw", "openclaw.json"))
        self.assertEqual(plan.openclaw_home, "/owned/.openclaw")
        self.assertTrue(plan.revert_openclaw)
        self.assertTrue(plan.remove_plugin)

    def test_missing_config_openclaw_pristine_enables_owned_openclaw_path(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        openclaw_home = Path(self._tmp.name) / "external-openclaw"
        openclaw_home.mkdir()
        (openclaw_home / "openclaw.json.pristine").write_text("owned", encoding="utf-8")

        with (
            patch("defenseclaw.commands.cmd_uninstall.config_module.load", side_effect=Exception("boom")),
            patch("defenseclaw.commands.cmd_uninstall.os.path.expanduser", return_value=str(openclaw_home)),
        ):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=False,
                revert_openclaw=True,
                remove_plugin=True,
            )

        self.assertEqual(plan.connectors, ("openclaw",))
        self.assertEqual(plan.openclaw_config_file, str(openclaw_home / "openclaw.json"))

    def test_missing_config_valid_backup_index_uses_recorded_openclaw_path(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        recorded_home = Path(self._tmp.name).parent / "recorded-openclaw"
        recorded_target = recorded_home / "openclaw.json"
        pristine = Path(self._tmp.name) / "backups" / "openclaw.json.pristine"
        pristine.parent.mkdir()
        pristine.write_bytes(b"owned snapshot")
        (Path(self._tmp.name) / "openclaw-backups.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": {
                        str(recorded_target): {
                            "pristine": str(pristine),
                            "captured_at": "2026-07-02T00:00:00Z",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        plan = cmd_uninstall._build_plan(
            wipe_data=True,
            binaries=False,
            revert_openclaw=True,
            remove_plugin=True,
        )

        self.assertEqual(plan.connectors, ("openclaw",))
        self.assertEqual(plan.openclaw_config_file, str(recorded_target))

    def test_backup_index_snapshot_outside_data_is_not_ownership(self):
        (Path(self._tmp.name) / "config.yaml").unlink()
        outside = Path(self._tmp.name).parent / "outside-snapshot"
        outside.write_bytes(b"not DefenseClaw-owned")
        recorded_target = Path(self._tmp.name).parent / "unrelated" / "openclaw.json"
        (Path(self._tmp.name) / "openclaw-backups.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": {
                        str(recorded_target): {
                            "pristine": str(outside),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        plan = cmd_uninstall._build_plan(
            wipe_data=True,
            binaries=False,
            revert_openclaw=True,
            remove_plugin=True,
        )

        self.assertEqual(plan.connectors, ())
        self.assertEqual(plan.openclaw_config_file, "")


class RenderPlanConnectorTests(unittest.TestCase):
    def test_render_empty_connector_state_as_none_without_fallback_teardown(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="",
            connectors=(),
            revert_openclaw=True,
            data_dir="/tmp/dc",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue().lower()
        self.assertIn("active connector:    none", text)
        self.assertIn("connector teardown:  no", text)
        self.assertNotIn("openclaw", text)

    def test_render_shows_connector_specific_line_for_codex(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("codex",),
            data_dir="/tmp/dc",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue()
        self.assertIn("active connector:    codex", text)
        self.assertIn("connector teardown:  codex", text)
        self.assertNotIn("revert openclaw.json", text)

    def test_render_lists_all_active_connectors_on_multi(self):
        # Multi-connector: the active line names every peer (no singular
        # "active connector: <primary>"), and surfaces no "primary" — the
        # connectors are equal peers.
        plan = cmd_uninstall.UninstallPlan(
            connector="antigravity",
            connectors=("antigravity", "claudecode", "codex"),
            data_dir="/tmp/dc",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue()
        self.assertIn("active connectors:", text)
        self.assertIn("antigravity, claudecode, codex", text)
        self.assertNotIn("primary", text)
        self.assertIn("connector teardown:  antigravity, claudecode, codex", text)

    def test_render_shows_openclaw_revert_for_openclaw(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="openclaw",
            connectors=("openclaw",),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
        )
        with capture_click_output() as buf:
            cmd_uninstall._render_plan(plan, dry_run=True)
        text = buf.getvalue()
        self.assertIn("revert openclaw.json", text)

    def test_teardown_connectors_include_inactive_managed_backup(self):
        with tempfile.TemporaryDirectory() as data_dir:
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as fh:
                fh.write("{}")
            got = cmd_uninstall._teardown_connectors(
                "openclaw",
                data_dir=data_dir,
                openclaw_config_file="",
                include_openclaw=True,
            )
        self.assertEqual(got, ("openclaw", "codex"))

    def test_teardown_connectors_include_inactive_amp_backup(self):
        with tempfile.TemporaryDirectory() as data_dir:
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "amp",
                "config.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w", encoding="utf-8") as fh:
                fh.write("{}")
            got = cmd_uninstall._teardown_connectors(
                (),
                data_dir=data_dir,
                openclaw_config_file="",
                include_openclaw=True,
            )
        self.assertEqual(got, ("amp",))

    def test_teardown_connectors_recognize_every_non_openclaw_backup_roster(self):
        expected = tuple(name for name in cmd_uninstall._CONNECTOR_BACKUP_MARKERS if name != "openclaw")
        with tempfile.TemporaryDirectory() as data_dir:
            for name in expected:
                marker = os.path.join(data_dir, cmd_uninstall._CONNECTOR_BACKUP_MARKERS[name][0])
                os.makedirs(os.path.dirname(marker), exist_ok=True)
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write("{}")
            got = cmd_uninstall._teardown_connectors(
                (),
                data_dir=data_dir,
                openclaw_config_file="",
                include_openclaw=True,
            )

        self.assertEqual(got, expected)

    def test_backup_roster_covers_all_native_lifecycle_connectors_and_legacy_receipts(self):
        native_connectors = {
            "amp",
            "antigravity",
            "claudecode",
            "codex",
            "copilot",
            "cursor",
            "hermes",
            "omnigent",
            "opencode",
            legacy_connector.RETIRED_DESKTOP_ID,
        }
        self.assertLessEqual(native_connectors, set(cmd_uninstall._CONNECTOR_BACKUP_MARKERS))
        self.assertIn(
            os.path.join("connector_backups", "cursor", "config.json"),
            cmd_uninstall._CONNECTOR_BACKUP_MARKERS["cursor"],
        )
        self.assertIn(
            os.path.join("connector_backups", "cursor", "hooks.json.json"),
            cmd_uninstall._CONNECTOR_BACKUP_MARKERS["cursor"],
        )
        self.assertIn(
            os.path.join("connector_backups", "antigravity", "config.json"),
            cmd_uninstall._CONNECTOR_BACKUP_MARKERS["antigravity"],
        )
        self.assertEqual(
            set(cmd_uninstall._CONNECTOR_BACKUP_MARKERS["omnigent"]),
            {
                os.path.join("connector_backups", "omnigent", "config.json"),
                os.path.join("connector_backups", "omnigent", "module.json"),
                os.path.join("connector_backups", "omnigent", "pth.json"),
            },
        )


class ConnectorTeardownDispatchTests(unittest.TestCase):
    def _plan(self, connector: str) -> cmd_uninstall.UninstallPlan:
        return cmd_uninstall.UninstallPlan(
            connector=connector,
            connectors=(connector,),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
            openclaw_home="/tmp/.openclaw",
        )

    def test_failed_teardown_abort_names_the_error_and_the_retry(self):
        # GAP-1048: only the last lines of the uninstall output were kept, and
        # they did not say what failed or what to do next.
        completed = type(
            "Completed",
            (),
            {"returncode": 1, "stdout": "", "stderr": "Error: failed to open audit store: disk image is malformed\n"},
        )()
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_gateway_connector_is_unknown", return_value=False),
            patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"),
            patch("subprocess.run", return_value=completed),
            capture_click_output(),
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_uninstall._connector_teardown(self._plan("claudecode"))
        text = str(raised.exception)
        self.assertIn("claudecode teardown failed (Error: failed to open audit store", text)
        self.assertIn("run the same uninstall command again", text)

    def test_uses_gateway_sentinel_when_supported(self):
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", return_value=True) as run_mock,
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
        ):
            cmd_uninstall._connector_teardown(self._plan("codex"))
            run_mock.assert_called_once_with("codex", errors=[])
            fallback.assert_not_called()

    def test_falls_back_to_python_for_openclaw_when_gateway_old(self):
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=False),
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
        ):
            cmd_uninstall._connector_teardown(self._plan("openclaw"))
            fallback.assert_called_once()

    def test_hard_fails_when_non_openclaw_and_gateway_old(self):
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=False),
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_uninstall._connector_teardown(self._plan("codex"))
        text = str(raised.exception)
        fallback.assert_not_called()
        self.assertIn("no Python fallback", text)
        self.assertIn("codex", text)
        self.assertIn("connector teardown", text)

    def test_falls_back_when_gateway_sentinel_errors_for_openclaw(self):
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", return_value=False),
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
        ):
            cmd_uninstall._connector_teardown(self._plan("openclaw"))
            fallback.assert_called_once()

    def test_does_not_fall_back_for_codex_when_sentinel_errors(self):
        with (
            capture_click_output() as buf,
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", return_value=False),
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
            self.assertRaises(click.ClickException) as raised,
        ):
            cmd_uninstall._connector_teardown(self._plan("codex"))
        fallback.assert_not_called()
        self.assertIn("reported errors", buf.getvalue())
        self.assertIn("aborting uninstall", str(raised.exception))
        self.assertIn("codex teardown failed", str(raised.exception))


class GatewaySupportProbeTests(unittest.TestCase):
    def test_returns_false_when_gateway_missing(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())

    def test_gateway_help_is_decoded_as_utf8(self):
        with patch("shutil.which", return_value="defenseclaw-gateway.exe"), patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run_mock.return_value.stdout = "teardown\nlist-backups\n"
            run_mock.return_value.stderr = ""
            self.assertTrue(cmd_uninstall._gateway_supports_connector_teardown())

        kwargs = run_mock.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertNotIn("text", kwargs)

    def test_returns_true_for_modern_gateway(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run_mock.return_value.stdout = "Available Commands:\n  list-backups ...\n  teardown ...\n  verify ...\n"
            run_mock.return_value.stderr = ""
            self.assertTrue(cmd_uninstall._gateway_supports_connector_teardown())

    def test_returns_false_when_help_lacks_subcommand(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run_mock.return_value.stdout = "Usage:\n  defenseclaw-gateway [command]\n"
            run_mock.return_value.stderr = ""
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())

    def test_returns_false_when_help_exits_nonzero(self):
        with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 1
            run_mock.return_value.stdout = ""
            run_mock.return_value.stderr = 'unknown command "connector"'
            self.assertFalse(cmd_uninstall._gateway_supports_connector_teardown())


class MCPWriterBackupRemovalTests(unittest.TestCase):
    def test_full_uninstall_removes_recorded_mcp_config_backups(self):
        # GAP-1699: the .defenseclaw-<name>.bak copies next to the agent
        # configs stayed after uninstall --all; files of the user stay.
        from defenseclaw.connector_paths import _managed_mcp_backup_path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / ".defenseclaw"
            registry_dir = data_dir / "connector_backups" / "mcp"
            registry_dir.mkdir(parents=True)
            config = root / ".codex" / "config.toml"
            config.parent.mkdir()
            config.write_text("[mcp_servers]\n")
            backup = Path(_managed_mcp_backup_path(str(config)))
            backup.write_text("copy")
            unrelated = config.parent / "notes.bak"
            unrelated.write_text("mine")
            registry = {
                "a": {"path": str(config), "backup": str(backup)},
                "b": {"path": str(config), "backup": str(unrelated)},
            }
            (registry_dir / "registry.json").write_text(json.dumps(registry))

            with capture_click_output() as buf:
                cmd_uninstall._remove_mcp_writer_backups(str(data_dir))

            self.assertFalse(backup.exists())
            self.assertTrue(unrelated.exists())
            self.assertTrue(config.exists())
            self.assertIn(str(backup), buf.getvalue())


class GatewayTeardownOutputTests(unittest.TestCase):
    def test_gateway_teardown_uses_utf8_and_preserves_checkmark(self):
        completed = type(
            "Completed",
            (),
            {"returncode": 0, "stdout": "✓ restored\n", "stderr": ""},
        )()
        with (
            patch("shutil.which", return_value="defenseclaw-gateway.exe"),
            patch("subprocess.run", return_value=completed) as run_mock,
            capture_click_output() as buf,
        ):
            self.assertTrue(cmd_uninstall._run_gateway_connector_teardown("codex"))

        self.assertIn("✓ restored", buf.getvalue())
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertNotIn("text", kwargs)

    def test_gateway_teardown_waits_for_a_slow_gateway(self):
        # GAP-1663: a no-op teardown took 108 s on a busy Windows home; the
        # fixed 60 s aborted every uninstall run there.
        completed = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with (
            patch("shutil.which", return_value="defenseclaw-gateway.exe"),
            patch("subprocess.run", return_value=completed) as run_mock,
            capture_click_output() as buf,
        ):
            self.assertTrue(cmd_uninstall._run_gateway_connector_teardown("codex"))

        self.assertIn("tearing down codex", buf.getvalue())
        timeouts = [call.kwargs["timeout"] for call in run_mock.call_args_list]
        self.assertEqual(len(timeouts), 2)  # teardown, then verify
        self.assertTrue(all(timeout >= 300 for timeout in timeouts), timeouts)

    def test_gateway_stop_uses_utf8(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": "✓ stopped\n", "stderr": ""})()
        with (
            patch("shutil.which", return_value="defenseclaw-gateway.exe"),
            patch("subprocess.run", return_value=completed) as run_mock,
        ):
            cmd_uninstall._stop_gateway()

        kwargs = run_mock.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        # GAP-2100: the gateway's own stop can take about 25s before it kills.
        self.assertTrue(all(call.kwargs["timeout"] >= 30 for call in run_mock.call_args_list))


class RemoveDataDirTests(unittest.TestCase):
    def test_reset_preserves_only_managed_venv_and_removes_all_user_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            venv = data_dir / ".venv"
            venv.mkdir(parents=True)
            (venv / "runtime.pyd").write_bytes(b"loaded")

            resettable = {
                "config.yaml": "config",
                "audit.db": "audit",
                "audit-history.db": "history",
                ".env": "tokens",
                "logs/gateway.log": "log",
                "policies/default.yaml": "policy",
                "quarantine/item": "quarantine",
                "connector_backups/codex/config.toml.json": "connector",
                "tokens/session": "token",
                "arbitrary/new-state.bin": "future state",
            }
            for relative, content in resettable.items():
                target = data_dir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

            cmd_uninstall._remove_data_dir(str(data_dir), preserve_entries=(".venv",))

            self.assertTrue(venv.is_dir())
            self.assertTrue((venv / "runtime.pyd").is_file())
            self.assertEqual({path.name for path in data_dir.iterdir()}, {".venv"})

    def test_full_uninstall_removes_managed_venv_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            (data_dir / ".venv").mkdir(parents=True)
            (data_dir / "config.yaml").write_text("config", encoding="utf-8")

            cmd_uninstall._remove_data_dir(str(data_dir))

            self.assertFalse(data_dir.exists())

    def test_mount_point_data_dir_is_emptied_and_kept(self):
        # GAP-1980: rmdir of a mount point fails with EBUSY; the contents are
        # gone, so the uninstall goes on to the binaries.
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            (data_dir / "policies").mkdir(parents=True)
            (data_dir / "config.yaml").write_text("config", encoding="utf-8")
            real_rmdir = os.rmdir

            def busy_rmdir(path, *args, **kwargs):
                if os.path.samefile(path, data_dir):
                    raise OSError(errno.EBUSY, "Device or resource busy", str(path))
                return real_rmdir(path, *args, **kwargs)

            out = io.StringIO()
            with patch.object(cmd_uninstall.os, "rmdir", side_effect=busy_rmdir), contextlib.redirect_stdout(out):
                cmd_uninstall._remove_data_dir(str(data_dir))

            self.assertTrue(data_dir.is_dir())
            self.assertEqual(list(data_dir.iterdir()), [])
            self.assertIn("mount point", out.getvalue())

    def test_binary_phase_accepts_the_emptied_mount_point(self):
        # GAP-1980: the binary phase re-validates the plan; the kept, empty
        # mount point must not fail the ownership-marker check.
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            gateway = bin_dir / "defenseclaw-gateway"
            gateway.write_text("bin", encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                data_dir=str(data_dir),
                install_root=str(bin_dir),
                gateway_path=str(gateway),
                binary_targets=(str(gateway),),
                remove_data_dir=True,
                remove_binaries=True,
            )
            # data_dir is what the data phase leaves on a mount point: empty.
            with contextlib.redirect_stdout(io.StringIO()):
                cmd_uninstall._remove_binaries(plan)
            self.assertFalse(gateway.exists())
            (data_dir / "unrelated.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(click.ClickException):
                cmd_uninstall._validate_plan(plan)

    def test_reset_rejects_symlinked_preserved_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / ".defenseclaw"
            outside = root / "outside"
            data_dir.mkdir()
            outside.mkdir()
            (data_dir / "config.yaml").write_text("config", encoding="utf-8")
            try:
                (data_dir / ".venv").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")

            with self.assertRaises(click.ClickException):
                cmd_uninstall._remove_data_dir(str(data_dir), preserve_entries=(".venv",))

            self.assertTrue(outside.is_dir())

    def test_partial_failure_retains_identity_marker_for_safe_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            marker = data_dir / "config.yaml"
            marker.write_text("config", encoding="utf-8")
            blocked = data_dir / "blocked.log"
            blocked.write_text("locked", encoding="utf-8")

            original_remove = cmd_uninstall._remove_tree_entry

            def fail_blocked(entry):
                if entry.name == "blocked.log":
                    raise OSError("access denied")
                original_remove(entry)

            with patch.object(cmd_uninstall, "_remove_tree_entry", side_effect=fail_blocked):
                with self.assertRaises(OSError):
                    cmd_uninstall._remove_data_dir(str(data_dir))

            self.assertTrue(marker.is_file())


class ExecutePlanConnectorTests(unittest.TestCase):
    """Lock down the polymorphic _execute_plan ordering: stop → teardown
    → OpenClaw plugin sweep → wipe → binaries.
    """

    def _common_patches(self):
        return [
            patch.object(cmd_uninstall, "_stop_gateway"),
            patch.object(cmd_uninstall, "_connector_teardown"),
            patch.object(cmd_uninstall, "_remove_plugin"),
            patch.object(cmd_uninstall, "_remove_data_dir"),
            patch.object(cmd_uninstall, "_remove_binaries"),
        ]

    def test_codex_plan_does_not_run_openclaw_plugin_sweep(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("codex",),
            data_dir="/tmp/dc",
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            stop_mock, teardown_mock, plugin_mock, wipe_mock, bin_mock = mocks
            cmd_uninstall._execute_plan(plan)
            stop_mock.assert_called_once()
            teardown_mock.assert_called_once_with(plan)
            plugin_mock.assert_not_called()
            wipe_mock.assert_not_called()
            bin_mock.assert_not_called()
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)

    def test_teardown_failure_aborts_before_wipe_or_binaries(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="codex",
            connectors=("codex",),
            data_dir="/tmp/dc",
            remove_data_dir=True,
            remove_binaries=True,
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            _, teardown_mock, _, wipe_mock, bin_mock = mocks
            teardown_mock.side_effect = click.ClickException("teardown failed")
            with self.assertRaises(click.ClickException):
                cmd_uninstall._execute_plan(plan)
            wipe_mock.assert_not_called()
            bin_mock.assert_not_called()
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)

    def test_openclaw_runs_remove_plugin_step(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="openclaw",
            connectors=("openclaw",),
            data_dir="/tmp/dc",
            remove_plugin=True,
        )
        ctx_mgrs = self._common_patches()
        try:
            mocks = [c.__enter__() for c in ctx_mgrs]
            _, teardown_mock, plugin_mock, _, _ = mocks
            cmd_uninstall._execute_plan(plan)
            teardown_mock.assert_called_once()
            plugin_mock.assert_called_once_with(plan)
        finally:
            for c in ctx_mgrs:
                c.__exit__(None, None, None)


class RemovePluginMessageTests(unittest.TestCase):
    """GAP-2497: after the openclaw teardown removed the plugin, the plugin
    step must not claim it "was not installed"."""

    def test_plugin_already_removed_by_teardown(self):
        plan = cmd_uninstall.UninstallPlan(
            connector="openclaw", connectors=("openclaw",), data_dir="/tmp/dc", remove_plugin=True
        )
        with (
            patch("defenseclaw.guardrail.uninstall_openclaw_plugin", return_value=""),
            capture_click_output() as out,
        ):
            cmd_uninstall._remove_plugin(plan)
        text = out.getvalue()
        self.assertIn("plugin already removed", text)
        self.assertNotIn("not installed", text)


def _completed(returncode: int, stderr: str = ""):
    return type("Completed", (), {"returncode": returncode, "stdout": "", "stderr": stderr})()


# On a host with a managed deployment `defenseclaw-gateway stop` refuses
# whenever this account's own gateway is not running; the uninstall used to
# treat that refusal as a failure and stop before the connector teardown.
@unittest.skipIf(sys.platform == "win32", "Linux and macOS managed hosts")
class StopGatewayOnAManagedHostTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name)
        self.gateway = self.data_dir / "defenseclaw-gateway"
        self.gateway.write_bytes(b"#!/bin/sh\n")
        self.plan = cmd_uninstall.UninstallPlan(
            platform_name=sys.platform, gateway_path=str(self.gateway), data_dir=str(self.data_dir)
        )
        self.refusal = _completed(1, "this computer's DefenseClaw is managed by your organization")

    def tearDown(self):
        self._tmp.cleanup()

    def _stop(self, *, managed: str | None):
        with (
            patch("defenseclaw.upgrade_shim.managed_deployment", return_value=managed),
            patch.object(cmd_uninstall.subprocess, "run", side_effect=[_completed(0), self.refusal]) as run,
        ):
            cmd_uninstall._stop_gateway(self.plan)
        self.assertEqual(run.call_args_list[1].args[0], [str(self.gateway), "stop"])

    def test_a_refused_stop_with_no_own_gateway_is_nothing_to_stop(self):
        self._stop(managed="/etc/defenseclaw/runtime.json")

    def test_a_refused_stop_while_this_accounts_gateway_runs_still_fails(self):
        (self.data_dir / "gateway.pid").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
        with self.assertRaises(click.ClickException) as raised:
            self._stop(managed="/etc/defenseclaw/runtime.json")
        self.assertIn("could not stop sidecar", str(raised.exception))


class OrphanCopilotPluginTests(unittest.TestCase):
    def test_orphan_managed_copilot_plugin_is_removed_without_a_managed_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin = Path(tmp) / ".copilot" / "installed-plugins" / "defenseclaw" / "defenseclaw"
            (plugin / "hooks").mkdir(parents=True)
            (plugin / "plugin.json").write_text(json.dumps(cmd_uninstall._COPILOT_PLUGIN_MANIFEST))
            command = "'/opt/dc/defenseclaw-hook' hook --connector copilot --enterprise-managed --event 'PreToolUse'"
            hooks = {"hooks": {"PreToolUse": [{"type": "command", "command": command, "timeout": 30}]}}
            (plugin / "hooks" / "hooks.json").write_text(json.dumps(hooks))
            with (
                patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp}, clear=False),
                patch("defenseclaw.upgrade_shim.managed_deployment", return_value="/managed"),
            ):
                cmd_uninstall._remove_orphan_copilot_plugin()
                self.assertTrue(plugin.exists(), "a managed deployment owns the plugin")
            with (
                patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp}, clear=False),
                patch("defenseclaw.upgrade_shim.managed_deployment", return_value=None),
            ):
                cmd_uninstall._remove_orphan_copilot_plugin()
            self.assertFalse(plugin.parent.exists())


class _BlockDefenseClawImports:
    """A meta path finder that fails any new defenseclaw import, as Python
    does once the data removal has deleted the venv this CLI runs from."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "defenseclaw" or fullname.startswith("defenseclaw."):
            raise ModuleNotFoundError(f"No module named {fullname!r}")
        return None


class ExecutePlanAfterVenvRemovalTests(unittest.TestCase):
    def test_all_binaries_finishes_after_the_venv_is_gone(self):
        # GAP-1397: a function-level import after the data removal raised
        # ModuleNotFoundError, so binary removal never ran.
        blocker = _BlockDefenseClawImports()
        evicted = {name: mod for name, mod in sys.modules.items() if name == "defenseclaw.bootstrap"}

        def remove_data(*_args, **_kwargs):
            for name in evicted:
                sys.modules.pop(name, None)
            sys.meta_path.insert(0, blocker)

        def restore():
            with contextlib.suppress(ValueError):
                sys.meta_path.remove(blocker)
            sys.modules.update(evicted)

        self.addCleanup(restore)
        plan = cmd_uninstall.UninstallPlan(
            platform_name="linux",
            data_dir="/tmp/dc-gap1397/.defenseclaw",
            install_root="/tmp/dc-gap1397/.local/bin",
            remove_data_dir=True,
            remove_binaries=True,
        )
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_stop_gateway"),
            patch.object(cmd_uninstall, "_remove_created_dirs"),
            patch.object(cmd_uninstall, "_remove_orphan_copilot_plugin"),
            patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=False),
            patch.object(cmd_uninstall, "_remove_data_dir", side_effect=remove_data),
            patch.object(cmd_uninstall, "_remove_empty_plugin_cache"),
            patch.object(cmd_uninstall, "remove_own_api_port_claims") as claims,
            patch.object(cmd_uninstall, "_remove_binaries") as binaries,
            capture_click_output(),
        ):
            result = cmd_uninstall._execute_plan(plan)

        self.assertTrue(result.succeeded)
        self.assertEqual([p.name for p in result.phases][-2:], ["data removal", "binary removal"])
        claims.assert_called_once_with()
        binaries.assert_called_once_with(plan)


class TurnGuardrailOffTests(unittest.TestCase):
    # GAP-1312: the default uninstall keeps the config; it must say that the
    # torn-down connectors no longer run, or status lists them as active and
    # the next gateway start sets their hooks up again.

    def test_kept_config_records_the_guardrail_off(self):
        from defenseclaw import config as config_module

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"DEFENSECLAW_CONFIG": ""}):
            cfg = config_module.load(data_dir=tmp)
            cfg.data_dir = tmp
            cfg.guardrail.enabled = True
            cfg.guardrail.mode = "action"
            cfg.save()
            self.assertTrue(config_module.config_path_for_data_dir(tmp).is_file())

            with capture_click_output():
                cmd_uninstall._turn_guardrail_off(tmp)

            kept = config_module.load(data_dir=tmp)
            self.assertFalse(kept.guardrail.enabled)
            self.assertEqual(kept.guardrail.mode, "action")

    def test_missing_config_is_not_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            cmd_uninstall._turn_guardrail_off(tmp)
            self.assertEqual(os.listdir(tmp), [])

    def test_only_the_default_uninstall_turns_it_off(self):
        for remove_data_dir, calls in ((False, 1), (True, 0)):
            with self.subTest(remove_data_dir=remove_data_dir):
                plan = cmd_uninstall.UninstallPlan(
                    connectors=("codex",), data_dir="/tmp/dc", remove_data_dir=remove_data_dir
                )
                with (
                    patch.object(cmd_uninstall, "_validate_plan"),
                    patch.object(cmd_uninstall, "_stop_gateway"),
                    patch.object(cmd_uninstall, "_connector_teardown"),
                    patch.object(cmd_uninstall, "_remove_data_dir"),
                    patch.object(cmd_uninstall, "_remove_empty_plugin_cache"),
                    patch.object(cmd_uninstall, "remove_own_api_port_claims"),
                    patch.object(cmd_uninstall, "_turn_guardrail_off") as turn_off,
                    capture_click_output(),
                ):
                    cmd_uninstall._execute_plan(plan)
                self.assertEqual(turn_off.call_count, calls)


class LauncherRemovedNextStepsTests(unittest.TestCase):
    """GAP-1923: --all without --binaries removed the defenseclaw launcher."""

    def test_next_steps_name_no_defenseclaw_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            gateway = bin_dir / "defenseclaw-gateway"
            gateway.write_text("gateway", encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                data_dir=str(Path(tmp) / ".defenseclaw"),
                install_root=str(bin_dir),
                remove_data_dir=True,
                binary_targets=(str(bin_dir / "defenseclaw"), str(gateway)),
                data_bound_launchers=(str(bin_dir / "defenseclaw"),),
            )
            with patch("defenseclaw.upgrade_shim.managed_deployment", return_value=None), \
                    capture_click_output() as buf:
                cmd_uninstall._render_kept_and_next_steps(plan)
        text = buf.getvalue()
        self.assertIn(f"{bin_dir}: defenseclaw-gateway (the defenseclaw command went with the data)", text)
        self.assertIn(f"rm -f {shlex.quote(str(gateway))}", text)
        self.assertIn("install.sh | bash", text)
        self.assertNotIn("the DefenseClaw commands", text)
        self.assertNotIn("  • set DefenseClaw up again:  defenseclaw", text)
        self.assertNotIn("defenseclaw uninstall --all", text)


class RetiredSourceInstallCopyTests(unittest.TestCase):
    """GAP-1929: copies a source install renamed aside go with --binaries."""

    def test_windows_plan_lists_the_retired_gateway_copy_and_helper_accepts_it(self):
        from defenseclaw.commands import windows_uninstall_helper

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            bin_dir = home / ".local" / "bin"
            bin_dir.mkdir(parents=True)
            retired = bin_dir / ".defenseclaw-gateway.exe.source-install-old-e9080aa812c842d58857a299fd53186e"
            retired.write_bytes(b"MZold")
            (bin_dir / ".claude.exe.source-install-old-0123").write_bytes(b"not ours")
            (bin_dir / "claude.exe.old.1").write_bytes(b"not ours")
            with patch.dict(os.environ, {"USERPROFILE": str(home)}):
                install_root, targets = cmd_uninstall._owned_binary_targets("win32")
            retired_targets = [target for target in targets if ".source-install-old-" in target]
            self.assertEqual(retired_targets, [str(retired)])

            managed_venv = home / ".defenseclaw" / ".venv"
            managed_venv.mkdir(parents=True)
            (bin_dir / "defenseclaw.cmd").write_text(
                f'@echo off\r\n"{managed_venv / "Scripts" / "defenseclaw.exe"}" %*\r\n', encoding="utf-8"
            )
            plan = {
                "install_root": install_root,
                "data_dir": str(home / ".defenseclaw"),
                "managed_venv": str(managed_venv),
                "protected_paths": [],
                "binary_targets": [str(retired)],
                "remove_data_dir": False,
            }
            _root, _data, accepted = windows_uninstall_helper._validate_plan(plan)
            self.assertEqual(accepted, [os.path.normcase(os.path.abspath(retired))])
            plan["binary_targets"] = [str(bin_dir / ".claude.exe.source-install-old-0123")]
            with self.assertRaises(ValueError):
                windows_uninstall_helper._validate_plan(plan)


if __name__ == "__main__":
    unittest.main()
