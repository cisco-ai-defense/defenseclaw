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
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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

from defenseclaw.commands import cmd_uninstall  # noqa: E402  (sys.path tweak above)
from defenseclaw.credential_protection import CredentialProtectionError  # noqa: E402


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
            self.assertIn("remove s-gw MCP", result.output)
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
            self.assertEqual(plan.preserve_data_entries, (".venv",))
            self.assertIn("preserve runtime:", result.output)

    def test_reset_failure_is_nonzero_and_never_reports_complete(self):
        runner = CliRunner()
        with (
            patch("defenseclaw.commands.cmd_uninstall._stop_gateway"),
            patch("defenseclaw.commands.cmd_uninstall._connector_teardown"),
            patch("defenseclaw.commands.cmd_uninstall._remove_credential_mcp"),
            patch("defenseclaw.commands.cmd_uninstall._remove_data_dir", side_effect=OSError("locked native module")),
        ):
            result = runner.invoke(cmd_uninstall.reset_cmd, ["--yes"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("gateway stop: succeeded", result.output)
        self.assertNotIn("connector teardown: succeeded", result.output)
        self.assertIn("data removal: failed", result.output)
        self.assertIn("locked native module", result.output)
        self.assertNotIn("Reset complete", result.output)


@unittest.skipIf(os.name == "nt", "POSIX source-install custody has separate Windows coverage")
class UnixOwnedCleanupTests(unittest.TestCase):
    @staticmethod
    def _write_source_marker(
        marker: Path,
        checkout: Path,
        *,
        gateway_sha256: str,
    ) -> None:
        marker.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "checkout_root": str(checkout),
                    "source_release": cmd_uninstall.__version__,
                    "source_install_compatibility_epoch": 2,
                    "runtime_config_version": 8,
                    "gateway_sha256": gateway_sha256,
                }
            ),
            encoding="utf-8",
        )

    def test_linux_plan_includes_source_ownership_marker(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"HOME": tmp}, clear=False),
            patch.object(cmd_uninstall.config_module, "default_data_path", return_value=Path(tmp) / ".defenseclaw"),
        ):
            plan = cmd_uninstall._build_plan(
                wipe_data=True,
                binaries=True,
                revert_openclaw=False,
                remove_plugin=False,
                platform_name="linux",
            )

        self.assertIn(".defenseclaw-source-root", tuple(Path(path).name for path in plan.binary_targets))

    def test_binary_removal_preserves_foreign_launcher_and_clears_source_owned_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            gateway = root / "defenseclaw-gateway"
            owned_litellm = root / "litellm"
            broken_owned_scanner = root / "mcp-scanner"
            foreign_scanner = root / "skill-scanner"
            foreign_scanner_link = root / "skill-scanner-api"
            broken_foreign_link = root / "mcp-scanner-api"
            marker = root / ".defenseclaw-source-root"
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            (source_bin / "litellm").write_text("source litellm", encoding="utf-8")
            cli.symlink_to(source_bin / "defenseclaw")
            owned_litellm.symlink_to(source_bin / "litellm")
            broken_owned_scanner.symlink_to(source_bin / "mcp-scanner")
            gateway.write_bytes(b"source gateway")
            gateway.chmod(0o700)
            foreign_scanner.write_text("foreign launcher", encoding="utf-8")
            outside = tmp_path / "outside-scanner"
            outside.write_text("foreign target", encoding="utf-8")
            foreign_scanner_link.symlink_to(outside)
            broken_foreign_link.symlink_to(tmp_path / "missing-foreign-scanner")
            self._write_source_marker(
                marker,
                checkout,
                gateway_sha256=hashlib.sha256(gateway.read_bytes()).hexdigest(),
            )
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                gateway_path=str(gateway),
                binary_targets=(
                    str(gateway),
                    str(cli),
                    str(owned_litellm),
                    str(broken_owned_scanner),
                    str(foreign_scanner),
                    str(foreign_scanner_link),
                    str(broken_foreign_link),
                    str(marker),
                ),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(cli.exists())
            self.assertFalse(gateway.exists())
            self.assertFalse(marker.exists())
            self.assertFalse(os.path.lexists(owned_litellm))
            self.assertFalse(os.path.lexists(broken_owned_scanner))
            self.assertEqual(foreign_scanner.read_text(encoding="utf-8"), "foreign launcher")
            self.assertTrue(os.path.lexists(foreign_scanner_link))
            self.assertTrue(os.path.lexists(broken_foreign_link))
            self.assertEqual(outside.read_text(encoding="utf-8"), "foreign target")
            custody = root / ".defenseclaw-install-custody"
            self.assertFalse(custody.exists())

    def test_source_custody_cleanup_resumes_after_marker_is_retired(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )
            real_unlink = cmd_uninstall.install_publish.os.unlink
            crashed = False

            def crash_during_discard(path, *args, **kwargs):
                nonlocal crashed
                real_unlink(path, *args, **kwargs)
                if str(path).startswith("retired-") and not crashed:
                    crashed = True
                    raise SystemExit("simulated process death during custody discard")

            with (
                patch.object(cmd_uninstall.install_publish.os, "unlink", side_effect=crash_during_discard),
                self.assertRaises(SystemExit),
            ):
                cmd_uninstall._remove_binaries(plan)

            custody = root / ".defenseclaw-install-custody"
            self.assertTrue(crashed)
            self.assertFalse(os.path.lexists(cli))
            self.assertFalse(marker.exists())
            self.assertTrue((custody / cmd_uninstall.install_publish.CUSTODY_DISCARD_MARKER).is_file())
            self.assertEqual(cmd_uninstall._posix_owned_binary_targets(plan), {})

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(custody.exists())

    def test_source_custody_cleanup_resumes_when_discard_dies_on_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )
            custody = root / ".defenseclaw-install-custody"
            real_discard = cmd_uninstall.install_publish.discard_custody

            with (
                patch.object(
                    cmd_uninstall.install_publish,
                    "discard_custody",
                    side_effect=SystemExit("simulated death on discard entry"),
                ),
                self.assertRaises(SystemExit),
            ):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(os.path.lexists(cli))
            self.assertFalse(marker.exists())
            self.assertTrue(cmd_uninstall.install_publish.custody_cleanup_armed(custody))

            with patch.object(cmd_uninstall.install_publish, "discard_custody", wraps=real_discard):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(custody.exists())

    def test_non_home_custody_cleanup_resumes_after_last_claim_is_retired(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "prefix" / "bin"
            managed_venv = tmp_path / "managed-venv"
            managed_bin = managed_venv / "bin"
            root.mkdir(parents=True)
            managed_bin.mkdir(parents=True)
            (managed_bin / "defenseclaw").write_text("managed cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(managed_bin / "defenseclaw")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                managed_venv=str(managed_venv),
                binary_targets=(str(cli),),
                remove_binaries=True,
            )
            custody = root.parent / ".defenseclaw-install-custody"
            real_discard = cmd_uninstall.install_publish.discard_custody

            with (
                patch.object(
                    cmd_uninstall.install_publish,
                    "discard_custody",
                    side_effect=SystemExit("simulated death before non-home custody discard"),
                ),
                self.assertRaises(SystemExit),
            ):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(cli.exists())
            self.assertTrue(cmd_uninstall.install_publish.custody_cleanup_armed(custody))
            self.assertEqual(cmd_uninstall._posix_owned_binary_targets(plan), {})

            with patch.object(cmd_uninstall.install_publish, "discard_custody", wraps=real_discard):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(custody.exists())

    def test_armed_source_custody_survives_preflight_failure_after_marker_retirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            custody = root / ".defenseclaw-install-custody"
            cmd_uninstall.install_publish.prepare_custody(custody, root)
            unknown = custody / "operator-note"
            unknown.write_text("preserve", encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            with self.assertRaisesRegex(OSError, "unexpected or incomplete"):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(os.path.lexists(cli))
            self.assertFalse(marker.exists())
            self.assertEqual(unknown.read_text(encoding="utf-8"), "preserve")
            self.assertTrue(cmd_uninstall.install_publish.custody_cleanup_armed(custody))

            unknown.unlink()
            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(custody.exists())

    def test_live_source_marker_does_not_hide_pending_release_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp).resolve() / "home"
            root = home / ".local" / "bin"
            checkout = home / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir(parents=True)
            source_bin.mkdir(parents=True)
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            release_custody = home / ".defenseclaw-install-custody"
            old_release = home / "old-release-entry"
            old_release.write_text("retired", encoding="utf-8")
            old_identity = cmd_uninstall.install_publish.path_identity(old_release)
            self.assertTrue(
                cmd_uninstall.install_publish.unlink_exact(
                    old_release,
                    old_identity,
                    custody_root=release_custody,
                )
            )
            cmd_uninstall.install_publish.arm_custody_discard(release_custody, home)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            with patch.dict(os.environ, {"HOME": str(home)}, clear=False):
                cmd_uninstall._remove_binaries(plan)

            self.assertFalse(release_custody.exists())
            self.assertFalse((root / ".defenseclaw-install-custody").exists())

    def test_custom_state_custody_is_removed_when_every_entry_is_proven(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            state_parent = tmp_path / "custom-state"
            root.mkdir()
            source_bin.mkdir(parents=True)
            state_parent.mkdir()
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            state_custody = state_parent / ".defenseclaw-install-custody"
            old_state = state_parent / "old-state"
            old_state.write_text("retired", encoding="utf-8")
            old_identity = cmd_uninstall.install_publish.path_identity(old_state)
            self.assertTrue(
                cmd_uninstall.install_publish.unlink_exact(old_state, old_identity, custody_root=state_custody)
            )
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                data_dir=str(state_parent / ".defenseclaw"),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(state_custody.exists())

    def test_custom_state_custody_recovers_interrupted_intent_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            state_parent = tmp_path / "custom-state"
            root.mkdir()
            source_bin.mkdir(parents=True)
            state_parent.mkdir()
            (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            state_custody = state_parent / ".defenseclaw-install-custody"
            cmd_uninstall.install_publish.prepare_custody(state_custody, state_parent)
            interrupted = state_custody / f"intent-{'a' * 64}.json.stage"
            interrupted.write_bytes(b"partial")
            interrupted.chmod(0o600)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                data_dir=str(state_parent / ".defenseclaw"),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(state_custody.exists())

    def test_custom_state_custody_preserves_unknown_entries_and_trees(self):
        for variant in ("unknown", "tree"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp).resolve()
                root = tmp_path / "bin"
                checkout = tmp_path / "checkout"
                source_bin = checkout / ".venv" / "bin"
                state_parent = tmp_path / "custom-state"
                root.mkdir()
                source_bin.mkdir(parents=True)
                state_parent.mkdir()
                (source_bin / "defenseclaw").write_text("source cli", encoding="utf-8")
                cli = root / "defenseclaw"
                cli.symlink_to(source_bin / "defenseclaw")
                marker = root / ".defenseclaw-source-root"
                self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
                state_custody = state_parent / ".defenseclaw-install-custody"
                if variant == "unknown":
                    cmd_uninstall.install_publish.prepare_custody(state_custody, state_parent)
                    preserved = state_custody / "operator-note"
                    preserved.write_text("preserve", encoding="utf-8")
                else:
                    tree = state_parent / "managed-tree"
                    tree.mkdir()
                    (tree / "state").write_text("preserve", encoding="utf-8")
                    tree_identity = cmd_uninstall.install_publish.path_identity(tree)
                    self.assertTrue(
                        cmd_uninstall.install_publish.remove_tree_exact(
                            tree,
                            tree_identity,
                            custody_root=state_custody,
                        )
                    )
                    preserved = next(state_custody.glob("retired-*")) / "state"
                plan = cmd_uninstall.UninstallPlan(
                    platform_name="linux",
                    install_root=str(root),
                    data_dir=str(state_parent / ".defenseclaw"),
                    binary_targets=(str(cli), str(marker)),
                    remove_binaries=True,
                )

                with self.assertRaisesRegex(OSError, "unresolved entries and was preserved"):
                    cmd_uninstall._remove_binaries(plan)

                self.assertEqual(preserved.read_text(encoding="utf-8"), "preserve")

    def test_no_claims_preserve_unrelated_source_custody_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "bin"
            root.mkdir()
            custody = root / ".defenseclaw-install-custody"
            custody.mkdir(mode=0o755)
            foreign = custody / "operator-note"
            foreign.write_text("preserve", encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(root / "defenseclaw"),),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertEqual(foreign.read_text(encoding="utf-8"), "preserve")

    def test_root_absent_invalid_close_intent_fails_visibly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "bin"
            root.mkdir()
            custody = root / ".defenseclaw-install-custody"
            close_intent = custody.parent / cmd_uninstall.install_publish._custody_close_name(custody)
            close_intent.write_bytes(b"invalid close intent\n")
            close_intent.chmod(0o600)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(root / "defenseclaw"),),
                remove_binaries=True,
            )

            with self.assertRaisesRegex(OSError, "close intent is invalid"):
                cmd_uninstall._remove_binaries(plan)

            self.assertEqual(close_intent.read_bytes(), b"invalid close intent\n")

    def test_missing_install_root_has_no_custody_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "missing" / "bin"
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(root / "defenseclaw"),),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(root.exists())

    def test_source_marker_symlink_refuses_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            source_bin = tmp_path / "checkout" / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            outside = tmp_path / "outside-marker"
            self._write_source_marker(outside, tmp_path / "checkout", gateway_sha256="0" * 64)
            marker = root / ".defenseclaw-source-root"
            marker.symlink_to(outside)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            with self.assertRaises(click.ClickException):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(os.path.lexists(cli))
            self.assertTrue(os.path.lexists(marker))
            self.assertTrue(outside.is_file())

    def test_utf16_source_marker_refuses_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            root.mkdir()
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, tmp_path / "checkout", gateway_sha256="0" * 64)
            marker.write_bytes(marker.read_text(encoding="utf-8").encode("utf-16"))
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(marker),),
                remove_binaries=True,
            )

            with self.assertRaisesRegex(click.ClickException, "not valid UTF-8 JSON"):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(marker.read_bytes().startswith((b"\xff\xfe", b"\xfe\xff")))

    def test_duplicate_source_marker_field_refuses_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            root.mkdir()
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, tmp_path / "checkout", gateway_sha256="0" * 64)
            raw = marker.read_bytes()
            marker.write_bytes(b'{"schema_version":2,' + raw.removeprefix(b"{"))
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(marker),),
                remove_binaries=True,
            )

            with self.assertRaisesRegex(click.ClickException, "duplicate field 'schema_version'"):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(marker.is_file())

    def test_newer_source_marker_refuses_before_launcher_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            payload = json.loads(marker.read_text(encoding="utf-8"))
            payload["runtime_config_version"] = 9
            marker.write_text(json.dumps(payload), encoding="utf-8")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            with self.assertRaisesRegex(click.ClickException, "newer than this checkout"):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(os.path.lexists(cli))
            self.assertTrue(marker.is_file())

    def test_gateway_digest_mismatch_refuses_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            gateway = root / "defenseclaw-gateway"
            gateway.write_bytes(b"unexpected gateway")
            gateway.chmod(0o700)
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                gateway_path=str(gateway),
                binary_targets=(str(cli), str(gateway), str(marker)),
                remove_binaries=True,
            )

            with self.assertRaises(click.ClickException):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(os.path.lexists(cli))
            self.assertTrue(gateway.is_file())
            self.assertTrue(marker.is_file())

    def test_gateway_digest_rejects_oversized_sparse_file_without_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = Path(tmp).resolve() / "defenseclaw-gateway"
            gateway.touch(mode=0o700)
            gateway.chmod(0o700)
            os.truncate(gateway, cmd_uninstall._MAX_GATEWAY_BINARY_BYTES + 1)

            with (
                patch.object(cmd_uninstall.os, "read", side_effect=AssertionError("gateway must not be read")),
                self.assertRaisesRegex(click.ClickException, "invalid size"),
            ):
                cmd_uninstall._posix_gateway_digest(str(gateway), "source-owned gateway")

    def test_owned_launcher_failure_preserves_source_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )

            with (
                patch.object(
                    cmd_uninstall.install_publish,
                    "unlink_exact_symlink",
                    side_effect=cmd_uninstall.install_publish.PublishError("locked"),
                ),
                self.assertRaises(OSError),
            ):
                cmd_uninstall._remove_binaries(plan)

            self.assertTrue(os.path.lexists(cli))
            self.assertTrue(marker.is_file())

    def test_release_cleanup_preserves_gateway_without_ownership_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / ".local" / "bin"
            managed_venv = tmp_path / ".defenseclaw" / ".venv"
            managed_bin = managed_venv / "bin"
            root.mkdir(parents=True)
            managed_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(managed_bin / "defenseclaw")
            gateway = root / "defenseclaw-gateway"
            gateway.write_bytes(b"release gateway")
            gateway.chmod(0o700)
            optional = root / "litellm"
            optional.symlink_to(managed_bin / "litellm")
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                managed_venv=str(managed_venv),
                gateway_path=str(gateway),
                binary_targets=(str(gateway), str(cli), str(optional)),
                remove_binaries=True,
            )

            cmd_uninstall._remove_binaries(plan)

            self.assertFalse(os.path.lexists(cli))
            self.assertEqual(gateway.read_bytes(), b"release gateway")
            self.assertTrue(os.path.lexists(optional))
            custody = tmp_path / ".defenseclaw-install-custody"
            self.assertFalse(custody.exists())

    def test_binary_path_swap_preserves_replacement_and_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            cli.symlink_to(source_bin / "defenseclaw")
            moved = root / "owned-away"
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )
            real_unlink = cmd_uninstall.install_publish.unlink_exact_symlink
            swapped = False

            def swap_before_unlink(path, identity, expected_targets, *, custody_root=None):
                nonlocal swapped
                if path == cli and not swapped:
                    swapped = True
                    cli.rename(moved)
                    cli.write_text("foreign replacement", encoding="utf-8")
                return real_unlink(path, identity, expected_targets, custody_root=custody_root)

            with (
                patch.object(
                    cmd_uninstall.install_publish,
                    "unlink_exact_symlink",
                    side_effect=swap_before_unlink,
                ),
                self.assertRaises(OSError),
            ):
                cmd_uninstall._remove_binaries(plan)

            self.assertEqual(cli.read_text(encoding="utf-8"), "foreign replacement")
            self.assertTrue(os.path.lexists(moved))
            self.assertTrue(marker.is_file())

    def test_readlink_aba_cannot_authorize_foreign_launcher_retirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            root = tmp_path / "bin"
            checkout = tmp_path / "checkout"
            source_bin = checkout / ".venv" / "bin"
            root.mkdir()
            source_bin.mkdir(parents=True)
            cli = root / "defenseclaw"
            foreign_target = tmp_path / "foreign" / "defenseclaw"
            cli.symlink_to(foreign_target)
            parked = root / "foreign-parked"
            marker = root / ".defenseclaw-source-root"
            self._write_source_marker(marker, checkout, gateway_sha256="0" * 64)
            plan = cmd_uninstall.UninstallPlan(
                platform_name="linux",
                install_root=str(root),
                binary_targets=(str(cli), str(marker)),
                remove_binaries=True,
            )
            real_readlink = os.readlink
            swaps = 0

            def swap_while_reading(path, *args, **kwargs):
                nonlocal swaps
                if kwargs.get("dir_fd") is None and os.fspath(path) == str(cli):
                    swaps += 1
                    cli.rename(parked)
                    cli.symlink_to(source_bin / "defenseclaw")
                    try:
                        return real_readlink(path, *args, **kwargs)
                    finally:
                        cli.unlink()
                        parked.rename(cli)
                return real_readlink(path, *args, **kwargs)

            with (
                patch.object(cmd_uninstall.os, "readlink", side_effect=swap_while_reading),
                self.assertRaises(OSError),
            ):
                cmd_uninstall._remove_binaries(plan)

            self.assertGreaterEqual(swaps, 2)
            self.assertEqual(os.readlink(cli), str(foreign_target))
            self.assertTrue(marker.is_file())


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
            ("defenseclaw.cmd", "defenseclaw-gateway.exe", "defenseclaw-hook.exe"),
        )
        self.assertEqual(plan.managed_venv, os.path.join(plan.data_dir, ".venv"))
        self.assertNotIn("defenseclaw.exe", tuple(Path(path).name for path in plan.binary_targets))

    def test_binary_only_removes_exact_targets_and_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp).resolve() / "kévin profile"
            root = profile / "bin"
            root.mkdir(parents=True)
            targets = tuple(
                str(root / name)
                for name in (
                    "defenseclaw.cmd",
                    "defenseclaw-gateway.exe",
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
        with (
            patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=True),
            capture_click_output() as output,
        ):
            cmd_uninstall._render_plan(plan, dry_run=True)
        rendered = output.getvalue()
        for target in plan.binary_targets:
            self.assertIn(target, rendered)
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


class ConnectorTeardownDispatchTests(unittest.TestCase):
    def _plan(self, connector: str) -> cmd_uninstall.UninstallPlan:
        return cmd_uninstall.UninstallPlan(
            connector=connector,
            connectors=(connector,),
            data_dir="/tmp/dc",
            openclaw_config_file="/tmp/openclaw.json",
            openclaw_home="/tmp/.openclaw",
        )

    def test_uses_gateway_sentinel_when_supported(self):
        with (
            patch.object(cmd_uninstall, "_gateway_supports_connector_teardown", return_value=True),
            patch.object(cmd_uninstall, "_run_gateway_connector_teardown", return_value=True) as run_mock,
            patch.object(cmd_uninstall, "_revert_openclaw_python") as fallback,
        ):
            cmd_uninstall._connector_teardown(self._plan("codex"))
            run_mock.assert_called_once_with("codex")
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


class OpenClawFallbackTests(unittest.TestCase):
    def test_missing_openclaw_config_is_already_reverted(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = cmd_uninstall.UninstallPlan(
                data_dir=os.path.join(tmp, ".defenseclaw"),
                openclaw_config_file=os.path.join(tmp, ".openclaw", "openclaw.json"),
            )
            with (
                capture_click_output() as output,
                patch("defenseclaw.guardrail.pristine_backup_path", return_value=""),
                patch("defenseclaw.guardrail.restore_openclaw_config") as restore,
            ):
                cmd_uninstall._revert_openclaw_python(plan)

        restore.assert_not_called()
        self.assertIn("already absent", output.getvalue())

    def test_existing_malformed_openclaw_config_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            openclaw_config = os.path.join(tmp, ".openclaw", "openclaw.json")
            os.makedirs(os.path.dirname(openclaw_config))
            with open(openclaw_config, "w", encoding="utf-8") as stream:
                stream.write("{malformed")
            plan = cmd_uninstall.UninstallPlan(
                data_dir=os.path.join(tmp, ".defenseclaw"),
                openclaw_config_file=openclaw_config,
            )
            with (
                patch("defenseclaw.guardrail.pristine_backup_path", return_value=""),
                patch("defenseclaw.guardrail.restore_openclaw_config", return_value=False) as restore,
                self.assertRaises(click.ClickException) as raised,
            ):
                cmd_uninstall._revert_openclaw_python(plan)

        restore.assert_called_once_with(openclaw_config, original_model="")
        self.assertIn("missing or malformed", str(raised.exception))

    def test_missing_target_with_pristine_backup_is_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            openclaw_config = os.path.join(tmp, ".openclaw", "openclaw.json")
            os.makedirs(os.path.dirname(openclaw_config))
            pristine = os.path.join(tmp, ".defenseclaw", "backups", "openclaw.json.pristine")
            os.makedirs(os.path.dirname(pristine))
            with open(pristine, "w", encoding="utf-8") as stream:
                stream.write('{"theme":"preserved"}\n')
            plan = cmd_uninstall.UninstallPlan(
                data_dir=os.path.join(tmp, ".defenseclaw"),
                openclaw_config_file=openclaw_config,
            )
            with patch("defenseclaw.guardrail.pristine_backup_path", return_value=pristine):
                cmd_uninstall._revert_openclaw_python(plan)

            with open(openclaw_config, encoding="utf-8") as stream:
                self.assertEqual(stream.read(), '{"theme":"preserved"}\n')


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


class CredentialMCPUninstallTests(unittest.TestCase):
    def test_cleanup_does_not_recreate_an_absent_data_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            plan = cmd_uninstall.UninstallPlan(data_dir=str(data_dir))
            with (
                patch.object(cmd_uninstall.config_module, "load") as load,
                patch("defenseclaw.credential_protection.remove_managed_mcp_connectors") as remove,
            ):
                cmd_uninstall._remove_credential_mcp(plan)

            load.assert_not_called()
            remove.assert_not_called()
            self.assertFalse(data_dir.exists())

    def test_cleanup_sweeps_known_connectors_when_config_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            cfg = SimpleNamespace(
                credential_protection=SimpleNamespace(enabled=False),
            )
            plan = cmd_uninstall.UninstallPlan(data_dir=str(data_dir))
            with (
                patch.object(cmd_uninstall.config_module, "load", return_value=cfg) as load,
                patch(
                    "defenseclaw.credential_protection.remove_managed_mcp_connectors",
                    return_value=[],
                ) as remove,
            ):
                cmd_uninstall._remove_credential_mcp(plan)

            load.assert_called_once_with(data_dir=str(data_dir))
            remove.assert_called_once_with(cfg, include_inactive=True)

    def test_cleanup_sweeps_inactive_connectors_and_disables_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            (data_dir / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
            saved: list[bool] = []
            cfg = SimpleNamespace(
                credential_protection=SimpleNamespace(enabled=True),
                save=lambda: saved.append(True),
            )
            results = [
                {
                    "connector": "codex",
                    "mcp_registration": "removed",
                    "changed": True,
                    "proxy_prompt_tokenization": "not_in_direct_upstream_path",
                }
            ]
            plan = cmd_uninstall.UninstallPlan(data_dir=str(data_dir))
            with (
                patch.object(cmd_uninstall.config_module, "load", return_value=cfg),
                patch(
                    "defenseclaw.credential_protection.remove_managed_mcp_connectors",
                    return_value=results,
                ) as remove,
            ):
                cmd_uninstall._remove_credential_mcp(plan)

            remove.assert_called_once_with(cfg, include_inactive=True)
            self.assertFalse(cfg.credential_protection.enabled)
            self.assertEqual(saved, [True])

    def test_cleanup_failure_stops_before_data_removal(self):
        plan = cmd_uninstall.UninstallPlan(
            data_dir="/tmp/dc",
            connectors=("codex",),
            remove_credential_mcp=True,
            remove_data_dir=True,
        )
        order: list[str] = []
        with (
            patch.object(cmd_uninstall, "_validate_plan"),
            patch.object(cmd_uninstall, "_stop_gateway"),
            patch.object(cmd_uninstall, "_connector_teardown", side_effect=lambda _: order.append("teardown")),
            patch.object(
                cmd_uninstall,
                "_remove_credential_mcp",
                side_effect=click.ClickException("injected MCP cleanup failure"),
            ),
            patch.object(cmd_uninstall, "_remove_data_dir", side_effect=lambda *_args, **_kwargs: order.append("wipe")),
        ):
            with self.assertRaises(click.ClickException):
                cmd_uninstall._execute_plan(plan)

        self.assertEqual(order, ["teardown"])

    def test_unproven_sgw_cleanup_blocks_data_removal_for_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            marker = data_dir / "module-repair-evidence"
            marker.write_text("preserve", encoding="utf-8")
            cfg = SimpleNamespace(
                credential_protection=SimpleNamespace(enabled=True),
            )
            plan = cmd_uninstall.UninstallPlan(
                data_dir=str(data_dir),
                remove_credential_mcp=True,
                remove_data_dir=True,
            )
            with (
                patch.object(cmd_uninstall, "_validate_plan"),
                patch.object(cmd_uninstall, "_stop_gateway"),
                patch.object(cmd_uninstall.config_module, "load", return_value=cfg),
                patch(
                    "defenseclaw.credential_protection.remove_managed_mcp_connectors",
                    side_effect=CredentialProtectionError("mcp_reconciliation_failed"),
                ),
                patch.object(cmd_uninstall, "_remove_data_dir") as remove_data,
            ):
                with self.assertRaises(click.ClickException) as caught:
                    cmd_uninstall._execute_plan(plan)

            self.assertIn("could not identify managed s-gw MCP registrations", str(caught.exception))
            remove_data.assert_not_called()
            self.assertTrue(marker.is_file())

    def test_cleanup_rolls_back_when_config_save_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".defenseclaw"
            data_dir.mkdir()
            (data_dir / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
            cfg = SimpleNamespace(
                credential_protection=SimpleNamespace(enabled=True),
                save=lambda: (_ for _ in ()).throw(OSError("injected save failure")),
            )
            results = [
                {
                    "connector": "codex",
                    "mcp_registration": "removed",
                    "changed": True,
                    "proxy_prompt_tokenization": "not_in_direct_upstream_path",
                }
            ]
            plan = cmd_uninstall.UninstallPlan(data_dir=str(data_dir))
            with (
                patch.object(cmd_uninstall.config_module, "load", return_value=cfg),
                patch(
                    "defenseclaw.credential_protection.remove_managed_mcp_connectors",
                    return_value=results,
                ),
                patch(
                    "defenseclaw.credential_protection.rollback_mcp_removal",
                    return_value=True,
                ) as rollback,
            ):
                with self.assertRaises(click.ClickException):
                    cmd_uninstall._remove_credential_mcp(plan)

            self.assertTrue(cfg.credential_protection.enabled)
            rollback.assert_called_once_with(cfg, results)


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


if __name__ == "__main__":
    unittest.main()
