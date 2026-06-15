# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Click runner tests for ``defenseclaw migrations``.

These are integration tests exercising the full command tree (group
+ subcommands + AppContext threading). Pure-logic tests for the
underlying state primitives live in ``test_migration_state.py``.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw import migration_state
from defenseclaw.commands.cmd_migrations import migrations_cmd
from defenseclaw.context import AppContext


def _runner_with_data_dir(data_dir: str):
    """Build a Click runner that injects an AppContext pointing at
    the supplied ``data_dir``.

    The migrations command is registered under ``defenseclaw cli``
    in ``main.py``, but for these tests we invoke the group
    directly to keep the surface narrow and avoid pulling in the
    full config-load machinery.
    """
    app = AppContext()

    class _Cfg:
        def __init__(self, d: str) -> None:
            self.data_dir = d

    app.cfg = _Cfg(data_dir)
    return CliRunner(), app


class TestMigrationsStatus(unittest.TestCase):
    def test_status_with_no_cursor_reports_absent(self):
        with tempfile.TemporaryDirectory() as data_dir:
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["status"], obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("absent", result.output)
        self.assertIn("first upgrade will bootstrap", result.output)

    def test_status_json_output_with_cursor(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(
                    package_version="0.5.0",
                    applied=["0.3.0", "0.4.0", "0.5.0"],
                    applied_at={
                        "0.3.0": migration_state.BOOTSTRAP_SENTINEL,
                        "0.4.0": "2026-04-29T11:22:00Z",
                        "0.5.0": "2026-05-04T20:31:55Z",
                    },
                ),
            )
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["status", "--json-output"], obj=app,
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertTrue(payload["cursor_present"])
        self.assertEqual(payload["package_version"], "0.5.0")
        self.assertEqual(
            [a["version"] for a in payload["applied"]],
            ["0.3.0", "0.4.0", "0.5.0"],
        )
        # Pending versions = registry minus applied (zero in this
        # synthetic case where applied covers the whole registry).
        self.assertIsInstance(payload["pending"], list)

    def test_status_surfaces_orphan_entries(self):
        """An entry in the cursor that has no registry callable
        should appear under "orphan" with a guidance message."""
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(
                    package_version="0.5.0",
                    applied=["0.5.0", "9.9.9"],  # 9.9.9 not in registry
                    applied_at={
                        "0.5.0": "ts",
                        "9.9.9": "ts",
                    },
                ),
            )
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["status", "--json-output"], obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertIn("9.9.9", payload["orphan"])


class TestMigrationsReset(unittest.TestCase):
    def test_reset_with_no_cursor_is_noop(self):
        with tempfile.TemporaryDirectory() as data_dir:
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["reset", "--yes"], obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("nothing to reset", result.output)

    def test_reset_with_yes_flag_removes_cursor(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(package_version="0.5.0"),
            )
            cursor_path = migration_state.state_path(data_dir)
            self.assertTrue(os.path.exists(cursor_path))

            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["reset", "--yes"], obj=app,
                catch_exceptions=False,
            )
            # Assertions inside the with-block — outside the block the
            # tempdir is already torn down and "file gone" is a false
            # positive even when the command never ran.
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(os.path.exists(cursor_path))

    def test_reset_aborts_on_no_confirm(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(package_version="0.5.0"),
            )
            cursor_path = migration_state.state_path(data_dir)

            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["reset"], obj=app,
                input="n\n", catch_exceptions=False,
            )

            self.assertEqual(result.exit_code, 0)
            self.assertIn("Aborted", result.output)
            self.assertTrue(os.path.exists(cursor_path))


class TestMigrationsUnmark(unittest.TestCase):
    def test_unmark_removes_specific_version(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(
                    package_version="0.5.0",
                    applied=["0.3.0", "0.4.0", "0.5.0"],
                    applied_at={"0.3.0": "ts", "0.4.0": "ts", "0.5.0": "ts"},
                ),
            )
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["unmark", "0.4.0", "--yes"], obj=app,
                catch_exceptions=False,
            )

            self.assertEqual(result.exit_code, 0)
            loaded = migration_state.load(data_dir)
            self.assertEqual(loaded.applied, ["0.3.0", "0.5.0"])
            self.assertNotIn("0.4.0", loaded.applied_at)

    def test_unmark_unknown_version_is_noop(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(
                    package_version="0.5.0",
                    applied=["0.5.0"],
                    applied_at={"0.5.0": "ts"},
                ),
            )
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["unmark", "9.9.9", "--yes"], obj=app,
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("not in the applied set", result.output)

    def test_unmark_with_no_cursor_is_noop(self):
        with tempfile.TemporaryDirectory() as data_dir:
            runner, app = _runner_with_data_dir(data_dir)
            result = runner.invoke(
                migrations_cmd, ["unmark", "0.5.0", "--yes"], obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("No cursor present", result.output)


class TestDataDirResolution(unittest.TestCase):
    """``_resolve_data_dir`` should honor cfg.data_dir, then env, then
    HOME — same precedence as run_migrations."""

    def test_uses_env_when_no_app_cfg(self):
        from defenseclaw.commands import cmd_migrations

        app = AppContext()
        app.cfg = None

        with tempfile.TemporaryDirectory() as env_dir, \
             patch.dict(os.environ, {"DEFENSECLAW_HOME": env_dir}):
            self.assertEqual(cmd_migrations._resolve_data_dir(app), env_dir)

    def test_prefers_cfg_data_dir_over_env(self):
        from defenseclaw.commands import cmd_migrations

        app = AppContext()

        class _Cfg:
            data_dir = "/from/cfg"

        app.cfg = _Cfg()
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": "/from/env"}):
            self.assertEqual(cmd_migrations._resolve_data_dir(app), "/from/cfg")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
