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

"""Unit tests for ``defenseclaw.migration_state``.

The cursor file is a public interface: ``defenseclaw migrations``
subcommands AND any external monitoring tooling read it. These tests
pin the on-disk schema and the load/save/bootstrap contract so a
future refactor can't silently change the JSON shape and break
operators who scripted around it.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone

from defenseclaw import migration_state


class TestStateRoundtrip(unittest.TestCase):
    """save() then load() reproduces the same ``MigrationState``."""

    def test_save_then_load_returns_equivalent_state(self):
        with tempfile.TemporaryDirectory() as data_dir:
            state = migration_state.MigrationState(
                schema=migration_state.CURRENT_SCHEMA_VERSION,
                package_version="0.5.0",
                applied=["0.3.0", "0.4.0", "0.5.0"],
                applied_at={
                    "0.3.0": migration_state.BOOTSTRAP_SENTINEL,
                    "0.4.0": "2026-04-29T11:22:00Z",
                    "0.5.0": "2026-05-04T20:31:55Z",
                },
            )
            migration_state.save(data_dir, state)

            loaded = migration_state.load(data_dir)

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.schema, state.schema)
        self.assertEqual(loaded.package_version, state.package_version)
        self.assertEqual(loaded.applied, state.applied)
        self.assertEqual(loaded.applied_at, state.applied_at)

    def test_save_writes_file_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(package_version="0.5.0"),
            )
            mode = stat.S_IMODE(os.stat(migration_state.state_path(data_dir)).st_mode)
        self.assertEqual(mode, 0o600, "cursor file must be 0o600 — owner-only")

    def test_save_is_atomic_no_temp_file_left_behind(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(package_version="0.5.0"),
            )
            stragglers = [
                f for f in os.listdir(data_dir)
                if f.startswith(".migration_state.") and f.endswith(".tmp")
            ]
        self.assertEqual(stragglers, [], "tempfile must be renamed away by os.replace")


class TestLoadFailureModes(unittest.TestCase):
    """All four "broken cursor" cases collapse to ``None`` so the
    caller (run_migrations) takes the bootstrap path."""

    def test_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as data_dir:
            self.assertIsNone(migration_state.load(data_dir))

    def test_empty_file_returns_none(self):
        with tempfile.TemporaryDirectory() as data_dir:
            with open(migration_state.state_path(data_dir), "w") as f:
                f.write("")
            self.assertIsNone(migration_state.load(data_dir))

    def test_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory() as data_dir:
            with open(migration_state.state_path(data_dir), "w") as f:
                f.write("{not valid")
            self.assertIsNone(migration_state.load(data_dir))

    def test_future_schema_returns_none(self):
        """Newer cursors written by a future build must be opaque to
        old loaders. Returning ``None`` forces ``defenseclaw
        migrations reset`` rather than silent data loss."""
        with tempfile.TemporaryDirectory() as data_dir:
            with open(migration_state.state_path(data_dir), "w") as f:
                json.dump(
                    {
                        "schema": migration_state.CURRENT_SCHEMA_VERSION + 1,
                        "package_version": "9.9.9",
                        "applied": [],
                        "applied_at": {},
                    },
                    f,
                )
            self.assertIsNone(migration_state.load(data_dir))

    def test_non_dict_returns_none(self):
        """A JSON list at the top level is a hand-edit error; refuse
        rather than guess at a structure."""
        with tempfile.TemporaryDirectory() as data_dir:
            with open(migration_state.state_path(data_dir), "w") as f:
                json.dump(["something", "else"], f)
            self.assertIsNone(migration_state.load(data_dir))

    def test_loader_filters_non_string_versions(self):
        """``applied: [123, "0.5.0"]`` returns only the string entry —
        we don't crash, we just drop the bad data so the operator's
        cursor stays usable."""
        with tempfile.TemporaryDirectory() as data_dir:
            with open(migration_state.state_path(data_dir), "w") as f:
                json.dump(
                    {
                        "schema": 1,
                        "package_version": "0.5.0",
                        "applied": [123, "0.5.0", None],
                        "applied_at": {"0.5.0": "ts"},
                    },
                    f,
                )
            loaded = migration_state.load(data_dir)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.applied, ["0.5.0"])


class TestBootstrap(unittest.TestCase):
    """Bootstrap rule: every registry version <= from_version is
    pre-marked as applied with the BOOTSTRAP_SENTINEL timestamp."""

    def test_pre_marks_versions_at_or_below_from_version(self):
        state = migration_state.bootstrap(
            None,
            from_version="0.4.0",
            package_version="0.5.0",
            registry_versions=["0.3.0", "0.4.0", "0.5.0"],
        )
        self.assertEqual(state.applied, ["0.3.0", "0.4.0"])
        self.assertEqual(
            state.applied_at["0.3.0"],
            migration_state.BOOTSTRAP_SENTINEL,
        )
        self.assertEqual(
            state.applied_at["0.4.0"],
            migration_state.BOOTSTRAP_SENTINEL,
        )
        self.assertNotIn("0.5.0", state.applied)
        self.assertEqual(state.package_version, "0.5.0")

    def test_empty_from_version_pre_marks_nothing(self):
        """A clean install has no prior version — bootstrap leaves the
        applied set empty so run_migrations applies the full registry."""
        state = migration_state.bootstrap(
            None,
            from_version="",
            package_version="0.5.0",
            registry_versions=["0.3.0", "0.4.0", "0.5.0"],
        )
        self.assertEqual(state.applied, [])

    def test_from_version_above_all_registry_marks_everything(self):
        """An operator who's somehow ahead of the bundled registry
        (downgrade case) gets every entry pre-marked — no migration
        re-runs unprompted."""
        state = migration_state.bootstrap(
            None,
            from_version="9.9.9",
            package_version="9.9.9",
            registry_versions=["0.3.0", "0.4.0", "0.5.0"],
        )
        self.assertEqual(state.applied, ["0.3.0", "0.4.0", "0.5.0"])

    def test_preserves_existing_state_entries(self):
        existing = migration_state.MigrationState(
            applied=["0.3.0"],
            applied_at={"0.3.0": "2025-01-01T00:00:00Z"},
        )
        state = migration_state.bootstrap(
            existing,
            from_version="0.5.0",
            package_version="0.5.0",
            registry_versions=["0.3.0", "0.4.0", "0.5.0"],
        )
        # 0.3.0's observed timestamp survives bootstrap; only the
        # new entries (0.4.0, 0.5.0) get the sentinel.
        self.assertEqual(state.applied_at["0.3.0"], "2025-01-01T00:00:00Z")
        self.assertEqual(
            state.applied_at["0.4.0"],
            migration_state.BOOTSTRAP_SENTINEL,
        )


class TestMarkApplied(unittest.TestCase):
    def test_marks_with_observed_timestamp_by_default(self):
        state = migration_state.MigrationState()
        fixed = datetime(2026, 5, 4, 20, 31, 55, tzinfo=timezone.utc)
        migration_state.mark_applied(
            state, "0.5.0", package_version="0.5.0", now=fixed,
        )
        self.assertEqual(state.applied, ["0.5.0"])
        self.assertEqual(state.applied_at["0.5.0"], "2026-05-04T20:31:55Z")
        self.assertEqual(state.package_version, "0.5.0")

    def test_bootstrap_flag_uses_sentinel(self):
        state = migration_state.MigrationState()
        migration_state.mark_applied(
            state, "0.5.0", package_version="0.5.0", bootstrap=True,
        )
        self.assertEqual(
            state.applied_at["0.5.0"],
            migration_state.BOOTSTRAP_SENTINEL,
        )

    def test_keeps_applied_sorted_ascending(self):
        state = migration_state.MigrationState()
        for ver in ("0.5.0", "0.3.0", "0.4.0", "1.0.0"):
            migration_state.mark_applied(state, ver, package_version=ver)
        self.assertEqual(state.applied, ["0.3.0", "0.4.0", "0.5.0", "1.0.0"])

    def test_marking_same_version_twice_does_not_duplicate(self):
        state = migration_state.MigrationState()
        migration_state.mark_applied(state, "0.5.0", package_version="0.5.0")
        migration_state.mark_applied(state, "0.5.0", package_version="0.5.0")
        self.assertEqual(state.applied, ["0.5.0"])

    def test_remarking_updates_timestamp(self):
        """A reapply (same-version upgrade) should refresh
        ``applied_at`` so the cursor shows when the last observed run
        happened, not the original bootstrap."""
        state = migration_state.MigrationState()
        ts1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        ts2 = datetime(2026, 6, 1, tzinfo=timezone.utc)
        migration_state.mark_applied(
            state, "0.5.0", package_version="0.5.0", now=ts1,
        )
        migration_state.mark_applied(
            state, "0.5.0", package_version="0.5.0", now=ts2,
        )
        self.assertEqual(state.applied_at["0.5.0"], "2026-06-01T00:00:00Z")


class TestUnmarkAndReset(unittest.TestCase):
    def test_unmark_removes_version_and_returns_true(self):
        state = migration_state.MigrationState(
            applied=["0.3.0", "0.4.0"],
            applied_at={"0.3.0": "ts1", "0.4.0": "ts2"},
        )
        self.assertTrue(migration_state.unmark(state, "0.3.0"))
        self.assertEqual(state.applied, ["0.4.0"])
        self.assertNotIn("0.3.0", state.applied_at)

    def test_unmark_unknown_version_returns_false(self):
        state = migration_state.MigrationState()
        self.assertFalse(migration_state.unmark(state, "0.5.0"))

    def test_reset_removes_existing_file(self):
        with tempfile.TemporaryDirectory() as data_dir:
            migration_state.save(
                data_dir,
                migration_state.MigrationState(package_version="0.5.0"),
            )
            self.assertTrue(migration_state.reset(data_dir))
            self.assertFalse(
                os.path.exists(migration_state.state_path(data_dir)),
            )

    def test_reset_returns_false_when_no_file(self):
        with tempfile.TemporaryDirectory() as data_dir:
            self.assertFalse(migration_state.reset(data_dir))


class TestIsApplied(unittest.TestCase):
    def test_returns_false_for_none_state(self):
        self.assertFalse(migration_state.is_applied(None, "0.5.0"))

    def test_returns_true_when_present(self):
        state = migration_state.MigrationState(applied=["0.5.0"])
        self.assertTrue(migration_state.is_applied(state, "0.5.0"))

    def test_returns_false_when_absent(self):
        state = migration_state.MigrationState(applied=["0.4.0"])
        self.assertFalse(migration_state.is_applied(state, "0.5.0"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
