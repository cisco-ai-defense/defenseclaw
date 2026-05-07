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

"""Release-time invariants for DefenseClaw.

These tests exist to catch authoring mistakes BEFORE a release ships:

* ``__version__`` and ``pyproject.toml::version`` drift apart — the
  classic "I bumped one but not the other" bug. Migration discovery
  inside ``run_migrations`` keys off ``__version__``; a stale
  ``pyproject.toml`` ships an artifact that thinks it's a different
  version than the runtime reports, and operators see migrations
  re-fire forever.
* The ``MIGRATIONS`` registry has malformed semver entries — the
  range comparison in ``run_migrations`` falls back to ``0`` for
  unparseable segments, which silently lumps ``0.5.0-rc1`` and
  ``0.5.0`` into the same bucket. Force canonical ``X.Y.Z`` here.
* ``MIGRATIONS`` is not sorted ascending — the cursor model tolerates
  out-of-order entries, but doctor output and changelog generators
  assume order. A test catches reorders during code review.
* Migration entries have empty descriptions or non-callable callables
  — both produce confusing failures only when an operator hits the
  upgrade flow. Catching them at unit-test time is cheap.

Run on every ``pytest`` invocation (no ``@unittest.skip`` markers).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from defenseclaw import __version__
from defenseclaw.migrations import MIGRATIONS, _ver_tuple

# Repo root is two parents up from this test file:
#   cli/tests/test_release_invariants.py → cli/tests → cli → <repo root>
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestReleaseInvariants(unittest.TestCase):
    def test_pyproject_version_matches_dunder(self):
        """Both files MUST agree.

        Why this matters: ``defenseclaw upgrade`` reads the live
        ``__version__`` to decide what migrations to bootstrap. The
        wheel artifact installed by ``upgrade`` is named from
        ``pyproject.toml::version``. If the two diverge, an upgrade
        downloads ``defenseclaw-0.5.0-...-whl`` but the post-install
        runtime reports ``__version__ == "0.4.0"`` — so on the next
        upgrade we'll bootstrap from 0.4.0 and re-run the 0.5.0
        migration despite it having shipped already.
        """
        pyproject = _REPO_ROOT / "pyproject.toml"
        self.assertTrue(
            pyproject.exists(),
            f"pyproject.toml not found at {pyproject} — adjust _REPO_ROOT",
        )
        text = pyproject.read_text()
        # First ``version = "..."`` under [project] (the only
        # version field in this file as of 0.5.0).
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        self.assertIsNotNone(m, "version field not found in pyproject.toml")
        self.assertEqual(
            m.group(1),
            __version__,
            f"pyproject.toml version ({m.group(1)!r}) must match "
            f"defenseclaw.__version__ ({__version__!r}). Bump both "
            "together — release artifacts and migration discovery "
            "rely on this invariant.",
        )

    def test_migration_registry_versions_are_canonical_semver(self):
        """``X.Y.Z`` only — no pre-release suffixes, no v-prefix.

        ``_ver_tuple`` coerces unparseable segments to 0, which would
        silently merge ``0.5.0-rc1`` with ``0.5.0`` and produce
        baffling double-applies. Force canonical form at registry
        registration time.
        """
        for ver, _desc, _fn in MIGRATIONS:
            self.assertRegex(
                ver,
                r"^\d+\.\d+\.\d+$",
                f"migration version {ver!r} must be canonical "
                f"semver X.Y.Z (no pre-release suffixes, no v-prefix)",
            )

    def test_migration_registry_is_sorted_ascending(self):
        """Doctor output, changelog generators, and ``defenseclaw
        migrations status`` all assume ascending order. Catch
        mis-orders at test time."""
        versions = [v for v, _, _ in MIGRATIONS]
        sorted_versions = sorted(versions, key=_ver_tuple)
        self.assertEqual(
            versions,
            sorted_versions,
            "MIGRATIONS list must be sorted ascending by semver. "
            f"got {versions}, expected {sorted_versions}",
        )

    def test_migration_descriptions_are_non_empty(self):
        """A blank description shows up in upgrade output as
        ``→ Migration 0.5.0: ``. Doctor output truncates to the
        description, so an empty one is functionally invisible."""
        for ver, desc, _fn in MIGRATIONS:
            self.assertTrue(
                desc and desc.strip(),
                f"migration {ver} must have a non-empty description",
            )

    def test_migration_callables_are_callable(self):
        """Catches typos like ``("0.5.0", "...", _migrate_0_5_O)`` —
        the registry takes a callable but Python doesn't validate it
        until the migration actually runs."""
        for ver, _desc, fn in MIGRATIONS:
            self.assertTrue(
                callable(fn),
                f"migration {ver} fn must be callable; got {type(fn).__name__}",
            )

    def test_migration_versions_are_unique(self):
        """Two entries at the same version means one of them silently
        runs first and the other "second" — order depends on list
        position, not anything semantically meaningful. Forbid."""
        versions = [v for v, _, _ in MIGRATIONS]
        self.assertEqual(
            len(versions),
            len(set(versions)),
            f"duplicate migration version in registry: {versions}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
