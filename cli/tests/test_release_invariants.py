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
import runpy
import unittest
from pathlib import Path

from defenseclaw import __version__
from defenseclaw.migrations import MIGRATIONS, _ver_tuple

# Repo root is two parents up from this test file:
#   cli/tests/test_release_invariants.py → cli/tests → cli → <repo root>
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestReleaseInvariants(unittest.TestCase):
    def test_wheel_manifest_excludes_python_bytecode(self):
        """A release wheel must never carry worktree ``__pycache__`` files.

        During an in-place upgrade, stale bytecode can be valid for the first
        fresh migration interpreter long enough to hide newly installed
        functions. The release smoke checks the built ZIP; this source-level
        invariant fails earlier when the manifest exclusions are removed.
        """
        manifest = (_REPO_ROOT / "MANIFEST.in").read_text()
        self.assertIn("recursive-exclude cli __pycache__ *", manifest)
        self.assertIn("recursive-exclude cli *.py[cod]", manifest)

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

    def test_upgrade_manifest_generator_requires_known_migrations(self):
        """Future releases ship an upgrade-manifest.json so old local
        upgrade scripts can enforce mandatory migrations. The generated
        manifest must include every migration version at or below the
        package version."""
        generator = runpy.run_path(str(_REPO_ROOT / "scripts" / "generate-upgrade-manifest.py"))
        manifest = generator["build_manifest"]()
        expected = [version for version, _desc, _fn in MIGRATIONS if _ver_tuple(version) <= _ver_tuple(__version__)]
        self.assertEqual(manifest["release_version"], __version__)
        self.assertEqual(manifest["required_cli_migrations"], expected)
        if _ver_tuple(__version__) >= (0, 8, 4):
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(
                manifest["runtime_config_version"],
                generator["expected_runtime_config_version"](__version__),
            )
            self.assertEqual(
                manifest["release_artifacts"],
                generator["protected_release_artifacts"](__version__),
            )

    def test_stamped_0_8_4_manifest_is_protocol_one_reachable_protocol_two_controller(self):
        """Exercise the bridge release policy without stamping source files."""
        generator = runpy.run_path(str(_REPO_ROOT / "scripts" / "generate-upgrade-manifest.py"))
        baseline_policy = __import__("json").loads(
            (_REPO_ROOT / "release" / "upgrade-baselines.json").read_text(encoding="utf-8")
        )
        expected_sources = baseline_policy["published_baselines"]
        expected_windows = baseline_policy["platform_published_baselines"]["windows"]

        self.assertEqual(
            generator["release_upgrade_policy"]("0.8.4"),
            {
                "min_upgrade_protocol": 1,
                "tested_source_versions": expected_sources,
                "platform_tested_source_versions": {"windows": expected_windows},
            },
        )
        self.assertEqual(generator["controller_upgrade_protocol"](), 2)
        self.assertEqual(generator["runtime_config_version"](), 7)
        self.assertNotIn(
            "required_bridge_version",
            generator["release_upgrade_policy"]("0.8.4"),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
