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

"""Unit tests for ``defenseclaw.bundle_refresh``.

Covers the rsync-style overwrite primitive, the Splunk + local
observability refresh wrappers (preserve / refresh contracts), and
the docker-ps-based running-stack detector. No real Docker calls are
made — :func:`is_compose_project_running` is exercised against a
mocked ``subprocess.run``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestRsyncOverwrite(unittest.TestCase):
    """Cover the low-level :func:`_rsync_overwrite` primitive."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-rsync-")
        self.src = os.path.join(self.tmp, "src")
        self.dest = os.path.join(self.tmp, "dest")
        os.makedirs(self.src)
        os.makedirs(self.dest)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, root: str, rel: str, contents: str) -> str:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(contents)
        return path

    def test_overwrites_dest_files_from_src(self) -> None:
        from defenseclaw.bundle_refresh import _rsync_overwrite

        self._write(self.src, "bin/run.sh", "new\n")
        self._write(self.dest, "bin/run.sh", "old\n")

        refreshed, preserved, errors = _rsync_overwrite(
            src=Path(self.src), dest=Path(self.dest), preserve=(),
        )

        self.assertEqual(errors, [])
        self.assertIn("bin/run.sh", refreshed)
        self.assertEqual(preserved, [])
        with open(os.path.join(self.dest, "bin/run.sh"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "new\n")

    def test_creates_missing_dest_subdirs(self) -> None:
        from defenseclaw.bundle_refresh import _rsync_overwrite

        self._write(self.src, "compose/docker-compose.local.yml", "new\n")

        refreshed, _preserved, errors = _rsync_overwrite(
            src=Path(self.src), dest=Path(self.dest), preserve=(),
        )

        self.assertEqual(errors, [])
        self.assertIn("compose/docker-compose.local.yml", refreshed)
        path = os.path.join(self.dest, "compose/docker-compose.local.yml")
        self.assertTrue(os.path.isfile(path))

    def test_preserves_files_listed_explicitly(self) -> None:
        from defenseclaw.bundle_refresh import _rsync_overwrite

        self._write(self.src, "env/.env", "new-secret\n")
        self._write(self.dest, "env/.env", "operator-secret\n")

        refreshed, preserved, errors = _rsync_overwrite(
            src=Path(self.src),
            dest=Path(self.dest),
            preserve=("env/.env",),
        )

        self.assertEqual(errors, [])
        self.assertNotIn("env/.env", refreshed)
        self.assertIn("env/.env", preserved)
        with open(os.path.join(self.dest, "env/.env"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "operator-secret\n")

    def test_preserves_whole_directory_subtree(self) -> None:
        from defenseclaw.bundle_refresh import _rsync_overwrite

        self._write(self.src, "splunk/build/app.tgz", "new-tarball\n")
        self._write(self.dest, "splunk/build/app.tgz", "old-tarball\n")
        self._write(self.dest, "splunk/build/old-only.txt", "operator-only\n")

        refreshed, preserved, errors = _rsync_overwrite(
            src=Path(self.src),
            dest=Path(self.dest),
            preserve=("splunk/build",),
        )

        self.assertEqual(errors, [])
        self.assertEqual(refreshed, [])
        self.assertIn("splunk/build", preserved)
        with open(os.path.join(self.dest, "splunk/build/app.tgz"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "old-tarball\n")
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "splunk/build/old-only.txt")))

    def test_does_not_prune_dest_only_files_outside_preserve(self) -> None:
        """A file present only in dest survives a refresh.

        The seeded copy can have generated artefacts (e.g.
        ``splunk/build/defenseclaw_local_mode.tgz``) that should not
        be deleted just because they don't appear in the source bundle.
        """
        from defenseclaw.bundle_refresh import _rsync_overwrite

        self._write(self.src, "bin/run.sh", "new\n")
        self._write(self.dest, "bin/run.sh", "old\n")
        self._write(self.dest, "bin/dest-only.sh", "i-stay\n")

        _refreshed, _preserved, errors = _rsync_overwrite(
            src=Path(self.src), dest=Path(self.dest), preserve=(),
        )

        self.assertEqual(errors, [])
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "bin/dest-only.sh")))


class TestRefreshSplunkBridge(unittest.TestCase):
    """Cover the :func:`refresh_splunk_bridge` wrapper."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-splunk-refresh-")
        self.bundle = tempfile.mkdtemp(prefix="dclaw-splunk-bundle-")

        os.makedirs(os.path.join(self.bundle, "bin"))
        with open(
            os.path.join(self.bundle, "bin", "splunk-claw-bridge"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("#!/usr/bin/env bash\n# new bridge\n")
        os.makedirs(os.path.join(self.bundle, "compose"))
        with open(
            os.path.join(self.bundle, "compose", "docker-compose.local.yml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("name: defenseclaw-splunk-local\n# new compose\n")
        os.makedirs(os.path.join(self.bundle, "env"))
        with open(
            os.path.join(self.bundle, "env", ".env.example"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("# example env (refreshed)\n")
        os.makedirs(os.path.join(self.bundle, "s3_exporter"))
        with open(
            os.path.join(self.bundle, "s3_exporter", "Dockerfile"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("# new s3 exporter\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.bundle, ignore_errors=True)

    def _seeded_dest(self) -> str:
        return os.path.join(self.tmp, "splunk-bridge")

    @patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir")
    def test_initial_seed_when_dest_missing(self, mock_bundle: MagicMock) -> None:
        from defenseclaw.bundle_refresh import refresh_splunk_bridge

        mock_bundle.return_value = Path(self.bundle)
        result = refresh_splunk_bridge(self.tmp)

        self.assertTrue(result.refreshed)
        self.assertEqual(result.refreshed_paths, ["(initial seed)"])
        bridge_bin = os.path.join(self._seeded_dest(), "bin", "splunk-claw-bridge")
        self.assertTrue(os.path.isfile(bridge_bin))
        self.assertTrue(os.access(bridge_bin, os.X_OK))

    @patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir")
    def test_refresh_overwrites_maintainer_files(self, mock_bundle: MagicMock) -> None:
        """A re-run after the bundle changes copies the new files
        across, ensuring operators who already ran ``init`` actually
        get bundle changes shipped post-PR-227 (s3_exporter, compose).
        """
        from defenseclaw.bundle_refresh import refresh_splunk_bridge

        mock_bundle.return_value = Path(self.bundle)
        # First seed.
        refresh_splunk_bridge(self.tmp)

        # Now bump bundle versions.
        with open(
            os.path.join(self.bundle, "compose", "docker-compose.local.yml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("name: defenseclaw-splunk-local\n# v2 compose\n")
        with open(
            os.path.join(self.bundle, "s3_exporter", "Dockerfile"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("# v2 s3 exporter\n")

        result = refresh_splunk_bridge(self.tmp)
        self.assertTrue(result.refreshed)
        self.assertIn("compose/docker-compose.local.yml", result.refreshed_paths)
        self.assertIn("s3_exporter/Dockerfile", result.refreshed_paths)

        with open(
            os.path.join(self._seeded_dest(), "compose", "docker-compose.local.yml"),
            encoding="utf-8",
        ) as handle:
            self.assertIn("v2 compose", handle.read())
        with open(
            os.path.join(self._seeded_dest(), "s3_exporter", "Dockerfile"),
            encoding="utf-8",
        ) as handle:
            self.assertIn("v2 s3 exporter", handle.read())

    @patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir")
    def test_refresh_preserves_operator_env_dotenv(self, mock_bundle: MagicMock) -> None:
        """``env/.env`` carries operator secrets (SPLUNK_PASSWORD, AWS
        keys) and must never be overwritten by a refresh.
        """
        from defenseclaw.bundle_refresh import refresh_splunk_bridge

        mock_bundle.return_value = Path(self.bundle)
        refresh_splunk_bridge(self.tmp)

        operator_env = os.path.join(self._seeded_dest(), "env", ".env")
        with open(operator_env, "w", encoding="utf-8") as handle:
            handle.write("SPLUNK_PASSWORD=do-not-overwrite\n")

        # Now ship a new bundle that includes a stale env/.env we
        # should NOT honour.
        with open(
            os.path.join(self.bundle, "env", ".env"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("SPLUNK_PASSWORD=stale-from-bundle\n")

        result = refresh_splunk_bridge(self.tmp)
        self.assertIn("env/.env", result.preserved_paths)
        self.assertNotIn("env/.env", result.refreshed_paths)
        with open(operator_env, encoding="utf-8") as handle:
            self.assertIn("do-not-overwrite", handle.read())

    @patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir")
    def test_refresh_preserves_generated_app_tarball(self, mock_bundle: MagicMock) -> None:
        from defenseclaw.bundle_refresh import refresh_splunk_bridge

        mock_bundle.return_value = Path(self.bundle)
        refresh_splunk_bridge(self.tmp)

        build_dir = os.path.join(self._seeded_dest(), "splunk", "build")
        os.makedirs(build_dir, exist_ok=True)
        tarball = os.path.join(build_dir, "defenseclaw_local_mode.tgz")
        with open(tarball, "wb") as handle:
            handle.write(b"\x1f\x8b\x08\x00fake")  # gzip magic + junk

        # A new bundle that ships a different tarball — we should not
        # ferry it over because we always rebuild from app source via
        # package_local_mode_app.sh on `up`.
        os.makedirs(os.path.join(self.bundle, "splunk", "build"), exist_ok=True)
        with open(
            os.path.join(self.bundle, "splunk", "build", "defenseclaw_local_mode.tgz"),
            "wb",
        ) as handle:
            handle.write(b"NEW")

        refresh_splunk_bridge(self.tmp)
        with open(tarball, "rb") as handle:
            data = handle.read()
        self.assertNotEqual(data, b"NEW")  # operator artefact survived

    @patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir")
    def test_missing_bundle_returns_skipped(self, mock_bundle: MagicMock) -> None:
        from defenseclaw.bundle_refresh import refresh_splunk_bridge

        mock_bundle.return_value = Path(self.bundle) / "does-not-exist"
        result = refresh_splunk_bridge(self.tmp)

        self.assertFalse(result.refreshed)
        self.assertIsNotNone(result.skipped_reason)
        self.assertFalse(os.path.isdir(self._seeded_dest()))


class TestRefreshLocalObservabilityStack(unittest.TestCase):
    """Cover :func:`refresh_local_observability_stack`."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-obs-refresh-")
        self.bundle = tempfile.mkdtemp(prefix="dclaw-obs-bundle-")

        os.makedirs(os.path.join(self.bundle, "bin"))
        with open(
            os.path.join(self.bundle, "bin", "openclaw-observability-bridge"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("#!/usr/bin/env bash\n# v2 bridge\n")
        with open(os.path.join(self.bundle, "run.sh"), "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\n# v2 shim\n")
        with open(
            os.path.join(self.bundle, "docker-compose.yml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("# v2 compose\n")
        os.makedirs(os.path.join(self.bundle, "grafana", "dashboards"))
        with open(
            os.path.join(self.bundle, "grafana", "dashboards", "overview.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write('{"title": "bundled-v2"}\n')
        os.makedirs(os.path.join(self.bundle, "prometheus"))
        with open(
            os.path.join(self.bundle, "prometheus", "prometheus.yml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("# v2 prometheus\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.bundle, ignore_errors=True)

    def _dest(self) -> str:
        return os.path.join(self.tmp, "observability-stack")

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_default_refresh_preserves_operator_dashboards(
        self, mock_bundle: MagicMock,
    ) -> None:
        """The default refresh must not stomp on operator-edited dashboards."""
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        refresh_local_observability_stack(self.tmp)

        dashboards = os.path.join(self._dest(), "grafana", "dashboards")
        os.makedirs(dashboards, exist_ok=True)
        operator = os.path.join(dashboards, "overview.json")
        with open(operator, "w", encoding="utf-8") as handle:
            handle.write('{"title": "operator-edited"}\n')
        operator_prom = os.path.join(self._dest(), "prometheus", "prometheus.yml")
        with open(operator_prom, "w", encoding="utf-8") as handle:
            handle.write("# operator-edited prometheus\n")

        # Bump bridge in the bundle to drive a maintainer-file refresh.
        with open(
            os.path.join(self.bundle, "bin", "openclaw-observability-bridge"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write("#!/usr/bin/env bash\n# v3 bridge\n")

        result = refresh_local_observability_stack(self.tmp)
        self.assertIn("bin/openclaw-observability-bridge", result.refreshed_paths)
        self.assertIn("grafana", result.preserved_paths)
        self.assertIn("prometheus", result.preserved_paths)

        with open(operator, encoding="utf-8") as handle:
            self.assertIn("operator-edited", handle.read())
        with open(operator_prom, encoding="utf-8") as handle:
            self.assertIn("operator-edited prometheus", handle.read())
        bridge_bin = os.path.join(
            self._dest(), "bin", "openclaw-observability-bridge",
        )
        with open(bridge_bin, encoding="utf-8") as handle:
            self.assertIn("v3 bridge", handle.read())
        self.assertTrue(os.access(bridge_bin, os.X_OK))

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_refresh_config_overwrites_operator_surfaces(
        self, mock_bundle: MagicMock,
    ) -> None:
        """``refresh_config=True`` is the destructive mode operators opt
        into when they want a clean wipe of dashboards / rules /
        configs to match the new bundle.
        """
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        refresh_local_observability_stack(self.tmp)

        # Operator edit in place...
        operator = os.path.join(self._dest(), "grafana", "dashboards", "overview.json")
        with open(operator, "w", encoding="utf-8") as handle:
            handle.write('{"title": "operator-edited"}\n')

        # ...gets overwritten when explicit opt-in is passed.
        result = refresh_local_observability_stack(self.tmp, refresh_config=True)
        self.assertIn("grafana/dashboards/overview.json", result.refreshed_paths)
        self.assertNotIn("grafana", result.preserved_paths)
        with open(operator, encoding="utf-8") as handle:
            self.assertIn("bundled-v2", handle.read())

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_refresh_config_removes_only_retired_managed_dashboards(
        self, mock_bundle: MagicMock,
    ) -> None:
        """Upgrade tombstones prune retired DefenseClaw assets without
        deleting destination-only operator dashboards.
        """
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        refresh_local_observability_stack(self.tmp)
        dashboards = os.path.join(self._dest(), "grafana", "dashboards")
        retired = os.path.join(dashboards, "defenseclaw-reliability.json")
        custom = os.path.join(dashboards, "team-custom.json")
        with open(retired, "w", encoding="utf-8") as handle:
            handle.write('{"title": "retired"}\n')
        with open(custom, "w", encoding="utf-8") as handle:
            handle.write('{"title": "custom"}\n')

        result = refresh_local_observability_stack(self.tmp, refresh_config=True)

        self.assertFalse(os.path.exists(retired))
        self.assertTrue(os.path.exists(custom))
        self.assertIn(
            "grafana/dashboards/defenseclaw-reliability.json (removed)",
            result.refreshed_paths,
        )

    def test_retired_path_tombstones_reject_traversal_and_external_symlinks(self) -> None:
        from defenseclaw.bundle_refresh import _remove_retired_paths

        root = Path(self._dest())
        root.mkdir(parents=True)
        outside = Path(self.tmp) / "outside.json"
        outside.write_text("keep me\n", encoding="utf-8")
        link = root / "external-link.json"
        retired = ["../outside.json"]
        symlink_created = False
        try:
            link.symlink_to(outside)
            retired.append("external-link.json")
            symlink_created = True
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
                raise

        removed, errors = _remove_retired_paths(
            root,
            tuple(retired),
        )

        self.assertEqual(removed, [])
        self.assertEqual(len(errors), len(retired))
        self.assertTrue(outside.exists())
        if symlink_created:
            self.assertTrue(link.is_symlink())

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_refresh_rejects_destination_reparse_escape(
        self, mock_bundle: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        refresh_local_observability_stack(self.tmp, refresh_config=True)
        outside = Path(self.tmp) / "outside"
        outside.mkdir()
        marker = outside / "overview.json"
        marker.write_text("outside unchanged\n", encoding="utf-8")
        grafana = Path(self._dest()) / "grafana"
        shutil.rmtree(grafana)
        try:
            grafana.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                created = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        (
                            "New-Item -ItemType Junction -Path $env:DC_TEST_LINK "
                            "-Target $env:DC_TEST_TARGET | Out-Null"
                        ),
                    ],
                    env={
                        **os.environ,
                        "DC_TEST_LINK": str(grafana),
                        "DC_TEST_TARGET": str(outside),
                    },
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
            else:
                raise

        result = refresh_local_observability_stack(self.tmp, refresh_config=True)

        self.assertTrue(result.errors)
        self.assertIn("escapes canonical bundle root", " ".join(result.errors))
        self.assertEqual(marker.read_text(encoding="utf-8"), "outside unchanged\n")

    @unittest.skipUnless(os.name == "nt", "Windows locked-file replacement semantics")
    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_locked_file_is_reported_and_left_unchanged(
        self, mock_bundle: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        refresh_local_observability_stack(self.tmp, refresh_config=True)
        target = Path(self._dest()) / "docker-compose.yml"
        original = target.read_bytes()
        (Path(self.bundle) / "docker-compose.yml").write_bytes(b"# changed\r\n")
        with target.open("rb"):
            result = refresh_local_observability_stack(self.tmp, refresh_config=True)

        self.assertTrue(result.errors)
        self.assertEqual(target.read_bytes(), original)

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_unicode_path_and_crlf_are_copied_byte_exactly(
        self, mock_bundle: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        unicode_root = Path(self.tmp) / "Profile Ω with spaces"
        unicode_root.mkdir()
        compose = Path(self.bundle) / "docker-compose.yml"
        compose.write_bytes(b"name: defenseclaw-observability\r\nservices: {}\r\n")
        mock_bundle.return_value = Path(self.bundle)

        result = refresh_local_observability_stack(
            str(unicode_root), refresh_config=True
        )

        self.assertFalse(result.errors)
        copied = unicode_root / "observability-stack" / "docker-compose.yml"
        self.assertEqual(copied.read_bytes(), compose.read_bytes())

    @patch("defenseclaw.bundle_refresh.bundled_local_observability_dir")
    def test_refresh_rejects_reparse_data_directory(
        self, mock_bundle: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import refresh_local_observability_stack

        mock_bundle.return_value = Path(self.bundle)
        actual = Path(self.tmp) / "actual-data"
        actual.mkdir()
        nominal = Path(self.tmp) / "linked-data"
        try:
            nominal.symlink_to(actual, target_is_directory=True)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                created = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        (
                            "New-Item -ItemType Junction -Path $env:DC_TEST_LINK "
                            "-Target $env:DC_TEST_TARGET | Out-Null"
                        ),
                    ],
                    env={
                        **os.environ,
                        "DC_TEST_LINK": str(nominal),
                        "DC_TEST_TARGET": str(actual),
                    },
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
            else:
                raise

        result = refresh_local_observability_stack(
            str(nominal), refresh_config=True
        )

        self.assertTrue(result.errors)
        self.assertIn("reparse/symlink", " ".join(result.errors))
        self.assertFalse((actual / "observability-stack").exists())


class TestIsComposeProjectRunning(unittest.TestCase):
    """Cover :func:`is_compose_project_running`."""

    @patch("defenseclaw.bundle_refresh.shutil.which", return_value=None)
    def test_returns_false_without_docker_binary(self, _which: MagicMock) -> None:
        from defenseclaw.bundle_refresh import is_compose_project_running

        self.assertFalse(is_compose_project_running("any-project"))

    @patch("defenseclaw.bundle_refresh.subprocess.run")
    @patch("defenseclaw.bundle_refresh.shutil.which", return_value="/usr/bin/docker")
    def test_returns_true_when_docker_lists_a_container_id(
        self, _which: MagicMock, mock_run: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import is_compose_project_running

        mock_run.return_value = MagicMock(returncode=0, stdout="abc123\n", stderr="")
        self.assertTrue(is_compose_project_running("defenseclaw-splunk-local"))
        # Confirm we asked docker for the right project label.
        called_args = mock_run.call_args.args[0]
        self.assertIn(
            "label=com.docker.compose.project=defenseclaw-splunk-local",
            called_args,
        )

    @patch("defenseclaw.bundle_refresh.subprocess.run")
    @patch("defenseclaw.bundle_refresh.shutil.which", return_value="/usr/bin/docker")
    def test_returns_false_when_docker_lists_no_containers(
        self, _which: MagicMock, mock_run: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import is_compose_project_running

        mock_run.return_value = MagicMock(returncode=0, stdout="\n", stderr="")
        self.assertFalse(is_compose_project_running("any-project"))

    @patch(
        "defenseclaw.bundle_refresh.subprocess.run",
        side_effect=OSError("broken pipe"),
    )
    @patch("defenseclaw.bundle_refresh.shutil.which", return_value="/usr/bin/docker")
    def test_returns_false_on_docker_exec_error(
        self, _which: MagicMock, _run: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import is_compose_project_running

        # OSError must NOT propagate — callers treat False as
        # "nothing to stop".
        self.assertFalse(is_compose_project_running("any-project"))


if __name__ == "__main__":
    unittest.main()
