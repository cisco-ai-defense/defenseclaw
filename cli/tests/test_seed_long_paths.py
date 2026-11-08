"""The packaged-data seeds work on a long profile folder (Windows MAX_PATH).

A per-user Windows account whose profile folder is about 100 characters has a
packaged Splunk app file 266 characters long, past the 260-character limit.
The first run used to fail on it and roll back; a copy that cannot be made for
the optional Splunk bridge is now a warning, and the copies themselves are not
limited by MAX_PATH. A seed the first run needs still fails it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defenseclaw import long_paths
from defenseclaw.bootstrap import FirstRunOptions, bootstrap_env, run_first_run
from defenseclaw.bundle_refresh import _rsync_overwrite, refresh_splunk_bridge
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    OpenShellConfig,
)

from tests.helpers import record_test_setup_agent_selections

_DEEP_DIRS = ("splunk", "apps", "defenseclaw_local_mode", "default", "data", "ui", "views")
_DEEP_FILE = "executive_agent_watch_overview.xml"
_DEEP_BODY = "<view/>\n"


def _make_deep_bundle(parent: str) -> str:
    """A bridge bundle whose root name is long, so a file below it is past 260 characters."""

    root = os.path.join(parent, "b" * 120)
    deep = os.path.join(root, *_DEEP_DIRS)
    os.makedirs(long_paths.extended(deep))
    with open(long_paths.extended(os.path.join(deep, _DEEP_FILE)), "w", encoding="utf-8") as handle:
        handle.write(_DEEP_BODY)
    os.makedirs(long_paths.extended(os.path.join(root, "bin")))
    with open(long_paths.extended(os.path.join(root, "bin", "splunk-claw-bridge")), "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n")
    return root


def _deep_file(dest: str) -> str:
    return long_paths.extended(os.path.join(dest, *_DEEP_DIRS, _DEEP_FILE))


def _cfg_for(tmp: str) -> Config:
    tmp = os.path.realpath(tmp)
    return Config(
        data_dir=tmp,
        audit_db=os.path.join(tmp, "audit.db"),
        quarantine_dir=os.path.join(tmp, "quarantine"),
        plugin_dir=os.path.join(tmp, "plugins"),
        policy_dir=os.path.join(tmp, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )


def _failing_copytree(match: str):
    """A shutil.copytree that leaves a partial copy and fails for a destination containing *match*."""

    real = shutil.copytree

    def copytree(src, dst, *args, **kwargs):
        if match in str(dst):
            os.makedirs(dst)
            with open(os.path.join(dst, "partial.txt"), "w", encoding="utf-8") as handle:
                handle.write("x")
            raise OSError(3, "The system cannot find the path specified", str(dst))
        return real(src, dst, *args, **kwargs)

    return copytree


class SeedLongPathTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = os.path.realpath(self._tmp.name)
        self.bundle = _make_deep_bundle(os.path.join(self.tmp, "src"))
        self.addCleanup(long_paths.rmtree, os.path.join(self.tmp, "src"))
        env = patch.dict(
            os.environ,
            {
                "DEFENSECLAW_HOME": os.path.join(self.tmp, "home"),
                "DEFENSECLAW_GATEWAY_TOKEN": "",
                "OPENCLAW_GATEWAY_TOKEN": "",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        bundle = patch("defenseclaw.paths.bundled_splunk_bridge_dir", return_value=Path(self.bundle))
        bundle.start()
        self.addCleanup(bundle.stop)

    def test_bootstrap_seeds_a_bridge_file_past_max_path_into_a_long_data_dir(self):
        data_dir = os.path.join(self.tmp, "p" * 110)
        report = bootstrap_env(_cfg_for(data_dir))

        self.assertEqual(report.errors, [], msg=report.errors)
        self.assertEqual(report.warnings, [], msg=report.warnings)
        with open(_deep_file(os.path.join(data_dir, "splunk-bridge")), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), _DEEP_BODY)

    def test_bridge_copy_failure_warns_names_the_path_and_leaves_no_partial_copy(self):
        data_dir = os.path.join(self.tmp, "home")
        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("splunk-bridge")):
            report = bootstrap_env(_cfg_for(data_dir))

        dest = os.path.join(os.path.realpath(data_dir), "splunk-bridge")
        self.assertEqual(report.errors, [], msg=report.errors)
        self.assertEqual(len(report.warnings), 1, msg=report.warnings)
        self.assertIn(dest, report.warnings[0])
        self.assertFalse(os.path.lexists(dest))

    def test_guardrail_profile_copy_failure_is_still_an_error(self):
        data_dir = os.path.join(self.tmp, "home")
        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("guardrail")):
            report = bootstrap_env(_cfg_for(data_dir))

        self.assertTrue(any(error.startswith("seed guardrail profile") for error in report.errors), report.errors)

    def test_first_run_completes_with_a_warning_when_the_bridge_cannot_be_copied(self):
        with (
            patch("defenseclaw.agent_selection.record_setup_agent_selections", side_effect=record_test_setup_agent_selections),
            patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("splunk-bridge")),
        ):
            report = run_first_run(
                FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False, verify=False)
            )

        self.assertNotEqual(report.status, "needs_attention", [s.to_dict() for s in report.setup])
        warns = [s for s in report.setup if s.name == "Bootstrap" and s.status == "warn"]
        self.assertEqual(len(warns), 1, [s.to_dict() for s in report.setup])
        self.assertIn("splunk-bridge", warns[0].detail)
        self.assertTrue(os.path.isfile(report.config_file), report.config_file)

    def test_first_run_still_fails_when_a_needed_seed_cannot_be_copied(self):
        with (
            patch("defenseclaw.agent_selection.record_setup_agent_selections", side_effect=record_test_setup_agent_selections),
            patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("guardrail")),
        ):
            report = run_first_run(
                FirstRunOptions(connector="none", profile="observe", skip_install=True, start_gateway=False, verify=False)
            )

        self.assertEqual(report.status, "needs_attention")

    def test_refresh_seeds_a_bridge_file_past_max_path(self):
        with patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir", return_value=Path(self.bundle)):
            result = refresh_splunk_bridge(os.path.join(self.tmp, "p" * 110))

        self.assertEqual(result.errors, [])
        self.assertTrue(result.refreshed)

    def test_failed_refresh_seed_leaves_no_partial_copy(self):
        data_dir = os.path.join(self.tmp, "home")
        os.makedirs(data_dir)
        with (
            patch("defenseclaw.bundle_refresh.bundled_splunk_bridge_dir", return_value=Path(self.bundle)),
            patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("splunk-bridge")),
        ):
            result = refresh_splunk_bridge(data_dir)

        self.assertTrue(result.errors)
        self.assertFalse(os.path.lexists(os.path.join(data_dir, "splunk-bridge")))

    def test_rsync_reads_a_source_file_past_max_path(self):
        dest = os.path.join(self.tmp, "d")
        os.makedirs(dest)
        refreshed, _preserved, errors = _rsync_overwrite(src=Path(self.bundle), dest=Path(dest), preserve=())

        self.assertEqual(errors, [])
        self.assertIn("/".join((*_DEEP_DIRS, _DEEP_FILE)), refreshed)
        with open(_deep_file(dest), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), _DEEP_BODY)

    def test_copytree_keeps_an_existing_destination_when_the_copy_is_refused(self):
        dest = os.path.join(self.tmp, "kept")
        os.makedirs(dest)
        with self.assertRaises(OSError):
            long_paths.copytree(self.bundle, dest)
        self.assertTrue(os.path.isdir(dest))

    def test_display_drops_the_extended_prefix(self):
        self.assertEqual(long_paths.display("\\\\?\\C:\\a\\b: denied"), "C:\\a\\b: denied")
        self.assertEqual(long_paths.display("\\\\?\\UNC\\srv\\share\\x"), "\\\\srv\\share\\x")
        self.assertEqual(long_paths.display("/plain/path"), "/plain/path")

    @unittest.skipIf(os.name == "nt", "posix paths are used as given")
    def test_extended_is_the_given_path_off_windows(self):
        self.assertEqual(long_paths.extended("/a/b"), "/a/b")

    @unittest.skipUnless(os.name == "nt", "extended-length prefix is Windows only")
    def test_extended_prefixes_an_absolute_path_on_windows(self):
        self.assertEqual(long_paths.extended("C:\\a\\b"), "\\\\?\\C:\\a\\b")
        self.assertEqual(long_paths.extended("\\\\srv\\share\\x"), "\\\\?\\UNC\\srv\\share\\x")


if __name__ == "__main__":
    unittest.main()
