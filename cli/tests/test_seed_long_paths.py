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
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
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
            os.makedirs(dst, exist_ok=True)
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
        self.assertEqual([n for n in os.listdir(os.path.dirname(dest)) if n.startswith(".splunk-bridge")], [])

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

    def _flat_source(self) -> str:
        # A flat source: shutil.copytree calls itself for every subfolder.
        flat = os.path.join(self.tmp, "flat")
        os.makedirs(flat)
        with open(os.path.join(flat, "needed.txt"), "w", encoding="utf-8") as handle:
            handle.write("needed")
        return flat

    def _staging_leftovers(self) -> list[str]:
        return [n for n in os.listdir(self.tmp) if n.startswith(".destination")]

    def test_two_runs_seeding_at_once_publish_one_complete_copy_and_refuse_the_other(self):
        real = shutil.copytree
        lock = threading.Lock()
        both_entered = threading.Event()
        entered: list[int] = []
        errors: list[BaseException] = []
        dest = os.path.join(self.tmp, "destination")
        flat = self._flat_source()

        def together(src, dst, *args, **kwargs):
            with lock:
                entered.append(1)
                if len(entered) == 2:
                    both_entered.set()
            self.assertTrue(both_entered.wait(10))
            return real(src, dst, *args, **kwargs)

        def seed():
            try:
                long_paths.copytree(flat, dest)
            except BaseException as exc:  # noqa: BLE001 - reported through the assertion below
                errors.append(exc)

        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=together):
            workers = [threading.Thread(target=seed) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(30)

        self.assertEqual([type(e) for e in errors], [FileExistsError], msg=errors)
        with open(os.path.join(dest, "needed.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "needed")
        self.assertEqual(self._staging_leftovers(), [])

    def test_a_staging_name_already_in_use_is_never_reused_or_removed(self):
        dest = os.path.join(self.tmp, "destination")
        flat = self._flat_source()
        taken = os.path.join(self.tmp, ".destination.seed-aaaaaaaa")
        os.makedirs(taken)
        with open(os.path.join(taken, "prior-data.txt"), "w", encoding="utf-8") as handle:
            handle.write("prior")
        names = [SimpleNamespace(hex="aaaaaaaa" + "0" * 24), SimpleNamespace(hex="bbbbbbbb" + "0" * 24)]

        with patch("defenseclaw.long_paths.uuid.uuid4", side_effect=names):
            long_paths.copytree(flat, dest)

        with open(os.path.join(taken, "prior-data.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "prior")
        self.assertFalse(os.path.exists(os.path.join(taken, "needed.txt")))
        with open(os.path.join(dest, "needed.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "needed")
        self.assertEqual(self._staging_leftovers(), [".destination.seed-aaaaaaaa"])

    def test_an_empty_destination_created_while_the_copy_runs_is_kept_as_it_is(self):
        real = shutil.copytree
        dest = os.path.join(self.tmp, "destination")
        flat = self._flat_source()
        made: list[os.stat_result] = []

        def copy_then_competitor_appears(src, dst, *args, **kwargs):
            result = real(src, dst, *args, **kwargs)
            os.mkdir(dest)
            made.append(os.stat(dest))
            return result

        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=copy_then_competitor_appears):
            with self.assertRaises(FileExistsError):
                long_paths.copytree(flat, dest)

        self.assertEqual(os.listdir(dest), [])
        self.assertEqual(os.stat(dest).st_ino, made[0].st_ino)
        self.assertEqual(self._staging_leftovers(), [])

    def test_a_partial_destination_created_while_the_copy_runs_is_never_reported_as_a_seed(self):
        dest = os.path.join(self.tmp, "destination")
        flat = self._flat_source()

        def competitor_leaves_a_partial_copy(src, dst, *args, **kwargs):
            os.makedirs(dest)
            with open(os.path.join(dest, "partial.txt"), "w", encoding="utf-8") as handle:
                handle.write("x")
            raise OSError(5, "refused", str(dst))

        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=competitor_leaves_a_partial_copy):
            with self.assertRaises(OSError):
                long_paths.copytree(flat, dest)

        self.assertEqual(os.listdir(dest), ["partial.txt"])
        self.assertEqual(self._staging_leftovers(), [])

    def test_refresh_does_not_report_a_competing_partial_copy_as_refreshed(self):
        data_dir = os.path.join(self.tmp, "home")
        dest = os.path.join(data_dir, "splunk-bridge")
        real = shutil.copytree

        def competitor_leaves_a_partial_copy(src, dst, *args, **kwargs):
            result = real(src, dst, *args, **kwargs)
            os.makedirs(dest)
            with open(os.path.join(dest, "partial.txt"), "w", encoding="utf-8") as handle:
                handle.write("x")
            return result

        with patch("defenseclaw.long_paths.shutil.copytree", side_effect=competitor_leaves_a_partial_copy):
            result = refresh_splunk_bridge(data_dir)

        self.assertTrue(result.errors, msg=result)
        self.assertFalse(result.refreshed)
        self.assertEqual(os.listdir(dest), ["partial.txt"])

    def test_a_destination_is_not_visible_while_another_run_is_publishing_it(self):
        from defenseclaw.bootstrap import BootstrapReport, _seed_guardrail_profiles

        bundle = Path(self.tmp) / "bundled"
        (bundle / "balanced").mkdir(parents=True)
        (bundle / "balanced" / "needed.yaml").write_text("rules: []\n", encoding="utf-8")
        policy_dir = Path(self.tmp) / "policy"
        final = policy_dir / "guardrail" / "balanced"
        reached_publish = threading.Event()
        release = threading.Event()
        first, second = BootstrapReport(), BootstrapReport()
        real_rename = os.rename
        seen_while_paused: list[bool] = []

        def fail_the_first_publish(source, destination):
            if threading.current_thread().name == "first-seed" and os.fspath(destination) == os.fspath(final):
                seen_while_paused.append(final.exists())
                reached_publish.set()
                self.assertTrue(release.wait(10))
                raise OSError(13, "injected publish failure", os.fspath(final))
            return real_rename(source, destination)

        with (
            patch("defenseclaw.long_paths.os.rename", side_effect=fail_the_first_publish),
            patch("defenseclaw.paths.bundled_guardrail_profiles_dir", return_value=bundle),
        ):
            worker = threading.Thread(
                target=_seed_guardrail_profiles, args=(os.fspath(policy_dir), first), name="first-seed"
            )
            worker.start()
            self.assertTrue(reached_publish.wait(10))
            _seed_guardrail_profiles(os.fspath(policy_dir), second)
            release.set()
            worker.join(10)

        self.assertEqual(seen_while_paused, [False])
        self.assertEqual(len(first.errors), 1, msg=first.errors)
        self.assertEqual(second.errors, [])
        self.assertEqual(second.guardrail_profiles_preserved, [])
        self.assertEqual(second.guardrail_profiles_seeded, ["balanced"])
        self.assertTrue((final / "needed.yaml").is_file())
        self.assertEqual(self._staging_leftovers_in(final.parent), [])

    def _staging_leftovers_in(self, folder: Path) -> list[str]:
        return [n for n in os.listdir(folder) if n.startswith(".balanced.seed-")]

    def test_a_relative_leaf_destination_is_seeded_in_the_working_directory(self):
        flat = self._flat_source()
        previous = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, previous)

        long_paths.copytree("flat", "destination")

        with open(os.path.join(self.tmp, "destination", "needed.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "needed")
        self.assertEqual(self._staging_leftovers(), [])
        self.assertTrue(os.path.isdir(flat))

    def test_a_partial_copy_that_cannot_be_removed_is_never_taken_for_a_seed(self):
        data_dir = os.path.join(self.tmp, "home")
        with (
            patch("defenseclaw.long_paths.shutil.copytree", side_effect=_failing_copytree("splunk-bridge")),
            patch("defenseclaw.long_paths.shutil.rmtree", return_value=None),
        ):
            first = bootstrap_env(_cfg_for(data_dir))
        dest = os.path.join(os.path.realpath(data_dir), "splunk-bridge")

        self.assertEqual(len(first.warnings), 1, msg=first.warnings)
        self.assertIn("could not be removed", first.warnings[0])
        self.assertFalse(os.path.lexists(dest))

        second = bootstrap_env(_cfg_for(data_dir))

        self.assertFalse(second.splunk_bridge_preserved)
        with open(_deep_file(dest), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), _DEEP_BODY)
        self.assertFalse(os.path.exists(os.path.join(dest, "partial.txt")))

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
