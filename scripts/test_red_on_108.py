# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.red_on_108 import candidates, mapped_python_files, overlay_go_fixtures, run_mapped_candidate, run_one
from scripts.red_on_108 import tests_for_gap as select_tests_for_gap


class RedOn108Test(unittest.TestCase):
    def test_gap_selector_excludes_neighbor_tests(self):
        tests = ["TestGAP0235KnownValue", "TestGAP0395Ordinary", "TestG235Twin", "TestG2350Neighbor", "TestOther"]
        self.assertEqual(select_tests_for_gap(tests, "GAP-0235"), ["TestGAP0235KnownValue", "TestG235Twin"])

    def test_gap_selector_accepts_gx_prefix(self):
        self.assertEqual(
            select_tests_for_gap(["TestGX054ArchiveScopeFourCell"], "GAP-0054"), ["TestGX054ArchiveScopeFourCell"]
        )

    def test_unmapped_gap_requires_review(self):
        self.assertEqual(select_tests_for_gap(["TestOther"], "GAP-0588"), [])

    def test_multiple_commits_select_the_one_with_the_mapped_test(self):
        found = [("newer", ["newer_test.go"]), ("earlier", ["earlier_test.go"])]
        with patch("scripts.red_on_108.run_one", side_effect=["NO_MAPPED_TEST", "BEHAVIOR_RED"]) as run:
            self.assertEqual(
                run_mapped_candidate(Path("."), Path("."), found, ["TestMapped"], "base"), ("earlier", "BEHAVIOR_RED")
            )
        self.assertEqual(run.call_count, 2)

    def test_python_candidate_requires_the_named_test(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "cli/tests/test_neighbor.py"
            path.parent.mkdir(parents=True)
            path.write_text("def test_neighbor():\n    pass\n", encoding="utf-8")
            self.assertEqual(mapped_python_files(root, ["cli/tests/test_neighbor.py"], ["test_mapped"]), [])
            self.assertEqual(
                mapped_python_files(root, ["cli/tests/test_neighbor.py"], ["test_neighbor"]),
                ["cli/tests/test_neighbor.py"],
            )

    def test_candidates_ignore_deleted_tests_and_reverts(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            repo = Path(temporary)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL
                ).strip()

            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("commit", "-q", "--allow-empty", "-m", "base")
            base = git("rev-parse", "HEAD")
            test_file = repo / "candidate_test.go"
            test_file.write_text("package example\n", encoding="utf-8")
            git("add", "candidate_test.go")
            git("commit", "-q", "-m", "fix(GAP-0607): add candidate test")
            fix = git("rev-parse", "HEAD")
            git("rm", "-q", "candidate_test.go")
            git("commit", "-q", "-m", "fix(GAP-0607): remove obsolete candidate test")
            (repo / "revert_test.go").write_text("package example\n", encoding="utf-8")
            git("add", "revert_test.go")
            git("commit", "-q", "-m", "revert(GAP-0607): restore prior state")
            self.assertEqual(candidates(repo, "GAP-0607", base), [(fix, ["candidate_test.go"])])

    def test_missing_dependency_inside_named_python_test_is_not_behavior_red(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            worktree = Path(temporary)
            test_file = "cli/tests/test_gap0607_dependency.py"
            source = b"def test_gap0607_dependency():\n    import absent_sample_module\n"
            output = (
                "FAILED cli/tests/test_gap0607_dependency.py::test_gap0607_dependency - "
                "ModuleNotFoundError: No module named 'absent_sample_module'\n"
            )

            def run(command, **_kwargs):
                if command[:3] == [sys.executable, "-m", "pytest"]:
                    return SimpleNamespace(returncode=1, stdout=output)
                return SimpleNamespace(returncode=0, stdout="")

            with (
                patch("scripts.red_on_108.subprocess.run", side_effect=run),
                patch("scripts.red_on_108.subprocess.check_output", return_value=source),
            ):
                status = run_one(Path("."), worktree, "commit", [test_file], ["test_gap0607_dependency"], "base")
            self.assertEqual(status, "COMPILE_ONLY")

    def test_assertion_failure_remains_behavior_red(self):
        from scripts.red_on_108 import classify_test_result

        command = [sys.executable, "-m", "pytest", "-q", "cli/tests/test_sample.py"]
        output = "FAILED cli/tests/test_sample.py::test_sample - AssertionError: expected sample result\n"
        self.assertEqual(classify_test_result(command, 1, output), "BEHAVIOR_RED")

    def test_go_missing_fixture_is_not_behavior_red(self):
        from scripts.red_on_108 import classify_test_result

        command = ["nice", "-n", "15", "go", "test", "./internal/example"]
        missing = (
            "--- FAIL: TestGAP0607Sample (0.00s)\n"
            "    sample_test.go:12: open testdata/sample.json: no such file or directory\n"
        )
        assertion = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: got allow, want block\n"
        unclassified = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: fixture bytes unavailable\n"
        self.assertEqual(classify_test_result(command, 1, missing), "COMPILE_ONLY")
        self.assertEqual(classify_test_result(command, 1, assertion), "BEHAVIOR_RED")
        self.assertEqual(classify_test_result(command, 1, unclassified), "UNCLASSIFIED_FAIL")

    def test_go_fixtures_match_the_test_commit_on_prior_release(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()

            def git(*args: str) -> str:
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            fixture = repo / "internal/example/testdata"
            fixture.mkdir(parents=True)
            (fixture / "existing.json").write_text("base", encoding="utf-8")
            (fixture / "removed.json").write_text("removed", encoding="utf-8")
            git("add", ".")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            (fixture / "existing.json").write_text("updated", encoding="utf-8")
            (fixture / "new.json").write_text("new", encoding="utf-8")
            git("rm", "-q", "internal/example/testdata/removed.json")
            git("add", ".")
            git("commit", "-q", "-m", "fix(GAP-0607): add test fixture")
            commit = git("rev-parse", "HEAD")
            prior = Path(temporary) / "prior"
            git("worktree", "add", "--quiet", "--detach", str(prior), base)
            try:
                overlay_go_fixtures(repo, prior, commit, "internal/example")
                self.assertEqual((prior / "internal/example/testdata/new.json").read_text(), "new")
                self.assertEqual((prior / "internal/example/testdata/existing.json").read_text(), "updated")
                self.assertFalse((prior / "internal/example/testdata/removed.json").exists())
            finally:
                git("worktree", "remove", "--force", str(prior))


if __name__ == "__main__":
    unittest.main()
