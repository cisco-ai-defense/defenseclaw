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
                patch("scripts.red_on_108.tree_entries", return_value={test_file: ("100644", "0" * 40)}),
                patch("scripts.red_on_108.subprocess.check_output", return_value=source),
            ):
                status = run_one(
                    Path("."), worktree, "commit", [test_file], ["test_gap0607_dependency"], "base", ["unused"]
                )
            self.assertEqual(status, "COMPILE_ONLY")

    def test_assertion_failure_is_certified_only_by_its_reviewed_lines(self):
        from scripts.red_on_108 import classify_test_result

        command = [sys.executable, "-m", "pytest", "-q", "cli/tests/test_sample.py"]
        output = (
            "E   AssertionError: expected sample result\n"
            "FAILED cli/tests/test_sample.py::test_sample - AssertionError: expected sample result\n"
        )
        self.assertEqual(classify_test_result(command, 1, output), "UNCLASSIFIED_FAIL")
        reviewed = ["AssertionError: expected sample result"]
        self.assertEqual(classify_test_result(command, 1, output, reviewed), "BEHAVIOR_RED")
        self.assertEqual(classify_test_result(command, 1, output, ["AssertionError: other"]), "UNCLASSIFIED_FAIL")

    def test_go_missing_fixture_is_not_behavior_red(self):
        from scripts.red_on_108 import classify_test_result

        command = ["nice", "-n", "15", "go", "test", "./internal/example"]
        missing = (
            "--- FAIL: TestGAP0607Sample (0.00s)\n"
            "    sample_test.go:12: open testdata/sample.json: no such file or directory\n"
        )
        assertion = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: got allow, want block\n"
        unavailable = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: fixture bytes unavailable\n"
        reviewed = ["sample_test.go:12: got allow, want block"]
        self.assertEqual(classify_test_result(command, 1, missing, reviewed), "COMPILE_ONLY")
        self.assertEqual(classify_test_result(command, 1, assertion), "UNCLASSIFIED_FAIL")
        self.assertEqual(classify_test_result(command, 1, assertion, reviewed), "BEHAVIOR_RED")
        self.assertEqual(classify_test_result(command, 1, unavailable, reviewed), "UNCLASSIFIED_FAIL")

    def test_reviewed_lines_must_be_exactly_the_failing_lines(self):
        from scripts.red_on_108 import classify_test_result

        command = ["nice", "-n", "15", "go", "test", "./internal/example"]
        product = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: got block, want allow\n"
        reviewed = ["sample_test.go:12: got block, want allow"]
        for extra in (
            "    sample_test.go:13: setup complete\n",
            "    sample_test.go:13: decision recorded\n",
            "    helper.go:9: got allow, want block\n",
        ):
            with self.subTest(extra=extra):
                self.assertEqual(classify_test_result(command, 1, product + extra, reviewed), "UNCLASSIFIED_FAIL")
        moved = "--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:14: got block, want allow\n"
        self.assertEqual(classify_test_result(command, 1, moved, reviewed), "UNCLASSIFIED_FAIL")
        self.assertEqual(classify_test_result(command, 1, product, reviewed), "BEHAVIOR_RED")

    def test_unreviewed_comparisons_are_never_certified(self):
        from scripts.red_on_108 import classify_test_result

        go = ["nice", "-n", "15", "go", "test", "./internal/example"]
        pytest = [sys.executable, "-m", "pytest", "-q", "cli/tests/test_sample.py"]
        for message in (
            "fixture observed old bytes, expected new bytes",
            "testdata observed old bytes, expected new bytes",
            "golden actual old, expected new",
            "seeded file: expected new, got old",
            "prepared workspace want new got old",
            "harness observed old bytes, expected new bytes",
            "asset observed old bytes, expected new bytes",
            "resource got old, want new",
            "mock server observed 0 calls, expected 1",
            "decision observed allow, expected block",
            "got allow, want block",
        ):
            with self.subTest(message=message):
                output = f"--- FAIL: TestGAP0607Sample (0.00s)\n    sample_test.go:12: {message}\n"
                self.assertEqual(classify_test_result(go, 1, output), "UNCLASSIFIED_FAIL")
                failed = f"E   AssertionError: {message}\nFAILED cli/tests/test_sample.py::test_sample - {message}\n"
                self.assertEqual(classify_test_result(pytest, 1, failed), "UNCLASSIFIED_FAIL")

    def test_run_one_passes_the_reviewed_lines(self):
        found = [("commit", ["sample_test.go"])]
        with patch("scripts.red_on_108.run_one", return_value="BEHAVIOR_RED") as run:
            run_mapped_candidate(Path("."), Path("."), found, ["TestMapped"], "base", ["sample_test.go:1: x"])
        self.assertEqual(run.call_args.args[-1], ["sample_test.go:1: x"])

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
            alternate = repo / "internal/example/fixtures/sample.json"
            alternate.parent.mkdir(parents=True)
            existing_asset = repo / "internal/example/assets/existing.json"
            existing_asset.parent.mkdir(parents=True)
            existing_asset.write_text("base asset", encoding="utf-8")
            deleted_asset = repo / "internal/example/assets/deleted.json"
            deleted_asset.write_text("old asset", encoding="utf-8")
            only_asset = repo / "internal/example/assets/deleted/only.json"
            only_asset.parent.mkdir(parents=True)
            only_asset.write_text("old only asset", encoding="utf-8")
            source = repo / "internal/example/subpkg/lib.go"
            source.parent.mkdir(parents=True)
            source.write_text("package subpkg\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            (fixture / "existing.json").write_text("updated", encoding="utf-8")
            (fixture / "new.json").write_text("new", encoding="utf-8")
            alternate.write_text("sample", encoding="utf-8")
            extra = repo / "internal/example/assets/sample.json"
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_text("asset", encoding="utf-8")
            existing_asset.write_text("updated asset", encoding="utf-8")
            source.write_text("package subpkg\n// later product source\n", encoding="utf-8")
            nested_asset = repo / "internal/example/subpkg/assets/new.json"
            nested_asset.parent.mkdir(parents=True)
            nested_asset.write_text("nested product asset", encoding="utf-8")
            git("rm", "-q", "internal/example/testdata/removed.json")
            git("rm", "-q", "internal/example/assets/deleted.json")
            git("rm", "-q", "internal/example/assets/deleted/only.json")
            git("add", ".")
            git("commit", "-q", "-m", "fix(GAP-0607): add test fixture")
            commit = git("rev-parse", "HEAD")
            prior = Path(temporary) / "prior"
            git("worktree", "add", "--quiet", "--detach", str(prior), base)
            try:
                overlay_go_fixtures(repo, prior, commit, "internal/example")
                self.assertEqual((prior / "internal/example/testdata/new.json").read_text(), "new")
                self.assertEqual((prior / "internal/example/testdata/existing.json").read_text(), "updated")
                self.assertEqual((prior / "internal/example/fixtures/sample.json").read_text(), "sample")
                self.assertEqual((prior / "internal/example/assets/sample.json").read_text(), "asset")
                self.assertEqual((prior / "internal/example/assets/existing.json").read_text(), "updated asset")
                self.assertFalse((prior / "internal/example/assets/deleted.json").exists())
                self.assertFalse((prior / "internal/example/assets/deleted").exists())
                self.assertEqual((prior / "internal/example/subpkg/lib.go").read_text(), "package subpkg\n")
                self.assertFalse((prior / "internal/example/subpkg/assets/new.json").exists())
                self.assertFalse((prior / "internal/example/testdata/removed.json").exists())
                git("rm", "-qr", "internal/example/testdata")
                git("commit", "-q", "-m", "fix(GAP-0607): remove old fixtures")
                subprocess.run(
                    ["git", "-C", str(prior), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL
                )
                overlay_go_fixtures(repo, prior, git("rev-parse", "HEAD"), "internal/example")
                self.assertFalse((prior / "internal/example/testdata").exists())
                # A directory that replaces a prior-release file is rebuilt.
                git("rm", "-q", "internal/example/assets/existing.json")
                (repo / "internal/example/assets/existing.json").mkdir()
                (repo / "internal/example/assets/existing.json/inner.json").write_text("inner", encoding="utf-8")
                git("add", ".")
                git("commit", "-q", "-m", "fix(GAP-0607): nest asset")
                subprocess.run(
                    ["git", "-C", str(prior), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL
                )
                overlay_go_fixtures(repo, prior, git("rev-parse", "HEAD"), "internal/example")
                self.assertEqual((prior / "internal/example/assets/existing.json/inner.json").read_text(), "inner")
                # A file that replaces an emptied prior-release directory is
                # written; one that would hide kept prior files is a mismatch.
                (repo / "internal/example/assets/deleted").write_text("file now", encoding="utf-8")
                git("add", ".")
                git("commit", "-q", "-m", "fix(GAP-0607): flatten asset")
                subprocess.run(
                    ["git", "-C", str(prior), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL
                )
                overlay_go_fixtures(repo, prior, git("rev-parse", "HEAD"), "internal/example")
                self.assertEqual((prior / "internal/example/assets/deleted").read_text(), "file now")
                (repo / "internal/example/subpkg").rename(repo / "internal/example/moved")
                (repo / "internal/example/subpkg").write_text("file over package", encoding="utf-8")
                git("add", "-A", ".")
                git("commit", "-q", "-m", "fix(GAP-0607): replace package path")
                subprocess.run(
                    ["git", "-C", str(prior), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL
                )
                with self.assertRaises(ValueError):
                    overlay_go_fixtures(repo, prior, git("rev-parse", "HEAD"), "internal/example")
            finally:
                git("worktree", "remove", "--force", str(prior))

    def test_overlay_reproduces_git_type_content_and_executable_bit(self):
        import os
        import stat
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()

            def git(*args: str) -> str:
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

            git("init", "-q")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.invalid")
            git("config", "core.fileMode", "true")
            fixture = repo / "internal/example/testdata"
            fixture.mkdir(parents=True)
            (fixture / "runner.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (fixture / "data.json").write_text("{}", encoding="utf-8")
            git("add", ".")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            (fixture / "runner.sh").chmod(0o755)
            (fixture / "data.json").chmod(0o755)
            (fixture / "link.json").symlink_to("data.json")
            (fixture / "data.json").chmod(0o644)
            git("add", ".")
            git("commit", "-q", "-m", "fix(GAP-0607): executable runner and linked fixture")
            commit = git("rev-parse", "HEAD")
            self.assertIn("100755", git("ls-tree", commit, "internal/example/testdata/runner.sh"))
            prior = Path(temporary) / "prior"
            git("worktree", "add", "--quiet", "--detach", str(prior), base)
            try:
                mask = os.umask(0o022)
                try:
                    overlay_go_fixtures(repo, prior, commit, "internal/example")
                finally:
                    os.umask(mask)
                runner = prior / "internal/example/testdata/runner.sh"
                self.assertTrue(stat.S_IMODE(runner.stat().st_mode) & 0o100)
                self.assertFalse(stat.S_IMODE((prior / "internal/example/testdata/data.json").stat().st_mode) & 0o111)
                link = prior / "internal/example/testdata/link.json"
                self.assertTrue(link.is_symlink())
                self.assertEqual(os.readlink(link), "data.json")

                # An overlay that loses the executable bit or writes a link as a
                # file is a mismatch, never a test run.
                def plain(repo_path, worktree, name, entry):
                    target = worktree / name
                    if target.is_symlink() or target.is_file():
                        target.unlink()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = subprocess.check_output(["git", "-C", str(repo_path), "cat-file", "blob", entry[1]])
                    target.write_bytes(data)
                    target.chmod(0o644)

                subprocess.run(
                    ["git", "-C", str(prior), "reset", "--hard", base], check=True, stdout=subprocess.DEVNULL
                )
                with patch("scripts.red_on_108.write_entry", side_effect=plain):
                    with self.assertRaises(ValueError):
                        overlay_go_fixtures(repo, prior, commit, "internal/example")
            finally:
                git("worktree", "remove", "--force", str(prior))


if __name__ == "__main__":
    unittest.main()
