# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.red_on_108 import mapped_python_files, run_mapped_candidate
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
            self.assertEqual(run_mapped_candidate(Path("."), Path("."), found, ["TestMapped"], "base"),
                             ("earlier", "BEHAVIOR_RED"))
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


if __name__ == "__main__":
    unittest.main()
