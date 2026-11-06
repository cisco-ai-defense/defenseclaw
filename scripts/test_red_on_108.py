# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import unittest

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


if __name__ == "__main__":
    unittest.main()
