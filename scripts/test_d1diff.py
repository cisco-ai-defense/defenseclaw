# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import unittest

from scripts.d1diff import regressions


class D1DiffTest(unittest.TestCase):
    def test_allow_to_refusal_fails_and_ratification_is_exact_cell(self):
        base = {("d1-1", "codex/oss"): ("allow", "-")}
        head = {("d1-1", "codex/oss"): ("block", "RULE")}
        self.assertEqual(regressions(base, head, set()), [("d1-1", "codex/oss", "block", "RULE", "new")])
        self.assertEqual(regressions(base, head, {("d1-1", "codex/oss")}), [])

    def test_error_always_fails(self):
        base = {("d1-1", "codex/oss"): ("block", "RULE")}
        head = {("d1-1", "codex/oss"): ("error", "-")}
        self.assertEqual(len(regressions(base, head, set())), 1)

    def test_unfinished_cells_fail_even_when_inherited(self):
        for decision in ("error", "timeout"):
            with self.subTest(decision=decision):
                base = {("d1-1", "codex/oss"): (decision, "-"), ("d1-2", "codex/oss"): ("allow", "-")}
                head = {("d1-1", "codex/oss"): (decision, "-"), ("d1-2", "codex/oss"): (decision, "-")}
                self.assertEqual(
                    regressions(base, head, set()),
                    [("d1-1", "codex/oss", decision, "-", "inherited"), ("d1-2", "codex/oss", decision, "-", "new")],
                )
                self.assertEqual(len(regressions(base, head, {("d1-1", "codex/oss")})), 1)

    def test_missing_row_fails(self):
        with self.assertRaisesRegex(ValueError, "row sets differ"):
            regressions({("d1-1", "codex/oss"): ("allow", "-")}, {}, set())


if __name__ == "__main__":
    unittest.main()
