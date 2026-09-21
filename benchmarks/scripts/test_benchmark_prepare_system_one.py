from __future__ import annotations

import unittest

from benchmarks.scripts import benchmark_prepare_system_one as prepare
from benchmarks.scripts.test_benchmark_inventory_system_one_sources import case


class PrepareTests(unittest.TestCase):
    def test_quota_parser(self) -> None:
        self.assertEqual(prepare.parse_quota("A:action:development:3"), (("A", "action", "development"), 3))
        with self.assertRaises(ValueError):
            prepare.parse_quota("bad")

    def test_family_deduplication_and_stable_selection(self) -> None:
        rows = [case("a", "D", "same"), case("b", "D", "same"), case("c", "D", "other")]
        selected, _ = prepare.select_rows(rows, {("D", "action", "development"): 2}, 7, set(), set(), set(), False)
        self.assertEqual(len(selected), 2)
        self.assertEqual(len({prepare.family_id(row) for row in selected}), 2)
        selected_again, _ = prepare.select_rows(
            rows, {("D", "action", "development"): 2}, 7, set(), set(), set(), False
        )
        self.assertEqual([row["id"] for row in selected], [row["id"] for row in selected_again])

    def test_overlapping_quota_allocation_is_independent_of_argument_order(self) -> None:
        rows = [case("a", "A", "f1"), case("b", "D", "f2"), case("c", "D", "f3")]
        specific = ("A", "action", "development")
        wildcard = ("any", "any", "any")
        first, _ = prepare.select_rows(rows, {wildcard: 2, specific: 1}, 7, set(), set(), set(), False)
        second, _ = prepare.select_rows(rows, {specific: 1, wildcard: 2}, 7, set(), set(), set(), False)
        self.assertEqual([row["id"] for row in first], [row["id"] for row in second])
        self.assertEqual(len(first), 3)

    def test_quota_specificity_orders_specific_keys_first(self) -> None:
        keys = [("any", "any", "any"), ("A", "action", "development"), ("A", "any", "development")]
        self.assertEqual(
            sorted(keys, key=prepare.quota_specificity),
            [("A", "action", "development"), ("A", "any", "development"), ("any", "any", "any")],
        )

    def test_family_authority_can_be_required_for_selection(self) -> None:
        fallback = case("a", "D")
        fallback["strata"] = {}
        fallback["source"] = {"dataset": "fixture", "revision": "r1"}
        quota = {("D", "action", "development"): 1}
        selected, _ = prepare.select_rows([fallback], quota, 7, set(), set(), set(), False)
        self.assertEqual(len(selected), 1)
        with self.assertRaisesRegex(ValueError, "no dataset family authority"):
            prepare.select_rows([fallback], quota, 7, set(), set(), set(), False, True)

    def test_protected_and_test_rows_are_excluded(self) -> None:
        protected = case("protected", "D", "p")
        protected["source"]["dataset"] = "protected"
        test = case("test", "D", "t")
        test["split"] = "test"
        with self.assertRaisesRegex(ValueError, "selected 0"):
            prepare.select_rows([protected, test], {("any", "any", "any"): 1}, 7, set(), set(), {"protected"}, False)


if __name__ == "__main__":
    unittest.main()
