from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.scripts import benchmark_inventory_system_one_sources as inventory


def case(case_id: str, grade: str, family: str = "family") -> dict[str, object]:
    truth = {"source_truth": "unknown", "applicability": "in_scope", "expected_disposition": "allow"}
    surface = "action"
    if grade == "A":
        truth.update(
            {
                "source_truth": "malicious",
                "deterministic_truth": "deterministic_malicious",
                "expected_disposition": "block",
                "label_confidence": "high",
            }
        )
    elif grade == "B":
        truth.update(
            {
                "source_truth": "malicious",
                "deterministic_truth": "contextual_or_dual_use",
                "expected_disposition": "detect_only",
                "label_confidence": "high",
            }
        )
        surface = "stateful"
    elif grade == "C":
        truth.update(
            {
                "source_truth": "malicious",
                "deterministic_truth": "contextual_or_dual_use",
                "expected_disposition": "detect_only",
                "label_confidence": "medium",
            }
        )
    elif grade == "D":
        truth.update(
            {
                "source_truth": "benign",
                "deterministic_truth": "benign",
                "expected_disposition": "allow",
                "label_confidence": "high",
            }
        )
    else:
        truth.update({"applicability": "out_of_scope", "exclusion_reason": "unknown"})
    return {
        "schema_version": "1",
        "id": case_id,
        "split": "development",
        "surface": surface,
        "source": {"dataset": "fixture", "revision": "r1", "original_id": case_id},
        "payload": {},
        "truth": truth,
        "strata": {"split_group": family},
    }


class InventoryTests(unittest.TestCase):
    def test_truth_grades(self) -> None:
        for grade in "ABCDE":
            self.assertEqual(inventory.truth_grade(case(grade, grade)), grade)

    def test_catalog_reports_overlap_and_value_free_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.jsonl"
            second = root / "second.jsonl"
            first.write_text(json.dumps(case("a", "A", "shared")) + "\n", encoding="utf-8")
            second.write_text(json.dumps(case("b", "D", "shared")) + "\n", encoding="utf-8")
            catalog = inventory.build_catalog([first, second], [])
            self.assertEqual(catalog["overlaps"]["cross_corpus_families"], 1)
            self.assertEqual(catalog["totals"]["grade:A"], 1)
            self.assertEqual(catalog["totals"]["grade_split:A:development"], 1)
            self.assertEqual(catalog["totals"]["grade_surface:D:action"], 1)
            self.assertNotIn("payload", json.dumps(catalog))

    def test_family_authority_names_its_source_and_can_be_required(self) -> None:
        authoritative = case("a", "D", "group-1")
        self.assertEqual(inventory.family_authority(authoritative), ("split_group", "group-1"))
        self.assertEqual(inventory.family_id(authoritative, True), "group-1")

        trajectory = case("b", "D")
        del trajectory["strata"]["split_group"]
        trajectory["strata"]["trajectory_id"] = "traj-9"
        self.assertEqual(inventory.family_authority(trajectory), ("trajectory_id", "traj-9"))

        fallback = case("c", "D")
        fallback["strata"] = {}
        fallback["source"] = {"dataset": "fixture", "revision": "r1"}
        self.assertEqual(inventory.family_authority(fallback), ("case_id", "c"))
        self.assertEqual(inventory.family_id(fallback), "c")
        with self.assertRaisesRegex(ValueError, "no dataset family authority"):
            inventory.family_id(fallback, True)

    def test_catalog_counts_family_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.jsonl"
            fallback = case("c", "D")
            fallback["strata"] = {}
            fallback["source"] = {"dataset": "fixture", "revision": "r1"}
            path.write_text(
                json.dumps(case("a", "D", "group-1")) + "\n" + json.dumps(fallback) + "\n", encoding="utf-8"
            )
            catalog = inventory.build_catalog([path], [])
            self.assertEqual(catalog["totals"]["family_authority:split_group"], 1)
            self.assertEqual(catalog["totals"]["family_authority:case_id"], 1)

    def test_duplicate_json_keys_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            json.loads('{"a":1,"a":2}', object_pairs_hook=inventory.strict_object)


if __name__ == "__main__":
    unittest.main()
