#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
prepare = importlib.import_module("benchmark_prepare_contextual_judge")


def row(case_id: str, surface: str, label: str, domain: str = "fixture-domain") -> dict[str, object]:
    benign = label == "benign"
    return {
        "id": case_id,
        "surface": surface,
        "source": {"dataset": "fixture", "original_id": case_id},
        "truth": {
            "source_truth": "unknown" if benign else "malicious",
            "deterministic_truth": "benign" if benign else "contextual_or_dual_use",
            "expected_disposition": "allow" if benign else "detect_only",
        },
        "strata": {"split_group": case_id, "domain": domain},
    }


def source_benign_row(case_id: str) -> dict[str, object]:
    item = row(case_id, "action", "benign")
    item["truth"] = {
        "source_truth": "benign",
        "expected_disposition": "allow",
    }
    return item


class ContextualJudgePrepareTests(unittest.TestCase):
    def test_source_benign_rows_are_negative_truth(self) -> None:
        selected, _ = prepare.select_rows(
            [source_benign_row("safe-1")],
            {("fixture", "benign", "action", "any"): 1},
            7,
        )
        self.assertEqual([item["id"] for item in selected], ["safe-1"])

    def test_quota_surface_is_optional(self) -> None:
        self.assertEqual(
            prepare.parse_quotas(["fixture:benign:2", "fixture:attack:action:3"]),
            {
                ("fixture", "benign", "any", "any"): 2,
                ("fixture", "attack", "action", "any"): 3,
            },
        )

    def test_zero_quota_selects_nothing(self) -> None:
        selected, available = prepare.select_rows(
            [row("a", "action", "attack")],
            {("fixture", "attack", "action", "any"): 0},
            7,
        )
        self.assertEqual(selected, [])
        self.assertEqual(available["fixture:attack:action:any"], 1)

    def test_extended_lock_provenance_is_validated_explicitly(self) -> None:
        selected = [row("a", "action", "attack")]
        with self.assertRaisesRegex(ValueError, "missing provenance fields"):
            prepare.selected_source_provenance(selected)

        selected[0]["source"].update(
            {"revision": "pinned", "license": "approved", "redistribution": "private"}
        )
        self.assertEqual(
            prepare.selected_source_provenance(selected)["fixture"]["revision"],
            "pinned",
        )

    def test_extended_lock_validates_every_row_and_rejects_conflicts(self) -> None:
        first = row("a", "action", "attack")
        second = row("b", "action", "attack")
        provenance = {
            "revision": "pinned",
            "license": "approved",
            "redistribution": "private",
        }
        first["source"].update(provenance)

        with self.assertRaisesRegex(ValueError, "missing provenance fields"):
            prepare.selected_source_provenance([first, second])

        second["source"].update(provenance | {"revision": "other"})
        with self.assertRaisesRegex(ValueError, "conflicting provenance fields: revision"):
            prepare.selected_source_provenance([first, second])

    def test_surface_filter_prevents_stateful_call_expansion(self) -> None:
        rows = [row("a", "action", "attack"), row("b", "stateful", "attack")]
        selected, available = prepare.select_rows(
            rows, {("fixture", "attack", "action", "any"): 1}, 7
        )
        self.assertEqual([item["id"] for item in selected], ["a"])
        self.assertEqual(available["fixture:attack:action:any"], 1)

    def test_domain_quota_and_family_exclusion(self) -> None:
        rows = [
            row("a", "stateful", "attack", "firewall"),
            row("b", "stateful", "attack", "sudo"),
        ]
        selected, available = prepare.select_rows(
            rows,
            {("fixture", "attack", "stateful", "firewall"): 1},
            7,
            excluded_families={"b"},
        )
        self.assertEqual([item["id"] for item in selected], ["a"])
        self.assertEqual(available["fixture:attack:stateful:firewall"], 1)

    def test_overlapping_quotas_do_not_duplicate_families(self) -> None:
        rows = [row("a", "action", "attack"), row("b", "action", "attack")]
        selected, _ = prepare.select_rows(
            rows,
            {
                ("fixture", "attack", "action", "fixture-domain"): 1,
                ("fixture", "attack", "action", "any"): 1,
            },
            7,
        )
        self.assertEqual({item["id"] for item in selected}, {"a", "b"})

    def test_split_group_is_the_family_boundary(self) -> None:
        first = row("a", "stateful", "benign")
        second = row("b", "stateful", "benign")
        first["source"]["dataset"] = "yoonholee/terminalbench-trajectories"
        second["source"]["dataset"] = "yoonholee/terminalbench-trajectories"
        first["strata"].update({"split_group": "same-task", "trajectory_id": "trajectory-a"})
        second["strata"].update({"split_group": "same-task", "trajectory_id": "trajectory-b"})
        with self.assertRaisesRegex(ValueError, "only 1 unique families"):
            prepare.select_rows(
                [first, second],
                {("yoonholee/terminalbench-trajectories", "benign", "stateful", "any"): 2},
                7,
            )


if __name__ == "__main__":
    unittest.main()
