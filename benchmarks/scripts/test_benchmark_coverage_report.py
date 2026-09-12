#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
coverage = importlib.import_module("benchmark_coverage_report")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def lock(*datasets: dict[str, object]) -> dict[str, object]:
    return {"schema_version": "1", "datasets": list(datasets)}


def dataset(dataset_id: str, purpose: list[str] | None = None, *, enabled: bool = True) -> dict[str, object]:
    return {
        "id": dataset_id,
        "source_url": f"https://example.test/datasets/{dataset_id}",
        "revision": "revision-1",
        "purpose": purpose or ["action"],
        "enabled": enabled,
    }


def metric_group(
    group_value: str,
    profile: str,
    *,
    dimension: str = "dataset",
    cases: int,
    applicable: int,
    tp: int,
    tn: int,
    fp: int,
    fn: int,
    enforcement: tuple[int, int, int, int] | None = None,
    blocks: int = 0,
    benign_total: int = 0,
) -> dict[str, object]:
    enforcement = enforcement or (tp, tn, fp, fn)
    return {
        "profile": profile,
        "dimension": dimension,
        "group": group_value,
        "cases": cases,
        "applicable": applicable,
        "detection": {
            "confusion": {
                "true_positive": tp,
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
            }
        },
        "enforcement": {
            "confusion": {
                "true_positive": enforcement[0],
                "true_negative": enforcement[1],
                "false_positive": enforcement[2],
                "false_negative": enforcement[3],
            }
        },
        "benign_block_rate": {"numerator": blocks, "denominator": benign_total},
    }


def result_run(
    root: Path,
    name: str,
    dataset_counts: dict[str, int],
    groups: list[dict[str, object]],
    profiles: list[str],
    *,
    extra_inventory: dict[str, object] | None = None,
) -> None:
    run = root / name
    write_json(run / "results.json", {"schema_version": "1", "run_id": name, "groups": groups})
    write_json(
        run / "corpus-manifest.json",
        {"schema_version": "1", "dataset_counts": dataset_counts},
    )
    inventory: dict[str, object] = {
        "schema_version": "1",
        "profiles": [{"profile": profile, "rules": []} for profile in profiles],
    }
    inventory.update(extra_inventory or {})
    write_json(run / "inventory.json", inventory)


class CoverageReportTests(unittest.TestCase):
    @staticmethod
    def raw_metrics(
        *,
        cases: int,
        applicable: int,
        detection: tuple[int, int, int, int],
        enforcement: tuple[int, int, int, int],
        blocks: int = 0,
        benign_total: int = 0,
    ) -> dict[str, object]:
        keys = ("tp", "tn", "fp", "fn")
        return {
            "cases": cases,
            "applicable": applicable,
            "detection": dict(zip(keys, detection)),
            "enforcement": dict(zip(keys, enforcement)),
            "benign_blocks": blocks,
            "benign_total": benign_total,
        }

    def test_reports_each_profile_and_separates_detection_from_enforcement(self) -> None:
        public = [dataset("conformance-public"), dataset("missing-public")]
        candidates = {
            ("conformance-public", "balanced"): [
                {
                    "run_id": "candidate-v2",
                    "metrics": self.raw_metrics(
                        cases=20,
                        applicable=20,
                        detection=(0, 0, 0, 20),
                        enforcement=(20, 0, 0, 0),
                        blocks=0,
                        benign_total=0,
                    ),
                }
            ],
            ("conformance-public", "strict"): [
                {
                    "run_id": "candidate-v2",
                    "metrics": self.raw_metrics(
                        cases=20,
                        applicable=20,
                        detection=(10, 0, 0, 10),
                        enforcement=(19, 0, 0, 1),
                    ),
                }
            ],
        }
        report = coverage.build_report(public, candidates, [], {"conformance-public"}, {}, {}, set())
        scored = report["datasets"][0]
        self.assertEqual(scored["status"], "scored")
        self.assertNotIn("overall", scored)
        self.assertIsNone(scored["profiles"]["balanced"]["detection"]["f1"])
        self.assertEqual(scored["profiles"]["balanced"]["enforcement"]["f1"], 1.0)
        self.assertEqual(scored["profiles"]["strict"]["detection"]["f1"], 2 / 3)
        self.assertEqual(report["datasets"][1]["status"], "missing")
        markdown = coverage.render_markdown(report)
        self.assertIn("Each profile is reported separately", markdown)
        self.assertIn("| conformance-public | balanced |", markdown)
        self.assertNotIn("| conformance-public | overall |", markdown)
        self.assertIn("Enforcement F1", markdown)

    def test_checked_in_mapping_covers_the_public_lock(self) -> None:
        benchmarks_root = Path(__file__).resolve().parent.parent
        public = coverage.load_lock(benchmarks_root / "datasets.lock.json")
        public_ids = {str(item["id"]) for item in public}
        mapping, selectors = coverage.load_mapping(
            benchmarks_root / "coverage-report.mapping.json",
            public_ids,
            set(),
            set(),
        )
        self.assertEqual(set(mapping), public_ids)
        self.assertTrue(all(entry["intended_use"] for entry in mapping.values()))
        self.assertEqual(
            set(selectors),
            {"bounded_chains", "sql", "kubernetes", "endpoint_host", "credentials"},
        )

    def test_status_mapping_and_disabled_precedence(self) -> None:
        public = [
            dataset("normalized-public"),
            dataset("labels-public"),
            dataset("mining-public"),
            dataset("gated-public"),
            dataset("inaccessible-public"),
            dataset("disabled-public", enabled=False),
        ]
        mapping = {
            "normalized-public": {
                "status": "normalized-only",
                "case_count": 8,
                "applicable_count": 0,
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
            "labels-public": {
                "status": "label-only",
                "case_count": 9,
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
            "mining-public": {
                "status": "normalized-mining-only",
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
            "gated-public": {
                "status": "gated",
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
            "inaccessible-public": {
                "status": "inaccessible",
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
            "disabled-public": {
                "status": "label-only",
                "domains": [],
                "intended_use": [],
                "limitations": [],
            },
        }
        report = coverage.build_report(public, {}, [], set(), mapping, {}, set())
        self.assertEqual(
            [row["status"] for row in report["datasets"]],
            [
                "normalized-only",
                "label-only",
                "normalized-mining-only",
                "gated",
                "inaccessible",
                "disabled",
            ],
        )
        self.assertEqual(report["datasets"][0]["case_count"], 8)
        self.assertEqual(report["datasets"][1]["case_count"], 9)
        self.assertIn("rule mining", report["datasets"][2]["limitations"][0])
        self.assertIn("gated", report["datasets"][3]["limitations"][0])
        self.assertIn("inaccessible", report["datasets"][4]["limitations"][0])

    def test_domain_metrics_require_exact_group_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result_run(
                root,
                "mixed-v1",
                {"mixed-public": 100},
                [
                    metric_group("mixed-public", "balanced", cases=100, applicable=100, tp=60, tn=30, fp=5, fn=5),
                    metric_group(
                        "k8s", "balanced", dimension="platform", cases=3, applicable=3, tp=2, tn=1, fp=0, fn=0
                    ),
                    metric_group(
                        "k8s-policy",
                        "balanced",
                        dimension="platform",
                        cases=2,
                        applicable=2,
                        tp=2,
                        tn=0,
                        fp=0,
                        fn=0,
                    ),
                    metric_group(
                        "stateful",
                        "balanced",
                        dimension="surface",
                        cases=8,
                        applicable=8,
                        tp=7,
                        tn=1,
                        fp=0,
                        fn=0,
                    ),
                ],
                ["balanced"],
            )
            candidates, groups, normalized, limitations = coverage.collect_candidates(
                root, {"mixed-public"}, set()
            )
            selectors = {
                "kubernetes": [
                    {"dimension": "platform", "group_values": ["k8s", "k8s-policy"], "dataset_ids": ["mixed-public"]}
                ]
            }
            report = coverage.build_report(
                [dataset("mixed-public", ["kubernetes", "yara"])],
                candidates,
                groups,
                normalized,
                {},
                selectors,
                set(),
                limitations,
            )
            k8s = report["domain_profile_metrics"]["kubernetes"]
            self.assertTrue(k8s["available"])
            self.assertEqual(k8s["profiles"]["balanced"]["cases"], 5)
            self.assertEqual(k8s["profiles"]["balanced"]["detection"]["tp"], 4)
            self.assertFalse(report["domain_profile_metrics"]["yara_content"]["available"])
            self.assertEqual(
                report["domain_profile_metrics"]["yara_content"]["reason"],
                "no_exact_group_selector",
            )

    def test_collects_only_public_aggregate_fields_and_redacts_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public_path = root / "public.json"
            private_path = root / "private.json"
            mapping_path = root / "mapping.json"
            write_json(public_path, lock(dataset("public-set", ["stateful"])))
            write_json(
                private_path,
                lock(
                    dataset("public-set", ["stateful"]),
                    {
                        **dataset("confidential-corpus"),
                        "source_url": "https://private.example.test/confidential-source",
                    },
                ),
            )
            write_json(
                mapping_path,
                {
                    "schema_version": "1",
                    "datasets": {
                        "public-set": {
                            "domains": ["bounded_chains"],
                            "status": "normalized-only",
                            "limitations": [
                                "reviewed at /custom/private.json using confidential-corpus and confidential-source"
                            ],
                        },
                        "confidential-corpus": {
                            "status": "label-only",
                            "limitations": ["confidential-source"],
                        },
                    },
                    "domain_group_selectors": {
                        "bounded_chains": [
                            {
                                "dimension": "surface",
                                "group_values": ["stateful"],
                                "dataset_ids": ["public-set"],
                            }
                        ]
                    },
                },
            )
            result_run(
                root / "results",
                "public-v1",
                {"public-set": 5, "confidential-corpus": 99},
                [
                    metric_group(
                        "public-set", "default", cases=5, applicable=5, tp=2, tn=3, fp=0, fn=0
                    ),
                    metric_group(
                        "confidential-corpus",
                        "default",
                        cases=99,
                        applicable=99,
                        tp=99,
                        tn=0,
                        fp=0,
                        fn=0,
                    ),
                    metric_group(
                        "stateful",
                        "default",
                        dimension="surface",
                        cases=4,
                        applicable=4,
                        tp=4,
                        tn=0,
                        fp=0,
                        fn=0,
                    ),
                ],
                ["default"],
                extra_inventory={
                    "payload": "must-not-appear",
                    "source_path": "/Users/person/source.jsonl",
                },
            )
            public = coverage.load_lock(public_path)
            excluded = coverage.private_only_ids(public, private_path)
            redactions = coverage.private_tokens(private_path, public)
            mapping, selectors = coverage.load_mapping(
                mapping_path, {"public-set"}, excluded, redactions
            )
            candidates, groups, normalized, limitations = coverage.collect_candidates(
                root / "results", {"public-set"}, excluded
            )
            report = coverage.build_report(
                public, candidates, groups, normalized, mapping, selectors, redactions, limitations
            )
            output = json.dumps(report) + coverage.render_markdown(report)
            self.assertEqual(len(report["datasets"]), 1)
            self.assertNotIn("confidential-corpus", output)
            self.assertNotIn("confidential-source", output)
            self.assertNotIn("must-not-appear", output)
            self.assertNotIn("/custom/", output)
            self.assertIn("[private]", output)
            self.assertIn("[local path]", output)
            self.assertFalse(report["domain_profile_metrics"]["bounded_chains"]["available"])
            self.assertEqual(
                report["domain_profile_metrics"]["bounded_chains"]["reason"],
                "no_matching_result_groups",
            )

    def test_candidate_selection_is_deterministic(self) -> None:
        public = [dataset("public-set")]
        lower = {
            "run_id": "tuning-v2",
            "metrics": self.raw_metrics(
                cases=10,
                applicable=10,
                detection=(1, 9, 0, 0),
                enforcement=(1, 9, 0, 0),
                benign_total=9,
            ),
        }
        higher = {
            "run_id": "tuning-v12",
            "metrics": self.raw_metrics(
                cases=10,
                applicable=10,
                detection=(2, 8, 0, 0),
                enforcement=(2, 8, 0, 0),
                benign_total=8,
            ),
        }
        first = coverage.build_report(
            public, {("public-set", "default"): [lower, higher]}, [], {"public-set"}, {}, {}, set()
        )
        second = coverage.build_report(
            public, {("public-set", "default"): [higher, lower]}, [], {"public-set"}, {}, {}, set()
        )
        self.assertEqual(first, second)
        self.assertEqual(first["datasets"][0]["profiles"]["default"]["detection"]["tp"], 2)
        self.assertIn("multiple_result_candidates:default", first["datasets"][0]["limitations"][0])


if __name__ == "__main__":
    unittest.main()
