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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
module = importlib.import_module("benchmark_build_near_miss_fpr_lane")


def queue_row(**overrides: object) -> dict[str, object]:
    """Return a synthetic queue row for selector and provenance tests."""

    row: dict[str, object] = {
        "schema_version": "1",
        "id": "fixture/case",
        "dataset": "fixture",
        "split": "validation",
        "surface": "action",
        "reasons": ["deterministic_benign_finding"],
        "truth_source": "deterministic",
        "deterministic_truth": "benign",
        "payload": {"tool_name": "shell", "args": {"command": "true"}},
        "baseline": {
            "detected": True,
            "action": "alert",
            "authoritative": True,
            "enforcement_eligible": False,
            "parse_status": "parsed",
            "issue_codes": [],
            "route": "semantic",
            "rule_ids": ["fixture.rule"],
        },
    }
    row.update(overrides)
    return row


class NearMissFPRLaneTests(unittest.TestCase):
    def test_selector_requires_frozen_validation_benign_finding(self) -> None:
        """The selector must reject non-validation, non-benign, and non-findings."""

        self.assertTrue(module.selected_case(queue_row()))
        for overrides in (
            {"split": "development"},
            {"truth_source": "model"},
            {"deterministic_truth": "contextual_or_dual_use"},
            {"baseline": {"detected": False}},
            {"reasons": ["other_reason"]},
        ):
            self.assertFalse(module.selected_case(queue_row(**overrides)))

    def test_payload_summary_does_not_retain_argument_values(self) -> None:
        """Shape summaries must not retain sensitive argument values."""

        summary = module.payload_summary(
            {
                "events": [
                    {"tool_name": "shell", "args": {"command": "private-value"}},
                    {"tool": "file_read", "args": {"path": "private-path"}},
                ]
            }
        )
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["event_tools"], ["file_read", "shell"])
        self.assertNotIn("private-value", summary)
        self.assertNotIn("private-path", summary)

    def test_manifest_contract_is_non_gating(self) -> None:
        """The lane schema remains explicitly review-only and non-gating."""

        self.assertEqual(module.SCHEMA_VERSION, "defenseclaw/near-miss-fpr-lane/v1")
        self.assertEqual(module.SELECTOR_REASON, "deterministic_benign_finding")

    def test_queue_cluster_pair_checks_schema_profile_and_count(self) -> None:
        """A queue cannot silently consume unrelated or stale cluster metadata."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            queue_path = root / "adjudication-queue.jsonl"
            clusters_path = root / "clusters.json"
            queue_path.write_text(json.dumps(queue_row()) + "\n", encoding="utf-8")
            clusters_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "profile": "default",
                        "case_count": 1,
                        "prediction_count": 3,
                        "queue_count": 1,
                        "queue_sha256": module.sha256_file(queue_path),
                        "corpus_sha256": "a" * 64,
                        "predictions_sha256": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )
            source, rows = module.build_source(queue_path, clusters_path)
            self.assertEqual(source["input_queue_count"], 1)
            self.assertEqual(len(rows), 1)

            stale = json.loads(clusters_path.read_text(encoding="utf-8"))
            stale["queue_count"] = 2
            clusters_path.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaises(ValueError):
                module.build_source(queue_path, clusters_path)

            stale["queue_count"] = 1
            stale["queue_sha256"] = "c" * 64
            clusters_path.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "queue_sha256"):
                module.build_source(queue_path, clusters_path)

            other = Path(temporary) / "other"
            other.mkdir()
            other_clusters = other / "clusters.json"
            other_clusters.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaises(ValueError):
                module.build_source(queue_path, other_clusters)

    def test_invalid_duplicate_input_does_not_create_output_directory(self) -> None:
        """Validation failures must not leave an output directory blocking retry."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            queue_path = root / "adjudication-queue.jsonl"
            clusters_path = root / "clusters.json"
            duplicate = queue_row()
            queue_path.write_text(
                json.dumps(duplicate) + "\n" + json.dumps(duplicate) + "\n",
                encoding="utf-8",
            )
            clusters_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "profile": "default",
                        "case_count": 1,
                        "prediction_count": 3,
                        "queue_count": 2,
                        "queue_sha256": module.sha256_file(queue_path),
                    }
                ),
                encoding="utf-8",
            )
            output_dir = Path(temporary) / "out"
            argv = [
                "benchmark_build_near_miss_fpr_lane.py",
                "--queue",
                str(queue_path),
                "--clusters",
                str(clusters_path),
                "--output-dir",
                str(output_dir),
                "--lane-id",
                "test",
            ]
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                module.main()
            self.assertFalse(output_dir.exists())

    def test_main_writes_payload_free_non_gating_output(self) -> None:
        """The CLI writes a value-free lane with verifiable non-gating metadata."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            queue_path = root / "adjudication-queue.jsonl"
            clusters_path = root / "clusters.json"
            queue_path.write_text(
                json.dumps(
                    queue_row(
                        payload={
                            "tool_name": "shell",
                            "args": {
                                "command": "private-value",
                                "path": "private-path",
                            },
                        }
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            clusters_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "profile": "default",
                        "case_count": 1,
                        "prediction_count": 3,
                        "queue_count": 1,
                        "queue_sha256": module.sha256_file(queue_path),
                    }
                ),
                encoding="utf-8",
            )
            output_dir = Path(temporary) / "out"
            argv = [
                "benchmark_build_near_miss_fpr_lane.py",
                "--queue",
                str(queue_path),
                "--clusters",
                str(clusters_path),
                "--output-dir",
                str(output_dir),
                "--lane-id",
                "test",
            ]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(module.main(), 0)

            cases_path = output_dir / "cases.jsonl"
            manifest_path = output_dir / "manifest.json"
            cases_text = cases_path.read_text(encoding="utf-8")
            self.assertNotIn("private-value", cases_text)
            self.assertNotIn("private-path", cases_text)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for field in (
                "gating",
                "included_in_authoritative_scores",
                "included_in_default_tuning_inputs",
                "changes_runtime_authority",
                "changes_thresholds",
                "changes_authoritative_labels",
                "payloads_committed",
            ):
                self.assertFalse(manifest[field])

            checksums = dict(
                reversed(line.split("  ", 1))
                for line in (output_dir / "checksums.txt").read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(checksums["cases.jsonl"], module.sha256_file(cases_path))
            self.assertEqual(checksums["manifest.json"], module.sha256_file(manifest_path))


if __name__ == "__main__":
    unittest.main()
