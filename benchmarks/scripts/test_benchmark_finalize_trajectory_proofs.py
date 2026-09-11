#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

finalizer = importlib.import_module("benchmark_finalize_trajectory_proofs")
labeler = importlib.import_module("benchmark_label_trajectory_bedrock")
scorer = importlib.import_module("benchmark_score_trajectories")


def action_case(trajectory_id: str, index: int, truth: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": f"case-{trajectory_id}-{index}",
        "source": {
            "dataset": "fixture/trajectory",
            "revision": "fixture-revision",
            "original_id": f"original-{trajectory_id}-{index}",
            "license": "Apache-2.0",
            "redistribution": "aggregate-only",
        },
        "split": "development",
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "tool_name": "fixture_tool",
            "args": {
                "path": f"/var/lib/fixture/{trajectory_id}/artifact.bin",
                "payload_secret_must_not_leak": f"value-{trajectory_id}-{index}",
            },
        },
        "truth": {
            "source_truth": truth,
            "applicability": "in_scope",
            "expected_disposition": "allow" if truth == "benign" else "detect_only",
        },
        "strata": {
            "trajectory_id": trajectory_id,
            "sequence_index": index,
            "call_index": index,
        },
    }


def stateful_case(trajectory_id: str, truth: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "id": f"stateful-{trajectory_id}",
        "source": {
            "dataset": "fixture/trajectory",
            "revision": "fixture-revision",
            "original_id": f"stateful-original-{trajectory_id}",
            "license": "Apache-2.0",
            "redistribution": "aggregate-only",
        },
        "split": "development",
        "surface": "stateful",
        "payload": {"direction": "tool_call", "events": [{"tool_name": "fixture_tool"}]},
        "truth": {
            "source_truth": truth,
            "applicability": "in_scope",
            "expected_disposition": "allow" if truth == "benign" else "detect_only",
        },
        "strata": {
            "trajectory_id": trajectory_id,
            "sequence_index": 0,
            "call_index": 0,
        },
    }


def facts(identity_refs: list[str]) -> dict[str, Any]:
    return {
        "operation": "other",
        "resource": "other",
        "scope": "single",
        "sensitivity": "none",
        "destination_trust": "unknown",
        "control_flow": "unconditional",
        "result": "unknown",
        "identity_refs": identity_refs,
    }


def event_label(event_index: int, *, proof: bool = False) -> dict[str, Any]:
    completed: list[dict[str, Any]] = []
    if proof:
        completed = [
            {
                "proof_id": "proof_1",
                "proof_type": "secret_read_same_value_egress",
                "event_indexes": [0, 1],
                "predecessor_indexes": [0],
                "terminal_event_index": 1,
                "identity_continuity": "exact_file_ref",
                "identity_ref": "artifact_1",
                "reason_code": "exact_bounded_proof",
            }
        ]
    return {
        "event_index": event_index,
        "verdict": "deterministic_malicious" if proof else "contextual_or_dual_use",
        "disposition": "block" if proof else "detect_only",
        "confidence": "high",
        "facts": facts(["artifact_1"]),
        "completed_proof_ids": ["proof_1"] if proof else [],
        "predecessor_indexes": [0] if proof else [],
        "reason_code": "completed_proof" if proof else "no_completed_proof",
        "completed_proofs": completed,
    }


class FinalizeTrajectoryProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.benign_id = "a" * 24
        self.unsafe_id = "b" * 24
        self.unknown_id = "c" * 24
        self.corpus_rows: list[dict[str, Any]] = []
        for trajectory_id, trajectory_truth, atomic_truth in (
            (self.benign_id, "benign", "benign"),
            (self.unsafe_id, "malicious", "unknown"),
            (self.unknown_id, "unknown", "unknown"),
        ):
            self.corpus_rows.extend(
                [
                    action_case(trajectory_id, 0, atomic_truth),
                    action_case(trajectory_id, 1, atomic_truth),
                    stateful_case(trajectory_id, trajectory_truth),
                ]
            )
        self.input_rows = [row for row in self.corpus_rows if row["surface"] == "action"]
        self.corpus = self.root / "corpus.jsonl"
        self.labeling_input = self.root / "actions.jsonl"
        self._write_jsonl(self.corpus, self.corpus_rows)
        self._write_jsonl(self.labeling_input, self.input_rows)
        self._prepare_bundle(self.root / "bundle")

    def _prepare_bundle(self, bundle: Path) -> None:
        self.bundle = bundle
        labeler.prepare(
            argparse.Namespace(
                input=self.labeling_input,
                output_dir=self.bundle,
                model_id=labeler.MODEL_ID,
                max_completion_tokens=4096,
                max_trajectory_events=64,
                max_serialized_chars=60_000,
                limit=0,
                allow_test_labeling=False,
                allow_small=True,
            )
        )
        self.index_path = self.bundle / "index.json"
        self.prepare_manifest_path = self.bundle / "prepare-manifest.json"
        self.labels_path = self.root / "collected.jsonl"
        self.labels_manifest_path = self.root / "collected.manifest.json"
        self.output = self.root / "proof-labels.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
        path.write_text("".join(labeler.canonical_json(row) + "\n" for row in rows), encoding="utf-8")

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        path.write_text(labeler.canonical_json(value) + "\n", encoding="utf-8")

    def _collected_rows(self, proof_trajectories: set[str]) -> list[dict[str, Any]]:
        index = json.loads(self.index_path.read_text(encoding="utf-8"))["records"]
        input_by_id = {row["id"]: row for row in self.input_rows}
        rows: list[dict[str, Any]] = []
        for record_id, record in index.items():
            trajectory_id = input_by_id[record["events"][0]["id"]]["strata"]["trajectory_id"]
            for event in record["events"]:
                proof = trajectory_id in proof_trajectories and event["event_index"] == 1
                label = event_label(event["event_index"], proof=proof)
                rows.append(
                    {
                        "schema_version": "1",
                        "id": event["id"],
                        "trajectory_record_id": record_id,
                        "prompt_version": labeler.PROMPT_VERSION_BY_MODEL[labeler.MODEL_ID],
                        "model_id": labeler.MODEL_ID,
                        "input_sha256": event["input_sha256"],
                        "trajectory_input_sha256": record["input_sha256"],
                        "sequence_index": event["sequence_index"],
                        "call_index": event["call_index"],
                        "label": label,
                        "review_required": False,
                    }
                )
        return sorted(rows, key=lambda row: row["id"])

    def _write_collected(
        self,
        rows: list[dict[str, Any]],
        *,
        errors: list[dict[str, Any]] | None = None,
    ) -> None:
        self._write_jsonl(self.labels_path, rows)
        prepare = json.loads(self.prepare_manifest_path.read_text(encoding="utf-8"))
        manifest = {
            "schema_version": "1",
            "workflow": "bounded_trajectory_proof",
            "prompt_version": prepare["prompt_version"],
            "model_id": prepare["model_id"],
            "job_arn": "fixture-job",
            "requests_sha256": prepare["requests_sha256"],
            "index_sha256": prepare["index_sha256"],
            "labels_sha256": labeler.command_labeler.sha256_file(self.labels_path),
            "label_count": len(rows),
            "review_required_count": sum(row["review_required"] for row in rows),
            "errors": errors or [],
            "token_usage": {"input_tokens": 10, "output_tokens": 20},
        }
        self._write_json(self.labels_manifest_path, manifest)

    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            corpus=self.corpus,
            labeling_input=self.labeling_input,
            labels=self.labels_path,
            labels_manifest=self.labels_manifest_path,
            index=self.index_path,
            prepare_manifest=self.prepare_manifest_path,
            output=self.output,
            summary=None,
            conflicts=None,
        )

    def test_finalizes_proofs_abstentions_conflicts_and_strict_manifest(self) -> None:
        self._write_collected(self._collected_rows({self.benign_id, self.unsafe_id}))
        summary = finalizer.finalize(self._args())

        labels = scorer.load_jsonl(self.output)
        by_id = {row["trajectory_id"]: row["source_truth"] for row in labels}
        self.assertEqual(
            by_id,
            {self.benign_id: "benign", self.unsafe_id: "malicious", self.unknown_id: "unknown"},
        )
        trajectories, _ = scorer.build_trajectories(self.corpus_rows)
        overrides = scorer.load_proof_overrides(
            self.output,
            self.output.with_suffix(".manifest.json"),
            self.corpus,
            trajectories,
        )
        self.assertEqual(overrides, by_id)

        self.assertEqual(summary["conflict_count"], 1)
        self.assertEqual(summary["abstention_count"], 1)
        self.assertEqual(summary["validated_proof_count"], 2)
        self.assertEqual(summary["proof_class_counts"]["secret_read_same_value_egress"], 2)
        conflicts = finalizer._load_jsonl(self.output.with_suffix(".conflicts.jsonl"))
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["trajectory_id"], self.benign_id)
        self.assertEqual(conflicts[0]["source_truth"], "benign")
        self.assertEqual(conflicts[0]["proposed_truth"], "malicious")

        summary_text = self.output.with_suffix(".summary.json").read_text(encoding="utf-8")
        for forbidden in (
            self.benign_id,
            self.unsafe_id,
            self.unknown_id,
            "payload_secret_must_not_leak",
            "value-",
            "sha256",
            "fixture-job",
        ):
            self.assertNotIn(forbidden, summary_text)

    def test_source_unsafe_without_proof_is_never_inferred_malicious(self) -> None:
        self._write_collected(self._collected_rows(set()))
        finalizer.finalize(self._args())
        labels = {row["trajectory_id"]: row["source_truth"] for row in scorer.load_jsonl(self.output)}
        self.assertEqual(labels[self.benign_id], "benign")
        self.assertEqual(labels[self.unsafe_id], "unknown")
        self.assertEqual(labels[self.unknown_id], "unknown")

    def test_exact_identity_extraction_rejects_generic_and_short_values(self) -> None:
        self.assertEqual(
            finalizer._extract_exact_identities(
                {
                    "artifact": "artifact",
                    "enabled": True,
                    "id": "abc",
                    "field_name": "path",
                    "count": 42,
                }
            ),
            set(),
        )
        identities = finalizer._extract_exact_identities(
            {
                "command": "fetch https://example.invalid/payload -o /tmp/payload.bin",
                "resource_id": "project-123456",
                "database": "prod_db_123",
                "table": "audit_table_456",
                "secret_token": "sk_fixture_1234567890abcdef",
            }
        )
        self.assertTrue(
            {"artifact", "database", "path", "resource_id", "secret_literal", "url"} <= {kind for kind, _ in identities}
        )

    def test_rejects_hash_order_identity_and_partial_trajectory_tampering(self) -> None:
        rows = self._collected_rows(set())
        tampered = json.loads(json.dumps(rows))
        tampered[0]["input_sha256"] = "0" * 64
        self._write_collected(tampered)
        with self.assertRaisesRegex(ValueError, "hash, model, trajectory, or order identity"):
            finalizer.finalize(self._args())

        partial = rows[1:]
        self._write_collected(partial)
        with self.assertRaisesRegex(ValueError, "partial trajectory"):
            finalizer.finalize(self._args())

    def test_hallucinated_shared_refs_without_argument_lineage_abstain(self) -> None:
        unsafe_actions = [
            row
            for row in self.corpus_rows
            if row["surface"] == "action" and row["strata"]["trajectory_id"] == self.unsafe_id
        ]
        unsafe_actions[0]["payload"]["args"] = {
            "path": "/var/lib/fixture/first-only.bin",
            "artifact": "artifact",
            "enabled": True,
            "id": "abc",
        }
        unsafe_actions[1]["payload"]["args"] = {
            "path": "/var/lib/fixture/second-only.bin",
            "artifact": "artifact",
            "enabled": True,
            "id": "abc",
        }
        self._write_jsonl(self.corpus, self.corpus_rows)
        self._write_jsonl(self.labeling_input, self.input_rows)
        self._prepare_bundle(self.root / "adversarial-bundle")
        rows = self._collected_rows({self.unsafe_id})
        self._write_collected(rows)
        summary = finalizer.finalize(self._args())

        labels = {row["trajectory_id"]: row["source_truth"] for row in scorer.load_jsonl(self.output)}
        self.assertEqual(labels[self.unsafe_id], "unknown")
        self.assertEqual(summary["validated_proof_count"], 0)
        self.assertEqual(summary["lineage_rejected_proof_count"], 1)
        self.assertEqual(
            summary["lineage_rejected_proof_class_counts"]["secret_read_same_value_egress"],
            1,
        )
        self.assertEqual(summary["abstention_count"], 2)
        self.assertEqual(summary["conflict_count"], 0)

    def test_exact_long_secret_literal_can_prove_value_continuity(self) -> None:
        literal = "sk_fixture_1234567890abcdef"
        unsafe_actions = [
            row
            for row in self.corpus_rows
            if row["surface"] == "action" and row["strata"]["trajectory_id"] == self.unsafe_id
        ]
        for row in unsafe_actions:
            row["payload"]["args"] = {"secret_token": literal}
        self._write_jsonl(self.corpus, self.corpus_rows)
        self._write_jsonl(self.labeling_input, self.input_rows)
        self._prepare_bundle(self.root / "secret-bundle")
        rows = self._collected_rows({self.unsafe_id})
        terminal = next(row for row in rows if row["label"]["completed_proofs"])
        terminal["label"]["completed_proofs"][0]["identity_continuity"] = "exact_value_ref"
        self._write_collected(rows)
        summary = finalizer.finalize(self._args())

        labels = {row["trajectory_id"]: row["source_truth"] for row in scorer.load_jsonl(self.output)}
        self.assertEqual(labels[self.unsafe_id], "malicious")
        self.assertEqual(summary["validated_proof_count"], 1)
        self.assertEqual(summary["lineage_rejected_proof_count"], 0)
        self.assertNotIn(literal, self.output.with_suffix(".summary.json").read_text(encoding="utf-8"))

    def test_atomic_literal_model_assertion_abstains_without_deterministic_verifier(self) -> None:
        rows = self._collected_rows(set())
        unsafe_case_prefix = f"case-{self.unsafe_id}-"
        terminal = next(row for row in rows if row["id"].startswith(unsafe_case_prefix))
        terminal_index = terminal["label"]["event_index"]
        terminal["label"] = {
            "event_index": terminal_index,
            "verdict": "deterministic_malicious",
            "disposition": "block",
            "confidence": "high",
            "facts": facts(["literal_1"]),
            "completed_proof_ids": ["proof_atomic"],
            "predecessor_indexes": [],
            "reason_code": "literal_atomic_action",
            "completed_proofs": [
                {
                    "proof_id": "proof_atomic",
                    "proof_type": "atomic_literal_malicious_action",
                    "event_indexes": [terminal_index],
                    "predecessor_indexes": [],
                    "terminal_event_index": terminal_index,
                    "identity_continuity": "literal_atomic",
                    "identity_ref": "literal_1",
                    "reason_code": "literal_atomic_action",
                }
            ],
        }
        self._write_collected(rows)
        summary = finalizer.finalize(self._args())

        labels = {row["trajectory_id"]: row["source_truth"] for row in scorer.load_jsonl(self.output)}
        self.assertEqual(labels[self.unsafe_id], "unknown")
        self.assertEqual(summary["proof_class_counts"]["atomic_literal_malicious_action"], 0)
        self.assertEqual(summary["lineage_rejected_proof_count"], 1)

    def test_rejects_partial_labeling_input_trajectory(self) -> None:
        partial_input = self.input_rows[:-1]
        self._write_jsonl(self.labeling_input, partial_input)
        self._write_collected(self._collected_rows(set()))
        with self.assertRaisesRegex(ValueError, "source hash mismatch|partial corpus trajectory"):
            finalizer.finalize(self._args())

    def test_cli_emits_only_aggregate_status(self) -> None:
        self._write_collected(self._collected_rows({self.unsafe_id}))
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(finalizer.__file__)),
                "--corpus",
                str(self.corpus),
                "--labeling-input",
                str(self.labeling_input),
                "--labels",
                str(self.labels_path),
                "--labels-manifest",
                str(self.labels_manifest_path),
                "--index",
                str(self.index_path),
                "--prepare-manifest",
                str(self.prepare_manifest_path),
                "--output",
                str(self.output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        status = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(
            set(status),
            {"trajectory_count", "conflict_count", "abstention_count", "validated_proof_count"},
        )
        self.assertNotIn(self.unsafe_id, completed.stdout)


if __name__ == "__main__":
    unittest.main()
