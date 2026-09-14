#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import benchmark_normalize_dtap as normalizer


def agent_call(tool_name, arguments):
    return {
        "role": "agent",
        "metadata": {"tool_name": tool_name, "tool_params": arguments},
        "content": "agent prose is not action evidence",
    }


def tool_result(tool_name, state):
    return {"role": "tool", "metadata": {"tool_name": tool_name}, "state": state}


def trace(*trajectory, instruction="List the records"):
    return {
        "task_info": {"domain": "research", "task_id": "task-1", "original_instruction": instruction},
        "trajectory": list(trajectory),
    }


class DTapNormalizerTest(unittest.TestCase):
    def test_dataset_lock_has_one_canonical_dtap_source(self):
        benchmarks_root = Path(__file__).resolve().parent.parent
        lock = json.loads((benchmarks_root / "datasets.lock.json").read_text(encoding="utf-8"))
        matching = [
            entry
            for entry in lock["datasets"]
            if entry.get("source_url") == normalizer.SOURCE_URL
            and entry.get("revision") == normalizer.PINNED_REVISION
        ]
        self.assertEqual([entry["id"] for entry in matching], [normalizer.DATASET_ID])
        self.assertEqual(
            set(matching[0]["purpose"]),
            {
                "action",
                "stateful",
                "bounded-chain-candidate",
                "benign",
                "hard-negative",
                "real-tool-arguments",
                "trajectory-label-candidate",
            },
        )

    def test_parallel_calls_require_matching_non_error_results_and_keep_identity(self):
        source = trace(
            agent_call("search", {"query": "records"}),
            agent_call("search", {"query": "users"}),
            tool_result("search", {"success": True, "items": [1]}),
            tool_result("search", {"text": '{"success": true, "items": [2]}'}),
            agent_call("empty", {}),
            agent_call("failed", {"cmd": "not-authorized"}),
            tool_result("failed", {"success": False, "error": "denied"}),
            agent_call("unmatched", {"query": "never returns"}),
        )
        events = normalizer.normalized_events(source)
        self.assertEqual([event["tool_name"] for event in events], ["search", "search"])
        self.assertEqual([event["offset_seconds"] for event in events], [0, 1])
        self.assertEqual([event["outcome"] for event in events], ["succeeded", "succeeded"])
        self.assertEqual([event["args"]["query"] for event in events], ["records", "users"])

    def test_unknown_but_non_error_result_is_kept_and_literal_state_is_safe(self):
        source = trace(
            agent_call("lookup", {"key": "abc"}),
            tool_result("lookup", "{'text': '{\"value\": 7}'}"),
        )
        events = normalizer.normalized_events(source)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["outcome"], "unknown")

    def test_plain_error_result_is_not_evidence(self):
        source = trace(
            agent_call("lookup", {"key": "abc"}),
            tool_result("lookup", "Error: permission denied"),
        )
        self.assertEqual(normalizer.normalized_events(source), [])

    def test_normalize_is_english_only_and_labels_are_source_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benign = root / "research" / "benign"
            malicious = root / "research" / "malicious" / "direct" / "dangerous-actions"
            benign.mkdir(parents=True)
            malicious.mkdir(parents=True)
            good = trace(agent_call("read", {"path": "/tmp/report"}), tool_result("read", {"success": True}))
            bad_language = trace(
                agent_call("read", {"path": "/tmp/report"}),
                tool_result("read", {"success": True}),
                instruction="列出报告",
            )
            malicious_candidate = trace(
                agent_call("write", {"path": "/tmp/report", "content": "candidate"}),
                tool_result("write", {"success": True}),
            )
            (benign / "one.json").write_text(json.dumps(good), encoding="utf-8")
            (benign / "judge_result.json").write_text(json.dumps({"task_success": True}), encoding="utf-8")
            (malicious / "two.json").write_text(json.dumps(bad_language), encoding="utf-8")
            (malicious / "three.json").write_text(json.dumps(malicious_candidate), encoding="utf-8")
            (malicious / "judge_result.json").write_text(json.dumps({"attack_success": True}), encoding="utf-8")
            rows, counts = normalizer.normalize(root, normalizer.PINNED_REVISION)
        self.assertEqual(len(rows), 2)
        by_truth = {row["truth"]["source_truth"]: row for row in rows}
        benign_truth = by_truth["benign"]["truth"]
        self.assertEqual(benign_truth["deterministic_truth"], "benign")
        self.assertEqual(benign_truth["expected_disposition"], "allow")
        self.assertEqual(benign_truth["applicability"], "in_scope")
        malicious_truth = by_truth["malicious"]["truth"]
        self.assertEqual(malicious_truth["deterministic_truth"], "contextual_or_dual_use")
        self.assertEqual(malicious_truth["expected_disposition"], "detect_only")
        self.assertEqual(malicious_truth["applicability"], "out_of_scope")
        self.assertEqual(malicious_truth["exclusion_reason"], normalizer.MALICIOUS_EXCLUSION_REASON)
        self.assertIn("trajectory_success_candidate", malicious_truth["categories"])
        self.assertIn("proof_pending", malicious_truth["categories"])
        self.assertEqual(counts["non_english"], 1)
        self.assertEqual(counts["benign_cases"], 1)
        self.assertEqual(counts["proof_pending_cases"], 1)
        self.assertTrue(all(row["source"]["revision"] == normalizer.PINNED_REVISION for row in rows))

    def test_bounded_chunks_and_revision_guard(self):
        events = [
            {"args": {"n": index}, "dialect": "none", "offset_seconds": index, "outcome": "unknown", "tool_name": "x"}
            for index in range(normalizer.MAX_EVENTS + 1)
        ]
        projected = normalizer.bounded_payloads(events)
        self.assertEqual([surface for surface, _ in projected], ["stateful", "action"])
        self.assertEqual(len(projected[0][1]["events"]), normalizer.MAX_EVENTS)
        sparse = [
            {"_ordinal": 0, "args": {"n": 0}, "dialect": "none", "offset_seconds": 0, "outcome": "unknown", "tool_name": "x"},
            {"_ordinal": 1, "args": {"n": 1}, "dialect": "none", "offset_seconds": 1, "outcome": "unknown", "tool_name": "x"},
            {"_ordinal": normalizer.MAX_EVENTS, "args": {"n": 1}, "dialect": "none", "offset_seconds": normalizer.MAX_EVENTS, "outcome": "unknown", "tool_name": "x"},
        ]
        sparse_projected = normalizer.bounded_payloads_from_source(sparse, normalizer.MAX_EVENTS + 1)
        self.assertEqual(len(sparse_projected), 2)
        self.assertNotIn("_ordinal", sparse_projected[0][1]["events"][0])
        with self.assertRaises(ValueError):
            normalizer.normalize(Path("/does/not/exist"), "not-the-pinned-revision")

    def test_strict_manifest_is_value_free_and_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benign = root / "research" / "benign"
            benign.mkdir(parents=True)
            (benign / "one.json").write_text(
                json.dumps(
                    trace(
                        agent_call("read", {"path": "/tmp/report"}),
                        tool_result("read", {"success": True}),
                    )
                ),
                encoding="utf-8",
            )
            (benign / "judge_result.json").write_text(
                json.dumps({"task_success": True}), encoding="utf-8"
            )
            first_rows, first_counts = normalizer.normalize(
                root, normalizer.PINNED_REVISION
            )
            second_rows, second_counts = normalizer.normalize(
                root, normalizer.PINNED_REVISION
            )
            first_body = normalizer.encode_rows(first_rows)
            second_body = normalizer.encode_rows(second_rows)
            first = normalizer.strict_manifest(
                first_rows, first_counts, root, normalizer.PINNED_REVISION
            )
            second = normalizer.strict_manifest(
                second_rows, second_counts, root, normalizer.PINNED_REVISION
            )
        self.assertEqual(first_body, second_body)
        self.assertEqual(first, second)
        self.assertEqual(
            set(first),
            {
                "adapter_statistics",
                "cases",
                "counts",
                "datasets",
                "exact_payload_duplicates_removed",
                "label_conflicts_excluded",
                "output_sha256",
                "schema_version",
                "source",
            },
        )
        self.assertEqual({normalizer.DATASET_ID: 1}, first["counts"])
        self.assertTrue(
            all(
                type(value) is int
                for value in first["adapter_statistics"][normalizer.ADAPTER].values()
            )
        )
        self.assertEqual("download-only", first["source"]["redistribution"])
        self.assertNotIn("/tmp/report", json.dumps(first, sort_keys=True))

    def test_existing_canonical_sidecar_repair_preserves_statistics_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benign = root / "research" / "benign"
            benign.mkdir(parents=True)
            (benign / "one.json").write_text(
                json.dumps(
                    trace(
                        agent_call("read", {"path": "/tmp/private-report"}),
                        tool_result("read", {"success": True}),
                    )
                ),
                encoding="utf-8",
            )
            (benign / "judge_result.json").write_text(
                json.dumps({"task_success": True}), encoding="utf-8"
            )
            rows, counts = normalizer.normalize(root, normalizer.PINNED_REVISION)
            body = normalizer.encode_rows(rows)
            corpus = root.parent / "cases.jsonl"
            corpus.write_bytes(body)
            legacy = {
                "counts": dict(counts),
                "dataset": normalizer.DATASET_ID,
                "label_limitation": "value-free label contract",
                "license": normalizer.LICENSE,
                "output_sha256": hashlib.sha256(body).hexdigest(),
                "revision": normalizer.PINNED_REVISION,
                "row_count": len(rows),
                "schema_version": normalizer.SCHEMA_VERSION,
                "source_url": normalizer.SOURCE_URL,
            }
            legacy_path = root.parent / "legacy.json"
            legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
            first = normalizer.repair_existing_manifest(corpus, legacy_path)
            second = normalizer.repair_existing_manifest(corpus, legacy_path)
        self.assertEqual(first, second)
        self.assertEqual({normalizer.DATASET_ID: len(rows)}, first["counts"])
        self.assertEqual(
            dict(sorted(counts.items())),
            first["adapter_statistics"][normalizer.ADAPTER],
        )
        self.assertEqual(
            "download-only", first["trajectory_source"]["redistribution"]
        )
        self.assertEqual(
            normalizer.PINNED_REVISION, first["trajectory_source"]["revision"]
        )
        self.assertNotIn("/tmp/private-report", json.dumps(first, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
