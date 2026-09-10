#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_label_trajectory_bedrock as labeler


def case(
    case_id: str,
    trajectory: str,
    sequence: int,
    call: int,
    *,
    split: str = "development",
    tool_name: str = "inspect_file",
    arguments: dict[str, object] | None = None,
) -> dict[str, object]:
    trajectory_id = labeler.sha256_text(trajectory)[:24]
    return {
        "id": case_id,
        "split": split,
        "source": {"original_id": f"{trajectory}/sequence-{sequence:06d}/call-{call:03d}"},
        "strata": {"split_group": "group-1", "trajectory_id": trajectory_id},
        "payload": {
            "direction": "tool_call",
            "tool_name": tool_name,
            "args": arguments if arguments is not None else {"path": f"item-{sequence}"},
            "observation": "must never leave the source row",
            "result": {"secret": "must never leave the source row"},
        },
        "truth": {"source_prose": "must never leave the source row"},
    }


def facts(*identity_refs: str) -> dict[str, object]:
    return {
        "operation": "read",
        "resource": "file",
        "scope": "single",
        "sensitivity": "secret",
        "destination_trust": "unknown",
        "control_flow": "unconditional",
        "result": "unknown",
        "identity_refs": sorted(identity_refs),
    }


def event(
    index: int,
    *,
    verdict: str = "contextual_or_dual_use",
    disposition: str = "detect_only",
    identity_refs: tuple[str, ...] = (),
    completed: list[str] | None = None,
    predecessors: list[int] | None = None,
) -> dict[str, object]:
    return {
        "event_index": index,
        "verdict": verdict,
        "disposition": disposition,
        "confidence": "high",
        "facts": facts(*identity_refs),
        "completed_proof_ids": completed or [],
        "predecessor_indexes": predecessors or [],
        "reason_code": "literal_action",
    }


def model_output(value: dict[str, object]) -> dict[str, object]:
    return {"choices": [{"message": {"content": json.dumps(value)}}]}


class TrajectoryBedrockLabelTests(unittest.TestCase):
    def test_parse_model_object_accepts_only_one_redundant_structured_wrapper(self):
        self.assertEqual(
            labeler.parse_model_object('<reasoning>done</reasoning>{\n{"events":[]}'),
            {"events": []},
        )
        self.assertEqual(
            labeler.parse_model_object('<reasoning>done</reasoning>{\n{"events":[]}\n}'),
            {"events": []},
        )
        with self.assertRaises(json.JSONDecodeError):
            labeler.parse_model_object('{{{"events":[]}}}')

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(
        self,
        rows: list[dict[str, object]],
        name: str = "bundle",
        *,
        frozen_rules_artifact: Path | None = None,
        candidate_manifest: Path | None = None,
    ) -> Path:
        input_path = self.root / f"{name}.jsonl"
        input_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        output_dir = self.root / name
        labeler.prepare(
            argparse.Namespace(
                input=input_path,
                output_dir=output_dir,
                model_id=labeler.MODEL_ID,
                max_completion_tokens=2048,
                max_trajectory_events=8,
                max_serialized_chars=4096,
                limit=0,
                frozen_rules_artifact=frozen_rules_artifact,
                candidate_manifest=candidate_manifest,
                allow_small=True,
            )
        )
        return output_dir

    def write_test_seal(
        self,
        *,
        candidate_id: str = "trajectory-candidate-001",
        policy_suffix: str = "a",
    ) -> tuple[Path, Path]:
        rules_path = self.root / f"{candidate_id}-rules.tar"
        rules_path.write_bytes(b"frozen deterministic rules\n")
        candidate_path = self.root / f"{candidate_id}.json"
        candidate_path.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "candidate_id": candidate_id,
                    "status": "frozen_for_sealed_test",
                    "frozen_rules_sha256": labeler.command_labeler.sha256_file(rules_path),
                    "profiles": {
                        profile: {"policy_sha256": policy_suffix * 64}
                        for profile in labeler.REQUIRED_POLICY_PROFILES
                    },
                }
            ),
            encoding="utf-8",
        )
        return rules_path, candidate_path

    def test_groups_complete_trajectories_and_orders_integer_ordinals(self) -> None:
        rows = [
            case("b", "rollout-b", 10, 0),
            case("a-10", "rollout-a", 10, 0),
            case("a-2", "rollout-a", 2, 1),
            case("a-2-0", "rollout-a", 2, 0),
        ]
        bundle = self.prepare(rows)
        requests = [json.loads(line) for line in (bundle / "requests.jsonl").read_text().splitlines()]
        self.assertEqual(len(requests), 2)
        request_by_count = {
            len(json.loads(item["modelInput"]["messages"][1]["content"])["events"]): item for item in requests
        }
        trajectory = json.loads(request_by_count[3]["modelInput"]["messages"][1]["content"])
        self.assertEqual(
            [item["arguments"]["path"] for item in trajectory["events"]],
            ["item-2", "item-2", "item-10"],
        )
        index = json.loads((bundle / "index.json").read_text())["records"]
        three_event = next(value for value in index.values() if value["event_count"] == 3)
        self.assertEqual(
            [(item["sequence_index"], item["call_index"]) for item in three_event["events"]],
            [(2, 0), (2, 1), (10, 0)],
        )

    def test_request_excludes_results_observations_and_source_prose(self) -> None:
        bundle = self.prepare([case("a", "rollout-a", 0, 0)])
        request_text = (bundle / "requests.jsonl").read_text()
        request = json.loads(request_text)
        user_text = request["modelInput"]["messages"][1]["content"]
        for forbidden in (
            "must never leave the source row",
            "observation",
            "source_prose",
            '"result":{"secret"',
        ):
            self.assertNotIn(forbidden, user_text)
        user_value = json.loads(user_text)
        self.assertEqual(set(user_value), {"trajectory_id", "events"})
        self.assertEqual(set(user_value["events"][0]), {"event_index", "tool_name", "arguments"})

    def test_refuses_mixed_splits_and_sealed_test_without_frozen_artifacts(self) -> None:
        with self.assertRaisesRegex(ValueError, "mixed splits"):
            self.prepare(
                [
                    case("a", "rollout-a", 0, 0, split="development"),
                    case("b", "rollout-b", 0, 0, split="validation"),
                ]
            )
        with self.assertRaisesRegex(ValueError, "sealed test"):
            self.prepare([case("test-a", "rollout-a", 0, 0, split="test")], "test-bundle")

    def test_test_seal_validates_and_hashes_rules_and_candidate(self) -> None:
        rules_path, candidate_path = self.write_test_seal()
        rules_sha256 = labeler.command_labeler.sha256_file(rules_path)

        bundle = self.prepare(
            [case("test-a", "rollout-a", 0, 0, split="test")],
            "sealed-bundle",
            frozen_rules_artifact=rules_path,
            candidate_manifest=candidate_path,
        )
        manifest = json.loads((bundle / "prepare-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["test_seal"],
            {
                "candidate_id": "trajectory-candidate-001",
                "candidate_manifest_sha256": labeler.command_labeler.sha256_file(candidate_path),
                "frozen_rules_artifact_sha256": rules_sha256,
                "policy_sha256_by_profile": {
                    profile: "a" * 64 for profile in labeler.REQUIRED_POLICY_PROFILES
                },
            },
        )

        rules_path.write_bytes(b"tampered deterministic rules\n")
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            self.prepare(
                [case("test-b", "rollout-b", 0, 0, split="test")],
                "tampered-bundle",
                frozen_rules_artifact=rules_path,
                candidate_manifest=candidate_path,
            )

    def test_test_seal_requires_all_valid_policy_digests(self) -> None:
        rules_path, candidate_path = self.write_test_seal()
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate.pop("profiles")
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "policy digests for all profiles"):
            self.prepare(
                [case("test-a", "rollout-a", 0, 0, split="test")],
                "missing-profiles-bundle",
                frozen_rules_artifact=rules_path,
                candidate_manifest=candidate_path,
            )

        for profile in labeler.REQUIRED_POLICY_PROFILES:
            with self.subTest(profile=profile):
                _, candidate_path = self.write_test_seal()
                candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
                candidate["profiles"][profile]["policy_sha256"] = "A" * 64
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, f"profile '{profile}'"):
                    self.prepare(
                        [case("test-a", "rollout-a", 0, 0, split="test")],
                        f"invalid-{profile}-policy-bundle",
                        frozen_rules_artifact=rules_path,
                        candidate_manifest=candidate_path,
                    )

    def test_submit_revalidates_complete_test_seal_and_records_it(self) -> None:
        rules_path, candidate_path = self.write_test_seal()
        bundle = self.prepare(
            [case("test-a", "rollout-a", 0, 0, split="test")],
            "sealed-submit-bundle",
            frozen_rules_artifact=rules_path,
            candidate_manifest=candidate_path,
        )
        prepared = json.loads((bundle / "prepare-manifest.json").read_text(encoding="utf-8"))
        submit_args = argparse.Namespace(
            bundle=bundle,
            s3_prefix="s3://private-bucket/sealed-trajectory-labels",
            role_arn="arn:aws:iam::123456789012:role/BedrockBatchRole",
            job_name="sealed-trajectory-labels",
            profile="devops",
            region="us-east-2",
            frozen_rules_artifact=None,
            candidate_manifest=None,
        )
        with self.assertRaisesRegex(ValueError, "sealed test rows without"):
            labeler.submit(submit_args)

        other_rules, other_candidate = self.write_test_seal(
            candidate_id="trajectory-candidate-002",
            policy_suffix="b",
        )
        submit_args.frozen_rules_artifact = other_rules
        submit_args.candidate_manifest = other_candidate
        with self.assertRaisesRegex(ValueError, "do not match the prepared test seal"):
            labeler.submit(submit_args)

        s3 = mock.Mock()
        bedrock = mock.Mock()
        bedrock.create_model_invocation_job.return_value = {"jobArn": "arn:aws:bedrock:test-job"}
        session = mock.Mock()
        session.client.side_effect = lambda service: {"s3": s3, "bedrock": bedrock}[service]
        submit_args.frozen_rules_artifact = rules_path
        submit_args.candidate_manifest = candidate_path
        with mock.patch.object(labeler.command_labeler.boto3, "Session", return_value=session):
            self.assertEqual(labeler.submit(submit_args), 0)
        s3.upload_file.assert_called_once()
        bedrock.create_model_invocation_job.assert_called_once()
        job = json.loads((bundle / "job.json").read_text(encoding="utf-8"))
        self.assertEqual(job["test_seal"], prepared["test_seal"])

    def test_test_seal_requires_explicitly_frozen_candidate_status(self) -> None:
        rules_path = self.root / "rules.tar"
        rules_path.write_bytes(b"frozen deterministic rules\n")
        candidate_path = self.root / "candidate.json"
        candidate_path.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "candidate_id": "trajectory-candidate-001",
                    "status": "development_simulation_only",
                    "frozen_rules_sha256": labeler.command_labeler.sha256_file(rules_path),
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "status must be"):
            self.prepare(
                [case("test-a", "rollout-a", 0, 0, split="test")],
                "unfrozen-bundle",
                frozen_rules_artifact=rules_path,
                candidate_manifest=candidate_path,
            )

    def test_prompt_and_output_enums_are_strict(self) -> None:
        self.assertIn("bounded ActionFacts", labeler.SYSTEM_PROMPT)
        self.assertIn("exact earlier predecessor event indexes", labeler.SYSTEM_PROMPT)
        self.assertIn("Use only these exact enum values", labeler.SYSTEM_PROMPT)
        value = {
            "trajectory_id": "trajectory-00000001",
            "events": [event(0)],
            "proofs": [],
        }
        normalized = labeler.normalize_trajectory_output(model_output(value), "trajectory-00000001", 1)
        self.assertEqual(normalized["events"][0]["disposition"], "detect_only")
        value["events"][0]["facts"]["operation"] = "invented"
        with self.assertRaisesRegex(ValueError, "invalid enum"):
            labeler.normalize_trajectory_output(model_output(value), "trajectory-00000001", 1)

    def test_prepare_uses_closed_bedrock_json_schema(self) -> None:
        bundle = self.prepare([case("a", "rollout-a", 0, 0)])
        request = json.loads((bundle / "requests.jsonl").read_text(encoding="utf-8"))
        response_format = request["modelInput"]["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        schema = response_format["json_schema"]["schema"]
        self.assertFalse(schema["additionalProperties"])
        event_schema = schema["properties"]["events"]["items"]
        facts_schema = event_schema["properties"]["facts"]
        self.assertFalse(event_schema["additionalProperties"])
        self.assertFalse(facts_schema["additionalProperties"])
        self.assertEqual(
            facts_schema["properties"]["operation"]["enum"],
            sorted(labeler.OPERATIONS),
        )
        self.assertEqual(
            event_schema["properties"]["confidence"]["enum"],
            sorted(labeler.CONFIDENCES),
        )

    def test_prepare_retry_selects_only_failed_complete_trajectories(self) -> None:
        parent = self.prepare(
            [
                case("success", "rollout-success", 0, 0),
                case("failed", "rollout-failed", 0, 0),
            ],
            "parent",
        )
        index = json.loads((parent / "index.json").read_text(encoding="utf-8"))["records"]
        success_record, failed_record = list(index)
        success_meta = index[success_record]["events"][0]
        success_event = {**event(0), "completed_proofs": []}
        successful_label = {
            "schema_version": labeler.SCHEMA_VERSION,
            "id": success_meta["id"],
            "trajectory_record_id": success_record,
            "prompt_version": labeler.PROMPT_VERSION_BY_MODEL[labeler.MODEL_ID],
            "model_id": labeler.MODEL_ID,
            "input_sha256": success_meta["input_sha256"],
            "trajectory_input_sha256": index[success_record]["input_sha256"],
            "sequence_index": success_meta["sequence_index"],
            "call_index": success_meta["call_index"],
            "label": success_event,
            "review_required": False,
        }
        labels_path = parent / "labels.jsonl"
        labels_path.write_text(labeler.canonical_json(successful_label) + "\n", encoding="utf-8")
        prepare_manifest = json.loads((parent / "prepare-manifest.json").read_text(encoding="utf-8"))
        labeler.command_labeler.write_json(
            parent / "labels.manifest.json",
            {
                "schema_version": labeler.SCHEMA_VERSION,
                "workflow": "bounded_trajectory_proof",
                "prompt_version": prepare_manifest["prompt_version"],
                "model_id": labeler.MODEL_ID,
                "job_arn": "test-job",
                "requests_sha256": prepare_manifest["requests_sha256"],
                "index_sha256": prepare_manifest["index_sha256"],
                "labels_sha256": labeler.command_labeler.sha256_file(labels_path),
                "label_count": 1,
                "review_required_count": 0,
                "errors": [
                    {
                        "record_id": failed_record,
                        "reason": "invalid_model_output",
                        "retryable": True,
                    }
                ],
                "token_usage": {"input_tokens": 100, "output_tokens": 50},
            },
        )

        retry = self.root / "retry"
        labeler.prepare_retry(argparse.Namespace(bundle=parent, output_dir=retry, allow_small=True))
        retry_requests = [
            json.loads(line) for line in (retry / "requests.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([row["recordId"] for row in retry_requests], [failed_record])
        self.assertIn("response_format", retry_requests[0]["modelInput"])
        retry_index = json.loads((retry / "index.json").read_text(encoding="utf-8"))["records"]
        self.assertEqual(retry_index, index)
        prior_rows = labeler.command_labeler.load_jsonl(retry / "prior-labels.jsonl")
        self.assertEqual([row["id"] for row in prior_rows], [success_meta["id"]])
        retry_manifest = json.loads((retry / "retry-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(retry_manifest["retry_record_ids"], [failed_record])
        prior, expected, usage = labeler._load_retry_context(
            retry,
            retry_index,
            labeler.MODEL_ID,
            labeler.PROMPT_VERSION_BY_MODEL[labeler.MODEL_ID],
        )
        self.assertEqual(set(prior), {success_meta["id"]})
        self.assertEqual(expected, {failed_record})
        self.assertEqual(usage, {"input_tokens": 100, "output_tokens": 50})

    def test_rejects_missing_identity_continuity_and_bad_proof_references(self) -> None:
        proof = {
            "proof_id": "proof_1",
            "proof_type": "secret_read_same_value_egress",
            "event_indexes": [0, 1],
            "predecessor_indexes": [0],
            "terminal_event_index": 1,
            "identity_continuity": "exact_file_ref",
            "identity_ref": "secret_file_1",
            "reason_code": "exact_file_egress",
        }
        good = {
            "trajectory_id": "trajectory-00000001",
            "events": [
                event(0, identity_refs=("secret_file_1",)),
                event(
                    1,
                    verdict="deterministic_malicious",
                    disposition="block",
                    identity_refs=("secret_file_1",),
                    completed=["proof_1"],
                    predecessors=[0],
                ),
            ],
            "proofs": [proof],
        }
        labeler.normalize_trajectory_output(model_output(good), "trajectory-00000001", 2)
        broken_identity = json.loads(json.dumps(good))
        broken_identity["events"][0]["facts"]["identity_refs"] = []
        with self.assertRaisesRegex(ValueError, "identity continuity"):
            labeler.normalize_trajectory_output(model_output(broken_identity), "trajectory-00000001", 2)
        broken_reference = json.loads(json.dumps(good))
        broken_reference["proofs"][0]["predecessor_indexes"] = [1]
        with self.assertRaisesRegex(ValueError, "predecessors"):
            labeler.normalize_trajectory_output(model_output(broken_reference), "trajectory-00000001", 2)

    def test_manifests_are_deterministic_value_free_and_record_safe_skips(self) -> None:
        long_rows = [case(f"long-{index}", "rollout-long", index, 0) for index in range(9)]
        first = self.prepare([case("a", "rollout-a", 0, 0), *long_rows], "first")
        second = self.prepare([*reversed(long_rows), case("a", "rollout-a", 0, 0)], "second")
        first_manifest = json.loads((first / "prepare-manifest.json").read_text())
        second_manifest = json.loads((second / "prepare-manifest.json").read_text())
        ignored = {"source_sha256", "requests_sha256"}
        self.assertEqual(
            {key: value for key, value in first_manifest.items() if key not in ignored},
            {key: value for key, value in second_manifest.items() if key not in ignored},
        )
        self.assertEqual(first_manifest["skipped"][0]["reason"], "trajectory_event_limit")
        manifest_text = (first / "prepare-manifest.json").read_text() + (first / "index.json").read_text()
        self.assertNotIn("item-", manifest_text)
        self.assertNotIn("must never leave", manifest_text)
        self.assertNotIn("rollout-long", manifest_text)


if __name__ == "__main__":
    unittest.main()
