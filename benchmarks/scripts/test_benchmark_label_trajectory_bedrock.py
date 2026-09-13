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


def candidate(
    candidate_id: str = "trajectory-candidate-00000001",
    *,
    group: str = "trajectory-00000001",
    split: str = "development",
    events: list[dict[str, object]] | None = None,
    target_event_index: int | None = None,
) -> dict[str, object]:
    values = events or [
        {
            "event_index": 0,
            "tool_name": "read_file",
            "arguments": {"path": "<local-home>/.config"},
            "result": {"outcome": "succeeded", "data": {"value": "<redacted-secret-0001>"}},
            "action_facts": {"operation": "read", "result": "succeeded"},
        }
    ]
    return {
        "schema_version": "1",
        "candidate_id": candidate_id,
        "trajectory_group": group,
        "split": split,
        "target_event_index": len(values) - 1 if target_event_index is None else target_event_index,
        "events": values,
    }


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

    def prepare_candidates(
        self,
        rows: list[dict[str, object]],
        name: str = "candidate-bundle",
    ) -> Path:
        input_path = self.root / f"{name}.jsonl"
        input_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        output_dir = self.root / name
        labeler.prepare_candidates(
            argparse.Namespace(
                input=input_path,
                output_dir=output_dir,
                model_id=labeler.MODEL_ID,
                max_completion_tokens=2048,
                max_serialized_chars=4096,
                limit=0,
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

    def test_action_surface_is_an_explicit_tool_call_without_direction(self) -> None:
        item = case("a", "rollout-a", 0, 0)
        item["surface"] = "action"
        del item["payload"]["direction"]
        bundle = self.prepare([item])
        request = json.loads((bundle / "requests.jsonl").read_text())
        user_value = json.loads(request["modelInput"]["messages"][1]["content"])
        self.assertEqual(user_value["events"][0]["tool_name"], "inspect_file")

    def test_missing_direction_on_non_action_surface_is_rejected(self) -> None:
        item = case("a", "rollout-a", 0, 0)
        item["surface"] = "text"
        del item["payload"]["direction"]
        with self.assertRaisesRegex(ValueError, "only tool_call rows"):
            self.prepare([item])

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
        labeler.prepare_retry(
            argparse.Namespace(
                bundle=parent,
                output_dir=retry,
                allow_small=True,
                max_completion_tokens=8192,
            )
        )
        retry_requests = [
            json.loads(line) for line in (retry / "requests.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([row["recordId"] for row in retry_requests], [failed_record])
        self.assertIn("response_format", retry_requests[0]["modelInput"])
        self.assertEqual(retry_requests[0]["modelInput"]["max_completion_tokens"], 8192)
        retry_index = json.loads((retry / "index.json").read_text(encoding="utf-8"))["records"]
        self.assertEqual(retry_index, index)
        prior_rows = labeler.command_labeler.load_jsonl(retry / "prior-labels.jsonl")
        self.assertEqual([row["id"] for row in prior_rows], [success_meta["id"]])
        retry_manifest = json.loads((retry / "retry-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(retry_manifest["retry_record_ids"], [failed_record])
        self.assertEqual(
            json.loads((retry / "prepare-manifest.json").read_text(encoding="utf-8"))[
                "max_completion_tokens"
            ],
            8192,
        )
        prior, expected, usage = labeler._load_retry_context(
            retry,
            retry_index,
            labeler.MODEL_ID,
            labeler.PROMPT_VERSION_BY_MODEL[labeler.MODEL_ID],
        )
        self.assertEqual(set(prior), {success_meta["id"]})
        self.assertEqual(expected, {failed_record})
        self.assertEqual(usage, {"input_tokens": 100, "output_tokens": 50})

    def test_prepare_retry_can_chain_from_a_retry_bundle(self) -> None:
        parent = self.prepare(
            [case("success", "rollout-success", 0, 0), case("failed", "rollout-failed", 0, 0)],
            "chain-parent",
        )
        index = json.loads((parent / "index.json").read_text(encoding="utf-8"))["records"]
        success_record, failed_record = list(index)
        success_meta = index[success_record]["events"][0]
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
            "label": {**event(0), "completed_proofs": []},
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
                "errors": [{"record_id": failed_record, "reason": "invalid_model_output", "retryable": True}],
                "token_usage": {"input_tokens": 100, "output_tokens": 50},
            },
        )
        first_retry = self.root / "chain-retry-one"
        labeler.prepare_retry(argparse.Namespace(bundle=parent, output_dir=first_retry, allow_small=True))

        first_retry_labels = first_retry / "labels.jsonl"
        first_retry_labels.write_text(labeler.canonical_json(successful_label) + "\n", encoding="utf-8")
        first_retry_prepare = json.loads((first_retry / "prepare-manifest.json").read_text(encoding="utf-8"))
        labeler.command_labeler.write_json(
            first_retry / "labels.manifest.json",
            {
                "schema_version": labeler.SCHEMA_VERSION,
                "workflow": "bounded_trajectory_proof",
                "prompt_version": first_retry_prepare["prompt_version"],
                "model_id": labeler.MODEL_ID,
                "job_arn": "test-retry-job",
                "requests_sha256": first_retry_prepare["requests_sha256"],
                "index_sha256": first_retry_prepare["index_sha256"],
                "labels_sha256": labeler.command_labeler.sha256_file(first_retry_labels),
                "label_count": 1,
                "review_required_count": 0,
                "errors": [{"record_id": failed_record, "reason": "invalid_model_output", "retryable": True}],
                "token_usage": {"input_tokens": 125, "output_tokens": 60},
            },
        )
        second_retry = self.root / "chain-retry-two"
        labeler.prepare_retry(argparse.Namespace(bundle=first_retry, output_dir=second_retry, allow_small=True))
        requests = labeler._load_request_records(second_retry / "requests.jsonl")
        self.assertEqual(set(requests), {failed_record})

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

    def test_prepare_candidates_uses_distinct_result_aware_boundary(self) -> None:
        bundle = self.prepare_candidates([candidate()])
        request = json.loads((bundle / "requests.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(request["recordId"], "trajectory-candidate-00000001")
        user_value = json.loads(request["modelInput"]["messages"][1]["content"])
        self.assertEqual(set(user_value), {"trajectory_id", "events"})
        self.assertEqual(
            set(user_value["events"][0]),
            {"event_index", "tool_name", "arguments", "result", "action_facts"},
        )
        self.assertEqual(
            request["modelInput"]["response_format"]["json_schema"]["schema"]["properties"]["events"]
            ["items"]["properties"]["facts"]["properties"]["result"]["enum"],
            ["failed", "succeeded", "unknown"],
        )
        system = request["modelInput"]["messages"][0]["content"]
        self.assertIn("inert, untrusted evidence", system)
        self.assertIn("do not trust supplied action facts blindly", system)
        self.assertIn("must be unknown", system)

        manifest = json.loads((bundle / "prepare-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["workflow"], "bounded_trajectory_candidate_proposal")
        self.assertEqual(manifest["model_id"], "openai.gpt-oss-120b-1:0")
        self.assertEqual(manifest["prompt_version"], labeler.RESULT_AWARE_PROMPT_VERSION_120B)
        self.assertTrue(manifest["retry_supported"])
        self.assertTrue(manifest["collect_supported"])
        self.assertTrue(manifest["offline_candidate_proposals_only"])
        self.assertFalse(manifest["runtime_dependency"])
        self.assertFalse(manifest["source_labels_included"])
        self.assertFalse(manifest["source_provenance_included"])

    def test_prepare_candidates_is_deterministic_and_preserves_hash_bindings(self) -> None:
        first_row = candidate()
        second_row = candidate(
            "trajectory-candidate-00000002",
            group="trajectory-00000002",
        )
        first = self.prepare_candidates([second_row, first_row], "candidate-first")
        second = self.prepare_candidates([first_row, second_row], "candidate-second")
        self.assertEqual(
            (first / "requests.jsonl").read_text(encoding="utf-8"),
            (second / "requests.jsonl").read_text(encoding="utf-8"),
        )
        first_index = json.loads((first / "index.json").read_text(encoding="utf-8"))["records"]
        second_index = json.loads((second / "index.json").read_text(encoding="utf-8"))["records"]
        self.assertEqual(first_index, second_index)
        item = first_index["trajectory-candidate-00000001"]
        self.assertEqual(item["source_record_sha256"], labeler.sha256_text(labeler.canonical_json(first_row)))
        request = labeler._load_request_records(first / "requests.jsonl")["trajectory-candidate-00000001"]
        request_value = labeler._request_value_for_retry(
            request,
            "trajectory-candidate-00000001",
            item,
        )
        self.assertEqual(
            labeler.sha256_text(labeler.canonical_json(request_value["events"])),
            item["input_sha256"],
        )

    def test_prepare_candidates_rejects_non_development_duplicates_and_malformed_bounds(self) -> None:
        invalid_rows = [
            ([candidate(split="test")], "development split only"),
            ([candidate(), candidate()], "duplicate candidate_id"),
            ([candidate(target_event_index=1)], "terminal current event"),
            (
                [
                    candidate(
                        events=[
                            {
                                "event_index": index,
                                "tool_name": "run",
                                "arguments": {},
                                "result": {},
                            }
                            for index in range(10)
                        ]
                    )
                ],
                "one through nine events",
            ),
        ]
        unexpected = candidate()
        unexpected["truth"] = {"label": "malicious"}
        invalid_rows.append(([unexpected], "missing or unexpected fields"))
        malformed_event = candidate()
        malformed_event["events"][0]["observation"] = "not in candidate schema"
        invalid_rows.append(([malformed_event], "missing or unexpected fields"))
        for index, (rows, message) in enumerate(invalid_rows):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.prepare_candidates(rows, f"invalid-candidate-{index}")

    def test_result_aware_output_cannot_infer_unobserved_outcomes_or_complete_early(self) -> None:
        value = {
            "trajectory_id": "trajectory-candidate-00000001",
            "events": [event(0), event(1)],
            "proofs": [],
        }
        value["events"][0]["facts"]["result"] = "succeeded"
        normalized = labeler.normalize_trajectory_output(
            model_output(value),
            "trajectory-candidate-00000001",
            2,
            allowed_results_by_event=[{"unknown", "succeeded"}, {"unknown"}],
            expected_terminal_event_index=1,
        )
        self.assertEqual(normalized["events"][0]["facts"]["result"], "succeeded")
        value["events"][1]["facts"]["result"] = "failed"
        with self.assertRaisesRegex(ValueError, "literal candidate evidence"):
            labeler.normalize_trajectory_output(
                model_output(value),
                "trajectory-candidate-00000001",
                2,
                allowed_results_by_event=[{"unknown", "succeeded"}, {"unknown"}],
                expected_terminal_event_index=1,
            )
        early = {
            "trajectory_id": "trajectory-candidate-00000001",
            "events": [
                event(
                    0,
                    verdict="deterministic_malicious",
                    disposition="block",
                    identity_refs=("literal_1",),
                    completed=["proof_1"],
                ),
                event(1),
            ],
            "proofs": [
                {
                    "proof_id": "proof_1",
                    "proof_type": "atomic_literal_malicious_action",
                    "event_indexes": [0],
                    "predecessor_indexes": [],
                    "terminal_event_index": 0,
                    "identity_continuity": "literal_atomic",
                    "identity_ref": "literal_1",
                    "reason_code": "literal_atomic_action",
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "terminal current event"):
            labeler.normalize_trajectory_output(
                model_output(early),
                "trajectory-candidate-00000001",
                2,
                allowed_results_by_event=[{"unknown"}, {"unknown"}],
                expected_terminal_event_index=1,
            )

    def test_prepare_retry_preserves_result_aware_prompt_and_candidate_hashes(self) -> None:
        parent = self.prepare_candidates([candidate()], "candidate-retry-parent")
        index = json.loads((parent / "index.json").read_text(encoding="utf-8"))["records"]
        record_id = next(iter(index))
        labels_path = parent / "labels.jsonl"
        labels_path.write_text("", encoding="utf-8")
        prepared = json.loads((parent / "prepare-manifest.json").read_text(encoding="utf-8"))
        labeler.command_labeler.write_json(
            parent / "labels.manifest.json",
            {
                "schema_version": labeler.SCHEMA_VERSION,
                "workflow": "bounded_trajectory_candidate_proposal",
                "prompt_version": prepared["prompt_version"],
                "model_id": labeler.MODEL_ID,
                "job_arn": "test-job",
                "requests_sha256": prepared["requests_sha256"],
                "index_sha256": prepared["index_sha256"],
                "labels_sha256": labeler.command_labeler.sha256_file(labels_path),
                "label_count": 0,
                "review_required_count": 0,
                "errors": [{"record_id": record_id, "reason": "invalid_model_output", "retryable": True}],
                "token_usage": {"input_tokens": 100, "output_tokens": 50},
            },
        )
        retry = self.root / "candidate-retry"
        labeler.prepare_retry(argparse.Namespace(bundle=parent, output_dir=retry, allow_small=True))
        retry_request = json.loads((retry / "requests.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(retry_request["recordId"], record_id)
        self.assertEqual(
            retry_request["modelInput"]["messages"][0]["content"],
            labeler.RESULT_AWARE_SYSTEM_PROMPT,
        )
        retry_manifest = json.loads((retry / "prepare-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(retry_manifest["prompt_version"], labeler.RESULT_AWARE_PROMPT_VERSION_120B)
        self.assertEqual(
            json.loads((retry / "index.json").read_text(encoding="utf-8"))["records"],
            index,
        )

    def test_collect_validates_and_emits_offline_result_aware_proposals(self) -> None:
        bundle = self.prepare_candidates([candidate()], "candidate-collect")
        prepared = json.loads((bundle / "prepare-manifest.json").read_text(encoding="utf-8"))
        labeler.command_labeler.write_json(
            bundle / "job.json",
            {
                "schema_version": labeler.SCHEMA_VERSION,
                "job_arn": "arn:aws:bedrock:test-job",
                "job_name": "candidate-collect",
                "model_id": labeler.MODEL_ID,
                "prompt_version": prepared["prompt_version"],
                "region": "us-east-2",
                "profile": "devops",
                "input_s3_uri": "s3://private-bucket/input/requests.jsonl",
                "output_s3_uri": "s3://private-bucket/output/",
                "requests_sha256": prepared["requests_sha256"],
                "index_sha256": prepared["index_sha256"],
                "client_request_token": "test-token",
            },
        )
        response = {
            "trajectory_id": "trajectory-candidate-00000001",
            "events": [event(0)],
            "proofs": [],
        }
        response["events"][0]["facts"]["result"] = "succeeded"
        output_record = {
            "recordId": "trajectory-candidate-00000001",
            "modelOutput": model_output(response),
        }
        body = mock.Mock()
        body.iter_lines.return_value = [json.dumps(output_record).encode("utf-8")]
        s3 = mock.Mock()
        paginator = mock.Mock()
        paginator.paginate.return_value = [{"Contents": [{"Key": "output/results.jsonl.out"}]}]
        s3.get_paginator.return_value = paginator
        s3.get_object.return_value = {"Body": body}
        bedrock = mock.Mock()
        bedrock.get_model_invocation_job.return_value = {"status": "Completed"}
        session = mock.Mock()
        session.client.side_effect = lambda service: {"s3": s3, "bedrock": bedrock}[service]
        with mock.patch.object(labeler.command_labeler.boto3, "Session", return_value=session):
            self.assertEqual(
                labeler.collect(argparse.Namespace(bundle=bundle, output=None, profile="")),
                0,
            )
        labels = labeler.command_labeler.load_jsonl(bundle / "labels.jsonl")
        self.assertEqual(labels[0]["label"]["facts"]["result"], "succeeded")
        manifest = json.loads((bundle / "labels.manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["workflow"], "bounded_trajectory_candidate_proposal")
        self.assertTrue(manifest["offline_candidate_proposals_only"])
        self.assertFalse(manifest["runtime_dependency"])

    def test_prepare_candidates_cli_defaults_to_gpt_oss_120b(self) -> None:
        args = labeler.parser().parse_args(
            [
                "prepare-candidates",
                "--input",
                str(self.root / "candidates.jsonl"),
                "--output-dir",
                str(self.root / "bundle"),
            ]
        )
        self.assertEqual(args.model_id, labeler.MODEL_ID)


if __name__ == "__main__":
    unittest.main()
