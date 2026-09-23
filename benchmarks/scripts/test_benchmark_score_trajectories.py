#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

scorer = importlib.import_module("benchmark_score_trajectories")


def case(trajectory: str, sequence: int, truth: str, split: str = "validation") -> dict[str, object]:
    case_id = f"case-{trajectory}-{sequence}"
    return {
        "schema_version": "1",
        "id": case_id,
        "source": {
            "dataset": "fixture/source-prose-must-not-leak",
            "revision": "fixture-revision",
            "original_id": f"source-prose-{trajectory}-{sequence}",
            "license": "Apache-2.0",
            "redistribution": "aggregate-only",
        },
        "split": split,
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "tool_name": "payload-tool-must-not-leak",
            "args": {"secret": "payload-value-must-not-leak"},
        },
        "truth": {
            "source_truth": truth,
            "applicability": "in_scope",
            "expected_disposition": "allow" if truth == "benign" else "detect_only",
        },
        "strata": {
            "trajectory_id": trajectory,
            "sequence_index": sequence,
            "call_index": sequence % 2,
        },
    }


def prediction(
    case_id: str,
    profile: str,
    *,
    detected: bool = False,
    blocked: bool = False,
    findings: int = 0,
    alerted: bool | None = None,
    audit_findings: int = 0,
) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": "1",
        "run_id": "fixture-run",
        "case_id": case_id,
        "engine": "defenseclaw",
        "profile": profile,
        "applicable": True,
        "detected": detected,
        "action": "block" if blocked else ("alert" if detected else "allow"),
        "severity": "HIGH" if detected else "NONE",
        "rule_ids": ["RULE-MUST-NOT-LEAK"] if detected else [],
        "finding_count": findings,
        "duration_micros": 1,
    }
    if alerted is not None:
        row["alerted"] = alerted
        row["audit_finding_count"] = audit_findings
        row["alert_finding_count"] = findings - audit_findings
    return row


class TrajectoryScorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cases = [
            case("a" * 24, 0, "benign"),
            case("a" * 24, 1, "benign"),
            case("b" * 24, 0, "malicious"),
            case("b" * 24, 1, "malicious"),
            case("b" * 24, 2, "malicious"),
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_jsonl(self, path: Path, rows: list[dict[str, object]]) -> None:
        path.write_bytes(b"".join(scorer.canonical_json(row) for row in rows))

    def parsed(self, predictions: list[dict[str, object]], rows: list[dict[str, object]] | None = None):
        trajectories, case_ids = scorer.build_trajectories(rows or self.cases)
        indexed, profiles = scorer.load_predictions(predictions, case_ids)
        return trajectories, indexed, profiles

    def complete_predictions(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for profile in ("default", "strict"):
            for item in self.cases:
                case_id = str(item["id"])
                is_attack = case_id.startswith(f"case-{'b' * 24}")
                sequence = int(item["strata"]["sequence_index"])  # type: ignore[index]
                rows.append(
                    prediction(
                        case_id,
                        profile,
                        detected=is_attack and sequence == 1 or profile == "strict" and not is_attack and sequence == 1,
                        blocked=is_attack and sequence == 2 or profile == "strict" and not is_attack and sequence == 1,
                        findings=2 if not is_attack and sequence == 1 else 0,
                    )
                )
        return rows

    def test_scores_trajectory_detection_enforcement_latency_and_noise(self) -> None:
        trajectories, predictions, profiles = self.parsed(self.complete_predictions())
        report = scorer.score(trajectories, predictions, profiles)
        self.assertEqual([row["profile"] for row in report["profiles"]], ["default", "strict"])
        default = report["profiles"][0]
        self.assertEqual(
            default["detection"]["confusion"],
            {"true_positive": 1, "true_negative": 1, "false_positive": 0, "false_negative": 0},
        )
        self.assertEqual(default["detection"]["f1"], 1.0)
        self.assertEqual(default["enforcement"]["f1"], 1.0)
        self.assertEqual(default["calls_before_first_detection"]["mean"], 1.0)
        self.assertEqual(default["calls_before_first_block"]["mean"], 2.0)
        self.assertEqual(default["benign_trajectory_block_rate"]["value"], 0.0)
        self.assertEqual(default["benign_findings_per_trajectory"]["mean"], 2.0)
        strict = report["profiles"][1]
        self.assertEqual(strict["detection"]["confusion"]["false_positive"], 1)
        self.assertEqual(strict["enforcement"]["confusion"]["false_positive"], 1)
        self.assertEqual(strict["benign_trajectory_block_rate"]["value"], 1.0)
        self.assertGreater(default["detection"]["recall_95"]["upper"], 0.0)

    def test_audit_only_detection_is_not_a_user_visible_alert(self) -> None:
        benign = [case("c" * 24, 0, "benign")]
        rows = [
            prediction(
                str(benign[0]["id"]),
                "default",
                detected=True,
                alerted=False,
                findings=2,
                audit_findings=2,
            )
        ]
        trajectories, predictions, profiles = self.parsed(rows, benign)
        report = scorer.score(trajectories, predictions, profiles)["profiles"][0]
        self.assertEqual(report["detection"]["confusion"]["false_positive"], 1)
        self.assertEqual(report["alert"]["confusion"]["false_positive"], 0)
        self.assertEqual(report["benign_trajectory_alert_rate"]["value"], 0.0)
        self.assertEqual(report["benign_findings_per_trajectory"]["audit_findings"], 2)
        self.assertEqual(report["benign_findings_per_trajectory"]["alert_findings"], 0)

    def test_alert_cannot_exist_without_detection(self) -> None:
        benign = [case("c" * 24, 0, "benign")]
        row = prediction(str(benign[0]["id"]), "default", alerted=True)
        _, case_ids = scorer.build_trajectories(benign)
        with self.assertRaisesRegex(ValueError, "cannot alert without"):
            scorer.load_predictions([row], case_ids)

    def test_report_is_value_free_and_deterministic(self) -> None:
        trajectories, predictions, profiles = self.parsed(list(reversed(self.complete_predictions())))
        first = scorer.canonical_json(scorer.score(trajectories, predictions, profiles))
        trajectories_again, predictions_again, profiles_again = self.parsed(self.complete_predictions())
        second = scorer.canonical_json(scorer.score(trajectories_again, predictions_again, profiles_again))
        self.assertEqual(first, second)
        text = first.decode()
        for forbidden in (
            "case-",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbb",
            "payload-tool-must-not-leak",
            "payload-value-must-not-leak",
            "RULE-MUST-NOT-LEAK",
            "source-prose-must-not-leak",
            "source-prose-",
            "fixture-run",
        ):
            self.assertNotIn(forbidden, text)

    def test_rejects_mixed_truth_cross_split_and_duplicate_order(self) -> None:
        mixed = [case("c" * 24, 0, "benign"), case("c" * 24, 1, "malicious")]
        with self.assertRaisesRegex(ValueError, "mixed source truth"):
            scorer.build_trajectories(mixed)
        leaked = [case("c" * 24, 0, "benign", "development"), case("c" * 24, 1, "benign", "test")]
        with self.assertRaisesRegex(ValueError, "leaks across splits"):
            scorer.build_trajectories(leaked)
        duplicated = [case("c" * 24, 0, "benign"), case("c" * 24, 1, "benign")]
        duplicated[1]["strata"]["sequence_index"] = 0
        duplicated[1]["strata"]["call_index"] = 0
        with self.assertRaisesRegex(ValueError, "duplicate call ordinals"):
            scorer.build_trajectories(duplicated)

    def test_rejects_duplicate_missing_and_partial_profile_predictions(self) -> None:
        complete = self.complete_predictions()
        _, case_ids = scorer.build_trajectories(self.cases)
        with self.assertRaisesRegex(ValueError, "duplicate prediction"):
            scorer.load_predictions([*complete, complete[0]], case_ids)
        with self.assertRaisesRegex(ValueError, "partial profile coverage"):
            scorer.load_predictions(complete[:-1], case_ids)
        unknown = prediction("not-a-case", "default")
        with self.assertRaisesRegex(ValueError, "unknown case"):
            scorer.load_predictions([unknown], case_ids)

    def proof_files(
        self, trajectories: list[scorer.Trajectory], cases_path: Path, labels: list[dict[str, object]]
    ) -> tuple[Path, Path]:
        labels_path = self.root / "proof.jsonl"
        manifest_path = self.root / "proof.manifest.json"
        self.write_jsonl(labels_path, labels)
        manifest = {
            "schema_version": "1",
            "kind": scorer.PROOF_KIND,
            "corpus_sha256": scorer.sha256_file(cases_path),
            "trajectory_identity_set_sha256": scorer.trajectory_identity_set_sha256(trajectories),
            "labels_sha256": scorer.sha256_file(labels_path),
            "trajectory_count": len(trajectories),
            "label_count": len(labels),
        }
        manifest_path.write_bytes(scorer.canonical_json(manifest))
        return labels_path, manifest_path

    def test_proof_override_requires_manifest_and_full_identity(self) -> None:
        unknown_cases = [case("d" * 24, 0, "unknown"), case("d" * 24, 1, "unknown")]
        cases_path = self.root / "cases.jsonl"
        self.write_jsonl(cases_path, unknown_cases)
        trajectories, _ = scorer.build_trajectories(unknown_cases)
        label = {
            "schema_version": "1",
            "trajectory_id": trajectories[0].trajectory_id,
            "trajectory_identity_sha256": trajectories[0].identity_sha256,
            "source_truth": "malicious",
        }
        labels_path, manifest_path = self.proof_files(trajectories, cases_path, [label])
        overrides = scorer.load_proof_overrides(labels_path, manifest_path, cases_path, trajectories)
        self.assertEqual(overrides, {"d" * 24: "malicious"})
        tampered = dict(label)
        tampered["trajectory_identity_sha256"] = "0" * 64
        labels_path, manifest_path = self.proof_files(trajectories, cases_path, [tampered])
        with self.assertRaisesRegex(ValueError, "full trajectory identity"):
            scorer.load_proof_overrides(labels_path, manifest_path, cases_path, trajectories)

    def test_proof_override_changes_only_trajectory_truth(self) -> None:
        unknown_cases = [case("d" * 24, 0, "unknown"), case("d" * 24, 1, "unknown")]
        rows = [prediction(str(item["id"]), "default", detected=True) for item in unknown_cases]
        trajectories, predictions, profiles = self.parsed(rows, unknown_cases)
        unproved = scorer.score(trajectories, predictions, profiles)
        self.assertEqual(unproved["profiles"][0]["unscored_trajectory_count"], 1)
        proved = scorer.score(trajectories, predictions, profiles, {"d" * 24: "malicious"})
        self.assertEqual(proved["profiles"][0]["detection"]["confusion"]["true_positive"], 1)

    def test_stateful_trajectory_truth_can_label_unknown_atomic_calls(self) -> None:
        trajectory = "e" * 24
        atomic = case(trajectory, 0, "unknown")
        stateful = case(trajectory, 0, "malicious")
        stateful["id"] = f"stateful-{trajectory}"
        stateful["surface"] = "stateful"
        stateful["payload"] = {"direction": "tool_call", "events": [{"tool_name": "shell"}]}
        trajectories, case_ids = scorer.build_trajectories([atomic, stateful])
        self.assertEqual(trajectories[0].source_truth, "malicious")
        predictions, profiles = scorer.load_predictions(
            [
                prediction(str(atomic["id"]), "default"),
                prediction(str(stateful["id"]), "default", detected=True, blocked=True),
            ],
            case_ids,
        )
        report = scorer.score(trajectories, predictions, profiles)
        self.assertEqual(report["profiles"][0]["enforcement"]["confusion"]["true_positive"], 1)

    def test_contextual_stateful_source_attack_abstains_until_proved(self) -> None:
        trajectory = "f" * 24
        atomic = case(trajectory, 0, "unknown")
        atomic["truth"]["applicability"] = "out_of_scope"  # type: ignore[index]
        atomic["truth"]["deterministic_truth"] = "contextual_or_dual_use"  # type: ignore[index]
        stateful = case(trajectory, 0, "malicious")
        stateful["id"] = f"stateful-{trajectory}"
        stateful["surface"] = "stateful"
        stateful["payload"] = {"direction": "tool_call", "events": [{"tool_name": "shell"}]}
        stateful["truth"]["deterministic_truth"] = "contextual_or_dual_use"  # type: ignore[index]
        trajectories, case_ids = scorer.build_trajectories([atomic, stateful])
        predictions, profiles = scorer.load_predictions(
            [
                prediction(str(atomic["id"]), "default"),
                prediction(str(stateful["id"]), "default", detected=True, blocked=True),
            ],
            case_ids,
        )
        report = scorer.score(trajectories, predictions, profiles)
        profile = report["profiles"][0]
        self.assertEqual(profile["unscored_trajectory_count"], 1)
        self.assertEqual(
            profile["detection"]["confusion"],
            {
                "true_positive": 0,
                "true_negative": 0,
                "false_positive": 0,
                "false_negative": 0,
            },
        )

    def test_stateful_latency_uses_proof_completion_and_noise_is_split_by_surface(self) -> None:
        trajectory = "1" * 24
        atomic = case(trajectory, 5, "benign")
        stateful = case(trajectory, 5, "benign")
        stateful["id"] = f"stateful-{trajectory}"
        stateful["surface"] = "stateful"
        stateful["payload"] = {
            "direction": "tool_call",
            "events": [{"tool_name": "shell"} for _ in range(4)],
        }
        trajectories, case_ids = scorer.build_trajectories([atomic, stateful])
        predictions, profiles = scorer.load_predictions(
            [
                prediction(str(atomic["id"]), "default", findings=2),
                prediction(str(stateful["id"]), "default", detected=True, findings=3),
            ],
            case_ids,
        )
        profile = scorer.score(trajectories, predictions, profiles)["profiles"][0]
        self.assertEqual(profile["calls_before_first_detection"]["minimum"], 8)
        self.assertEqual(
            profile["benign_findings_per_trajectory"],
            {
                "total_findings": 5,
                "audit_findings": 0,
                "alert_findings": 5,
                "action_findings": 2,
                "stateful_findings": 3,
                "trajectory_count": 1,
                "mean": 5.0,
            },
        )

    def test_cli_writes_aggregate_report(self) -> None:
        cases_path = self.root / "cases.jsonl"
        predictions_path = self.root / "predictions.jsonl"
        output_path = self.root / "report.json"
        self.write_jsonl(cases_path, self.cases)
        self.write_jsonl(predictions_path, self.complete_predictions())
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(scorer.__file__)),
                "--cases",
                str(cases_path),
                "--predictions",
                str(predictions_path),
                "--output",
                str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(json.loads(completed.stdout)["trajectory_count"], 2)
        report = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(report["kind"], scorer.REPORT_KIND)
        self.assertEqual(report["input_bindings"]["corpus_sha256"], scorer.sha256_file(cases_path))
        self.assertEqual(report["input_bindings"]["predictions_sha256"], scorer.sha256_file(predictions_path))
        self.assertIsNone(report["input_bindings"]["environment_sha256"])


if __name__ == "__main__":
    unittest.main()
