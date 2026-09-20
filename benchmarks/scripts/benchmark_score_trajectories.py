#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Score value-free DefenseClaw predictions at the trajectory boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
REPORT_KIND = "trajectory-score-v1"
PROOF_KIND = "trajectory-proof-labels-v1"
PROFILES = {"default", "permissive", "strict"}
SOURCE_TRUTHS = {"benign", "malicious", "sensitive", "unknown"}
PROOF_TRUTHS = {"benign", "malicious", "sensitive", "unknown"}
DETERMINISTIC_TRUTHS = {"deterministic_malicious", "contextual_or_dual_use", "benign"}
DISPOSITION_COUNT_FIELDS = (
    "audit_finding_count",
    "advisory_finding_count",
    "detect_only_finding_count",
    "enforceable_finding_count",
)


@dataclass(frozen=True)
class Trajectory:
    trajectory_id: str
    split: str
    source_truth: str
    scoring_truth: str
    cases: tuple[dict[str, Any], ...]
    identity_sha256: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--proof-labels", type=Path)
    parser.add_argument("--proof-manifest", type=Path)
    return parser.parse_args()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path}: invalid JSON on line {line_number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}: JSONL row {line_number} is not an object")
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    return value.strip()


def required_index(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"missing or invalid {field}")
    return value


def trajectory_identity(trajectory_id: str, cases: Sequence[Mapping[str, Any]]) -> str:
    """Bind all value-free source and ordering identities for one trajectory."""
    identities: list[dict[str, Any]] = []
    for row in cases:
        source = row["source"]
        strata = row["strata"]
        identities.append(
            {
                "case_id": row["id"],
                "dataset": source["dataset"],
                "revision": source["revision"],
                "original_id": source["original_id"],
                "split": row["split"],
                "source_truth": row["truth"]["source_truth"],
                "deterministic_truth": row["truth"].get("deterministic_truth", ""),
                "applicability": row["truth"]["applicability"],
                "surface": row["surface"],
                "sequence_index": strata["sequence_index"],
                "call_index": strata["call_index"],
            }
        )
    return sha256_bytes(canonical_json({"trajectory_id": trajectory_id, "cases": identities}))


def build_trajectories(case_rows: Iterable[dict[str, Any]]) -> tuple[list[Trajectory], set[str]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    case_ids: set[str] = set()
    split_by_trajectory: dict[str, str] = {}
    for row in case_rows:
        case_id = required_text(row.get("id"), "case identity")
        if case_id in case_ids:
            raise ValueError("duplicate case identity")
        case_ids.add(case_id)
        if row.get("surface") not in {"action", "stateful"}:
            raise ValueError("trajectory scorer accepts action and bounded-stateful cases only")
        strata = row.get("strata")
        truth = row.get("truth")
        source = row.get("source")
        if not isinstance(strata, dict) or not isinstance(truth, dict) or not isinstance(source, dict):
            raise ValueError("case requires source, truth, and strata objects")
        trajectory_id = required_text(strata.get("trajectory_id"), "trajectory identity")
        split = required_text(row.get("split"), "split")
        prior_split = split_by_trajectory.setdefault(trajectory_id, split)
        if prior_split != split:
            raise ValueError("trajectory identity leaks across splits")
        source_truth = required_text(truth.get("source_truth"), "source truth")
        if source_truth not in SOURCE_TRUTHS:
            raise ValueError("unsupported source truth")
        applicability = required_text(truth.get("applicability"), "applicability")
        if applicability not in {"in_scope", "out_of_scope"}:
            raise ValueError("unsupported applicability")
        deterministic_truth = truth.get("deterministic_truth", "")
        if deterministic_truth and deterministic_truth not in DETERMINISTIC_TRUTHS:
            raise ValueError("unsupported deterministic truth")
        required_text(source.get("dataset"), "source dataset")
        required_text(source.get("revision"), "source revision")
        required_text(source.get("original_id"), "source original identity")
        required_index(strata.get("sequence_index"), "sequence index")
        required_index(strata.get("call_index"), "call index")
        grouped[trajectory_id].append(row)

    trajectories: list[Trajectory] = []
    for trajectory_id, rows in grouped.items():
        source_truths = {row["truth"]["source_truth"] for row in rows}
        stateful_truths = {row["truth"]["source_truth"] for row in rows if row["surface"] == "stateful"}
        if len(stateful_truths) > 1:
            raise ValueError("trajectory has mixed stateful source truth")
        if stateful_truths:
            source_truth = next(iter(stateful_truths))
            allowed_atomic_truths = {source_truth, "unknown"} if source_truth != "unknown" else {"unknown"}
            if any(
                row["truth"]["source_truth"] not in allowed_atomic_truths for row in rows if row["surface"] == "action"
            ):
                raise ValueError("trajectory atomic truth conflicts with trajectory truth")
        elif len(source_truths) == 1:
            source_truth = next(iter(source_truths))
        else:
            raise ValueError("trajectory has mixed source truth")
        rows.sort(key=lambda row: (row["strata"]["sequence_index"], row["strata"]["call_index"], row["id"]))
        action_rows = [row for row in rows if row["surface"] == "action"]
        action_ordinals = {(row["strata"]["sequence_index"], row["strata"]["call_index"]) for row in action_rows}
        if len(action_ordinals) != len(action_rows):
            raise ValueError("trajectory ordering contains duplicate call ordinals")
        split = rows[0]["split"]
        identity = trajectory_identity(trajectory_id, rows)
        stateful_rows = [row for row in rows if row["surface"] == "stateful"]
        truth_rows = stateful_rows or rows
        in_scope_rows = [row for row in truth_rows if row["truth"]["applicability"] == "in_scope"]
        deterministic_values = {row["truth"].get("deterministic_truth", "") for row in in_scope_rows} - {""}
        if deterministic_values == {"deterministic_malicious"}:
            scoring_truth = "malicious"
        elif deterministic_values == {"benign"}:
            scoring_truth = "benign"
        elif not deterministic_values and in_scope_rows:
            scoring_truth = source_truth
        else:
            scoring_truth = "unknown"
        trajectories.append(Trajectory(trajectory_id, split, source_truth, scoring_truth, tuple(rows), identity))
    trajectories.sort(key=lambda trajectory: trajectory.trajectory_id)
    return trajectories, case_ids


def trajectory_identity_set_sha256(trajectories: Sequence[Trajectory]) -> str:
    values = [
        {"trajectory_id": trajectory.trajectory_id, "identity_sha256": trajectory.identity_sha256}
        for trajectory in trajectories
    ]
    return sha256_bytes(canonical_json(values))


def load_proof_overrides(
    labels_path: Path,
    manifest_path: Path,
    cases_path: Path,
    trajectories: Sequence[Trajectory],
) -> dict[str, str]:
    labels = load_jsonl(labels_path)
    manifest = load_json_object(manifest_path)
    expected_manifest_keys = {
        "schema_version",
        "kind",
        "corpus_sha256",
        "trajectory_identity_set_sha256",
        "labels_sha256",
        "trajectory_count",
        "label_count",
    }
    if set(manifest) != expected_manifest_keys:
        raise ValueError("proof manifest has an unsupported schema")
    if manifest["schema_version"] != SCHEMA_VERSION or manifest["kind"] != PROOF_KIND:
        raise ValueError("proof manifest has an unsupported version or kind")
    if manifest["corpus_sha256"] != sha256_file(cases_path):
        raise ValueError("proof manifest corpus hash mismatch")
    if manifest["labels_sha256"] != sha256_file(labels_path):
        raise ValueError("proof manifest label hash mismatch")
    if manifest["trajectory_identity_set_sha256"] != trajectory_identity_set_sha256(trajectories):
        raise ValueError("proof manifest trajectory identity set mismatch")
    if manifest["trajectory_count"] != len(trajectories) or manifest["label_count"] != len(labels):
        raise ValueError("proof manifest count mismatch")

    by_trajectory = {trajectory.trajectory_id: trajectory for trajectory in trajectories}
    overrides: dict[str, str] = {}
    expected_label_keys = {"schema_version", "trajectory_id", "trajectory_identity_sha256", "source_truth"}
    for row in labels:
        if set(row) != expected_label_keys or row.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("proof label has an unsupported schema")
        trajectory_id = required_text(row.get("trajectory_id"), "proof trajectory identity")
        if trajectory_id in overrides:
            raise ValueError("duplicate trajectory proof label")
        trajectory = by_trajectory.get(trajectory_id)
        if trajectory is None or row.get("trajectory_identity_sha256") != trajectory.identity_sha256:
            raise ValueError("proof label does not match a full trajectory identity")
        source_truth = row.get("source_truth")
        if source_truth not in PROOF_TRUTHS:
            raise ValueError("proof label has unsupported source truth")
        overrides[trajectory_id] = source_truth
    return overrides


def load_predictions(
    rows: Iterable[dict[str, Any]], case_ids: set[str]
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[str]]:
    predictions: dict[tuple[str, str], dict[str, Any]] = {}
    profiles: set[str] = set()
    run_ids: set[str] = set()
    for row in rows:
        case_id = required_text(row.get("case_id"), "prediction case identity")
        profile = required_text(row.get("profile"), "prediction profile")
        if profile not in PROFILES:
            raise ValueError("unsupported prediction profile")
        if case_id not in case_ids:
            raise ValueError("prediction references an unknown case")
        key = (case_id, profile)
        if key in predictions:
            raise ValueError("duplicate prediction for case/profile")
        if not isinstance(row.get("detected"), bool):
            raise ValueError("prediction detected value must be boolean")
        alerted = prediction_alerted(row)
        if not isinstance(alerted, bool):
            raise ValueError("prediction alerted value must be boolean")
        if alerted and not row["detected"]:
            raise ValueError("prediction cannot alert without a detection")
        action = row.get("action")
        if action not in {"allow", "alert", "confirm", "block", "not_applicable", "error"}:
            raise ValueError("prediction action is unsupported")
        finding_count = row.get("finding_count")
        if isinstance(finding_count, bool) or not isinstance(finding_count, int) or finding_count < 0:
            raise ValueError("prediction finding count is invalid")
        if prediction_has_disposition_projection(row):
            counts = [row.get(field, 0) for field in DISPOSITION_COUNT_FIELDS]
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
                raise ValueError("prediction disposition finding count is invalid")
            if sum(counts) != finding_count:
                raise ValueError("prediction disposition counts do not equal finding count")
            expected_alert_count = sum(counts[1:])
            if row.get("alert_finding_count", 0) != expected_alert_count:
                raise ValueError("prediction alert finding count is invalid")
            if alerted != (expected_alert_count > 0):
                raise ValueError("prediction alerted value disagrees with disposition counts")
        run_ids.add(required_text(row.get("run_id"), "prediction run identity"))
        required_text(row.get("engine"), "prediction engine")
        profiles.add(profile)
        predictions[key] = row
    if len(run_ids) != 1:
        raise ValueError("predictions contain mixed run identities")
    if not profiles:
        raise ValueError("no prediction profiles")
    expected = {(case_id, profile) for case_id in case_ids for profile in profiles}
    if set(predictions) != expected:
        raise ValueError("partial profile coverage")
    return predictions, sorted(profiles)


def prediction_has_disposition_projection(row: Mapping[str, Any]) -> bool:
    return any(field in row for field in DISPOSITION_COUNT_FIELDS)


def prediction_alerted(row: Mapping[str, Any]) -> bool:
    if prediction_has_disposition_projection(row):
        return bool(row.get("alerted", False))
    return bool(row["detected"])


def prediction_alert_count(row: Mapping[str, Any]) -> int:
    if prediction_has_disposition_projection(row):
        return int(row.get("alert_finding_count", 0))
    return int(row["finding_count"])


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def wilson(successes: int, total: int) -> dict[str, float]:
    if total == 0:
        return {"lower": 0.0, "upper": 0.0}
    z = 1.959963984540054
    n = float(total)
    proportion = successes / n
    z_squared = z * z
    center = (proportion + z_squared / (2 * n)) / (1 + z_squared / n)
    half = z * math.sqrt((proportion * (1 - proportion) + z_squared / (4 * n)) / n) / (1 + z_squared / n)
    return {"lower": max(0.0, center - half), "upper": min(1.0, center + half)}


def binary_metrics(true_positive: int, true_negative: int, false_positive: int, false_negative: int) -> dict[str, Any]:
    precision = ratio(true_positive, true_positive + false_positive)
    recall = ratio(true_positive, true_positive + false_negative)
    fpr = ratio(false_positive, false_positive + true_negative)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "confusion": {
            "true_positive": true_positive,
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
        },
        "precision": precision,
        "precision_95": wilson(true_positive, true_positive + false_positive),
        "recall": recall,
        "recall_95": wilson(true_positive, true_positive + false_negative),
        "f1": f1,
        "false_positive_rate": fpr,
        "false_positive_rate_95": wilson(false_positive, false_positive + true_negative),
    }


def rate(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": ratio(numerator, denominator),
        "confidence_95": wilson(numerator, denominator),
    }


def quantile(values: Sequence[int], probability: float) -> int:
    if not values:
        return 0
    index = max(0, math.ceil(probability * len(values)) - 1)
    return sorted(values)[index]


def calls_before_summary(values: Sequence[int]) -> dict[str, Any]:
    return {
        "observed_trajectories": len(values),
        "mean": sum(values) / len(values) if values else 0.0,
        "minimum": min(values) if values else 0,
        "maximum": max(values) if values else 0,
        "p50": quantile(values, 0.50),
        "p95": quantile(values, 0.95),
    }


def observe(truth: bool, prediction: bool, confusion: dict[str, int]) -> None:
    if truth and prediction:
        confusion["tp"] += 1
    elif truth:
        confusion["fn"] += 1
    elif prediction:
        confusion["fp"] += 1
    else:
        confusion["tn"] += 1


def score_profile(
    profile: str,
    trajectories: Sequence[Trajectory],
    predictions: Mapping[tuple[str, str], Mapping[str, Any]],
    overrides: Mapping[str, str],
) -> dict[str, Any]:
    detection = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    alert = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    enforcement = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    benign_count = 0
    benign_alerts = 0
    benign_blocks = 0
    benign_findings = 0
    benign_audit_findings = 0
    benign_alert_findings = 0
    benign_action_findings = 0
    benign_stateful_findings = 0
    unscored = 0
    calls_before_detection: list[int] = []
    calls_before_alert: list[int] = []
    calls_before_block: list[int] = []
    for trajectory in trajectories:
        rows = [predictions[(case["id"], profile)] for case in trajectory.cases]
        completion_indices = [
            int(case["strata"]["sequence_index"])
            + (len(case["payload"].get("events", [])) - 1 if case["surface"] == "stateful" else 0)
            for case in trajectory.cases
        ]
        detected_indices = [
            completion_index for completion_index, row in zip(completion_indices, rows, strict=True) if row["detected"]
        ]
        alerted_indices = [
            completion_index
            for completion_index, row in zip(completion_indices, rows, strict=True)
            if prediction_alerted(row)
        ]
        blocked_indices = [
            completion_index
            for completion_index, row in zip(completion_indices, rows, strict=True)
            if row["action"] == "block"
        ]
        detected = bool(detected_indices)
        alerted = bool(alerted_indices)
        blocked = bool(blocked_indices)
        if detected_indices:
            calls_before_detection.append(detected_indices[0])
        if blocked_indices:
            calls_before_block.append(blocked_indices[0])
        if alerted_indices:
            calls_before_alert.append(alerted_indices[0])
        truth = overrides.get(trajectory.trajectory_id, trajectory.scoring_truth)
        if truth == "unknown":
            unscored += 1
            continue
        positive = truth in {"malicious", "sensitive"}
        observe(positive, detected, detection)
        observe(positive, alerted, alert)
        observe(positive, blocked, enforcement)
        if not positive:
            benign_count += 1
            benign_alerts += int(alerted)
            benign_blocks += int(blocked)
            action_findings = sum(
                row["finding_count"]
                for case, row in zip(trajectory.cases, rows, strict=True)
                if case["surface"] == "action"
            )
            stateful_findings = sum(
                row["finding_count"]
                for case, row in zip(trajectory.cases, rows, strict=True)
                if case["surface"] == "stateful"
            )
            benign_action_findings += action_findings
            benign_stateful_findings += stateful_findings
            benign_findings += action_findings + stateful_findings
            benign_audit_findings += sum(int(row.get("audit_finding_count", 0)) for row in rows)
            benign_alert_findings += sum(prediction_alert_count(row) for row in rows)
    return {
        "profile": profile,
        "trajectory_count": len(trajectories),
        "scored_trajectory_count": len(trajectories) - unscored,
        "unscored_trajectory_count": unscored,
        "detection": binary_metrics(detection["tp"], detection["tn"], detection["fp"], detection["fn"]),
        "alert": binary_metrics(alert["tp"], alert["tn"], alert["fp"], alert["fn"]),
        "enforcement": binary_metrics(enforcement["tp"], enforcement["tn"], enforcement["fp"], enforcement["fn"]),
        "benign_trajectory_alert_rate": rate(benign_alerts, benign_count),
        "benign_trajectory_block_rate": rate(benign_blocks, benign_count),
        "benign_findings_per_trajectory": {
            "total_findings": benign_findings,
            "audit_findings": benign_audit_findings,
            "alert_findings": benign_alert_findings,
            "action_findings": benign_action_findings,
            "stateful_findings": benign_stateful_findings,
            "trajectory_count": benign_count,
            "mean": ratio(benign_findings, benign_count),
        },
        "calls_before_first_detection": calls_before_summary(calls_before_detection),
        "calls_before_first_alert": calls_before_summary(calls_before_alert),
        "calls_before_first_block": calls_before_summary(calls_before_block),
    }


def score(
    trajectories: Sequence[Trajectory],
    predictions: Mapping[tuple[str, str], Mapping[str, Any]],
    profiles: Sequence[str],
    overrides: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    proof_overrides = overrides or {}
    unknown_overrides = set(proof_overrides) - {trajectory.trajectory_id for trajectory in trajectories}
    if unknown_overrides:
        raise ValueError("proof overrides contain unknown trajectory identities")
    split_counts: dict[str, int] = defaultdict(int)
    source_truth_counts: dict[str, int] = defaultdict(int)
    scoring_truth_counts: dict[str, int] = defaultdict(int)
    for trajectory in trajectories:
        split_counts[trajectory.split] += 1
        source_truth_counts[trajectory.source_truth] += 1
        scoring_truth_counts[proof_overrides.get(trajectory.trajectory_id, trajectory.scoring_truth)] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": REPORT_KIND,
        "case_count": sum(len(trajectory.cases) for trajectory in trajectories),
        "trajectory_count": len(trajectories),
        "profile_count": len(profiles),
        "proof_override_count": len(proof_overrides),
        "split_counts": dict(sorted(split_counts.items())),
        "source_truth_counts": dict(sorted(source_truth_counts.items())),
        "scoring_truth_counts": dict(sorted(scoring_truth_counts.items())),
        "profiles": [score_profile(profile, trajectories, predictions, proof_overrides) for profile in profiles],
    }


def report_input_bindings(
    args: argparse.Namespace,
    prediction_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    run_ids = sorted({required_text(row.get("run_id"), "prediction run identity") for row in prediction_rows})
    if len(run_ids) != 1:
        raise ValueError("predictions contain mixed run identities")
    bindings: dict[str, Any] = {
        "corpus_sha256": sha256_file(args.cases),
        "predictions_sha256": sha256_file(args.predictions),
        "prediction_run_identity_sha256": sha256_bytes(canonical_json(run_ids[0])),
        "proof_labels_sha256": sha256_file(args.proof_labels) if args.proof_labels else None,
        "proof_manifest_sha256": sha256_file(args.proof_manifest) if args.proof_manifest else None,
        "environment_sha256": None,
        "dataset_lock_sha256": None,
    }
    environment_path = args.predictions.parent / "environment.json"
    if environment_path.is_file():
        environment = load_json_object(environment_path)
        if environment.get("corpus_sha256") != bindings["corpus_sha256"]:
            raise ValueError("adjacent environment corpus hash mismatch")
        dataset_lock_sha256 = environment.get("dataset_lock_sha256")
        if not isinstance(dataset_lock_sha256, str) or len(dataset_lock_sha256) != 64:
            raise ValueError("adjacent environment dataset lock hash is invalid")
        bindings["environment_sha256"] = sha256_file(environment_path)
        bindings["dataset_lock_sha256"] = dataset_lock_sha256
    return bindings


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    args = parse_args()
    if (args.proof_labels is None) != (args.proof_manifest is None):
        raise ValueError("--proof-labels and --proof-manifest must be provided together")
    trajectories, case_ids = build_trajectories(load_jsonl(args.cases))
    prediction_rows = load_jsonl(args.predictions)
    predictions, profiles = load_predictions(prediction_rows, case_ids)
    overrides: dict[str, str] = {}
    if args.proof_labels is not None and args.proof_manifest is not None:
        overrides = load_proof_overrides(
            args.proof_labels,
            args.proof_manifest,
            args.cases,
            trajectories,
        )
    report = score(trajectories, predictions, profiles, overrides)
    report["input_bindings"] = report_input_bindings(args, prediction_rows)
    atomic_write(args.output, canonical_json(report))
    print(
        json.dumps(
            {
                "case_count": report["case_count"],
                "trajectory_count": report["trajectory_count"],
                "profile_count": report["profile_count"],
                "proof_override_count": report["proof_override_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
