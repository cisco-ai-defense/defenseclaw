# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Produce deterministic error clusters and a model-adjudication queue."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


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
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(value)
    return rows


def effective_truth(case: dict[str, Any]) -> tuple[str, str]:
    truth = case["truth"]
    if truth.get("applicability") != "in_scope":
        return "unscored", "out_of_scope"
    deterministic = truth.get("deterministic_truth")
    if deterministic == "deterministic_malicious":
        return "positive", "deterministic"
    if deterministic == "benign":
        return "benign", "deterministic"
    if deterministic == "contextual_or_dual_use":
        return "unscored", "deterministic"
    source = truth["source_truth"]
    if source in {"malicious", "sensitive"}:
        return "positive", "source"
    if source == "benign":
        return "benign", "source"
    return "unscored", "source"


def error_kind(case: dict[str, Any], prediction: dict[str, Any]) -> str:
    if prediction.get("error_code") or prediction.get("action") == "error":
        return "evaluation_error"
    detected = bool(prediction.get("detected"))
    alerted = bool(prediction.get("alerted", detected))
    truth_class, _ = effective_truth(case)
    truth = case["truth"]
    if (
        truth.get("applicability") == "in_scope"
        and truth.get("expected_disposition") == "detect_only"
        and prediction.get("action") == "block"
    ):
        # Contextual/dual-use rows are excluded from binary detection F1, but
        # blocking them is still a policy error that must be visible during
        # tuning. Keep this separate from benign_block: the UX and publication
        # denominators intentionally distinguish known-benign traffic from
        # risky actions whose evidence supports only an advisory finding.
        return "detect_only_overblock"
    if truth_class == "positive":
        return "true_positive" if detected else "false_negative"
    if truth_class == "benign":
        if prediction.get("action") == "block":
            return "benign_block"
        if alerted:
            return "false_positive"
        return "audit_telemetry" if detected else "true_negative"
    return "unscored"


def cluster_rows(
    cases: dict[str, dict[str, Any]],
    predictions: list[dict[str, Any]],
    profile: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    selected = [row for row in predictions if row.get("profile") == profile]
    counters: dict[str, Counter[tuple[str, ...]]] = defaultdict(Counter)
    per_case: dict[str, dict[str, Any]] = {}
    for prediction in selected:
        case_id = str(prediction["case_id"])
        case = cases.get(case_id)
        if case is None:
            raise ValueError(f"prediction references unknown case {case_id!r}")
        kind = error_kind(case, prediction)
        rule_set = ",".join(prediction.get("rule_ids") or []) or "none"
        issue_set = ",".join(prediction.get("issue_codes") or []) or "none"
        dataset = str(case["source"]["dataset"])
        truth = case.get("truth") or {}
        span_labels = sorted(
            {str(span.get("label")) for span in truth.get("spans", []) if isinstance(span, dict) and span.get("label")}
        )
        truth_families = span_labels or sorted(str(item) for item in truth.get("categories", []) if item)
        truth_family_set = ",".join(truth_families) or "none"
        parse_status = str(prediction.get("parse_status") or "none")
        route = str(prediction.get("route") or "none")
        counters[f"{kind}_by_dataset_parse"][(dataset, parse_status)] += 1
        counters[f"{kind}_by_rule_set"][(rule_set, route)] += 1
        counters[f"{kind}_by_issue"][(issue_set, parse_status)] += 1
        counters[f"{kind}_by_truth_family"][(truth_family_set,)] += 1
        per_case[case_id] = {"kind": kind, "prediction": prediction}

    rendered: dict[str, list[dict[str, Any]]] = {}
    for name, counter in sorted(counters.items()):
        if name.endswith("dataset_parse"):
            fields = ["dataset", "parse_status"]
        elif name.endswith("_by_issue"):
            fields = ["issue_codes", "parse_status"]
        elif name.endswith("_by_truth_family"):
            fields = ["truth_families"]
        else:
            fields = ["rule_ids", "route"]
        rendered[name] = [
            {**dict(zip(fields, key, strict=True)), "count": count}
            for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        ]
    return rendered, per_case


def build_queue(
    cases: dict[str, dict[str, Any]],
    predictions: list[dict[str, Any]],
    profile: str,
    maximum: int,
) -> list[dict[str, Any]]:
    by_profile: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for prediction in predictions:
        by_profile[str(prediction["profile"])][str(prediction["case_id"])] = prediction
    selected = by_profile.get(profile, {})
    rows: list[tuple[int, str, dict[str, Any]]] = []
    for case_id, case in cases.items():
        prediction = selected.get(case_id)
        if prediction is None:
            continue
        kind = error_kind(case, prediction)
        _, truth_source = effective_truth(case)
        reasons: list[str] = []
        priority = 0
        if kind == "benign_block":
            priority, reasons = 100, ["benign_block"]
        elif kind == "detect_only_overblock":
            priority, reasons = 90, ["detect_only_overblock"]
        elif kind == "false_positive":
            priority, reasons = 80, [f"{truth_source}_benign_finding"]
        elif kind == "audit_telemetry":
            # Audit-only observations are retained in aggregate clusters but
            # are not user-visible alerts and do not need adjudication.
            continue
        elif kind == "false_negative":
            priority = 65 if prediction.get("authoritative") else 50
            reasons = [f"{truth_source}_attack_miss"]
            reasons.append("authoritative_miss" if prediction.get("authoritative") else "non_authoritative_miss")
        elif kind == "true_positive":
            priority, reasons = 30, ["source_attack_catch_audit"]
        else:
            continue

        actions = {name: row[case_id].get("action") for name, row in sorted(by_profile.items()) if case_id in row}
        detections = {
            name: bool(row[case_id].get("detected")) for name, row in sorted(by_profile.items()) if case_id in row
        }
        if len(set(actions.values())) > 1 or len(set(detections.values())) > 1:
            priority += 15
            reasons.append("profile_disagreement")

        payload = case.get("payload") or {}
        command = payload.get("command")
        content = payload.get("content")
        if isinstance(command, str) and command.strip():
            review_payload = {
                "command": command,
                "dialect": payload.get("dialect", ""),
            }
        elif isinstance(content, str) and content.strip():
            review_payload = {
                "content": content,
                "direction": payload.get("direction", ""),
                "filename": payload.get("filename", ""),
            }
        else:
            continue
        queue_row = {
            "schema_version": "1",
            "id": case_id,
            "split": case["split"],
            "dataset": case["source"]["dataset"],
            "source_truth": case["truth"]["source_truth"],
            "deterministic_truth": case["truth"].get("deterministic_truth", ""),
            "truth_source": truth_source,
            "source_disposition": case["truth"]["expected_disposition"],
            "surface": case.get("surface", ""),
            "payload": review_payload,
            "priority": priority,
            "reasons": sorted(set(reasons)),
            "baseline": {
                "detected": bool(prediction.get("detected")),
                "action": prediction.get("action"),
                "parse_status": prediction.get("parse_status", ""),
                "authoritative": bool(prediction.get("authoritative")),
                "enforcement_eligible": bool(prediction.get("enforcement_eligible")),
                "route": prediction.get("route", "none"),
                "issue_codes": prediction.get("issue_codes") or [],
                "rule_ids": prediction.get("rule_ids") or [],
            },
            "profile_actions": actions,
        }
        rows.append((priority, case_id, queue_row))
    rows.sort(key=lambda item: (-item[0], item[1]))
    if maximum > 0:
        rows = rows[:maximum]
    return [row for _, _, row in rows]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--max-queue", type=int, default=0, help="0 keeps every eligible case")
    parser.add_argument("--allow-test", action="store_true")
    args = parser.parse_args()

    case_rows = load_jsonl(args.corpus)
    if not args.allow_test and any(row.get("split") == "test" for row in case_rows):
        parser.error("refusing to analyze sealed test rows without --allow-test")
    cases = {str(row["id"]): row for row in case_rows}
    if len(cases) != len(case_rows):
        parser.error("corpus contains duplicate case IDs")
    prediction_rows = load_jsonl(args.predictions)
    clusters, _ = cluster_rows(cases, prediction_rows, args.profile)
    queue = build_queue(cases, prediction_rows, args.profile, args.max_queue)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    write_json(
        args.output_dir / "clusters.json",
        {
            "schema_version": "1",
            "profile": args.profile,
            "corpus_sha256": sha256_file(args.corpus),
            "predictions_sha256": sha256_file(args.predictions),
            "case_count": len(cases),
            "prediction_count": len(prediction_rows),
            "queue_count": len(queue),
            "clusters": clusters,
        },
    )
    write_jsonl(args.output_dir / "adjudication-queue.jsonl", queue)
    print(f"wrote {len(queue)} adjudication rows to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
