#!/usr/bin/env python3
"""Build a metadata-only, non-gating benign near-miss review lane.

The input queue is produced by benchmark_error_analysis.py. This script keeps
stable case provenance and profile outcomes while deliberately dropping the
normalized payload. The resulting lane is for later adjudication and replay;
it is not an authoritative label overlay and must not be used to tune rules.
"""

# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "defenseclaw/near-miss-fpr-lane/v1"
SELECTOR_REASON = "deterministic_benign_finding"


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without interpreting its values."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    """Return a stable digest for a JSON-compatible value."""

    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_json(path: Path) -> Any:
    """Read one small JSON provenance file."""

    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def payload_summary(payload: Any) -> dict[str, Any]:
    """Describe payload shape and tool names without retaining argument values."""

    if not isinstance(payload, dict):
        return {"type": type(payload).__name__}

    summary: dict[str, Any] = {
        "type": "object",
        "keys": sorted(str(key) for key in payload),
    }
    events = payload.get("events")
    if isinstance(events, list):
        summary["event_count"] = len(events)
        tools = set()
        for event in events:
            if not isinstance(event, dict):
                continue
            for key in ("tool_name", "tool", "name"):
                value = event.get(key)
                if isinstance(value, str) and value:
                    tools.add(value)
                    break
        summary["event_tools"] = sorted(tools)
    return summary


def selected_case(row: dict[str, Any]) -> bool:
    """Return whether a row satisfies the frozen benign near-miss selector."""

    reasons = row.get("reasons")
    baseline = row.get("baseline")
    return (
        isinstance(reasons, list)
        and SELECTOR_REASON in reasons
        and row.get("split") == "validation"
        and row.get("truth_source") == "deterministic"
        and row.get("deterministic_truth") == "benign"
        and isinstance(baseline, dict)
        and baseline.get("detected") is True
    )


def compact_baseline(baseline: dict[str, Any]) -> dict[str, Any]:
    """Keep only stable, non-payload baseline decision metadata."""

    return {
        "detected": baseline.get("detected") is True,
        "action": baseline.get("action", ""),
        "authoritative": baseline.get("authoritative") is True,
        "enforcement_eligible": baseline.get("enforcement_eligible") is True,
        "parse_status": baseline.get("parse_status", ""),
        "issue_codes": list(baseline.get("issue_codes", [])),
        "route": baseline.get("route", ""),
        "rule_ids": list(baseline.get("rule_ids", [])),
    }


def build_source(queue_path: Path, clusters_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate one queue/cluster pair and return its source metadata and rows."""

    if queue_path.resolve().parent != clusters_path.resolve().parent:
        raise ValueError(
            f"queue and clusters must be from the same source directory: "
            f"{queue_path} / {clusters_path}"
        )
    clusters = read_json(clusters_path)
    if not isinstance(clusters, dict):
        raise ValueError(f"{clusters_path}: cluster metadata is not an object")
    if clusters.get("schema_version") != "1":
        raise ValueError(f"{clusters_path}: unsupported cluster schema")
    if clusters.get("profile") != "default":
        raise ValueError(f"{clusters_path}: cluster profile is not default")
    for field in ("case_count", "prediction_count", "queue_count"):
        value = clusters.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{clusters_path}: invalid {field}")
    queue_rows: list[dict[str, Any]] = []
    with queue_path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{queue_path}:{line_number}: queue row is not an object")
            if value.get("schema_version") != "1":
                raise ValueError(f"{queue_path}:{line_number}: unsupported queue schema")
            queue_rows.append(value)

    queue_sha256 = sha256_file(queue_path)
    if clusters.get("queue_sha256") != queue_sha256:
        raise ValueError(
            f"{clusters_path}: queue_sha256 does not match {queue_path}"
        )
    if clusters["queue_count"] != len(queue_rows):
        raise ValueError(
            f"{queue_path}: queue row count {len(queue_rows)} does not match "
            f"cluster metadata {clusters['queue_count']}"
        )

    rows: list[dict[str, Any]] = []
    for value in queue_rows:
        if selected_case(value):
            payload = value.get("payload")
            rows.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "case_id": value.get("id", ""),
                    "dataset": value.get("dataset", ""),
                    "split": value.get("split", ""),
                    "surface": value.get("surface", ""),
                    "selection_reason": (
                        "authoritative benign case selected because the frozen "
                        "baseline emitted a finding; review-only"
                    ),
                    "reason_codes": list(value.get("reasons", [])),
                    "source_disposition": value.get("source_disposition", ""),
                    "label_reference": {
                        "truth_source": "deterministic",
                        "deterministic_truth": "benign",
                        "authoritative_label_unchanged": True,
                    },
                    "baseline": compact_baseline(value["baseline"]),
                    "profile_actions": dict(value.get("profile_actions", {})),
                    "payload_sha256": sha256_json(payload),
                    "payload_summary": payload_summary(payload),
                }
            )

    source = {
        "queue_file_sha256": queue_sha256,
        "clusters_file_sha256": sha256_file(clusters_path),
        "corpus_sha256": clusters.get("corpus_sha256", ""),
        "predictions_sha256": clusters.get("predictions_sha256", ""),
        "input_case_count": clusters.get("case_count", 0),
        "input_prediction_count": clusters.get("prediction_count", 0),
        "input_queue_count": clusters.get("queue_count", 0),
        "profile": clusters.get("profile", "default"),
        "selected_case_count": len(rows),
    }
    return source, rows


def action_counts(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Count retained rows by recorded profile action."""

    profiles = {"default", "permissive", "strict"}
    for row in rows:
        profiles.update(row.get("profile_actions", {}).keys())
    counts: dict[str, dict[str, int]] = {}
    for profile in sorted(profiles):
        profile_counts: dict[str, int] = {}
        for row in rows:
            action = row.get("profile_actions", {}).get(profile, "missing")
            profile_counts[action] = profile_counts.get(action, 0) + 1
        counts[profile] = dict(sorted(profile_counts.items()))
    return counts


def parse_args() -> argparse.Namespace:
    """Parse the command-line interface for the metadata-only lane builder."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", action="append", required=True)
    parser.add_argument("--clusters", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--lane-id", required=True)
    return parser.parse_args()


def main() -> int:
    """Validate all sources, then atomically begin writing the requested lane."""

    args = parse_args()
    if len(args.queue) != len(args.clusters):
        raise SystemExit("--queue and --clusters must have the same number of values")

    output_dir = Path(args.output_dir)
    if output_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output directory: {output_dir}")

    sources: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for queue_name, clusters_name in zip(args.queue, args.clusters):
        source, source_rows = build_source(Path(queue_name), Path(clusters_name))
        for row in source_rows:
            case_id = row["case_id"]
            if not case_id or case_id in seen_ids:
                raise SystemExit(f"duplicate or empty case ID in near-miss inputs: {case_id!r}")
            seen_ids.add(case_id)
        sources.append(source)
        rows.extend(source_rows)

    rows.sort(key=lambda row: (row["dataset"], row["case_id"]))
    output_dir.mkdir(parents=True)
    cases_path = output_dir / "cases.jsonl"
    with cases_path.open("x", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "lane_id": args.lane_id,
        "purpose": "Review-only benign near-miss FPR evaluation lane for future adjudication.",
        "gating": False,
        "included_in_authoritative_scores": False,
        "included_in_default_tuning_inputs": False,
        "changes_runtime_authority": False,
        "changes_thresholds": False,
        "changes_authoritative_labels": False,
        "payloads_committed": False,
        "selection": {
            "source": "benchmark_error_analysis adjudication queues",
            "split": "validation",
            "truth_source": "deterministic",
            "deterministic_truth": "benign",
            "requires_baseline_detected": True,
            "reason_code": SELECTOR_REASON,
            "selection_bias": (
                "Cases are selected because the baseline emitted a finding; the "
                "selected-finding rate is not an unbiased FPR estimate."
            ),
        },
        "promotion": {
            "requires_explicit_adjudication": True,
            "required_before_promotion": [
                "review the canonical source row outside this lane",
                "record an independent adjudication decision",
                "rerun the frozen authoritative benchmark and all safety gates",
            ],
            "forbidden_shortcut": "Do not use this lane to justify broad suppression or label changes.",
        },
        "counts": {
            "source_count": len(sources),
            "selected_case_count": len(rows),
        },
        "metrics": {
            "selection_conditioned_baseline_finding_rate": 1.0 if rows else 0.0,
            "profile_action_counts": action_counts(rows),
            "interpretation": "Selection-conditioned review yield only; non-gating.",
        },
        "sources": sources,
        "cases_file": "cases.jsonl",
    }
    manifest_path = output_dir / "manifest.json"
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")

    checksum_path = output_dir / "checksums.txt"
    with checksum_path.open("x", encoding="utf-8") as stream:
        for path in (cases_path, manifest_path):
            stream.write(f"{sha256_file(path)}  {path.name}\n")

    print(f"wrote {len(rows)} metadata-only near-miss rows to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
