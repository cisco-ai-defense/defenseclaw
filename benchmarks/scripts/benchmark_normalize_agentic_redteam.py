#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize bounded structured-tool windows around trajectory drift steps.

The source is treated strictly as untrusted data. Tool-call names, bounded JSON
arguments, and ordering are retained. Thoughts, observations, raw renderings,
goals, and plans are excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
DETECT_DECISIONS = {"KILL_SESSION", "WARN"}
SOURCE_REVISION = "12ddc82333e5df3581341493df4513a24cfc61bb"
PRE_PARTITION_SPLIT = "smoke"
SOURCE_FILES_SHA256 = "b963a4e12404316acd025c1288f0720a524308a4752e2340f1abba17c62fabd1"
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_ARGUMENT_DEPTH = 8
MAX_ARGUMENT_NODES = 1024
MAX_ARGUMENT_KEY_BYTES = 256
MAX_ARGUMENT_STRING_BYTES = 16 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=(PRE_PARTITION_SPLIT,), default=PRE_PARTITION_SPLIT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded_arguments(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    nodes = 0

    def clone(candidate: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_ARGUMENT_NODES or depth > MAX_ARGUMENT_DEPTH:
            raise ValueError("argument limit")
        if candidate is None or isinstance(candidate, (bool, int)):
            return candidate
        if isinstance(candidate, float):
            if not math.isfinite(candidate):
                raise ValueError("non-finite number")
            return candidate
        if isinstance(candidate, str):
            if len(candidate.encode("utf-8")) > MAX_ARGUMENT_STRING_BYTES:
                raise ValueError("argument string limit")
            return candidate
        if isinstance(candidate, list):
            return [clone(item, depth + 1) for item in candidate]
        if isinstance(candidate, dict):
            result: dict[str, Any] = {}
            for key, item in candidate.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key.encode("utf-8")) > MAX_ARGUMENT_KEY_BYTES
                ):
                    raise ValueError("invalid argument key")
                result[key] = clone(item, depth + 1)
            return result
        raise ValueError("unsupported argument value")

    try:
        copied = clone(value, 0)
        encoded = json.dumps(
            copied, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(encoded) > MAX_ARGUMENT_BYTES:
        return None
    return copied


def tool_events(
    trajectory: list[dict[str, Any]], through_index: int, source_id: str
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    resource_identity = (
        "benchmark://agentic-redteam/"
        + hashlib.sha256(source_id.encode()).hexdigest()[:24]
        + "/database"
    )
    for step in trajectory[: through_index + 1]:
        action = step.get("action")
        if not isinstance(action, dict) or action.get("type") != "tool_call":
            continue
        name = action.get("name")
        if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name):
            return []
        arguments = bounded_arguments(action.get("args", {}))
        if arguments is None:
            return []
        event = {"tool_name": name, "args": arguments, "dialect": "none"}
        if name.startswith("db."):
            # The source trajectory ID, not model-controlled arguments, supplies
            # a stable opaque connector identity for deterministic replay. The
            # runtime still requires its adapter to authenticate this context.
            event["tool_resource_identity"] = resource_identity
        events.append(event)
    return [
        {**event, "offset_seconds": index}
        for index, event in enumerate(events[-64:])
    ]


def case_row(
    source: dict[str, Any],
    revision: str,
    split: str,
    events: list[dict[str, Any]],
    truth: str,
) -> dict[str, Any]:
    source_id = str(source["id"])
    suffix = "at-drift" if truth == "malicious" else "pre-drift"
    digest = hashlib.sha256(f"{source_id}\x00{suffix}".encode()).hexdigest()
    category = str(source.get("category", "unknown"))
    return {
        "schema_version": "1",
        "id": f"agentic-redteam/{digest[:24]}",
        "source": {
            "dataset": "agentic-redteam-benchmark",
            "revision": revision,
            "original_id": f"{source_id}:{suffix}",
            "license": "CC-BY-4.0",
            "redistribution": "download-only",
        },
        "split": split,
        "surface": "stateful",
        "payload": {"events": events},
        "truth": {
            "source_truth": truth,
            "applicability": "in_scope",
            "expected_disposition": "detect_only" if truth == "malicious" else "allow",
            "categories": ["trajectory_drift", "multi_tool_chain", category, suffix.replace("-", "_")],
        },
        "strata": {
            "campaign": category,
            "domain": "structured_tool_call",
            "hard_negative": truth == "benign",
            "split_group": hashlib.sha256(source_id.encode()).hexdigest()[:24],
        },
    }


def normalize(
    root: Path, revision: str, split: str, *, verify_source: bool = True
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("Agentic RedTeam revision differs from datasets.lock.json")
    if split != PRE_PARTITION_SPLIT:
        raise ValueError("Agentic RedTeam rows must remain pre-partitioned")
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    source_files: list[dict[str, Any]] = []
    selected_sources = 0
    for path in sorted(root.rglob("*.json")):
        source_files.append({"path": str(path.relative_to(root)), "sha256": sha256_file(path)})
        source = json.loads(path.read_text(encoding="utf-8"))
        # The upstream repository identifies augmented variants with a
        # provenance object. Keep only its original 513-example tier.
        if "provenance" in source:
            skipped["augmented_tier"] += 1
            continue
        ground_truth = source.get("ground_truth")
        trajectory = source.get("trajectory")
        if not isinstance(ground_truth, dict) or not isinstance(trajectory, list):
            skipped["invalid_shape"] += 1
            continue
        if ground_truth.get("expected_decision_at_drift") not in DETECT_DECISIONS:
            skipped["continue_decision"] += 1
            continue
        drift = ground_truth.get("drift_step")
        if not isinstance(drift, int) or drift < 1 or drift >= len(trajectory):
            skipped["invalid_drift_step"] += 1
            continue
        drift_action = trajectory[drift].get("action")
        if not isinstance(drift_action, dict) or drift_action.get("type") != "tool_call":
            skipped["non_tool_drift"] += 1
            continue
        source_id = str(source["id"])
        pre = tool_events(trajectory, drift - 1, source_id)
        at_drift = tool_events(trajectory, drift, source_id)
        if len(pre) < 2 or len(at_drift) < 2:
            skipped["insufficient_tool_history"] += 1
            continue
        selected_sources += 1
        rows.append(case_row(source, revision, split, pre, "benign"))
        rows.append(case_row(source, revision, split, at_drift, "malicious"))
    rows.sort(key=lambda row: str(row["id"]))
    source_files_sha256 = hashlib.sha256(
        json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if verify_source and source_files_sha256 != SOURCE_FILES_SHA256:
        raise ValueError("Agentic RedTeam source bytes differ from pinned inventory")
    truth_counts = Counter(row["truth"]["source_truth"] for row in rows)
    argument_events = sum(
        bool(event["args"])
        for row in rows
        for event in row["payload"]["events"]
    )
    authenticated_database_events = sum(
        "tool_resource_identity" in event
        for row in rows
        for event in row["payload"]["events"]
    )
    manifest = {
        "schema_version": "1",
        "datasets": ["agentic-redteam-benchmark"],
        "cases": len(rows),
        "counts": {"agentic-redteam-benchmark": len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {
            "agentic-redteam-v3": {
                "selected_source_trajectories": selected_sources,
                "benign_cases": truth_counts["benign"],
                "malicious_cases": truth_counts["malicious"],
                "events_with_arguments": argument_events,
                "database_events_with_benchmark_resource_identity": authenticated_database_events,
                "source_file_count": len(source_files),
                **dict(sorted(skipped.items())),
            }
        },
        # Keep descriptive provenance under the schema's extensible, value-free
        # trajectory metadata field so the Go harness can decode this manifest
        # strictly without dropping important label limitations.
        "trajectory_source": {
            "source_id": "agentic-redteam-benchmark",
            "source_revision": revision,
            "source_license": "CC-BY-4.0",
            "split": split,
            "source_files_sha256": source_files_sha256,
            "normalization": (
                "original-tier tool names and bounded JSON arguments through the labeled drift step plus "
                "paired pre-drift prefixes; goals, plans, thoughts, observations, raw calls, and post-drift "
                "steps excluded; database connector replay identities are opaque hashes of source trajectory "
                "metadata and never copied from model-controlled arguments"
            ),
            "label_limitation": (
                "The upstream README calls the 513-example tier gold, but this pinned revision has empty "
                "metadata.reviewed_by arrays; report it as upstream-original, not independently human-reviewed."
            ),
        },
    }
    return rows, manifest


def main() -> int:
    args = parse_args()
    rows, manifest = normalize(args.input_dir, args.revision, args.split)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest["output_sha256"] = sha256_file(args.output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
