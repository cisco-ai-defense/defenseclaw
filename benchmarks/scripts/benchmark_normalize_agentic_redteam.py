#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize bounded tool-name windows around trajectory drift steps.

The source is treated strictly as untrusted data. Only tool-call names and
ordering are retained; thoughts, observations, raw renderings, arguments,
goals, and plans are excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
DETECT_DECISIONS = {"KILL_SESSION", "WARN"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=("development", "validation", "test"), default="validation")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_events(trajectory: list[dict[str, Any]], through_index: int) -> list[dict[str, Any]]:
    names: list[str] = []
    for step in trajectory[: through_index + 1]:
        action = step.get("action")
        if not isinstance(action, dict) or action.get("type") != "tool_call":
            continue
        name = action.get("name")
        if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name):
            return []
        names.append(name)
    return [
        {"tool_name": name, "args": {}, "dialect": "none", "offset_seconds": index}
        for index, name in enumerate(names[-64:])
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


def normalize(root: Path, revision: str, split: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
        pre = tool_events(trajectory, drift - 1)
        at_drift = tool_events(trajectory, drift)
        if len(pre) < 2 or len(at_drift) < 2:
            skipped["insufficient_tool_history"] += 1
            continue
        selected_sources += 1
        rows.append(case_row(source, revision, split, pre, "benign"))
        rows.append(case_row(source, revision, split, at_drift, "malicious"))
    rows.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": "1",
        "source_id": "agentic-redteam-benchmark",
        "source_revision": revision,
        "source_license": "CC-BY-4.0",
        "split": split,
        "selected_source_trajectories": selected_sources,
        "row_count": len(rows),
        "truth_counts": dict(sorted(Counter(row["truth"]["source_truth"] for row in rows).items())),
        "skipped": dict(sorted(skipped.items())),
        "source_file_count": len(source_files),
        "source_files_sha256": hashlib.sha256(
            json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "normalization": (
            "original-tier tool names through the labeled drift step plus paired pre-drift prefixes; "
            "goals, plans, thoughts, observations, raw calls, arguments, and post-drift steps excluded"
        ),
        "label_limitation": (
            "The upstream README calls the 513-example tier gold, but this pinned revision has empty "
            "metadata.reviewed_by arrays; report it as upstream-original, not independently human-reviewed."
        ),
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
