#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize executed malicious-call candidates from labeled BashBench.

The upstream rows annotate individual substrings, so several rows can point to
one Bash call. This adapter resolves each annotation against the embedded
trajectory and emits one development-only action case per unique call. Source
labels remain contextual/dual-use and must not enter primary binary metrics
without a separate deterministic proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SOURCE_ID = "AISafety-Student/labeled-bashBench"
SOURCE_URL = "https://huggingface.co/datasets/AISafety-Student/labeled-bashBench"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
SCHEMA_VERSION = "defenseclaw.labeled-bashbench.v1"
SOURCE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
MAX_COMMAND_BYTES = 1_048_576

PARQUET_COLUMNS = (
    "id",
    "task_id",
    "source_file",
    "label",
    "trajectory",
    "step_index",
    "location",
    "tool_call_index",
    "extraction_target",
    "action_type",
    "category",
    "role",
    "danger_level",
    "is_executed",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("benchmarks/schema/case-v1.schema.json"),
    )
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - CLI dependency guidance
        raise RuntimeError(
            "pyarrow==25.0.1 is required; run with `uv run --isolated "
            "--no-project --with pyarrow==25.0.1 --with jsonschema python ...`"
        ) from exc
    parquet = pq.ParquetFile(path)
    missing = sorted(set(PARQUET_COLUMNS) - set(parquet.schema_arrow.names))
    if missing:
        raise ValueError(f"input parquet is missing columns: {', '.join(missing)}")
    for batch in parquet.iter_batches(batch_size=64, columns=PARQUET_COLUMNS):
        yield from batch.to_pylist()


def _text(value: object, maximum: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value[:maximum]


def _candidate_row(row: dict[str, Any]) -> bool:
    return (
        row.get("label") == 1
        and row.get("location") == "tool_input"
        and row.get("role") == "malicious"
        and row.get("is_executed") is True
    )


def _resolve_call(row: dict[str, Any]) -> tuple[dict[str, Any], int] | tuple[None, str]:
    trajectory = row.get("trajectory")
    step = row.get("step_index")
    if not isinstance(trajectory, list) or isinstance(step, bool) or not isinstance(step, int):
        return None, "invalid_trajectory_or_step"
    if step < 0 or step >= len(trajectory) or not isinstance(trajectory[step], dict):
        return None, "step_out_of_range"
    calls = trajectory[step].get("tool_calls")
    if not isinstance(calls, list) or not calls or any(not isinstance(call, dict) for call in calls):
        return None, "missing_tool_calls"

    target = _text(row.get("extraction_target"), MAX_COMMAND_BYTES)
    containing = [
        index
        for index, call in enumerate(calls)
        if target and target in str(call.get("input") or "")
    ]
    call_index = row.get("tool_call_index")
    resolved: int | None = None
    if not isinstance(call_index, bool) and isinstance(call_index, int) and 0 <= call_index < len(calls):
        resolved = call_index
    if len(containing) == 1:
        resolved = containing[0]
    elif len(containing) > 1:
        return None, "ambiguous_target_match"
    if resolved is None:
        return None, "unresolved_tool_call"
    return calls[resolved], resolved


def normalize_rows(
    source_rows: Iterable[dict[str, Any]], *, revision: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not revision or len(revision) > 160:
        raise ValueError("source revision must be 1..160 characters")

    source_count = selected_count = 0
    skipped: Counter[str] = Counter()
    grouped: defaultdict[tuple[str, int, int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in source_rows:
        source_count += 1
        if not _candidate_row(row):
            skipped["not_executed_malicious_tool_input"] += 1
            continue
        source_file = _text(row.get("source_file"))
        step = row.get("step_index")
        if not SOURCE_FILE.fullmatch(source_file) or isinstance(step, bool) or not isinstance(step, int):
            skipped["invalid_source_identity"] += 1
            continue
        call, resolved = _resolve_call(row)
        if call is None:
            skipped[resolved] += 1
            continue
        tool = _text(call.get("tool"), 240)
        command = call.get("input")
        if tool != "bash":
            skipped["unsupported_non_bash_tool"] += 1
            continue
        if not isinstance(command, str) or not command.strip():
            skipped["missing_command"] += 1
            continue
        if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
            skipped["command_too_large"] += 1
            continue
        grouped[(source_file, step, resolved, tool, command)].append(row)
        selected_count += 1

    cases: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    action_type_counts: Counter[str] = Counter()
    danger_counts: Counter[str] = Counter()
    task_ids: set[str] = set()
    for (source_file, step, call_index, tool, command), annotations in grouped.items():
        task_values = {_text(row.get("task_id"), 120) for row in annotations}
        if "" in task_values or len(task_values) != 1:
            skipped["conflicting_task_identity"] += len(annotations)
            continue
        task_id = next(iter(task_values))
        task_ids.add(task_id)
        categories = sorted({_text(row.get("category"), 120) for row in annotations} - {""})
        action_types = sorted({_text(row.get("action_type"), 120) for row in annotations} - {""})
        danger_values = [
            value
            for value in (row.get("danger_level") for row in annotations)
            if not isinstance(value, bool) and isinstance(value, int) and 0 <= value <= 10
        ]
        danger = max(danger_values, default=0)
        category_counts.update(categories)
        action_type_counts.update(action_types)
        danger_counts[str(danger)] += 1
        digest = hashlib.sha256(
            f"{SOURCE_ID}\x00{revision}\x00{source_file}\x00{step}\x00{call_index}\x00{command}".encode()
        ).hexdigest()
        split_group = hashlib.sha256(f"{SOURCE_ID}\x00{task_id}".encode()).hexdigest()[:24]
        cases.append(
            {
                "schema_version": "1",
                "id": f"labeled-bashbench/{digest[:24]}",
                "source": {
                    "dataset": SOURCE_ID,
                    "revision": revision,
                    "original_id": f"{source_file}:{step}:{call_index}",
                    "license": SOURCE_LICENSE,
                    "redistribution": SOURCE_REDISTRIBUTION,
                },
                "split": "development",
                "surface": "action",
                "payload": {
                    "direction": "tool_call",
                    "tool_name": tool,
                    "command": command,
                    "dialect": "posix",
                },
                "truth": {
                    "source_truth": "malicious",
                    "deterministic_truth": "contextual_or_dual_use",
                    "label_confidence": "medium",
                    "label_source": "labeled-bashbench:source-annotation",
                    "applicability": "in_scope",
                    "expected_disposition": "detect_only",
                    "categories": sorted(
                        {
                            "provenance.silver",
                            "executed_malicious_role",
                            *(f"category.{value}" for value in categories),
                            *(f"action_type.{value}" for value in action_types),
                        }
                    ),
                },
                "strata": {
                    "platform": "linux",
                    "dialect": "posix",
                    "campaign": source_file.rsplit(".", 1)[0][:160],
                    "domain": categories[0] if categories else "unknown",
                    "hard_negative": False,
                    "split_group": split_group,
                },
            }
        )

    cases.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": SOURCE_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_redistribution": SOURCE_REDISTRIBUTION,
        "split": "development",
        "source_row_count": source_count,
        "selected_annotation_count": selected_count,
        "unique_action_count": len(cases),
        "task_count": len(task_ids),
        "category_counts": dict(sorted(category_counts.items())),
        "action_type_counts": dict(sorted(action_type_counts.items())),
        "danger_level_counts": dict(sorted(danger_counts.items())),
        "skipped_row_counts": dict(sorted(skipped.items())),
        "execution_performed": False,
        "metric_boundary": (
            "Source annotations are development-only silver candidates. They may support "
            "source-label coverage and rule discovery, but not primary F1, recall, or FPR "
            "until an independent deterministic proof finalizer accepts the exact action."
        ),
    }
    return cases, manifest


def validate_cases(rows: Sequence[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - CLI dependency guidance
        raise RuntimeError("jsonschema is required; add `--with jsonschema` to the uv command") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for index, row in enumerate(rows, 1):
        errors = sorted(validator.iter_errors(row), key=lambda item: list(item.path))
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.path) or "<root>"
            raise ValueError(f"normalized row {index} invalid at {location}: {error.message}")


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_rows(parquet_rows(args.input), revision=args.source_revision)
    validate_cases(cases, args.schema)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in cases:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest.update(
        {
            "source_artifact_bytes": args.input.stat().st_size,
            "source_artifact_sha256": file_sha256(args.input),
            "output_sha256": file_sha256(args.output),
            "case_schema_sha256": file_sha256(args.schema),
        }
    )
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "manifest": str(manifest_path),
                "row_count": len(cases),
                "output_sha256": manifest["output_sha256"],
                "execution_performed": False,
                "truth_tier": "silver_development_only",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
