#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct and normalize contextual labeled BashBench trajectories.

Rows contain progressively longer snapshots. Calls are canonicalized by exact
source/step/call coordinate before annotation targets are resolved. All output
remains development-only and out of primary metrics because outcomes are not
reliably recorded by the source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SOURCE_ID = "AISafety-Student/labeled-bashBench"
SOURCE_URL = "https://huggingface.co/datasets/AISafety-Student/labeled-bashBench"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
SCHEMA_VERSION = "defenseclaw.labeled-bashbench.v2"
SOURCE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
MAX_COMMAND_BYTES = 1_048_576
MAX_EVENTS = 8
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
Coordinate = tuple[int, int]


@dataclass(frozen=True)
class Call:
    step: int
    index: int
    tool: str
    command: str
    output: str


@dataclass(frozen=True)
class Annotation:
    source_file: str
    task_id: str
    coordinate: Coordinate
    target: str
    start: int
    end: int
    role: str
    category: str
    action_type: str
    executed: bool
    index_mismatch: bool
    danger: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
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
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pyarrow==25.0.1 is required") from exc
    parquet = pq.ParquetFile(path)
    missing = sorted(set(PARQUET_COLUMNS) - set(parquet.schema_arrow.names))
    if missing:
        raise ValueError(f"input parquet is missing columns: {', '.join(missing)}")
    for batch in parquet.iter_batches(batch_size=64, columns=PARQUET_COLUMNS):
        yield from batch.to_pylist()


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL row {number}: {exc.msg}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"invalid JSONL row {number}: expected object")
            missing = sorted(set(PARQUET_COLUMNS) - set(row))
            if missing:
                raise ValueError(f"input JSONL row {number} is missing columns: {', '.join(missing)}")
            yield row


def source_rows(path: Path) -> Iterable[dict[str, Any]]:
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return jsonl_rows(path)
    if path.suffix.lower() == ".parquet":
        return parquet_rows(path)
    raise ValueError("input must be .jsonl, .ndjson, or .parquet")


def _text(value: object, maximum: int = 200) -> str:
    return value.strip()[:maximum] if isinstance(value, str) else ""


def _source_file(row: dict[str, Any]) -> str:
    value = _text(row.get("source_file"))
    return value if SOURCE_FILE.fullmatch(value) else ""


def _snapshot_calls(row: dict[str, Any]) -> Iterable[tuple[Coordinate, dict[str, Any]]]:
    trajectory = row.get("trajectory")
    if not isinstance(trajectory, list):
        return
    for step, message in enumerate(trajectory):
        if not isinstance(message, dict) or not isinstance(message.get("tool_calls"), list):
            continue
        for index, call in enumerate(message["tool_calls"]):
            if isinstance(call, dict):
                yield (step, index), call


def _canonical(coordinate: Coordinate, snapshots: Sequence[dict[str, Any]]) -> Call | None:
    tools = {_text(item.get("tool"), 240) for item in snapshots}
    commands = [item.get("input") for item in snapshots]
    if len(tools) != 1 or "" in tools or any(not isinstance(item, str) for item in commands):
        return None
    distinct = sorted(set(commands), key=lambda item: (len(item), item))
    longest = distinct[-1]
    if any(not longest.startswith(item) for item in distinct):
        return None
    # An upstream coordinate with an empty input is incomplete but not
    # divergent. Retaining it in the ordered trajectory digest prevents alias
    # collisions; it cannot resolve a non-empty annotation target.
    if len(longest.encode()) > MAX_COMMAND_BYTES:
        return None
    complete_snapshots = [item for item in snapshots if item.get("input") == longest]
    outputs = [item.get("output") for item in complete_snapshots]
    output = max((item for item in outputs if isinstance(item, str)), key=len, default="")
    return Call(coordinate[0], coordinate[1], next(iter(tools)), longest, output)


def _trajectory_digest(calls: Sequence[Call]) -> str:
    value = [[call.step, call.index, call.tool, call.command, call.output] for call in calls]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _candidate(row: dict[str, Any]) -> bool:
    return (
        row.get("label") == 1
        and row.get("location") == "tool_input"
        and row.get("role") in {"supporting", "malicious"}
        and isinstance(row.get("is_executed"), bool)
    )


def _occurrences(command: str, target: str) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    offset = 0
    while (index := command.find(target, offset)) >= 0:
        start = len(command[:index].encode())
        found.append((start, start + len(target.encode())))
        offset = index + 1
    return found


def _resolve(
    row: dict[str, Any], calls: dict[Coordinate, Call], divergent: set[Coordinate]
) -> tuple[Annotation | None, str]:
    source_file = _source_file(row)
    step, supplied = row.get("step_index"), row.get("tool_call_index")
    if not source_file or isinstance(step, bool) or not isinstance(step, int) or step < 0:
        return None, "invalid_source_identity"
    if isinstance(supplied, int) and not isinstance(supplied, bool) and (step, supplied) in divergent:
        return None, "divergent_coordinate"
    target_value = row.get("extraction_target")
    if not isinstance(target_value, str) or not target_value:
        return None, "missing_target"
    if len(target_value.encode()) > MAX_COMMAND_BYTES:
        return None, "target_too_large"
    target = target_value
    matches = [
        (coordinate, start, end)
        for coordinate, call in calls.items()
        if coordinate[0] == step
        for start, end in _occurrences(call.command, target)
    ]
    if not matches:
        return None, "target_absent"
    if len(matches) != 1:
        return None, "ambiguous_target"
    coordinate, start, end = matches[0]
    task_id = _text(row.get("task_id"), 120)
    if not task_id:
        return None, "missing_task_id"
    danger = row.get("danger_level")
    danger = danger if isinstance(danger, int) and not isinstance(danger, bool) and 0 <= danger <= 10 else 0
    mismatch = isinstance(supplied, int) and not isinstance(supplied, bool) and supplied != coordinate[1]
    return Annotation(
        source_file,
        task_id,
        coordinate,
        target,
        start,
        end,
        _text(row.get("role"), 120),
        _text(row.get("category"), 120),
        _text(row.get("action_type"), 120),
        row["is_executed"],
        mismatch,
        danger,
    ), ""


def _signature(item: Annotation) -> tuple[object, ...]:
    return (
        item.coordinate,
        item.target,
        item.start,
        item.end,
        item.role,
        item.category,
        item.action_type,
        item.executed,
        item.index_mismatch,
        item.danger,
    )


def _spans(items: Sequence[Annotation], event: int | None = None) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    prefix = f"event{event}." if event is not None else ""
    for item in sorted(items, key=_signature):
        rule_id = "labeled-bashbench/" + hashlib.sha256(repr(_signature(item)).encode()).hexdigest()[:24]
        labels = [
            f"{prefix}role.{item.role}",
            f"{prefix}category.{item.category or 'unknown'}",
            f"{prefix}action_type.{item.action_type or 'unknown'}",
            f"{prefix}target_execution.{'executed' if item.executed else 'unexecuted'}",
        ]
        if item.index_mismatch:
            labels.append(f"{prefix}audit.index_mismatch")
        for label in labels:
            key = (item.start, item.end, label[:120], rule_id)
            if key not in seen:
                seen.add(key)
                span: dict[str, object] = {
                    "start": item.start,
                    "end": item.end,
                    "label": label[:120],
                    "rule_id": rule_id,
                }
                if event is not None:
                    span["event_index"] = event
                result.append(span)
    return sorted(result, key=lambda item: (item["start"], item["end"], item["label"]))


def _truth(items: Sequence[Annotation], stateful: bool) -> dict[str, object]:
    roles = {item.role for item in items}
    categories = {
        "provenance.silver",
        "benchmark.contextual",
        "benchmark.outcome_unknown",
        *(f"role.{value}" for value in roles),
        *(f"category.{item.category}" for item in items if item.category),
        *(f"action_type.{item.action_type}" for item in items if item.action_type),
    }
    if stateful:
        categories.add("benchmark.bounded_sequence")
    if any(item.index_mismatch for item in items):
        categories.add("audit.index_mismatch")
    return {
        "source_truth": "malicious" if "malicious" in roles else "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium",
        "label_source": "labeled-bashbench:source-annotation",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "Development-only contextual annotation with unknown command outcome; "
            "requires deterministic proof finalization before primary metrics."
        ),
        "categories": sorted(categories),
    }


def _source(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": SOURCE_ID,
        "revision": revision,
        "original_id": original_id[:240],
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def normalize_rows(rows: Iterable[dict[str, Any]], *, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not revision or len(revision) > 160:
        raise ValueError("source revision must be 1..160 characters")
    raw = list(rows)
    skipped: Counter[str] = Counter()
    snapshots: defaultdict[str, defaultdict[Coordinate, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    tasks: set[str] = set()
    for row in raw:
        source_file = _source_file(row)
        if not source_file:
            skipped["invalid_source_identity"] += 1
            continue
        task_id = _text(row.get("task_id"), 120)
        if task_id:
            tasks.add(task_id)
        for coordinate, call in _snapshot_calls(row):
            snapshots[source_file][coordinate].append(call)

    calls_by_source: dict[str, dict[Coordinate, Call]] = {}
    divergent_by_source: dict[str, set[Coordinate]] = {}
    digest_by_source: dict[str, str] = {}
    for source_file, observed in snapshots.items():
        calls: dict[Coordinate, Call] = {}
        divergent: set[Coordinate] = set()
        for coordinate, versions in observed.items():
            call = _canonical(coordinate, versions)
            if call is None:
                divergent.add(coordinate)
            else:
                calls[coordinate] = call
        ordered = sorted(calls.values(), key=lambda item: (item.step, item.index))
        calls_by_source[source_file], divergent_by_source[source_file] = calls, divergent
        digest_by_source[source_file] = _trajectory_digest(ordered)

    resolved: defaultdict[str, list[Annotation]] = defaultdict(list)
    candidate_count = 0
    for row in raw:
        if not _candidate(row):
            skipped["not_annotated_tool_input"] += 1
            continue
        candidate_count += 1
        source_file = _source_file(row)
        if source_file not in calls_by_source:
            skipped["missing_canonical_trajectory"] += 1
            continue
        annotation, reason = _resolve(row, calls_by_source[source_file], divergent_by_source[source_file])
        if annotation is None:
            skipped[reason] += 1
        elif calls_by_source[source_file][annotation.coordinate].tool != "bash":
            skipped["unsupported_non_bash_tool"] += 1
        else:
            resolved[source_file].append(annotation)

    aliases: defaultdict[str, list[str]] = defaultdict(list)
    for source_file, digest in digest_by_source.items():
        aliases[digest].append(source_file)

    cases: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    danger_counts: Counter[str] = Counter()
    selected = mismatches = stateful_count = 0
    for trajectory_id, names in sorted(aliases.items()):
        names.sort()
        representative = names[0]
        calls = sorted(calls_by_source[representative].values(), key=lambda item: (item.step, item.index))
        positions = {(call.step, call.index): index for index, call in enumerate(calls)}
        merged: dict[tuple[object, ...], Annotation] = {}
        for name in names:
            for annotation in resolved.get(name, []):
                merged.setdefault(_signature(annotation), annotation)
        annotations = list(merged.values())
        selected += len(annotations)
        mismatches += sum(item.index_mismatch for item in annotations)
        category_counts.update(item.category for item in annotations if item.category)
        action_counts.update(item.action_type for item in annotations if item.action_type)
        danger_counts.update(str(item.danger) for item in annotations)
        by_coordinate: defaultdict[Coordinate, list[Annotation]] = defaultdict(list)
        for annotation in annotations:
            by_coordinate[annotation.coordinate].append(annotation)
        split_group = hashlib.sha256(f"{SOURCE_ID}\0{trajectory_id}".encode()).hexdigest()[:24]

        for coordinate, items in sorted(by_coordinate.items()):
            call = calls_by_source[representative].get(coordinate)
            if call is None:
                continue
            position = positions[coordinate]
            case_digest = hashlib.sha256(f"{revision}\0atomic\0{trajectory_id}\0{position}".encode()).hexdigest()[:24]
            cases.append(
                {
                    "schema_version": "1",
                    "id": f"labeled-bashbench/atomic/{case_digest}",
                    "source": _source(revision, f"{representative}:{call.step}:{call.index}"),
                    "split": "development",
                    "surface": "action",
                    "payload": {
                        "direction": "tool_call",
                        "tool_name": call.tool,
                        "command": call.command,
                        "dialect": "posix",
                        "annotation_spans": _spans(items),
                    },
                    "truth": _truth(items, False),
                    "strata": {
                        "platform": "linux",
                        "dialect": "posix",
                        "campaign": f"trajectory-{trajectory_id[:16]}",
                        "domain": next((item.category for item in items if item.category), "unknown"),
                        "hard_negative": False,
                        "split_group": split_group,
                        "trajectory_id": trajectory_id,
                        "sequence_index": position,
                        "call_index": call.index,
                    },
                }
            )

        supporting = [item for item in annotations if item.role == "supporting" and item.executed]
        malicious = [item for item in annotations if item.role == "malicious" and item.executed]
        pairs: set[tuple[int, int]] = set()
        for support in supporting:
            start = positions.get(support.coordinate)
            if start is None:
                continue
            for target in malicious:
                end = positions.get(target.coordinate)
                pair = (start, end)
                if end is None or start >= end or pair in pairs:
                    continue
                pairs.add(pair)
                window = calls[start : end + 1]
                if not 2 <= len(window) <= MAX_EVENTS:
                    skipped["stateful_window_out_of_bounds"] += 1
                    continue
                endpoint_items = [*by_coordinate[support.coordinate], *by_coordinate[target.coordinate]]
                spans = [
                    *_spans(by_coordinate[support.coordinate], 0),
                    *_spans(by_coordinate[target.coordinate], len(window) - 1),
                ]
                case_digest = hashlib.sha256(f"{revision}\0stateful\0{trajectory_id}\0{pair!r}".encode()).hexdigest()[
                    :24
                ]
                cases.append(
                    {
                        "schema_version": "1",
                        "id": f"labeled-bashbench/stateful/{case_digest}",
                        "source": _source(
                            revision,
                            f"{representative}:{support.coordinate[0]}:{support.coordinate[1]}->{target.coordinate[0]}:{target.coordinate[1]}",
                        ),
                        "split": "development",
                        "surface": "stateful",
                        "payload": {
                            "direction": "tool_call",
                            "annotation_spans": spans,
                            "events": [
                                {
                                    "tool_name": call.tool,
                                    "command": call.command,
                                    "dialect": "posix",
                                    "outcome": "unknown",
                                }
                                for call in window
                            ],
                        },
                        "truth": _truth(endpoint_items, True),
                        "strata": {
                            "platform": "linux",
                            "dialect": "posix",
                            "campaign": f"trajectory-{trajectory_id[:16]}",
                            "domain": target.category or "unknown",
                            "hard_negative": False,
                            "split_group": split_group,
                            "trajectory_id": trajectory_id,
                            "sequence_index": end,
                            "call_index": target.coordinate[1],
                        },
                    }
                )
                stateful_count += 1

    cases.sort(key=lambda item: item["id"])
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": SOURCE_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_redistribution": SOURCE_REDISTRIBUTION,
        "split": "development",
        "source_row_count": len(raw),
        "candidate_annotation_count": candidate_count,
        "selected_annotation_count": selected,
        "resolved_annotation_count_before_alias_dedup": sum(len(items) for items in resolved.values()),
        "index_mismatch_annotation_count": mismatches,
        "source_trajectory_count": len(snapshots),
        "unique_trajectory_count": len(aliases),
        "deduplicated_alias_count": len(snapshots) - len(aliases),
        "canonical_call_count": sum(len(items) for items in calls_by_source.values()),
        "divergent_coordinate_count": sum(len(items) for items in divergent_by_source.values()),
        "unique_action_count": len(cases) - stateful_count,
        "stateful_sequence_count": stateful_count,
        "total_case_count": len(cases),
        "task_count": len(tasks),
        "category_counts": dict(sorted(category_counts.items())),
        "action_type_counts": dict(sorted(action_counts.items())),
        "danger_level_counts": dict(sorted(danger_counts.items())),
        "skipped_row_counts": dict(sorted(skipped.items())),
        "execution_performed": False,
        "metric_boundary": (
            "All cases are development-only contextual candidates with unknown outcomes "
            "and are out of primary F1, recall, and FPR until deterministic proof finalization."
        ),
    }
    return cases, manifest


def validate_cases(rows: Sequence[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    for index, row in enumerate(rows, 1):
        errors = sorted(validator.iter_errors(row), key=lambda item: list(item.path))
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.path) or "<root>"
            raise ValueError(f"normalized row {index} invalid at {location}: {error.message}")


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_rows(source_rows(args.input), revision=args.source_revision)
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
                "atomic_count": manifest["unique_action_count"],
                "stateful_count": manifest["stateful_sequence_count"],
                "output_sha256": manifest["output_sha256"],
                "execution_performed": False,
                "truth_tier": "silver_contextual_development_only",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
