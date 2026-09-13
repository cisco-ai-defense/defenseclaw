#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize compact WildClawBench trajectories conservatively.

The compact Parquet contains complete OpenClaw conversations. This adapter
retains only executed tool names, structured arguments, paired result status,
and stable bounded ordering. Prompts, assistant text/reasoning, tool-result
content, images, usage, timestamps, and final answers are excluded.

English non-safety tasks are benign FPR cases. Safety Alignment tasks have no
joined execution score in the compact Parquet, so every case from those tasks
remains contextual and out of scored scope. No WildClawBench row becomes a
malicious positive through this adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "internlm/WildClawBench-Trajectories"
SOURCE_URL = "https://huggingface.co/datasets/internlm/WildClawBench-Trajectories"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_PATH = "train.parquet"
SOURCE_BYTES = 25_358_054
SOURCE_SHA256 = "9be080beb826b4c620d0a5d2987d1a0d3be758248076dfff48807fb11fcb4c17"
SOURCE_COLUMNS = frozenset({"task_id", "trajectory", "model_name", "task_category"})
SAFETY_CATEGORY = "Safety Alignment"
MAX_EVENTS = 64
CHAIN_BOUND = 8
MAX_ARGUMENT_BYTES = 1_048_576
MAX_VALUE_BYTES = 262_144
MAX_CONTAINER_ITEMS = 4096
MAX_SOURCE_TRAJECTORY_BYTES = 16 * 1024 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/&() -]{0,199}$")
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """An untrusted source record cannot be projected safely."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--split", choices=("development", "validation", "test"), required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def required_text(value: object, code: str, *, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProjectionError(code)
    return value.strip()


def bounded(value: object, *, depth: int = 0) -> object:
    if depth > 32:
        raise ProjectionError("arguments_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_argument")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("argument_value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProjectionError("arguments_too_many_items")
        return [bounded(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS or any(
            not isinstance(key, str) for key in value
        ):
            raise ProjectionError("invalid_arguments_object")
        return {key: bounded(item, depth=depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def is_english_task(task_id: str) -> bool:
    # Upstream marks its 12 Chinese-language tasks per model with stable `_zh`
    # task-name components (including one English-to-Chinese dubbing task).
    # Some English tasks intentionally process multilingual artifacts, so content
    # script heuristics would incorrectly discard valid English instructions.
    return "_zh" not in task_id


def decode_trajectory(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, str) or not value:
        raise ProjectionError("invalid_trajectory")
    if len(value.encode("utf-8")) > MAX_SOURCE_TRAJECTORY_BYTES:
        raise ProjectionError("trajectory_too_large")
    try:
        decoded = json.loads(
            value,
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite_json,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        raise ProjectionError("invalid_trajectory_json") from exc
    if not isinstance(decoded, list) or any(not isinstance(item, dict) for item in decoded):
        raise ProjectionError("invalid_trajectory_messages")
    return decoded


def result_statuses(messages: Sequence[Mapping[str, Any]]) -> tuple[dict[str, str], int]:
    statuses: dict[str, str] = {}
    orphan_candidates = 0
    for message in messages:
        if message.get("role") != "toolResult":
            continue
        call_id = message.get("toolCallId")
        if not isinstance(call_id, str) or not call_id or len(call_id) > 240:
            raise ProjectionError("invalid_tool_result_identity")
        if call_id in statuses:
            raise ProjectionError("duplicate_tool_result_identity")
        is_error = message.get("isError")
        if type(is_error) is not bool:
            raise ProjectionError("invalid_tool_result_status")
        statuses[call_id] = "failed" if is_error else "succeeded"
        orphan_candidates += 1
    return statuses, orphan_candidates


def projected_events(
    messages: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], Counter[str], set[str]]:
    statuses, _ = result_statuses(messages)
    events: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    call_ids: set[str] = set()
    for message in messages:
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            raise ProjectionError("invalid_assistant_content")
        for item in content:
            if not isinstance(item, Mapping) or item.get("type") != "toolCall":
                continue
            call_id = required_text(item.get("id"), "invalid_tool_call_identity", maximum=240)
            tool = required_text(item.get("name"), "invalid_tool_name", maximum=160)
            if call_id in call_ids or not SAFE_TOOL.fullmatch(tool):
                raise ProjectionError("invalid_or_duplicate_tool_call_identity")
            arguments = item.get("arguments")
            if not isinstance(arguments, dict):
                raise ProjectionError("invalid_tool_arguments")
            try:
                argument_size = len(canonical_json(arguments).encode("utf-8"))
            except (TypeError, ValueError, RecursionError) as exc:
                raise ProjectionError("invalid_tool_arguments") from exc
            if argument_size > MAX_ARGUMENT_BYTES:
                raise ProjectionError("arguments_too_large")
            call_ids.add(call_id)
            outcome = statuses.get(call_id, "unknown")
            event: dict[str, Any] = {
                "tool_name": tool,
                "args": bounded(arguments),
                "dialect": "none",
                "outcome": outcome,
                "offset_seconds": len(events),
            }
            command = arguments.get("command")
            if tool == "exec" and isinstance(command, str) and command:
                event["command"] = command
                event["dialect"] = "posix"
            events.append(event)
            counts[f"source_calls_{outcome}"] += 1
    counts["orphan_tool_results"] = len(set(statuses) - call_ids)
    return events, counts, call_ids


def bounded_windows(event_count: int) -> Iterable[tuple[int, int]]:
    start = 0
    while start < event_count - 1:
        end = min(event_count, start + MAX_EVENTS)
        yield start, end
        if end == event_count:
            return
        start = end - CHAIN_BOUND


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def benign_truth(*, stateful: bool) -> dict[str, Any]:
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "medium",
        "label_source": "wildclawbench:non_safety_executed_task",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": [
            "wildclawbench",
            "executed_trajectory",
            "benign_hard_negative",
            "bounded_action_sequence" if stateful else "atomic_tool_call",
        ],
    }


def contextual_truth(*, stateful: bool) -> dict[str, Any]:
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "wildclawbench:safety_score_not_joined",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": [
            "wildclawbench",
            "safety_alignment",
            "score_join_required",
            "bounded_action_sequence" if stateful else "atomic_tool_call",
        ],
        "exclusion_reason": (
            "The compact Parquet does not contain a trustworthy joined safety outcome; "
            "task category alone cannot assign malicious or benign security truth."
        ),
    }


def project_row(
    row: Mapping[str, Any], *, revision: str, split: str
) -> tuple[list[dict[str, Any]], Counter[str], str]:
    task_id = required_text(row.get("task_id"), "invalid_task_id")
    model = required_text(row.get("model_name"), "invalid_model_name")
    category = required_text(row.get("task_category"), "invalid_task_category")
    if not all(SAFE_ID.fullmatch(value) for value in (task_id, model, category)):
        raise ProjectionError("invalid_source_identity")
    if not is_english_task(task_id):
        raise ProjectionError("non_english")
    messages = decode_trajectory(row.get("trajectory"))
    events, event_counts, _ = projected_events(messages)
    identity = digest(DATASET_ID, revision, model, task_id)
    base = {
        "schema_version": SCHEMA_VERSION,
        "source": source_record(revision, f"{model}/{task_id}"),
        "split": split,
    }
    safety = category == SAFETY_CATEGORY
    atomic_truth = contextual_truth(stateful=False) if safety else benign_truth(stateful=False)
    stateful_truth = contextual_truth(stateful=True) if safety else benign_truth(stateful=True)
    cases: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        payload = {
            key: event[key]
            for key in ("tool_name", "command", "args", "dialect")
            if key in event
        }
        cases.append(
            {
                **base,
                "id": f"wildclawbench/{identity[:24]}/call-{index:03d}",
                "surface": "action",
                "payload": {"direction": "tool_call", **payload},
                "truth": dict(atomic_truth),
                "strata": {
                    "language": "en",
                    "ecosystem": "openclaw",
                    "campaign": model,
                    "domain": category,
                    "hard_negative": not safety,
                    "split_group": identity[:24],
                    "trajectory_id": identity[:24],
                    "sequence_index": index,
                    "call_index": index,
                },
            }
        )
    for window_number, (start, end) in enumerate(bounded_windows(len(events))):
        cases.append(
            {
                **base,
                "id": f"wildclawbench/{identity[:24]}/window-{window_number:03d}",
                "surface": "stateful",
                "payload": {
                    "direction": "tool_call",
                    "events": [dict(event) for event in events[start:end]],
                    "args": {
                        "_wildclawbench_evidence": {
                            "window": {
                                "start_event": start,
                                "end_event_exclusive": end,
                                "total_events": len(events),
                            },
                            "task_category": category,
                            "safety_score_joined": False,
                        }
                    },
                },
                "truth": dict(stateful_truth),
                "strata": {
                    "language": "en",
                    "ecosystem": "openclaw",
                    "campaign": model,
                    "domain": category,
                    "hard_negative": not safety,
                    "split_group": identity[:24],
                    "trajectory_id": identity[:24],
                    "sequence_index": start,
                    "call_index": end - 1,
                },
            }
        )
    return cases, event_counts, "safety" if safety else "benign"


def normalize(
    rows: Iterable[Mapping[str, Any]], *, revision: str, split: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    revision = required_text(revision, "invalid_revision")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full lowercase Git commit")
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for row in rows:
        counts["source_trajectories"] += 1
        if not isinstance(row, Mapping):
            skipped["invalid_source_row"] += 1
            continue
        identity = (str(row.get("model_name", "")), str(row.get("task_id", "")))
        if identity in seen:
            skipped["duplicate_trajectory_identity"] += 1
            continue
        seen.add(identity)
        try:
            projected, event_counts, disposition = project_row(
                row, revision=revision, split=split
            )
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        counts["selected_english_trajectories"] += 1
        counts[f"trajectories_{disposition}"] += 1
        counts.update(event_counts)
        action_count = sum(case["surface"] == "action" for case in projected)
        counts["source_tool_calls"] += action_count
        if action_count == 0:
            counts["zero_tool_call_trajectories"] += 1
        for case in projected:
            counts[f"cases_{case['surface']}"] += 1
            counts[f"cases_{case['truth']['source_truth']}"] += 1
        cases.extend(projected)
    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    return cases, {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_path": SOURCE_PATH,
        "split": split,
        "row_count": len(cases),
        "counts": dict(sorted(counts.items())),
        "skipped": dict(sorted(skipped.items())),
        "language": "en",
        "excluded_fields": [
            "user text and prompts",
            "assistant text and reasoning",
            "tool-result content and images",
            "final answers",
            "usage and timestamps",
        ],
        "normalization": (
            "exact executed tool names and arguments plus paired result status and "
            "bounded ordering; non-safety tasks are benign hard negatives"
        ),
        "label_limitation": (
            "Safety Alignment task membership is not an outcome label. Safety rows remain "
            "contextual and out of scored scope until trustworthy evaluation scores are joined; "
            "this adapter emits no malicious positives."
        ),
    }


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError(
            "pyarrow==25.0.1 is required to read WildClawBench Parquet"
        ) from exc
    source = parquet.ParquetFile(path)
    missing = sorted(SOURCE_COLUMNS - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=16, columns=sorted(SOURCE_COLUMNS)):
        yield from batch.to_pylist()


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(
        json.loads(schema_path.read_text(encoding="utf-8"))
    )
    seen: set[str] = set()
    for row in rows:
        case_id = str(row.get("id", ""))
        if case_id in seen:
            raise ValueError("duplicate benchmark case ID")
        seen.add(case_id)
        errors = sorted(
            validator.iter_errors(row), key=lambda error: list(error.absolute_path)
        )
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{case_id}:{location or '<root>'}: {errors[0].message}")
        if row["truth"]["source_truth"] == "malicious":
            raise ValueError(f"{case_id}: WildClawBench cannot supply malicious truth")
        if row["surface"] == "stateful" and not (
            2 <= len(row["payload"]["events"]) <= MAX_EVENTS
        ):
            raise ValueError(f"{case_id}: invalid bounded event count")


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
    if args.input.stat().st_size != SOURCE_BYTES:
        raise ValueError(
            f"unexpected source size: {args.input.stat().st_size}; expected {SOURCE_BYTES}"
        )
    source_digest = file_sha256(args.input)
    if source_digest != SOURCE_SHA256:
        raise ValueError(f"unexpected source SHA-256: {source_digest}")
    cases, manifest = normalize(
        parquet_rows(args.input), revision=args.revision, split=args.split
    )
    validate_cases(cases, args.schema)
    output_data = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {
        **manifest,
        "source": {
            "dataset": DATASET_ID,
            "revision": args.revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": SOURCE_PATH,
            "bytes": SOURCE_BYTES,
            "sha256": SOURCE_SHA256,
        },
        "output_sha256": hashlib.sha256(output_data).hexdigest(),
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, output_data)
    atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
