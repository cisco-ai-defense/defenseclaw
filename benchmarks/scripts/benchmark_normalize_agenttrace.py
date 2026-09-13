#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned AgentTrace executions as conservative benign FPR cases."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import tempfile
import warnings
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "agent-trace"
SOURCE = "pagarsky/agent-trace"
SOURCE_URL = f"https://huggingface.co/datasets/{SOURCE}"
SOURCE_REVISION = "4b05b2f00eea267a5bb4d841c228059d1bf9ac0c"
SOURCE_SHA256 = "11c04875f9b6e91b117b5739d748e6bd4f8fa621e95faf430fa40d5d4d223c97"
SOURCE_BYTES = 10_638_584
SOURCE_LICENSE = "Apache-2.0 (upstream-source caveat)"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "agenttrace-executed-benign-v1"

REQUIRED_COLUMNS = frozenset(
    {"trace_id", "dataset_name", "task_id", "run_id", "tool_span_count", "spans_json", "metadata_json", "prompt"}
)
SOURCE_DATASETS = frozenset({"mbpp", "nl2bash"})
ACTION_TOOLS = frozenset({"bash", "python_interpreter"})
IGNORED_TOOLS = frozenset({"final_answer"})
TOOL_ARGUMENT = {"bash": "command", "python_interpreter": "code"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
MAX_EVENTS = 64
CHAIN_OVERLAP = 8
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_VALUE_BYTES = 32 * 1024
MAX_ITEMS = 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """A source record cannot be projected without weakening its evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def decode_json(value: object, code: str) -> object:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_JSON_BYTES:
        raise ProjectionError(code)
    try:
        return json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError(code) from exc


def bounded(value: object, depth: int = 0) -> object:
    if depth > 24:
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
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [bounded(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_arguments")
        return {key: bounded(item, depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def exact_tool_arguments(value: object, tool: str) -> dict[str, object]:
    if not isinstance(value, str) or not value.startswith("kwargs="):
        raise ProjectionError("unsupported_tool_input")
    if len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            parsed = ast.literal_eval(value.removeprefix("kwargs="))
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as exc:
        raise ProjectionError("invalid_tool_input") from exc
    argument_name = TOOL_ARGUMENT[tool]
    if not isinstance(parsed, dict) or set(parsed) != {argument_name}:
        raise ProjectionError("non_exact_tool_schema")
    projected = bounded(parsed)
    if not isinstance(projected, dict):
        raise ProjectionError("invalid_tool_input")
    action = projected.get(argument_name)
    if not isinstance(action, str) or not action or len(action.encode("utf-8")) > MAX_VALUE_BYTES:
        raise ProjectionError("missing_exact_action")
    return projected


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def english_task(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(re.search(r"[A-Za-z]", value))
        and NON_ENGLISH_SCRIPT.search(value) is None
        and len(value.encode("utf-8")) <= 256 * 1024
    )


def validate_provenance(row: Mapping[str, Any]) -> tuple[str, str, int]:
    trace_id = required_id(row.get("trace_id"), "invalid_trace_id")
    dataset = row.get("dataset_name")
    task_id = row.get("task_id")
    run_id = required_id(row.get("run_id"), "invalid_run_id")
    if dataset not in SOURCE_DATASETS:
        raise ProjectionError("unsupported_source_dataset")
    if type(task_id) is not int or task_id < 0:
        raise ProjectionError("invalid_task_id")
    if not english_task(row.get("prompt")):
        raise ProjectionError("non_english_or_invalid_task")
    metadata = decode_json(row.get("metadata_json"), "invalid_metadata_json")
    if not isinstance(metadata, dict):
        raise ProjectionError("invalid_metadata")
    expected = {
        "schema_version": "0.3.0",
        "collector_version": "0.3.0",
        "dataset_name": dataset,
        "source": dataset,
        "task_id": task_id,
        "run_id": run_id,
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ProjectionError("provenance_mismatch")
    expected_split = "test" if dataset == "mbpp" else "train"
    if metadata.get("dataset_split") != expected_split:
        raise ProjectionError("provenance_mismatch")
    if dataset == "nl2bash" and not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("fixture_version", ""))):
        raise ProjectionError("provenance_mismatch")
    return trace_id, dataset, task_id


def project_events(row: Mapping[str, Any]) -> tuple[list[dict[str, Any]], Counter[str]]:
    spans = decode_json(row.get("spans_json"), "invalid_spans_json")
    declared = row.get("tool_span_count")
    if not isinstance(spans, list) or any(not isinstance(span, dict) for span in spans):
        raise ProjectionError("invalid_spans")
    if type(declared) is not int or declared != len(spans):
        raise ProjectionError("tool_span_count_mismatch")
    events: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_span_ids: set[str] = set()
    for span in spans:
        span_id = required_id(span.get("span_id"), "invalid_span_id")
        if span_id in seen_span_ids:
            raise ProjectionError("duplicate_span_id")
        seen_span_ids.add(span_id)
        if span.get("type") != "TOOL":
            raise ProjectionError("invalid_span_type")
        tool = span.get("tool_name")
        if tool in IGNORED_TOOLS:
            counts[f"excluded_{tool}"] += 1
            continue
        if tool not in ACTION_TOOLS:
            raise ProjectionError("unsupported_tool")
        arguments = exact_tool_arguments(span.get("tool_input"), str(tool))
        exit_code = span.get("exit_code")
        if type(exit_code) is not int:
            raise ProjectionError("missing_explicit_exit_code")
        event: dict[str, Any] = {
            "args": arguments,
            "dialect": "posix" if tool == "bash" else "none",
            "offset_seconds": len(events),
            "outcome": "succeeded" if exit_code == 0 else "failed",
            "tool_name": tool,
        }
        if tool == "bash":
            event["command"] = arguments["command"]
        events.append(event)
        counts[f"accepted_{tool}"] += 1
        counts[f"outcome_{event['outcome']}"] += 1
    return events, counts


def split_group(dataset: str, task_id: int) -> str:
    return hashlib.sha256(f"{DATASET_ID}\0{dataset}\0{task_id}".encode()).hexdigest()[:24]


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode()).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def bounded_chunks(events: list[dict[str, Any]]) -> Iterable[tuple[int, list[dict[str, Any]]]]:
    start = 0
    while start < len(events):
        end = min(len(events), start + MAX_EVENTS)
        yield start, events[start:end]
        if end == len(events):
            return
        start = end - CHAIN_OVERLAP


def truth(dataset: str, stateful: bool) -> dict[str, Any]:
    return {
        "applicability": "in_scope",
        "categories": [
            "benign",
            "executed_benchmark_task",
            dataset,
            "bounded_action_sequence" if stateful else "atomic_tool_call",
        ],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
        "label_confidence": "medium",
        "label_source": "source:executed_mbpp_nl2bash_task",
        "source_truth": "benign",
    }


def normalize(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_traces: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        if not isinstance(row, Mapping):
            counts["rejected_invalid_row"] += 1
            continue
        try:
            trace_id, dataset, task_id = validate_provenance(row)
            if trace_id in seen_traces:
                raise ProjectionError("duplicate_trace_id")
            events, event_counts = project_events(row)
        except ProjectionError as exc:
            counts[f"rejected_{exc.code}"] += 1
            continue
        seen_traces.add(trace_id)
        counts.update(event_counts)
        if not events:
            counts["excluded_no_executed_action"] += 1
            continue
        group = split_group(dataset, task_id)
        split = split_for(group)
        trajectory = hashlib.sha256(f"{SOURCE_REVISION}\0{trace_id}".encode()).hexdigest()[:24]
        chunks = list(bounded_chunks(events))
        for chunk_number, (start, chunk) in enumerate(chunks):
            stateful = len(chunk) > 1
            if stateful:
                surface = "stateful"
                payload: dict[str, Any] = {"direction": "tool_call", "events": chunk}
            else:
                surface = "action"
                event = chunk[0]
                payload = {
                    "direction": "tool_call",
                    **{key: event[key] for key in ("tool_name", "command", "args", "dialect") if key in event},
                }
            suffix = f"chunk-{chunk_number:03d}" if len(chunks) > 1 else "trajectory"
            cases.append(
                {
                    "id": f"agent-trace/{trajectory}/{suffix}",
                    "payload": payload,
                    "schema_version": SCHEMA_VERSION,
                    "source": {
                        "dataset": DATASET_ID,
                        "license": SOURCE_LICENSE,
                        "original_id": trace_id,
                        "redistribution": SOURCE_REDISTRIBUTION,
                        "revision": SOURCE_REVISION,
                    },
                    "split": split,
                    "strata": {
                        "domain": dataset,
                        "ecosystem": "agent-trace",
                        "hard_negative": True,
                        "language": "en",
                        "sequence_index": start,
                        "call_index": start + len(chunk) - 1,
                        "split_group": group,
                        "trajectory_id": trajectory,
                    },
                    "surface": surface,
                    "truth": truth(dataset, stateful),
                }
            )
            counts[f"cases_{surface}"] += 1
            counts[split] += 1
        counts[f"accepted_trajectories_{dataset}"] += 1
        counts["accepted_trajectories"] += 1
        counts["events"] += len(events)
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    return cases, counts


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read AgentTrace Parquet") from exc
    source = parquet.ParquetFile(path)
    missing = sorted(REQUIRED_COLUMNS - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"missing AgentTrace columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=64, columns=sorted(REQUIRED_COLUMNS)):
        yield from batch.to_pylist()


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    group_splits: dict[str, str] = {}
    for case in cases:
        case_id = str(case.get("id", ""))
        if case_id in seen_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
            raise ValueError(f"{case_id}:{location}: {errors[0].message}")
        if case["truth"]["deterministic_truth"] != "benign":
            raise ValueError(f"{case_id}: AgentTrace may only supply benign truth")
        group = case["strata"]["split_group"]
        previous = group_splits.setdefault(group, case["split"])
        if previous != case["split"]:
            raise ValueError(f"{case_id}: split group crosses dataset splits")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.is_file() or args.input.is_symlink():
        raise ValueError("input must be a regular non-symlink file")
    if args.input.stat().st_size != SOURCE_BYTES or sha256_file(args.input) != SOURCE_SHA256:
        raise ValueError("pinned AgentTrace source identity mismatch")
    cases, counts = normalize(parquet_rows(args.input))
    validate_cases(cases, args.schema)
    body = "".join(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n" for case in cases).encode()
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(body).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": SOURCE_BYTES,
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "path": args.input.name,
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
            "sha256": SOURCE_SHA256,
        },
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, body)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
