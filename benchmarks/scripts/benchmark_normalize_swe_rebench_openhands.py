#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned resolved SWE-rebench OpenHands executions as benign candidates."""

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
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "swe-rebench-openhands-trajectories"
SOURCE = "nebius/SWE-rebench-openhands-trajectories"
SOURCE_REVISION = "35455389ab51bf5e2306bfd436ef72d0f98bf882"
SOURCE_SHA256 = "14048dd1fcd22ce094b6e85f8a38f223a9ef1327031aaaad052804870212efa1"
SOURCE_BYTES = 2_079_503_354
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "swe-rebench-openhands-executed-benign-v1"

REQUIRED_COLUMNS = frozenset({"trajectory_id", "instance_id", "repo", "trajectory", "exit_status", "resolved"})
ACTION_TOOLS = frozenset({"execute_bash", "str_replace_editor"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
EXIT_MARKER = re.compile(r"^\[(?:The command completed|Command finished) with exit code (-?[0-9]+)\.?\]$")
MAX_EVENTS = 64
CHAIN_OVERLAP = 8
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_VALUE_BYTES = 32 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_TASK_BYTES = 256 * 1024
MAX_ITEMS = 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """A source trajectory cannot be projected without weakening its evidence."""

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


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


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
        if "\x00" in value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("invalid_argument_value")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [bounded(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_arguments")
        return {key: bounded(item, depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def decode_arguments(value: object) -> dict[str, object]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_arguments")
    try:
        decoded = json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError("invalid_arguments") from exc
    projected = bounded(decoded)
    if not isinstance(projected, dict) or len(canonical_json(projected).encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_arguments")
    return projected


def exact_arguments(tool: str, value: object) -> dict[str, object]:
    arguments = decode_arguments(value)
    if tool == "execute_bash":
        allowed = {"command", "is_input", "timeout"}
        if not set(arguments) <= allowed or "command" not in arguments:
            raise ProjectionError("non_exact_tool_schema")
        command = arguments["command"]
        if not isinstance(command, str) or not command:
            raise ProjectionError("non_exact_tool_schema")
        if "is_input" in arguments and arguments["is_input"] not in {"true", "false"}:
            raise ProjectionError("non_exact_tool_schema")
        if "timeout" in arguments and (
            type(arguments["timeout"]) is not int or not 1 <= int(arguments["timeout"]) <= 1800
        ):
            raise ProjectionError("non_exact_tool_schema")
        return arguments

    command = arguments.get("command")
    path = arguments.get("path")
    if not isinstance(command, str) or not isinstance(path, str) or not path.startswith("/"):
        raise ProjectionError("non_exact_tool_schema")
    expected: dict[str, frozenset[str]] = {
        "view": frozenset({"command", "path"}),
        "create": frozenset({"command", "file_text", "path"}),
        "str_replace": frozenset({"command", "new_str", "old_str", "path"}),
        "insert": frozenset({"command", "insert_line", "new_str", "path"}),
    }
    keys = frozenset(arguments)
    if command == "view" and keys == frozenset({"command", "path", "view_range"}):
        view_range = arguments["view_range"]
        if not (
            isinstance(view_range, list)
            and len(view_range) == 2
            and all(type(item) is int for item in view_range)
        ):
            raise ProjectionError("non_exact_tool_schema")
    elif command not in expected or keys != expected[command]:
        raise ProjectionError("non_exact_tool_schema")
    if command == "create" and not isinstance(arguments["file_text"], str):
        raise ProjectionError("non_exact_tool_schema")
    if command == "str_replace" and not all(isinstance(arguments[key], str) for key in ("new_str", "old_str")):
        raise ProjectionError("non_exact_tool_schema")
    if command == "insert" and (
        type(arguments["insert_line"]) is not int
        or int(arguments["insert_line"]) < 0
        or not isinstance(arguments["new_str"], str)
    ):
        raise ProjectionError("non_exact_tool_schema")
    return arguments


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def is_english_task(messages: Sequence[object]) -> bool:
    user_parts = [
        message.get("content")
        for message in messages
        if isinstance(message, Mapping) and message.get("role") == "user" and isinstance(message.get("content"), str)
    ]
    if not user_parts:
        return False
    task = "\n".join(user_parts)
    return (
        bool(re.search(r"[A-Za-z]", task))
        and NON_ENGLISH_SCRIPT.search(task) is None
        and len(task.encode("utf-8")) <= MAX_TASK_BYTES
    )


def explicit_outcome(tool: str, result: object) -> str:
    if not isinstance(result, str) or len(result.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ProjectionError("invalid_tool_result")
    if tool == "execute_bash":
        markers = [EXIT_MARKER.fullmatch(line.strip()) for line in result.splitlines()[-6:]]
        codes = [int(match.group(1)) for match in markers if match is not None]
        return "unknown" if not codes else "succeeded" if codes[-1] == 0 else "failed"
    if result.startswith("ERROR:"):
        return "failed"
    if (
        result.startswith("Here's the result of running `cat -n` on ")
        or result.startswith("Here's the files and directories up to ")
        or (result.startswith("The file ") and " has been edited." in result)
        or (result.startswith("The file ") and " has been created successfully" in result)
    ):
        return "succeeded"
    return "unknown"


def project_events(messages: Sequence[object]) -> tuple[list[dict[str, Any]], Counter[str]]:
    pending: dict[str, tuple[str, dict[str, object] | None, int]] = {}
    completed: set[str] = set()
    events: list[tuple[int, dict[str, Any]]] = []
    counts: Counter[str] = Counter()
    call_index = 0
    for message in messages:
        if not isinstance(message, Mapping):
            raise ProjectionError("invalid_message")
        role = message.get("role")
        calls = message.get("tool_calls")
        if calls is not None:
            if role != "assistant" or not isinstance(calls, list):
                raise ProjectionError("invalid_tool_calls")
            for call in calls:
                current_index = call_index
                call_index += 1
                if not isinstance(call, Mapping) or call.get("type") != "function":
                    raise ProjectionError("invalid_tool_call")
                call_id = required_id(call.get("id"), "invalid_tool_call_id")
                if call_id in pending or call_id in completed:
                    raise ProjectionError("duplicate_tool_call_id")
                function = call.get("function")
                if not isinstance(function, Mapping) or not isinstance(function.get("name"), str):
                    raise ProjectionError("invalid_tool_call")
                tool = str(function["name"])
                if tool in ACTION_TOOLS:
                    arguments = exact_arguments(tool, function.get("arguments"))
                    pending[call_id] = (tool, arguments, current_index)
                else:
                    pending[call_id] = (tool, None, current_index)
                    counts[f"excluded_tool_{tool}"] += 1
        if role != "tool":
            continue
        result_id = required_id(message.get("tool_call_id"), "invalid_tool_result_id")
        if result_id not in pending:
            raise ProjectionError("orphan_tool_result")
        tool, arguments, index = pending.pop(result_id)
        completed.add(result_id)
        if message.get("name") != tool:
            raise ProjectionError("tool_result_name_mismatch")
        if arguments is None:
            continue
        outcome = explicit_outcome(tool, message.get("content"))
        event: dict[str, Any] = {
            "args": arguments,
            "dialect": "posix" if tool == "execute_bash" else "none",
            "offset_seconds": index,
            "outcome": outcome,
            "tool_name": tool,
        }
        if tool == "execute_bash":
            event["command"] = arguments["command"]
        events.append((index, event))
        counts[f"accepted_{tool}"] += 1
        counts[f"outcome_{outcome}"] += 1
    if any(arguments is not None for _, arguments, _ in pending.values()):
        raise ProjectionError("missing_tool_result")
    events.sort(key=lambda item: item[0])
    return [event for _, event in events], counts


def split_group(instance_id: str) -> str:
    return hashlib.sha256(f"{DATASET_ID}\0{instance_id}".encode()).hexdigest()[:24]


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
        chunk = [dict(event, offset_seconds=index) for index, event in enumerate(events[start:end])]
        if len(chunk) >= 2:
            yield start, chunk
        if end == len(events):
            return
        start = end - CHAIN_OVERLAP


def truth() -> dict[str, Any]:
    return {
        "applicability": "in_scope",
        "categories": [
            "benign_candidate",
            "resolved_software_engineering_task",
            "real_executed_tool_calls",
            "bounded_action_sequence",
        ],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
        "label_confidence": "medium",
        "label_source": "source:resolved_swe_rebench_task",
        "source_truth": "benign",
    }


def normalize(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_trajectories: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        if not isinstance(row, Mapping):
            counts["rejected_invalid_row"] += 1
            continue
        try:
            trajectory_id = required_id(row.get("trajectory_id"), "invalid_trajectory_id")
            instance_id = required_id(row.get("instance_id"), "invalid_instance_id")
            repo = row.get("repo")
            messages = row.get("trajectory")
            if trajectory_id in seen_trajectories:
                raise ProjectionError("duplicate_trajectory_id")
            if not isinstance(repo, str) or SAFE_REPO.fullmatch(repo) is None:
                raise ProjectionError("invalid_repo")
            if type(row.get("resolved")) is not int or row.get("resolved") != 1:
                raise ProjectionError("not_resolved")
            if not isinstance(messages, list) or not is_english_task(messages):
                raise ProjectionError("non_english_or_invalid_task")
            events, event_counts = project_events(messages)
        except ProjectionError as exc:
            counts[f"rejected_{exc.code}"] += 1
            continue
        seen_trajectories.add(trajectory_id)
        counts.update(event_counts)
        chunks = list(bounded_chunks(events))
        if not chunks:
            counts["excluded_fewer_than_two_executed_actions"] += 1
            continue
        group = split_group(instance_id)
        split = split_for(group)
        trajectory = hashlib.sha256(f"{SOURCE_REVISION}\0{trajectory_id}".encode()).hexdigest()[:24]
        for chunk_number, (start, chunk) in enumerate(chunks):
            cases.append(
                {
                    "id": f"swe-rebench-openhands/{trajectory}/chunk-{chunk_number:03d}",
                    "payload": {"direction": "tool_call", "events": chunk},
                    "schema_version": SCHEMA_VERSION,
                    "source": {
                        "dataset": DATASET_ID,
                        "license": SOURCE_LICENSE,
                        "original_id": trajectory_id,
                        "redistribution": SOURCE_REDISTRIBUTION,
                        "revision": SOURCE_REVISION,
                    },
                    "split": split,
                    "strata": {
                        "call_index": start + len(chunk) - 1,
                        "domain": "software_engineering",
                        "ecosystem": "openhands",
                        "hard_negative": True,
                        "language": "en",
                        "sequence_index": start,
                        "split_group": group,
                        "trajectory_id": trajectory,
                    },
                    "surface": "stateful",
                    "truth": truth(),
                }
            )
            counts[f"cases_{split}"] += 1
        counts["accepted_trajectories"] += 1
        counts["events"] += len(events)
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    return cases, counts


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read SWE-rebench OpenHands Parquet") from exc
    source = parquet.ParquetFile(path)
    missing = sorted(REQUIRED_COLUMNS - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"missing SWE-rebench OpenHands columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=32, columns=sorted(REQUIRED_COLUMNS)):
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
            raise ValueError(f"{case_id}: this adapter may only supply benign candidates")
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
        raise ValueError("pinned SWE-rebench OpenHands source identity mismatch")
    cases, counts = normalize(parquet_rows(args.input))
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
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
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
