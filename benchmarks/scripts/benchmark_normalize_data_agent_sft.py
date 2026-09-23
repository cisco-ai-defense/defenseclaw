#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned HuggingEnvs Data Agent executions as benign candidates.

The source card states that every row is an ordinary data-analysis task that
reached the correct answer under a deterministic grader. That evidence supports
benign *task intent*; it does not make every command successful or universally
safe. This adapter therefore retains each exact structured call once as an
atomic action, joins results only by their source call IDs, and emits an outcome
only inside stateful cases and only for an exact source return-code marker.
Prompts, prose, reasoning, answers, tool schemas, and result bodies are never
copied into detector payloads.

Every stateful case represents one current call and no more than its eight
immediate predecessors. Atomic calls are not content-deduplicated because
repeated legitimate operations belong in the operational FPR denominator.
Exact duplicate stateful windows are retained once, after rows are sorted by
task ID, so duplicate chains cannot leak across task-grouped splits.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "HuggingEnvs/data-agent-sft"
SOURCE_REVISION = "cc0a03c10342a8f7fcf33c9203039582df405703"
SOURCE_FILE = "data/train-00000-of-00001.parquet"
SOURCE_SHA256 = "73a8d0587c73d1b712b514add40c647ee792f89d7eb5540252c66336533aa907"
SOURCE_BYTES = 28_918_861
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "data-agent-sft-executed-benign-v1"

REQUIRED_COLUMNS = frozenset(
    {"task_id", "difficulty", "difficulty_tier", "n_turns", "source_agent", "messages", "tools"}
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_AGENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
EXACT_RC = re.compile(r"^\(empty output, rc=(-?[0-9]+)\)$")
MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_MESSAGES = 256
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 1024 * 1024
MAX_ITEMS = 4096
MAX_DEPTH = 24

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """A source row cannot be projected without weakening its evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProjectedTrajectory:
    task_id: str
    difficulty: int
    difficulty_tier: str
    source_agent: str
    events: tuple[dict[str, Any], ...]


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
    if depth > MAX_DEPTH:
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


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def decode_message(value: object) -> dict[str, Any]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ProjectionError("invalid_message")
    try:
        decoded = json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError("invalid_message") from exc
    if not isinstance(decoded, dict):
        raise ProjectionError("invalid_message")
    return decoded


def available_tools(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        raise ProjectionError("invalid_tools")
    names: set[str] = set()
    for tool in value:
        if not isinstance(tool, Mapping) or set(tool) != {"type", "function"} or tool.get("type") != "function":
            raise ProjectionError("invalid_tools")
        function = tool.get("function")
        if not isinstance(function, Mapping):
            raise ProjectionError("invalid_tools")
        name = function.get("name")
        parameters = function.get("parameters")
        if not isinstance(name, str) or SAFE_ID.fullmatch(name) is None or name in names:
            raise ProjectionError("invalid_tools")
        if not isinstance(parameters, Mapping) or parameters.get("type") != "object":
            raise ProjectionError("invalid_tools")
        names.add(name)
    if names != {"bash"}:
        raise ProjectionError("unsupported_tool_set")
    return frozenset(names)


def exact_arguments(value: object) -> dict[str, object]:
    if isinstance(value, str):
        raise ProjectionError("dynamic_arguments")
    projected = bounded(value)
    if not isinstance(projected, dict) or set(projected) != {"command"}:
        raise ProjectionError("non_exact_tool_schema")
    command = projected.get("command")
    if not isinstance(command, str) or not command or len(command.encode("utf-8")) > MAX_VALUE_BYTES:
        raise ProjectionError("non_exact_tool_schema")
    try:
        encoded = canonical_json(projected).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_arguments") from exc
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_arguments")
    return projected


def explicit_outcome(value: object) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ProjectionError("invalid_tool_result")
    match = EXACT_RC.fullmatch(value.strip())
    if match is None:
        return "unknown"
    return "succeeded" if int(match.group(1)) == 0 else "failed"


def english_task(messages: Sequence[dict[str, Any]]) -> bool:
    user_parts = [
        message.get("content")
        for message in messages
        if message.get("role") == "user" and isinstance(message.get("content"), str)
    ]
    if not user_parts:
        return False
    task = "\n".join(user_parts)
    return bool(re.search(r"[A-Za-z]", task)) and NON_ENGLISH_SCRIPT.search(task) is None


def project_events(messages_value: object, tool_names: frozenset[str]) -> tuple[list[dict[str, Any]], Counter[str]]:
    if not isinstance(messages_value, list) or not 1 <= len(messages_value) <= MAX_MESSAGES:
        raise ProjectionError("invalid_messages")
    messages = [decode_message(message) for message in messages_value]
    if not english_task(messages):
        raise ProjectionError("non_english_or_invalid_task")

    pending: dict[str, tuple[int, str, dict[str, object]]] = {}
    completed: set[str] = set()
    events: list[tuple[int, dict[str, Any]]] = []
    statistics: Counter[str] = Counter()
    call_index = 0
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if not isinstance(content, str):
            raise ProjectionError("invalid_message_content")
        if role in {"system", "user"}:
            if set(message) != {"role", "content"} or pending:
                raise ProjectionError("interrupted_call_result_block" if pending else "invalid_message_shape")
            statistics[f"excluded_role_{role}"] += 1
            continue
        if role == "assistant":
            if pending:
                raise ProjectionError("interrupted_call_result_block")
            if set(message) == {"role", "content"}:
                statistics["excluded_assistant_prose"] += 1
                continue
            if set(message) != {"role", "content", "tool_calls"}:
                raise ProjectionError("invalid_message_shape")
            calls = message.get("tool_calls")
            if not isinstance(calls, list) or not calls or len(calls) > MAX_ITEMS:
                raise ProjectionError("invalid_tool_calls")
            for call in calls:
                if not isinstance(call, Mapping) or set(call) != {"id", "type", "function"}:
                    raise ProjectionError("invalid_tool_call")
                if call.get("type") != "function":
                    raise ProjectionError("invalid_tool_call")
                call_id = required_id(call.get("id"), "invalid_tool_call_id")
                if call_id in pending or call_id in completed:
                    raise ProjectionError("duplicate_tool_call_id")
                function = call.get("function")
                if not isinstance(function, Mapping) or set(function) != {"name", "arguments"}:
                    raise ProjectionError("invalid_tool_call")
                tool_name = function.get("name")
                if not isinstance(tool_name, str) or tool_name not in tool_names:
                    raise ProjectionError("unknown_tool")
                arguments = exact_arguments(function.get("arguments"))
                pending[call_id] = (call_index, tool_name, arguments)
                call_index += 1
                statistics["source_tool_calls"] += 1
            continue
        if role != "tool" or set(message) != {"role", "content", "name", "tool_call_id"}:
            raise ProjectionError("invalid_message_shape")
        result_id = required_id(message.get("tool_call_id"), "invalid_tool_result_id")
        if result_id not in pending:
            raise ProjectionError("orphan_tool_result")
        index, tool_name, arguments = pending.pop(result_id)
        completed.add(result_id)
        if message.get("name") != tool_name:
            raise ProjectionError("tool_result_name_mismatch")
        outcome = explicit_outcome(content)
        events.append(
            (
                index,
                {
                    "args": arguments,
                    "command": arguments["command"],
                    "dialect": "posix",
                    "offset_seconds": index,
                    "outcome": outcome,
                    "tool_name": tool_name,
                },
            )
        )
        statistics["paired_tool_calls"] += 1
        statistics[f"outcome_{outcome}"] += 1
    if pending:
        raise ProjectionError("missing_tool_result")
    events.sort(key=lambda item: item[0])
    return [event for _, event in events], statistics


def project_row(row: Mapping[str, Any]) -> tuple[ProjectedTrajectory, Counter[str]]:
    if set(row) != REQUIRED_COLUMNS:
        raise ProjectionError("invalid_row_shape")
    task_id = required_id(row.get("task_id"), "invalid_task_id")
    difficulty = row.get("difficulty")
    tier = row.get("difficulty_tier")
    n_turns = row.get("n_turns")
    source_agent = row.get("source_agent")
    if type(difficulty) is not int or not 1 <= difficulty <= 5:
        raise ProjectionError("invalid_difficulty")
    if tier not in {"easy", "medium", "hard"}:
        raise ProjectionError("invalid_difficulty_tier")
    if type(n_turns) is not int or not 1 <= n_turns <= MAX_MESSAGES:
        raise ProjectionError("invalid_turn_count")
    if not isinstance(source_agent, str) or SAFE_AGENT.fullmatch(source_agent) is None:
        raise ProjectionError("invalid_source_agent")
    tools = available_tools(row.get("tools"))
    events, statistics = project_events(row.get("messages"), tools)
    if len(events) < 2:
        raise ProjectionError("fewer_than_two_paired_calls")
    return ProjectedTrajectory(task_id, difficulty, str(tier), source_agent, tuple(events)), statistics


def bounded_windows(events: Sequence[dict[str, Any]]) -> Iterable[tuple[int, int, list[dict[str, Any]]]]:
    for current in range(1, len(events)):
        start = max(0, current - MAX_PREDECESSORS)
        window = [dict(event, offset_seconds=index) for index, event in enumerate(events[start : current + 1])]
        yield start, current, window


def split_group(task_id: str) -> str:
    return hashlib.sha256(f"{DATASET_ID}\0{task_id}".encode()).hexdigest()[:24]


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode()).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def truth(*, stateful: bool) -> dict[str, Any]:
    representation = "bounded_action_sequence" if stateful else "structured_tool_call"
    return {
        "applicability": "in_scope",
        "categories": [
            "benign_candidate",
            "ordinary_data_analysis",
            "deterministic_grader_success",
            "executed_linux_sandbox",
            representation,
        ],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
        "label_confidence": "medium",
        "label_source": "source:data_agent_sft_card_verified_correct",
        "source_truth": "benign",
    }


def normalize(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    projected: list[ProjectedTrajectory] = []
    task_fingerprints: dict[str, str] = {}
    conflicted_tasks: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        if not isinstance(row, Mapping):
            counts["quarantined_invalid_row"] += 1
            continue
        try:
            trajectory, event_counts = project_row(row)
        except ProjectionError as exc:
            counts[f"quarantined_{exc.code}"] += 1
            continue
        fingerprint = hashlib.sha256(canonical_json(trajectory.events).encode()).hexdigest()
        previous = task_fingerprints.get(trajectory.task_id)
        if previous is not None:
            if previous == fingerprint:
                counts["exact_trajectory_duplicates_removed"] += 1
            else:
                conflicted_tasks.add(trajectory.task_id)
                counts["quarantined_conflicting_task_id"] += 1
            continue
        task_fingerprints[trajectory.task_id] = fingerprint
        projected.append(trajectory)
        counts.update(event_counts)

    cases: list[dict[str, Any]] = []
    seen_windows: set[str] = set()
    for trajectory in sorted(projected, key=lambda item: item.task_id):
        if trajectory.task_id in conflicted_tasks:
            continue
        group = split_group(trajectory.task_id)
        split = split_for(group)
        trajectory_id = hashlib.sha256(f"{SOURCE_REVISION}\0{trajectory.task_id}".encode()).hexdigest()[:24]
        source = {
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "original_id": trajectory.task_id,
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
        }
        common_strata = {
            "campaign": f"source_agent:{trajectory.source_agent}",
            "dialect": "posix",
            "domain": "data_analysis",
            "ecosystem": "linux_sandbox",
            "hard_negative": True,
            "language": "en",
            "platform": "linux",
            "split_group": group,
            "trajectory_id": trajectory_id,
        }
        for index, event in enumerate(trajectory.events):
            cases.append(
                {
                    "id": f"data-agent-sft/{trajectory_id}/action-{index:04d}",
                    "payload": {
                        "args": event["args"],
                        "command": event["command"],
                        "dialect": event["dialect"],
                        "direction": "tool_call",
                        "tool_name": event["tool_name"],
                    },
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                    "split": split,
                    "strata": {**common_strata, "call_index": index, "sequence_index": index},
                    "surface": "action",
                    "truth": truth(stateful=False),
                }
            )
            counts["action_cases"] += 1
            counts[f"action_cases_{split}"] += 1
            counts[f"cases_{split}"] += 1

        accepted_stateful = 0
        for start, current, window in bounded_windows(trajectory.events):
            fingerprint = hashlib.sha256(canonical_json(window).encode()).hexdigest()
            if fingerprint in seen_windows:
                counts["exact_payload_duplicates_removed"] += 1
                counts["exact_stateful_windows_removed"] += 1
                continue
            seen_windows.add(fingerprint)
            cases.append(
                {
                    "id": f"data-agent-sft/{trajectory_id}/current-{current:04d}",
                    "payload": {"direction": "tool_call", "events": window},
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                    "split": split,
                    "strata": {**common_strata, "call_index": current, "sequence_index": start},
                    "surface": "stateful",
                    "truth": truth(stateful=True),
                }
            )
            accepted_stateful += 1
            counts["stateful_cases"] += 1
            counts[f"stateful_cases_{split}"] += 1
            counts[f"cases_{split}"] += 1
        if not accepted_stateful:
            counts["trajectories_without_unique_stateful_window"] += 1
        counts["accepted_trajectories"] += 1
        counts["events"] += len(trajectory.events)
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    return cases, counts


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read Data Agent SFT Parquet") from exc
    source = parquet.ParquetFile(path)
    if set(source.schema_arrow.names) != REQUIRED_COLUMNS:
        raise ValueError("Data Agent SFT Parquet schema does not match the pinned source")
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
    seen_stateful_payloads: set[str] = set()
    action_positions: set[tuple[str, int]] = set()
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
        if case["source"]["revision"] != SOURCE_REVISION or case["source"]["license"] != SOURCE_LICENSE:
            raise ValueError(f"{case_id}: source identity is not pinned")
        if case["truth"].get("deterministic_truth") != "benign" or case["truth"].get("source_truth") != "benign":
            raise ValueError(f"{case_id}: this adapter may only supply benign-intent candidates")
        categories = case["truth"].get("categories", [])
        if case["surface"] == "action":
            if "structured_tool_call" not in categories or "bounded_action_sequence" in categories:
                raise ValueError(f"{case_id}: action truth categories are inconsistent")
            payload = case["payload"]
            required = {"args", "command", "dialect", "direction", "tool_name"}
            if set(payload) != required or "outcome" in payload or "offset_seconds" in payload:
                raise ValueError(f"{case_id}: atomic action payload is not exact")
            if payload["tool_name"] != "bash" or payload["dialect"] != "posix":
                raise ValueError(f"{case_id}: atomic action tool identity is invalid")
            if payload["args"] != {"command": payload["command"]}:
                raise ValueError(f"{case_id}: atomic action arguments do not match command")
            position = (case["strata"]["trajectory_id"], case["strata"]["call_index"])
            if position in action_positions:
                raise ValueError(f"{case_id}: duplicate atomic action position")
            action_positions.add(position)
        elif case["surface"] == "stateful":
            if "bounded_action_sequence" not in categories or "structured_tool_call" in categories:
                raise ValueError(f"{case_id}: stateful truth categories are inconsistent")
            events = case["payload"].get("events", [])
            if not 2 <= len(events) <= MAX_EVENTS:
                raise ValueError(f"{case_id}: sequence exceeds current plus eight predecessors")
            if [event["offset_seconds"] for event in events] != list(range(len(events))):
                raise ValueError(f"{case_id}: event order is not contiguous")
            if any("outcome" not in event for event in events):
                raise ValueError(f"{case_id}: stateful event outcome is missing")
            payload_fingerprint = hashlib.sha256(canonical_json(events).encode()).hexdigest()
            if payload_fingerprint in seen_stateful_payloads:
                raise ValueError(f"{case_id}: exact stateful payload duplicate crosses benchmark cases")
            seen_stateful_payloads.add(payload_fingerprint)
        else:
            raise ValueError(f"{case_id}: unsupported Data Agent surface")
        group = case["strata"]["split_group"]
        previous = group_splits.setdefault(group, case["split"])
        if previous != case["split"]:
            raise ValueError(f"{case_id}: task group crosses dataset splits")


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
        raise ValueError("pinned Data Agent SFT source identity mismatch")
    cases, counts = normalize(parquet_rows(args.input))
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": counts["exact_payload_duplicates_removed"],
        "label_conflicts_excluded": counts["quarantined_conflicting_task_id"],
        "output_sha256": hashlib.sha256(body).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": SOURCE_BYTES,
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "path": SOURCE_FILE,
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
