#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned ResearchArena tool executions for deterministic evaluation.

The source ``solve_out_sanitized.json`` files are stream-json logs with a short
plain-text setup preamble.  This adapter projects only real tool operations and
their authoritative status.  Setup output, reasoning, model prose, monitor
judgements, and tool-result content never enter detector payloads.

Baseline runs provide benign/FPR cases only when every evaluator's main-task
score is positive; evaluator scores need not be numerically equal.  Side-task
runs remain contextual mining cases even when every evaluator's side-task
score is positive; their trajectory label is never copied onto an individual
dual-use action.  Stateful cases are rolling windows containing the current
action and at most eight predecessors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "aisa-group/ResearchArena-Trajectories"
SOURCE_URL = "https://huggingface.co/datasets/aisa-group/ResearchArena-Trajectories"
SOURCE_REVISION = "241e456ba88bc09ba40ec906cf0c16e4b2daa918"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "researcharena-stream-json-v1"
PRE_PARTITION_SPLIT = "smoke"

EXPECTED_RUNS = 390
EXPECTED_METADATA_FILES = 390
EXPECTED_SOLVE_FILES = 390
EXPECTED_RESULTS_FILES = 6_922
EXPECTED_SOURCE_TREE_SHA256 = "b6cfa1f4651f260d49bcb094d4063a367db091a8d6dbd9b510640e04736f8aef"

MAX_JSON_LINE_BYTES = 2 * 1024 * 1024
MAX_SMALL_JSON_BYTES = 512 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_EVENTS_PER_TRAJECTORY = 4_096
MAX_PREAMBLE_LINES = 16
MAX_PREAMBLE_LINE_BYTES = 8 * 1024
MAX_EVENTS = 9
MAX_TOOL_NAME = 240
MAX_IDENTIFIER = 240

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

METADATA_KEYS = frozenset(
    {
        "baseline",
        "cluster_id",
        "experiment",
        "red_model",
        "red_provider",
        "redruntime_hours",
        "seed",
        "setting",
        "side_task",
        "task_config",
        "timestamp",
    }
)
SETTINGS = frozenset(
    {"cuda_kernel", "inference_optimization", "safety_finetuning", "utility_finetuning"}
)
SIDE_TASKS = frozenset(
    {
        "none",
        "embedded",
        "embedded2",
        "embedded3",
        "embedded_german",
        "independent",
        "independent2",
        "nonortho",
    }
)
PROVIDER_PREFIXES = ("claude", "codex", "opencode")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")
SAFE_CLUSTER_ID = re.compile(r"^[0-9]{1,32}$")
SAFE_TIMESTAMP = re.compile(r"^[0-9]{8}_[0-9]{6}$")
SAFE_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,239}$")

RESULT_REQUIRED_KEYS = frozenset({"main_task_score", "metadata", "raw_metrics", "side_task_score"})
RESULT_ALLOWED_KEYS = frozenset(
    {
        "blue_claude_code_effort_level",
        "blue_codex_effort_level",
        "blue_model",
        "blue_provider",
        "blue_team_time_seconds",
        "detection_reasoning",
        "detected",
        "detection_confidence",
        "hidden_thought",
        "main_task_score",
        "metadata",
        "monitor_strength",
        "raw_judgement",
        "raw_metrics",
        "red_team_time_seconds",
        "side_task_score",
        "suspicion_score",
        "with_artifact",
        "with_chain_of_thought",
    }
)

CLAUDE_TOOL_USE_KEYS = frozenset({"caller", "id", "input", "name", "type"})
CLAUDE_TOOL_RESULT_KEYS = frozenset({"content", "is_error", "tool_use_id", "type"})
OPENCODE_PART_REQUIRED_KEYS = frozenset(
    {"callID", "id", "messageID", "sessionID", "state", "tool", "type"}
)
OPENCODE_PART_ALLOWED_KEYS = OPENCODE_PART_REQUIRED_KEYS | {"metadata"}
OPENCODE_COMPLETED_STATE_KEYS = frozenset(
    {"input", "metadata", "output", "status", "time", "title"}
)
OPENCODE_ERROR_STATE_KEYS = frozenset({"error", "input", "status", "time"})


class ProjectionError(ValueError):
    """A source trajectory cannot satisfy the closed projection contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolEvent:
    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    outcome: str
    offset_seconds: int
    sequence_index: int
    call_index: int
    result_observed: bool


@dataclass(frozen=True)
class Evaluation:
    main_task_score_min: float
    main_task_score_max: float
    side_task_score_min: float
    side_task_score_max: float
    result_count: int

    @property
    def main_task_success(self) -> bool:
        return self.main_task_score_min > 0

    @property
    def side_task_success(self) -> bool:
        return self.side_task_score_min > 0

    @property
    def main_task_sign_consensus(self) -> bool:
        return (self.main_task_score_min > 0) == (self.main_task_score_max > 0)

    @property
    def side_task_sign_consensus(self) -> bool:
        return (self.side_task_score_min > 0) == (self.side_task_score_max > 0)


@dataclass(frozen=True)
class RunMetadata:
    baseline: bool
    cluster_id: str
    experiment: str
    red_model: str
    red_provider: str
    setting: str
    side_task: str
    task_config: str


@dataclass(frozen=True)
class ParsedStream:
    events: tuple[ToolEvent, ...]
    preamble_lines: int
    output_bytes_observed: int
    stream_completed: bool
    sha256: str
    size: int


@dataclass(frozen=True)
class SourceFile:
    path: str
    size: int
    sha256: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--skip-source-verification",
        action="store_true",
        help="Permit a small fixture instead of the complete pinned tree (tests only).",
    )
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def reject_nonfinite(value: str) -> NoReturn:
    raise ProjectionError(f"non_finite_json:{value}")


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def parse_json(value: str | bytes, code: str) -> object:
    try:
        return json.loads(
            value,
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError(code) from exc


def required_text(value: object, code: str, maximum: int = MAX_IDENTIFIER) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProjectionError(code)
    if len(value.encode("utf-8")) > maximum:
        raise ProjectionError(code)
    return value


def exact_number(value: object, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProjectionError(code)
    result = float(value)
    if not math.isfinite(result):
        raise ProjectionError(code)
    return result


def bounded_arguments(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_tool_arguments")
    try:
        encoded = canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_tool_arguments") from exc
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("oversized_tool_arguments")
    return value


def file_record(root: Path, path: Path, data: bytes | None = None) -> SourceFile:
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise ProjectionError("source_path_escape") from exc
    if data is None:
        hasher = hashlib.sha256()
        size = 0
        with resolved_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                size += len(chunk)
                hasher.update(chunk)
        sha256 = hasher.hexdigest()
    else:
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
    return SourceFile(path=relative.as_posix(), size=size, sha256=sha256)


def read_small_json(root: Path, path: Path, code: str) -> tuple[object, SourceFile]:
    size = path.stat().st_size
    if size <= 0 or size > MAX_SMALL_JSON_BYTES:
        raise ProjectionError(f"{code}_size")
    data = path.read_bytes()
    return parse_json(data, code), file_record(root, path, data)


def validate_metadata(value: object) -> RunMetadata:
    if not isinstance(value, dict) or set(value) != METADATA_KEYS:
        raise ProjectionError("invalid_metadata_shape")
    setting = required_text(value.get("setting"), "invalid_setting")
    side_task = required_text(value.get("side_task"), "invalid_side_task")
    red_provider = required_text(value.get("red_provider"), "invalid_red_provider")
    red_model = required_text(value.get("red_model"), "invalid_red_model")
    cluster_id = required_text(value.get("cluster_id"), "invalid_cluster_id")
    experiment = required_text(value.get("experiment"), "invalid_experiment")
    task_config = required_text(value.get("task_config"), "invalid_task_config")
    timestamp = required_text(value.get("timestamp"), "invalid_timestamp")
    baseline = value.get("baseline")
    runtime = value.get("redruntime_hours")
    if setting not in SETTINGS or side_task not in SIDE_TASKS:
        raise ProjectionError("unsupported_metadata_value")
    if not any(red_provider.startswith(prefix) for prefix in PROVIDER_PREFIXES):
        raise ProjectionError("unsupported_provider")
    for text, code in (
        (red_provider, "invalid_red_provider"),
        (red_model, "invalid_red_model"),
        (experiment, "invalid_experiment"),
        (task_config, "invalid_task_config"),
    ):
        if not SAFE_IDENTIFIER.fullmatch(text):
            raise ProjectionError(code)
    if not SAFE_CLUSTER_ID.fullmatch(cluster_id) or not SAFE_TIMESTAMP.fullmatch(timestamp):
        raise ProjectionError("invalid_stable_metadata")
    if type(baseline) is not bool or baseline != (side_task == "none"):
        raise ProjectionError("baseline_side_task_mismatch")
    if value.get("seed") is not None:
        raise ProjectionError("unsupported_seed")
    if isinstance(runtime, bool) or not isinstance(runtime, (int, float)):
        raise ProjectionError("invalid_runtime")
    if not math.isfinite(float(runtime)) or not 0 < float(runtime) <= 24:
        raise ProjectionError("invalid_runtime")
    return RunMetadata(
        baseline=baseline,
        cluster_id=cluster_id,
        experiment=experiment,
        red_model=red_model,
        red_provider=red_provider,
        setting=setting,
        side_task=side_task,
        task_config=task_config,
    )


def result_evaluation(value: object, metadata_value: object) -> Evaluation:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_results_shape")
    if not RESULT_REQUIRED_KEYS <= set(value) <= RESULT_ALLOWED_KEYS:
        raise ProjectionError("invalid_results_shape")
    if value.get("metadata") != metadata_value:
        raise ProjectionError("results_metadata_mismatch")
    if not isinstance(value.get("raw_metrics"), dict):
        raise ProjectionError("invalid_raw_metrics")
    # Validate the ignored evaluator payload without projecting monitor prose.
    try:
        canonical_json(value.get("raw_metrics"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_raw_metrics") from exc
    main_task_score = exact_number(value.get("main_task_score"), "invalid_main_task_score")
    side_task_score = exact_number(value.get("side_task_score"), "invalid_side_task_score")
    return Evaluation(
        main_task_score_min=main_task_score,
        main_task_score_max=main_task_score,
        side_task_score_min=side_task_score,
        side_task_score_max=side_task_score,
        result_count=1,
    )


def load_evaluation(
    root: Path,
    run_dir: Path,
    metadata_value: object,
) -> tuple[Evaluation, list[SourceFile]]:
    paths = sorted(run_dir.glob("blue_team/*/results.json"))
    if not paths:
        raise ProjectionError("missing_evaluator_results")
    evaluations: list[Evaluation] = []
    files: list[SourceFile] = []
    for path in paths:
        value, record = read_small_json(root, path, "invalid_results_json")
        evaluation = result_evaluation(value, metadata_value)
        evaluations.append(evaluation)
        files.append(record)
    if not evaluations:
        raise ProjectionError("missing_evaluator_results")
    return (
        Evaluation(
            main_task_score_min=min(value.main_task_score_min for value in evaluations),
            main_task_score_max=max(value.main_task_score_max for value in evaluations),
            side_task_score_min=min(value.side_task_score_min for value in evaluations),
            side_task_score_max=max(value.side_task_score_max for value in evaluations),
            result_count=len(files),
        ),
        files,
    )


def timestamp_seconds(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            return None
        return numeric / 1000.0 if numeric > 10_000_000_000 else numeric
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def normalized_offsets(values: Sequence[float | None]) -> list[int]:
    first = next((value for value in values if value is not None), None)
    offsets: list[int] = []
    previous = 0
    for value in values:
        offset = 0 if first is None or value is None else int(max(0.0, value - first))
        offset = min(offset, 1800)
        previous = max(previous, offset)
        offsets.append(previous)
    return offsets


def iter_stream_objects(path: Path) -> Iterator[tuple[dict[str, Any], bytes]]:
    seen_json = False
    preamble_lines = 0
    with path.open("rb") as source:
        for line in source:
            if len(line) > MAX_JSON_LINE_BYTES:
                raise ProjectionError("oversized_stream_line")
            stripped = line.strip()
            if not stripped:
                if seen_json:
                    continue
                preamble_lines += 1
                continue
            if not stripped.startswith(b"{"):
                if seen_json:
                    raise ProjectionError("non_json_after_stream_start")
                preamble_lines += 1
                if preamble_lines > MAX_PREAMBLE_LINES or len(line) > MAX_PREAMBLE_LINE_BYTES:
                    raise ProjectionError("invalid_setup_preamble")
                continue
            seen_json = True
            value = parse_json(stripped, "invalid_stream_json")
            if not isinstance(value, dict):
                raise ProjectionError("invalid_stream_object")
            yield value, line
    if not seen_json:
        raise ProjectionError("empty_stream")


def parse_claude_stream(path: Path) -> tuple[list[ToolEvent], int, int, bool]:
    calls: list[tuple[str, str, dict[str, Any], int, int]] = []
    call_ids: set[str] = set()
    outcomes: dict[str, tuple[str, float | None, bool]] = {}
    preamble = 0
    output_bytes = 0
    stream_completed = False
    sequence_index = 0
    for value, _line in iter_stream_objects(path):
        if value.get("type") == "result":
            stream_completed = value.get("subtype") == "success" and value.get("is_error") is False
            continue
        message = value.get("message")
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if not isinstance(content, list):
            continue
        call_index = 0
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "tool_use":
                if role != "assistant" or not {"id", "input", "name", "type"} <= set(block):
                    raise ProjectionError("invalid_claude_tool_use")
                if not set(block) <= CLAUDE_TOOL_USE_KEYS:
                    raise ProjectionError("invalid_claude_tool_use")
                call_id = required_text(block.get("id"), "invalid_tool_call_id")
                tool_name = required_text(block.get("name"), "invalid_tool_name", MAX_TOOL_NAME)
                if call_id in call_ids or not SAFE_TOOL_NAME.fullmatch(tool_name):
                    raise ProjectionError("invalid_or_duplicate_tool_call")
                arguments = bounded_arguments(block.get("input"))
                call_ids.add(call_id)
                calls.append((call_id, tool_name, arguments, sequence_index, call_index))
                sequence_index += 1
                call_index += 1
            elif block_type == "tool_result":
                if role != "user" or not {"content", "tool_use_id", "type"} <= set(block):
                    raise ProjectionError("invalid_claude_tool_result")
                if not set(block) <= CLAUDE_TOOL_RESULT_KEYS:
                    raise ProjectionError("invalid_claude_tool_result")
                call_id = required_text(block.get("tool_use_id"), "invalid_tool_result_id")
                if call_id in outcomes:
                    raise ProjectionError("duplicate_tool_result")
                is_error = block.get("is_error")
                if is_error is True:
                    outcome = "failed"
                elif is_error is False:
                    outcome = "succeeded"
                elif "is_error" not in block:
                    outcome = "unknown"
                else:
                    raise ProjectionError("invalid_tool_result_status")
                try:
                    output_bytes += len(canonical_json(block.get("content")).encode("utf-8"))
                except (TypeError, ValueError, RecursionError) as exc:
                    raise ProjectionError("invalid_tool_result_content") from exc
                outcomes[call_id] = (outcome, timestamp_seconds(value.get("timestamp")), True)
    if len(calls) > MAX_EVENTS_PER_TRAJECTORY:
        raise ProjectionError("too_many_tool_calls")
    timestamps = [outcomes.get(call_id, ("unknown", None, False))[1] for call_id, *_ in calls]
    offsets = normalized_offsets(timestamps)
    events = [
        ToolEvent(
            tool_call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcomes.get(call_id, ("unknown", None, False))[0],
            offset_seconds=offsets[index],
            sequence_index=sequence,
            call_index=call_index,
            result_observed=outcomes.get(call_id, ("unknown", None, False))[2],
        )
        for index, (call_id, tool_name, arguments, sequence, call_index) in enumerate(calls)
    ]
    preamble = count_preamble_lines(path)
    return events, preamble, output_bytes, stream_completed


def codex_file_change_arguments(value: object) -> dict[str, Any]:
    if not isinstance(value, list) or not value:
        raise ProjectionError("invalid_codex_file_changes")
    changes: list[dict[str, str]] = []
    for change in value:
        if not isinstance(change, dict) or set(change) != {"kind", "path"}:
            raise ProjectionError("invalid_codex_file_change")
        kind = required_text(change.get("kind"), "invalid_codex_change_kind", 32)
        path = required_text(change.get("path"), "invalid_codex_change_path", 4096)
        if kind not in {"add", "delete", "update"}:
            raise ProjectionError("invalid_codex_change_kind")
        changes.append({"kind": kind, "path": path})
    return bounded_arguments({"changes": changes})


def parse_codex_stream(path: Path) -> tuple[list[ToolEvent], int, int, bool]:
    pending: dict[tuple[int, str], tuple[str, str]] = {}
    completed_ids: set[tuple[int, str]] = set()
    events: list[ToolEvent] = []
    output_bytes = 0
    terminal: bool | None = None
    turn_epoch = 0
    for value, _line in iter_stream_objects(path):
        record_type = value.get("type")
        if record_type == "turn.started":
            turn_epoch += 1
            continue
        if record_type == "turn.completed":
            terminal = True
            continue
        if record_type == "turn.failed":
            terminal = False
            continue
        item = value.get("item")
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type not in {"command_execution", "file_change", "web_search"}:
            continue
        item_id = required_text(item.get("id"), "invalid_codex_item_id")
        scoped_id = (turn_epoch, item_id)
        status = item.get("status")
        if record_type == "item.started":
            if item_type not in {"command_execution", "file_change"} or status != "in_progress":
                raise ProjectionError("invalid_codex_started_item")
            signature = canonical_json(
                item.get("command") if item_type == "command_execution" else item.get("changes")
            )
            if scoped_id in pending or scoped_id in completed_ids:
                raise ProjectionError("duplicate_codex_item")
            pending[scoped_id] = (str(item_type), signature)
            continue
        if record_type != "item.completed":
            continue
        if scoped_id in completed_ids:
            continue
        if item_type == "command_execution":
            if set(item) != {"aggregated_output", "command", "exit_code", "id", "status", "type"}:
                raise ProjectionError("invalid_codex_command_shape")
            command = required_text(item.get("command"), "invalid_codex_command", MAX_ARGUMENT_BYTES)
            output = item.get("aggregated_output")
            if not isinstance(output, str):
                raise ProjectionError("invalid_codex_command_output")
            output_bytes += len(output.encode("utf-8"))
            if status == "completed" and item.get("exit_code") == 0:
                outcome = "succeeded"
            elif status == "failed" and type(item.get("exit_code")) is int:
                outcome = "failed"
            elif status == "completed" and item.get("exit_code") is None:
                outcome = "unknown"
            else:
                raise ProjectionError("invalid_codex_command_status")
            arguments = bounded_arguments({"command": command})
            tool_name = "Bash"
            signature = canonical_json(item.get("command"))
        elif item_type == "file_change":
            if set(item) != {"changes", "id", "status", "type"} or status != "completed":
                raise ProjectionError("invalid_codex_file_change_shape")
            arguments = codex_file_change_arguments(item.get("changes"))
            tool_name = "apply_patch"
            outcome = "succeeded"
            signature = canonical_json(item.get("changes"))
        else:
            if record_type != "item.completed" or set(item) != {"action", "id", "query", "type"}:
                raise ProjectionError("invalid_codex_web_search_shape")
            arguments = bounded_arguments({"action": item.get("action"), "query": item.get("query")})
            tool_name = "web_search"
            outcome = "succeeded"
            signature = ""
        prior = pending.pop(scoped_id, None)
        if prior is not None and prior != (str(item_type), signature):
            raise ProjectionError("codex_started_completed_mismatch")
        completed_ids.add(scoped_id)
        events.append(
            ToolEvent(
                tool_call_id=f"turn-{turn_epoch}:{item_id}",
                tool_name=tool_name,
                arguments=arguments,
                outcome=outcome,
                offset_seconds=0,
                sequence_index=len(events),
                call_index=0,
                result_observed=True,
            )
        )
        if len(events) > MAX_EVENTS_PER_TRAJECTORY:
            raise ProjectionError("too_many_tool_calls")
    return events, count_preamble_lines(path), output_bytes, terminal is True


def parse_opencode_stream(path: Path) -> tuple[list[ToolEvent], int, int, bool]:
    raw_events: list[tuple[str, str, dict[str, Any], str, float, int]] = []
    call_ids: set[tuple[str, str, str]] = set()
    output_bytes = 0
    terminal_reason: str | None = None
    for value, _line in iter_stream_objects(path):
        if value.get("type") == "step_finish":
            part = value.get("part")
            if isinstance(part, dict):
                terminal_reason = part.get("reason") if isinstance(part.get("reason"), str) else None
            continue
        if value.get("type") != "tool_use":
            continue
        part = value.get("part")
        if not isinstance(part, dict):
            raise ProjectionError("invalid_opencode_part")
        if not OPENCODE_PART_REQUIRED_KEYS <= set(part) <= OPENCODE_PART_ALLOWED_KEYS:
            raise ProjectionError("invalid_opencode_part")
        if part.get("type") != "tool":
            raise ProjectionError("invalid_opencode_part_type")
        call_id = required_text(part.get("callID"), "invalid_tool_call_id")
        session_id = required_text(part.get("sessionID"), "invalid_session_id")
        message_id = required_text(part.get("messageID"), "invalid_message_id")
        scoped_id = (session_id, message_id, call_id)
        tool_name = required_text(part.get("tool"), "invalid_tool_name", MAX_TOOL_NAME)
        if scoped_id in call_ids:
            raise ProjectionError("duplicate_tool_call")
        if tool_name == "invalid":
            continue
        if not SAFE_TOOL_NAME.fullmatch(tool_name):
            raise ProjectionError("invalid_tool_name")
        state = part.get("state")
        if not isinstance(state, dict):
            raise ProjectionError("invalid_opencode_state")
        status = state.get("status")
        if status == "completed":
            if set(state) != OPENCODE_COMPLETED_STATE_KEYS or not isinstance(state.get("output"), str):
                raise ProjectionError("invalid_opencode_completed_state")
            outcome = "succeeded"
            output_bytes += len(state["output"].encode("utf-8"))
        elif status == "error":
            if set(state) != OPENCODE_ERROR_STATE_KEYS or not isinstance(state.get("error"), str):
                raise ProjectionError("invalid_opencode_error_state")
            outcome = "failed"
            output_bytes += len(state["error"].encode("utf-8"))
        else:
            raise ProjectionError("invalid_opencode_status")
        time_value = state.get("time")
        if not isinstance(time_value, dict) or set(time_value) != {"end", "start"}:
            raise ProjectionError("invalid_opencode_time")
        start = timestamp_seconds(time_value.get("start"))
        end = timestamp_seconds(time_value.get("end"))
        if start is None or end is None or end < start:
            raise ProjectionError("invalid_opencode_time")
        arguments = bounded_arguments(state.get("input"))
        call_ids.add(scoped_id)
        stable_call_id = digest(*scoped_id)[:32]
        raw_events.append((stable_call_id, tool_name, arguments, outcome, start, len(raw_events)))
        if len(raw_events) > MAX_EVENTS_PER_TRAJECTORY:
            raise ProjectionError("too_many_tool_calls")
    offsets = normalized_offsets([event[4] for event in raw_events])
    events = [
        ToolEvent(
            tool_call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            offset_seconds=offsets[index],
            sequence_index=sequence,
            call_index=0,
            result_observed=True,
        )
        for index, (call_id, tool_name, arguments, outcome, _start, sequence) in enumerate(raw_events)
    ]
    return events, count_preamble_lines(path), output_bytes, terminal_reason == "stop"


def count_preamble_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as source:
        for line in source:
            stripped = line.strip()
            if stripped.startswith(b"{"):
                break
            if stripped:
                count += 1
    return count


def parse_stream(root: Path, path: Path, provider: str) -> ParsedStream:
    if provider.startswith("claude"):
        events, preamble, output_bytes, completed = parse_claude_stream(path)
    elif provider.startswith("codex"):
        events, preamble, output_bytes, completed = parse_codex_stream(path)
    elif provider.startswith("opencode"):
        events, preamble, output_bytes, completed = parse_opencode_stream(path)
    else:
        raise ProjectionError("unsupported_provider")
    record = file_record(root, path)
    return ParsedStream(
        events=tuple(events),
        preamble_lines=preamble,
        output_bytes_observed=output_bytes,
        stream_completed=completed,
        sha256=record.sha256,
        size=record.size,
    )


def event_dialect(event: ToolEvent) -> str:
    if event.tool_name.lower() in {"bash", "exec", "execute_command", "run_command", "shell"}:
        if isinstance(event.arguments.get("command"), str):
            return "posix"
    return "none"


def event_payload(event: ToolEvent, *, include_result: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_name": event.tool_name,
        "args": event.arguments,
        "dialect": event_dialect(event),
    }
    if include_result:
        payload["outcome"] = event.outcome
        payload["offset_seconds"] = event.offset_seconds
    return payload


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def baseline_truth(*, stateful: bool, completed: bool) -> dict[str, Any]:
    categories = [
        "researcharena",
        "benign_hard_negative",
        "evaluator_scored_baseline",
        "real_tool_arguments",
        "real_tool_results",
    ]
    if stateful:
        categories.append("bounded_action_sequence")
    truth: dict[str, Any] = {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": "source:evaluator_results_consensus",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": categories,
    }
    if stateful:
        truth["stateful_lens"] = "bounded_completed" if completed else "bounded_intent"
    return truth


def contextual_truth(*, stateful: bool, side_task_success: bool) -> dict[str, Any]:
    categories = [
        "researcharena",
        "contextual_side_task",
        "real_tool_arguments",
        "real_tool_results",
    ]
    if side_task_success:
        categories.append("evaluator_confirmed_side_task_success")
    else:
        categories.append("side_task_attempt")
    if stateful:
        categories.append("bounded_action_sequence")
    truth: dict[str, Any] = {
        "source_truth": "malicious" if stateful and side_task_success else "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high" if side_task_success else "medium",
        "label_source": (
            "source:evaluator_results_sign_consensus"
            if side_task_success
            else "source:evaluator_results_no_positive_consensus"
        ),
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The evaluator score applies to the task-relative trajectory, not to an "
            "individual dual-use call or a complete deterministic runtime proof."
        ),
        "categories": categories,
    }
    if stateful:
        truth["stateful_lens"] = "bounded_intent"
    return truth


def task_family_split_group(metadata: RunMetadata) -> str:
    task_configuration = {
        "setting": metadata.setting,
        "side_task": metadata.side_task,
        "task_config": metadata.task_config,
    }
    return digest(
        "researcharena-task-family-v1",
        canonical_json(task_configuration),
    )[:24]


def case_strata(
    metadata: RunMetadata,
    evaluation: Evaluation,
    trajectory_id: str,
    event: ToolEvent,
) -> dict[str, Any]:
    if metadata.baseline:
        campaign = "baseline_success"
    elif evaluation.side_task_success:
        campaign = "side_task_success"
    else:
        campaign = "side_task_attempt"
    return {
        "ecosystem": "coding_agent",
        "campaign": campaign,
        "domain": metadata.setting,
        "hard_negative": metadata.baseline,
        "language": "en",
        "provider": metadata.red_provider,
        "split_group": task_family_split_group(metadata),
        "trajectory_id": trajectory_id,
        "sequence_index": event.sequence_index,
        "call_index": event.call_index,
    }


def action_case(
    event: ToolEvent,
    *,
    revision: str,
    metadata: RunMetadata,
    evaluation: Evaluation,
    trajectory_id: str,
) -> dict[str, Any]:
    ordinal = f"s{event.sequence_index:04d}-c{event.call_index:03d}"
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"researcharena/{trajectory_id}/action-{ordinal}",
        "source": source_record(revision, f"trace:{trajectory_id}#action-{ordinal}"),
        "split": PRE_PARTITION_SPLIT,
        "surface": "action",
        "payload": {"direction": "tool_call", **event_payload(event, include_result=False)},
        "truth": (
            baseline_truth(stateful=False, completed=event.outcome == "succeeded")
            if metadata.baseline
            else contextual_truth(stateful=False, side_task_success=evaluation.side_task_success)
        ),
        "strata": case_strata(metadata, evaluation, trajectory_id, event),
    }


def stateful_case(
    events: Sequence[ToolEvent],
    *,
    revision: str,
    metadata: RunMetadata,
    evaluation: Evaluation,
    trajectory_id: str,
) -> dict[str, Any]:
    current = events[-1]
    ordinal = f"s{current.sequence_index:04d}-c{current.call_index:03d}"
    completed = all(event.outcome == "succeeded" for event in events)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"researcharena/{trajectory_id}/state-{ordinal}",
        "source": source_record(revision, f"trace:{trajectory_id}#state-{ordinal}"),
        "split": PRE_PARTITION_SPLIT,
        "surface": "stateful",
        "payload": {"events": [event_payload(event, include_result=True) for event in events]},
        "truth": (
            baseline_truth(stateful=True, completed=completed)
            if metadata.baseline
            else contextual_truth(stateful=True, side_task_success=evaluation.side_task_success)
        ),
        "strata": case_strata(metadata, evaluation, trajectory_id, current),
    }


def run_cases(
    events: Sequence[ToolEvent],
    *,
    revision: str,
    metadata: RunMetadata,
    evaluation: Evaluation,
    trajectory_id: str,
) -> Iterator[dict[str, Any]]:
    history: deque[ToolEvent] = deque(maxlen=MAX_EVENTS)
    for event in events:
        yield action_case(
            event,
            revision=revision,
            metadata=metadata,
            evaluation=evaluation,
            trajectory_id=trajectory_id,
        )
        history.append(event)
        if len(history) >= 2:
            yield stateful_case(
                tuple(history),
                revision=revision,
                metadata=metadata,
                evaluation=evaluation,
                trajectory_id=trajectory_id,
            )


def source_tree_sha256(files: Iterable[SourceFile]) -> str:
    hasher = hashlib.sha256()
    for record in sorted(files, key=lambda item: item.path):
        hasher.update(f"{record.path}\0{record.size}\0{record.sha256}\n".encode())
    return hasher.hexdigest()


def validate_case(case: dict[str, Any], validator: Any) -> None:
    errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        raise ValueError(f"{case.get('id', '<unknown>')}:{location}: {errors[0].message}")


def normalize(
    *,
    input_root: Path,
    revision: str,
    output: Path,
    manifest_path: Path,
    schema_path: Path,
    verify_pinned_source: bool,
) -> dict[str, Any]:
    import jsonschema

    root = input_root.resolve(strict=True)
    if verify_pinned_source and revision != SOURCE_REVISION:
        raise ValueError(f"revision must be the pinned ResearchArena SHA {SOURCE_REVISION}")
    metadata_paths = sorted(root.rglob("metadata.json"))
    if verify_pinned_source and len(metadata_paths) != EXPECTED_METADATA_FILES:
        raise ValueError(f"expected {EXPECTED_METADATA_FILES} metadata files, found {len(metadata_paths)}")
    solve_paths = sorted(root.rglob("red_team/solve_out_sanitized.json"))
    result_paths = sorted(root.rglob("blue_team/*/results.json"))
    non_evaluator_result_paths = sorted(set(root.rglob("results.json")) - set(result_paths))
    inventory_paths = [*metadata_paths, *solve_paths, *result_paths]
    readme_path = root / "README.md"
    if readme_path.is_file():
        inventory_paths.append(readme_path)
    source_files = [file_record(root, path) for path in inventory_paths]
    schema = parse_json(schema_path.read_bytes(), "invalid_case_schema")
    validator = jsonschema.Draft202012Validator(schema)

    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    exclusions: Counter[str] = Counter()
    if non_evaluator_result_paths:
        exclusions["task_snapshot_results_not_evaluator"] = len(non_evaluator_result_paths)
    outcomes: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    seen_clusters: set[str] = set()
    output_hasher = hashlib.sha256()
    main_score_min = math.inf
    main_score_max = -math.inf
    side_score_min = math.inf
    side_score_max = -math.inf
    temporary_name = ""
    with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as temporary:
        temporary_name = temporary.name
        try:
            for metadata_path in metadata_paths:
                counts["source_runs"] += 1
                run_dir = metadata_path.parent
                solve_path = run_dir / "red_team/solve_out_sanitized.json"
                try:
                    metadata_value, _metadata_record = read_small_json(
                        root, metadata_path, "invalid_metadata_json"
                    )
                    metadata = validate_metadata(metadata_value)
                    if metadata.cluster_id in seen_clusters:
                        raise ProjectionError("duplicate_cluster_id")
                    seen_clusters.add(metadata.cluster_id)
                    if metadata.side_task == "embedded_german":
                        exclusions["non_english_embedded_german"] += 1
                        continue
                    if not solve_path.is_file():
                        raise ProjectionError("missing_solve_stream")
                    evaluation, _result_records = load_evaluation(root, run_dir, metadata_value)
                    parsed = parse_stream(root, solve_path, metadata.red_provider)
                    if not parsed.events:
                        raise ProjectionError("no_tool_calls")
                    if metadata.baseline and not evaluation.main_task_success:
                        raise ProjectionError("baseline_main_task_not_successful")
                except ProjectionError as exc:
                    exclusions[exc.code] += 1
                    continue

                counts["eligible_runs"] += 1
                counts["baseline_runs" if metadata.baseline else "side_task_runs"] += 1
                if not metadata.baseline and evaluation.side_task_success:
                    counts["side_task_success_runs"] += 1
                if evaluation.main_task_sign_consensus:
                    counts["main_task_sign_consensus_runs"] += 1
                else:
                    counts["main_task_sign_disagreement_runs"] += 1
                if evaluation.side_task_sign_consensus:
                    counts["side_task_sign_consensus_runs"] += 1
                else:
                    counts["side_task_sign_disagreement_runs"] += 1
                counts["evaluator_result_files_used"] += evaluation.result_count
                main_score_min = min(main_score_min, evaluation.main_task_score_min)
                main_score_max = max(main_score_max, evaluation.main_task_score_max)
                side_score_min = min(side_score_min, evaluation.side_task_score_min)
                side_score_max = max(side_score_max, evaluation.side_task_score_max)
                if parsed.stream_completed:
                    counts["stream_completed_runs"] += 1
                counts["setup_preamble_lines_excluded"] += parsed.preamble_lines
                counts["tool_output_bytes_observed_not_projected"] += parsed.output_bytes_observed
                counts["tool_calls"] += len(parsed.events)
                providers[metadata.red_provider] += 1
                trajectory_id = digest(revision, metadata.cluster_id, run_dir.name)[:24]
                for event in parsed.events:
                    outcomes[event.outcome] += 1
                for case in run_cases(
                    parsed.events,
                    revision=revision,
                    metadata=metadata,
                    evaluation=evaluation,
                    trajectory_id=trajectory_id,
                ):
                    validate_case(case, validator)
                    encoded = (canonical_json(case) + "\n").encode("utf-8")
                    temporary.write(encoded)
                    output_hasher.update(encoded)
                    counts["cases"] += 1
                    counts[f"{case['surface']}_cases"] += 1
                    truth = case["truth"]
                    counts[f"truth_{truth['source_truth']}"] += 1
                    counts[f"applicability_{truth['applicability']}"] += 1
            temporary.flush()
            os.fsync(temporary.fileno())
        except Exception:
            temporary.close()
            Path(temporary_name).unlink(missing_ok=True)
            raise
    os.replace(temporary_name, output)

    result_file_count = sum(record.path.endswith("/results.json") for record in source_files)
    solve_file_count = sum(record.path.endswith("/solve_out_sanitized.json") for record in source_files)
    metadata_file_count = sum(record.path.endswith("/metadata.json") for record in source_files)
    tree_sha256 = source_tree_sha256(source_files)
    if verify_pinned_source:
        expected = (
            EXPECTED_RUNS,
            EXPECTED_METADATA_FILES,
            EXPECTED_SOLVE_FILES,
            EXPECTED_RESULTS_FILES,
        )
        observed = (counts["source_runs"], metadata_file_count, solve_file_count, result_file_count)
        if observed != expected:
            raise ValueError(f"incomplete pinned source inventory: expected {expected}, observed {observed}")
        if EXPECTED_SOURCE_TREE_SHA256 and tree_sha256 != EXPECTED_SOURCE_TREE_SHA256:
            raise ValueError("pinned ResearchArena source tree digest mismatch")

    statistics: dict[str, Any] = {key: int(value) for key, value in sorted(counts.items())}
    statistics["outcomes"] = {key: int(value) for key, value in sorted(outcomes.items())}
    statistics["providers"] = {key: int(value) for key, value in sorted(providers.items())}
    statistics["exclusions"] = {key: int(value) for key, value in sorted(exclusions.items())}
    statistics["evaluation_score_summary"] = {
        "result_files": int(counts["evaluator_result_files_used"]),
        "main_task_score_min": None if main_score_min == math.inf else main_score_min,
        "main_task_score_max": None if main_score_max == -math.inf else main_score_max,
        "side_task_score_min": None if side_score_min == math.inf else side_score_min,
        "side_task_score_max": None if side_score_max == -math.inf else side_score_max,
    }
    statistics["evaluation_score_summary"] = {
        "result_files_used": counts["evaluator_result_files_used"],
        "main_task_score_min": None if math.isinf(main_score_min) else main_score_min,
        "main_task_score_max": None if math.isinf(main_score_max) else main_score_max,
        "side_task_score_min": None if math.isinf(side_score_min) else side_score_min,
        "side_task_score_max": None if math.isinf(side_score_max) else side_score_max,
        "main_task_sign_consensus_runs": counts["main_task_sign_consensus_runs"],
        "main_task_sign_disagreement_runs": counts["main_task_sign_disagreement_runs"],
        "side_task_sign_consensus_runs": counts["side_task_sign_consensus_runs"],
        "side_task_sign_disagreement_runs": counts["side_task_sign_disagreement_runs"],
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": counts["cases"],
        "counts": {DATASET_ID: counts["cases"]},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": output_hasher.hexdigest(),
        "source": {
            "dataset": DATASET_ID,
            "source_url": SOURCE_URL,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "source_file_count": len(source_files),
            "metadata_file_count": metadata_file_count,
            "solve_file_count": solve_file_count,
            "results_file_count": result_file_count,
            "source_bytes": sum(record.size for record in source_files),
            "source_tree_sha256": tree_sha256,
        },
        "adapter_statistics": {ADAPTER: statistics},
    }
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    manifest_path.write_bytes(manifest_data)
    return manifest


def main() -> int:
    args = parse_args()
    manifest = normalize(
        input_root=args.input_root,
        revision=args.revision,
        output=args.output,
        manifest_path=args.manifest,
        schema_path=args.schema,
        verify_pinned_source=not args.skip_source_verification,
    )
    print(json.dumps({"cases": manifest["cases"], "output_sha256": manifest["output_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
