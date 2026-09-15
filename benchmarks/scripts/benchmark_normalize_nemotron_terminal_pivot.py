#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned Nemotron Terminal Pivot actions as benign FPR cases.

The release contains one decision point per JSONL row from trajectories that
passed an automated task verifier. ``expected_answer`` is the serialized next
Terminus action that the teacher executed. Only its concrete
``commands[].keystrokes`` tool arguments are projected. Prompt/history text,
analysis, plan, terminal output, and task-completion prose never enter detector
payloads and are never interpreted as actions.

The 1.4 GB source is processed one bounded line at a time. Stateful cases use
only a rolling window of the current action plus eight contiguous predecessors
from the same source trajectory. The release does not provide per-command
results, so stateful events honestly retain an ``unknown`` outcome even though
the complete source trajectory passed its verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1"
SOURCE_URL = "https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Terminal-Pivot-v1"
SOURCE_REVISION = "eaef26944643644c8a3dbbf361ce6128142f5976"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_PATH = "atcb_terminal_pivot_release_final_v2.jsonl"
SOURCE_BYTES = 1_372_462_504
SOURCE_SHA256 = "2d55e4f135a3722cacc3e0987f018734ad61de0824a3ea870cf18fe9ac36f482"
SOURCE_ROWS = 31_111
ADAPTER = "nemotron-terminal-pivot-v1"
PRE_PARTITION_SPLIT = "smoke"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

MAX_LINE_BYTES = 512 * 1024
MAX_ROWS = 40_000
MAX_INPUT_MESSAGES = 512
MAX_TEXT_BYTES = 480 * 1024
MAX_COMMAND_BYTES = 256 * 1024
MAX_COMMANDS_PER_TURN = 32
MAX_TRAJECTORY_TURNS = 4_096
MAX_EVENTS = 9

TOP_LEVEL_KEYS = frozenset(
    {
        "agent_ref",
        "expected_answer",
        "metadata",
        "responses_create_params",
        "schema_version",
        "task_name",
        "tool_name",
        "uuid",
    }
)
METADATA_KEYS = frozenset(
    {
        "harness",
        "pivot_agent_turn_index",
        "source_trajectory_uid",
        "teacher_model",
        "total_source_agent_turns",
    }
)
SAFE_UUID = re.compile(r"^t2_pre_rp_[0-9a-f]{32}$")
SAFE_TRAJECTORY = re.compile(r"^[0-9a-f]{16}$")
SAFE_TASK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
TEACHER_MODELS = frozenset({"zai-org/GLM-5.1", "zai-org/GLM-5.1-FP8"})


class ProjectionError(ValueError):
    """A source row cannot satisfy the closed projection contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Event:
    command: str
    duration: int | float | None
    sequence_index: int
    call_index: int


@dataclass(frozen=True)
class ProjectedRow:
    uuid: str
    task_name: str
    trajectory_uid: str
    pivot_index: int
    total_turns: int
    teacher_model: str
    events: tuple[Event, ...]
    excluded_terminal_controls: int
    completion_only: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument(
        "--split",
        choices=(PRE_PARTITION_SPLIT, "development", "validation", "test"),
        default=PRE_PARTITION_SPLIT,
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--skip-source-verification",
        action="store_true",
        help="Allow a small fixture instead of the pinned release (tests only).",
    )
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


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
        return json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError(code) from exc


def required_text(value: object, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode("utf-8")) > maximum:
        raise ProjectionError(code)
    return value


def exact_keys(value: object, expected: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ProjectionError(code)
    return value


def exact_int(value: object, code: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProjectionError(code)
    return value


def exact_duration(value: object) -> int | float:
    if type(value) not in {int, float} or not math.isfinite(float(value)) or not 0 <= float(value) <= 60:
        raise ProjectionError("invalid_command_duration")
    return value


def english_compatible(messages: object) -> bool:
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_INPUT_MESSAGES:
        return False
    latin = 0
    non_latin = 0
    user_messages = 0
    for message in messages:
        if not isinstance(message, Mapping) or set(message) != {"role", "content"}:
            return False
        role = message.get("role")
        content = message.get("content")
        if role not in {"system", "user", "assistant", "tool"} or not isinstance(content, str):
            return False
        if len(content.encode("utf-8")) > MAX_TEXT_BYTES:
            return False
        if role != "user":
            continue
        user_messages += 1
        for character in content:
            if not unicodedata.category(character).startswith("L"):
                continue
            if "LATIN" in unicodedata.name(character, ""):
                latin += 1
            else:
                non_latin += 1
    return user_messages > 0 and latin >= 20 and (non_latin <= 4 or non_latin * 50 <= latin)


def parse_expected_answer(raw: object) -> tuple[tuple[tuple[str, int | float | None], ...], bool]:
    text = required_text(raw, "invalid_expected_answer", MAX_TEXT_BYTES)
    answer = parse_json(text, "invalid_expected_answer_json")
    if not isinstance(answer, Mapping) or not {"analysis", "plan", "commands"} <= set(answer):
        raise ProjectionError("invalid_expected_answer_shape")
    if not set(answer) <= {"analysis", "plan", "commands", "task_complete"}:
        raise ProjectionError("unexpected_expected_answer_field")
    # Analysis and plan are validated as source structure, but never projected.
    required_text(answer.get("analysis"), "invalid_analysis", MAX_TEXT_BYTES)
    required_text(answer.get("plan"), "invalid_plan", MAX_TEXT_BYTES)
    commands = answer.get("commands")
    if not isinstance(commands, list) or len(commands) > MAX_COMMANDS_PER_TURN:
        raise ProjectionError("invalid_commands")
    task_complete = answer.get("task_complete", False)
    if type(task_complete) is not bool:
        raise ProjectionError("invalid_task_complete")
    projected: list[tuple[str, int | float | None]] = []
    for command in commands:
        if not isinstance(command, Mapping) or not {"keystrokes"} <= set(command) <= {"keystrokes", "duration"}:
            raise ProjectionError("invalid_command_shape")
        keystrokes = command.get("keystrokes")
        if not isinstance(keystrokes, str) or "\x00" in keystrokes:
            raise ProjectionError("invalid_command_keystrokes")
        if len(keystrokes.encode("utf-8")) > MAX_COMMAND_BYTES:
            raise ProjectionError("oversized_command")
        duration = exact_duration(command["duration"]) if "duration" in command else None
        projected.append((keystrokes, duration))
    return tuple(projected), task_complete


def project_row(row: object) -> ProjectedRow:
    value = exact_keys(row, TOP_LEVEL_KEYS, "invalid_top_level_shape")
    if value.get("schema_version") != "terminus2_pre_rp_pivot_sample_v1":
        raise ProjectionError("unsupported_source_schema")

    uuid = required_text(value.get("uuid"), "invalid_uuid", 64)
    if not SAFE_UUID.fullmatch(uuid):
        raise ProjectionError("invalid_uuid")
    task_name = required_text(value.get("task_name"), "invalid_task_name", 160)
    if not SAFE_TASK.fullmatch(task_name):
        raise ProjectionError("invalid_task_name")

    agent_ref = exact_keys(value.get("agent_ref"), frozenset({"type", "name"}), "invalid_agent_ref")
    if agent_ref != {
        "type": "responses_api_agents",
        "name": "terminus_judge_string_only_simple_agent",
    }:
        raise ProjectionError("unsupported_agent_ref")

    metadata = exact_keys(value.get("metadata"), METADATA_KEYS, "invalid_metadata")
    if metadata.get("harness") != "terminus_2":
        raise ProjectionError("unsupported_harness")
    teacher_model = required_text(metadata.get("teacher_model"), "invalid_teacher_model", 80)
    if teacher_model not in TEACHER_MODELS:
        raise ProjectionError("unsupported_teacher_model")
    trajectory_uid = required_text(metadata.get("source_trajectory_uid"), "invalid_trajectory_uid", 32)
    if not SAFE_TRAJECTORY.fullmatch(trajectory_uid):
        raise ProjectionError("invalid_trajectory_uid")
    total_turns = exact_int(
        metadata.get("total_source_agent_turns"),
        "invalid_total_turns",
        minimum=1,
        maximum=MAX_TRAJECTORY_TURNS,
    )
    pivot_index = exact_int(
        metadata.get("pivot_agent_turn_index"),
        "invalid_pivot_index",
        minimum=0,
        maximum=total_turns - 1,
    )

    request = exact_keys(value.get("responses_create_params"), frozenset({"input"}), "invalid_request")
    if not english_compatible(request.get("input")):
        raise ProjectionError("non_english_or_invalid_input")

    commands, task_complete = parse_expected_answer(value.get("expected_answer"))
    tool_name = value.get("tool_name")
    if tool_name == "mark_task_complete":
        if commands or not task_complete:
            raise ProjectionError("invalid_completion_action")
        return ProjectedRow(
            uuid, task_name, trajectory_uid, pivot_index, total_turns, teacher_model, (), 0, True
        )
    if tool_name != "bash_command" or not commands or task_complete:
        raise ProjectionError("invalid_bash_action")

    events: list[Event] = []
    for call_index, (keystrokes, duration) in enumerate(commands):
        # Empty waits and tmux-style controls are real terminal interactions but
        # are not shell actions and therefore are outside this benchmark surface.
        if not keystrokes.strip() or not keystrokes.endswith("\n"):
            continue
        events.append(
            Event(
                command=keystrokes,
                duration=duration,
                sequence_index=pivot_index * MAX_COMMANDS_PER_TURN + call_index,
                call_index=call_index,
            )
        )
    return ProjectedRow(
        uuid,
        task_name,
        trajectory_uid,
        pivot_index,
        total_turns,
        teacher_model,
        tuple(events),
        len(commands) - len(events),
        False,
    )


def event_payload(event: Event, *, include_outcome: bool, offset: int = 0) -> dict[str, Any]:
    arguments: dict[str, Any] = {"keystrokes": event.command}
    if event.duration is not None:
        arguments["duration"] = event.duration
    payload: dict[str, Any] = {
        "tool_name": "bash_command",
        "command": event.command,
        "args": arguments,
        "dialect": "posix",
    }
    if include_outcome:
        payload["outcome"] = "unknown"
        payload["offset_seconds"] = offset
    return payload


def truth(*, stateful: bool) -> dict[str, Any]:
    value: dict[str, Any] = {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": "nemotron-terminal-pivot:automated-trajectory-verifier",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": ["verifier_passing_terminal_action", "real_tool_arguments"],
    }
    if stateful:
        value["stateful_lens"] = "bounded_intent"
    return value


def strata(row: ProjectedRow, event: Event) -> dict[str, Any]:
    trajectory_id = digest("nemotron-terminal-pivot-trajectory-v1", SOURCE_REVISION, row.trajectory_uid)
    return {
        "platform": "linux",
        "dialect": "posix",
        "language": "en",
        "ecosystem": "coding_agent",
        "campaign": "atcb-verifier-passing",
        "domain": "terminal",
        "hard_negative": True,
        "split_group": digest("nemotron-terminal-pivot-task-v1", row.task_name)[:24],
        "trajectory_id": trajectory_id,
        "sequence_index": event.sequence_index,
        "call_index": event.call_index,
    }


def make_cases(row: ProjectedRow, event: Event, history: Sequence[Event], split: str) -> tuple[dict[str, Any], ...]:
    original = f"trajectory:{row.trajectory_uid}/turn:{row.pivot_index}/sample:{row.uuid}/command:{event.call_index}"
    common = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "dataset": DATASET_ID,
            "revision": SOURCE_REVISION,
            "original_id": original,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
        },
        "split": split,
        "strata": strata(row, event),
    }
    action = {
        **common,
        "id": f"nemotron-terminal-pivot/{row.uuid}/c{event.call_index}",
        "surface": "action",
        "payload": {"direction": "tool_call", **event_payload(event, include_outcome=False)},
        "truth": truth(stateful=False),
    }
    if not history:
        return (action,)
    window = [*history[-(MAX_EVENTS - 1) :], event]
    stateful = {
        **common,
        "id": f"nemotron-terminal-pivot/{row.uuid}/w{event.call_index}",
        "surface": "stateful",
        "payload": {
            "events": [event_payload(item, include_outcome=True, offset=index) for index, item in enumerate(window)]
        },
        "truth": truth(stateful=True),
    }
    return action, stateful


class StreamNormalizer:
    """Maintain only source identities and one bounded trajectory window."""

    def __init__(self, emit: Callable[[dict[str, Any]], None], *, split: str) -> None:
        self.emit = emit
        self.split = split
        self.statistics: Counter[str] = Counter()
        self.seen_uuids: set[str] = set()
        self.closed_trajectories: set[str] = set()
        self.current_trajectory: str | None = None
        self.current_task: str | None = None
        self.last_pivot = -1
        self.history: deque[Event] = deque(maxlen=MAX_EVENTS - 1)

    def consume(self, source_row: object) -> None:
        row = project_row(source_row)
        self.statistics["source_rows"] += 1
        if row.uuid in self.seen_uuids:
            raise ProjectionError("duplicate_source_uuid")
        self.seen_uuids.add(row.uuid)

        if row.trajectory_uid != self.current_trajectory:
            if self.current_trajectory is not None:
                self.closed_trajectories.add(self.current_trajectory)
            if row.trajectory_uid in self.closed_trajectories:
                raise ProjectionError("noncontiguous_trajectory")
            self.current_trajectory = row.trajectory_uid
            self.current_task = row.task_name
            self.last_pivot = -1
            self.history.clear()
            self.statistics["source_trajectories"] += 1
        elif row.task_name != self.current_task:
            raise ProjectionError("trajectory_task_mismatch")

        if row.pivot_index <= self.last_pivot:
            raise ProjectionError("nonmonotonic_pivot_index")
        if self.last_pivot >= 0 and row.pivot_index != self.last_pivot + 1:
            self.history.clear()
            self.statistics["history_resets_for_filtered_turn_gap"] += 1
        self.last_pivot = row.pivot_index

        if row.completion_only:
            self.statistics["completion_markers_excluded"] += 1
            return
        self.statistics["bash_action_rows"] += 1
        self.statistics["terminal_controls_excluded"] += row.excluded_terminal_controls
        if not row.events:
            self.statistics["rows_with_only_non_shell_terminal_controls"] += 1
            return
        for event in row.events:
            cases = make_cases(row, event, tuple(self.history), self.split)
            for case in cases:
                self.emit(case)
                self.statistics["cases"] += 1
                self.statistics[f"{case['surface']}_cases"] += 1
            self.statistics["projected_shell_actions"] += 1
            self.history.append(event)


def validate_case(case: Mapping[str, Any], validator: Any) -> None:
    errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        raise ValueError(f"{case.get('id', '<unknown>')}:{location}: {errors[0].message}")


def schema_validator(schema_path: Path = DEFAULT_SCHEMA) -> Any:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def base_manifest(statistics: Mapping[str, int], output_sha256: str) -> dict[str, Any]:
    cases = int(statistics.get("cases", 0))
    return {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": cases,
        "counts": {DATASET_ID: cases},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {ADAPTER: {key: int(value) for key, value in sorted(statistics.items())}},
        "output_sha256": output_sha256,
    }


def normalize_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    revision: str = SOURCE_REVISION,
    split: str = PRE_PARTITION_SPLIT,
    schema_path: Path = DEFAULT_SCHEMA,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"Nemotron Terminal Pivot revision must be pinned to {SOURCE_REVISION}")
    cases: list[dict[str, Any]] = []
    validator = schema_validator(schema_path)

    def emit(case: dict[str, Any]) -> None:
        validate_case(case, validator)
        cases.append(case)

    normalizer = StreamNormalizer(emit, split=split)
    for row in rows:
        normalizer.consume(row)
    output = b"".join(canonical_json(case) for case in cases)
    return cases, base_manifest(normalizer.statistics, hashlib.sha256(output).hexdigest())


def atomic_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def normalize_file(
    source: Path,
    output: Path,
    manifest_path: Path,
    *,
    revision: str = SOURCE_REVISION,
    split: str = PRE_PARTITION_SPLIT,
    schema_path: Path = DEFAULT_SCHEMA,
    verify_source: bool = True,
) -> dict[str, Any]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"Nemotron Terminal Pivot revision must be pinned to {SOURCE_REVISION}")
    if source.name != SOURCE_PATH or not source.is_file() or source.is_symlink():
        raise ValueError(f"input must be a regular {SOURCE_PATH} file")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    source_hash = hashlib.sha256()
    output_hash = hashlib.sha256()
    validator = schema_validator(schema_path)
    seen_case_ids: set[str] = set()
    source_bytes = 0
    source_rows = 0
    try:
        with os.fdopen(descriptor, "wb") as target, source.open("rb") as handle:
            def emit(case: dict[str, Any]) -> None:
                identifier = str(case["id"])
                if identifier in seen_case_ids:
                    raise ValueError(f"duplicate normalized case ID: {identifier}")
                seen_case_ids.add(identifier)
                validate_case(case, validator)
                encoded = canonical_json(case)
                target.write(encoded)
                output_hash.update(encoded)

            normalizer = StreamNormalizer(emit, split=split)
            for line_number, line in enumerate(handle, start=1):
                source_rows = line_number
                if line_number > MAX_ROWS:
                    raise ValueError("source exceeds row bound")
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError(f"source line exceeds byte bound: {line_number}")
                source_bytes += len(line)
                source_hash.update(line)
                if not line.strip():
                    raise ValueError(f"blank source line: {line_number}")
                try:
                    row = parse_json(line, "invalid_source_json")
                    normalizer.consume(row)
                except ProjectionError as exc:
                    raise ValueError(f"invalid source row {line_number}: {exc.code}") from exc
            target.flush()
            os.fsync(target.fileno())

        if verify_source and (
            source_rows != SOURCE_ROWS or source_bytes != SOURCE_BYTES or source_hash.hexdigest() != SOURCE_SHA256
        ):
            raise ValueError("pinned Nemotron Terminal Pivot source identity mismatch")
        os.replace(temporary, output)
        manifest = base_manifest(normalizer.statistics, output_hash.hexdigest())
        manifest["source"] = {
            "dataset": DATASET_ID,
            "url": SOURCE_URL,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": SOURCE_PATH,
            "rows": source_rows,
            "bytes": source_bytes,
            "sha256": source_hash.hexdigest(),
            "language": "en",
            "trajectory_verification": "release_contains_only_automated_verifier_passing_trajectories",
        }
        atomic_manifest(manifest_path, manifest)
        return manifest
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    args = parse_args()
    manifest = normalize_file(
        args.input,
        args.output,
        args.manifest,
        revision=args.revision,
        split=args.split,
        schema_path=args.schema,
        verify_source=not args.skip_source_verification,
    )
    print(json.dumps({"cases": manifest["cases"], "output_sha256": manifest["output_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
