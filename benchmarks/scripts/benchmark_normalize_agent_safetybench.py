#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned public Agent-SafetyBench release conservatively.

Agent-SafetyBench labels risky *test cases* and whether each instruction can be
completed safely.  Those labels do not establish that a recorded tool call is
malicious, that the call succeeded, or that a harmful objective was completed.
Consequently, every emitted case is contextual/out-of-scope.  In particular,
this adapter deliberately contributes zero deterministic malicious positives.

Only exact native function names and parsed structured arguments are retained.
Calls and results are joined by their native IDs, but result bodies, prompts,
assistant prose/reasoning, environment parameters, and tool schemas are never
copied.  The source exposes no explicit execution status, so joined calls have
an ``unknown`` outcome in stateful windows.  Arguments with credential or PII
indicators are quarantined instead of redacted so accepted arguments remain
exact.  Stateful cases contain the current event and at most eight immediate
predecessors; the pinned release currently has no multi-call dialogs, so its
full normalization emits atomic cases but zero stateful cases.
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
from urllib.parse import parse_qsl, urlsplit

SCHEMA_VERSION = "1"
DATASET_ID = "thu-coai/Agent-SafetyBench"
SOURCE_URL = "https://huggingface.co/datasets/thu-coai/Agent-SafetyBench"
SOURCE_REVISION = "3c60d5aa0af6a5c817b4ea4856e72f252e283bb7"
SOURCE_FILE = "released_data.json"
SOURCE_SHA256 = "59dd0333001ef767766d803e97086ec02af0fbf7ff1f7070b3797863b0dacbe2"
SOURCE_BYTES = 2_876_562
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "agent-safetybench-contextual-tool-calls-v1"

MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_ROWS = 10_000
MAX_MESSAGES = 128
MAX_CALLS_PER_MESSAGE = 64
MAX_ARGUMENT_BYTES = 256 * 1024
MAX_VALUE_BYTES = 64 * 1024
MAX_ITEMS = 2048
MAX_DEPTH = 20
MAX_SOURCE_BYTES = 16 * 1024 * 1024

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,239}$")
FAILURE_MODES = re.compile(r"^(?:10|[1-9])(?:,(?:10|[1-9]))*$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:access[_-]?key|api[_-]?key|auth(?:orization)?|cookie|credential|"
    r"credit[_-]?card|email|pass(?:word|wd)?|phone|private[_-]?key|secret|session[_-]?id|"
    r"ssn|token)(?:$|[_-])",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|authorization|bearer|cookie|credential|password|private[_-]?key|"
    r"secret|token)\s*[:=]\s*[^\s,;]{4,}"
)
EMAIL_ADDRESS = re.compile(r"(?i)(?<![\w.+-])[\w.+-]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}(?![\w.-])")
PRIVATE_KEY_MARKER = re.compile(r"-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}")
SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[^/]*)?|\.aws/credentials|\.ssh/(?:id_[^/]+|authorized_keys)|"
    r"etc/(?:shadow|gshadow)|keychain[^/]*|secrets?\.(?:json|ya?ml)|credentials?\.(?:json|ya?ml))(?:$|/)"
)
HOME_IDENTITY = re.compile(r"/(?:Users|home)/(?!(?:runner|sandbox|user|workspace)(?:/|$))[^/\s]+(?:/|$)")
SENSITIVE_QUERY_KEY = re.compile(
    r"(?i)^(?:access[_-]?key|api[_-]?key|auth|authorization|code|credential|password|secret|token)$"
)

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
    risk: str
    failure_modes: str
    fulfillable: bool
    ecosystem: str
    events: tuple[dict[str, Any], ...]
    call_ids: tuple[str, ...]


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


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def bounded(value: object, *, depth: int = 0) -> object:
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
        return [bounded(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_arguments")
        return {key: bounded(item, depth=depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def required_id(value: object, code: str) -> str:
    if type(value) is int and value >= 0:
        return str(value)
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def required_tool(value: object, code: str = "invalid_tool_name") -> str:
    if not isinstance(value, str) or SAFE_TOOL.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def english_compatible(value: object) -> bool:
    if not isinstance(value, str) or not re.search(r"[A-Za-z]", value):
        return False
    return NON_ENGLISH_SCRIPT.search(value) is None


def luhn_candidate(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        number = int(character)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        checksum += number
    return checksum % 10 == 0


def string_is_sensitive(value: str) -> bool:
    if SECRET_ASSIGNMENT.search(value) or EMAIL_ADDRESS.search(value) or PRIVATE_KEY_MARKER.search(value):
        return True
    if SENSITIVE_PATH.search(value) or HOME_IDENTITY.search(value):
        return True
    for token in re.findall(r"(?<!\d)[0-9][0-9 -]{11,25}[0-9](?!\d)", value):
        if luhn_candidate(token):
            return True
    try:
        parsed = urlsplit(value)
    except ValueError:
        return True
    if parsed.scheme and parsed.netloc:
        if parsed.username or parsed.password:
            return True
        if any(SENSITIVE_QUERY_KEY.fullmatch(key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
            return True
    return False


def contains_sensitive(value: object, *, key: str = "") -> bool:
    if key and SENSITIVE_KEY.search(key):
        return True
    if isinstance(value, str):
        return string_is_sensitive(value)
    if isinstance(value, list):
        return any(contains_sensitive(item) for item in value)
    if isinstance(value, dict):
        return any(contains_sensitive(item, key=name) for name, item in value.items())
    return False


def parse_arguments(value: object) -> dict[str, object]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_arguments_json")
    try:
        decoded = json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError("invalid_arguments_json") from exc
    projected = bounded(decoded)
    if not isinstance(projected, dict):
        raise ProjectionError("arguments_not_object")
    if len(canonical_json(projected).encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    if contains_sensitive(projected):
        raise ProjectionError("credential_or_pii_argument")
    return projected


def environment_tools(value: object) -> tuple[frozenset[str], str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ITEMS:
        raise ProjectionError("invalid_environments")
    names: set[str] = set()
    environments: list[str] = []
    for environment in value:
        if not isinstance(environment, Mapping) or set(environment) != {"name", "parameters", "tools"}:
            raise ProjectionError("invalid_environment")
        name = required_tool(environment.get("name"), "invalid_environment_name")
        if not isinstance(environment.get("parameters"), Mapping):
            raise ProjectionError("invalid_environment_parameters")
        tools = environment.get("tools")
        if not isinstance(tools, list) or len(tools) > MAX_ITEMS:
            raise ProjectionError("invalid_environment_tools")
        for tool in tools:
            tool_name = required_tool(tool)
            if tool_name in names:
                raise ProjectionError("duplicate_environment_tool")
            names.add(tool_name)
        environments.append(name)
    if not names:
        raise ProjectionError("no_environment_tools")
    return frozenset(names), "+".join(sorted(environments))[:80]


def project_dialog(value: object, available: frozenset[str]) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MESSAGES:
        raise ProjectionError("invalid_dialog")
    pending: dict[str, tuple[int, str, dict[str, object]]] = {}
    completed: set[str] = set()
    projected: list[tuple[int, dict[str, Any], str]] = []
    call_index = 0
    saw_user = False
    for message in value:
        if not isinstance(message, Mapping):
            raise ProjectionError("invalid_dialog_message")
        role = message.get("role")
        if role == "user":
            if set(message) != {"role", "content"} or not isinstance(message.get("content"), str):
                raise ProjectionError("invalid_user_message")
            if pending:
                raise ProjectionError("interrupted_call_result_block")
            saw_user = True
            continue
        if role == "assistant":
            if set(message) != {"role", "tool_calls"} or pending:
                raise ProjectionError("invalid_assistant_message")
            calls = message.get("tool_calls")
            if not isinstance(calls, list) or not 1 <= len(calls) <= MAX_CALLS_PER_MESSAGE:
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
                    raise ProjectionError("invalid_tool_function")
                tool_name = required_tool(function.get("name"))
                if tool_name not in available:
                    raise ProjectionError("unknown_environment_tool")
                pending[call_id] = (call_index, tool_name, parse_arguments(function.get("arguments")))
                call_index += 1
            continue
        if role != "tool" or set(message) != {"role", "content", "tool_call_id", "name"}:
            raise ProjectionError("invalid_tool_result")
        call_id = required_id(message.get("tool_call_id"), "invalid_tool_result_id")
        if call_id not in pending:
            raise ProjectionError("orphan_tool_result")
        index, tool_name, arguments = pending.pop(call_id)
        if message.get("name") != tool_name or not isinstance(message.get("content"), str):
            raise ProjectionError("tool_result_mismatch")
        completed.add(call_id)
        projected.append(
            (
                index,
                {
                    "args": arguments,
                    "offset_seconds": index,
                    "outcome": "unknown",
                    "tool_name": tool_name,
                },
                call_id,
            )
        )
    if pending:
        raise ProjectionError("missing_tool_result")
    if not saw_user or not projected:
        raise ProjectionError("refusal_or_no_executed_call")
    projected.sort(key=lambda item: item[0])
    return [item[1] for item in projected], tuple(item[2] for item in projected)


def project_row(row: Mapping[str, Any]) -> ProjectedTrajectory:
    expected = {"id", "risks", "instruction", "environments", "failure_modes", "fulfillable", "dialog"}
    if set(row) != expected:
        raise ProjectionError("no_dialog" if set(row) == expected - {"dialog"} else "invalid_row_shape")
    task_id = required_id(row.get("id"), "invalid_task_id")
    instruction = row.get("instruction")
    if not english_compatible(instruction):
        raise ProjectionError("non_english")
    risks = row.get("risks")
    if not isinstance(risks, list) or len(risks) != 1 or not isinstance(risks[0], str) or not risks[0]:
        raise ProjectionError("invalid_risk_label")
    failure_modes = row.get("failure_modes")
    if not isinstance(failure_modes, str) or FAILURE_MODES.fullmatch(failure_modes) is None:
        raise ProjectionError("invalid_failure_modes")
    fulfillable = row.get("fulfillable")
    if type(fulfillable) is not int or fulfillable not in {0, 1}:
        raise ProjectionError("invalid_fulfillable")
    tools, ecosystem = environment_tools(row.get("environments"))
    events, call_ids = project_dialog(row.get("dialog"), tools)
    return ProjectedTrajectory(
        task_id=task_id,
        risk=risks[0],
        failure_modes=failure_modes,
        fulfillable=bool(fulfillable),
        ecosystem=ecosystem,
        events=tuple(events),
        call_ids=call_ids,
    )


def split_group(task_id: str) -> str:
    return digest(DATASET_ID, task_id)[:24]


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
        "applicability": "out_of_scope",
        "categories": [
            "agent_safetybench",
            "risky_task_context",
            representation,
            "proof_pending",
        ],
        "deterministic_truth": "contextual_or_dual_use",
        "exclusion_reason": (
            "Agent-SafetyBench labels risky task intent and safe fulfillability, not whether this exact "
            "call or bounded window is malicious, successful, or sufficient to complete harm."
        ),
        "expected_disposition": "detect_only",
        "label_confidence": "high",
        "label_source": "source:agent_safetybench_task_label_not_call_truth",
        "source_truth": "unknown",
    }


def bounded_windows(events: Sequence[dict[str, Any]]) -> Iterable[tuple[int, int, list[dict[str, Any]]]]:
    for current in range(1, len(events)):
        start = max(0, current - MAX_PREDECESSORS)
        window = [dict(event, offset_seconds=index) for index, event in enumerate(events[start : current + 1])]
        yield start, current, window


def normalize(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    trajectories: list[ProjectedTrajectory] = []
    seen_tasks: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        if counts["source_rows"] > MAX_ROWS:
            raise ValueError("Agent-SafetyBench source exceeds the row bound")
        if not isinstance(row, Mapping):
            counts["quarantined_invalid_row"] += 1
            continue
        try:
            trajectory = project_row(row)
        except ProjectionError as exc:
            counts[f"quarantined_{exc.code}"] += 1
            continue
        if trajectory.task_id in seen_tasks:
            counts["quarantined_duplicate_task_id"] += 1
            continue
        seen_tasks.add(trajectory.task_id)
        trajectories.append(trajectory)

    cases: list[dict[str, Any]] = []
    for trajectory in sorted(trajectories, key=lambda item: item.task_id):
        group = split_group(trajectory.task_id)
        split = split_for(group)
        trajectory_id = digest(SOURCE_REVISION, trajectory.task_id)[:24]
        common_strata = {
            "campaign": f"failure_modes:{trajectory.failure_modes}",
            "domain": trajectory.risk[:160],
            "ecosystem": trajectory.ecosystem,
            "hard_negative": False,
            "language": "en",
            "split_group": group,
            "trajectory_id": trajectory_id,
        }
        for index, event in enumerate(trajectory.events):
            call_id = trajectory.call_ids[index]
            source = {
                "dataset": DATASET_ID,
                "license": SOURCE_LICENSE,
                "original_id": f"task:{trajectory.task_id}/call:{call_id}"[:240],
                "redistribution": SOURCE_REDISTRIBUTION,
                "revision": SOURCE_REVISION,
            }
            cases.append(
                {
                    "id": f"agent-safetybench/{trajectory_id}/action-{index:03d}-{digest(call_id)[:12]}",
                    "payload": {
                        "args": event["args"],
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

        for start, current, window in bounded_windows(trajectory.events):
            current_id = trajectory.call_ids[current]
            source = {
                "dataset": DATASET_ID,
                "license": SOURCE_LICENSE,
                "original_id": f"task:{trajectory.task_id}/current:{current_id}"[:240],
                "redistribution": SOURCE_REDISTRIBUTION,
                "revision": SOURCE_REVISION,
            }
            cases.append(
                {
                    "id": f"agent-safetybench/{trajectory_id}/current-{current:03d}-{digest(current_id)[:12]}",
                    "payload": {"direction": "tool_call", "events": window},
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                    "split": split,
                    "strata": {**common_strata, "call_index": current, "sequence_index": start},
                    "surface": "stateful",
                    "truth": truth(stateful=True),
                }
            )
            counts["stateful_cases"] += 1
            counts[f"stateful_cases_{split}"] += 1
        counts["accepted_trajectories"] += 1
        counts["events"] += len(trajectory.events)
        counts[f"accepted_fulfillable_{int(trajectory.fulfillable)}"] += 1
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    counts["deterministic_positive_cases"] = 0
    counts["out_of_scope_cases"] = len(cases)
    return cases, counts


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("input must be a bounded regular non-symlink file")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ValueError("invalid Agent-SafetyBench JSON") from exc
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise ValueError("Agent-SafetyBench source must be a bounded array")
    return value


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    group_splits: dict[str, str] = {}
    action_positions: set[tuple[str, int]] = set()
    for case in cases:
        case_id = str(case.get("id", ""))
        if case_id in seen_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
            raise ValueError(f"{case_id}:{location}: {errors[0].message}")
        truth_value = case["truth"]
        if (
            truth_value.get("applicability") != "out_of_scope"
            or truth_value.get("deterministic_truth") != "contextual_or_dual_use"
            or truth_value.get("source_truth") != "unknown"
        ):
            raise ValueError(f"{case_id}: source task labels must not become deterministic call labels")
        if case["source"]["revision"] != SOURCE_REVISION or case["source"]["license"] != SOURCE_LICENSE:
            raise ValueError(f"{case_id}: source identity is not pinned")
        if contains_sensitive(case["payload"]):
            raise ValueError(f"{case_id}: projected payload contains credential or PII indicators")
        if case["surface"] == "action":
            if set(case["payload"]) != {"args", "direction", "tool_name"}:
                raise ValueError(f"{case_id}: atomic payload shape is not exact")
            position = (case["strata"]["trajectory_id"], case["strata"]["call_index"])
            if position in action_positions:
                raise ValueError(f"{case_id}: duplicate atomic action position")
            action_positions.add(position)
        elif case["surface"] == "stateful":
            events = case["payload"].get("events", [])
            if not 2 <= len(events) <= MAX_EVENTS:
                raise ValueError(f"{case_id}: stateful window is outside current-plus-eight bound")
            if [event.get("offset_seconds") for event in events] != list(range(len(events))):
                raise ValueError(f"{case_id}: stateful event order is not contiguous")
            if any(event.get("outcome") != "unknown" for event in events):
                raise ValueError(f"{case_id}: source does not support inferred execution outcomes")
        else:
            raise ValueError(f"{case_id}: unsupported surface")
        group = case["strata"]["split_group"]
        prior = group_splits.setdefault(group, case["split"])
        if prior != case["split"]:
            raise ValueError(f"{case_id}: task group crosses deterministic splits")


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
    parser.add_argument("--revision", default=SOURCE_REVISION)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned Agent-SafetyBench revision {SOURCE_REVISION}")
    if not args.input.is_file() or args.input.is_symlink():
        raise ValueError("input must be a regular non-symlink file")
    if args.input.stat().st_size != SOURCE_BYTES or sha256_file(args.input) != SOURCE_SHA256:
        raise ValueError("pinned Agent-SafetyBench source identity mismatch")
    cases, counts = normalize(load_rows(args.input))
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
