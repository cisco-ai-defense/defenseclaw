#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize a pinned ISETrace trajectory shard as benign FPR cases.

Only assistant tool-call names and decoded structured arguments become detector
input. Tool results contribute only an explicit succeeded/failed outcome;
missing results become unknown. Messages, reasoning, final output, tool result
content, intent text, personas, and tool descriptions are never projected.

ISETrace does not publish a per-trajectory attack label, so this adapter treats
the corpus as benign execution-grounded hard negatives and never infers labels
from suspicious-looking arguments. Every row is emitted into the schema-valid
``smoke`` staging split. ``benchmark_partition.py`` remains the sole authority
for development, validation, and sealed-test assignments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "isetrace-execution-grounded-v1"
DATASET = "valiere/ISETrace"
LICENSE = "CC-BY-4.0"
REDISTRIBUTION = "download-only"
GROUPING_STRATEGY = "isetrace-intent-task-environment-component-v1"
PARTITION_AUTHORITY = "benchmarks/scripts/benchmark_partition.py"
PRE_PARTITION_SPLIT = "smoke"
DEFAULT_MAX_ARGUMENT_BYTES = 128 * 1024
DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY = 512
DEFAULT_MAX_EVENTS_PER_CASE = 64
MAX_OFFSET_SECONDS = 1800

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_ROOT = REPO_ROOT / "outputs/benchmark-data/sources/isetrace"
DEFAULT_SOURCE = DEFAULT_SOURCE_ROOT / "trajectories/trajectories-00000.jsonl"
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

HEX_24 = re.compile(r"^[0-9a-f]{24}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "datasets",
        "cases",
        "counts",
        "exact_payload_duplicates_removed",
        "label_conflicts_excluded",
        "adapter_statistics",
        "output_sha256",
    }
)
GROUP_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "grouping_strategy",
        "partition_authority",
        "group_count",
        "trajectory_count",
        "tool_call_count",
        "case_count",
        "groups",
        "corpus_sha256",
    }
)
GROUP_ENTRY_KEYS = frozenset({"group", "trajectories", "tool_calls", "cases", "action_cases", "stateful_cases"})
ROW_KEYS = frozenset(
    {
        "enable_thinking",
        "final_output",
        "intent_id",
        "messages",
        "metadata",
        "session_finalized_by_intent_id",
        "session_id",
        "source_intent_count",
        "source_intent_ids",
        "source_intents",
        "status",
        "tools",
        "total_steps",
    }
)
SOURCE_INTENT_KEYS = frozenset({"intent_id", "natural_language_intent", "task_type"})
METADATA_KEYS = frozenset({"domains", "persona"})
DOMAIN_KEYS = frozenset({"description", "name", "selected_tasks"})
TASK_KEYS = frozenset({"description", "name"})
PERSONA_KEYS = frozenset(
    {
        "communication_style",
        "experience_level",
        "expertise",
        "industry",
        "name",
        "role",
        "work_context",
    }
)
TOOL_DEFINITION_KEYS = frozenset({"function", "type"})
TOOL_FUNCTION_KEYS = frozenset({"description", "name", "parameters"})
CALL_KEYS = frozenset({"function", "id", "type"})
CALL_FUNCTION_KEYS = frozenset({"arguments", "name"})
BASE_MESSAGE_KEYS = frozenset({"content", "role"})
TOOL_MESSAGE_KEYS = frozenset({"content", "name", "role", "success", "tool_call_id"})
EXCLUDED_PAYLOAD_KEYS = frozenset(
    {
        "content",
        "final_output",
        "message",
        "messages",
        "observation",
        "output",
        "reasoning",
        "reasoning_content",
        "result",
        "thought",
    }
)


@dataclass(frozen=True)
class ProjectedCall:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    sequence_index: int
    call_index: int
    outcome: str
    argument_bytes: int


@dataclass(frozen=True)
class Trajectory:
    session_token: str
    identity_digest: str
    family_token: str
    intent_tokens: tuple[str, ...]
    calls: tuple[ProjectedCall, ...]
    orphan_results: int


class Components:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, value: str) -> str:
        self.parent.setdefault(value, value)
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while value != root:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--revision", help="must equal the pinned HF download revision")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--group-manifest", "--freeze-manifest", dest="group_manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
    parser.add_argument(
        "--max-tool-calls-per-trajectory",
        type=int,
        default=DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY,
    )
    parser.add_argument("--max-events-per-case", type=int, default=DEFAULT_MAX_EVENTS_PER_CASE)
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return (serialized + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()  # noqa: S324


def stable_digest(*parts: str) -> str:
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def strict_loads(value: str, *, field: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=strict_object,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{field} is not strict JSON") from exc


def require_exact_keys(value: object, expected: frozenset[str], *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{field} does not match its strict schema")
    return value


def required_text(value: object, *, field: str, max_length: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    result = value.strip()
    if len(result) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters")
    return result


def validate_text(value: object, *, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")


def parse_argument_object(value: object, *, max_argument_bytes: int) -> tuple[dict[str, Any], int]:
    if not isinstance(value, str):
        raise ValueError("tool-call arguments must be a JSON string")
    decoded = strict_loads(value, field="tool-call arguments")
    if not isinstance(decoded, dict):
        raise ValueError("tool-call arguments must decode to a JSON object")
    try:
        encoded = canonical_json(decoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("tool-call arguments are not bounded JSON data") from exc
    if len(encoded) > max_argument_bytes:
        raise ValueError("tool-call arguments exceed the configured byte bound")
    return decoded, len(encoded)


def validate_tool_definitions(value: object) -> set[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("tools must be a non-empty array")
    names: set[str] = set()
    for item in value:
        tool = require_exact_keys(item, TOOL_DEFINITION_KEYS, field="tool definition")
        if tool["type"] != "function":
            raise ValueError("tool definition type must be function")
        function = require_exact_keys(tool["function"], TOOL_FUNCTION_KEYS, field="tool definition function")
        name = required_text(function["name"], field="tool definition name")
        validate_text(function["description"], field="tool definition description")
        parameters = function["parameters"]
        if not isinstance(parameters, str) or not isinstance(
            strict_loads(parameters, field="tool definition parameters"), dict
        ):
            raise ValueError("tool definition parameters must encode a JSON object")
        if name in names:
            raise ValueError("duplicate tool definition name")
        names.add(name)
    return names


def task_environment_token(row: Mapping[str, Any]) -> str:
    metadata = require_exact_keys(row.get("metadata"), METADATA_KEYS, field="metadata")
    persona = require_exact_keys(metadata["persona"], PERSONA_KEYS, field="metadata persona")
    for key in PERSONA_KEYS - {"expertise"}:
        validate_text(persona[key], field=f"metadata persona {key}")
    expertise = persona["expertise"]
    if not isinstance(expertise, list) or not expertise or any(not isinstance(item, str) for item in expertise):
        raise ValueError("metadata persona expertise must be a non-empty string array")

    domains = metadata["domains"]
    if not isinstance(domains, list) or not domains:
        raise ValueError("metadata domains must be a non-empty array")
    family: list[dict[str, Any]] = []
    for item in domains:
        domain = require_exact_keys(item, DOMAIN_KEYS, field="metadata domain")
        name = required_text(domain["name"], field="metadata domain name", max_length=320)
        validate_text(domain["description"], field="metadata domain description")
        tasks = domain["selected_tasks"]
        if not isinstance(tasks, list) or not tasks:
            raise ValueError("metadata selected tasks must be a non-empty array")
        task_names: list[str] = []
        for task_value in tasks:
            task = require_exact_keys(task_value, TASK_KEYS, field="metadata selected task")
            task_names.append(required_text(task["name"], field="metadata selected task name", max_length=320))
            validate_text(task["description"], field="metadata selected task description")
        if len(task_names) != len(set(task_names)):
            raise ValueError("duplicate selected task within metadata domain")
        family.append({"domain": name, "tasks": sorted(task_names)})
    family.sort(key=lambda item: (item["domain"], item["tasks"]))
    return stable_digest(
        "isetrace-task-environment-family-v1",
        canonical_json(family).decode("utf-8"),
    )


def source_intent_tokens(row: Mapping[str, Any]) -> tuple[str, ...]:
    source_ids = row.get("source_intent_ids")
    if not isinstance(source_ids, list) or not source_ids:
        raise ValueError("source_intent_ids must be a non-empty array")
    normalized_ids = tuple(required_text(value, field="source intent identity", max_length=240) for value in source_ids)
    if len(normalized_ids) != len(set(normalized_ids)):
        raise ValueError("duplicate source intent identity")
    count = row.get("source_intent_count")
    if type(count) is not int or count != len(normalized_ids):
        raise ValueError("source_intent_count does not match source_intent_ids")

    source_intents = row.get("source_intents")
    if not isinstance(source_intents, list) or len(source_intents) != len(normalized_ids):
        raise ValueError("source_intents does not match source_intent_ids")
    expanded_ids: list[str] = []
    for item in source_intents:
        source = require_exact_keys(item, SOURCE_INTENT_KEYS, field="source intent")
        expanded_ids.append(required_text(source["intent_id"], field="expanded source intent identity"))
        validate_text(source["natural_language_intent"], field="source natural language intent")
        required_text(source["task_type"], field="source task type", max_length=240)
    if tuple(expanded_ids) != normalized_ids:
        raise ValueError("expanded source intent identities do not match source_intent_ids")

    primary = required_text(row.get("intent_id"), field="primary intent identity")
    finalized = required_text(row.get("session_finalized_by_intent_id"), field="finalizing intent identity")
    if primary != finalized or primary not in normalized_ids:
        raise ValueError("primary and finalizing intents must identify a source intent")
    return tuple(stable_digest("isetrace-source-intent-v1", value) for value in normalized_ids)


def validate_base_message(message: Mapping[str, Any], *, role: str) -> None:
    validate_text(message.get("content"), field=f"{role} message content")


def project_messages(
    value: object,
    *,
    defined_tools: set[str],
    max_argument_bytes: int,
    max_tool_calls: int,
) -> tuple[tuple[ProjectedCall, ...], int]:
    if not isinstance(value, list) or not value:
        raise ValueError("messages must be a non-empty array")
    projected: list[tuple[str, str, dict[str, Any], int, int, int]] = []
    results: dict[str, tuple[str, bool, int]] = {}
    seen_call_ids: set[str] = set()
    for message_index, raw_message in enumerate(value):
        if not isinstance(raw_message, Mapping):
            raise ValueError("message must be an object")
        role = required_text(raw_message.get("role"), field="message role", max_length=40)
        if role in {"system", "user"}:
            message = require_exact_keys(raw_message, BASE_MESSAGE_KEYS, field=f"{role} message")
            validate_base_message(message, role=role)
            continue
        if role == "tool":
            message = require_exact_keys(raw_message, TOOL_MESSAGE_KEYS, field="tool result message")
            validate_base_message(message, role=role)
            call_id = required_text(message["tool_call_id"], field="tool result call identity")
            name = required_text(message["name"], field="tool result name")
            success = message["success"]
            if not isinstance(success, bool):
                raise ValueError("tool result success must be boolean")
            if call_id in results:
                raise ValueError("duplicate tool result identity")
            results[call_id] = (name, success, message_index)
            continue
        if role != "assistant":
            raise ValueError("unsupported message role")
        allowed = set(BASE_MESSAGE_KEYS) | {"reasoning_content", "tool_calls"}
        if not set(raw_message).issubset(allowed) or not BASE_MESSAGE_KEYS.issubset(raw_message):
            raise ValueError("assistant message does not match its strict schema")
        validate_base_message(raw_message, role=role)
        if "reasoning_content" in raw_message:
            validate_text(raw_message["reasoning_content"], field="assistant reasoning content")
        calls = raw_message.get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list) or not calls:
            raise ValueError("assistant tool_calls must be a non-empty array when present")
        for call_index, raw_call in enumerate(calls):
            call = require_exact_keys(raw_call, CALL_KEYS, field="tool call")
            if call["type"] != "function":
                raise ValueError("tool call type must be function")
            call_id = required_text(call["id"], field="tool call identity")
            if call_id in seen_call_ids:
                raise ValueError("duplicate tool call identity")
            seen_call_ids.add(call_id)
            function = require_exact_keys(call["function"], CALL_FUNCTION_KEYS, field="tool call function")
            tool_name = required_text(function["name"], field="tool call name")
            if tool_name not in defined_tools:
                raise ValueError("tool call references an undefined tool")
            arguments, argument_bytes = parse_argument_object(
                function["arguments"], max_argument_bytes=max_argument_bytes
            )
            projected.append((call_id, tool_name, arguments, message_index, call_index, argument_bytes))
            if len(projected) > max_tool_calls:
                raise ValueError("trajectory exceeds the configured tool-call bound")
    if not projected:
        raise ValueError("trajectory has no tool calls")

    calls: list[ProjectedCall] = []
    for sequence_index, (
        call_id,
        tool_name,
        arguments,
        _message_index,
        call_index,
        argument_bytes,
    ) in enumerate(projected):
        result = results.get(call_id)
        if result is None:
            outcome = "unknown"
        else:
            result_name, succeeded, result_message_index = result
            if result_name != tool_name:
                raise ValueError("tool result name does not match tool call")
            if result_message_index <= _message_index:
                raise ValueError("tool result must follow its tool call")
            outcome = "succeeded" if succeeded else "failed"
        calls.append(
            ProjectedCall(
                call_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
                sequence_index=sequence_index,
                call_index=call_index,
                outcome=outcome,
                argument_bytes=argument_bytes,
            )
        )
    return tuple(calls), len(set(results) - seen_call_ids)


def project_trajectory(
    row: Mapping[str, Any],
    *,
    max_argument_bytes: int,
    max_tool_calls: int,
) -> Trajectory:
    row = require_exact_keys(row, ROW_KEYS, field="ISETrace trajectory")
    if row["status"] != "completed":
        raise ValueError("ISETrace trajectory status must be completed")
    session_id = required_text(row["session_id"], field="session identity")
    if not isinstance(row["enable_thinking"], bool):
        raise ValueError("enable_thinking must be boolean")
    validate_text(row["final_output"], field="final output")
    if type(row["total_steps"]) is not int or row["total_steps"] < 0:
        raise ValueError("total_steps must be a non-negative integer")
    intent_tokens = source_intent_tokens(row)
    family_token = task_environment_token(row)
    defined_tools = validate_tool_definitions(row["tools"])
    calls, orphan_results = project_messages(
        row["messages"],
        defined_tools=defined_tools,
        max_argument_bytes=max_argument_bytes,
        max_tool_calls=max_tool_calls,
    )
    call_identity = [
        {
            "tool_name": call.tool_name,
            "arguments": call.arguments,
            "sequence_index": call.sequence_index,
            "call_index": call.call_index,
            "outcome": call.outcome,
        }
        for call in calls
    ]
    identity_digest = stable_digest(
        "isetrace-trajectory-v1",
        session_id,
        sha256_bytes(canonical_json(call_identity)),
    )
    return Trajectory(
        session_token=stable_digest("isetrace-session-v1", session_id),
        identity_digest=identity_digest,
        family_token=family_token,
        intent_tokens=intent_tokens,
        calls=calls,
        orphan_results=orphan_results,
    )


def leakage_groups(trajectories: Sequence[Trajectory]) -> dict[str, str]:
    components = Components()
    for trajectory in trajectories:
        nodes = (f"family:{trajectory.family_token}",) + tuple(f"intent:{value}" for value in trajectory.intent_tokens)
        for node in nodes[1:]:
            components.union(nodes[0], node)
    members: dict[str, list[str]] = defaultdict(list)
    for node in sorted(components.parent):
        members[components.find(node)].append(node)
    component_digests = {
        root: stable_digest("isetrace-leakage-component-v1", *sorted(nodes)) for root, nodes in members.items()
    }
    return {
        trajectory.identity_digest: component_digests[components.find(f"family:{trajectory.family_token}")]
        for trajectory in trajectories
    }


def event_for_call(call: ProjectedCall) -> dict[str, Any]:
    event: dict[str, Any] = {
        "tool_name": call.tool_name,
        "args": call.arguments,
        "dialect": "none",
        "outcome": call.outcome,
        "offset_seconds": min(call.sequence_index, MAX_OFFSET_SECONDS),
    }
    command = call.arguments.get("command")
    if call.tool_name.casefold() == "exec" and isinstance(command, str):
        event["command"] = command
        event["dialect"] = "posix"
    return event


def benign_truth() -> dict[str, Any]:
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "medium",
        "label_source": "isetrace:published_execution_grounded_trajectory",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": [
            "agent_trajectory",
            "benign_hard_negative",
            "execution_grounded",
            "real_tool_arguments",
        ],
    }


def bounded_windows(calls: Sequence[ProjectedCall], max_events: int) -> list[Sequence[ProjectedCall]]:
    if len(calls) <= 1:
        return [calls]
    windows: list[Sequence[ProjectedCall]] = []
    start = 0
    while len(calls) - start > max_events:
        size = max_events - 1 if len(calls) - start == max_events + 1 else max_events
        windows.append(calls[start : start + size])
        start += size
    windows.append(calls[start:])
    if any(len(window) < 2 for window in windows):
        raise ValueError("stateful window construction produced a singleton")
    return windows


def make_cases(
    trajectory: Trajectory,
    *,
    group_digest: str,
    revision: str,
    max_events_per_case: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for window in bounded_windows(trajectory.calls, max_events_per_case):
        first = window[0]
        last = window[-1]
        window_id = f"calls-{first.sequence_index:04d}-{last.sequence_index:04d}"
        if len(window) == 1:
            event = event_for_call(first)
            payload: dict[str, Any] = {
                "direction": "tool_call",
                "tool_name": event["tool_name"],
                "args": event["args"],
                "dialect": event["dialect"],
            }
            if "command" in event:
                payload["command"] = event["command"]
            surface = "action"
        else:
            payload = {"direction": "tool_call", "events": [event_for_call(call) for call in window]}
            surface = "stateful"
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"isetrace/{trajectory.identity_digest[:24]}/{window_id}",
                "source": {
                    "dataset": DATASET,
                    "revision": revision,
                    "original_id": f"trajectory:{trajectory.identity_digest[:24]}/{window_id}",
                    "license": LICENSE,
                    "redistribution": REDISTRIBUTION,
                },
                "split": PRE_PARTITION_SPLIT,
                "surface": surface,
                "payload": payload,
                "truth": benign_truth(),
                "strata": {
                    "ecosystem": "os_agent",
                    "campaign": "isetrace_execution_grounded_benign",
                    "domain": "multi_domain_os_agent",
                    "hard_negative": True,
                    "split_group": group_digest[:24],
                    "trajectory_id": trajectory.identity_digest,
                    "sequence_index": first.sequence_index,
                    "call_index": first.call_index,
                },
            }
        )
    return rows


def build_corpus(
    source_rows: Iterable[Mapping[str, Any]],
    *,
    revision: str,
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
    max_tool_calls_per_trajectory: int = DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY,
    max_events_per_case: int = DEFAULT_MAX_EVENTS_PER_CASE,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if not HEX_40.fullmatch(revision):
        raise ValueError("ISETrace revision must be a lowercase 40-character commit hash")
    if max_argument_bytes <= 0:
        raise ValueError("max argument bytes must be positive")
    if not 1 <= max_tool_calls_per_trajectory <= MAX_OFFSET_SECONDS + 1:
        raise ValueError("max tool calls per trajectory must be between 1 and 1801")
    if not 2 <= max_events_per_case <= DEFAULT_MAX_EVENTS_PER_CASE:
        raise ValueError("max events per case must be between 2 and 64")

    trajectories: list[Trajectory] = []
    seen_sessions: set[str] = set()
    seen_trajectories: set[str] = set()
    for row in source_rows:
        trajectory = project_trajectory(
            row,
            max_argument_bytes=max_argument_bytes,
            max_tool_calls=max_tool_calls_per_trajectory,
        )
        if trajectory.session_token in seen_sessions:
            raise ValueError("duplicate ISETrace source session identity")
        if trajectory.identity_digest in seen_trajectories:
            raise ValueError("duplicate ISETrace trajectory identity")
        seen_sessions.add(trajectory.session_token)
        seen_trajectories.add(trajectory.identity_digest)
        trajectories.append(trajectory)
    if not trajectories:
        raise ValueError("no ISETrace trajectories were loaded")
    groups_by_trajectory = leakage_groups(trajectories)

    rows: list[dict[str, Any]] = []
    group_trajectory_counts: Counter[str] = Counter()
    group_call_counts: Counter[str] = Counter()
    group_case_counts: Counter[str] = Counter()
    group_surface_counts: dict[str, Counter[str]] = defaultdict(Counter)
    outcome_counts: Counter[str] = Counter()
    orphan_results = 0
    for trajectory in trajectories:
        group = groups_by_trajectory[trajectory.identity_digest]
        cases = make_cases(
            trajectory,
            group_digest=group,
            revision=revision,
            max_events_per_case=max_events_per_case,
        )
        rows.extend(cases)
        group_trajectory_counts[group] += 1
        group_call_counts[group] += len(trajectory.calls)
        group_case_counts[group] += len(cases)
        group_surface_counts[group].update(str(case["surface"]) for case in cases)
        outcome_counts.update(call.outcome for call in trajectory.calls)
        orphan_results += trajectory.orphan_results
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate ISETrace case IDs")

    groups = [
        {
            "group": group[:24],
            "trajectories": group_trajectory_counts[group],
            "tool_calls": group_call_counts[group],
            "cases": group_case_counts[group],
            "action_cases": group_surface_counts[group]["action"],
            "stateful_cases": group_surface_counts[group]["stateful"],
        }
        for group in sorted(group_trajectory_counts)
    ]
    output_data = b"".join(canonical_json(row) for row in rows)
    group_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "isetrace-trajectory-group-index-v1",
        "grouping_strategy": GROUPING_STRATEGY,
        "partition_authority": PARTITION_AUTHORITY,
        "group_count": len(groups),
        "trajectory_count": len(trajectories),
        "tool_call_count": sum(len(trajectory.calls) for trajectory in trajectories),
        "case_count": len(rows),
        "groups": groups,
        "corpus_sha256": sha256_bytes(output_data),
    }
    statistics = {
        "source_rows": len(trajectories),
        "trajectory_groups": len(groups),
        "tool_calls": sum(len(trajectory.calls) for trajectory in trajectories),
        "outcome_succeeded": outcome_counts["succeeded"],
        "outcome_failed": outcome_counts["failed"],
        "outcome_unknown": outcome_counts["unknown"],
        "orphan_tool_results_excluded": orphan_results,
        "action_cases": sum(1 for row in rows if row["surface"] == "action"),
        "stateful_cases": sum(1 for row in rows if row["surface"] == "stateful"),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"isetrace": statistics},
        "output_sha256": sha256_bytes(output_data),
    }
    validate_manifests(manifest, group_manifest)
    return rows, manifest, group_manifest


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = strict_loads(line, field=f"{path.name}:{line_number}")
            except ValueError as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON object") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{line_number}: expected JSON object")
            yield row


def metadata_path(source_root: Path, path: Path) -> Path:
    try:
        relative = path.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ValueError("ISETrace source files must be under source-root") from exc
    return source_root / ".cache/huggingface/download" / relative.parent / f"{relative.name}.metadata"


def metadata_identity(source_root: Path, path: Path) -> tuple[str, str]:
    metadata = metadata_path(source_root, path)
    if not metadata.is_file():
        raise ValueError(f"missing Hugging Face metadata for {path.name}")
    lines = metadata.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        raise ValueError(f"invalid Hugging Face metadata for {path.name}")
    revision = required_text(lines[0], field="Hugging Face revision", max_length=40)
    etag = required_text(lines[1], field="Hugging Face etag", max_length=64)
    if not HEX_40.fullmatch(revision) or not (HEX_40.fullmatch(etag) or HEX_64.fullmatch(etag)):
        raise ValueError(f"invalid Hugging Face metadata identity for {path.name}")
    return revision, etag


def validate_etag(path: Path, etag: str) -> None:
    actual = sha256_file(path) if len(etag) == 64 else git_blob_sha1(path)
    if actual != etag:
        raise ValueError(f"Hugging Face etag mismatch for {path.name}")


def resolve_revision(source_root: Path, source: Path, override: str | None) -> str:
    readme = source_root / "README.md"
    license_path = source_root / "LICENSE"
    for path in (source, readme, license_path):
        if not path.is_file():
            raise ValueError(f"missing required ISETrace source file: {path.name}")
    identities = {path: metadata_identity(source_root, path) for path in (source, readme, license_path)}
    revisions = {revision for revision, _etag in identities.values()}
    if len(revisions) != 1:
        raise ValueError("ISETrace source files do not resolve to one pinned revision")
    revision = next(iter(revisions))
    if override is not None and override != revision:
        raise ValueError("requested ISETrace revision differs from downloaded metadata")
    readme_text = readme.read_text(encoding="utf-8")
    license_text = license_path.read_text(encoding="utf-8")
    if not re.search(r"(?m)^license:\s*cc-by-4\.0\s*$", readme_text):
        raise ValueError("ISETrace README does not declare cc-by-4.0")
    if not re.search(
        r"Creative Commons Attribution 4\.0\s+International License \(CC BY 4\.0\)",
        license_text,
    ):
        raise ValueError("ISETrace LICENSE does not declare CC BY 4.0")
    for path, (_path_revision, etag) in identities.items():
        validate_etag(path, etag)
    return revision


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path, *, max_argument_bytes: int) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    split_by_group: dict[str, str] = {}
    for row in rows:
        case_id = str(row.get("id", ""))
        if case_id in seen_ids:
            raise ValueError("duplicate benchmark case ID")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"case schema validation failed at {location or '<root>'}")
        if row["split"] != PRE_PARTITION_SPLIT:
            raise ValueError("ISETrace cases must remain in the pre-partition staging split")
        if row["truth"]["source_truth"] != "benign" or not row["strata"]["hard_negative"]:
            raise ValueError("ISETrace cases must remain benign hard negatives")
        group = row["strata"]["split_group"]
        if group in split_by_group and split_by_group[group] != row["split"]:
            raise ValueError("ISETrace leakage group crosses benchmark splits")
        split_by_group[group] = row["split"]
        payload = row["payload"]
        if EXCLUDED_PAYLOAD_KEYS.intersection(payload):
            raise ValueError("payload contains excluded conversational or result fields")
        projected = payload.get("events")
        values = projected if isinstance(projected, list) else [payload]
        for value in values:
            if EXCLUDED_PAYLOAD_KEYS.intersection(value):
                raise ValueError("event contains excluded conversational or result fields")
            if not isinstance(value.get("args"), dict):
                raise ValueError("tool-call arguments must remain structured objects")
            if len(canonical_json(value["args"])) > max_argument_bytes:
                raise ValueError("tool-call arguments exceed the configured byte bound")
        if row["surface"] == "stateful" and not 2 <= len(values) <= 64:
            raise ValueError("stateful event count is outside the bounded schema")


def validate_manifests(manifest: object, group_manifest: object) -> None:
    manifest_map = require_exact_keys(manifest, MANIFEST_KEYS, field="normalization manifest")
    group_map = require_exact_keys(group_manifest, GROUP_MANIFEST_KEYS, field="trajectory group manifest")
    if manifest_map["schema_version"] != SCHEMA_VERSION or manifest_map["datasets"] != [DATASET]:
        raise ValueError("normalization manifest identity is invalid")
    if (
        group_map["schema_version"] != SCHEMA_VERSION
        or group_map["kind"] != "isetrace-trajectory-group-index-v1"
        or group_map["grouping_strategy"] != GROUPING_STRATEGY
        or group_map["partition_authority"] != PARTITION_AUTHORITY
    ):
        raise ValueError("trajectory group manifest identity is invalid")
    statistics = manifest_map["adapter_statistics"]
    if not isinstance(statistics, Mapping) or set(statistics) != {"isetrace"}:
        raise ValueError("normalization manifest statistics are invalid")
    if not isinstance(statistics["isetrace"], Mapping) or any(
        type(value) is not int for value in statistics["isetrace"].values()
    ):
        raise ValueError("normalization manifest statistics must be integer counters")
    if manifest_map["counts"] != {DATASET: manifest_map["cases"]}:
        raise ValueError("normalization manifest dataset counts are inconsistent")
    if not HEX_64.fullmatch(str(manifest_map["output_sha256"])):
        raise ValueError("normalization manifest output digest is invalid")

    groups = group_map["groups"]
    if not isinstance(groups, list) or len(groups) != group_map["group_count"]:
        raise ValueError("trajectory group count is invalid")
    seen_groups: set[str] = set()
    totals: Counter[str] = Counter()
    for value in groups:
        group = require_exact_keys(value, GROUP_ENTRY_KEYS, field="trajectory group entry")
        digest = str(group["group"])
        if not HEX_24.fullmatch(digest) or digest in seen_groups:
            raise ValueError("trajectory group digest is invalid or duplicated")
        seen_groups.add(digest)
        if any(type(group[key]) is not int or group[key] < 0 for key in GROUP_ENTRY_KEYS - {"group"}):
            raise ValueError("trajectory group counters are invalid")
        if group["cases"] != group["action_cases"] + group["stateful_cases"]:
            raise ValueError("trajectory group case counts are inconsistent")
        for key in ("trajectories", "tool_calls", "cases"):
            totals[key] += group[key]
    if totals["trajectories"] != group_map["trajectory_count"]:
        raise ValueError("trajectory group trajectory count is inconsistent")
    if totals["tool_calls"] != group_map["tool_call_count"]:
        raise ValueError("trajectory group tool-call count is inconsistent")
    if totals["cases"] != group_map["case_count"] or group_map["case_count"] != manifest_map["cases"]:
        raise ValueError("trajectory group case count is inconsistent")
    if group_map["corpus_sha256"] != manifest_map["output_sha256"]:
        raise ValueError("trajectory group manifest does not bind normalized corpus")


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


def write_outputs(
    rows: Sequence[dict[str, Any]],
    manifest: Mapping[str, Any],
    group_manifest: Mapping[str, Any],
    *,
    output: Path,
    manifest_path: Path,
    group_manifest_path: Path,
) -> None:
    validate_manifests(manifest, group_manifest)
    output_data = b"".join(canonical_json(row) for row in rows)
    if manifest.get("output_sha256") != sha256_bytes(output_data):
        raise ValueError("normalization manifest does not bind output bytes")
    if group_manifest.get("corpus_sha256") != sha256_bytes(output_data):
        raise ValueError("trajectory group manifest does not bind output bytes")
    atomic_write(output, output_data)
    atomic_write(manifest_path, canonical_json(manifest))
    atomic_write(group_manifest_path, canonical_json(group_manifest))


def main() -> int:
    args = parse_args()
    revision = resolve_revision(args.source_root, args.source, args.revision)
    rows, manifest, group_manifest = build_corpus(
        jsonl_rows(args.source),
        revision=revision,
        max_argument_bytes=args.max_argument_bytes,
        max_tool_calls_per_trajectory=args.max_tool_calls_per_trajectory,
        max_events_per_case=args.max_events_per_case,
    )
    validate_cases(rows, args.schema, max_argument_bytes=args.max_argument_bytes)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    group_manifest_path = args.group_manifest or args.output.with_suffix(".groups.json")
    write_outputs(
        rows,
        manifest,
        group_manifest,
        output=args.output,
        manifest_path=manifest_path,
        group_manifest_path=group_manifest_path,
    )
    print(
        json.dumps(
            {
                "cases": manifest["cases"],
                "tool_calls": group_manifest["tool_call_count"],
                "trajectory_groups": group_manifest["group_count"],
                "pre_partition_split": PRE_PARTITION_SPLIT,
                "partition_authority": PARTITION_AUTHORITY,
                "output_sha256": manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
