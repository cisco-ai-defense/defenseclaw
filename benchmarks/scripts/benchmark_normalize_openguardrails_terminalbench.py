#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize a pinned OpenGuardrails Terminal-Bench 2.1 snapshot.

Only trajectories whose task intent is ordinary, English terminal work are
admitted as benign hard negatives. Security, credential-recovery,
cryptanalysis, model-extraction, secret-handling, and ambiguous tasks are
quarantined by exact task identity. A verifier reward is task-correctness
evidence only and never changes the safety label.

The two source scaffolds use different native formats. DSH call/result events
are joined only by ``callId``. Terminus ATIF steps are joined by
``tool_call_id``/``source_call_id`` when present, or by position only when an
entire adjacent step has no result IDs. Prompts, reasoning, assistant prose,
tool-result bodies, tool schemas, and credential-bearing trajectories are not
projected. Each accepted call appears once as an atomic case. Stateful cases
contain the current call and at most its eight immediate predecessors.
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
DATASET_ID = "openguardrails/terminal-bench-2.1-deepseek-v4-flash-trajectories"
SOURCE_REVISION = "3f5b93ff1c5ea84b2c94cf479d0c942227191b4a"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_TREE_FILES = 444
SOURCE_TREE_BYTES = 69_597_601
SOURCE_TREE_SHA256 = "a2631036e276ed916f3c282b9c5db84b1085d9a5e0b23e30af8da0bb29067157"
ADAPTER = "openguardrails-terminalbench-executed-benign-v1"

MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 1024 * 1024
MAX_ITEMS = 4096
MAX_DEPTH = 24

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
EXIT_CODE = re.compile(r"(?:^|\n)\[exit code: (-?[0-9]+)]\s*$")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|authorization|client[_-]?secret)"
        r"\s*(?:=|:)\s*['\"]?[^\s'\";,]{4,}"
    ),
    re.compile(r"(?i)https?://[^\s/:@]+:[^\s/@]+@"),
)

# Directory names are the immutable task identities in this snapshot. They are
# truncated by the producer, so exact values are safer than keyword matching.
QUARANTINED_TASKS = frozenset(
    {
        "break-filter-js",
        "crack-7z-hash",
        "feal-differentia",
        "feal-linear-cryp",
        "filter-js-from-h",
        "fix-code-vulnera",
        "git-leak-recover",
        "model-extraction",
        "password-recover",
        "sanitize-git-rep",
        "vulnerable-secre",
    }
)

SOURCE_PATTERNS = (
    ("README.md", 1),
    ("trajectories/dsh/*/agent/dsh-session.jsonl", 88),
    ("trajectories/dsh/*/agent/instruction.txt", 89),
    ("trajectories/dsh/*/result.json", 89),
    ("trajectories/terminus2/*/agent/trajectory.json", 88),
    ("trajectories/terminus2/*/result.json", 89),
)


class ProjectionError(ValueError):
    """A source trajectory cannot be projected without weakening evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SourceTrajectory:
    scaffold: str
    task_id: str
    instruction: str
    reward: float | None
    payload: object


@dataclass(frozen=True)
class ProjectedTrajectory:
    scaffold: str
    task_id: str
    reward: float | None
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


def decode_json(value: str, code: str) -> object:
    try:
        return json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError(code) from exc


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


def exact_arguments(value: object) -> dict[str, object]:
    if isinstance(value, str):
        decoded = decode_json(value, "invalid_arguments_json")
    else:
        decoded = value
    projected = bounded(decoded)
    if not isinstance(projected, dict):
        raise ProjectionError("arguments_not_object")
    try:
        encoded = canonical_json(projected).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_arguments") from exc
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    if contains_secret(projected):
        raise ProjectionError("credential_bearing_arguments")
    return projected


def contains_secret(value: object) -> bool:
    serialized = canonical_json(value)
    return any(pattern.search(serialized) is not None for pattern in SECRET_PATTERNS)


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ProjectionError(code)
    return value


def english_instruction(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    return bool(re.search(r"[A-Za-z]", value)) and NON_ENGLISH_SCRIPT.search(value) is None


def command_fields(tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
    event: dict[str, object] = {
        "args": dict(arguments),
        "dialect": "none",
        "tool_name": tool_name,
    }
    command: object | None = None
    if tool_name == "bash":
        command = arguments.get("command")
    elif tool_name == "bash_command":
        command = arguments.get("keystrokes")
    if command is not None:
        if not isinstance(command, str):
            raise ProjectionError("invalid_command")
        event["command"] = command
        event["dialect"] = "posix"
    return event


def result_text(item: Mapping[str, Any]) -> str | None:
    content = item.get("content")
    if not isinstance(content, list):
        return None
    texts = [part.get("text") for part in content if isinstance(part, Mapping) and part.get("type") == "text"]
    if not texts or any(not isinstance(text, str) for text in texts):
        return None
    return "\n".join(texts)


def dsh_outcome(event: Mapping[str, Any]) -> str:
    data = event.get("data")
    if not isinstance(data, Mapping):
        raise ProjectionError("invalid_dsh_result")
    if data.get("error") is not None:
        return "failed"
    message = data.get("message")
    if not isinstance(message, Mapping):
        raise ProjectionError("invalid_dsh_result")
    contents = message.get("content")
    if not isinstance(contents, list) or len(contents) != 1 or not isinstance(contents[0], Mapping):
        raise ProjectionError("invalid_dsh_result")
    item = contents[0]
    is_error = item.get("isError")
    if type(is_error) is not bool:
        raise ProjectionError("invalid_dsh_result")
    if is_error:
        return "failed"
    text = result_text(item)
    match = EXIT_CODE.search(text) if text is not None else None
    if match is None:
        return "unknown"
    return "succeeded" if int(match.group(1)) == 0 else "failed"


def project_dsh(payload: object) -> tuple[list[dict[str, Any]], Counter[str]]:
    if not isinstance(payload, list):
        raise ProjectionError("invalid_dsh_payload")
    pending: dict[str, tuple[int, str, dict[str, object]]] = {}
    completed: set[str] = set()
    events: list[tuple[int, dict[str, Any]]] = []
    counts: Counter[str] = Counter()
    sequence = 0
    for source_event in payload:
        if not isinstance(source_event, Mapping):
            raise ProjectionError("invalid_dsh_event")
        event_type = source_event.get("type")
        data = source_event.get("data")
        if event_type == "tool/call":
            if not isinstance(data, Mapping):
                raise ProjectionError("invalid_dsh_call")
            call_id = required_id(data.get("callId"), "invalid_call_id")
            if call_id in pending or call_id in completed:
                raise ProjectionError("duplicate_call_id")
            tool_name = required_id(data.get("name"), "invalid_tool_name")
            arguments = exact_arguments(data.get("arguments"))
            pending[call_id] = (sequence, tool_name, arguments)
            sequence += 1
            counts["source_tool_calls"] += 1
        elif event_type == "tool/result":
            if not isinstance(data, Mapping):
                raise ProjectionError("invalid_dsh_result")
            message = data.get("message")
            call_id: object = None
            if isinstance(message, Mapping):
                source = message.get("source")
                if isinstance(source, Mapping):
                    call_id = source.get("callId")
                content = message.get("content")
                if isinstance(content, list) and len(content) == 1 and isinstance(content[0], Mapping):
                    embedded = content[0].get("toolCallId")
                    if call_id is not None and embedded != call_id:
                        raise ProjectionError("result_call_id_mismatch")
            result_id = required_id(call_id, "invalid_result_call_id")
            if result_id not in pending:
                raise ProjectionError("orphan_result")
            index, tool_name, arguments = pending.pop(result_id)
            completed.add(result_id)
            event = command_fields(tool_name, arguments)
            event["outcome"] = dsh_outcome(source_event)
            events.append((index, event))
            counts["paired_tool_calls"] += 1
            counts[f"outcome_{event['outcome']}"] += 1
    if pending:
        raise ProjectionError("missing_result")
    events.sort(key=lambda item: item[0])
    return [event for _, event in events], counts


def terminus_outcome(result: Mapping[str, Any]) -> str:
    # ATIF result bodies in this release have no structured command exit status.
    # Their presence proves pairing, not success.
    return "unknown"


def project_terminus(payload: object) -> tuple[list[dict[str, Any]], Counter[str]]:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("steps"), list):
        raise ProjectionError("invalid_terminus_payload")
    events: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_ids: set[str] = set()
    for step in payload["steps"]:
        if not isinstance(step, Mapping):
            raise ProjectionError("invalid_terminus_step")
        calls = step.get("tool_calls") or []
        observation = step.get("observation")
        if not calls:
            continue
        if not isinstance(calls, list) or not isinstance(observation, Mapping):
            raise ProjectionError("missing_adjacent_observation")
        results = observation.get("results")
        if not isinstance(results, list) or not results:
            raise ProjectionError("unpaired_step")
        parsed_calls: list[tuple[str, str, dict[str, object]]] = []
        for call in calls:
            if not isinstance(call, Mapping):
                raise ProjectionError("invalid_terminus_call")
            call_id = required_id(call.get("tool_call_id"), "invalid_call_id")
            if call_id in seen_ids:
                raise ProjectionError("duplicate_call_id")
            seen_ids.add(call_id)
            tool_name = required_id(call.get("function_name"), "invalid_tool_name")
            arguments = exact_arguments(call.get("arguments"))
            parsed_calls.append((call_id, tool_name, arguments))
        counts["source_tool_calls"] += len(parsed_calls)

        if any(not isinstance(result, Mapping) for result in results):
            raise ProjectionError("invalid_terminus_result")
        result_ids = [result.get("source_call_id") for result in results]
        if all(result_id is None for result_id in result_ids):
            # This scaffold emits one adjacent terminal-screen observation for
            # a whole ordered keystroke block. It proves execution ordering but
            # not a separate outcome for each call.
            paired = [(call, results[0]) for call in parsed_calls]
            counts["order_joined_steps"] += 1
        elif all(isinstance(result_id, str) for result_id in result_ids):
            indexed = {
                required_id(result.get("source_call_id"), "invalid_result_call_id"): result for result in results
            }
            call_ids = {call[0] for call in parsed_calls}
            if len(indexed) != len(results) or not set(indexed).issubset(call_ids):
                raise ProjectionError("result_call_id_mismatch")
            paired = [(call, indexed[call[0]]) for call in parsed_calls if call[0] in indexed]
            counts["unpaired_calls_excluded"] += len(parsed_calls) - len(paired)
            counts["id_joined_steps"] += 1
        else:
            raise ProjectionError("mixed_result_identity")
        for (_, tool_name, arguments), result in paired:
            event = command_fields(tool_name, arguments)
            event["outcome"] = terminus_outcome(result)
            events.append(event)
            counts["paired_tool_calls"] += 1
            counts["outcome_unknown"] += 1
    return events, counts


def project_trajectory(source: SourceTrajectory) -> tuple[ProjectedTrajectory, Counter[str]]:
    if source.task_id in QUARANTINED_TASKS:
        raise ProjectionError("security_or_ambiguous_task")
    if not english_instruction(source.instruction):
        raise ProjectionError("non_english_or_invalid_task")
    if source.scaffold == "dsh":
        events, counts = project_dsh(source.payload)
    elif source.scaffold == "terminus2":
        events, counts = project_terminus(source.payload)
    else:
        raise ProjectionError("unsupported_scaffold")
    if not events:
        raise ProjectionError("no_paired_calls")
    return ProjectedTrajectory(source.scaffold, source.task_id, source.reward, tuple(events)), counts


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


CHAIN_RULE_IDS = [
    "chain.cloud_iam_principal_create_then_admin_attach_same_principal",
    "chain.download_decode_execute_same_artifact",
    "chain.download_then_execute_same_artifact",
    "chain.endpoint_security_control_request_then_completed_same_process",
    "chain.firewall_trust_expansion_then_destination_use",
    "chain.guardrails_off_then_egress",
    "chain.kubernetes_privileged_cronjob_patch_then_create_job",
    "chain.kubernetes_privileged_host_root_write_apply_exec",
    "chain.permission_denied_then_runtime_bypass",
    "chain.privilege_discovery_then_elevation",
    "chain.reverse_shell_payload_write_then_persistence_install_same_artifact",
    "chain.secret_manager_read_then_egress",
    "chain.secret_read_then_egress",
    "chain.secretsdump_then_psexec_same_target_principal",
    "chain.sensitive_egress_artifact_then_execute",
    "chain.sensitive_read_value_then_external_literal_transmit",
    "chain.sql_command_udf_create_then_invoke_same_function",
    "chain.sqlserver_xp_cmdshell_enable_then_invoke",
    "chain.wireless_capture_then_deauth_same_bssid",
    "chain.workload_identity_then_lateral_execution",
]


def truth(*, stateful: bool) -> dict[str, Any]:
    representation = "bounded_action_sequence" if stateful else "structured_tool_call"
    result = {
        "applicability": "in_scope",
        "categories": [
            "benign_candidate",
            "ordinary_terminal_task",
            "executed_container_trajectory",
            "security_tasks_quarantined",
            representation,
        ],
        "deterministic_truth": "benign",
        "expected_disposition": "allow",
        "label_confidence": "medium",
        "label_source": "source:terminalbench_ordinary_task_intent",
        "source_truth": "benign",
    }
    if stateful:
        result["stateful_lens"] = "bounded_intent"
        result["rule_ids"] = CHAIN_RULE_IDS
    return result


def normalize(sources: Iterable[SourceTrajectory]) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    projected: list[ProjectedTrajectory] = []
    fingerprints: dict[tuple[str, str], str] = {}
    conflicted: set[tuple[str, str]] = set()
    for source in sources:
        counts["source_trajectories"] += 1
        try:
            trajectory, event_counts = project_trajectory(source)
        except ProjectionError as exc:
            counts[f"quarantined_{exc.code}"] += 1
            continue
        key = (trajectory.scaffold, trajectory.task_id)
        fingerprint = hashlib.sha256(canonical_json(trajectory.events).encode()).hexdigest()
        previous = fingerprints.get(key)
        if previous is not None:
            if previous == fingerprint:
                counts["exact_trajectory_duplicates_removed"] += 1
            else:
                conflicted.add(key)
                counts["quarantined_conflicting_model_task"] += 1
            continue
        fingerprints[key] = fingerprint
        projected.append(trajectory)
        counts.update(event_counts)

    cases: list[dict[str, Any]] = []
    for trajectory in sorted(projected, key=lambda item: (item.task_id, item.scaffold)):
        if (trajectory.scaffold, trajectory.task_id) in conflicted:
            continue
        group = split_group(trajectory.task_id)
        split = split_for(group)
        original_id = f"{trajectory.task_id}/{trajectory.scaffold}"
        trajectory_id = hashlib.sha256(f"{SOURCE_REVISION}\0{original_id}".encode()).hexdigest()[:24]
        source = {
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "original_id": original_id,
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
        }
        reward_class = "missing" if trajectory.reward is None else ("positive" if trajectory.reward > 0 else "zero")
        common_strata = {
            "campaign": f"scaffold:{trajectory.scaffold}",
            "domain": "terminal_operations",
            "ecosystem": "linux_container",
            "hard_negative": True,
            "language": "en",
            "platform": "linux",
            "split_group": group,
            "trajectory_id": trajectory_id,
            "document_type": f"task_reward:{reward_class}",
        }
        for index, event in enumerate(trajectory.events):
            payload = {key: value for key, value in event.items() if key != "outcome"}
            payload["direction"] = "tool_call"
            cases.append(
                {
                    "id": f"openguardrails-terminalbench/{trajectory_id}/action-{index:04d}",
                    "payload": payload,
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                    "split": split,
                    "strata": {**common_strata, "call_index": index, "sequence_index": index},
                    "surface": "action",
                    "truth": truth(stateful=False),
                }
            )
            counts["action_cases"] += 1
            counts[f"cases_{split}"] += 1
        for start, current, window in bounded_windows(trajectory.events):
            cases.append(
                {
                    "id": f"openguardrails-terminalbench/{trajectory_id}/current-{current:04d}",
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
            counts[f"cases_{split}"] += 1
        counts["accepted_trajectories"] += 1
        counts[f"accepted_scaffold_{trajectory.scaffold}"] += 1
        counts[f"source_reward_{reward_class}"] += 1
        counts["events"] += len(trajectory.events)
    cases.sort(key=lambda case: case["id"])
    counts["cases"] = len(cases)
    return cases, counts


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def trusted_files(source_root: Path) -> list[Path]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("source root must be a regular non-symlink directory")
    root = source_root.resolve(strict=True)
    files: list[Path] = []
    for pattern, expected in SOURCE_PATTERNS:
        if "*" not in pattern:
            candidate = root / pattern
            matched = [candidate] if candidate.is_file() else []
        else:
            matched = sorted(root.glob(pattern))
        if len(matched) != expected:
            raise ValueError(f"pinned source file count mismatch for {pattern}")
        for path in matched:
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError("source path escapes trusted root") from exc
            if path.is_symlink() or not resolved.is_file() or resolved.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("source member is not an allowed regular file")
            files.append(resolved)
    files.sort(key=lambda path: path.relative_to(root).as_posix())
    return files


def source_tree_identity(source_root: Path) -> tuple[int, int, str]:
    root = source_root.resolve(strict=True)
    files = trusted_files(root)
    digest = hashlib.sha256()
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        member_hash = sha256_file(path)
        digest.update(f"{relative}\0{size}\0{member_hash}\n".encode())
        total += size
    return len(files), total, digest.hexdigest()


def verify_source_tree(source_root: Path) -> None:
    identity = source_tree_identity(source_root)
    expected = (SOURCE_TREE_FILES, SOURCE_TREE_BYTES, SOURCE_TREE_SHA256)
    if identity != expected:
        raise ValueError("pinned OpenGuardrails Terminal-Bench source identity mismatch")


def read_json_file(path: Path) -> object:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ProjectionError("source_file_too_large")
    return decode_json(path.read_text(encoding="utf-8"), "invalid_source_json")


def reward_from_result(path: Path) -> float | None:
    value = read_json_file(path)
    if not isinstance(value, Mapping):
        raise ProjectionError("invalid_result_metadata")
    verifier = value.get("verifier_result")
    rewards = verifier.get("rewards") if isinstance(verifier, Mapping) else None
    reward = rewards.get("reward") if isinstance(rewards, Mapping) else None
    if reward is None:
        return None
    if type(reward) not in {int, float} or not math.isfinite(float(reward)):
        raise ProjectionError("invalid_result_metadata")
    return float(reward)


def dsh_payload(path: Path) -> list[object]:
    events: list[object] = []
    with path.open("rb") as handle:
        for raw in handle:
            if len(raw) > MAX_LINE_BYTES:
                raise ProjectionError("source_line_too_large")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProjectionError("invalid_source_json") from exc
            if text.strip():
                events.append(decode_json(text, "invalid_source_json"))
    return events


def load_sources(source_root: Path) -> list[SourceTrajectory]:
    root = source_root.resolve(strict=True)
    sources: list[SourceTrajectory] = []
    instructions: dict[str, str] = {}
    for path in sorted(root.glob("trajectories/dsh/*/agent/instruction.txt")):
        instructions[path.parent.parent.name] = path.read_text(encoding="utf-8")
    for scaffold, filename in (("dsh", "dsh-session.jsonl"), ("terminus2", "trajectory.json")):
        pattern = f"trajectories/{scaffold}/*/agent/{filename}"
        for path in sorted(root.glob(pattern)):
            task_id = path.parent.parent.name
            instruction = instructions.get(task_id, "")
            result_path = path.parent.parent / "result.json"
            payload = dsh_payload(path) if scaffold == "dsh" else read_json_file(path)
            sources.append(SourceTrajectory(scaffold, task_id, instruction, reward_from_result(result_path), payload))
    return sources


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
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
        if case["truth"].get("deterministic_truth") != "benign":
            raise ValueError(f"{case_id}: adapter may emit only benign candidates")
        categories = case["truth"].get("categories", [])
        if case["surface"] == "action":
            if "structured_tool_call" not in categories or "outcome" in case["payload"]:
                raise ValueError(f"{case_id}: invalid atomic case")
            position = (case["strata"]["trajectory_id"], case["strata"]["call_index"])
            if position in action_positions:
                raise ValueError(f"{case_id}: duplicate atomic action position")
            action_positions.add(position)
        elif case["surface"] == "stateful":
            events = case["payload"].get("events", [])
            if "bounded_action_sequence" not in categories or not 2 <= len(events) <= MAX_EVENTS:
                raise ValueError(f"{case_id}: invalid bounded sequence")
            if [event.get("offset_seconds") for event in events] != list(range(len(events))):
                raise ValueError(f"{case_id}: invalid event order")
            if any(event.get("outcome") not in {"succeeded", "failed", "unknown"} for event in events):
                raise ValueError(f"{case_id}: invalid explicit outcome")
        else:
            raise ValueError(f"{case_id}: unsupported surface")
        group = case["strata"]["split_group"]
        previous = group_splits.setdefault(group, case["split"])
        if previous != case["split"]:
            raise ValueError(f"{case_id}: task group crosses splits")


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
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    verify_source_tree(args.source_root)
    cases, counts = normalize(load_sources(args.source_root))
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": counts["quarantined_conflicting_model_task"],
        "output_sha256": hashlib.sha256(body).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": SOURCE_TREE_BYTES,
            "dataset": DATASET_ID,
            "files": SOURCE_TREE_FILES,
            "license": SOURCE_LICENSE,
            "path": "pinned-source-tree",
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
            "sha256": SOURCE_TREE_SHA256,
        },
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, body)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
