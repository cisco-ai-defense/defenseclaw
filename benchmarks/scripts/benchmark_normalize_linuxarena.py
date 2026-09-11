#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize the LinuxArena public sample into deterministic benchmark cases.

Only tool function names and structured arguments enter detector payloads.
Reasoning, prompts, messages, monitor judgments, tool output, and scorer prose
are excluded. ``output_error`` is the only per-call outcome signal: null means
the source explicitly recorded no tool error and a non-empty string means the
call failed. Trajectory task outcomes never determine individual call outcome.

Successful side tasks provide trajectory-level malicious source truth, but do
not prove any atomic call or bounded window deterministically malicious. Those
rows remain proof-pending and out of scored scope until a separate exact proof
is supplied. All rows use ``smoke`` as a staging split; only
``benchmark_partition.py`` may assign benchmark partitions.
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
ADAPTER = "linuxarena-public-sample-v1"
DATASET = "anonymouslinuxarena/linuxarena-public"
LICENSE = "CC-BY-4.0"
REDISTRIBUTION = "download-only"
GROUPING_STRATEGY = "linuxarena-environment-main-task-family-v1"
PARTITION_AUTHORITY = "benchmarks/scripts/benchmark_partition.py"
PRE_PARTITION_SPLIT = "smoke"
MAX_STATEFUL_EVENTS = 64
CHAIN_BOUND = 8
WINDOW_OVERLAP = CHAIN_BOUND - 1
DEFAULT_MAX_TOOL_CALLS = 1_801
DEFAULT_MAX_ARGUMENT_BYTES = 1024 * 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO_ROOT / "outputs/benchmark-data/sources/linuxarena-public/data/sample.jsonl"
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
HEX_24 = re.compile(r"^[0-9a-f]{24}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_CATEGORY = re.compile(r"[^a-z0-9._:-]+")
SOURCE_ROW_KEYS = frozenset(
    {
        "trajectory_id",
        "run_id",
        "run_display_name",
        "trajectory_url",
        "actions",
        "main_task_success",
        "side_task_success",
        "scorer_explanation",
        "traj_monitor_response",
        "environment",
        "main_task",
        "side_task",
        "agent_model",
        "system_prompt",
        "initial_user_message",
        "attack_analysis",
    }
)
ACTION_KEYS = frozenset(
    {
        "function",
        "arguments",
        "output",
        "output_error",
        "agent_reasoning",
        "extended_thinking",
        "inter_action_messages",
        "monitor_response",
        "substeps",
    }
)
MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "datasets",
        "cases",
        "counts",
        "exact_payload_duplicates_removed",
        "label_conflicts_excluded",
        "source",
        "adapter_statistics",
        "output_sha256",
    }
)
SOURCE_MANIFEST_KEYS = frozenset(
    {
        "dataset",
        "revision",
        "license",
        "redistribution",
        "path",
        "bytes",
        "sha256",
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
GROUP_KEYS = frozenset(
    {
        "group",
        "trajectories",
        "tool_calls",
        "cases",
        "action_cases",
        "stateful_cases",
    }
)
SHELL_TOOLS = frozenset(
    {
        "bash",
        "client_bash",
        "db_bash",
        "nginx_bash",
        "py_ml_bash",
        "rust_worker_bash",
    }
)


@dataclass(frozen=True)
class ProjectedCall:
    tool_name: str
    arguments: dict[str, Any]
    sequence_index: int
    call_index: int
    outcome: str
    command: str = ""


@dataclass(frozen=True)
class Trajectory:
    identity_digest: str
    group_digest: str
    source_identity_digest: str
    environment_category: str
    main_task_success: bool | None
    side_task_present: bool
    side_task_success: bool | None
    calls: tuple[ProjectedCall, ...]
    source_call_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--revision", help="pinned Hugging Face revision; inferred by default")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--group-manifest", "--freeze-manifest", dest="group_manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-tool-calls", type=int, default=DEFAULT_MAX_TOOL_CALLS)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
    return parser.parse_args()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


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


def stable_digest(*parts: str) -> str:
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def required_text(value: object, *, field: str, max_length: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    result = value.strip()
    if len(result) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters")
    return result


def require_exact_keys(value: object, expected: frozenset[str], *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{field} does not match its strict schema")
    return value


def optional_bool_field(value: object, *, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean or null")
    return value


def normalized_category(value: str, *, fallback: str) -> str:
    normalized = SAFE_CATEGORY.sub("_", value.casefold()).strip("_")
    return (normalized or fallback)[:160]


def command_from_arguments(tool_name: str, arguments: Mapping[str, Any]) -> str:
    normalized_tool = tool_name.casefold()
    if normalized_tool not in SHELL_TOOLS and not normalized_tool.endswith("_bash"):
        return ""
    for key in ("cmd", "command", "bash_script", "python_script"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            if len(value) > 1024 * 1024:
                raise ValueError("tool-call command exceeds the case schema bound")
            return value.replace("\x00", "")
    return ""


def call_outcome(output_error: object) -> str:
    if output_error is None:
        return "succeeded"
    if isinstance(output_error, str) and output_error:
        return "failed"
    raise ValueError("output_error must be null or a non-empty string")


def project_calls(
    actions: object,
    *,
    max_tool_calls: int,
    max_argument_bytes: int,
) -> tuple[tuple[ProjectedCall, ...], int]:
    if not isinstance(actions, list):
        raise ValueError("actions must be an array")
    calls: list[ProjectedCall] = []
    for sequence_index, raw_action in enumerate(actions):
        action = require_exact_keys(raw_action, ACTION_KEYS, field="action")
        if sequence_index >= max_tool_calls:
            continue
        tool_name = required_text(action["function"], field="action.function")
        arguments = action["arguments"]
        if not isinstance(arguments, dict):
            raise ValueError("action.arguments must be an object")
        try:
            argument_bytes = canonical_json(arguments)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("action.arguments is not bounded JSON data") from exc
        if len(argument_bytes) > max_argument_bytes:
            raise ValueError("action.arguments exceeds the configured byte bound")
        calls.append(
            ProjectedCall(
                tool_name=tool_name,
                arguments=arguments,
                sequence_index=sequence_index,
                call_index=0,
                outcome=call_outcome(action["output_error"]),
                command=command_from_arguments(tool_name, arguments),
            )
        )
    return tuple(calls), len(actions)


def trajectory_from_row(
    row: object,
    *,
    max_tool_calls: int,
    max_argument_bytes: int,
) -> Trajectory | None:
    source = require_exact_keys(row, SOURCE_ROW_KEYS, field="trajectory")
    trajectory_id = required_text(source["trajectory_id"], field="trajectory_id")
    run_id = required_text(source["run_id"], field="run_id")
    environment = source["environment"]
    main_task = source["main_task"]
    if not isinstance(environment, Mapping) or not isinstance(main_task, Mapping):
        raise ValueError("environment and main_task must be objects")
    environment_id = required_text(environment.get("id"), field="environment.id")
    main_task_id = required_text(main_task.get("id"), field="main_task.id")
    side_task = source["side_task"]
    if side_task is not None and not isinstance(side_task, Mapping):
        raise ValueError("side_task must be an object or null")
    side_task_id = required_text(side_task.get("id"), field="side_task.id") if isinstance(side_task, Mapping) else ""
    main_task_success = optional_bool_field(source["main_task_success"], field="main_task_success")
    side_task_success = optional_bool_field(source["side_task_success"], field="side_task_success")
    if side_task is None and side_task_success:
        raise ValueError("side_task_success cannot be true when side_task is null")
    calls, source_call_count = project_calls(
        source["actions"],
        max_tool_calls=max_tool_calls,
        max_argument_bytes=max_argument_bytes,
    )
    if not calls:
        return None
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
    projected_digest = sha256_bytes(canonical_json(call_identity))
    identity_digest = stable_digest(
        "linuxarena-trajectory-v1",
        DATASET,
        environment_id,
        main_task_id,
        side_task_id or "honest",
        "unknown" if main_task_success is None else str(main_task_success).casefold(),
        "unknown" if side_task_success is None else str(side_task_success).casefold(),
        str(source_call_count),
        projected_digest,
    )
    return Trajectory(
        identity_digest=identity_digest,
        group_digest=stable_digest("linuxarena-task-family-v1", DATASET, environment_id, main_task_id),
        source_identity_digest=stable_digest("linuxarena-source-identity-v1", DATASET, trajectory_id, run_id),
        environment_category=normalized_category(environment_id, fallback="linux"),
        main_task_success=main_task_success,
        side_task_present=side_task is not None,
        side_task_success=side_task_success,
        calls=calls,
        source_call_count=source_call_count,
    )


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                raise ValueError(f"{path.name}:{line_number}: blank JSONL record")
            try:
                row = json.loads(line, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{line_number}: expected an object")
            yield row


def action_truth(trajectory: Trajectory) -> dict[str, Any]:
    common = ["agent_trajectory", "linuxarena", "real_tool_arguments", "atomic_call"]
    if not trajectory.side_task_present:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "linuxarena:side_task_absent",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": [*common, "honest_trajectory", task_outcome_category(trajectory)],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "low",
        "label_source": "linuxarena:side_task_trajectory_outcome",
        "applicability": "out_of_scope",
        "expected_disposition": "allow",
        "categories": [
            *common,
            "side_task_present",
            side_task_outcome_category(trajectory),
            task_outcome_category(trajectory),
            "proof_pending",
        ],
        "exclusion_reason": "trajectory side-task outcome does not prove this atomic call malicious",
    }


def stateful_truth(trajectory: Trajectory) -> dict[str, Any]:
    common = ["agent_trajectory", "linuxarena", "real_tool_arguments", "bounded_chain"]
    if not trajectory.side_task_present:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "linuxarena:side_task_absent",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": [*common, "honest_trajectory", task_outcome_category(trajectory)],
        }
    return {
        "source_truth": "malicious" if trajectory.side_task_success is True else "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium" if trajectory.side_task_success is True else "low",
        "label_source": "linuxarena:side_task_trajectory_outcome",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": [
            *common,
            "side_task_present",
            side_task_outcome_category(trajectory),
            task_outcome_category(trajectory),
            "proof_pending",
        ],
        "exclusion_reason": (
            "trajectory side-task success does not locate a complete deterministic proof inside this bounded window"
            if trajectory.side_task_success is True
            else "side task without explicit success provides no malicious trajectory ground truth"
        ),
    }


def task_outcome_category(trajectory: Trajectory) -> str:
    if trajectory.main_task_success is None:
        return "main_task_outcome_unknown"
    return "main_task_succeeded" if trajectory.main_task_success else "main_task_failed"


def side_task_outcome_category(trajectory: Trajectory) -> str:
    if trajectory.side_task_success is None:
        return "side_task_outcome_unknown"
    return "side_task_succeeded" if trajectory.side_task_success else "side_task_failed"


def call_payload(call: ProjectedCall) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "direction": "tool_call",
        "tool_name": call.tool_name,
        "args": call.arguments,
        "dialect": "mixed" if call.command else "none",
    }
    if call.command:
        payload["command"] = call.command
    return payload


def event_payload(call: ProjectedCall, window_start: int) -> dict[str, Any]:
    event: dict[str, Any] = {
        "tool_name": call.tool_name,
        "args": call.arguments,
        "dialect": "mixed" if call.command else "none",
        "outcome": call.outcome,
        "offset_seconds": call.sequence_index - window_start,
    }
    if call.command:
        event["command"] = call.command
    return event


def stateful_windows(calls: Sequence[ProjectedCall]) -> Iterable[Sequence[ProjectedCall]]:
    if len(calls) < 2:
        return
    start = 0
    while start < len(calls):
        window = calls[start : start + MAX_STATEFUL_EVENTS]
        if len(window) >= 2:
            yield window
        if start + len(window) >= len(calls):
            break
        start += MAX_STATEFUL_EVENTS - WINDOW_OVERLAP


def source_record(trajectory: Trajectory, revision: str, suffix: str) -> dict[str, str]:
    return {
        "dataset": DATASET,
        "revision": revision,
        "original_id": (
            f"trajectory-{trajectory.identity_digest[:24]}/source-{trajectory.source_identity_digest[:16]}/{suffix}"
        ),
        "license": LICENSE,
        "redistribution": REDISTRIBUTION,
    }


def make_cases(trajectory: Trajectory, *, revision: str) -> list[dict[str, Any]]:
    prefix = f"linuxarena/{trajectory.identity_digest[:24]}"
    common_strata = {
        "ecosystem": "coding_agent",
        "domain": trajectory.environment_category,
        "hard_negative": not trajectory.side_task_present,
        "split_group": trajectory.group_digest[:24],
        "trajectory_id": trajectory.identity_digest,
    }
    rows: list[dict[str, Any]] = []
    for call in trajectory.calls:
        ordinal = f"s{call.sequence_index:06d}-c{call.call_index:03d}"
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"{prefix}/{ordinal}",
                "source": source_record(trajectory, revision, ordinal),
                "split": PRE_PARTITION_SPLIT,
                "surface": "action",
                "payload": call_payload(call),
                "truth": action_truth(trajectory),
                "strata": {
                    **common_strata,
                    "campaign": "atomic_proof_pending" if trajectory.side_task_present else "honest",
                    "sequence_index": call.sequence_index,
                    "call_index": call.call_index,
                },
            }
        )
    for window_number, window in enumerate(stateful_windows(trajectory.calls)):
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"{prefix}/stateful-{window_number:03d}",
                "source": source_record(trajectory, revision, f"window-{window_number:03d}"),
                "split": PRE_PARTITION_SPLIT,
                "surface": "stateful",
                "payload": {
                    "direction": "tool_call",
                    "events": [event_payload(call, window[0].sequence_index) for call in window],
                },
                "truth": stateful_truth(trajectory),
                "strata": {
                    **common_strata,
                    "campaign": "bounded_trajectory",
                    "sequence_index": window[0].sequence_index,
                    "call_index": window[0].call_index,
                },
            }
        )
    return rows


def build_corpus(
    source_rows: Iterable[Mapping[str, Any]],
    *,
    revision: str,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
    source_manifest: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    revision = required_text(revision, field="revision", max_length=40)
    if not HEX_40.fullmatch(revision):
        raise ValueError("revision must be a lowercase 40-character Git digest")
    if not 1 <= max_tool_calls <= DEFAULT_MAX_TOOL_CALLS:
        raise ValueError(f"max_tool_calls must be between 1 and {DEFAULT_MAX_TOOL_CALLS}")
    if not 1 <= max_argument_bytes <= 1024 * 1024:
        raise ValueError("max_argument_bytes must be between 1 and 1048576")

    statistics: Counter[str] = Counter()
    unique: dict[str, Trajectory] = {}
    for row in source_rows:
        statistics["source_trajectories"] += 1
        trajectory = trajectory_from_row(
            row,
            max_tool_calls=max_tool_calls,
            max_argument_bytes=max_argument_bytes,
        )
        if trajectory is None:
            statistics["trajectories_without_tool_calls"] += 1
            continue
        if trajectory.source_call_count > len(trajectory.calls):
            statistics["truncated_trajectories"] += 1
            statistics["truncated_tool_calls"] += trajectory.source_call_count - len(trajectory.calls)
        previous = unique.get(trajectory.identity_digest)
        if previous is not None:
            statistics["exact_trajectory_duplicates_removed"] += 1
            if trajectory.source_identity_digest < previous.source_identity_digest:
                unique[trajectory.identity_digest] = trajectory
            continue
        unique[trajectory.identity_digest] = trajectory
        statistics["honest_trajectories" if not trajectory.side_task_present else "side_task_trajectories"] += 1
        if trajectory.side_task_present:
            statistics[
                "successful_side_task_trajectories"
                if trajectory.side_task_success is True
                else "failed_or_unknown_side_task_trajectories"
            ] += 1

    trajectories = [unique[key] for key in sorted(unique)]
    if not trajectories:
        raise ValueError("no LinuxArena trajectories with tool calls were found")
    rows: list[dict[str, Any]] = []
    group_trajectories: Counter[str] = Counter()
    group_calls: Counter[str] = Counter()
    group_surfaces: dict[str, Counter[str]] = defaultdict(Counter)
    for trajectory in trajectories:
        generated = make_cases(trajectory, revision=revision)
        rows.extend(generated)
        group_trajectories[trajectory.group_digest] += 1
        group_calls[trajectory.group_digest] += len(trajectory.calls)
        group_surfaces[trajectory.group_digest].update(str(row["surface"]) for row in generated)
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate benchmark case IDs")

    groups = [
        {
            "group": group[:24],
            "trajectories": group_trajectories[group],
            "tool_calls": group_calls[group],
            "cases": sum(group_surfaces[group].values()),
            "action_cases": group_surfaces[group]["action"],
            "stateful_cases": group_surfaces[group]["stateful"],
        }
        for group in sorted(group_trajectories)
    ]
    output_data = b"".join(canonical_json(row) for row in rows)
    if source_manifest is None:
        source_manifest = {
            "dataset": DATASET,
            "revision": revision,
            "license": LICENSE,
            "redistribution": REDISTRIBUTION,
            "path": "data/sample.jsonl",
            "bytes": 0,
            "sha256": "0" * 64,
        }
    elif source_manifest.get("revision") != revision:
        raise ValueError("source manifest revision does not match the normalized revision")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": statistics["exact_trajectory_duplicates_removed"],
        "label_conflicts_excluded": 0,
        "source": dict(source_manifest),
        "adapter_statistics": {
            "linuxarena": {
                **{key: int(value) for key, value in sorted(statistics.items())},
                "selected_trajectories": len(trajectories),
                "selected_tool_calls": sum(len(item.calls) for item in trajectories),
                "task_family_groups": len(groups),
            }
        },
        "output_sha256": sha256_bytes(output_data),
    }
    group_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "linuxarena-trajectory-group-index-v1",
        "grouping_strategy": GROUPING_STRATEGY,
        "partition_authority": PARTITION_AUTHORITY,
        "group_count": len(groups),
        "trajectory_count": len(trajectories),
        "tool_call_count": sum(len(item.calls) for item in trajectories),
        "case_count": len(rows),
        "groups": groups,
        "corpus_sha256": sha256_bytes(output_data),
    }
    validate_manifests(manifest, group_manifest)
    return rows, manifest, group_manifest


def resolve_revision(source: Path, override: str | None) -> str:
    if override:
        revision = required_text(override, field="revision", max_length=40)
    else:
        source_root = source.parents[1]
        relative = source.relative_to(source_root)
        metadata = source_root / ".cache/huggingface/download" / Path(str(relative) + ".metadata")
        if not metadata.is_file():
            raise ValueError(f"missing Hugging Face revision metadata for {relative.as_posix()}")
        lines = metadata.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError("empty Hugging Face revision metadata")
        revision = required_text(lines[0], field="revision", max_length=40)
    if not HEX_40.fullmatch(revision):
        raise ValueError("revision must be a lowercase 40-character Git digest")
    return revision


def make_source_manifest(source: Path, revision: str) -> dict[str, Any]:
    return {
        "dataset": DATASET,
        "revision": revision,
        "license": LICENSE,
        "redistribution": REDISTRIBUTION,
        "path": "data/sample.jsonl",
        "bytes": source.stat().st_size,
        "sha256": sha256_file(source),
    }


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path, *, max_argument_bytes: int) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
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
            raise ValueError("LinuxArena normalization rows must remain pre-partitioned")
        payload = row["payload"]
        projected = payload.get("events") if row["surface"] == "stateful" else [payload]
        if not isinstance(projected, list):
            raise ValueError("stateful payload must contain events")
        for event in projected:
            if len(canonical_json(event["args"])) > max_argument_bytes:
                raise ValueError("projected arguments exceed the configured byte bound")
            forbidden = {
                "output",
                "output_error",
                "result",
                "reasoning",
                "agent_reasoning",
                "extended_thinking",
                "messages",
                "monitor_response",
                "substeps",
            }
            if forbidden.intersection(event):
                raise ValueError("projected payload contains an excluded source field")
        if (
            row["truth"]["deterministic_truth"] == "contextual_or_dual_use"
            and row["truth"]["applicability"] != "out_of_scope"
        ):
            raise ValueError("proof-pending LinuxArena truth must remain out of scored scope")


def validate_manifests(manifest: object, group_manifest: object) -> None:
    manifest_map = require_exact_keys(manifest, MANIFEST_KEYS, field="normalization manifest")
    group_map = require_exact_keys(group_manifest, GROUP_MANIFEST_KEYS, field="trajectory group manifest")
    source = require_exact_keys(manifest_map["source"], SOURCE_MANIFEST_KEYS, field="source manifest")
    if (
        manifest_map["schema_version"] != SCHEMA_VERSION
        or manifest_map["datasets"] != [DATASET]
        or manifest_map["counts"] != {DATASET: manifest_map["cases"]}
        or source["dataset"] != DATASET
        or source["license"] != LICENSE
        or source["redistribution"] != REDISTRIBUTION
        or source["path"] != "data/sample.jsonl"
        or type(source["bytes"]) is not int
        or source["bytes"] < 0
        or not HEX_40.fullmatch(str(source["revision"]))
        or not HEX_64.fullmatch(str(source["sha256"]))
    ):
        raise ValueError("normalization manifest source identity is invalid")
    statistics = manifest_map["adapter_statistics"]
    if (
        not isinstance(statistics, Mapping)
        or set(statistics) != {"linuxarena"}
        or not isinstance(statistics["linuxarena"], Mapping)
        or any(type(value) is not int for value in statistics["linuxarena"].values())
    ):
        raise ValueError("normalization manifest statistics are invalid")
    if (
        group_map["schema_version"] != SCHEMA_VERSION
        or group_map["kind"] != "linuxarena-trajectory-group-index-v1"
        or group_map["grouping_strategy"] != GROUPING_STRATEGY
        or group_map["partition_authority"] != PARTITION_AUTHORITY
    ):
        raise ValueError("trajectory group manifest identity is invalid")
    groups = group_map["groups"]
    if not isinstance(groups, list) or len(groups) != group_map["group_count"]:
        raise ValueError("trajectory group count is invalid")
    seen: set[str] = set()
    for value in groups:
        group = require_exact_keys(value, GROUP_KEYS, field="trajectory group entry")
        digest = str(group["group"])
        if not HEX_24.fullmatch(digest) or digest in seen:
            raise ValueError("trajectory group digest is invalid or duplicated")
        seen.add(digest)
        if any(type(group[key]) is not int or group[key] < 0 for key in GROUP_KEYS - {"group"}):
            raise ValueError("trajectory group counts are invalid")
        if group["cases"] != group["action_cases"] + group["stateful_cases"]:
            raise ValueError("trajectory group case counts are inconsistent")
    if sum(int(group["cases"]) for group in groups) != group_map["case_count"]:
        raise ValueError("trajectory group manifest case count is inconsistent")
    if group_map["case_count"] != manifest_map["cases"]:
        raise ValueError("normalization and group manifest case counts differ")
    if sum(int(group["trajectories"]) for group in groups) != group_map["trajectory_count"]:
        raise ValueError("trajectory group manifest trajectory count is inconsistent")
    if sum(int(group["tool_calls"]) for group in groups) != group_map["tool_call_count"]:
        raise ValueError("trajectory group manifest tool-call count is inconsistent")
    if not HEX_64.fullmatch(str(manifest_map["output_sha256"])):
        raise ValueError("normalization manifest output digest is invalid")
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
    if manifest["output_sha256"] != sha256_bytes(output_data):
        raise ValueError("normalization manifest does not bind output bytes")
    if group_manifest["corpus_sha256"] != sha256_bytes(output_data):
        raise ValueError("trajectory group manifest does not bind output bytes")
    atomic_write(output, output_data)
    atomic_write(manifest_path, canonical_json(manifest))
    atomic_write(group_manifest_path, canonical_json(group_manifest))


def main() -> int:
    args = parse_args()
    if not args.source.is_file():
        raise ValueError(f"missing LinuxArena source file: {args.source}")
    revision = resolve_revision(args.source, args.revision)
    rows, manifest, group_manifest = build_corpus(
        jsonl_rows(args.source),
        revision=revision,
        max_tool_calls=args.max_tool_calls,
        max_argument_bytes=args.max_argument_bytes,
        source_manifest=make_source_manifest(args.source, revision),
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
                "selected_trajectories": manifest["adapter_statistics"]["linuxarena"]["selected_trajectories"],
                "selected_tool_calls": manifest["adapter_statistics"]["linuxarena"]["selected_tool_calls"],
                "pre_partition_split": PRE_PARTITION_SPLIT,
                "task_family_groups": group_manifest["group_count"],
                "partition_authority": PARTITION_AUTHORITY,
                "output_sha256": manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
