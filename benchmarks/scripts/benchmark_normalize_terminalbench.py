#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize successful TerminalBench trajectories as benign hard negatives.

Only source tool invocations (``steps[*].tools[*].fn`` and ``cmd``) enter a
benchmark payload. Messages, reasoning, observations, and tool results are
never projected. Task identities are hashed before entering manifests, and all
rollouts for one task share one leakage group. Normalized rows use the
schema-valid ``smoke`` split only as a pre-partition placeholder;
``benchmark_partition.py`` is the sole authority for development, validation,
and test assignments. Because only reward-1 trajectories are admitted, their
projected stateful tool events are marked succeeded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "terminalbench-trajectories-v1"
DATASET = "yoonholee/terminalbench-trajectories"
LICENSE = "Apache-2.0"
REDISTRIBUTION = "download-only"
GROUPING_STRATEGY = "terminalbench-task-identity-v1"
PARTITION_AUTHORITY = "benchmarks/scripts/benchmark_partition.py"
PRE_PARTITION_SPLIT = "smoke"
SAMPLING_STRATEGY = "terminalbench-hash-ranked-task-balanced-v1"
DEFAULT_SEED = 741983
MIN_PARTITION_GROUPS = 3
DEFAULT_MAX_TRAJECTORIES = 2_000
DEFAULT_MAX_TRAJECTORIES_PER_TASK = 32
DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY = 256
DEFAULT_MAX_EVENTS_PER_CASE = 64
DEFAULT_MAX_ARGUMENT_BYTES = 64 * 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_ROOT = REPO_ROOT / "outputs/benchmark-data/sources/terminalbench-trajectories"
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

SHELL_TOOLS = {
    "bash",
    "bash_command",
    "execute",
    "execute_bash",
    "interact_with_shell",
    "run-shell-command",
    "run_shell-command",
    "run_shell_command",
    "shell",
}


@dataclass(frozen=True)
class ProjectedCall:
    tool_name: str
    argument: Any
    sequence_index: int
    call_index: int
    argument_bytes: int


@dataclass(frozen=True)
class Trajectory:
    task_group: str
    trajectory_digest: str
    source_identity: str
    agent_model_digest: str
    calls: tuple[ProjectedCall, ...]
    source_call_count: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--revision", help="pinned HF revision; inferred from download metadata by default")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--group-manifest", "--freeze-manifest", dest="group_manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--max-trajectories", type=int, default=DEFAULT_MAX_TRAJECTORIES)
    parser.add_argument(
        "--max-trajectories-per-task", type=int, default=DEFAULT_MAX_TRAJECTORIES_PER_TASK
    )
    parser.add_argument(
        "--max-tool-calls-per-trajectory",
        type=int,
        default=DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY,
    )
    parser.add_argument("--max-events-per-case", type=int, default=DEFAULT_MAX_EVENTS_PER_CASE)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
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


def stable_digest(*parts: str) -> str:
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def required_text(value: object, *, field: str, max_length: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    result = value.strip()
    if len(result) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters")
    return result


def validate_bounds(
    *,
    max_trajectories: int,
    max_trajectories_per_task: int,
    max_tool_calls_per_trajectory: int,
    max_events_per_case: int,
    max_argument_bytes: int,
) -> None:
    if max_trajectories < 0 or max_trajectories_per_task < 0:
        raise ValueError("trajectory sampling bounds must be non-negative (zero means unlimited)")
    if not 1 <= max_tool_calls_per_trajectory <= 1_801:
        raise ValueError("max tool calls per trajectory must be between 1 and 1801")
    if not 2 <= max_events_per_case <= 64:
        raise ValueError("max events per case must be between 2 and 64")
    if max_argument_bytes <= 0:
        raise ValueError("max argument bytes must be positive")


def decode_steps(value: object) -> list[dict[str, Any]] | None:
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("steps is not valid JSON") from exc
    if decoded is None:
        return None
    if not isinstance(decoded, list) or any(not isinstance(step, dict) for step in decoded):
        raise ValueError("steps must decode to an array of objects or null")
    return decoded


def project_calls(
    steps: Sequence[Mapping[str, Any]],
    *,
    max_tool_calls: int,
    max_argument_bytes: int,
) -> tuple[tuple[ProjectedCall, ...], int]:
    calls: list[ProjectedCall] = []
    source_call_count = 0
    sequence_index = 0
    for step in steps:
        tools = step.get("tools")
        if tools is None:
            continue
        if not isinstance(tools, list):
            raise ValueError("step tools must be an array or null")
        if tools and step.get("src") != "agent":
            raise ValueError("tool-bearing steps must have src=agent")
        for call_index, tool in enumerate(tools):
            source_call_count += 1
            if source_call_count > max_tool_calls:
                continue
            if not isinstance(tool, dict) or set(tool) != {"fn", "cmd"}:
                raise ValueError("tool invocation must contain exactly fn and cmd")
            tool_name = required_text(tool.get("fn"), field="tool name")
            argument = tool.get("cmd")
            try:
                argument_data = canonical_json(argument)
            except (TypeError, ValueError, RecursionError) as exc:
                raise ValueError("tool argument is not bounded JSON data") from exc
            if len(argument_data) > max_argument_bytes:
                raise ValueError("tool argument exceeds the configured byte bound")
            calls.append(
                ProjectedCall(
                    tool_name,
                    argument,
                    sequence_index,
                    call_index,
                    len(argument_data),
                )
            )
            sequence_index += 1
    return tuple(calls), source_call_count


def source_identity(row: Mapping[str, Any]) -> tuple[str, str]:
    trial_id = row.get("trial_id")
    if isinstance(trial_id, str) and trial_id.strip():
        return "trial-id", required_text(trial_id, field="trial_id")
    return "trial-name", required_text(row.get("trial_name"), field="trial_name")


def trajectory_from_row(
    row: Mapping[str, Any],
    *,
    max_tool_calls: int,
    max_argument_bytes: int,
) -> Trajectory | None:
    if row.get("reward") != 1:
        return None
    steps = decode_steps(row.get("steps"))
    if steps is None:
        return None
    task_name = required_text(row.get("task_name"), field="task_name", max_length=160)
    identity_kind, identity_value = source_identity(row)
    agent = required_text(row.get("agent"), field="agent", max_length=160)
    model = required_text(row.get("model"), field="model", max_length=160)
    calls, source_call_count = project_calls(
        steps,
        max_tool_calls=max_tool_calls,
        max_argument_bytes=max_argument_bytes,
    )
    if not calls:
        return None
    task_group = stable_digest("terminalbench-task-v1", DATASET, task_name)
    agent_model_digest = stable_digest("terminalbench-agent-model-v1", agent, model)
    identity = f"{identity_kind}:{identity_value}"
    trajectory_digest = stable_digest(
        "terminalbench-trajectory-v1",
        DATASET,
        task_name,
        identity,
        agent,
        model,
    )
    return Trajectory(
        task_group=task_group,
        trajectory_digest=trajectory_digest,
        source_identity=identity,
        agent_model_digest=agent_model_digest,
        calls=calls,
        source_call_count=source_call_count,
    )


def sample_trajectories(
    trajectories: Iterable[Trajectory],
    *,
    seed: int,
    max_trajectories: int,
    max_trajectories_per_task: int,
) -> list[Trajectory]:
    by_task: dict[str, list[Trajectory]] = defaultdict(list)
    seen: set[str] = set()
    for trajectory in trajectories:
        if trajectory.trajectory_digest in seen:
            raise ValueError("duplicate TerminalBench trajectory identity")
        seen.add(trajectory.trajectory_digest)
        by_task[trajectory.task_group].append(trajectory)

    selected_by_task: dict[str, list[Trajectory]] = {}
    for group, values in by_task.items():
        ordered = sorted(
            values,
            key=lambda item: stable_digest(
                SAMPLING_STRATEGY, str(seed), group, item.trajectory_digest
            ),
        )
        selected_by_task[group] = (
            ordered[:max_trajectories_per_task] if max_trajectories_per_task else ordered
        )

    selected = [item for values in selected_by_task.values() for item in values]
    if not max_trajectories or len(selected) <= max_trajectories:
        return sorted(selected, key=lambda item: item.trajectory_digest)
    if max_trajectories < MIN_PARTITION_GROUPS:
        raise ValueError("max trajectories must permit at least three task groups")

    ordered_groups = sorted(
        selected_by_task,
        key=lambda group: stable_digest(SAMPLING_STRATEGY, str(seed), "group", group),
    )
    retained_groups = ordered_groups[: min(len(ordered_groups), max_trajectories)]
    result = [selected_by_task[group][0] for group in retained_groups]
    remaining = [
        item
        for group in retained_groups
        for item in selected_by_task[group][1:]
    ]
    remaining.sort(
        key=lambda item: stable_digest(
            SAMPLING_STRATEGY, str(seed), "global", item.trajectory_digest
        )
    )
    result.extend(remaining[: max_trajectories - len(result)])
    return sorted(result, key=lambda item: item.trajectory_digest)


def event_for_call(call: ProjectedCall) -> dict[str, Any]:
    event: dict[str, Any] = {
        "tool_name": call.tool_name,
        "args": {"cmd": call.argument},
        "dialect": "none",
        "outcome": "succeeded",
        "offset_seconds": call.sequence_index,
    }
    if call.tool_name.casefold() in SHELL_TOOLS and isinstance(call.argument, str):
        event["command"] = call.argument
        event["dialect"] = "posix"
    return event


def truth() -> dict[str, Any]:
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": "terminalbench:successful_reward",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": [
            "agent_trajectory",
            "benign_hard_negative",
            "real_tool_arguments",
            "successful_terminalbench_task",
        ],
    }


def make_cases(
    trajectory: Trajectory,
    *,
    revision: str,
    max_events_per_case: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for start in range(0, len(trajectory.calls), max_events_per_case):
        window = trajectory.calls[start : start + max_events_per_case]
        end = start + len(window) - 1
        window_id = f"calls-{start:04d}-{end:04d}"
        payload: dict[str, Any]
        if len(window) == 1:
            event = event_for_call(window[0])
            payload = {
                "direction": "tool_call",
                "tool_name": event["tool_name"],
                "args": event["args"],
                "dialect": event["dialect"],
            }
            if "command" in event:
                payload["command"] = event["command"]
        else:
            payload = {"events": [event_for_call(call) for call in window]}
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"terminalbench/{trajectory.trajectory_digest[:24]}/{window_id}",
                "source": {
                    "dataset": DATASET,
                    "revision": revision,
                    "original_id": (
                        f"{trajectory.source_identity}:agent-model:"
                        f"{trajectory.agent_model_digest[:16]}:{window_id}"
                    ),
                    "license": LICENSE,
                    "redistribution": REDISTRIBUTION,
                },
                "split": PRE_PARTITION_SPLIT,
                "surface": "action" if len(window) == 1 else "stateful",
                "payload": payload,
                "truth": truth(),
                "strata": {
                    "ecosystem": "coding_agent",
                    "campaign": "successful_terminalbench_task",
                    "domain": "terminal",
                    "hard_negative": True,
                    "split_group": trajectory.task_group[:24],
                    "trajectory_id": trajectory.trajectory_digest,
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
    seed: int = DEFAULT_SEED,
    max_trajectories: int = DEFAULT_MAX_TRAJECTORIES,
    max_trajectories_per_task: int = DEFAULT_MAX_TRAJECTORIES_PER_TASK,
    max_tool_calls_per_trajectory: int = DEFAULT_MAX_TOOL_CALLS_PER_TRAJECTORY,
    max_events_per_case: int = DEFAULT_MAX_EVENTS_PER_CASE,
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
    source_files: Sequence[Mapping[str, Any]] = (),
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    revision = required_text(revision, field="revision", max_length=160)
    validate_bounds(
        max_trajectories=max_trajectories,
        max_trajectories_per_task=max_trajectories_per_task,
        max_tool_calls_per_trajectory=max_tool_calls_per_trajectory,
        max_events_per_case=max_events_per_case,
        max_argument_bytes=max_argument_bytes,
    )

    statistics: Counter[str] = Counter()
    eligible: list[Trajectory] = []
    source_record_digests: list[str] = []
    for row in source_rows:
        statistics["source_rows"] += 1
        if row.get("reward") != 1:
            statistics["non_successful_rows"] += 1
            continue
        statistics["successful_rows"] += 1
        trajectory = trajectory_from_row(
            row,
            max_tool_calls=max_tool_calls_per_trajectory,
            max_argument_bytes=max_argument_bytes,
        )
        if trajectory is None:
            statistics["successful_rows_without_tool_calls"] += 1
            continue
        statistics["successful_rows_with_tool_calls"] += 1
        if trajectory.source_call_count > len(trajectory.calls):
            statistics["truncated_tool_calls"] += trajectory.source_call_count - len(trajectory.calls)
            statistics["truncated_trajectories"] += 1
        call_identity = [
            {
                "tool_name": call.tool_name,
                "argument": call.argument,
                "sequence": call.sequence_index,
                "call_index": call.call_index,
            }
            for call in trajectory.calls
        ]
        source_record_digests.append(
            stable_digest(
                "terminalbench-source-record-v1",
                trajectory.trajectory_digest,
                sha256_bytes(canonical_json(call_identity)),
            )
        )
        eligible.append(trajectory)

    selected = sample_trajectories(
        eligible,
        seed=seed,
        max_trajectories=max_trajectories,
        max_trajectories_per_task=max_trajectories_per_task,
    )
    if not selected:
        raise ValueError("no successful TerminalBench trajectories with tool calls were selected")
    rows: list[dict[str, Any]] = []
    group_trajectory_counts: Counter[str] = Counter()
    group_call_counts: Counter[str] = Counter()
    group_case_counts: Counter[str] = Counter()
    for trajectory in selected:
        cases = make_cases(
            trajectory,
            revision=revision,
            max_events_per_case=max_events_per_case,
        )
        rows.extend(cases)
        group_trajectory_counts[trajectory.task_group] += 1
        group_call_counts[trajectory.task_group] += len(trajectory.calls)
        group_case_counts[trajectory.task_group] += len(cases)
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate benchmark case IDs")

    selected_groups = sorted({trajectory.task_group for trajectory in selected})
    groups = [
        {
            "group": group[:24],
            "trajectories": group_trajectory_counts[group],
            "tool_calls": group_call_counts[group],
            "cases": group_case_counts[group],
        }
        for group in selected_groups
    ]
    output_data = b"".join(canonical_json(row) for row in rows)
    group_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "terminalbench-trajectory-group-index-v1",
        "grouping_strategy": GROUPING_STRATEGY,
        "partition_authority": PARTITION_AUTHORITY,
        "sampling_strategy": SAMPLING_STRATEGY,
        "sampling_seed": seed,
        "sampling": {
            "max_trajectories": max_trajectories,
            "max_trajectories_per_task": max_trajectories_per_task,
            "max_tool_calls_per_trajectory": max_tool_calls_per_trajectory,
            "max_events_per_case": max_events_per_case,
            "max_argument_bytes": max_argument_bytes,
        },
        "group_count": len(groups),
        "trajectory_count": len(selected),
        "tool_call_count": sum(len(item.calls) for item in selected),
        "case_count": len(rows),
        "groups": groups,
        "corpus_sha256": sha256_bytes(output_data),
    }
    normalization_manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {
            "terminalbench": {
                **{key: int(value) for key, value in sorted(statistics.items())},
                "selected_trajectories": len(selected),
                "selected_tool_calls": sum(len(item.calls) for item in selected),
                "eligible_task_groups": len({item.task_group for item in eligible}),
                "selected_task_groups": len(selected_groups),
            }
        },
        "output_sha256": sha256_bytes(output_data),
    }
    validate_group_manifest(normalization_manifest, group_manifest)
    return rows, normalization_manifest, group_manifest


def parquet_paths(source_root: Path) -> list[Path]:
    paths = sorted((source_root / "data").glob("*.parquet"), key=lambda path: path.name)
    if not paths:
        raise ValueError("no TerminalBench Parquet source files found")
    return paths


def parquet_rows(paths: Sequence[Path]) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:  # pragma: no cover - exercised by the CLI environment
        raise RuntimeError("pyarrow is required to read TerminalBench Parquet files") from exc
    columns = ["task_name", "agent", "model", "reward", "trial_name", "trial_id", "steps"]
    for path in paths:
        source = parquet.ParquetFile(path)
        missing = sorted(set(columns) - set(source.schema_arrow.names))
        if missing:
            raise ValueError(f"{path.name}: missing required columns: {', '.join(missing)}")
        for batch in source.iter_batches(columns=columns, batch_size=512):
            yield from batch.to_pylist()


def resolve_revision(source_root: Path, paths: Sequence[Path], override: str | None) -> str:
    if override:
        return required_text(override, field="revision", max_length=160)
    revisions: set[str] = set()
    metadata_root = source_root / ".cache/huggingface/download"
    for path in paths:
        relative = path.relative_to(source_root)
        metadata_path = metadata_root / relative.parent / f"{relative.name}.metadata"
        if not metadata_path.is_file():
            raise ValueError(f"missing Hugging Face revision metadata for {relative}")
        lines = metadata_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError(f"empty Hugging Face revision metadata for {relative}")
        revisions.add(required_text(lines[0], field="revision", max_length=160))
    if len(revisions) != 1:
        raise ValueError("TerminalBench source files do not resolve to one revision")
    return next(iter(revisions))


def source_file_manifest(source_root: Path, paths: Sequence[Path]) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(source_root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in paths
    ]


def validate_cases(
    rows: Iterable[dict[str, Any]],
    schema_path: Path,
    *,
    max_argument_bytes: int,
) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    group_splits: dict[str, str] = {}
    for row in rows:
        case_id = str(row.get("id", ""))
        if case_id in seen_ids:
            raise ValueError("duplicate benchmark case ID")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"case schema validation failed at {location or '<root>'}")
        if row["truth"]["source_truth"] != "benign" or not row["strata"]["hard_negative"]:
            raise ValueError("TerminalBench cases must be benign hard negatives")
        if row["split"] != PRE_PARTITION_SPLIT:
            raise ValueError("TerminalBench normalization rows must remain pre-partitioned")
        group = row["strata"]["split_group"]
        split = row["split"]
        if group in group_splits and group_splits[group] != split:
            raise ValueError("TerminalBench task group crosses benchmark splits")
        group_splits[group] = split
        payload = row["payload"]
        events = payload.get("events")
        projected = events if isinstance(events, list) else [payload]
        for event in projected:
            args = event.get("args")
            if set(args) != {"cmd"} or len(canonical_json(args["cmd"])) > max_argument_bytes:
                raise ValueError("projected tool arguments violate the adapter contract")
            if any(key in event for key in ("obs", "observation", "result", "output", "msg")):
                raise ValueError("projected payload contains an excluded trajectory field")
            if events is not None and event.get("outcome") != "succeeded":
                raise ValueError("successful TerminalBench stateful events must be succeeded")


def validate_group_manifest(
    manifest: Mapping[str, Any], group_manifest: Mapping[str, Any]
) -> None:
    if (
        group_manifest.get("schema_version") != SCHEMA_VERSION
        or group_manifest.get("kind") != "terminalbench-trajectory-group-index-v1"
        or group_manifest.get("grouping_strategy") != GROUPING_STRATEGY
        or group_manifest.get("partition_authority") != PARTITION_AUTHORITY
    ):
        raise ValueError("TerminalBench trajectory group manifest identity is invalid")
    forbidden_split_fields = {
        "assignment_sha256", "case_counts", "group_counts", "ratios", "split", "strategy",
        "tool_call_counts", "trajectory_counts",
    }
    if forbidden_split_fields.intersection(group_manifest):
        raise ValueError("trajectory group manifest must not claim partition assignments")
    groups = group_manifest.get("groups")
    if not isinstance(groups, list) or len(groups) != group_manifest.get("group_count"):
        raise ValueError("trajectory group manifest group count is invalid")
    for group in groups:
        if not isinstance(group, Mapping) or forbidden_split_fields.intersection(group):
            raise ValueError("trajectory group entry must not claim a partition assignment")
    if group_manifest.get("case_count") != manifest.get("cases"):
        raise ValueError("trajectory group manifest case count is invalid")
    if group_manifest.get("corpus_sha256") != manifest.get("output_sha256"):
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
    validate_group_manifest(manifest, group_manifest)
    output_data = b"".join(canonical_json(row) for row in rows)
    group_data = canonical_json(group_manifest)
    if manifest.get("output_sha256") != sha256_bytes(output_data):
        raise ValueError("normalization manifest does not bind output bytes")
    if group_manifest.get("corpus_sha256") != sha256_bytes(output_data):
        raise ValueError("trajectory group manifest does not bind output bytes")
    atomic_write(output, output_data)
    atomic_write(manifest_path, canonical_json(manifest))
    atomic_write(group_manifest_path, group_data)


def main() -> int:
    args = parse_args()
    paths = parquet_paths(args.source_root)
    revision = resolve_revision(args.source_root, paths, args.revision)
    rows, manifest, group_manifest = build_corpus(
        parquet_rows(paths),
        revision=revision,
        seed=args.seed,
        max_trajectories=args.max_trajectories,
        max_trajectories_per_task=args.max_trajectories_per_task,
        max_tool_calls_per_trajectory=args.max_tool_calls_per_trajectory,
        max_events_per_case=args.max_events_per_case,
        max_argument_bytes=args.max_argument_bytes,
        source_files=source_file_manifest(args.source_root, paths),
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
                "selected_trajectories": manifest["adapter_statistics"]["terminalbench"]["selected_trajectories"],
                "selected_tool_calls": manifest["adapter_statistics"]["terminalbench"]["selected_tool_calls"],
                "pre_partition_split": PRE_PARTITION_SPLIT,
                "trajectory_group_count": group_manifest["group_count"],
                "partition_authority": PARTITION_AUTHORITY,
                "output_sha256": manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
