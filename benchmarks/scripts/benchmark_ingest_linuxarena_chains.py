#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize bounded LinuxArena tool-call windows with real arguments.

The source is untrusted data. This program parses JSON and parquet but never
executes a command, imports source code, or reads tool outputs/reasoning. Only
closed, tool-specific argument schemas are projected. Unknown keys quarantine
the arguments for that event instead of being guessed.

LinuxArena's policy and outcome fields are trajectory-level context. They are
never promoted to per-call malicious/benign truth by this adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

SOURCE_ID = "eval-aware/linuxarena-trajectories"
SOURCE_URL = "https://huggingface.co/datasets/eval-aware/linuxarena-trajectories"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
SCHEMA_VERSION = "defenseclaw.linuxarena-real-arguments.v1"
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")

PARQUET_COLUMNS = (
    "trajectory_id",
    "policy",
    "environment",
    "has_side_task",
    "main_task_success",
    "side_task_success",
    "number_of_actions",
    "action_functions",
    "action_arguments_json",
    "action_has_error",
)

SHELL_TOOLS = frozenset(
    {
        "Bash",
        "bash",
        "bash_12",
        "bash_13",
        "bash_15",
        "bash_root",
        "client_bash",
        "db_bash",
        "nginx_bash",
        "py_ml_bash",
        "rust_worker_bash",
    }
)

# These are exact schemas observed at the pinned revision. Content-bearing
# values are accepted only so they can be replaced with a digest below.
TOOL_ALLOWED_KEYS: dict[str, frozenset[str]] = {
    "text_editor": frozenset(
        {
            "command",
            "path",
            "view_range",
            "insert_line",
            "file_text",
            "new_str",
            "old_str",
        }
    ),
    "text_editor_14": frozenset({"command", "path", "view_range"}),
    "Read": frozenset({"file_path", "offset", "limit"}),
    "Write": frozenset({"file_path", "content"}),
    "Edit": frozenset({"file_path", "old_string", "new_string", "replace_all"}),
    "Grep": frozenset(
        {
            "pattern",
            "path",
            "glob",
            "output_mode",
            "head_limit",
            "context",
            "-A",
            "-B",
            "-C",
            "-i",
            "-n",
        }
    ),
    "grep": frozenset({"pattern", "path"}),
    "Glob": frozenset({"pattern", "path"}),
}

SHELL_ALLOWED_KEYS = frozenset(
    {
        "cmd",
        "command",
        "cwd",
        "timeout",
        "description",
        "run_in_background",
    }
)

CONTENT_KEYS = frozenset(
    {
        "content",
        "description",
        "file_text",
        "new_str",
        "new_string",
        "old_str",
        "old_string",
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument(
        "--split",
        choices=("development", "validation", "test"),
        default="development",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("benchmarks/schema/case-v1.schema.json"),
    )
    parser.add_argument(
        "--policies",
        nargs="+",
        choices=("attack", "honest", "claude-code"),
        default=("attack", "honest"),
    )
    parser.add_argument("--max-trajectories-per-policy", type=int, default=25)
    parser.add_argument("--window-size", type=int, default=8)
    parser.add_argument("--stride", type=int, default=1)
    parser.add_argument("--max-argument-bytes", type=int, default=131_072)
    parser.add_argument("--max-value-bytes", type=int, default=65_536)
    return parser.parse_args()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parquet_rows(path: Path) -> Iterator[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - exercised by CLI operators
        raise RuntimeError(
            "pyarrow==25.0.1 is required; run with "
            "`uv run --isolated --no-project --with pyarrow==25.0.1 "
            "--with jsonschema python benchmarks/scripts/benchmark_ingest_linuxarena_chains.py ...`"
        ) from exc

    parquet = pq.ParquetFile(path)
    missing = sorted(set(PARQUET_COLUMNS) - set(parquet.schema_arrow.names))
    if missing:
        raise ValueError(f"input parquet is missing columns: {', '.join(missing)}")
    for batch in parquet.iter_batches(batch_size=32, columns=PARQUET_COLUMNS):
        yield from batch.to_pylist()


def validate_options(
    *,
    revision: str,
    window_size: int,
    stride: int,
    max_trajectories_per_policy: int,
    max_argument_bytes: int,
    max_value_bytes: int,
) -> None:
    if not revision or len(revision) > 160:
        raise ValueError("source revision must be 1..160 characters")
    if not 2 <= window_size <= 8:
        raise ValueError("window size must be between 2 and 8")
    if not 1 <= stride <= window_size:
        raise ValueError("stride must be between 1 and window size")
    if max_trajectories_per_policy < 1:
        raise ValueError("max trajectories per policy must be positive")
    if not 1 <= max_argument_bytes <= 1_048_576:
        raise ValueError("max argument bytes must be 1..1048576")
    if not 1 <= max_value_bytes <= max_argument_bytes:
        raise ValueError("max value bytes must be positive and no larger than max argument bytes")


def selection_key(row: dict[str, Any]) -> tuple[str, str]:
    trajectory_id = str(row.get("trajectory_id") or "")
    digest = hashlib.sha256(f"{SOURCE_ID}\x00{trajectory_id}".encode()).hexdigest()
    return digest, trajectory_id


def select_rows(
    rows: Iterable[dict[str, Any]],
    policies: Sequence[str],
    max_trajectories_per_policy: int,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    selected_policies = set(policies)
    by_policy: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    source_policy_counts: Counter[str] = Counter()
    for row in rows:
        policy = str(row.get("policy") or "missing")
        source_policy_counts[policy] += 1
        if policy in selected_policies:
            by_policy[policy].append(row)

    selected: list[dict[str, Any]] = []
    for policy in policies:
        selected.extend(sorted(by_policy.get(policy, []), key=selection_key)[:max_trajectories_per_policy])
    selected.sort(key=lambda row: (str(row.get("policy")), selection_key(row)))
    return selected, source_policy_counts


def bounded_value(value: object, max_value_bytes: int) -> object:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > max_value_bytes:
            raise ValueError("argument value exceeds byte bound")
        return value
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("argument array exceeds item bound")
        return [bounded_value(item, max_value_bytes) for item in value]
    raise ValueError("argument value has unsupported type")


def content_fingerprint(value: object, max_value_bytes: int) -> dict[str, object]:
    if not isinstance(value, str):
        raise ValueError("content-bearing argument must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) > max_value_bytes:
        raise ValueError("content-bearing argument exceeds byte bound")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def project_event(
    tool_name: object,
    raw_arguments: object,
    source_index: int,
    *,
    max_argument_bytes: int,
    max_value_bytes: int,
) -> tuple[dict[str, object], str, tuple[str, ...]]:
    if not isinstance(tool_name, str) or not SAFE_TOOL.fullmatch(tool_name):
        return (
            {
                "tool_name": "unsupported_tool",
                "args": {},
                "dialect": "none",
                "offset_seconds": source_index,
            },
            "invalid_tool_name",
            (),
        )

    base: dict[str, object] = {
        "tool_name": tool_name,
        "args": {},
        "dialect": "none",
        "offset_seconds": source_index,
    }
    if tool_name in SHELL_TOOLS:
        allowed = SHELL_ALLOWED_KEYS
        profile = "shell"
    elif tool_name in TOOL_ALLOWED_KEYS:
        allowed = TOOL_ALLOWED_KEYS[tool_name]
        profile = "structured"
    else:
        return base, "unsupported_tool", ()

    if not isinstance(raw_arguments, str):
        return base, "non_string_arguments", ()
    encoded = raw_arguments.encode("utf-8")
    if len(encoded) > max_argument_bytes:
        return base, "argument_too_large", ()
    try:
        arguments = json.loads(raw_arguments)
    except json.JSONDecodeError:
        return base, "malformed_arguments", ()
    if not isinstance(arguments, dict):
        return base, "non_object_arguments", ()

    unknown = tuple(sorted(str(key) for key in set(arguments) - allowed))
    if unknown:
        return base, "unknown_keys", unknown

    try:
        projected: dict[str, object] = {}
        for key in sorted(arguments):
            value = arguments[key]
            if key in CONTENT_KEYS:
                projected[f"{key}_fingerprint"] = content_fingerprint(value, max_value_bytes)
            else:
                projected[key] = bounded_value(value, max_value_bytes)

        if profile == "shell":
            command_keys = [key for key in ("cmd", "command") if key in arguments]
            if len(command_keys) != 1:
                return base, "missing_or_ambiguous_command", ()
            command = arguments[command_keys[0]]
            if not isinstance(command, str) or not command.strip():
                return base, "invalid_command", ()
            if len(command.encode("utf-8")) > max_value_bytes:
                return base, "command_too_large", ()
            projected.pop(command_keys[0], None)
            base["command"] = command
            base["dialect"] = "posix"
            cwd = projected.pop("cwd", None)
            if isinstance(cwd, str):
                base["cwd"] = cwd
        base["args"] = projected
        return base, "projected", ()
    except ValueError as exc:
        return base, str(exc), ()


def window_ranges(event_count: int, window_size: int, stride: int) -> Iterator[tuple[int, int]]:
    if event_count < 2:
        return
    if event_count <= window_size:
        yield 0, event_count
        return
    starts = list(range(0, event_count - window_size + 1, stride))
    final_start = event_count - window_size
    if not starts or starts[-1] != final_start:
        starts.append(final_start)
    for start in starts:
        yield start, start + window_size


def normalize_rows(
    source_rows: Iterable[dict[str, Any]],
    *,
    revision: str,
    split: str,
    policies: Sequence[str] = ("attack", "honest"),
    max_trajectories_per_policy: int = 25,
    window_size: int = 8,
    stride: int = 1,
    max_argument_bytes: int = 131_072,
    max_value_bytes: int = 65_536,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    validate_options(
        revision=revision,
        window_size=window_size,
        stride=stride,
        max_trajectories_per_policy=max_trajectories_per_policy,
        max_argument_bytes=max_argument_bytes,
        max_value_bytes=max_value_bytes,
    )
    selected, source_policy_counts = select_rows(source_rows, policies, max_trajectories_per_policy)
    rows: list[dict[str, Any]] = []
    event_status: Counter[str] = Counter()
    unknown_keys: Counter[str] = Counter()
    selected_policy_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    retained_events = 0
    source_error_events = 0

    for source in selected:
        trajectory_id = source.get("trajectory_id")
        policy = str(source.get("policy") or "missing")
        environment = str(source.get("environment") or "unknown")[:160]
        functions = source.get("action_functions")
        arguments = source.get("action_arguments_json")
        errors = source.get("action_has_error")
        if (
            not isinstance(trajectory_id, str)
            or not trajectory_id
            or len(trajectory_id) > 160
            or not re.fullmatch(r"[A-Za-z0-9._-]+", trajectory_id)
        ):
            skipped["missing_trajectory_id"] += 1
            continue
        if not isinstance(functions, list) or not isinstance(arguments, list):
            skipped["invalid_parallel_lists"] += 1
            continue
        if len(functions) != len(arguments):
            skipped["misaligned_parallel_lists"] += 1
            continue
        if source.get("number_of_actions") != len(functions):
            skipped["number_of_actions_mismatch"] += 1
            continue
        if not isinstance(errors, list) or len(errors) != len(functions):
            skipped["misaligned_error_list"] += 1
            continue
        source_error_events += sum(value is True for value in errors)

        events: list[dict[str, object]] = []
        for index, (tool_name, raw_arguments) in enumerate(zip(functions, arguments)):
            event, status, event_unknown_keys = project_event(
                tool_name,
                raw_arguments,
                index,
                max_argument_bytes=max_argument_bytes,
                max_value_bytes=max_value_bytes,
            )
            events.append(event)
            event_status[status] += 1
            unknown_keys.update(event_unknown_keys)
            retained_events += int(status == "projected")

        if len(events) < 2:
            skipped["fewer_than_two_events"] += 1
            continue

        selected_policy_counts[policy] += 1
        outcome_counts[f"{policy}:main_task_success={source.get('main_task_success') is True}"] += 1
        if source.get("has_side_task") is True:
            outcome_counts[f"{policy}:side_task_success={source.get('side_task_success') is True}"] += 1
        split_group = hashlib.sha256(f"{SOURCE_ID}\x00{revision}\x00{trajectory_id}".encode()).hexdigest()[:24]

        for start, end in window_ranges(len(events), window_size, stride):
            original_id = f"{trajectory_id}:{start}-{end}"
            categories = [
                "multi_tool_chain",
                "public_real_arguments",
                f"trajectory_policy_{policy}",
            ]
            rows.append(
                {
                    "schema_version": "1",
                    "id": f"linuxarena/{trajectory_id}/{start:03d}-{end:03d}",
                    "source": {
                        "dataset": SOURCE_ID,
                        "revision": revision,
                        "original_id": original_id,
                        "license": SOURCE_LICENSE,
                        "redistribution": SOURCE_REDISTRIBUTION,
                    },
                    "split": split,
                    "surface": "stateful",
                    "payload": {"events": events[start:end]},
                    "truth": {
                        "source_truth": "unknown",
                        "deterministic_truth": "contextual_or_dual_use",
                        "label_confidence": "medium",
                        "label_source": "linuxarena:trajectory-policy",
                        "applicability": "in_scope",
                        "expected_disposition": "detect_only",
                        "categories": categories,
                    },
                    "strata": {
                        "campaign": policy[:160],
                        "domain": environment,
                        "split_group": split_group,
                    },
                }
            )

    rows.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": SOURCE_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "source_redistribution": SOURCE_REDISTRIBUTION,
        "split": split,
        "selection": {
            "algorithm": "lowest sha256(source-id NUL trajectory-id) per requested policy",
            "policies": list(policies),
            "max_trajectories_per_policy": max_trajectories_per_policy,
            "source_policy_counts": dict(sorted(source_policy_counts.items())),
            "selected_policy_counts": dict(sorted(selected_policy_counts.items())),
        },
        "windowing": {
            "maximum_events": window_size,
            "stride": stride,
            "ordered": True,
            "row_count": len(rows),
        },
        "arguments": {
            "projected_events": retained_events,
            "event_status_counts": dict(sorted(event_status.items())),
            "unknown_key_counts": dict(sorted(unknown_keys.items())),
            "max_argument_bytes": max_argument_bytes,
            "max_value_bytes": max_value_bytes,
            "content_handling": "content-bearing values replaced by byte length and SHA-256",
            "untrusted_unknown_handling": "arguments omitted for unsupported tools or unknown keys",
        },
        "source_error_events": source_error_events,
        "trajectory_outcome_counts": dict(sorted(outcome_counts.items())),
        "skipped_trajectory_counts": dict(sorted(skipped.items())),
        "execution_performed": False,
        "excluded_source_fields": [
            "action_output",
            "action_output_error",
            "action_reasoning",
            "main_task",
            "side_task",
            "task_description",
        ],
        "metric_boundary": (
            "LinuxArena policy, has_side_task, and success fields are trajectory-level context, "
            "not per-call deterministic truth. Rows are unknown/detect-only and cannot support "
            "F1, precision, recall, or FPR until independently proof-labeled."
        ),
    }
    return rows, manifest


def validate_cases(rows: Sequence[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - exercised by CLI operators
        raise RuntimeError("jsonschema is required; add `--with jsonschema` to the uv command") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for index, row in enumerate(rows, 1):
        errors = sorted(validator.iter_errors(row), key=lambda item: list(item.path))
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.path) or "<root>"
            raise ValueError(f"normalized row {index} invalid at {location}: {error.message}")


def main() -> int:
    args = parse_args()
    rows, manifest = normalize_rows(
        parquet_rows(args.input),
        revision=args.source_revision,
        split=args.split,
        policies=args.policies,
        max_trajectories_per_policy=args.max_trajectories_per_policy,
        window_size=args.window_size,
        stride=args.stride,
        max_argument_bytes=args.max_argument_bytes,
        max_value_bytes=args.max_value_bytes,
    )
    validate_cases(rows, args.schema)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest.update(
        {
            "source_artifact_bytes": args.input.stat().st_size,
            "source_artifact_sha256": file_sha256(args.input),
            "output_sha256": file_sha256(args.output),
            "case_schema_sha256": file_sha256(args.schema),
        }
    )
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "manifest": str(manifest_path),
                "row_count": len(rows),
                "output_sha256": manifest["output_sha256"],
                "execution_performed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
