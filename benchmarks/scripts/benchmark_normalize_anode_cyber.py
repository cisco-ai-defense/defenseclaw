#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize AnodeAI Agent-Trace-Cyber trajectories into tool-call cases.

Only ``trajectory[].tool_call`` names and parameters become detector input.
Thoughts, observations, results, prompts, and critiques are never projected.
Source task/step success is retained as metadata, but it is deliberately not
treated as proof that any individual call is deterministically malicious.
Normalized rows use a staging split; ``benchmark_partition.py`` is the sole
authority that assigns development, validation, and test partitions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "anode-agent-trace-cyber-v1"
DATASET = "AnodeAI/Agent-Trace-Cyber-v1"
LICENSE = "Apache-2.0"
REDISTRIBUTION = "download-only"
STAGING_SPLIT = "development"
DEFAULT_MAX_ARGUMENT_BYTES = 64 * 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO_ROOT / "outputs/benchmark-data/sources/anode-agent-trace-cyber-v1/agent_trajectories.jsonl"
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
DEFAULT_DATASET_LOCK = REPO_ROOT / "benchmarks/datasets.lock.json"


@dataclass(frozen=True)
class ProjectedCall:
    trajectory_id: str
    trajectory_success: bool
    task_category: str
    step_id: str
    step_position: int
    step_success: bool
    tool_name: str
    parameters: dict[str, Any]
    argument_bytes: int
    group_digest: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--revision")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--dataset-lock", type=Path, default=DEFAULT_DATASET_LOCK)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return (serialized + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_digest(*parts: str) -> str:
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def required_text(value: object, *, field: str, max_length: int = 240) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    result = value.strip()
    if len(result) > max_length:
        raise ValueError(f"{field} exceeds the configured length bound")
    return result


def step_identity(value: object) -> str:
    if isinstance(value, bool):
        raise ValueError("invalid trajectory step identity")
    if isinstance(value, int):
        return str(value)
    return required_text(value, field="trajectory step identity", max_length=120)


def normalized_category(value: object) -> str:
    raw = required_text(value, field="task category", max_length=160)
    normalized = "_".join(part for part in "".join(char.casefold() if char.isalnum() else " " for char in raw).split())
    return normalized[:160] or "unknown"


def parse_parameters(value: object, *, max_argument_bytes: int) -> tuple[dict[str, Any], int]:
    if not isinstance(value, dict):
        raise ValueError("tool-call parameters must be a JSON object")
    try:
        data = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("tool-call parameters are not bounded JSON data") from exc
    if len(data) > max_argument_bytes:
        raise ValueError("tool-call parameters exceed the configured byte bound")
    return value, len(data)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON object") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{line_number}: expected JSON object")
            rows.append(row)
    return rows


def project_trajectory(row: Mapping[str, Any], *, max_argument_bytes: int) -> tuple[ProjectedCall, ...]:
    trajectory_id = required_text(row.get("id"), field="trajectory identity")
    trajectory_success = row.get("is_successful")
    if not isinstance(trajectory_success, bool):
        raise ValueError("trajectory success metadata must be boolean")
    task_category = normalized_category(row.get("task_category"))
    trajectory = row.get("trajectory")
    if not isinstance(trajectory, list) or not trajectory:
        raise ValueError("trajectory must be a non-empty array")

    group_digest = stable_digest("anode-cyber-trajectory-group-v1", DATASET, trajectory_id)
    projected: list[ProjectedCall] = []
    seen_steps: set[str] = set()
    for position, step in enumerate(trajectory):
        if not isinstance(step, dict):
            raise ValueError("trajectory step must be an object")
        source_step_id = step_identity(step.get("step"))
        if source_step_id in seen_steps:
            raise ValueError("duplicate step identity within trajectory")
        seen_steps.add(source_step_id)
        success = step.get("success")
        if not isinstance(success, bool):
            raise ValueError("step success metadata must be boolean")
        tool_call = step.get("tool_call")
        if not isinstance(tool_call, dict):
            raise ValueError("trajectory step tool_call must be an object")
        tool_name = required_text(tool_call.get("tool_name"), field="tool name")
        parameters, argument_bytes = parse_parameters(
            tool_call.get("parameters"), max_argument_bytes=max_argument_bytes
        )
        projected.append(
            ProjectedCall(
                trajectory_id=trajectory_id,
                trajectory_success=trajectory_success,
                task_category=task_category,
                step_id=source_step_id,
                step_position=position,
                step_success=success,
                tool_name=tool_name,
                parameters=parameters,
                argument_bytes=argument_bytes,
                group_digest=group_digest,
            )
        )
    return tuple(projected)


def locked_provenance(path: Path) -> dict[str, str]:
    lock = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    if not isinstance(lock, dict) or not isinstance(lock.get("datasets"), list):
        raise ValueError("dataset lock has an invalid shape")
    matches = [entry for entry in lock["datasets"] if isinstance(entry, dict) and entry.get("id") == DATASET]
    if len(matches) != 1:
        raise ValueError(f"dataset lock must contain exactly one {DATASET} entry")
    entry = matches[0]
    required = ("revision", "license", "redistribution")
    if any(not isinstance(entry.get(field), str) or not entry[field] for field in required):
        raise ValueError(f"dataset lock entry for {DATASET} has invalid provenance")
    return {field: str(entry[field]) for field in required}


def validate_locked_provenance(revision: str, dataset_lock: Path) -> None:
    locked = locked_provenance(dataset_lock)
    actual = {"revision": revision, "license": LICENSE, "redistribution": REDISTRIBUTION}
    if actual != locked:
        raise ValueError(f"provenance for {DATASET} differs from dataset lock")


def make_case(call: ProjectedCall, *, revision: str) -> dict[str, Any]:
    trajectory_digest = stable_digest("anode-cyber-trajectory-case-v1", call.trajectory_id)[:24]
    original_id = f"trajectory:{call.trajectory_id}/step:{call.step_id}/position:{call.step_position:06d}"
    if len(original_id) > 240:
        raise ValueError("projected source identity exceeds the schema bound")
    categories = [
        "agent_trajectory",
        "real_tool_arguments",
        "cyber_task_pending_bounded_proof",
        f"source_trajectory_success:{str(call.trajectory_success).lower()}",
        f"source_step_success:{str(call.step_success).lower()}",
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"anode-cyber/{trajectory_digest}/p{call.step_position:06d}",
        "source": {
            "dataset": DATASET,
            "revision": revision,
            "original_id": original_id,
            "license": LICENSE,
            "redistribution": REDISTRIBUTION,
        },
        "split": STAGING_SPLIT,
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "tool_name": call.tool_name,
            "args": call.parameters,
            "dialect": "none",
        },
        "truth": {
            "source_truth": "unknown",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "low",
            "label_source": "anode:cyber_task_completion_pending_bounded_proof",
            "applicability": "out_of_scope",
            "expected_disposition": "allow",
            "categories": categories,
            "exclusion_reason": "individual tool call requires later GPT-OSS bounded-proof annotation",
        },
        "strata": {
            "ecosystem": "agent_tool_call",
            "campaign": "cyber_task_pending_bounded_proof",
            "domain": call.task_category,
            "hard_negative": False,
            "split_group": call.group_digest[:24],
            "trajectory_id": call.group_digest[:24],
            "sequence_index": call.step_position,
            "call_index": 0,
        },
    }


def build_corpus(
    source: Path,
    *,
    revision: str,
    dataset_lock: Path = DEFAULT_DATASET_LOCK,
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if max_argument_bytes <= 0:
        raise ValueError("max argument bytes must be positive")
    revision = required_text(revision, field="dataset revision", max_length=160)
    validate_locked_provenance(revision, dataset_lock)

    calls: list[ProjectedCall] = []
    seen_trajectories: set[str] = set()
    source_record_digests: list[str] = []
    for row in load_jsonl(source):
        trajectory_id = required_text(row.get("id"), field="trajectory identity")
        if trajectory_id in seen_trajectories:
            raise ValueError("duplicate trajectory identity")
        seen_trajectories.add(trajectory_id)
        projected = project_trajectory(row, max_argument_bytes=max_argument_bytes)
        calls.extend(projected)
        source_record_digests.append(
            stable_digest(
                "anode-cyber-source-record-v1",
                trajectory_id,
                sha256_bytes(
                    canonical_json(
                        [
                            {
                                "position": call.step_position,
                                "step": call.step_id,
                                "tool_name": call.tool_name,
                                "parameters": call.parameters,
                            }
                            for call in projected
                        ]
                    )
                ),
            )
        )

    groups = {call.group_digest for call in calls}
    if len(groups) != len(seen_trajectories):
        raise ValueError("trajectory group digest collision")
    rows = [make_case(call, revision=revision) for call in calls]
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate case IDs")

    trajectory_success_counts = Counter(call.trajectory_success for call in calls if call.step_position == 0)
    step_success_counts = Counter(call.step_success for call in calls)
    output_data = b"".join(canonical_json(row) for row in rows)
    normalization_manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET],
        "cases": len(rows),
        "counts": {DATASET: len(rows)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {
            "anode_cyber": {
                "source_rows": len(seen_trajectories),
                "trajectory_groups": len(groups),
                "tool_call_cases": len(rows),
                "source_trajectory_success_false": trajectory_success_counts[False],
                "source_trajectory_success_true": trajectory_success_counts[True],
                "source_step_success_false": step_success_counts[False],
                "source_step_success_true": step_success_counts[True],
            }
        },
        "output_sha256": sha256_bytes(output_data),
    }
    return rows, normalization_manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path, *, max_argument_bytes: int) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    groups: dict[str, str] = {}
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
        payload = row["payload"]
        if set(payload) != {"direction", "tool_name", "args", "dialect"}:
            raise ValueError("tool-call payload contains excluded trajectory fields")
        if len(canonical_json(payload["args"])) > max_argument_bytes:
            raise ValueError("tool-call arguments exceed the configured byte bound")
        group = row["strata"]["split_group"]
        split = row["split"]
        if group in groups and groups[group] != split:
            raise ValueError("trajectory group crosses benchmark splits")
        groups[group] = split


def resolve_revision(source: Path, override: str | None) -> str:
    if override:
        return required_text(override, field="dataset revision", max_length=160)
    metadata = source.parent / ".cache/huggingface/download" / f"{source.name}.metadata"
    if not metadata.is_file():
        raise ValueError(f"missing Hugging Face revision metadata for {source.name}")
    lines = metadata.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"empty Hugging Face revision metadata for {source.name}")
    return required_text(lines[0], field="dataset revision", max_length=160)


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
    normalization_manifest: Mapping[str, Any],
    *,
    output: Path,
    manifest_path: Path,
) -> None:
    output_data = b"".join(canonical_json(row) for row in rows)
    if normalization_manifest.get("output_sha256") != sha256_bytes(output_data):
        raise ValueError("normalization manifest does not bind output bytes")
    atomic_write(output, output_data)
    atomic_write(manifest_path, canonical_json(normalization_manifest))


def main() -> int:
    args = parse_args()
    revision = resolve_revision(args.source, args.revision)
    rows, manifest = build_corpus(
        args.source,
        revision=revision,
        dataset_lock=args.dataset_lock,
        max_argument_bytes=args.max_argument_bytes,
    )
    validate_cases(rows, args.schema, max_argument_bytes=args.max_argument_bytes)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_outputs(
        rows,
        manifest,
        output=args.output,
        manifest_path=manifest_path,
    )
    print(
        json.dumps(
            {
                "case_count": manifest["cases"],
                "output_sha256": manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
