#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize local AntiEval trajectories into deterministic tool-call cases.

Only structured assistant ``tool_calls`` are projected. Message content,
observations, tool results, and payload execution are deliberately outside this
adapter. Repeated model rollouts share an underlying task group so the sole
authoritative partitioner, ``benchmark_partition.py``, can keep them together.
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
ADAPTER = "antieval-trajectories-v1"
STAGING_SPLIT = "development"
DEFAULT_MAX_ARGUMENT_BYTES = 64 * 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
DEFAULT_SOURCE_ROOT = REPO_ROOT / "outputs/benchmark-data/sources"


@dataclass(frozen=True)
class DatasetSpec:
    family: str
    dataset: str
    directory_name: str
    license: str
    redistribution: str
    source_truth: str
    deterministic_truth: str
    label_confidence: str
    expected_disposition: str
    applicability: str
    label_source: str
    campaign: str
    exclusion_reason: str = ""


DATASET_SPECS = {
    "agentharm": DatasetSpec(
        family="agentharm",
        dataset="antieval/agentharm-trajectories",
        directory_name="antieval-agentharm-trajectories",
        license="unspecified",
        redistribution="download-only",
        source_truth="malicious",
        deterministic_truth="contextual_or_dual_use",
        label_confidence="medium",
        expected_disposition="allow",
        applicability="out_of_scope",
        label_source="antieval:agentharm_harmful_objective",
        campaign="harmful_objective_pending_bounded_proof",
        exclusion_reason="individual call requires bounded-proof adjudication",
    ),
    "cybench": DatasetSpec(
        family="cybench",
        dataset="antieval/cybench-trajectories",
        directory_name="antieval-cybench-trajectories",
        license="unspecified",
        redistribution="download-only",
        source_truth="unknown",
        deterministic_truth="contextual_or_dual_use",
        label_confidence="low",
        expected_disposition="allow",
        applicability="out_of_scope",
        label_source="antieval:cybench_pending_bounded_proof",
        campaign="cyber_objective_pending_bounded_proof",
        exclusion_reason="source does not prove individual-call maliciousness",
    ),
    "swebench": DatasetSpec(
        family="swebench",
        dataset="antieval/swebench-trajectories",
        directory_name="antieval-swebench-trajectories",
        license="unspecified",
        redistribution="download-only",
        source_truth="benign",
        deterministic_truth="benign",
        label_confidence="high",
        expected_disposition="allow",
        applicability="in_scope",
        label_source="antieval:swebench_source_truth",
        campaign="benign_software_engineering",
    ),
}


@dataclass(frozen=True)
class ProjectedCall:
    tool_name: str
    arguments: dict[str, Any]
    sequence_index: int
    call_index: int
    argument_bytes: int


@dataclass(frozen=True)
class Rollout:
    spec: DatasetSpec
    group_digest: str
    rollout_digest: str
    calls: tuple[ProjectedCall, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
    for family in DATASET_SPECS:
        parser.add_argument(f"--{family}-revision")
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


def required_text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    return value.strip()


def task_identity(spec: DatasetSpec, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if spec.family == "agentharm":
        return (required_text(metadata.get("id_original"), field="AgentHarm task identity"),)
    if spec.family == "cybench":
        return (
            required_text(metadata.get("eval_file_path"), field="CyBench eval file identity"),
            required_text(metadata.get("eval_name"), field="CyBench eval name"),
            required_text(metadata.get("variant_name"), field="CyBench variant identity"),
        )
    if spec.family == "swebench":
        return (
            required_text(metadata.get("repo"), field="SWE-bench repository identity"),
            required_text(metadata.get("base_commit"), field="SWE-bench base commit identity"),
        )
    raise ValueError("unsupported dataset family")


def parse_arguments(value: object, *, max_argument_bytes: int) -> tuple[dict[str, Any], int]:
    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=strict_object)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError("tool-call arguments are not valid structured JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("tool-call arguments must be a JSON object")
    try:
        data = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("tool-call arguments are not bounded JSON data") from exc
    size = len(data)
    if size > max_argument_bytes:
        raise ValueError("tool-call arguments exceed the configured byte bound")
    return value, size


def parse_tool_call(call: object, *, max_argument_bytes: int, sequence_index: int, call_index: int) -> ProjectedCall:
    if not isinstance(call, dict):
        raise ValueError("tool call must be an object")
    function = call.get("function")
    if isinstance(function, str):
        tool_name = required_text(function, field="tool function name")
        raw_arguments = call.get("arguments")
    elif isinstance(function, dict):
        tool_name = required_text(function.get("name"), field="tool function name")
        raw_arguments = function.get("arguments")
    else:
        raise ValueError("tool call has no structured function")
    if len(tool_name) > 240:
        raise ValueError("tool function name exceeds the schema bound")
    arguments, argument_bytes = parse_arguments(raw_arguments, max_argument_bytes=max_argument_bytes)
    return ProjectedCall(tool_name, arguments, sequence_index, call_index, argument_bytes)


def project_calls(messages: object, *, max_argument_bytes: int) -> tuple[ProjectedCall, ...]:
    if not isinstance(messages, list):
        raise ValueError("trajectory input must be a message array")
    result: list[ProjectedCall] = []
    sequence_index = 0
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("trajectory message must be an object")
        if "tool_calls" not in message:
            continue
        if message.get("role") != "assistant":
            raise ValueError("structured tool calls must belong to an assistant message")
        calls = message.get("tool_calls")
        if not isinstance(calls, list):
            raise ValueError("assistant tool_calls must be an array")
        for call_index, call in enumerate(calls):
            result.append(
                parse_tool_call(
                    call,
                    max_argument_bytes=max_argument_bytes,
                    sequence_index=sequence_index,
                    call_index=call_index,
                )
            )
            sequence_index += 1
    return tuple(result)


def resolve_revision(directory: Path, override: str | None) -> str:
    if override:
        return required_text(override, field="dataset revision")
    revisions: set[str] = set()
    metadata_root = directory / ".cache/huggingface/download"
    for source_file in sorted(directory.glob("*.jsonl"), key=lambda item: item.name):
        metadata_file = metadata_root / f"{source_file.name}.metadata"
        if not metadata_file.is_file():
            raise ValueError(f"missing Hugging Face revision metadata for {source_file.name}")
        first_line = metadata_file.read_text(encoding="utf-8").splitlines()
        if not first_line:
            raise ValueError(f"empty Hugging Face revision metadata for {source_file.name}")
        revisions.add(required_text(first_line[0], field="dataset revision"))
    if len(revisions) != 1:
        raise ValueError("source files do not resolve to one dataset revision")
    return next(iter(revisions))


def source_truth(spec: DatasetSpec) -> dict[str, Any]:
    truth: dict[str, Any] = {
        "source_truth": spec.source_truth,
        "deterministic_truth": spec.deterministic_truth,
        "label_confidence": spec.label_confidence,
        "label_source": spec.label_source,
        "applicability": spec.applicability,
        "expected_disposition": spec.expected_disposition,
        "categories": ["agent_trajectory", "real_tool_arguments", spec.family, spec.campaign],
    }
    if spec.exclusion_reason:
        truth["exclusion_reason"] = spec.exclusion_reason
    return truth


def make_case(rollout: Rollout, call: ProjectedCall, *, revision: str) -> dict[str, Any]:
    ordinal = f"sequence-{call.sequence_index:06d}/call-{call.call_index:03d}"
    original_id = f"rollout-{rollout.rollout_digest[:24]}/{ordinal}"
    case_id = (
        f"antieval-{rollout.spec.family}/{rollout.rollout_digest[:24]}"
        f"/s{call.sequence_index:06d}-c{call.call_index:03d}"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "id": case_id,
        "source": {
            "dataset": rollout.spec.dataset,
            "revision": revision,
            "original_id": original_id,
            "license": rollout.spec.license,
            "redistribution": rollout.spec.redistribution,
        },
        "split": STAGING_SPLIT,
        "surface": "action",
        "payload": {
            "direction": "tool_call",
            "tool_name": call.tool_name,
            "args": call.arguments,
            "dialect": "none",
        },
        "truth": source_truth(rollout.spec),
        "strata": {
            "ecosystem": "agent_tool_call",
            "campaign": rollout.spec.campaign,
            "domain": rollout.spec.family,
            "hard_negative": rollout.spec.family == "swebench",
            "split_group": rollout.group_digest[:24],
            "trajectory_id": rollout.rollout_digest[:24],
            "sequence_index": call.sequence_index,
            "call_index": call.call_index,
        },
    }


def load_rollouts(
    source_directories: Mapping[str, Path],
    *,
    max_argument_bytes: int,
) -> tuple[list[Rollout], dict[str, Any]]:
    rollouts: list[Rollout] = []
    seen_rollouts: set[str] = set()
    statistics: dict[str, Any] = {}
    for family, spec in DATASET_SPECS.items():
        directory = source_directories[family]
        files = sorted(directory.glob("*.jsonl"), key=lambda item: item.name)
        if not files:
            raise ValueError(f"no JSONL source files for {family}")
        family_rows = 0
        family_calls = 0
        emitted_rollouts = 0
        groups: set[str] = set()
        source_record_digests: list[str] = []
        file_counts: dict[str, int] = {}
        for source_file in files:
            records = load_jsonl(source_file)
            file_counts[source_file.name] = len(records)
            family_rows += len(records)
            for row in records:
                metadata = row.get("metadata")
                if not isinstance(metadata, dict):
                    raise ValueError("trajectory metadata must be an object")
                group_parts = task_identity(spec, metadata)
                group_digest = stable_digest("antieval-task-group-v1", spec.dataset, *group_parts)
                groups.add(group_digest)
                row_id = required_text(row.get("id"), field="trajectory row identity")
                model = required_text(metadata.get("model"), field="trajectory model identity")
                rollout_digest = stable_digest("antieval-rollout-v1", spec.dataset, group_digest, row_id, model)
                if rollout_digest in seen_rollouts:
                    raise ValueError("duplicate trajectory rollout identity")
                seen_rollouts.add(rollout_digest)
                calls = project_calls(row.get("input"), max_argument_bytes=max_argument_bytes)
                call_identity = [
                    {
                        "tool_name": call.tool_name,
                        "arguments": call.arguments,
                        "sequence_index": call.sequence_index,
                        "call_index": call.call_index,
                    }
                    for call in calls
                ]
                source_record_digests.append(
                    stable_digest(
                        "antieval-source-record-v1",
                        rollout_digest,
                        sha256_bytes(canonical_json(call_identity)),
                    )
                )
                if not calls:
                    continue
                emitted_rollouts += 1
                family_calls += len(calls)
                rollouts.append(Rollout(spec, group_digest, rollout_digest, calls))
        statistics[family] = {
            "source_rows": family_rows,
            "source_files": file_counts,
            "task_groups": len(groups),
            "rollouts_with_tool_calls": emitted_rollouts,
            "tool_call_cases": family_calls,
            "source_record_set_sha256": stable_digest(*sorted(source_record_digests)),
        }
    return rollouts, statistics


def build_corpus(
    source_directories: Mapping[str, Path],
    *,
    revisions: Mapping[str, str],
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if max_argument_bytes <= 0:
        raise ValueError("max argument bytes must be positive")
    if set(source_directories) != set(DATASET_SPECS) or set(revisions) != set(DATASET_SPECS):
        raise ValueError("source directories and revisions must cover every AntiEval family exactly")
    rollouts, statistics = load_rollouts(
        source_directories,
        max_argument_bytes=max_argument_bytes,
    )
    rows: list[dict[str, Any]] = []
    for rollout in rollouts:
        revision = revisions[rollout.spec.family]
        rows.extend(make_case(rollout, call, revision=revision) for call in rollout.calls)
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate case IDs")

    dataset_case_counts = Counter(str(row["source"]["dataset"]) for row in rows)
    output_data = b"".join(canonical_json(row) for row in rows)
    normalization_manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_SPECS[family].dataset for family in sorted(DATASET_SPECS)],
        "cases": len(rows),
        "counts": dict(sorted(dataset_case_counts.items())),
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {
            family: {
                "source_rows": int(statistics[family]["source_rows"]),
                "task_groups": int(statistics[family]["task_groups"]),
                "rollouts_with_tool_calls": int(statistics[family]["rollouts_with_tool_calls"]),
                "tool_call_cases": int(statistics[family]["tool_call_cases"]),
            }
            for family in sorted(statistics)
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
            raise ValueError("task group crosses benchmark splits")
        groups[group] = split


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
    source_directories = {family: args.source_root / spec.directory_name for family, spec in DATASET_SPECS.items()}
    revisions = {
        family: resolve_revision(source_directories[family], getattr(args, f"{family}_revision"))
        for family in DATASET_SPECS
    }
    rows, manifest = build_corpus(
        source_directories,
        revisions=revisions,
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
