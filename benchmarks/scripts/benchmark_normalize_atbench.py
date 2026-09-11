#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize the Apache-2.0 ATBench family into deterministic tool-call cases.

The adapter projects only assistant tool invocations and their concrete
arguments. User messages, assistant prose/reasoning, tool observations, and
tool results are never copied into detector input. Atomic calls from unsafe
trajectories remain proof-pending and out of scored scope; only complete
stateful rows inherit an unsafe trajectory label. Normalized rows use the
schema-valid ``smoke`` split only as a pre-partition placeholder;
``benchmark_partition.py`` is the sole authority for development, validation,
and test assignments.
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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "atbench-family-v1"
GROUPING_STRATEGY = "atbench-trajectory-identity-v1"
PARTITION_AUTHORITY = "benchmarks/scripts/benchmark_partition.py"
PRE_PARTITION_SPLIT = "smoke"
DEFAULT_MAX_ARGUMENT_BYTES = 64 * 1024
MAX_STATEFUL_EVENTS = 64
CHAIN_BOUND = 8
WINDOW_OVERLAP = CHAIN_BOUND - 1

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
DEFAULT_SOURCE_ROOT = REPO_ROOT / "outputs/benchmark-data/sources"
SAFE_CATEGORY = re.compile(r"[^a-z0-9._:-]+")
HEX_24 = re.compile(r"^[0-9a-f]{24}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_KEYS = frozenset({
    "schema_version", "datasets", "cases", "counts", "exact_payload_duplicates_removed",
    "label_conflicts_excluded", "adapter_statistics", "output_sha256",
})
GROUP_MANIFEST_KEYS = frozenset({
    "schema_version", "kind", "grouping_strategy", "partition_authority", "group_count",
    "case_count", "groups", "corpus_sha256",
})
GROUP_MANIFEST_GROUP_KEYS = frozenset({
    "group", "dataset", "config", "cases", "action_cases", "stateful_cases",
})
SOURCE_KEYS = frozenset({"dataset", "revision", "license", "redistribution"})
SOURCE_STAT_KEYS = frozenset({
    "source_file", "source_file_sha256", "source_records", "quarantined_records", "source_safe",
    "source_unsafe", "trajectories_with_tool_calls", "trajectories_without_tool_calls", "tool_calls",
    "source_record_set_sha256",
})
QUARANTINE_KEYS = frozenset({
    "atbench_id_range", "atbench_codex_id_count", "atbench_claw_physical_record_count",
})


@dataclass(frozen=True)
class DatasetSpec:
    family: str
    dataset: str
    directory_name: str
    label_source: str


DATASET_SPECS = {
    "codex": DatasetSpec(
        family="codex",
        dataset="AI45Research/ATBench-Codex",
        directory_name="atbench-codex",
        label_source="atbench-codex:trajectory_is_safe",
    ),
    "claw": DatasetSpec(
        family="claw",
        dataset="AI45Research/ATBench-Claw",
        directory_name="atbench-claw",
        label_source="atbench-claw:trajectory_is_safe",
    ),
    "atbench": DatasetSpec(
        family="atbench",
        dataset="AI45Research/ATBench",
        directory_name="atbench",
        label_source="atbench:trajectory_label",
    ),
}


@dataclass(frozen=True)
class ProjectedCall:
    tool_name: str
    arguments: Any
    sequence_index: int
    call_index: int
    command: str = ""
    outcome: str = "unknown"


@dataclass(frozen=True)
class Trajectory:
    spec: DatasetSpec
    config: str
    identity_digest: str
    group_digest: str
    source_safe: bool
    taxonomy: tuple[str, ...]
    calls: tuple[ProjectedCall, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--group-manifest", "--freeze-manifest", dest="group_manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-argument-bytes", type=int, default=DEFAULT_MAX_ARGUMENT_BYTES)
    for family in DATASET_SPECS:
        parser.add_argument(f"--{family}-revision")
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


def required_text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid {field}")
    return value.strip()


def load_json_array(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path}: invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{path}: expected a JSON array of objects")
    return value


def normalized_category(value: object, *, prefix: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = SAFE_CATEGORY.sub("_", value.casefold()).strip("_")
    if not normalized or normalized in {"none", "null", "n/a", "safe"}:
        return None
    return f"{prefix}:{normalized[:96]}"


def parse_argument_value(value: object, *, max_argument_bytes: int) -> tuple[Any, int]:
    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=strict_object)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError("tool-call arguments are not valid JSON") from exc
    try:
        encoded = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("tool-call arguments are not bounded JSON data") from exc
    if len(encoded) > max_argument_bytes:
        raise ValueError("tool-call arguments exceed the configured byte bound")
    return value, len(encoded)


def command_from_arguments(arguments: object) -> str:
    if not isinstance(arguments, dict):
        return ""
    for key in ("command", "cmd"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            if len(value) > 1024 * 1024:
                raise ValueError("tool-call command exceeds the case schema bound")
            return value.replace("\x00", "")
    return ""


SUCCESS_STATES = frozenset({"complete", "completed", "ok", "passed", "success", "succeeded"})
FAILURE_STATES = frozenset({"cancelled", "denied", "error", "failed", "failure"})


def explicit_outcome(value: object) -> str:
    """Return an outcome only when the source provides an explicit execution marker."""
    if not isinstance(value, Mapping):
        return "unknown"
    for key in ("success", "succeeded", "ok"):
        marker = value.get(key)
        if isinstance(marker, bool):
            return "succeeded" if marker else "failed"
    for key in ("isError", "is_error"):
        marker = value.get(key)
        if isinstance(marker, bool):
            return "failed" if marker else "succeeded"
    for key in ("status", "outcome", "state", "result_status"):
        marker = value.get(key)
        if not isinstance(marker, str):
            continue
        normalized = marker.strip().casefold()
        if normalized in SUCCESS_STATES:
            return "succeeded"
        if normalized in FAILURE_STATES:
            return "failed"
    return "unknown"


def call_identity(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    wrapped = value.get("toolCall")
    if isinstance(wrapped, Mapping):
        value = wrapped
    for key in ("call_id", "callId", "tool_call_id", "toolCallId", "id"):
        identifier = value.get(key)
        if isinstance(identifier, (str, int)) and str(identifier):
            return str(identifier)
    return None


def explicit_result_outcomes(value: object) -> dict[str, str]:
    """Collect only ID-bound result statuses without retaining result payloads."""
    outcomes: dict[str, str] = {}

    def visit(item: object) -> None:
        if isinstance(item, list):
            for child in item:
                visit(child)
            return
        if not isinstance(item, Mapping):
            return
        role = str(item.get("role", "")).casefold().replace("_", "")
        item_type = str(item.get("type", "")).casefold().replace("_", "")
        is_result = role in {"tool", "toolresult", "function"} or item_type in {
            "functioncalloutput", "toolresult", "toolresponse",
        }
        if is_result:
            identifier = call_identity(item)
            outcome = explicit_outcome(item)
            if identifier is not None and outcome != "unknown":
                outcomes[identifier] = outcome
        for key in ("payload", "message", "content", "events"):
            child = item.get(key)
            if isinstance(child, (Mapping, list)):
                visit(child)

    visit(value)
    return outcomes


def parse_call(
    value: object,
    *,
    sequence_index: int,
    call_index: int,
    max_argument_bytes: int,
) -> ProjectedCall:
    if not isinstance(value, dict):
        raise ValueError("tool call must be an object")
    source_outcome = explicit_outcome(value)
    wrapped = value.get("toolCall")
    if isinstance(wrapped, dict):
        value = wrapped
        if source_outcome == "unknown":
            source_outcome = explicit_outcome(value)
    function = value.get("function")
    if isinstance(function, dict):
        name = function.get("name")
        raw_arguments = function.get("arguments")
        if source_outcome == "unknown":
            source_outcome = explicit_outcome(function)
    else:
        name = value.get("name")
        raw_arguments = value.get("arguments", value.get("args", {}))
    tool_name = required_text(name, field="tool-call name")
    if len(tool_name) > 240:
        raise ValueError("tool-call name exceeds the case schema bound")
    arguments, _ = parse_argument_value(raw_arguments, max_argument_bytes=max_argument_bytes)
    return ProjectedCall(
        tool_name=tool_name,
        arguments=arguments,
        sequence_index=sequence_index,
        call_index=call_index,
        command=command_from_arguments(arguments),
        outcome=source_outcome,
    )


def bind_result_outcome(
    call: ProjectedCall,
    source_call: object,
    result_outcomes: Mapping[str, str],
) -> ProjectedCall:
    if call.outcome != "unknown":
        return call
    identifier = call_identity(source_call)
    if identifier is None or identifier not in result_outcomes:
        return call
    return replace(call, outcome=result_outcomes[identifier])


def codex_calls(row: Mapping[str, Any], *, max_argument_bytes: int) -> tuple[ProjectedCall, ...]:
    rollout = row.get("codex_rollout")
    if not isinstance(rollout, list):
        raise ValueError("ATBench-Codex row requires codex_rollout")
    calls: list[ProjectedCall] = []
    result_outcomes = explicit_result_outcomes(rollout)
    for event in rollout:
        if not isinstance(event, dict) or event.get("type") != "response_item":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("Codex response_item payload must be an object")
        # A result item has call_id/output/type. Only call items have name and
        # arguments, so observations cannot enter this projection.
        if "name" not in payload or "arguments" not in payload:
            continue
        source_call = payload
        calls.append(
            bind_result_outcome(
                parse_call(
                    source_call,
                    sequence_index=len(calls),
                    call_index=0,
                    max_argument_bytes=max_argument_bytes,
                ),
                source_call,
                result_outcomes,
            )
        )
    return tuple(calls)


def content_calls(contents: object, *, max_argument_bytes: int) -> tuple[ProjectedCall, ...]:
    if not isinstance(contents, list):
        raise ValueError("ATBench trajectory content must be an array")
    calls: list[ProjectedCall] = []
    result_outcomes = explicit_result_outcomes(contents)

    def append_call(source_call: object, *, call_index: int) -> None:
        calls.append(
            bind_result_outcome(
                parse_call(
                    source_call,
                    sequence_index=len(calls),
                    call_index=call_index,
                    max_argument_bytes=max_argument_bytes,
                ),
                source_call,
                result_outcomes,
            )
        )

    def visit_message(value: object) -> None:
        if isinstance(value, list):
            for child in value:
                visit_message(child)
            return
        if not isinstance(value, dict):
            raise ValueError("ATBench trajectory message must be an object")
        role = str(value.get("role", "")).casefold()
        if role not in {"assistant", "agent"}:
            return
        action = value.get("action")
        if isinstance(action, str):
            try:
                parsed = json.loads(action, object_pairs_hook=strict_object)
            except (json.JSONDecodeError, ValueError):
                # ATBench500 includes non-call terminal action markers. They
                # are not concrete tool calls and are intentionally omitted.
                parsed = None
            if isinstance(parsed, dict) and "error" not in parsed and "name" in parsed:
                append_call(parsed, call_index=0)
        elif isinstance(action, dict) and "error" not in action and "name" in action:
            append_call(action, call_index=0)

        structured = value.get("tool_calls", value.get("toolCalls"))
        if structured is not None:
            if not isinstance(structured, list):
                raise ValueError("assistant tool_calls must be an array")
            for call_index, call in enumerate(structured):
                append_call(call, call_index=call_index)

        content = value.get("content")
        if isinstance(content, list):
            call_index = 0
            for item in content:
                if not isinstance(item, dict):
                    continue
                item_type = str(item.get("type", "")).casefold().replace("_", "")
                if item_type in {"toolcall", "functioncall"} or isinstance(item.get("toolCall"), dict):
                    append_call(item, call_index=call_index)
                    call_index += 1

    for entry in contents:
        visit_message(entry)
    return tuple(calls)


def claw_calls(row: Mapping[str, Any], *, max_argument_bytes: int) -> tuple[ProjectedCall, ...]:
    trajectory = row.get("trajectory")
    if not isinstance(trajectory, dict) or not isinstance(trajectory.get("events"), list):
        raise ValueError("ATBench-Claw row requires trajectory.events")
    calls: list[ProjectedCall] = []
    result_outcomes = explicit_result_outcomes(trajectory["events"])
    for event in trajectory["events"]:
        if not isinstance(event, dict):
            raise ValueError("OpenClaw trajectory event must be an object")
        message = event.get("message", event)
        if not isinstance(message, dict):
            raise ValueError("OpenClaw message event must be an object")
        if str(message.get("role", "")).casefold() != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        call_index = 0
        for item in content:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type", "")).casefold().replace("_", "")
            if item_type not in {"toolcall", "functioncall"} and not isinstance(item.get("toolCall"), dict):
                continue
            calls.append(
                bind_result_outcome(
                    parse_call(
                        item,
                        sequence_index=len(calls),
                        call_index=call_index,
                        max_argument_bytes=max_argument_bytes,
                    ),
                    item,
                    result_outcomes,
                )
            )
            call_index += 1
    return tuple(calls)


def source_identity(spec: DatasetSpec, row: Mapping[str, Any], physical_index: int) -> str:
    if spec.family == "codex":
        value = row.get("id")
    elif spec.family == "claw":
        trajectory = row.get("trajectory")
        value = None
        if isinstance(trajectory, dict):
            for key in ("id", "session_id", "sessionId"):
                if trajectory.get(key) not in (None, ""):
                    value = trajectory[key]
                    break
        if value is None:
            value = row.get("id")
    else:
        value = row.get("id", row.get("conv_id"))
    if isinstance(value, (str, int)) and str(value):
        return str(value)
    # Physical position is included only to disambiguate exact duplicate
    # records; the canonical digest keeps the identity value-free downstream.
    return f"physical-{physical_index}-{sha256_bytes(canonical_json(row))}"


def source_safe(spec: DatasetSpec, row: Mapping[str, Any]) -> bool:
    if spec.family == "codex":
        value = row.get("is_safe")
        if not isinstance(value, bool):
            raise ValueError("ATBench-Codex is_safe must be boolean")
        return value
    if spec.family == "claw":
        labels = row.get("labels")
        if not isinstance(labels, dict) or not isinstance(labels.get("is_safe"), bool):
            raise ValueError("ATBench-Claw labels.is_safe must be boolean")
        return bool(labels["is_safe"])
    value = row.get("label")
    if type(value) is not int or value not in (0, 1):
        raise ValueError("ATBench label must be 0 or 1")
    return value == 0


def taxonomy_categories(spec: DatasetSpec, row: Mapping[str, Any]) -> tuple[str, ...]:
    labels = row.get("labels") if spec.family == "claw" else row
    if not isinstance(labels, Mapping):
        labels = {}
    categories: list[str] = []
    for key, prefix in (
        ("risk_source", "risk_source"),
        ("failure_mode", "failure_mode"),
        ("harm_type", "harm_type"),
        ("real_world_harm", "harm_type"),
    ):
        category = normalized_category(labels.get(key), prefix=prefix)
        if category and category not in categories:
            categories.append(category)
    return tuple(categories)


def quarantined(spec: DatasetSpec, config: str, identity: str, physical_index: int) -> bool:
    if spec.family == "codex":
        return identity in {"2759", "2951"}
    if spec.family == "claw":
        return physical_index < 2
    if spec.family == "atbench" and config.casefold() == "atbench":
        try:
            return 1 <= int(identity) <= 19
        except ValueError:
            return False
    return False


def source_files(spec: DatasetSpec, directory: Path) -> list[tuple[str, Path]]:
    if spec.family in {"codex", "claw"}:
        path = directory / "test.json"
        if not path.is_file():
            raise ValueError(f"missing pinned source file for {spec.family}: {path}")
        return [(spec.family, path)]
    # ATBench500 is an overlapping predecessor retained only as pinned source
    # material. The 1,000-record ATBench config is the sole canonical corpus.
    path = directory / "ATBench" / "test.json"
    if not path.is_file():
        raise ValueError(f"missing canonical pinned ATBench source file: {path}")
    return [("ATBench", path)]


def resolve_revision(directory: Path, files: Sequence[tuple[str, Path]], override: str | None) -> str:
    if override:
        return required_text(override, field="dataset revision")
    revisions: set[str] = set()
    metadata_root = directory / ".cache/huggingface/download"
    for _, source_path in files:
        relative = source_path.relative_to(directory)
        metadata_path = metadata_root / Path(str(relative) + ".metadata")
        if not metadata_path.is_file():
            raise ValueError(f"missing Hugging Face revision metadata for {relative.as_posix()}")
        lines = metadata_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError(f"empty Hugging Face revision metadata for {relative.as_posix()}")
        revisions.add(required_text(lines[0], field="dataset revision"))
    if len(revisions) != 1:
        raise ValueError("source files do not resolve to one dataset revision")
    return next(iter(revisions))


def load_trajectories(
    source_directories: Mapping[str, Path],
    *,
    max_argument_bytes: int,
) -> tuple[list[Trajectory], dict[str, Any], dict[str, list[tuple[str, Path]]]]:
    trajectories: list[Trajectory] = []
    statistics: dict[str, Any] = {}
    files_by_family: dict[str, list[tuple[str, Path]]] = {}
    seen_identity: set[tuple[str, str, str]] = set()
    for family, spec in DATASET_SPECS.items():
        directory = source_directories[family]
        files = source_files(spec, directory)
        files_by_family[family] = files
        family_stats: dict[str, Any] = {}
        for config, path in files:
            records = load_json_array(path)
            counters: Counter[str] = Counter()
            source_digests: list[str] = []
            for physical_index, row in enumerate(records):
                identity = source_identity(spec, row, physical_index)
                identity_key = (spec.dataset, config, identity)
                if identity_key in seen_identity:
                    raise ValueError("duplicate ATBench trajectory identity")
                seen_identity.add(identity_key)
                if quarantined(spec, config, identity, physical_index):
                    counters["quarantined"] += 1
                    continue
                safe = source_safe(spec, row)
                if family == "codex":
                    calls = codex_calls(row, max_argument_bytes=max_argument_bytes)
                elif family == "claw":
                    calls = claw_calls(row, max_argument_bytes=max_argument_bytes)
                else:
                    content = row.get("contents", row.get("content"))
                    calls = content_calls(content, max_argument_bytes=max_argument_bytes)
                identity_digest = stable_digest("atbench-trajectory-v1", spec.dataset, config, identity)
                source_digests.append(
                    stable_digest(
                        "atbench-source-record-v1",
                        identity_digest,
                        sha256_bytes(
                            canonical_json(
                                [
                                    {
                                        "tool_name": call.tool_name,
                                        "arguments": call.arguments,
                                        "sequence_index": call.sequence_index,
                                        "call_index": call.call_index,
                                    }
                                    for call in calls
                                ]
                            )
                        ),
                        "safe" if safe else "unsafe",
                    )
                )
                counters["source_safe" if safe else "source_unsafe"] += 1
                if not calls:
                    counters["without_tool_calls"] += 1
                    continue
                counters["with_tool_calls"] += 1
                counters["tool_calls"] += len(calls)
                group_digest = stable_digest("atbench-split-group-v1", spec.dataset, config, identity)
                trajectories.append(
                    Trajectory(
                        spec=spec,
                        config=config,
                        identity_digest=identity_digest,
                        group_digest=group_digest,
                        source_safe=safe,
                        taxonomy=taxonomy_categories(spec, row),
                        calls=calls,
                    )
                )
            family_stats[config] = {
                "source_file": path.relative_to(directory).as_posix(),
                "source_file_sha256": sha256_file(path),
                "source_records": len(records),
                "quarantined_records": counters["quarantined"],
                "source_safe": counters["source_safe"],
                "source_unsafe": counters["source_unsafe"],
                "trajectories_with_tool_calls": counters["with_tool_calls"],
                "trajectories_without_tool_calls": counters["without_tool_calls"],
                "tool_calls": counters["tool_calls"],
                "source_record_set_sha256": stable_digest(*sorted(source_digests)),
            }
        statistics[family] = family_stats
    return trajectories, statistics, files_by_family


def action_truth(trajectory: Trajectory) -> dict[str, Any]:
    common = ["agent_trajectory", "real_tool_arguments", trajectory.spec.family]
    if trajectory.source_safe:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": trajectory.spec.label_source,
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": [*common, "source_trajectory_safe", "atomic_call"],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "low",
        "label_source": trajectory.spec.label_source,
        "applicability": "out_of_scope",
        "expected_disposition": "allow",
        "categories": [*common, "source_trajectory_unsafe", "atomic_call", "proof_pending"],
        "exclusion_reason": "trajectory label does not prove this individual tool call malicious",
    }


def stateful_truth(trajectory: Trajectory) -> dict[str, Any]:
    common = ["agent_trajectory", "real_tool_arguments", trajectory.spec.family, *trajectory.taxonomy]
    if trajectory.source_safe:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": trajectory.spec.label_source,
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": [*common, "source_trajectory_safe", "bounded_chain"],
        }
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium",
        "label_source": trajectory.spec.label_source,
        "applicability": "in_scope",
        "expected_disposition": "detect_only",
        "categories": [*common, "source_trajectory_unsafe", "bounded_chain", "proof_pending"],
    }


def source_record(trajectory: Trajectory, revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": trajectory.spec.dataset,
        "revision": revision,
        "original_id": original_id,
        "license": "Apache-2.0",
        "redistribution": "download-only",
    }


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


def stateful_windows(calls: Sequence[ProjectedCall]) -> Iterable[tuple[int, Sequence[ProjectedCall]]]:
    if len(calls) < 2:
        return
    start = 0
    while start < len(calls):
        window = calls[start : start + MAX_STATEFUL_EVENTS]
        if len(window) >= 2:
            yield start, window
        if start + len(window) >= len(calls):
            break
        start += MAX_STATEFUL_EVENTS - WINDOW_OVERLAP


def make_cases(trajectory: Trajectory, *, revision: str) -> list[dict[str, Any]]:
    prefix = f"atbench-{trajectory.spec.family}/{trajectory.identity_digest[:24]}"
    common_strata = {
        "ecosystem": "agent_tool_call",
        "domain": trajectory.config.casefold(),
        "hard_negative": trajectory.source_safe,
        "split_group": trajectory.group_digest[:24],
        "trajectory_id": trajectory.identity_digest[:24],
    }
    rows: list[dict[str, Any]] = []
    for call in trajectory.calls:
        ordinal = f"sequence-{call.sequence_index:06d}/call-{call.call_index:03d}"
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"{prefix}/s{call.sequence_index:06d}-c{call.call_index:03d}",
                "source": source_record(
                    trajectory,
                    revision,
                    f"trajectory-{trajectory.identity_digest[:24]}/{ordinal}",
                ),
                "split": PRE_PARTITION_SPLIT,
                "surface": "action",
                "payload": call_payload(call),
                "truth": action_truth(trajectory),
                "strata": {
                    **common_strata,
                    "campaign": "atomic_proof_pending",
                    "sequence_index": call.sequence_index,
                    "call_index": call.call_index,
                },
            }
        )
    for window_number, (window_start, window) in enumerate(stateful_windows(trajectory.calls)):
        rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"{prefix}/stateful-{window_number:03d}",
                "source": source_record(
                    trajectory,
                    revision,
                    f"trajectory-{trajectory.identity_digest[:24]}/window-{window_number:03d}",
                ),
                "split": PRE_PARTITION_SPLIT,
                "surface": "stateful",
                "payload": {
                    "direction": "tool_call",
                    "events": [event_payload(call, window_start) for call in window],
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
    source_directories: Mapping[str, Path],
    *,
    revisions: Mapping[str, str],
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if set(source_directories) != set(DATASET_SPECS) or set(revisions) != set(DATASET_SPECS):
        raise ValueError("source directories and revisions must cover every ATBench family exactly")
    if max_argument_bytes <= 0:
        raise ValueError("max argument bytes must be positive")
    trajectories, statistics, _ = load_trajectories(
        source_directories,
        max_argument_bytes=max_argument_bytes,
    )
    rows: list[dict[str, Any]] = []
    group_case_counts: Counter[str] = Counter()
    group_surface_counts: dict[str, Counter[str]] = defaultdict(Counter)
    group_metadata: dict[str, tuple[str, str]] = {}
    for trajectory in trajectories:
        generated = make_cases(trajectory, revision=revisions[trajectory.spec.family])
        rows.extend(generated)
        group_case_counts[trajectory.group_digest] += len(generated)
        group_surface_counts[trajectory.group_digest].update(str(row["surface"]) for row in generated)
        group_metadata[trajectory.group_digest] = (trajectory.spec.dataset, trajectory.config)
    rows.sort(key=lambda row: str(row["id"]))
    if len({str(row["id"]) for row in rows}) != len(rows):
        raise ValueError("generated duplicate case IDs")

    dataset_counts = Counter(str(row["source"]["dataset"]) for row in rows)
    groups = []
    for group in sorted(group_metadata):
        dataset, config = group_metadata[group]
        groups.append(
            {
                "group": group[:24],
                "dataset": dataset,
                "config": config,
                "cases": group_case_counts[group],
                "action_cases": group_surface_counts[group]["action"],
                "stateful_cases": group_surface_counts[group]["stateful"],
            }
        )
    output_data = b"".join(canonical_json(row) for row in rows)
    group_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "atbench-trajectory-group-index-v1",
        "grouping_strategy": GROUPING_STRATEGY,
        "partition_authority": PARTITION_AUTHORITY,
        "group_count": len(groups),
        "case_count": len(rows),
        "groups": groups,
        "corpus_sha256": sha256_bytes(output_data),
    }
    flat_statistics = {
        family: {
            key: sum(int(config_stats[key]) for config_stats in family_stats.values())
            for key in (
                "source_records", "quarantined_records", "source_safe", "source_unsafe",
                "trajectories_with_tool_calls", "trajectories_without_tool_calls", "tool_calls",
            )
        }
        for family, family_stats in statistics.items()
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_SPECS[family].dataset for family in sorted(DATASET_SPECS)],
        "cases": len(rows),
        "counts": dict(sorted(dataset_counts.items())),
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": flat_statistics,
        "output_sha256": sha256_bytes(output_data),
    }
    validate_manifests(manifest, group_manifest)
    return rows, manifest, group_manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path, *, max_argument_bytes: int) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    splits_by_group: dict[str, str] = {}
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
        if row["surface"] == "action":
            expected = {"direction", "tool_name", "args", "dialect"}
            if "command" in payload:
                expected.add("command")
            if set(payload) != expected:
                raise ValueError("atomic payload contains excluded trajectory fields")
            if row["truth"]["source_truth"] == "malicious":
                raise ValueError("atomic call must not inherit malicious trajectory truth")
            if len(canonical_json(payload["args"])) > max_argument_bytes:
                raise ValueError("tool-call arguments exceed the configured byte bound")
        elif row["surface"] == "stateful":
            if set(payload) != {"direction", "events"}:
                raise ValueError("stateful payload contains excluded trajectory fields")
            if not 2 <= len(payload["events"]) <= MAX_STATEFUL_EVENTS:
                raise ValueError("stateful event count is outside the bounded schema")
            for event in payload["events"]:
                if len(canonical_json(event["args"])) > max_argument_bytes:
                    raise ValueError("stateful arguments exceed the configured byte bound")
        else:
            raise ValueError("ATBench adapter emitted an unsupported surface")
        group = row["strata"]["split_group"]
        split = row["split"]
        if group in splits_by_group and splits_by_group[group] != split:
            raise ValueError("trajectory identity crosses benchmark splits")
        splits_by_group[group] = split


def require_exact_keys(value: object, expected: frozenset[str], *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError(f"{field} does not match its strict schema")
    return value


def validate_manifests(manifest: object, group_manifest: object) -> None:
    manifest_map = require_exact_keys(manifest, MANIFEST_KEYS, field="normalization manifest")
    group_map = require_exact_keys(
        group_manifest, GROUP_MANIFEST_KEYS, field="trajectory group manifest"
    )
    if manifest_map["schema_version"] != SCHEMA_VERSION:
        raise ValueError("normalization manifest identity is invalid")
    if (
        group_map["schema_version"] != SCHEMA_VERSION
        or group_map["kind"] != "atbench-trajectory-group-index-v1"
        or group_map["grouping_strategy"] != GROUPING_STRATEGY
        or group_map["partition_authority"] != PARTITION_AUTHORITY
    ):
        raise ValueError("trajectory group manifest identity is invalid")
    statistics = manifest_map["adapter_statistics"]
    if not isinstance(statistics, Mapping) or set(statistics) != set(DATASET_SPECS):
        raise ValueError("normalization manifest statistics are invalid")
    for family_statistics in statistics.values():
        if not isinstance(family_statistics, Mapping) or any(
            type(value) is not int for value in family_statistics.values()
        ):
            raise ValueError("normalization manifest statistics must be integer counters")

    groups = group_map["groups"]
    if not isinstance(groups, list) or len(groups) != group_map["group_count"]:
        raise ValueError("trajectory group count is invalid")
    seen_groups: set[str] = set()
    valid_datasets = {spec.dataset for spec in DATASET_SPECS.values()}
    for value in groups:
        group = require_exact_keys(
            value, GROUP_MANIFEST_GROUP_KEYS, field="trajectory group manifest entry"
        )
        digest = str(group["group"])
        if not HEX_24.fullmatch(digest) or digest in seen_groups:
            raise ValueError("trajectory group digest is invalid or duplicated")
        seen_groups.add(digest)
        if group["dataset"] not in valid_datasets:
            raise ValueError("trajectory group identity is invalid")
        if group["cases"] != group["action_cases"] + group["stateful_cases"]:
            raise ValueError("trajectory group case counts are inconsistent")
    if sum(int(group["cases"]) for group in groups) != group_map["case_count"]:
        raise ValueError("trajectory group manifest case count is inconsistent")
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
    source_directories = {
        family: args.source_root / spec.directory_name for family, spec in DATASET_SPECS.items()
    }
    files_by_family = {
        family: source_files(spec, source_directories[family]) for family, spec in DATASET_SPECS.items()
    }
    revisions = {
        family: resolve_revision(
            source_directories[family],
            files_by_family[family],
            getattr(args, f"{family}_revision"),
        )
        for family in DATASET_SPECS
    }
    rows, manifest, group_manifest = build_corpus(
        source_directories,
        revisions=revisions,
        max_argument_bytes=args.max_argument_bytes,
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
                "case_count": manifest["cases"],
                "surface_counts": dict(Counter(str(row["surface"]) for row in rows)),
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
