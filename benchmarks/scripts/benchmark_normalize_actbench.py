#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize ActBench tool calls at conservative action and trajectory boundaries.

Successful clean trajectories contribute successful calls as benign atomic hard
negatives and, when possible, as benign bounded sequences. Grader-confirmed
successful attack trajectories contribute only stateful source-positive cases:
the attack label never leaks onto an individual tool call.

Only structured tool names, structured arguments, call/result pairing, and
ordering metadata are projected. Prompts, reasoning, tool-result content,
workspace artifacts, API audit logs, and downloaded grader code are ignored and
never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "actbench"
HUB_DATASET_ID = "ZJUICSR/ActBench"
SOURCE_URL = f"https://huggingface.co/datasets/{HUB_DATASET_ID}"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
STAGING_SPLIT = "development"
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_EVENTS = 64
SAFE_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,239}$")
TRAJECTORY_ROLE = {"clean": "benign_baseline", "attack": "attacked_attempt"}

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """An untrusted source row cannot be projected without weakening labels."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolEvent:
    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    outcome: str
    offset_seconds: int
    sequence_index: int
    call_index: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--max-argument-bytes", type=int, default=MAX_ARGUMENT_BYTES)
    return parser.parse_args()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def required_text(value: object, code: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ProjectionError(code)
    return value.strip()


def parse_json_object(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ProjectionError(code)
    try:
        parsed = json.loads(value, object_pairs_hook=strict_object)
    except (json.JSONDecodeError, ProjectionError, RecursionError) as exc:
        raise ProjectionError(code) from exc
    if not isinstance(parsed, dict):
        raise ProjectionError(code)
    return parsed


def bounded_arguments(value: object, max_argument_bytes: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_tool_arguments")
    try:
        encoded = canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_tool_arguments") from exc
    if len(encoded) > max_argument_bytes:
        raise ProjectionError("oversized_tool_arguments")
    return value


def result_outcome(message: Mapping[str, Any]) -> str:
    is_error = message.get("isError")
    if is_error is False:
        return "succeeded"
    if is_error is True:
        return "failed"
    return "unknown"


def normalized_offset(timestamp: object, first_timestamp: float | None) -> tuple[int, float | None]:
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
        return 0, first_timestamp
    numeric = float(timestamp)
    if not math.isfinite(numeric) or numeric < 0:
        return 0, first_timestamp
    if first_timestamp is None:
        return 0, numeric
    seconds = int(max(0.0, (numeric - first_timestamp) / 1000.0))
    return min(seconds, 1800), first_timestamp


def project_events(trajectory: Mapping[str, Any], *, max_argument_bytes: int) -> tuple[ToolEvent, ...]:
    transcript = trajectory.get("transcript")
    if not isinstance(transcript, dict) or not isinstance(transcript.get("entries"), list):
        raise ProjectionError("invalid_transcript")

    pending: list[tuple[str, str, dict[str, Any], int, int, object]] = []
    call_ids: set[str] = set()
    outcomes: dict[str, str] = {}
    first_timestamp: float | None = None
    sequence_index = 0

    for entry in transcript["entries"]:
        if not isinstance(entry, dict):
            raise ProjectionError("invalid_transcript_entry")
        message = entry.get("message")
        if message is None:
            continue
        if not isinstance(message, dict):
            raise ProjectionError("invalid_message")
        role = message.get("role")

        if role == "toolResult":
            call_id = required_text(message.get("toolCallId"), "invalid_tool_result_id", max_length=240)
            if call_id in outcomes:
                raise ProjectionError("duplicate_tool_result")
            outcomes[call_id] = result_outcome(message)
            continue

        content = message.get("content")
        if not isinstance(content, list):
            continue
        call_index = 0
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "toolCall":
                continue
            if role != "assistant":
                raise ProjectionError("non_assistant_tool_call")
            call_id = required_text(block.get("id"), "invalid_tool_call_id", max_length=240)
            if call_id in call_ids:
                raise ProjectionError("duplicate_tool_call")
            name = required_text(block.get("name"), "invalid_tool_name", max_length=240)
            if not SAFE_TOOL_NAME.fullmatch(name):
                raise ProjectionError("invalid_tool_name")
            arguments = bounded_arguments(block.get("arguments"), max_argument_bytes)
            call_ids.add(call_id)
            pending.append(
                (call_id, name, arguments, sequence_index, call_index, message.get("timestamp"))
            )
            sequence_index += 1
            call_index += 1

    if not pending:
        raise ProjectionError("no_tool_calls")
    if len(pending) > MAX_EVENTS:
        raise ProjectionError("too_many_tool_calls")

    events: list[ToolEvent] = []
    for call_id, name, arguments, sequence, call_index, timestamp in pending:
        offset, first_timestamp = normalized_offset(timestamp, first_timestamp)
        # Source timestamps may be recorded when concurrent calls complete rather
        # than when they were emitted.  Preserve authoritative transcript order
        # and clamp offsets monotonically so a late-written timestamp cannot make
        # a bounded sequence travel backwards in time.
        if events:
            offset = max(offset, events[-1].offset_seconds)
        events.append(
            ToolEvent(
                tool_call_id=call_id,
                tool_name=name,
                arguments=arguments,
                outcome=outcomes.get(call_id, "unknown"),
                offset_seconds=offset,
                sequence_index=sequence,
                call_index=call_index,
            )
        )
    return tuple(events)


def event_dialect(event: ToolEvent) -> str:
    shell_tools = {"bash", "exec", "execute_command", "run_command", "shell"}
    if event.tool_name.lower() in shell_tools and isinstance(event.arguments.get("command"), str):
        return "posix"
    return "none"


def event_payload(event: ToolEvent, *, include_result: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_name": event.tool_name,
        "args": event.arguments,
        "dialect": event_dialect(event),
    }
    if include_result:
        payload["outcome"] = event.outcome
        payload["offset_seconds"] = event.offset_seconds
    return payload


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": "download-only",
    }


def clean_truth(*, stateful: bool) -> dict[str, Any]:
    categories = ["actbench", "benign_hard_negative", "clean_task_pass", "real_tool_arguments"]
    if stateful:
        categories.append("bounded_action_sequence")
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": (
            "source:clean_task_pass_trajectory"
            if stateful
            else "source:clean_task_pass_and_successful_tool_result"
        ),
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": categories,
    }


def attack_truth() -> dict[str, Any]:
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "source:automated_attack_pass_contextual_trajectory",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "exclusion_reason": (
            "The attack grader proves a prohibited task-relative outcome, but the "
            "projected tool calls omit the user-authority boundary and trusted grader "
            "artifact/API-audit evidence needed for a deterministic runtime proof."
        ),
        "categories": [
            "actbench",
            "automated_attack_pass",
            "bounded_action_sequence",
            "real_tool_arguments",
            "contextual_trajectory_source_positive",
            "proof_pending",
        ],
    }


def atomic_clean_case(
    event: ToolEvent,
    *,
    revision: str,
    group_id: str,
    trajectory_digest: str,
) -> dict[str, Any]:
    ordinal = f"s{event.sequence_index:03d}-c{event.call_index:03d}"
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"actbench/{trajectory_digest}/action-{ordinal}",
        "source": source_record(revision, f"trajectory:{trajectory_digest}#call-{ordinal}"),
        "split": STAGING_SPLIT,
        "surface": "action",
        "payload": {"direction": "tool_call", **event_payload(event, include_result=False)},
        "truth": clean_truth(stateful=False),
        "strata": {
            "ecosystem": "agent_tool_call",
            "campaign": "clean_task_pass",
            "domain": "actbench",
            "language": "en",
            "hard_negative": True,
            "split_group": group_id,
            "trajectory_id": trajectory_digest,
            "sequence_index": event.sequence_index,
            "call_index": event.call_index,
        },
    }


def stateful_case(
    events: Sequence[ToolEvent],
    *,
    revision: str,
    group_id: str,
    trajectory_digest: str,
    role: str,
) -> dict[str, Any]:
    malicious = role == "attack"
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"actbench/{trajectory_digest}/trajectory",
        "source": source_record(revision, f"trajectory:{trajectory_digest}"),
        "split": STAGING_SPLIT,
        "surface": "stateful",
        "payload": {"events": [event_payload(event, include_result=True) for event in events]},
        "truth": attack_truth() if malicious else clean_truth(stateful=True),
        "strata": {
            "ecosystem": "agent_tool_call",
            "campaign": "attack_pass" if malicious else "clean_task_pass",
            "domain": "actbench",
            "language": "en",
            "hard_negative": not malicious,
            "split_group": group_id,
            "trajectory_id": trajectory_digest,
            "sequence_index": 0,
            "call_index": 0,
        },
    }


def eligible_role(row: Mapping[str, Any], score: Mapping[str, Any]) -> str:
    role = row.get("role")
    if role not in {"clean", "attack"}:
        raise ProjectionError("unsupported_role")
    if score.get("available") is not True:
        raise ProjectionError("score_unavailable")
    if score.get("evaluation_error") is not False:
        raise ProjectionError("evaluation_error")
    if role == "clean" and score.get("task_pass") is not True:
        raise ProjectionError("clean_task_not_passed")
    if role == "attack" and score.get("attack_pass") is not True:
        raise ProjectionError("attack_not_passed")
    return role


def normalize(
    rows: Iterable[dict[str, Any]],
    revision: str,
    *,
    max_argument_bytes: int = MAX_ARGUMENT_BYTES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    revision = required_text(revision, "invalid_revision", max_length=160)
    if max_argument_bytes <= 0 or max_argument_bytes > MAX_ARGUMENT_BYTES:
        raise ValueError(f"max_argument_bytes must be between 1 and {MAX_ARGUMENT_BYTES}")

    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    counts: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    seen_trajectories: set[str] = set()

    for row in rows:
        counts["source_rows"] += 1
        if not isinstance(row, dict):
            skipped["invalid_row"] += 1
            continue
        try:
            task_id = required_text(row.get("task_id"), "invalid_task_id", max_length=240)
            source_trajectory_id = required_text(
                row.get("trajectory_id"), "invalid_trajectory_id", max_length=4096
            )
            source_identity = digest(revision, source_trajectory_id)
            if source_identity in seen_trajectories:
                raise ProjectionError("duplicate_trajectory")
            score = parse_json_object(row.get("score_json"), "invalid_score_json")
            role = eligible_role(row, score)
            trajectory = parse_json_object(row.get("trajectory_json"), "invalid_trajectory_json")
            if trajectory.get("role") != TRAJECTORY_ROLE[role]:
                raise ProjectionError("trajectory_role_mismatch")
            events = project_events(trajectory, max_argument_bytes=max_argument_bytes)
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue

        seen_trajectories.add(source_identity)
        group_id = digest(revision, task_id)[:24]
        trajectory_id = source_identity[:24]
        counts[f"eligible_{role}_trajectories"] += 1
        counts["projected_tool_calls"] += len(events)
        for event in events:
            outcomes[event.outcome] += 1

        if role == "clean":
            successful = tuple(event for event in events if event.outcome == "succeeded")
            if not successful:
                skipped["clean_without_successful_calls"] += 1
                continue
            for event in successful:
                cases.append(
                    atomic_clean_case(
                        event,
                        revision=revision,
                        group_id=group_id,
                        trajectory_digest=trajectory_id,
                    )
                )
                counts["clean_action_cases"] += 1
            if len(events) >= 2:
                cases.append(
                    stateful_case(
                        events,
                        revision=revision,
                        group_id=group_id,
                        trajectory_digest=trajectory_id,
                        role=role,
                    )
                )
                counts["clean_stateful_cases"] += 1
            else:
                skipped["clean_stateful_requires_two_calls"] += 1
        else:
            if len(events) < 2:
                skipped["attack_stateful_requires_two_calls"] += 1
                continue
            cases.append(
                stateful_case(
                    events,
                    revision=revision,
                    group_id=group_id,
                    trajectory_digest=trajectory_id,
                    role=role,
                )
            )
            counts["attack_stateful_cases"] += 1
            counts["attack_contextual_cases"] += 1

    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    statistics = {key: int(value) for key, value in sorted(counts.items())}
    statistics.update({f"outcome_{key}": int(value) for key, value in sorted(outcomes.items())})
    statistics.update({f"skipped_{key}": int(value) for key, value in sorted(skipped.items())})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {"actbench": statistics},
    }
    return cases, manifest


def parquet_rows(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read ActBench Parquet") from exc

    required = {"task_id", "role", "trajectory_id", "trajectory_json", "score_json"}
    for path in paths:
        source = parquet.ParquetFile(path)
        missing = sorted(required - set(source.schema_arrow.names))
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(missing)}")
        for batch in source.iter_batches(batch_size=32, columns=sorted(required)):
            yield from batch.to_pylist()


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")


def write_outputs(
    cases: Sequence[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    output: Path,
    manifest_path: Path,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = "".join(canonical_json(case) + "\n" for case in cases)
    output.write_text(serialized, encoding="utf-8")
    manifest["output_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    cases, manifest = normalize(
        parquet_rows(args.input),
        args.revision,
        max_argument_bytes=args.max_argument_bytes,
    )
    aggregate = hashlib.sha256()
    for path in sorted(args.input, key=lambda candidate: candidate.name):
        digest = hashlib.sha256(path.read_bytes()).digest()
        aggregate.update(path.name.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest)
    manifest = {
        **manifest,
        "source": {
            "dataset": DATASET_ID,
            "revision": args.revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "data/trajectories/*.parquet",
            "paths": sorted(path.name for path in args.input),
            "bytes": sum(path.stat().st_size for path in args.input),
            "files": len(args.input),
            "sha256": aggregate.hexdigest(),
            "source_url": SOURCE_URL,
        },
    }
    validate_cases(cases, args.schema)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_outputs(cases, manifest, output=args.output, manifest_path=manifest_path)
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
