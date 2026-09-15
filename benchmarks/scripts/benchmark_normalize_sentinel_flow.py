#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned Sentinel-Flow synthetic contextual trajectories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "sentinel-flow"
SOURCE_REPOSITORY = "ihabler/sentinel-flow"
SOURCE_URL = "https://huggingface.co/datasets/ihabler/sentinel-flow"
SOURCE_REVISION = "f3b8d86ab1b2c8bfd99648478110b218c064ceaf"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_FILE = "sentinel-flow.jsonl"
SOURCE_BYTES = 4_641_323
SOURCE_SHA256 = "b2e9efb8ebf3674000b601c20a7a4b4f07dc63cb34ee5119216be832bde57aab"
ADAPTER = "sentinel-flow-contextual-trajectories-v1"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 512 * 1024
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_EVENTS = 8
ABSOLUTE_MAX_EVENTS = 64
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
SAFE_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:#-]{0,199}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)


class ProjectionError(ValueError):
    """A source row cannot be projected without weakening evidence controls."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_json(value: str, *, maximum: int) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise ProjectionError("invalid or oversized JSON value")
    try:
        return json.loads(value, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ProjectionError("invalid JSON value") from exc


def required_text(value: Any, field: str, *, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProjectionError(f"invalid {field}")
    return value


def english_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(re.search(r"[A-Za-z]", value))
        and NON_ENGLISH_SCRIPT.search(value) is None
    )


def digest(*parts: str) -> str:
    framed = "".join(f"{len(part)}:{part}" for part in parts)
    return hashlib.sha256(framed.encode("utf-8")).hexdigest()


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode("utf-8")).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def parse_function(value: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {"name", "arguments"}:
        raise ProjectionError("invalid function schema")
    name = value.get("name")
    if not isinstance(name, str) or SAFE_TOOL.fullmatch(name) is None:
        raise ProjectionError("invalid tool name")
    arguments = exact_json(value.get("arguments"), maximum=MAX_ARGUMENT_BYTES)
    if not isinstance(arguments, dict):
        raise ProjectionError("tool arguments must be an object")
    return name, arguments


def paired_outcomes(messages: list[Any]) -> dict[str, str]:
    outcomes: dict[str, str] = {}
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") != "tool":
            continue
        call_id = message.get("tool_call_id")
        if not isinstance(call_id, str) or not call_id or call_id in outcomes:
            raise ProjectionError("invalid or duplicate tool result ID")
        # Do not infer success from a result message or parse attacker-controlled
        # result content. Only explicit structured status metadata strengthens an
        # outcome; otherwise the conservative outcome is unknown.
        if message.get("is_error") is True or message.get("error") not in (None, "", False):
            outcomes[call_id] = "failed"
        elif message.get("is_error") is False or message.get("success") is True:
            outcomes[call_id] = "succeeded"
        else:
            outcomes[call_id] = "unknown"
    return outcomes


def history_events(raw_history: Any) -> list[dict[str, Any]]:
    history = exact_json(raw_history, maximum=MAX_LINE_BYTES)
    if not isinstance(history, list):
        raise ProjectionError("history must be an array")
    outcomes = paired_outcomes(history)
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for message in history:
        if not isinstance(message, Mapping) or message.get("role") != "assistant":
            continue
        calls = message.get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list):
            raise ProjectionError("tool_calls must be an array")
        for call in calls:
            if not isinstance(call, Mapping) or set(call) != {"id", "type", "function"}:
                raise ProjectionError("invalid history tool-call schema")
            call_id = call.get("id")
            if (
                call.get("type") != "function"
                or not isinstance(call_id, str)
                or not call_id
                or call_id in seen
            ):
                raise ProjectionError("invalid or duplicate history tool call")
            name, arguments = parse_function(call.get("function"))
            seen.add(call_id)
            events.append(
                {
                    "args": arguments,
                    "dialect": "none",
                    "offset_seconds": len(events),
                    "outcome": outcomes.get(call_id, "unknown"),
                    "tool_name": name,
                }
            )
            if len(events) > ABSOLUTE_MAX_EVENTS:
                raise ProjectionError("history exceeds absolute event bound")
    if not set(outcomes).issubset(seen):
        raise ProjectionError("orphan tool result")
    return events


def candidate_event(raw_candidate: Any, expected_tool: Any, present: Any) -> dict[str, Any] | None:
    candidate = exact_json(raw_candidate, maximum=MAX_ARGUMENT_BYTES)
    if type(present) is not bool:
        raise ProjectionError("invalid candidate-presence flag")
    if not present:
        if candidate is not None or expected_tool not in (None, ""):
            raise ProjectionError("candidate fields disagree")
        return None
    if not isinstance(candidate, Mapping) or set(candidate) != {"type", "function"}:
        raise ProjectionError("invalid candidate action schema")
    if candidate.get("type") != "function":
        raise ProjectionError("candidate action is not a function")
    name, arguments = parse_function(candidate.get("function"))
    if expected_tool != name:
        raise ProjectionError("candidate tool name mismatch")
    return {
        "args": arguments,
        "dialect": "none",
        "offset_seconds": 0,
        "outcome": "unknown",
        "tool_name": name,
    }


def truth_for(label: str) -> dict[str, Any]:
    if label not in {"SAFE", "UNSAFE"}:
        raise ProjectionError("unsupported source label")
    unsafe = label == "UNSAFE"
    return {
        "applicability": "in_scope",
        "categories": [
            "sentinel_flow",
            "synthetic_conformance",
            "contextual_source_label",
        ],
        "deterministic_truth": "contextual_or_dual_use",
        "expected_disposition": "detect_only" if unsafe else "allow",
        "label_confidence": "high",
        "label_source": "source:sentinel_flow_contextual_label",
        "source_truth": "malicious" if unsafe else "benign",
    }


def project_row(row: Mapping[str, Any]) -> dict[str, Any]:
    row_id = required_text(row.get("row_id"), "row_id")
    trace_id = required_text(row.get("trace_id"), "trace_id")
    scenario_id = required_text(row.get("scenario_id"), "scenario_id")
    if not all(SAFE_SOURCE_ID.fullmatch(value) for value in (row_id, trace_id, scenario_id)):
        raise ProjectionError("invalid source identity")
    if not english_text(row.get("scenario_description")):
        raise ProjectionError("non-English scenario")
    flow_class = required_text(row.get("flow_class"), "flow_class", maximum=80)
    application_domain = required_text(
        row.get("application_domain"), "application_domain", maximum=80
    )
    if not SAFE_TOOL.fullmatch(flow_class) or not SAFE_TOOL.fullmatch(application_domain):
        raise ProjectionError("invalid source stratum")

    events = history_events(row.get("history_json"))
    candidate = candidate_event(
        row.get("candidate_action_json"),
        row.get("candidate_tool"),
        row.get("has_candidate_action"),
    )
    if candidate is not None:
        candidate["offset_seconds"] = len(events)
        events.append(candidate)
    if not events:
        raise ProjectionError("no typed tool calls")
    if len(events) > MAX_EVENTS:
        raise ProjectionError("trajectory exceeds preferred event bound")

    group_id = digest("sentinel-flow-pair-v1", SOURCE_REVISION, scenario_id)[:24]
    trajectory_id = digest("sentinel-flow-trace-v1", SOURCE_REVISION, trace_id)[:24]
    split = split_for(group_id)
    base = {
        "id": f"sentinel-flow/{trajectory_id}",
        "schema_version": SCHEMA_VERSION,
        "source": {
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "original_id": row_id,
            "redistribution": "download-only",
            "revision": SOURCE_REVISION,
        },
        "split": split,
        "strata": {
            "campaign": flow_class,
            "domain": application_domain,
            "ecosystem": "agent_tool_call",
            "hard_negative": row.get("ground_truth") == "SAFE",
            "language": "en",
            "platform": "cross-platform",
            "split_group": group_id,
            "trajectory_id": trajectory_id,
            "sequence_index": 0,
            "call_index": 0,
        },
        "truth": truth_for(row.get("ground_truth")),
    }
    if len(events) == 1:
        event = events[0]
        base["surface"] = "action"
        base["payload"] = {
            "args": event["args"],
            "dialect": event["dialect"],
            "direction": "tool_call",
            "tool_name": event["tool_name"],
        }
    else:
        base["surface"] = "stateful"
        base["payload"] = {"direction": "tool_call", "events": events}
    return base


def normalize_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen_rows: set[str] = set()
    seen_traces: set[str] = set()
    for row in rows:
        counts["source_rows"] += 1
        try:
            row_id = required_text(row.get("row_id"), "row_id")
            trace_id = required_text(row.get("trace_id"), "trace_id")
            if row_id in seen_rows or trace_id in seen_traces:
                raise ProjectionError("duplicate row or trace identity")
            case = project_row(row)
        except ProjectionError as exc:
            counts[f"excluded:{exc}"] += 1
            continue
        seen_rows.add(row_id)
        seen_traces.add(trace_id)
        cases.append(case)
        counts[case["split"]] += 1
        counts[f"source_{row['ground_truth'].lower()}"] += 1
        counts["events"] += 1 if case["surface"] == "action" else len(case["payload"]["events"])
        counts[case["surface"]] += 1
    cases.sort(key=lambda case: case["id"])
    counts["accepted"] = len(cases)
    counts["paired_groups"] = len({case["strata"]["split_group"] for case in cases})
    return cases, counts


def jsonl_rows(path: Path) -> Iterable[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, line in enumerate(handle, 1):
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ProjectionError(f"source line {line_number} exceeds size bound")
            value = exact_json(line, maximum=MAX_LINE_BYTES)
            if not isinstance(value, Mapping):
                raise ProjectionError(f"source line {line_number} is not an object")
            yield value


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for case in cases:
        validator.validate(case)


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def atomic_write(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ProjectionError("refusing to replace a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--schema", default=DEFAULT_SCHEMA, type=Path)
    args = parser.parse_args()
    if not args.input.is_file() or args.input.is_symlink():
        fail("input must be a regular non-symlink file")
    size = args.input.stat().st_size
    if size != SOURCE_BYTES or size > MAX_SOURCE_BYTES or sha256_file(args.input) != SOURCE_SHA256:
        fail("pinned Sentinel-Flow source identity mismatch")

    cases, counts = normalize_rows(jsonl_rows(args.input))
    validate_cases(cases, args.schema)
    body = "".join(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n" for case in cases)
    atomic_write(args.output, body)
    manifest = {
        "adapter_statistics": {ADAPTER: dict(sorted(counts.items()))},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": size,
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "path": SOURCE_FILE,
            "redistribution": "download-only",
            "revision": SOURCE_REVISION,
            "sha256": SOURCE_SHA256,
        },
    }
    atomic_write(args.manifest, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"adapter": ADAPTER, "cases": len(cases), "counts": dict(sorted(counts.items()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
