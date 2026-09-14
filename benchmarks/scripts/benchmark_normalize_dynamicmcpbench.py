#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Conservatively normalize bounded DynamicMCPBench reference traces.

Validator-approved live-read traces are benign FPR cases. State-changing
traces and failed atomic calls remain out-of-scope contextual coverage because
the source measures task effects, not security intent. Real names, arguments,
outcomes, and bounded results are retained; oversized results become hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
TRACE_SCHEMA_VERSION = "0.1.0"
SPEC_SCHEMA_VERSION = "0.2.0"
DATASET_ID = "TokenWasteGroup/DynamicMCPBench"
ADAPTER = "dynamicmcpbench-v2"
SOURCE_URL = "https://huggingface.co/datasets/TokenWasteGroup/DynamicMCPBench"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_FILES = ("README.md", "labels.json", "specs.jsonl", "traces.jsonl")
# The pinned corpus has one 134,459,576-byte trace line because it embeds a
# large discovered tool schema. That schema is discarded, but the JSONL reader
# must admit the complete source record before projecting only bounded fields.
MAX_SOURCE_LINE_BYTES = 192 * 1024 * 1024
MAX_EVENTS = 64
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_RESULT_BYTES_PER_WINDOW = 2 * 1024 * 1024
MAX_VALUE_BYTES = 256 * 1024
MAX_CONTAINER_ITEMS = 4096
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
HARD_NEGATIVE_STRATEGIES = frozenset(
    {"ambiguous_intent", "decoy", "destructive_adjacent", "hard_neg",
     "homonym_trap", "long_similar_chain", "same_name", "sibling"}
)
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=("development", "validation", "test"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite_json(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def required_text(value: object, code: str, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProjectionError(code)
    return value.strip()


def bounded(value: object, depth: int = 0) -> object:
    if depth > 32:
        raise ProjectionError("value_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_value")
        return value
    if isinstance(value, str):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise ProjectionError("value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProjectionError("too_many_items")
        return [bounded(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_object")
        return {key: bounded(item, depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_value")


def english_compatible(*texts: object) -> bool:
    latin = non_latin = 0
    for value in texts:
        if not isinstance(value, str):
            return False
        for character in value:
            if unicodedata.category(character).startswith("L"):
                if "LATIN" in unicodedata.name(character, ""):
                    latin += 1
                else:
                    non_latin += 1
    return latin >= 20 and (non_latin <= 2 or non_latin * 50 <= latin)


def jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            if len(raw) > MAX_SOURCE_LINE_BYTES:
                raise ValueError(f"{path.name}:{number}: source line too large")
            try:
                row = json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite_json)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"{path.name}:{number}: invalid source JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path.name}:{number}: expected object")
            yield row


def load_specs(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for spec in jsonl_rows(path):
        if spec.get("schema_version") != SPEC_SCHEMA_VERSION:
            raise ValueError("unsupported DynamicMCPBench spec schema")
        trace_id = required_text(spec.get("source_trace_id"), "invalid_source_trace_id")
        task_id = required_text(spec.get("task_id"), "invalid_task_id")
        if not SAFE_ID.fullmatch(trace_id) or not SAFE_ID.fullmatch(task_id) or trace_id in result:
            raise ValueError("invalid or duplicate DynamicMCPBench spec identity")
        provenance = spec.get("provenance")
        validator = provenance.get("validator") if isinstance(provenance, dict) else None
        if not isinstance(validator, dict) or validator.get("verdict") != "valid":
            raise ValueError(f"unvalidated DynamicMCPBench spec: {task_id}")
        if spec.get("dynamism") not in {"live_read", "stateful_write"}:
            raise ValueError(f"invalid DynamicMCPBench dynamism: {task_id}")
        result[trace_id] = spec
    return result


def trace_strategy(trace: Mapping[str, Any]) -> str:
    metadata = trace.get("seed_metadata")
    tags = metadata.get("goal_tags") if isinstance(metadata, Mapping) else None
    if not isinstance(tags, list):
        raise ProjectionError("invalid_goal_tags")
    values = [tag[9:] for tag in tags if isinstance(tag, str) and tag.startswith("strategy:")]
    if len(values) != 1 or not SAFE_ID.fullmatch(values[0]):
        raise ProjectionError("invalid_strategy")
    return values[0]


def event_projection(step: Mapping[str, Any], ordinal: int) -> dict[str, Any]:
    if step.get("kind") != "call_tool_agent":
        raise ProjectionError("invalid_step_kind")
    tool = required_text(step.get("tool_name"), "invalid_tool_name")
    server = required_text(step.get("server_id"), "invalid_server_name")
    if not SAFE_ID.fullmatch(tool) or not SAFE_ID.fullmatch(server):
        raise ProjectionError("invalid_tool_identity")
    arguments = step.get("arguments")
    if not isinstance(arguments, dict):
        raise ProjectionError("invalid_arguments")
    try:
        size = len(canonical_json(arguments).encode())
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_arguments") from exc
    if size > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    status = step.get("status")
    if status not in {"success", "error"}:
        raise ProjectionError("invalid_status")
    event: dict[str, Any] = {
        "tool_name": tool, "args": bounded(arguments), "dialect": "none",
        "outcome": "succeeded" if status == "success" else "failed",
        "offset_seconds": ordinal,
    }
    command = arguments.get("command")
    if isinstance(command, str) and command and (
        server.lower() in {"shell", "terminal"}
        or tool.lower() in {"bash", "exec", "execute_command", "run_command", "shell"}
    ):
        event.update(command=command, dialect="posix")
    return event


def project_events(steps: object) -> list[dict[str, Any]]:
    if not isinstance(steps, list) or not steps:
        raise ProjectionError("no_tool_steps")
    if any(not isinstance(step, Mapping) for step in steps):
        raise ProjectionError("invalid_step")
    return [event_projection(step, index) for index, step in enumerate(steps)]


def bounded_windows(count: int) -> Iterable[tuple[int, int]]:
    start = 0
    while start < count - 1:
        end = min(count, start + MAX_EVENTS)
        yield start, end
        if end == count:
            return
        start = end - 1


def result_evidence(steps: Sequence[Mapping[str, Any]], start: int, end: int) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    retained = 0
    for index in range(start, end):
        value = steps[index].get("result")
        try:
            encoded = canonical_json(value).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProjectionError("invalid_result") from exc
        item: dict[str, Any] = {
            "event_index": index, "status": steps[index]["status"],
            "result_truncated": steps[index].get("result_truncated") is True,
            "result_bytes": len(encoded), "result_sha256": hashlib.sha256(encoded).hexdigest(),
        }
        error = steps[index].get("error")
        if error is not None:
            item["error"] = bounded(error)
        if len(encoded) <= MAX_RESULT_BYTES and retained + len(encoded) <= MAX_RESULT_BYTES_PER_WINDOW:
            item["result"] = bounded(value)
            retained += len(encoded)
        else:
            item["result_omitted_oversized"] = True
        evidence.append(item)
    return evidence


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {"dataset": DATASET_ID, "revision": revision, "original_id": original_id,
            "license": SOURCE_LICENSE, "redistribution": SOURCE_REDISTRIBUTION}


def benign_truth(stateful: bool) -> dict[str, Any]:
    return {
        "source_truth": "benign", "deterministic_truth": "benign",
        "label_confidence": "medium",
        "label_source": "dynamicmcpbench:validated_live_read_reference",
        "applicability": "in_scope", "expected_disposition": "allow",
        "categories": ["dynamicmcpbench", "validator_approved_reference", "live_read",
                       "real_tool_arguments", "bounded_action_sequence" if stateful else "successful_atomic_call"],
    }


def contextual_truth(reason: str) -> dict[str, Any]:
    return {
        "source_truth": "unknown", "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "dynamicmcpbench:task_effect_not_security_truth",
        "applicability": "out_of_scope", "expected_disposition": "detect_only",
        "categories": ["dynamicmcpbench", "contextual_sequence_coverage", "real_tool_arguments", reason],
        "exclusion_reason": "The source validates task effects but does not assign security truth to this action.",
    }


def project_trace(
    trace: Mapping[str, Any],
    spec: Mapping[str, Any],
    *,
    revision: str,
    split: str,
) -> list[dict[str, Any]]:
    if trace.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise ProjectionError("unsupported_trace_schema")
    trace_id = required_text(trace.get("trace_id"), "invalid_trace_id")
    task_id = required_text(spec.get("task_id"), "invalid_task_id")
    if spec.get("source_trace_id") != trace_id or not SAFE_ID.fullmatch(trace_id):
        raise ProjectionError("trace_spec_mismatch")
    if not english_compatible(trace.get("goal"), spec.get("prompt")):
        raise ProjectionError("non_english")
    campaign = trace_strategy(trace)
    steps = trace.get("steps")
    events = project_events(steps)
    assert isinstance(steps, list)
    live_read = spec["dynamism"] == "live_read"
    hard_negative = campaign in HARD_NEGATIVE_STRATEGIES
    identity = digest(DATASET_ID, revision, trace_id, task_id)
    base = {
        "schema_version": SCHEMA_VERSION,
        "source": source_record(revision, f"{task_id}/{trace_id}"),
        "split": split,
    }
    cases: list[dict[str, Any]] = []
    for index, (step, event) in enumerate(zip(steps, events, strict=True)):
        successful = event["outcome"] == "succeeded"
        truth = benign_truth(False) if live_read and successful else contextual_truth(
            "failed_atomic_call" if live_read else "state_changing_reference"
        )
        payload = {key: event[key] for key in ("tool_name", "command", "args", "dialect") if key in event}
        cases.append({
            **base, "id": f"dynamicmcpbench/{identity[:24]}/call-{index:03d}", "surface": "action",
            "payload": {"direction": "tool_call", **payload}, "truth": truth,
            "strata": {"language": "en", "ecosystem": f"mcp:{step['server_id']}", "campaign": campaign,
                       "domain": "mcp_reference_trace", "hard_negative": hard_negative,
                       "split_group": identity[:24], "trajectory_id": identity[:24],
                       "sequence_index": index, "call_index": index},
        })
    sequence_truth = benign_truth(True) if live_read else contextual_truth("state_changing_reference")
    for number, (start, end) in enumerate(bounded_windows(len(events))):
        cases.append({
            **base, "id": f"dynamicmcpbench/{identity[:24]}/window-{number:03d}", "surface": "stateful",
            "payload": {"direction": "tool_call", "events": events[start:end],
                        "args": {"_dynamicmcpbench_evidence": {
                            "window": {"start_event": start, "end_event_exclusive": end, "total_events": len(events)},
                            "dynamism": spec["dynamism"], "strategy": campaign,
                            "event_servers": [step["server_id"] for step in steps[start:end]],
                            "results": result_evidence(steps, start, end),
                        }}},
            "truth": sequence_truth,
            "strata": {"language": "en", "ecosystem": "mcp", "campaign": campaign,
                       "domain": str(spec["dynamism"]), "hard_negative": hard_negative,
                       "split_group": identity[:24], "trajectory_id": identity[:24],
                       "sequence_index": start, "call_index": end - 1},
        })
    return cases


def normalize(
    specs: Mapping[str, Mapping[str, Any]],
    traces: Iterable[Mapping[str, Any]],
    *,
    revision: str,
    split: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    revision = required_text(revision, "invalid_revision")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full lowercase Git commit")
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    seen: set[str] = set()
    for trace in traces:
        counts["source_traces"] += 1
        trace_id = str(trace.get("trace_id", ""))
        if trace_id in seen:
            skipped["duplicate_trace_id"] += 1
            continue
        seen.add(trace_id)
        spec = specs.get(trace_id)
        if spec is None:
            skipped["unlinked_reference_trace"] += 1
            continue
        try:
            projected = project_trace(trace, spec, revision=revision, split=split)
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        counts["linked_traces"] += 1
        counts[f"traces_{spec['dynamism']}"] += 1
        counts["source_tool_calls"] += len(trace["steps"])
        counts["source_calls_succeeded"] += sum(
            step.get("status") == "success" for step in trace["steps"]
        )
        counts["source_calls_failed"] += sum(
            step.get("status") == "error" for step in trace["steps"]
        )
        for case in projected:
            counts[f"cases_{case['surface']}"] += 1
            counts[f"cases_{case['truth']['source_truth']}"] += 1
        cases.extend(projected)
    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    return cases, {
        "schema_version": SCHEMA_VERSION, "source_id": DATASET_ID, "source_url": SOURCE_URL,
        "source_revision": revision, "source_license": SOURCE_LICENSE, "split": split,
        "row_count": len(cases), "counts": dict(sorted(counts.items())), "skipped": dict(sorted(skipped.items())),
        "normalization": (
            "validated live-read references are benign FPR cases; state-changing "
            "and failed atomic calls are contextual coverage only"
        ),
        "label_limitation": (
            "DynamicMCPBench is effect-scored, model-generated data without malicious "
            "security labels; no row is a malicious positive."
        ),
        "result_policy": (
            f"retain canonical results up to {MAX_RESULT_BYTES} bytes each and "
            f"{MAX_RESULT_BYTES_PER_WINDOW} bytes per window; otherwise retain "
            "SHA-256 and byte count"
        ),
    }


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text()))
    seen: set[str] = set()
    for row in rows:
        if row["id"] in seen:
            raise ValueError("duplicate benchmark case ID")
        seen.add(row["id"])
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            raise ValueError(f"{row['id']}: {errors[0].message}")
        if row["truth"]["source_truth"] == "malicious":
            raise ValueError(f"{row['id']}: DynamicMCPBench cannot supply malicious truth")
        if row["surface"] == "stateful" and not 2 <= len(row["payload"]["events"]) <= MAX_EVENTS:
            raise ValueError(f"{row['id']}: invalid bounded event count")


def source_hashes(input_dir: Path) -> tuple[dict[str, str], str]:
    hashes: dict[str, str] = {}
    aggregate = hashlib.sha256()
    for filename in SOURCE_FILES:
        path = input_dir / filename
        if not path.is_file():
            raise ValueError(f"missing required source file: {filename}")
        value = file_sha256(path)
        hashes[filename] = value
        aggregate.update(filename.encode())
        aggregate.update(b"\0")
        aggregate.update(bytes.fromhex(value))
    return hashes, aggregate.hexdigest()


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


def strict_manifest(
    cases: Sequence[Mapping[str, Any]],
    metadata: Mapping[str, Any],
    *,
    output_data: bytes,
    source_bytes: int,
    source_sha256: str,
) -> dict[str, Any]:
    statistics = dict(metadata["counts"])
    statistics.update(
        {f"skipped_{key}": int(value) for key, value in metadata["skipped"].items()}
    )
    return {
        "adapter_statistics": {
            ADAPTER: {key: int(value) for key, value in sorted(statistics.items())}
        },
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(output_data).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": source_bytes,
            "dataset": DATASET_ID,
            "files": len(SOURCE_FILES),
            "license": SOURCE_LICENSE,
            "path": "",
            "paths": list(SOURCE_FILES),
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": metadata["source_revision"],
            "sha256": source_sha256,
            "source_url": SOURCE_URL,
        },
    }


def main() -> int:
    args = parse_args()
    _, aggregate = source_hashes(args.input_dir)
    specs = load_specs(args.input_dir / "specs.jsonl")
    cases, manifest = normalize(
        specs,
        jsonl_rows(args.input_dir / "traces.jsonl"),
        revision=args.revision,
        split=args.split,
    )
    validate_cases(cases, args.schema)
    output_data = "".join(canonical_json(case) + "\n" for case in cases).encode()
    source_bytes = sum((args.input_dir / filename).stat().st_size for filename in SOURCE_FILES)
    manifest = strict_manifest(
        cases, manifest, output_data=output_data,
        source_bytes=source_bytes, source_sha256=aggregate,
    )
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, output_data)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
