#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize public AgentDojo executed traces into benchmark case-v1.

Only role == "tool" messages are execution evidence. Assistant-emitted calls
without a linked tool-result message are never projected. Prompts, assistant
text, reasoning, injected document text, and final answers are excluded. Real
structured arguments are retained. Bounded result/error records are attached
only as non-runtime stateful evidence, so observations cannot be mistaken for
tool-call arguments by the benchmark harness.

AgentDojo's security score is trajectory-level truth. A violated run is a
contextual positive only when its complete executed trajectory fits in one
bounded window; individual calls and partial windows remain out of scope.
Security-preserving attacked runs are useful hard negatives.
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
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "agentdojo"
PINNED_REVISION = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
SOURCE_URL = f"https://github.com/ethz-spylab/agentdojo/tree/{PINNED_REVISION}/runs"
LICENSE_URL = f"https://github.com/ethz-spylab/agentdojo/blob/{PINNED_REVISION}/LICENSE"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
ENGLISH_SUITES = frozenset({"banking", "slack", "travel", "workspace"})
MAX_EVENTS = 8
MAX_MESSAGES = 512
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 256 * 1024
MAX_CONTAINER_ITEMS = 4096
SAFE_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,239}$")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """An untrusted source record cannot be projected safely."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=PINNED_REVISION)
    parser.add_argument("--split", choices=("development", "validation", "test"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def required_text(value: object, code: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProjectionError(code)
    return value.strip()


def bounded(value: object, *, depth: int = 0) -> object:
    if depth > 32:
        raise ProjectionError("value_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_value")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProjectionError("too_many_items")
        return [bounded(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_object")
        return {key: bounded(item, depth=depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_value")


def load_record(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ProjectionError("source_file_too_large")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except ProjectionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProjectionError("invalid_json") from exc
    if not isinstance(value, dict):
        raise ProjectionError("invalid_record")
    return value


def runs_root(root: Path) -> Path:
    candidate = root / "runs"
    return candidate if candidate.is_dir() else root


def source_paths(root: Path) -> list[Path]:
    base = runs_root(root)
    if not base.is_dir():
        raise ValueError(f"AgentDojo runs directory not found: {base}")
    return sorted(path for path in base.rglob("*.json") if path.is_file())


def call_reference(call: Mapping[str, Any], message: Mapping[str, Any]) -> str:
    embedded = call.get("id")
    linked = message.get("tool_call_id")
    for value in (embedded, linked):
        if value is not None and (not isinstance(value, str) or len(value) > 512):
            raise ProjectionError("invalid_tool_call_id")
    embedded = embedded or None
    linked = linked or None
    if embedded is not None and linked is not None and embedded != linked:
        raise ProjectionError("mismatched_tool_call_id")
    value = embedded or linked
    if value is None:
        return ""
    return digest("agentdojo-call-v1", value)[:24]


def executed_event(message: Mapping[str, Any], ordinal: int) -> tuple[dict[str, Any], dict[str, Any]]:
    call = message.get("tool_call")
    if not isinstance(call, Mapping):
        raise ProjectionError("missing_executed_tool_call")
    tool = required_text(call.get("function"), "invalid_tool_name")
    if not SAFE_TOOL.fullmatch(tool):
        raise ProjectionError("invalid_tool_name")
    args = call.get("args")
    if not isinstance(args, dict):
        raise ProjectionError("invalid_tool_arguments")
    projected_args = bounded(args)
    if len(canonical_json(projected_args).encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("tool_arguments_too_large")

    error = message.get("error")
    if error is not None and not isinstance(error, str):
        raise ProjectionError("invalid_tool_error")
    result = bounded(message.get("content"))
    if len(canonical_json(result).encode("utf-8")) > MAX_RESULT_BYTES:
        raise ProjectionError("tool_result_too_large")
    event = {
        "tool_name": tool,
        "args": projected_args,
        "dialect": "none",
        "outcome": "failed" if error else "succeeded",
        "offset_seconds": ordinal,
    }
    call_ref = call_reference(call, message)
    evidence: dict[str, Any] = {
        "event_index": ordinal,
        "call_ref": call_ref,
        "result_join_authority": "exact-id" if call_ref else "message-local",
        "result": result,
        "error": error,
    }
    return event, evidence


def executed_events(
    record: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    messages = record.get("messages")
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGES:
        raise ProjectionError("invalid_messages")
    events: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    emitted_calls = 0
    for message in messages:
        if not isinstance(message, Mapping):
            raise ProjectionError("invalid_message")
        if message.get("role") == "assistant":
            calls = message.get("tool_calls")
            if isinstance(calls, list):
                emitted_calls += len(calls)
            continue
        if message.get("role") != "tool":
            continue
        event, linked = executed_event(message, len(events))
        events.append(event)
        evidence.append(linked)
    return events, evidence, max(0, emitted_calls - len(events))


def run_identity(record: Mapping[str, Any], relative_path: str) -> tuple[str, str, str]:
    suite = required_text(record.get("suite_name"), "invalid_suite", maximum=80)
    if suite not in ENGLISH_SUITES:
        raise ProjectionError("non_english_or_unknown_suite")
    pipeline = required_text(record.get("pipeline_name"), "invalid_pipeline", maximum=160)
    user_task = required_text(record.get("user_task_id"), "invalid_user_task")
    if not all(SAFE_IDENTITY.fullmatch(value) for value in (pipeline, user_task)):
        raise ProjectionError("invalid_run_identity")
    return suite, pipeline, digest(relative_path, suite, pipeline, user_task)


def run_class(record: Mapping[str, Any]) -> tuple[str, bool, str]:
    utility = record.get("utility")
    security = record.get("security")
    if type(utility) is not bool or type(security) is not bool:
        raise ProjectionError("invalid_evaluation_outcome")
    run_error = record.get("error")
    if run_error is not None and not isinstance(run_error, str):
        raise ProjectionError("invalid_run_error")
    attack = record.get("attack_type")
    injection = record.get("injection_task_id")
    attacked = attack not in {None, "none"} or injection not in {None, "none"}
    if run_error:
        return "unknown", attacked, "run_error"
    if not attacked:
        if security:
            return "benign", False, "no_injection"
        return "unknown", False, "invalid_no_injection_security"
    if security:
        return "benign", True, "security_preserved"
    return "malicious", False, "security_violated"


def source(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def truth_for(run_truth: str, *, complete_trajectory: bool, atomic: bool) -> dict[str, Any]:
    if run_truth == "benign":
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "agentdojo:security_utility_evaluators",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": [
                "agentdojo",
                "executed_tool_call" if atomic else "bounded_execution_window",
                "security_preserved",
            ],
        }
    if run_truth == "malicious" and complete_trajectory and not atomic:
        return {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "agentdojo:security_evaluator",
            "applicability": "in_scope",
            "expected_disposition": "detect_only",
            "categories": [
                "agentdojo",
                "bounded_execution_window",
                "prompt_injection_success",
            ],
        }
    reason = (
        "AgentDojo assigns security truth to the complete trajectory, not to an "
        "individual call or a partial bounded window."
        if run_truth == "malicious"
        else "The source run did not complete with usable security truth."
    )
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "low",
        "label_source": "agentdojo:projection_guard",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": [
            "agentdojo",
            "executed_tool_call" if atomic else "partial_execution_window",
            "run_level_truth_only",
        ],
        "exclusion_reason": reason,
    }


def project_record(
    record: Mapping[str, Any], relative_path: str, revision: str, split: str
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    suite, pipeline, trajectory_digest = run_identity(record, relative_path)
    events, evidence, unobserved = executed_events(record)
    run_truth, attacked_hard_negative, run_outcome = run_class(record)
    if not events:
        raise ProjectionError("no_executed_calls")
    base_strata = {
        "platform": "agentdojo",
        "language": "en",
        "ecosystem": "agentdojo",
        "campaign": pipeline,
        "domain": suite,
        "hard_negative": attacked_hard_negative,
        "split_group": trajectory_digest[:24],
        "trajectory_id": trajectory_digest[:24],
    }
    common_source = source(revision, relative_path)
    cases: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        cases.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"agentdojo/{trajectory_digest[:24]}/call-{index:03d}",
                "source": common_source,
                "split": split,
                "surface": "action",
                "payload": {
                    "tool_name": event["tool_name"],
                    "args": event["args"],
                    "dialect": "none",
                },
                "truth": truth_for(run_truth, complete_trajectory=False, atomic=True),
                "strata": {
                    **base_strata,
                    "sequence_index": index,
                    "call_index": index,
                },
            }
        )

    if len(events) >= 2:
        for end in range(2, len(events) + 1):
            start = max(0, end - MAX_EVENTS)
            complete = start == 0 and end == len(events)
            window_events = [{**event, "offset_seconds": offset} for offset, event in enumerate(events[start:end])]
            window_evidence = [
                {**linked, "event_index": linked["event_index"] - start} for linked in evidence[start:end]
            ]
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"agentdojo/{trajectory_digest[:24]}/window-{end - 2:03d}",
                    "source": common_source,
                    "split": split,
                    "surface": "stateful",
                    "payload": {
                        "events": window_events,
                        "args": {
                            "_agentdojo_execution": {
                                "security": record["security"],
                                "utility": record["utility"],
                                "run_outcome": run_outcome,
                                "complete_trajectory": complete,
                                "linked_results": window_evidence,
                            }
                        },
                    },
                    "truth": truth_for(run_truth, complete_trajectory=complete, atomic=False),
                    "strata": {
                        **base_strata,
                        "sequence_index": end - 2,
                        "call_index": end - 1,
                    },
                }
            )
    return cases, {
        "executed_calls": len(events),
        "result_join_exact_id": sum(
            item["result_join_authority"] == "exact-id" for item in evidence
        ),
        "result_join_message_local": sum(
            item["result_join_authority"] == "message-local" for item in evidence
        ),
        "unobserved_emitted_calls": unobserved,
    }


def build_corpus(root: Path, revision: str, split: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != PINNED_REVISION:
        raise ValueError(f"AgentDojo revision must be pinned to {PINNED_REVISION}; got {revision}")
    base = runs_root(root)
    paths = source_paths(root)
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    statistics: Counter[str] = Counter()
    source_files: list[dict[str, Any]] = []
    for path in paths:
        relative = path.relative_to(base).as_posix()
        if len(relative) > 240:
            skipped["source_path_too_long"] += 1
            continue
        source_files.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        )
        try:
            projected, counts = project_record(load_record(path), relative, revision, split)
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        cases.extend(projected)
        statistics.update(counts)
        statistics["projected_runs"] += 1

    cases.sort(key=lambda row: row["id"])
    tree_material = canonical_json(source_files).encode("utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_revision": revision,
        "source_url": SOURCE_URL,
        "source_license": SOURCE_LICENSE,
        "source_license_url": LICENSE_URL,
        "source_redistribution": SOURCE_REDISTRIBUTION,
        "source_file_count": len(source_files),
        "source_tree_sha256": hashlib.sha256(tree_material).hexdigest(),
        "split": split,
        "row_count": len(cases),
        "surface_counts": dict(sorted(Counter(row["surface"] for row in cases).items())),
        "truth_counts": dict(sorted(Counter(row["truth"]["source_truth"] for row in cases).items())),
        "statistics": dict(sorted(statistics.items())),
        "skipped": dict(sorted(skipped.items())),
        "language_policy": ("English-only AgentDojo v1 suites: banking, slack, travel, workspace"),
        "execution_policy": ("Only linked role=tool messages are executed calls; assistant-only calls are excluded"),
        "window_policy": (
            "Rolling windows end at each executed call and contain at most eight "
            "events; only a complete violated trajectory is a contextual positive"
        ),
        "content_policy": (
            "Prompts and reasoning are excluded; bounded structured arguments "
            "and linked tool results/errors are retained"
        ),
    }
    return cases, manifest


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - dependency error
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    for row in rows:
        validator.validate(row)
        if row["surface"] == "stateful":
            events = row["payload"]["events"]
            if not 2 <= len(events) <= MAX_EVENTS:
                raise ValueError(f"{row['id']}: invalid stateful window")
            if [event["offset_seconds"] for event in events] != list(range(len(events))):
                raise ValueError(f"{row['id']}: non-contiguous event offsets")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(canonical_json(row) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                value,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    args = parse_args()
    cases, manifest = build_corpus(args.input_dir, args.revision, args.split)
    validate_cases(cases, args.schema)
    write_jsonl(args.output, cases)
    manifest["output_sha256"] = file_sha256(args.output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    write_json(manifest_path, manifest)
    print(canonical_json({"manifest": str(manifest_path), "output": str(args.output), **manifest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
