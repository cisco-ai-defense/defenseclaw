#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned DiscoPosse agent execution traces into case-v1.

The source stores OpenTelemetry chat spans. A tool call is projected only when
its structured assistant call ID has one consistent response ID in a later
input-history span from the same trace and session. The published Parquet
schema does not contain ``parent_span_id`` despite the dataset-card example;
when parent IDs are present, malformed or cyclic parent graphs are rejected,
but no missing relation is inferred.

Only tool names, redacted structured arguments, and explicit part-level status
are emitted. Prompts, assistant prose/reasoning, result bodies, tool schemas,
chat status, and benchmark pass/fail signals never enter normalized payloads or
labels. SWE-bench rows are always excluded to avoid benchmark overlap.
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
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "DiscoPosse/agent-llm-traces"
SOURCE_URL = "https://huggingface.co/datasets/DiscoPosse/agent-llm-traces"
SOURCE_REVISION = "6b1add7c19f1fb50bb0edf5b240d6149a5c621fb"
SOURCE_LICENSE = "CDLA-Permissive-2.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_FILE_COUNT = 39
SOURCE_BYTES = 983_592_848
SOURCE_TREE_SHA256 = "9a0decc36a41ea97f69a3c7c068e423e90f7a90621734e0cd262410c7f27ee6d"
ADAPTER = "discoposse-agent-llm-traces-executed-benign-v1"
MAX_EVENTS = 9  # current event plus at most eight predecessors
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_STRING_BYTES = 256 * 1024
MAX_ITEMS = 4096
MAX_DEPTH = 24
MAX_SPANS = 4096
MAX_MESSAGES = 4096
MAX_PARTS = 4096
MAX_PARENT_DEPTH = 4096

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
SUPPORTED_BENCHMARKS = frozenset({"appworld", "browsecompplus", "tau2_airline", "tau2_retail", "tau2_telecom"})
SWE_BENCHMARKS = frozenset({"swebench", "swe_bench"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,239}$")
SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|authorization|auth|bearer|cookie|credential|cvv|"
    r"password|passwd|private[_-]?key|secret|session[_-]?token|access[_-]?token|"
    r"refresh[_-]?token)(?:$|[_-])"
)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)"
    r"\s*=\s*)([^\s;&|]+)"
)
ENGLISH_WORD = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")
ENGLISH_MARKERS = frozenset(
    {"a", "and", "for", "from", "help", "in", "is", "of", "please", "task", "the", "to", "with", "you"}
)
SHELL_TOOLS = frozenset({"bash", "execute", "execute_command", "run_command", "shell", "terminal"})


class ProjectionError(ValueError):
    """A source record cannot satisfy the conservative projection contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Span:
    span_id: str
    parent_span_id: str | None
    trace_id: str
    start_time: datetime
    input_messages: list[Mapping[str, Any]]
    output_messages: list[Mapping[str, Any]]


@dataclass(frozen=True)
class Call:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    span_id: str
    span_index: int
    part_index: int
    outcome: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(raw: str, code: str) -> Any:
    if len(raw.encode()) > MAX_ARGUMENT_BYTES * 16:
        raise ProjectionError(f"{code}_too_large")
    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProjectionError(code) from exc


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def validate_source_files(paths: Sequence[Path]) -> list[dict[str, object]]:
    expected_names = {f"train-{index:05d}-of-{SOURCE_FILE_COUNT:05d}.parquet" for index in range(SOURCE_FILE_COUNT)}
    if len(paths) != SOURCE_FILE_COUNT or {path.name for path in paths} != expected_names:
        raise ValueError("inputs must identify the exact pinned DiscoPosse Parquet shards")
    records: list[dict[str, object]] = []
    aggregate = hashlib.sha256(b"discoposse-agent-llm-traces-source-tree-v1\0")
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.name):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"source must be a regular non-symlink file: {path}")
        byte_count = path.stat().st_size
        sha256 = file_sha256(path)
        total_bytes += byte_count
        aggregate.update(f"{path.name}\0{byte_count}\0{sha256}\n".encode())
        records.append({"name": path.name, "bytes": byte_count, "sha256": sha256})
    if total_bytes != SOURCE_BYTES or aggregate.hexdigest() != SOURCE_TREE_SHA256:
        raise ValueError("pinned DiscoPosse source tree identity mismatch")
    return records


def normalize_benchmark(value: object) -> str:
    if not isinstance(value, str):
        raise ProjectionError("missing_benchmark")
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    if normalized in SWE_BENCHMARKS or ("swe" in normalized and "bench" in normalized):
        raise ProjectionError("excluded_swebench")
    if normalized not in SUPPORTED_BENCHMARKS:
        raise ProjectionError("unsupported_benchmark")
    return normalized


def required_id(value: object, code: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ProjectionError(code)
    return value


def parse_messages(value: object, code: str) -> list[Mapping[str, Any]]:
    if value is None or value == "":
        return []
    parsed = strict_json(value, code) if isinstance(value, str) else value
    if not isinstance(parsed, list) or len(parsed) > MAX_MESSAGES:
        raise ProjectionError(code)
    if any(not isinstance(message, Mapping) for message in parsed):
        raise ProjectionError(code)
    return list(parsed)


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 80:
        raise ProjectionError("invalid_span_time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("invalid_span_time") from exc
    if parsed.tzinfo is None:
        # Four of the five admitted upstream families serialize local-naive ISO
        # timestamps. The adapter uses time only to order spans within one
        # trace, so a fixed zone preserves that exact relative ordering without
        # claiming a source timezone.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def project_span(raw: Mapping[str, Any], session_id: str) -> Span:
    span_id = required_id(raw.get("span_id"), "invalid_span_id")
    parent = raw.get("parent_span_id")
    if parent in {None, ""}:
        parent = None
    elif not isinstance(parent, str) or not SAFE_ID.fullmatch(parent):
        raise ProjectionError("invalid_parent_span_id")
    trace_id = required_id(raw.get("trace_id"), "invalid_trace_id")
    span_session = raw.get("session_id")
    if span_session is not None and span_session != session_id:
        raise ProjectionError("span_session_mismatch")
    attributes = raw.get("attributes")
    if not isinstance(attributes, Mapping):
        raise ProjectionError("invalid_span_attributes")
    return Span(
        span_id=span_id,
        parent_span_id=parent,
        trace_id=trace_id,
        start_time=parse_time(raw.get("start_time")),
        input_messages=parse_messages(attributes.get("gen_ai.input.messages"), "invalid_input_messages"),
        output_messages=parse_messages(attributes.get("gen_ai.output.messages"), "invalid_output_messages"),
    )


def validate_parent_graph(spans: Sequence[Span]) -> None:
    parents = {span.span_id: span.parent_span_id for span in spans}
    if len(parents) != len(spans):
        raise ProjectionError("duplicate_span_id")
    for start in parents:
        current: str | None = start
        seen: set[str] = set()
        while current is not None:
            if current in seen or len(seen) >= MAX_PARENT_DEPTH:
                raise ProjectionError("cyclic_or_excessive_parent_graph")
            seen.add(current)
            current = parents.get(current)


def redact_string(value: str) -> str:
    if len(value.encode()) > MAX_STRING_BYTES:
        raise ProjectionError("argument_string_too_large")
    if PRIVATE_KEY.search(value):
        return "<redacted-private-key>"
    value = BEARER.sub(r"\1<redacted>", value)
    value = JWT.sub("<redacted-jwt>", value)
    value = URL_USERINFO.sub(r"\1<redacted>:<redacted>@", value)
    return SECRET_ASSIGNMENT.sub(r"\1<redacted>", value)


def bounded_arguments(value: object, *, key: str = "", depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [MAX_ITEMS]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise ProjectionError("arguments_exceed_shape_bound")
    if SENSITIVE_KEY.search(key):
        return "<redacted>"
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_argument")
        return value
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [bounded_arguments(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(not isinstance(item_key, str) for item_key in value):
            raise ProjectionError("invalid_argument_object")
        return {
            item_key: bounded_arguments(item, key=item_key, depth=depth + 1, budget=budget)
            for item_key, item in value.items()
        }
    raise ProjectionError("unsupported_argument_value")


def project_arguments(value: object) -> dict[str, Any]:
    parsed = strict_json(value, "invalid_arguments") if isinstance(value, str) else value
    if not isinstance(parsed, Mapping):
        raise ProjectionError("invalid_arguments")
    projected = bounded_arguments(parsed)
    if not isinstance(projected, dict):
        raise ProjectionError("invalid_arguments")
    if len(canonical_json(projected).encode()) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    return projected


def message_parts(message: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    parts = message.get("parts")
    if not isinstance(parts, list) or len(parts) > MAX_PARTS:
        return []
    return [part for part in parts if isinstance(part, Mapping)]


def response_occurrences(spans: Sequence[Span]) -> dict[str, list[tuple[int, object, str | None]]]:
    responses: dict[str, list[tuple[int, object, str | None]]] = defaultdict(list)
    for span_index, span in enumerate(spans):
        for message in span.input_messages:
            # OpenAI-style traces use role=tool; Anthropic-style BrowseComp
            # traces use role=user with a typed tool_call_response part.
            if message.get("role") not in {"tool", "user"}:
                continue
            for part in message_parts(message):
                if part.get("type") not in {"tool_call_response", "tool_result", "tool_response"}:
                    continue
                response_id = part.get("id", part.get("tool_call_id"))
                if not isinstance(response_id, str) or not SAFE_ID.fullmatch(response_id):
                    continue
                explicit_status: str | None = None
                if part.get("is_error") is True:
                    explicit_status = "failed"
                elif part.get("is_error") is False:
                    explicit_status = "succeeded"
                responses[response_id].append((span_index, part.get("result"), explicit_status))
    return responses


def unique_later_response(
    call_id: str,
    call_span_index: int,
    responses: Mapping[str, Sequence[tuple[int, object, str | None]]],
) -> tuple[int, str] | None:
    matches = [match for match in responses.get(call_id, ()) if match[0] > call_span_index]
    if not matches:
        return None
    fingerprints: set[str] = set()
    statuses: set[str] = set()
    for _, body, explicit_status in matches:
        try:
            fingerprints.add(digest(canonical_json(body)))
        except (TypeError, ValueError, RecursionError):
            return None
        if explicit_status is not None:
            statuses.add(explicit_status)
    if len(fingerprints) != 1 or len(statuses) > 1:
        return None
    return min(match[0] for match in matches), next(iter(statuses), "unknown")


def extract_calls(spans: Sequence[Span], statistics: Counter[str]) -> list[Call]:
    responses = response_occurrences(spans)
    calls: list[Call] = []
    seen_ids: set[str] = set()
    for span_index, span in enumerate(spans):
        for message in span.output_messages:
            if message.get("role") != "assistant":
                continue
            for part_index, part in enumerate(message_parts(message)):
                if part.get("type") != "tool_call":
                    continue
                statistics["source_tool_calls"] += 1
                call_id = part.get("id")
                tool_name = part.get("name")
                if (
                    not isinstance(call_id, str)
                    or not SAFE_ID.fullmatch(call_id)
                    or call_id in seen_ids
                    or not isinstance(tool_name, str)
                    or not SAFE_TOOL.fullmatch(tool_name)
                ):
                    statistics["quarantined:invalid_or_duplicate_call"] += 1
                    continue
                seen_ids.add(call_id)
                response = unique_later_response(call_id, span_index, responses)
                if response is None:
                    statistics["quarantined:missing_or_ambiguous_response"] += 1
                    continue
                try:
                    arguments = project_arguments(part.get("arguments"))
                except ProjectionError as exc:
                    statistics[f"quarantined:{exc.code}"] += 1
                    continue
                _, outcome = response
                calls.append(Call(call_id, tool_name, arguments, span.span_id, span_index, part_index, outcome))
                statistics["exact_call_response_pairs"] += 1
    calls.sort(key=lambda call: (call.span_index, call.part_index, call.call_id))
    return calls


def text_parts(messages: Sequence[Mapping[str, Any]]) -> Iterator[str]:
    for message in messages:
        for part in message_parts(message):
            if part.get("type") == "text" and isinstance(part.get("content"), str):
                yield part["content"]


def task_fingerprint_and_language(spans: Sequence[Span], benchmark: str) -> tuple[str, bool]:
    if not spans:
        raise ProjectionError("no_spans")
    # The initial input carries the task/scenario. It is used only to cluster
    # repeated model runs and validate language; the text is never emitted.
    initial = list(text_parts(spans[0].input_messages))
    if not initial:
        raise ProjectionError("missing_task_context")
    task_material = "\n".join(initial)
    words = [word.casefold() for word in ENGLISH_WORD.findall(task_material)]
    latin = non_latin = 0
    for character in task_material:
        if not character.isalpha():
            continue
        if "LATIN" in unicodedata.name(character, ""):
            latin += 1
        else:
            non_latin += 1
    english = (
        latin >= 20 and (non_latin <= 2 or non_latin * 50 <= latin) and any(word in ENGLISH_MARKERS for word in words)
    )
    return digest("discoposse-task-cluster-v1", benchmark, canonical_json(initial))[:24], english


def assigned_split(split_group: str) -> str:
    bucket = int(split_group[:8], 16) % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def event_payload(call: Call, offset: int) -> dict[str, Any]:
    event: dict[str, Any] = {
        "tool_name": call.tool_name,
        "args": call.arguments,
        "dialect": "none",
        "outcome": call.outcome,
        "offset_seconds": offset,
    }
    if call.tool_name.casefold() in SHELL_TOOLS:
        command = call.arguments.get("command")
        if isinstance(command, str):
            event.update(command=command, dialect="posix")
    return event


def truth(stateful: bool) -> dict[str, Any]:
    categories = [
        "discoposse_agent_llm_traces",
        "ordinary_benchmark_intent",
        "exact_call_response_identity",
        "bounded_action_sequence" if stateful else "structured_tool_call",
    ]
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "medium",
        "label_source": "discoposse:benchmark_family_benign_intent",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": categories,
    }


def project_trajectory(row: Mapping[str, Any], *, revision: str) -> tuple[list[dict[str, Any]], str, str, str]:
    benchmark = normalize_benchmark(row.get("benchmark"))
    session_id = required_id(row.get("session_id"), "invalid_session_id")
    raw_spans = row.get("spans")
    if not isinstance(raw_spans, list) or not raw_spans or len(raw_spans) > MAX_SPANS:
        raise ProjectionError("invalid_span_collection")
    spans = [project_span(raw, session_id) for raw in raw_spans if isinstance(raw, Mapping)]
    if len(spans) != len(raw_spans):
        raise ProjectionError("invalid_span")
    spans.sort(key=lambda span: (span.start_time, span.span_id))
    validate_parent_graph(spans)
    if len({span.trace_id for span in spans}) != 1:
        raise ProjectionError("mixed_trace_ids")
    split_group, english = task_fingerprint_and_language(spans, benchmark)
    if not english:
        raise ProjectionError("non_english_or_unknown")
    statistics: Counter[str] = Counter()
    calls = extract_calls(spans, statistics)
    if not calls:
        raise ProjectionError("no_exact_call_response_pairs")
    sequence = canonical_json(
        [{"tool_name": call.tool_name, "args": call.arguments, "outcome": call.outcome} for call in calls]
    )
    trajectory_fingerprint = digest("discoposse-trajectory-v1", benchmark, sequence)
    trajectory_id = digest(DATASET_ID, revision, benchmark, session_id, trajectory_fingerprint)[:24]
    split = assigned_split(split_group)
    source_base = {
        "dataset": DATASET_ID,
        "revision": revision,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }
    common_strata = {
        "language": "en",
        "ecosystem": "agent_execution_trace",
        "campaign": benchmark,
        "domain": benchmark,
        "hard_negative": True,
        "split_group": split_group,
        "trajectory_id": trajectory_id,
    }
    cases: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        event = event_payload(call, 0)
        event.pop("outcome")
        event.pop("offset_seconds")
        cases.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"discoposse/{trajectory_id}/call-{index:04d}",
                "source": {
                    **source_base,
                    "original_id": f"session:{digest(session_id)[:24]}#call:{index}",
                },
                "split": split,
                "surface": "action",
                "payload": {"direction": "tool_call", **event},
                "truth": truth(False),
                "strata": {**common_strata, "sequence_index": index, "call_index": index},
            }
        )
        window = calls[max(0, index - MAX_EVENTS + 1) : index + 1]
        if len(window) < 2:
            continue
        cases.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": f"discoposse/{trajectory_id}/window-{index:04d}",
                "source": {
                    **source_base,
                    "original_id": f"session:{digest(session_id)[:24]}#window:{index}",
                },
                "split": split,
                "surface": "stateful",
                "payload": {
                    "direction": "tool_call",
                    "events": [event_payload(item, offset) for offset, item in enumerate(window)],
                },
                "truth": truth(True),
                "strata": {**common_strata, "sequence_index": index, "call_index": index},
            }
        )
    return cases, split_group, trajectory_fingerprint, benchmark


def normalize(rows: Iterable[Mapping[str, Any]], *, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned commit {SOURCE_REVISION}")
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    seen_sessions: set[str] = set()
    seen_trajectories: set[tuple[str, str]] = set()
    for row in rows:
        counts["source_rows"] += 1
        session = row.get("session_id")
        if isinstance(session, str) and session in seen_sessions:
            skipped["duplicate_session_id"] += 1
            continue
        if isinstance(session, str):
            seen_sessions.add(session)
        try:
            projected, split_group, trajectory_fingerprint, benchmark = project_trajectory(row, revision=revision)
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        dedup_key = (split_group, trajectory_fingerprint)
        if dedup_key in seen_trajectories:
            skipped["duplicate_task_trajectory"] += 1
            continue
        seen_trajectories.add(dedup_key)
        counts["normalized_trajectories"] += 1
        counts[f"trajectories_{benchmark}"] += 1
        counts["action_cases"] += sum(case["surface"] == "action" for case in projected)
        counts["stateful_cases"] += sum(case["surface"] == "stateful" for case in projected)
        cases.extend(projected)
    cases.sort(key=lambda case: str(case["id"]))
    counts["cases"] = len(cases)
    return cases, {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_url": SOURCE_URL,
        "source_revision": revision,
        "source_license": SOURCE_LICENSE,
        "row_count": len(cases),
        "counts": dict(sorted(counts.items())),
        "skipped": dict(sorted(skipped.items())),
        "label_policy": (
            "Only English AppWorld, BrowseCompPlus, and tau2 benchmark-family traces with "
            "exact call/response identity are benign-intent FPR cases. Status and task success "
            "are not safety labels; ambiguity is quarantined."
        ),
        "projection_policy": (
            "Prompt, prose, reasoning, result bodies, schemas, and secrets are excluded; "
            "rolling stateful cases contain the current event and at most eight predecessors."
        ),
        "split_policy": (
            "70/15/15 deterministic development/validation/test assignment by initial-task "
            "fingerprint; identical trajectories within a task cluster are deduplicated."
        ),
        "upstream_schema_note": (
            "The pinned Parquet schema omits parent_span_id. Causality therefore requires "
            "same-trace chronological call/response ID continuity; no parent is inferred. "
            "Source timestamps without a zone are used only for within-trace ordering."
        ),
    }


def parquet_rows(paths: Iterable[Path]) -> Iterator[Mapping[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to normalize Parquet source files") from exc
    for path in sorted(paths, key=lambda item: str(item)):
        if not path.is_file() or path.suffix != ".parquet":
            raise ValueError(f"expected Parquet source file: {path}")
        source = parquet.ParquetFile(path)
        required = {"benchmark", "session_id", "spans"}
        if not required <= set(source.schema_arrow.names):
            raise ValueError(f"{path}: incompatible DiscoPosse schema")
        for batch in source.iter_batches(batch_size=32, columns=sorted(required)):
            for row in batch.to_pylist():
                if not isinstance(row, Mapping):
                    raise ValueError(f"{path}: non-object source row")
                yield row


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text()))
    seen: set[str] = set()
    for row in rows:
        row_id = row.get("id")
        if not isinstance(row_id, str) or row_id in seen:
            raise ValueError("duplicate or invalid benchmark case ID")
        seen.add(row_id)
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            raise ValueError(f"{row_id}: {errors[0].message}")
        if row["truth"]["source_truth"] != "benign":
            raise ValueError(f"{row_id}: this adapter cannot assign malicious truth")
        if row["surface"] == "stateful":
            count = len(row["payload"]["events"])
            if not 2 <= count <= MAX_EVENTS:
                raise ValueError(f"{row_id}: invalid bounded event count")


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


def build_normalization_manifest(
    cases: Sequence[dict[str, Any]],
    diagnostics: Mapping[str, Any],
    output: bytes,
) -> dict[str, Any]:
    statistics = {
        **{key: int(value) for key, value in diagnostics["counts"].items()},
        **{f"skipped_{key}": int(value) for key, value in diagnostics["skipped"].items()},
    }
    duplicate_count = int(diagnostics["skipped"].get("duplicate_task_trajectory", 0))
    return {
        "adapter_statistics": {ADAPTER: dict(sorted(statistics.items()))},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": duplicate_count,
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": SOURCE_BYTES,
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "path": "data/train-*-of-00039.parquet",
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
            "sha256": SOURCE_TREE_SHA256,
        },
    }


def main() -> int:
    args = parse_args()
    if args.revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned commit {SOURCE_REVISION}")
    validate_source_files(args.input)
    cases, diagnostics = normalize(parquet_rows(args.input), revision=args.revision)
    validate_cases(cases, args.schema)
    output = "".join(canonical_json(case) + "\n" for case in cases).encode()
    manifest = build_normalization_manifest(cases, diagnostics, output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, output)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
