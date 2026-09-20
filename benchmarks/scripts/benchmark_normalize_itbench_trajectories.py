#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned ITBench SRE trajectories as conservative benign evidence.

ITBench task completion is not security ground truth. A call is an applicable
benign hard negative only when it is an English-session, exactly paired,
affirmatively successful invocation of a closed structured diagnostic tool,
with a complete static argument object and workspace-scoped data paths. Shell
wrappers, mutations, credential or secret access, Kubernetes object reads,
exec/apply/delete, RBAC/security changes, unknown tools, failures, and ambiguous
pairings remain contextual and out of scope.

Only projected call arguments enter detector payloads. Instructions, reasoning,
assistant prose, result bodies, judge output, agent answers, and ground truth are
never emitted. Result data is used solely to derive the runtime-visible outcome.
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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "ibm-research/ITBench-Trajectories"
SOURCE_URL = "https://huggingface.co/datasets/ibm-research/ITBench-Trajectories"
SOURCE_REVISION = "c3093ee33b4f16a8eed97ade1266d0d7e88b2dec"
SOURCE_LICENSE = "CC-BY-NC-4.0"
SOURCE_REDISTRIBUTION = "download-only"
SOURCE_PREFIX = "ReAct-Agent-Trajectories/OpenAI-GPT-OSS-120B/sre"
SOURCE_FILES = 105
SOURCE_BYTES = 21_697_208
SOURCE_INVENTORY_SHA256 = "aa8ab12d26cac3eb247af9c8aa1ebe1b7933adae41273ea62e8e1267a72aafae"
ADAPTER = "itbench-trajectories-sre-benign-v1"
PRE_PARTITION_SPLIT = "smoke"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_ROWS = 2048
MAX_CALLS = 512
MAX_ARGUMENT_BYTES = 256 * 1024
MAX_STRING_BYTES = 64 * 1024
MAX_ITEMS = 1024
MAX_DEPTH = 16
MAX_EVENTS = 9

SOURCE_PATH = re.compile(
    rf"^{re.escape(SOURCE_PREFIX)}/Scenario-(?P<scenario>[1-9][0-9]*)/(?P<run>[1-9][0-9]*)/session\.jsonl$"
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/|<>-]{0,239}$")
DYNAMIC_TEXT = re.compile(r"(?:\$\{|\$\(|`|\x00|\r|\n)")
ERROR_TEXT = re.compile(
    r"(?i)^\s*(?:error\b|failed\b|failure\b|invalid\b|permission denied\b|access denied\b|"
    r"unauthorized\b|forbidden\b|timed? out\b|unable to\b|cannot\b|traceback\b)"
)
SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:access[_-]?key|api[_-]?key|auth|authorization|cookie|credential|"
    r"password|private[_-]?key|secret|session[_-]?token|token)(?:$|[_-])"
)
SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:\.aws|\.kube|\.ssh|\.env|credentials?|id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"secrets?)(?:$|[./_-])"
)
SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b(?:api[_-]?key|authorization|credential|password|private[_-]?key|secret|token)\s*[:=]\s*\S+)"
)
IDENTITY_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:cluster|host|hostname|k8[_-]?object[_-]?name|namespace|node|object|pod|"
    r"service|service[_-]?name|trace[_-]?id|uid|user)(?:$|[_-])"
)
ENGLISH_WORD = re.compile(r"(?i)\b(?:the|and|to|of|in|for|is|with|from|this|that|you|an|a)\b")

# Closed diagnostic-only schemas. Keys not listed here fail closed. Fields that
# can execute expressions or return Kubernetes specs are intentionally absent.
SAFE_SCHEMAS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "mcp__sre_utils__alert_summary": (
        frozenset({"base_dir", "limit", "min_duration_min", "start_time", "end_time", "state_filter", "time_basis"}),
        frozenset(),
    ),
    "mcp__sre_utils__alert_analysis": (
        frozenset({"agg", "base_dir", "filters", "group_by", "limit", "sort_by", "state_filter", "time_basis"}),
        frozenset({"base_dir"}),
    ),
    "mcp__sre_utils__event_analysis": (
        frozenset({"agg", "events_file", "filters", "group_by", "limit", "sort_by"}),
        frozenset({"events_file"}),
    ),
    "mcp__sre_utils__get_metric_anomalies": (
        frozenset({"base_dir", "k8_object_name", "metric_name_filter"}),
        frozenset({"base_dir"}),
    ),
    "mcp__sre_utils__get_trace_error_tree": (
        frozenset(
            {"delta_time", "error_threshold_pct", "latency_threshold_pct", "pivot_time", "service_name", "trace_file"}
        ),
        frozenset({"trace_file"}),
    ),
    "mcp__sre_utils__log_analysis": (
        frozenset({"limit", "logs_file", "pattern_analysis", "service_name"}),
        frozenset({"logs_file"}),
    ),
    "mcp__sre_utils__metric_analysis": (
        frozenset(
            {
                "agg",
                "base_dir",
                "end_time",
                "filters",
                "group_by",
                "k8_object_name",
                "limit",
                "metric_name_filter",
                "metric_names",
                "object_pattern",
                "start_time",
                "verbosity",
            }
        ),
        frozenset({"base_dir"}),
    ),
}
PATH_KEYS = frozenset({"base_dir", "events_file", "logs_file", "trace_file"})


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Call:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    row_index: int
    sequence_index: int


@dataclass(frozen=True)
class Result:
    call_id: str
    output: object
    row_index: int


@dataclass(frozen=True)
class Event:
    call: Call
    arguments: dict[str, Any]
    outcome: str
    benign: bool
    reason: str


@dataclass(frozen=True)
class Candidate:
    source_key: str
    payload_digest: str
    case: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--skip-source-verification", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


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


def reject_nonfinite(value: str) -> NoReturn:
    raise ProjectionError(f"non_finite_json:{value}")


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def strict_json(text: str, code: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProjectionError(code) from exc


def english_compatible(*texts: object) -> bool:
    joined = " ".join(item for item in texts if isinstance(item, str))
    if not joined or len(joined.encode()) > MAX_STRING_BYTES:
        return False
    printable = sum(ch.isprintable() or ch.isspace() for ch in joined)
    latin = sum("LATIN" in unicodedata.name(ch, "") for ch in joined if ch.isalpha())
    alpha = sum(ch.isalpha() for ch in joined)
    return printable / len(joined) >= 0.98 and (not alpha or latin / alpha >= 0.9) and bool(ENGLISH_WORD.search(joined))


def bounded_value(value: object, *, depth: int = 0) -> bool:
    if depth > MAX_DEPTH:
        return False
    if value is None or type(value) is bool or type(value) is int:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value.encode()) <= MAX_STRING_BYTES
    if isinstance(value, list):
        return len(value) <= MAX_ITEMS and all(bounded_value(item, depth=depth + 1) for item in value)
    if isinstance(value, Mapping):
        return len(value) <= MAX_ITEMS and all(
            isinstance(key, str) and len(key.encode()) <= 256 and bounded_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def scoped_path(value: object, cwd: str, scenario: str) -> str | None:
    if not isinstance(value, str) or not value or SENSITIVE_PATH.search(value) or DYNAMIC_TEXT.search(value):
        return None
    root = PurePosixPath(cwd)
    candidate = PurePosixPath(value)
    if not root.is_absolute():
        return None
    resolved = candidate if candidate.is_absolute() else root / candidate
    parts: list[str] = []
    for part in resolved.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    normalized = PurePosixPath("/", *parts)
    try:
        relative = normalized.relative_to(root)
    except ValueError:
        sandbox = PurePosixPath("/root/projects/open_source/zero")
        scenario_name = f"Scenario-{scenario}"
        if not normalized.is_relative_to(sandbox) or scenario_name not in normalized.parts:
            return None
        scenario_index = normalized.parts.index(scenario_name)
        scenario_root = PurePosixPath(*normalized.parts[: scenario_index + 1])
        try:
            relative = normalized.relative_to(scenario_root)
        except ValueError:
            return None
    return "/workspace" if str(relative) == "." else f"/workspace/{relative.as_posix()}"


def redact_value(key: str, value: object, cwd: str, scenario: str, *, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("arguments_too_deep")
    if key in PATH_KEYS:
        projected = scoped_path(value, cwd, scenario)
        if projected is None:
            raise ProjectionError("unscoped_or_sensitive_path")
        return projected
    if SENSITIVE_KEY.search(key):
        raise ProjectionError("sensitive_argument")
    if isinstance(value, str):
        if DYNAMIC_TEXT.search(value):
            raise ProjectionError("dynamic_argument")
        if SENSITIVE_PATH.search(value) or SECRET_VALUE.search(value):
            raise ProjectionError("sensitive_argument")
        if IDENTITY_KEY.search(key):
            return {"identity_ref": digest("itbench-identity-v1", value)[:20]}
        return value
    if isinstance(value, list):
        return [redact_value(key, item, cwd, scenario, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        return {
            str(child): redact_value(str(child), item, cwd, scenario, depth=depth + 1) for child, item in value.items()
        }
    return value


def project_safe_arguments(tool_name: str, arguments: Mapping[str, Any], cwd: str, scenario: str) -> dict[str, Any]:
    schema = SAFE_SCHEMAS.get(tool_name)
    if schema is None:
        raise ProjectionError("unsupported_or_protected_tool")
    allowed, required = schema
    keys = frozenset(arguments)
    if not required.issubset(keys) or not keys.issubset(allowed):
        raise ProjectionError("argument_schema_not_closed")
    if not bounded_value(arguments) or len(canonical_json(arguments).encode()) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_or_oversized_arguments")
    projected = {str(key): redact_value(str(key), value, cwd, scenario) for key, value in arguments.items()}
    if len(canonical_json(projected).encode()) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("oversized_projected_arguments")
    return projected


def parse_call(payload: Mapping[str, Any], row_index: int, sequence_index: int) -> Call | None:
    if payload.get("type") != "function_call":
        return None
    call_id, name, raw_arguments = payload.get("call_id"), payload.get("name"), payload.get("arguments")
    if not isinstance(call_id, str) or not SAFE_ID.fullmatch(call_id):
        raise ProjectionError("invalid_call_id")
    if not isinstance(name, str) or not SAFE_ID.fullmatch(name):
        raise ProjectionError("invalid_tool_name")
    if not isinstance(raw_arguments, str) or len(raw_arguments.encode()) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_or_oversized_arguments")
    arguments = strict_json(raw_arguments, "invalid_arguments")
    if not isinstance(arguments, dict) or not bounded_value(arguments):
        raise ProjectionError("arguments_not_concrete_object")
    return Call(call_id, name, arguments, row_index, sequence_index)


def parse_result(payload: Mapping[str, Any], row_index: int) -> Result | None:
    if payload.get("type") != "function_call_output":
        return None
    call_id, raw_output = payload.get("call_id"), payload.get("output")
    if not isinstance(call_id, str) or not SAFE_ID.fullmatch(call_id) or not isinstance(raw_output, str):
        raise ProjectionError("invalid_result")
    if len(raw_output.encode()) > MAX_FILE_BYTES:
        raise ProjectionError("oversized_result")
    return Result(call_id, strict_json(raw_output, "invalid_result_json"), row_index)


def result_outcome(result: Result | None) -> str:
    if result is None:
        return "unknown"
    value = result.output
    if isinstance(value, Mapping):
        metadata = value.get("metadata")
        if isinstance(metadata, Mapping) and type(metadata.get("exit_code")) is int:
            return "succeeded" if metadata["exit_code"] == 0 else "failed"
        return "unknown"
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], Mapping):
        block = value[0]
        if set(block) == {"type", "text"} and block.get("type") == "text" and isinstance(block.get("text"), str):
            return "failed" if ERROR_TEXT.search(block["text"]) else "succeeded"
    return "unknown"


def truth(benign: bool, reason: str, kind: str) -> dict[str, object]:
    if benign:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "itbench:successful-closed-diagnostic-v1",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": ["itbench_sre", "benign_hard_negative", kind],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "itbench:conservative-context-v1",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": ["itbench_sre", "contextual_tool_call"],
        "exclusion_reason": reason,
    }


def event_payload(event: Event, *, stateful: bool = False, first_index: int = 0) -> dict[str, object]:
    payload: dict[str, object] = {
        "tool_name": event.call.tool_name,
        "args": event.arguments,
        "dialect": "none",
        "cwd": "/workspace",
    }
    if stateful:
        payload["outcome"] = event.outcome
        payload["offset_seconds"] = event.call.sequence_index - first_index
    return payload


def base_case(
    *,
    revision: str,
    original_id: str,
    scenario: str,
    run: str,
    event: Event,
    suffix: str,
    benign: bool,
    reason: str,
    kind: str,
) -> dict[str, Any]:
    identity = digest("itbench-case-v1", original_id, suffix)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"itbench-sre/{identity[:32]}",
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "original_id": f"{original_id}:{suffix}",
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
        },
        "split": PRE_PARTITION_SPLIT,
        "truth": truth(benign, reason, kind),
        "strata": {
            "platform": "linux",
            "dialect": "structured",
            "language": "en",
            "ecosystem": "kubernetes_sre",
            "campaign": "itbench_sre",
            "domain": "benign_sre_diagnostics",
            "hard_negative": benign,
            "split_group": digest("itbench-scenario-v1", scenario)[:24],
            "trajectory_id": digest("itbench-run-v1", scenario, run)[:24],
            "sequence_index": event.call.sequence_index,
            "call_index": event.call.sequence_index,
        },
    }


def normalize_session(
    rows: Sequence[Mapping[str, Any]], *, original_id: str, scenario: str, run: str, revision: str = SOURCE_REVISION
) -> tuple[list[Candidate], Counter[str]]:
    statistics: Counter[str] = Counter()
    if len(rows) > MAX_ROWS:
        raise ProjectionError("too_many_rows")
    metadata = [row.get("payload") for row in rows if row.get("type") == "session_meta"]
    if len(metadata) != 1 or not isinstance(metadata[0], Mapping):
        raise ProjectionError("missing_or_ambiguous_session_metadata")
    cwd = metadata[0].get("cwd")
    instructions = metadata[0].get("instructions")
    if not isinstance(cwd, str) or not PurePosixPath(cwd).is_absolute():
        raise ProjectionError("invalid_workspace")
    workspace = str(PurePosixPath(cwd).parent)
    if workspace == "/":
        raise ProjectionError("invalid_workspace")
    if not english_compatible(instructions):
        raise ProjectionError("non_english_or_unknown")

    calls: list[Call] = []
    results: list[Result] = []
    for row_index, row in enumerate(rows):
        if row.get("type") != "response_item" or not isinstance(row.get("payload"), Mapping):
            continue
        payload = row["payload"]
        try:
            parsed_call = parse_call(payload, row_index, len(calls))
        except ProjectionError as exc:
            statistics[f"excluded_call_{exc.code}"] += 1
            parsed_call = None
        if parsed_call is not None:
            calls.append(parsed_call)
        try:
            parsed_result = parse_result(payload, row_index)
        except ProjectionError as exc:
            statistics[f"excluded_result_{exc.code}"] += 1
            parsed_result = None
        if parsed_result is not None:
            results.append(parsed_result)
    if len(calls) > MAX_CALLS:
        raise ProjectionError("too_many_calls")
    result_by_id: dict[str, list[Result]] = defaultdict(list)
    call_counts = Counter(call.call_id for call in calls)
    for result in results:
        result_by_id[result.call_id].append(result)

    events: list[Event] = []
    for call in calls:
        exact = [item for item in result_by_id.get(call.call_id, []) if item.row_index > call.row_index]
        result = exact[0] if call_counts[call.call_id] == 1 and len(exact) == 1 else None
        outcome = result_outcome(result)
        benign = False
        reason = "missing_or_ambiguous_exact_result" if result is None else "result_not_affirmatively_successful"
        projected: dict[str, Any] = {}
        if outcome == "succeeded":
            try:
                projected = project_safe_arguments(call.tool_name, call.arguments, workspace, scenario)
                benign = True
                reason = "benign"
            except ProjectionError as exc:
                reason = exc.code
        elif result is not None and outcome == "failed":
            reason = "call_failed"
        events.append(Event(call, projected, outcome, benign, reason))
        statistics["benign_action_events" if benign else "contextual_action_events"] += 1
        statistics[f"disposition_{reason}"] += 1

    candidates: list[Candidate] = []
    for index, event in enumerate(events):
        payload = {"direction": "tool_call", **event_payload(event)}
        case = base_case(
            revision=revision,
            original_id=original_id,
            scenario=scenario,
            run=run,
            event=event,
            suffix=f"call-{event.call.sequence_index}-{event.call.call_id}",
            benign=event.benign,
            reason=event.reason,
            kind="successful_scoped_sre_diagnostic",
        )
        case["surface"] = "action"
        case["payload"] = payload
        candidates.append(
            Candidate(
                f"{original_id}:{event.call.sequence_index}:action",
                digest("itbench-payload-v1", "action", canonical_json(payload)),
                case,
            )
        )
        if not event.benign:
            continue
        start = index
        while start > 0 and index - start < MAX_EVENTS - 1 and events[start - 1].benign:
            start -= 1
        window = events[start : index + 1]
        if len(window) < 2:
            continue
        first = window[0].call.sequence_index
        stateful_payload = {
            "direction": "tool_call",
            "events": [event_payload(item, stateful=True, first_index=first) for item in window],
        }
        stateful = base_case(
            revision=revision,
            original_id=original_id,
            scenario=scenario,
            run=run,
            event=event,
            suffix=f"window-{first}-{event.call.sequence_index}",
            benign=True,
            reason="benign",
            kind="successful_scoped_sre_diagnostic_sequence",
        )
        stateful["surface"] = "stateful"
        stateful["payload"] = stateful_payload
        candidates.append(
            Candidate(
                f"{original_id}:{event.call.sequence_index}:stateful",
                digest("itbench-payload-v1", "stateful", canonical_json(stateful_payload)),
                stateful,
            )
        )
        statistics["benign_stateful_windows"] += 1
    statistics["source_calls"] += len(calls)
    statistics["source_results"] += len(results)
    return candidates, statistics


def load_jsonl(path: Path) -> list[Mapping[str, Any]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"invalid or oversized source file: {path}")
    rows: list[Mapping[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            if len(line.encode()) > MAX_LINE_BYTES:
                raise ValueError(f"oversized line: {path}:{line_number}")
            value = strict_json(line, "invalid_source_jsonl")
            if not isinstance(value, Mapping):
                raise ValueError(f"source row is not an object: {path}:{line_number}")
            rows.append(value)
    return rows


def source_files(root: Path, verify: bool) -> tuple[list[tuple[str, str, str, Path]], str, int]:
    root = root.resolve(strict=True)
    files: list[tuple[str, str, str, Path]] = []
    inventory = hashlib.sha256()
    total_bytes = 0
    for path in sorted(root.rglob("session.jsonl")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source file must be regular: {path}")
        resolved = path.resolve(strict=True)
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("source path escapes input root") from exc
        match = SOURCE_PATH.fullmatch(relative)
        if match is None:
            raise ValueError(f"unexpected trajectory path: {relative}")
        size = resolved.stat().st_size
        sha = file_sha256(resolved)
        inventory.update(f"{sha}  {relative}\n".encode())
        total_bytes += size
        files.append((relative, match["scenario"], match["run"], resolved))
    inventory_sha = inventory.hexdigest()
    if verify and (
        len(files) != SOURCE_FILES or total_bytes != SOURCE_BYTES or inventory_sha != SOURCE_INVENTORY_SHA256
    ):
        raise ValueError("pinned ITBench session inventory mismatch")
    return files, inventory_sha, total_bytes


def deduplicate(candidates: Sequence[Candidate], statistics: Counter[str]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        grouped[candidate.payload_digest].append(candidate)
    selected: list[Candidate] = []
    for values in grouped.values():
        contracts = {
            (
                value.case["truth"]["source_truth"],
                value.case["truth"]["applicability"],
                value.case["truth"]["expected_disposition"],
            )
            for value in values
        }
        if len(contracts) != 1:
            statistics["exact_payload_label_conflicts_excluded"] += len(values)
            continue
        ordered = sorted(values, key=lambda value: value.source_key)
        selected.append(ordered[0])
        statistics["exact_payload_duplicates_removed"] += len(ordered) - 1
    return sorted((value.case for value in selected), key=lambda case: case["id"])


def normalize_input(
    root: Path, *, revision: str = SOURCE_REVISION, verify_pinned_source: bool = True
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"ITBench revision must be pinned to {SOURCE_REVISION}")
    files, inventory_sha, total_bytes = source_files(root, verify_pinned_source)
    candidates: list[Candidate] = []
    statistics: Counter[str] = Counter()
    for original_id, scenario, run, path in files:
        statistics["source_sessions"] += 1
        try:
            projected, session_stats = normalize_session(
                load_jsonl(path), original_id=original_id, scenario=scenario, run=run, revision=revision
            )
        except ProjectionError as exc:
            statistics[f"quarantined_{exc.code}"] += 1
            continue
        candidates.extend(projected)
        statistics.update(session_stats)
        statistics["normalized_sessions"] += 1
    cases = deduplicate(candidates, statistics)
    output = b"".join((canonical_json(case) + "\n").encode() for case in cases)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": int(statistics["exact_payload_duplicates_removed"]),
        "label_conflicts_excluded": int(statistics["exact_payload_label_conflicts_excluded"]),
        "adapter_statistics": {ADAPTER: {key: int(value) for key, value in sorted(statistics.items())}},
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "source": {
            "dataset": DATASET_ID,
            "url": SOURCE_URL,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": SOURCE_PREFIX,
            "files": len(files),
            "bytes": total_bytes,
            "sha256": inventory_sha,
        },
    }
    return cases, manifest


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen: set[str] = set()
    for case in cases:
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{case.get('id', '<unknown>')}:{location}: {errors[0].message}")
        identifier = case["id"]
        if identifier in seen:
            raise ValueError(f"duplicate normalized case ID: {identifier}")
        seen.add(identifier)
        if case["truth"]["source_truth"] == "malicious":
            raise ValueError("ITBench trajectories cannot create malicious truth")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
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
    cases, manifest = normalize_input(
        args.input_dir, revision=args.revision, verify_pinned_source=not args.skip_source_verification
    )
    validate_cases(cases, args.schema)
    output = b"".join((canonical_json(case) + "\n").encode() for case in cases)
    atomic_write(args.output, output)
    atomic_write(args.manifest, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"cases": len(cases), "output_sha256": manifest["output_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
