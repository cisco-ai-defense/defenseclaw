#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize public AgentHazard native traces conservatively.

This adapter reads the pinned public AgentHazard tree without extracting its
archives. It retains exact native tool names and structured arguments, plus
only the execution metadata needed to distinguish linked success, failure,
denial, cancellation, approval-pending, and unobserved calls. Tool-result
bodies, prompts, assistant prose/reasoning, evaluator prose, final answers,
timestamps, and usage are never copied into runtime benchmark payloads.

AgentHazard labels harmful scenarios, not deterministic maliciousness of each
call or successful completion of each trajectory. Atomic calls therefore stay
unknown/proof-pending. Bounded stateful cases retain the source-positive
scenario label but remain contextual and out of scored scope until a separate
deterministic proof closes the operation, identity, lineage, and result joins.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import tempfile
import unicodedata
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"
ADAPTER = "agenthazard-native-traces-v2"
DATASET_ID = "Yunhao-Feng/AgentHazard"
SOURCE_URL = "https://huggingface.co/datasets/Yunhao-Feng/AgentHazard"
SOURCE_REVISION = "786147ad768f924608697cdcca87c367379b11ee"
CODE_URL = "https://github.com/Yunhao-Feng/AgentHazard"
CODE_REVISION = "0ea6aabc77d697ee3c3c61af63d839cbeb2d5709"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
CATALOG_PATH = "dataset.json"
EVALUATIONS_PATH = "evaluation_results.csv"
MAX_SOURCE_METADATA_BYTES = 32 * 1024 * 1024
MAX_SOURCE_LINE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVES = 32
MAX_MEMBERS_PER_ARCHIVE = 10_000
MAX_EVENTS = 8
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 256 * 1024
MAX_CONTAINER_ITEMS = 4096
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,239}$")
SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+ -]{0,159}$")
OPENCLAW_MEMBER = re.compile(r"(?:^|/)([0-9]+)_session\.jsonl$")
WRAPPED_MEMBER = re.compile(r"(?:^|/)trajectory_([0-9]+)\.jsonl$")

SUCCESS_STATES = frozenset({"completed", "ok", "success", "succeeded"})
FAILURE_STATES = frozenset({"error", "failed", "failure"})
DENIED_STATES = frozenset({"approval_denied", "denied", "not_approved", "permission_denied", "rejected"})
CANCELLED_STATES = frozenset({"canceled", "cancelled"})
PENDING_STATES = frozenset(
    {
        "approval_pending",
        "awaiting_approval",
        "pending",
        "requires_approval",
        "waiting_for_approval",
    }
)

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
    parser.add_argument("--revision", required=True)
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
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite_json(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


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
    result = value.strip()
    if any(unicodedata.category(character).startswith("C") for character in result):
        raise ProjectionError(code)
    return result


def bounded(value: object, *, depth: int = 0) -> object:
    if depth > 32:
        raise ProjectionError("arguments_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_argument")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("argument_value_too_large")
        return value
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ProjectionError("arguments_too_many_items")
        return [bounded(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_arguments_object")
        return {key: bounded(item, depth=depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def english_compatible(*texts: object) -> bool:
    latin = 0
    non_latin = 0
    for value in texts:
        if not isinstance(value, str):
            continue
        for character in value:
            if not unicodedata.category(character).startswith("L"):
                continue
            if "LATIN" in unicodedata.name(character, ""):
                latin += 1
            else:
                non_latin += 1
    return latin >= 20 and (non_latin <= 2 or non_latin * 50 <= latin)


def source_id(value: object, code: str = "invalid_task_id") -> int:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return int(value)
    raise ProjectionError(code)


def load_json(path: Path) -> object:
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_METADATA_BYTES:
        raise ValueError(f"missing or oversized source metadata: {path}")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite_json,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid source JSON: {path}") from exc


def load_catalog(path: Path) -> dict[int, dict[str, Any]]:
    rows = load_json(path)
    if not isinstance(rows, list):
        raise ValueError("AgentHazard dataset.json must contain an array")
    result: dict[int, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("AgentHazard catalog row must be an object")
        identifier = source_id(row.get("id"))
        if identifier in result:
            raise ValueError(f"duplicate AgentHazard task ID: {identifier}")
        category = required_text(row.get("category"), "invalid_category", maximum=160)
        strategy = required_text(row.get("jailbreak_method"), "invalid_jailbreak_method", maximum=160)
        if not SAFE_LABEL.fullmatch(category) or not SAFE_LABEL.fullmatch(strategy):
            raise ValueError(f"invalid AgentHazard labels for task {identifier}")
        query = row.get("query")
        decomposed = row.get("decomposed_query")
        if (
            not isinstance(query, str)
            or not isinstance(decomposed, list)
            or any(not isinstance(item, str) for item in decomposed)
        ):
            raise ValueError(f"invalid AgentHazard language fields for task {identifier}")
        result[identifier] = {
            "category": category,
            "strategy": strategy,
            "english": english_compatible(query, *decomposed),
        }
    return result


def load_evaluations(path: Path) -> dict[int, bool]:
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_METADATA_BYTES:
        raise ValueError(f"missing or oversized source metadata: {path}")
    csv.field_size_limit(MAX_SOURCE_METADATA_BYTES)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "id",
            "harmful",
            "reason",
            "target",
            "category",
            "comment",
            "jailbreak_method",
        }
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("invalid AgentHazard evaluation header")
        if not required.issubset(reader.fieldnames):
            raise ValueError("missing AgentHazard evaluation columns")
        result: dict[int, bool] = {}
        for row in reader:
            identifier = source_id(row.get("id"))
            if identifier in result:
                raise ValueError(f"duplicate AgentHazard evaluation ID: {identifier}")
            harmful = row.get("harmful", "").strip().lower()
            if harmful not in {"true", "false"}:
                raise ValueError(f"invalid AgentHazard harmful label: {identifier}")
            # Evaluator reason, target, comment, and other prose are deliberately
            # validated as present by the header but never retained.
            result[identifier] = harmful == "true"
    return result


def exact_status(value: object, code: str = "invalid_result_status") -> str:
    return required_text(value, code, maximum=80)


def status_class(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"[ -]+", "_", value.lower())


def explicit_status(mapping: Mapping[str, Any]) -> str | None:
    for key in ("status", "outcome", "state", "result_status", "resultStatus"):
        if key in mapping:
            return exact_status(mapping[key])
    return None


def explicit_approval(mapping: Mapping[str, Any]) -> str | None:
    for key in ("approval_status", "approvalStatus", "approval"):
        if key not in mapping:
            continue
        value = mapping[key]
        if type(value) is bool:
            return "approved" if value else "denied"
        return exact_status(value, "invalid_approval_status")
    return None


def outcome_from_result(
    *,
    result_present: bool,
    source_status: str | None,
    approval_status: str | None,
    is_error: bool | None,
    return_code: int | None,
    interrupted: bool | None,
    default_observed_success: bool,
) -> str:
    status = status_class(source_status)
    approval = status_class(approval_status)
    if approval in DENIED_STATES:
        return "denied"
    if approval in PENDING_STATES:
        return "unknown"
    if interrupted is True:
        return "cancelled"
    if status in DENIED_STATES:
        return "denied"
    if status in CANCELLED_STATES:
        return "cancelled"
    if status in PENDING_STATES or status == "running":
        return "unknown"
    if is_error is True or (return_code is not None and return_code != 0) or status in FAILURE_STATES:
        return "failed"
    if return_code == 0 or status in SUCCESS_STATES:
        return "succeeded"
    if result_present and is_error is False and default_observed_success:
        return "succeeded"
    return "unknown"


def safe_arguments(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_tool_arguments")
    try:
        size = len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProjectionError("invalid_tool_arguments") from exc
    if size > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    projected = bounded(value)
    if not isinstance(projected, dict):
        raise AssertionError("bounded argument object changed type")
    return projected


def tool_event(
    *,
    tool: object,
    arguments: object,
    call_id: object,
    ordinal: int,
    result: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    name = required_text(tool, "invalid_tool_name", maximum=240)
    identity = required_text(call_id, "invalid_tool_call_identity", maximum=240)
    if not SAFE_TOOL.fullmatch(name):
        raise ProjectionError("invalid_tool_name")
    args = safe_arguments(arguments)
    has_result_metadata = result is not None
    result_present = has_result_metadata and result.get("result_present", True) is True
    source_status = result.get("source_status") if has_result_metadata else None
    approval_status = result.get("approval_status") if has_result_metadata else None
    is_error = result.get("is_error") if has_result_metadata else None
    return_code = result.get("return_code") if has_result_metadata else None
    interrupted = result.get("interrupted") if has_result_metadata else None
    default_success = result.get("default_observed_success") is True if has_result_metadata else False
    if source_status is not None and not isinstance(source_status, str):
        raise ProjectionError("invalid_result_status")
    if approval_status is not None and not isinstance(approval_status, str):
        raise ProjectionError("invalid_approval_status")
    if is_error is not None and type(is_error) is not bool:
        raise ProjectionError("invalid_result_error_status")
    if return_code is not None and type(return_code) is not int:
        raise ProjectionError("invalid_result_return_code")
    if interrupted is not None and type(interrupted) is not bool:
        raise ProjectionError("invalid_result_interrupted_status")
    outcome = outcome_from_result(
        result_present=result_present,
        source_status=source_status,
        approval_status=approval_status,
        is_error=is_error,
        return_code=return_code,
        interrupted=interrupted,
        default_observed_success=default_success,
    )
    event: dict[str, Any] = {
        "tool_name": name,
        "args": args,
        "dialect": "none",
        "outcome": outcome,
        "offset_seconds": ordinal,
    }
    command = args.get("command")
    if (
        isinstance(command, str)
        and command
        and name.lower()
        in {
            "bash",
            "exec",
            "execute_command",
            "run_command",
            "shell",
        }
    ):
        event["command"] = command
        event["dialect"] = "posix"
    evidence: dict[str, Any] = {
        "event_index": ordinal,
        "call_ref": digest("agenthazard-call-v1", identity)[:24],
        "linked_result": result_present,
        "outcome": outcome,
        "execution_observed": outcome in {"succeeded", "failed"},
    }
    if source_status is not None:
        evidence["source_status"] = source_status
    if approval_status is not None:
        evidence["approval_status"] = approval_status
    if is_error is not None:
        evidence["is_error"] = is_error
    if return_code is not None:
        evidence["return_code"] = return_code
    if interrupted is not None:
        evidence["interrupted"] = interrupted
    return event, evidence


def openclaw_results(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for row in rows:
        message = row.get("message")
        if row.get("type") != "message" or not isinstance(message, Mapping):
            continue
        if message.get("role") != "toolResult":
            continue
        call_id = required_text(message.get("toolCallId"), "invalid_tool_result_identity", maximum=240)
        if call_id in results:
            raise ProjectionError("duplicate_tool_result_identity")
        details = message.get("details")
        if details is not None and not isinstance(details, Mapping):
            raise ProjectionError("invalid_tool_result_details")
        is_error = message.get("isError")
        if type(is_error) is not bool:
            raise ProjectionError("invalid_result_error_status")
        result_details = details or {}
        results[call_id] = {
            "source_status": explicit_status(result_details),
            "approval_status": explicit_approval(result_details) or explicit_approval(message),
            "is_error": is_error,
            "default_observed_success": True,
        }
    return results


def project_openclaw(rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results = openclaw_results(rows)
    events: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen_calls: set[str] = set()
    for row in rows:
        message = row.get("message")
        if row.get("type") != "message" or not isinstance(message, Mapping):
            continue
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            raise ProjectionError("invalid_assistant_content")
        for item in content:
            if not isinstance(item, Mapping) or item.get("type") != "toolCall":
                continue
            call_id = required_text(item.get("id"), "invalid_tool_call_identity", maximum=240)
            if call_id in seen_calls:
                raise ProjectionError("duplicate_tool_call_identity")
            seen_calls.add(call_id)
            event, event_evidence = tool_event(
                tool=item.get("name"),
                arguments=item.get("arguments"),
                call_id=call_id,
                ordinal=len(events),
                result=results.get(call_id),
            )
            events.append(event)
            evidence.append(event_evidence)
    return events, evidence


def history_results(history: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for row in history:
        message = row.get("message")
        if not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        result_meta = row.get("toolUseResult")
        if result_meta is not None and not isinstance(result_meta, Mapping):
            raise ProjectionError("invalid_tool_result_details")
        metadata = result_meta or {}
        for item in content:
            if not isinstance(item, Mapping) or item.get("type") != "tool_result":
                continue
            call_id = required_text(item.get("tool_use_id"), "invalid_tool_result_identity", maximum=240)
            if call_id in results:
                raise ProjectionError("duplicate_tool_result_identity")
            results[call_id] = {
                "source_status": explicit_status(metadata) or explicit_status(item),
                "approval_status": explicit_approval(metadata) or explicit_approval(item),
                "is_error": item.get("is_error") if type(item.get("is_error")) is bool else None,
                "default_observed_success": False,
            }
    return results


def project_claude_hooks(
    logs: Sequence[object],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if any(not isinstance(item, Mapping) for item in logs):
        raise ProjectionError("invalid_claude_hook_log")
    results: dict[str, dict[str, Any]] = {}
    post_calls: dict[str, Mapping[str, Any]] = {}
    for item in logs:
        if not isinstance(item, Mapping) or item.get("type") != "post_tool":
            continue
        call_id = required_text(item.get("tool_use_id"), "invalid_tool_result_identity", maximum=240)
        if call_id in results:
            raise ProjectionError("duplicate_tool_result_identity")
        response = item.get("tool_response")
        response_mapping = response if isinstance(response, Mapping) else {}
        explicit_error = response_mapping.get("isError")
        if explicit_error is None and response_mapping.get("error") is not None:
            explicit_error = True
        results[call_id] = {
            "source_status": explicit_status(response_mapping),
            "approval_status": explicit_approval(item) or explicit_approval(response_mapping),
            "is_error": explicit_error,
            "return_code": response_mapping.get("returnCode"),
            "interrupted": response_mapping.get("interrupted"),
            "default_observed_success": False,
        }
        post_calls[call_id] = item

    events: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen_calls: set[str] = set()
    for item in logs:
        if not isinstance(item, Mapping) or item.get("type") != "pre_tool":
            continue
        call_id = required_text(item.get("tool_use_id"), "invalid_tool_call_identity", maximum=240)
        if call_id in seen_calls:
            raise ProjectionError("duplicate_tool_call_identity")
        seen_calls.add(call_id)
        post = post_calls.get(call_id)
        if post is not None and (
            post.get("tool_name") != item.get("tool_name") or post.get("tool_input") != item.get("tool_input")
        ):
            raise ProjectionError("tool_result_call_mismatch")
        result = results.get(call_id)
        if result is None:
            approval_status = explicit_approval(item)
            if approval_status is not None:
                result = {
                    "result_present": False,
                    "source_status": None,
                    "approval_status": approval_status,
                    "is_error": None,
                    "return_code": None,
                    "interrupted": None,
                    "default_observed_success": False,
                }
        event, event_evidence = tool_event(
            tool=item.get("tool_name"),
            arguments=item.get("tool_input"),
            call_id=call_id,
            ordinal=len(events),
            result=result,
        )
        events.append(event)
        evidence.append(event_evidence)
    if set(results) - seen_calls:
        raise ProjectionError("orphan_tool_result_identity")
    return events, evidence


def project_wrapped(record: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    detail_logs = record.get("detail_logs")
    if detail_logs is None:
        return [], []
    if isinstance(detail_logs, list):
        return project_claude_hooks(detail_logs)
    if not isinstance(detail_logs, Mapping):
        raise ProjectionError("invalid_detail_logs")
    history = detail_logs.get("conversation_history")
    if history is None and not detail_logs:
        return [], []
    if not isinstance(history, list) or any(not isinstance(row, Mapping) for row in history):
        raise ProjectionError("invalid_conversation_history")
    results = history_results(history)
    events: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen_calls: set[str] = set()
    for row in history:
        message = row.get("message")
        if not isinstance(message, Mapping) or message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            raise ProjectionError("invalid_assistant_content")
        for item in content:
            if not isinstance(item, Mapping) or item.get("type") not in {
                "tool_use",
                "toolCall",
            }:
                continue
            call_id = required_text(item.get("id"), "invalid_tool_call_identity", maximum=240)
            if call_id in seen_calls:
                raise ProjectionError("duplicate_tool_call_identity")
            seen_calls.add(call_id)
            arguments = item.get("input") if item.get("type") == "tool_use" else item.get("arguments")
            event, event_evidence = tool_event(
                tool=item.get("name"),
                arguments=arguments,
                call_id=call_id,
                ordinal=len(events),
                result=results.get(call_id),
            )
            events.append(event)
            evidence.append(event_evidence)
    return events, evidence


def safe_member(info: zipfile.ZipInfo) -> bool:
    if info.is_dir():
        return False
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts or info.flag_bits & 0x1:
        raise ValueError(f"unsafe AgentHazard archive member: {info.filename}")
    if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
        raise ValueError(f"oversized AgentHazard archive member: {info.filename}")
    return info.filename.endswith(".jsonl")


def member_rows(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with archive.open(info, "r") as handle:
        while True:
            raw = handle.readline(MAX_SOURCE_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_SOURCE_LINE_BYTES:
                raise ProjectionError("source_line_too_large")
            if not raw.strip():
                continue
            try:
                row = json.loads(
                    raw,
                    object_pairs_hook=strict_object,
                    parse_constant=reject_nonfinite_json,
                )
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ProjectionError("invalid_trace_json") from exc
            if not isinstance(row, dict):
                raise ProjectionError("invalid_trace_row")
            rows.append(row)
    return rows


def bounded_windows(event_count: int) -> Iterable[tuple[int, int]]:
    # Emit one causal window per event after the first. Each window contains the
    # current event plus at most seven predecessors, matching the runtime's
    # bounded-history contract without promoting whole-trajectory proximity.
    for end in range(2, event_count + 1):
        yield max(0, end - MAX_EVENTS), end


def source_record(revision: str, original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": revision,
        "original_id": original_id,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def atomic_truth() -> dict[str, Any]:
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "agenthazard:harmful_scenario_not_atomic_truth",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": ["agenthazard", "atomic_call", "proof_pending"],
        "exclusion_reason": (
            "A harmful scenario label does not prove that an individual native tool call "
            "is malicious or executed successfully."
        ),
    }


def stateful_truth(*, harmful: bool) -> dict[str, Any]:
    if not harmful:
        return {
            "source_truth": "unknown",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "medium",
            "label_source": "agenthazard:source_not_harmful",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "categories": ["agenthazard", "bounded_chain", "unlabeled_security_truth"],
            "exclusion_reason": "The source does not label this scenario harmful.",
        }
    return {
        "source_truth": "malicious",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "medium",
        "label_source": "agenthazard:harmful_scenario",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": [
            "agenthazard",
            "source_harmful_scenario",
            "bounded_chain",
            "proof_pending",
        ],
        "exclusion_reason": (
            "AgentHazard labels the scenario harmful but does not provide a deterministic "
            "run-level proof that this bounded event window completed the harmful objective."
        ),
    }


def project_cases(
    *,
    task_id: int,
    framework: str,
    campaign: str,
    archive_path: str,
    member_path: str,
    category: str,
    strategy: str,
    harmful: bool,
    events: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    revision: str,
    split: str,
) -> list[dict[str, Any]]:
    identity = digest(DATASET_ID, revision, archive_path, member_path, str(task_id))
    source = source_record(revision, f"{archive_path}:{member_path}")
    base = {"schema_version": SCHEMA_VERSION, "source": source, "split": split}
    strata_base = {
        "language": "en",
        "ecosystem": framework,
        "campaign": campaign,
        "domain": category,
        "hard_negative": False,
        "split_group": identity[:24],
        "trajectory_id": identity[:24],
    }
    cases: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        payload = {key: event[key] for key in ("tool_name", "command", "args", "dialect") if key in event}
        cases.append(
            {
                **base,
                "id": f"agenthazard/{identity[:24]}/call-{index:03d}",
                "surface": "action",
                "payload": {"direction": "tool_call", **payload},
                "truth": atomic_truth(),
                "strata": {
                    **strata_base,
                    "sequence_index": index,
                    "call_index": index,
                },
            }
        )
    for window_index, (start, end) in enumerate(bounded_windows(len(events))):
        cases.append(
            {
                **base,
                "id": f"agenthazard/{identity[:24]}/window-{window_index:03d}",
                "surface": "stateful",
                "payload": {
                    "direction": "tool_call",
                    "events": [dict(event) for event in events[start:end]],
                    "args": {
                        "_agenthazard_evidence": {
                            "task_id": task_id,
                            "risk_category": category,
                            "attack_strategy": strategy,
                            "window": {
                                "start_event": start,
                                "end_event_exclusive": end,
                                "total_events": len(events),
                            },
                            "execution": [dict(item) for item in evidence[start:end]],
                            "result_bodies_retained": False,
                        }
                    },
                },
                "truth": stateful_truth(harmful=harmful),
                "strata": {
                    **strata_base,
                    "sequence_index": start,
                    "call_index": end - 1,
                },
            }
        )
    return cases


def normalize_input(input_dir: Path, *, revision: str, split: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned AgentHazard revision {SOURCE_REVISION}")
    catalog = load_catalog(input_dir / CATALOG_PATH)
    evaluations = load_evaluations(input_dir / EVALUATIONS_PATH)
    archives = sorted((input_dir / "traces").glob("*/*.zip"))
    if not archives:
        raise ValueError("no AgentHazard native trace archives found")
    if len(archives) > MAX_ARCHIVES:
        raise ValueError("too many AgentHazard native trace archives")
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    sources: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for archive_path in archives:
        relative = archive_path.relative_to(input_dir).as_posix()
        framework = archive_path.parent.name
        campaign = archive_path.stem
        if not SAFE_LABEL.fullmatch(framework) or not SAFE_LABEL.fullmatch(campaign):
            raise ValueError(f"invalid AgentHazard archive identity: {relative}")
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError(f"oversized AgentHazard archive: {relative}")
        sources.append(
            {
                "path": relative,
                "bytes": archive_path.stat().st_size,
                "sha256": file_sha256(archive_path),
            }
        )
        try:
            archive = zipfile.ZipFile(archive_path)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"invalid AgentHazard archive: {relative}") from exc
        with archive:
            if len(archive.infolist()) > MAX_MEMBERS_PER_ARCHIVE:
                raise ValueError(f"too many members in AgentHazard archive: {relative}")
            for info in archive.infolist():
                if not safe_member(info):
                    continue
                counts["source_trace_members"] += 1
                openclaw_match = OPENCLAW_MEMBER.search(info.filename)
                wrapped_match = WRAPPED_MEMBER.search(info.filename)
                match = openclaw_match if framework == "openclaw" else wrapped_match
                if match is None:
                    skipped["unsupported_trace_member"] += 1
                    continue
                task_id = int(match.group(1))
                identity = (relative, info.filename)
                if identity in seen:
                    skipped["duplicate_trace_identity"] += 1
                    continue
                seen.add(identity)
                task = catalog.get(task_id)
                if task is None or task_id not in evaluations:
                    skipped["missing_catalog_or_evaluation"] += 1
                    continue
                if not task["english"]:
                    skipped["non_english"] += 1
                    continue
                try:
                    rows = member_rows(archive, info)
                    if framework == "openclaw":
                        events, evidence = project_openclaw(rows)
                    else:
                        if len(rows) != 1 or source_id(rows[0].get("id")) != task_id:
                            raise ProjectionError("invalid_wrapped_trace_identity")
                        for key, expected in (
                            ("category", task["category"]),
                            ("jailbreak_method", task["strategy"]),
                        ):
                            if rows[0].get(key) != expected:
                                raise ProjectionError("trace_catalog_mismatch")
                        events, evidence = project_wrapped(rows[0])
                except (ProjectionError, zipfile.BadZipFile, RuntimeError) as exc:
                    code = exc.code if isinstance(exc, ProjectionError) else "invalid_archive_member"
                    skipped[code] += 1
                    continue
                if not events:
                    skipped["no_native_tool_calls"] += 1
                    continue
                counts["selected_english_trajectories"] += 1
                counts[f"framework_{framework}"] += 1
                counts["source_tool_calls"] += len(events)
                counts.update(f"outcome_{event['outcome']}" for event in events)
                projected = project_cases(
                    task_id=task_id,
                    framework=framework,
                    campaign=campaign,
                    archive_path=relative,
                    member_path=info.filename,
                    category=task["category"],
                    strategy=task["strategy"],
                    harmful=evaluations[task_id],
                    events=events,
                    evidence=evidence,
                    revision=revision,
                    split=split,
                )
                for case in projected:
                    counts[f"cases_{case['surface']}"] += 1
                    counts[f"cases_{case['truth']['source_truth']}"] += 1
                cases.extend(projected)
    cases.sort(key=lambda case: str(case["id"]))
    counts["archives"] = len(archives)
    counts["cases"] = len(cases)
    adapter_statistics = dict(counts)
    adapter_statistics.update({f"skipped_{key}": value for key, value in skipped.items()})
    source_bytes = sum(int(item["bytes"]) for item in sources)
    source_inventory_sha256 = digest(canonical_json(sources))
    return cases, {
        "schema_version": SCHEMA_VERSION,
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {ADAPTER: dict(sorted(adapter_statistics.items()))},
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "pinned-source-tree",
            "bytes": source_bytes,
            "sha256": source_inventory_sha256,
        },
    }


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))
    seen: set[str] = set()
    for row in rows:
        case_id = str(row.get("id", ""))
        if case_id in seen:
            raise ValueError("duplicate benchmark case ID")
        seen.add(case_id)
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{case_id}:{location or '<root>'}: {errors[0].message}")
        if row["truth"]["applicability"] != "out_of_scope":
            raise ValueError(f"{case_id}: AgentHazard cases must remain out of scored scope")
        if row["surface"] == "action" and row["truth"]["source_truth"] != "unknown":
            raise ValueError(f"{case_id}: AgentHazard cannot supply atomic malicious truth")
        if row["surface"] == "stateful" and not (2 <= len(row["payload"]["events"]) <= MAX_EVENTS):
            raise ValueError(f"{case_id}: invalid bounded event count")


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


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_input(args.input_dir, revision=args.revision, split=args.split)
    validate_cases(cases, args.schema)
    output_data = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {**manifest, "output_sha256": hashlib.sha256(output_data).hexdigest()}
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, output_data)
    atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
