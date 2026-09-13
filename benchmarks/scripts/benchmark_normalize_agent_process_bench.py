#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize the pinned public AgentProcessBench as conservative hard negatives.

Process and reward labels describe task effectiveness, not security intent.
Consequently this adapter never creates malicious truth. A call is benign only
when its trajectory succeeded, its exact assistant step has a positive process
label, it has one causally subsequent result with matching call identity/name,
the result has no explicit failure evidence, and the action is read-only and
repository/service scoped. Every other call remains contextual and out of scope.

Detector payloads contain only bounded structured call arguments. Prompts,
reasoning, assistant prose, result bodies, answers, per-step labels, critiques,
tool metrics, and evaluator fields are excluded. Stateful benign windows follow
one exact trajectory and contain the current call plus at most eight contiguous
benign predecessors.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
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
from urllib.parse import urlsplit

SCHEMA_VERSION = "1"
DATASET_ID = "LulaCola/AgentProcessBench"
SOURCE_URL = "https://huggingface.co/datasets/LulaCola/AgentProcessBench"
SOURCE_REVISION = "cd81f326aece8b0a3f6359e20df370690d3a98bf"
SOURCE_LICENSE = "MIT"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "agent-process-bench-v2"
PRE_PARTITION_SPLIT = "smoke"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

SOURCE_FILES = {
    "bfcl/test.jsonl": (15_010_475, "6aee0b71eff7feb872c6b54d962f8831b56f7bebf770cba9cb657f219afb6fe5"),
    "gaia_dev/test.jsonl": (11_957_593, "f7b75c668fc1e6ad943e8f6d93a21a9a8f5f076841e1230e1ed2fc6d05ce8192"),
    "hotpotqa/test.jsonl": (3_174_572, "160eef2ded872d8dc6ddf4cee5752295fda691b6a9e99b5bafc2d484e6309c57"),
    "tau2/test.jsonl": (9_960_563, "6f22818ff88822512767fe735f56e7b78bed4b9aaf26959144feb92f127e1e95"),
}
SOURCE_BYTES = sum(item[0] for item in SOURCE_FILES.values())
SOURCE_AGGREGATE_SHA256 = "9804faa29b6fdaaba053fc60ad45339dd504ab9523c331a6c88ec33af7981014"

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_MESSAGES = 512
MAX_CALLS = 256
MAX_ARGUMENT_BYTES = 256 * 1024
MAX_PROJECTED_ARGUMENT_BYTES = 64 * 1024
MAX_RESULT_BYTES = 1024 * 1024
MAX_STRING_BYTES = 64 * 1024
MAX_ITEMS = 1024
MAX_DEPTH = 20
MAX_EVENTS = 9
CHAIN_RULE_IDS = [
    "chain.cloud_iam_principal_create_then_admin_attach_same_principal",
    "chain.download_decode_execute_same_artifact",
    "chain.download_then_execute_same_artifact",
    "chain.endpoint_security_control_request_then_completed_same_process",
    "chain.firewall_trust_expansion_then_destination_use",
    "chain.guardrails_off_then_egress",
    "chain.kubernetes_privileged_cronjob_patch_then_create_job",
    "chain.kubernetes_privileged_host_root_write_apply_exec",
    "chain.permission_denied_then_runtime_bypass",
    "chain.privilege_discovery_then_elevation",
    "chain.reverse_shell_payload_write_then_persistence_install_same_artifact",
    "chain.secret_manager_read_then_egress",
    "chain.secret_read_then_egress",
    "chain.secretsdump_then_psexec_same_target_principal",
    "chain.sensitive_egress_artifact_then_execute",
    "chain.sensitive_read_value_then_external_literal_transmit",
    "chain.sql_command_udf_create_then_invoke_same_function",
    "chain.sqlserver_xp_cmdshell_enable_then_invoke",
    "chain.wireless_capture_then_deauth_same_bssid",
    "chain.workload_identity_then_lateral_execution",
]
SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,239}$")
SAFE_CALL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,239}$")
FAILURE_TEXT = re.compile(
    r"(?i)(?:^|[\s{[(,:])(?:error|failed|failure|invalid|not[ _-]?found|permission denied|"
    r"access denied|unauthorized|forbidden|timed?[ _-]?out|unable to|cannot)\b"
)
RISKY_TOOL_TOKEN = re.compile(
    r"(?i)(?:^|[_-])(?:add|activate|authenticate|book|cancel|close|create|delete|disable|echo|"
    r"exchange|fill|insert|lock|make|modify|move|mv|patch|post|purchase|reboot|release|remove|"
    r"reset|resume|return|send|set|start|stop|suspend|terminate|toggle|touch|transfer|unlock|"
    r"update|upload|write)(?:$|[_-])"
)
SAFE_RETRIEVAL_TOOLS = frozenset(
    {
        "cat",
        "estimate_drive_feasibility_by_mileage",
        "fetch_url",
        "find",
        "find_user_id_by_email",
        "find_user_id_by_name_zip",
        "get_flight_status",
        "get_order_details",
        "get_product_details",
        "get_reservation_details",
        "get_symbol_by_name",
        "get_tweet",
        "get_user_details",
        "liter_to_gallon",
        "ls",
        "mean",
        "pwd",
        "read_file",
        "retrieve_invoice",
        "search",
        "search_direct_flight",
        "search_onestop_flight",
        "wc",
    }
)
FILESYSTEM_TOOLS = frozenset({"cat", "find", "ls", "pwd", "read_file", "wc"})
URL_TOOLS = frozenset({"fetch_url"})
PATH_KEYS = frozenset({"directory", "file", "file_name", "filename", "folder", "path", "uri"})
PROSE_KEYS = frozenset(
    {
        "answer",
        "content",
        "critique",
        "description",
        "explanation",
        "message",
        "purpose",
        "reason",
        "summary",
        "thought",
    }
)
SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:access[_-]?token|api[_-]?key|authorization|card[_-]?id|cookie|credential|"
    r"date[_-]?of[_-]?birth|dob|email|imei|password|payment[_-]?method[_-]?id|phone[_-]?number|"
    r"private[_-]?key|secret|session[_-]?token|ssn)(?:$|[_-])"
)
SENSITIVE_TOOL_SEMANTIC = re.compile(
    r"(?:^|_)(?:admin|administrator|auth|authentication|authorization|credential|credentials|iam|"
    r"login|password|policy|policies|privilege|privileges|role|roles|secret|secrets|security|token|tokens)(?:$|_)"
)
SECURITY_SENSITIVE_ARGUMENT_KEY = re.compile(
    r"(?:^|_)(?:admin|auth|authorization|credential|credentials|iam|password|policy|policies|"
    r"privilege|privileges|role|roles|secret|secrets|security|token|tokens)(?:$|_)"
)


class ProjectionError(ValueError):
    """A source record cannot satisfy the conservative projection contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Call:
    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    message_index: int
    sequence_index: int


@dataclass(frozen=True)
class Result:
    call_id: str
    tool_name: str
    content: object
    message_index: int


@dataclass(frozen=True)
class Event:
    call: Call
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
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode("utf-8")).hexdigest()


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


def strict_json(raw: str, code: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError(code) from exc


def validate_shape(value: object, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_argument_depth_exceeded")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ProjectionError("oversized_argument_string")
    elif isinstance(value, Mapping):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_argument_object")
        for child in value.values():
            validate_shape(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("oversized_argument_array")
        for child in value:
            validate_shape(child, depth=depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ProjectionError("non_finite_argument")
    elif value is not None and type(value) not in {bool, int, float}:
        raise ProjectionError("unsupported_argument_value")


def english_compatible(row: Mapping[str, Any], messages: Sequence[object]) -> bool:
    texts: list[str] = []
    for key in ("question", "task_description"):
        value = row.get(key)
        if isinstance(value, str):
            texts.append(value)
    for message in messages:
        if isinstance(message, Mapping) and message.get("role") == "user":
            value = message.get("content")
            if isinstance(value, str):
                texts.append(value)
    latin = 0
    non_latin = 0
    for text in texts:
        for character in text:
            if not unicodedata.category(character).startswith("L"):
                continue
            if "LATIN" in unicodedata.name(character, ""):
                latin += 1
            else:
                non_latin += 1
    return latin >= 20 and (non_latin <= 2 or non_latin * 50 <= latin)


def redact_arguments(value: object, *, key: str | None = None, depth: int = 0) -> object | None:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_argument_depth_exceeded")
    if key is not None and key.lower() in PROSE_KEYS:
        return None
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ProjectionError("oversized_argument_string")
        if key is not None and SENSITIVE_KEY.search(key):
            return {"value_ref": digest("agent-process-sensitive-v1", key.lower(), value)}
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_members")
        projected: dict[str, object] = {}
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise ProjectionError("non_string_argument_key")
            child_value = redact_arguments(child, key=child_key, depth=depth + 1)
            if child_value is not None:
                projected[child_key] = child_value
        return projected
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [redact_arguments(child, depth=depth + 1) for child in value]
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ProjectionError("unsupported_argument_value")


def parse_calls_and_results(messages: Sequence[object]) -> tuple[list[Call], dict[str, Result], Counter[str]]:
    if len(messages) > MAX_MESSAGES:
        raise ProjectionError("too_many_messages")
    calls: list[Call] = []
    call_ids: set[str] = set()
    ambiguous_calls: set[str] = set()
    results: dict[str, Result] = {}
    ambiguous_results: set[str] = set()
    statistics: Counter[str] = Counter()
    sequence_index = 0
    for message_index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            statistics["invalid_messages"] += 1
            continue
        raw_calls = message.get("tool_calls")
        if raw_calls is not None:
            if message.get("role") != "assistant" or not isinstance(raw_calls, list):
                statistics["invalid_tool_call_messages"] += 1
                continue
            for raw_call in raw_calls:
                if len(calls) >= MAX_CALLS:
                    raise ProjectionError("too_many_calls")
                if not isinstance(raw_call, Mapping):
                    statistics["invalid_calls"] += 1
                    continue
                function = raw_call.get("function")
                call_id = raw_call.get("id")
                if (
                    not isinstance(function, Mapping)
                    or not isinstance(call_id, str)
                    or not SAFE_CALL_ID.fullmatch(call_id)
                ):
                    statistics["invalid_calls"] += 1
                    continue
                if call_id in call_ids:
                    ambiguous_calls.add(call_id)
                    statistics["duplicate_calls"] += 1
                    continue
                name = function.get("name")
                raw_arguments = function.get("arguments")
                if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name):
                    statistics["invalid_tool_names"] += 1
                    continue
                if isinstance(raw_arguments, str):
                    if len(raw_arguments.encode("utf-8")) > MAX_ARGUMENT_BYTES:
                        statistics["oversized_arguments"] += 1
                        continue
                    try:
                        arguments = strict_json(raw_arguments, "invalid_arguments")
                    except ProjectionError:
                        statistics["invalid_arguments"] += 1
                        continue
                else:
                    arguments = raw_arguments
                if not isinstance(arguments, dict):
                    statistics["invalid_arguments"] += 1
                    continue
                try:
                    validate_shape(arguments)
                except ProjectionError:
                    statistics["invalid_arguments"] += 1
                    continue
                call_ids.add(call_id)
                calls.append(Call(call_id, name, arguments, message_index, sequence_index))
                sequence_index += 1
        if message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            name = message.get("name")
            content = message.get("content")
            if (
                not isinstance(call_id, str)
                or not SAFE_CALL_ID.fullmatch(call_id)
                or not isinstance(name, str)
                or not SAFE_TOOL.fullmatch(name)
            ):
                statistics["invalid_results"] += 1
                continue
            if call_id in results:
                ambiguous_results.add(call_id)
                statistics["duplicate_results"] += 1
                continue
            if not isinstance(content, (str, dict, list, int, float, bool)) and content is not None:
                statistics["invalid_results"] += 1
                continue
            results[call_id] = Result(call_id, name, content, message_index)
    if ambiguous_calls:
        calls = [call for call in calls if call.call_id not in ambiguous_calls]
    for call_id in ambiguous_results:
        results.pop(call_id, None)
    statistics["ambiguous_call_identities"] = len(ambiguous_calls)
    statistics["ambiguous_result_identities"] = len(ambiguous_results)
    return calls, results, statistics


def explicit_result_success(result: Result) -> bool:
    content = result.content
    if isinstance(content, str):
        encoded = content.encode("utf-8")
        if not content.strip() or len(encoded) > MAX_RESULT_BYTES or FAILURE_TEXT.search(content[:MAX_STRING_BYTES]):
            return False
        try:
            content = strict_json(content, "invalid_result_json")
        except ProjectionError:
            return True
    if isinstance(content, Mapping):
        error_value = content.get("error")
        if error_value is not None and error_value is not False and error_value != "" and error_value != 0:
            return False
        for key in ("success", "ok"):
            if key in content and content[key] is not True:
                return False
        status = content.get("status", content.get("status_code"))
        if type(status) is int and status >= 400:
            return False
        if isinstance(status, str) and status.lower() in {
            "error",
            "failed",
            "failure",
            "forbidden",
            "invalid",
            "not_found",
            "unauthorized",
        }:
            return False
    return True


def safe_relative_path(value: str) -> bool:
    if not value or len(value) > 4096 or "\x00" in value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and not any(part == "" for part in path.parts)


def filesystem_scoped(name: str, arguments: Mapping[str, Any]) -> bool:
    if name == "pwd":
        return not arguments
    paths: list[str] = []
    for key, value in arguments.items():
        if key.lower() in PATH_KEYS:
            if not isinstance(value, str):
                return False
            if value.startswith("file://"):
                value = value[7:]
            paths.append(value)
    if name == "ls" and not paths:
        return all(type(value) in {bool, int} for value in arguments.values())
    return bool(paths) and all(safe_relative_path(path) for path in paths)


def public_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return False
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def url_scoped(arguments: Mapping[str, Any]) -> bool:
    values: list[str] = []
    for key, value in arguments.items():
        if key.lower() not in {"url", "urls"}:
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            values.extend(value)
        else:
            return False
    return bool(values) and all(public_http_url(value) for value in values)


def action_is_scoped_read_only(name: str, arguments: Mapping[str, Any]) -> bool:
    lowered = name.lower()
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).replace("-", "_").replace(".", "_").lower()
    argument_keys = {
        re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).replace("-", "_").replace(".", "_").lower() for key in arguments
    }
    if (
        RISKY_TOOL_TOKEN.search(name)
        or SENSITIVE_TOOL_SEMANTIC.search(normalized)
        or any(SECURITY_SENSITIVE_ARGUMENT_KEY.search(key) for key in argument_keys)
    ):
        return False
    if lowered in FILESYSTEM_TOOLS:
        return filesystem_scoped(lowered, arguments)
    if lowered in URL_TOOLS:
        return url_scoped(arguments)
    if lowered == "search":
        return bool(arguments) and set(arguments) <= {"query", "query_list"}
    return lowered in SAFE_RETRIEVAL_TOOLS


def normalized_labels(row: Mapping[str, Any]) -> dict[int, int]:
    raw = row.get("step_labels")
    if not isinstance(raw, Mapping):
        return {}
    labels: dict[int, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key.isdigit() or type(value) is not int or value not in {-1, 0, 1}:
            raise ProjectionError("invalid_step_labels")
        labels[int(key)] = value
    return labels


def truth(benign: bool, reason: str) -> dict[str, object]:
    if benign:
        return {
            "source_truth": "benign",
            "deterministic_truth": "benign",
            "label_confidence": "high",
            "label_source": "agent-process-bench:successful-positive-step-result-v2",
            "applicability": "in_scope",
            "expected_disposition": "allow",
            "categories": ["agent_process", "benign_hard_negative", "successful_scoped_read"],
        }
    return {
        "source_truth": "unknown",
        "deterministic_truth": "contextual_or_dual_use",
        "label_confidence": "high",
        "label_source": "agent-process-bench:conservative-context-v1",
        "applicability": "out_of_scope",
        "expected_disposition": "detect_only",
        "categories": ["agent_process", "contextual_tool_call"],
        "exclusion_reason": reason,
    }


def action_payload(event: Event, *, with_outcome: bool = False) -> dict[str, object]:
    projected = redact_arguments(event.call.arguments)
    if not isinstance(projected, dict):
        raise ProjectionError("invalid_projected_arguments")
    if len(canonical_json(projected).encode("utf-8")) > MAX_PROJECTED_ARGUMENT_BYTES:
        raise ProjectionError("oversized_projected_arguments")
    payload: dict[str, object] = {
        "tool_name": event.call.tool_name,
        "args": projected,
        "dialect": "none",
    }
    if with_outcome:
        payload["outcome"] = event.outcome
        payload["offset_seconds"] = event.call.sequence_index
    return payload


def case_base(
    *,
    subset: str,
    revision: str,
    original_id: str,
    trajectory: str,
    split_group: str,
    sequence_index: int,
    suffix: str,
    benign: bool,
    reason: str,
) -> dict[str, Any]:
    identity = digest("agent-process-case-v1", subset, original_id, suffix)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"agent-process-bench/{identity[:32]}",
        "source": {
            "dataset": DATASET_ID,
            "revision": revision,
            "original_id": f"{subset}:{original_id}:{suffix}",
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
        },
        "split": PRE_PARTITION_SPLIT,
        "truth": truth(benign, reason),
        "strata": {
            "platform": "service",
            "dialect": "structured",
            "language": "en",
            "ecosystem": "tool_using_agent",
            "campaign": subset,
            "domain": "agent_process_hard_negative",
            "hard_negative": benign,
            "split_group": split_group[:24],
            "trajectory_id": trajectory[:24],
            "sequence_index": sequence_index,
            "call_index": sequence_index,
        },
    }


def row_identity(row: Mapping[str, Any], subset: str) -> tuple[str, str]:
    query_index = row.get("query_index")
    total_index = row.get("total_index")
    sample_index = row.get("sample_index")
    if type(query_index) is not int or type(total_index) is not int or type(sample_index) is not int:
        raise ProjectionError("invalid_row_identity")
    if not all(0 <= value <= 1_000_000_000 for value in (query_index, total_index, sample_index)):
        raise ProjectionError("invalid_row_identity")
    return f"query-{query_index}", f"total-{total_index}-sample-{sample_index}"


def normalize_row(row: Mapping[str, Any], *, subset: str, revision: str) -> tuple[list[Candidate], Counter[str]]:
    statistics: Counter[str] = Counter()
    messages = row.get("messages")
    if not isinstance(messages, list):
        raise ProjectionError("invalid_messages")
    group_id, original_id = row_identity(row, subset)
    if not english_compatible(row, messages):
        raise ProjectionError("non_english_or_unknown")
    final_label = row.get("final_label")
    if type(final_label) is not int or final_label not in {-1, 0, 1}:
        raise ProjectionError("invalid_final_label")
    labels = normalized_labels(row)
    calls, results, parse_stats = parse_calls_and_results(messages)
    statistics.update(parse_stats)
    trajectory = digest("agent-process-trajectory-v1", subset, original_id)
    split_group = digest("agent-process-task-v1", subset, group_id)
    events: list[Event] = []
    for call in calls:
        result = results.get(call.call_id)
        outcome = "unknown"
        reason = "missing_or_ambiguous_result"
        result_ok = False
        if result is not None:
            if result.message_index <= call.message_index:
                reason = "noncausal_result"
            elif result.tool_name != call.tool_name:
                reason = "result_tool_name_mismatch"
            else:
                result_ok = explicit_result_success(result)
                outcome = "succeeded" if result_ok else "failed"
                reason = "result_not_affirmatively_successful" if not result_ok else "insufficient_safe_task_evidence"
        step_label = labels.get(call.message_index)
        scoped = action_is_scoped_read_only(call.tool_name, call.arguments)
        benign = final_label == 1 and step_label == 1 and result_ok and scoped
        if benign:
            reason = "benign"
        elif final_label != 1:
            reason = "trajectory_not_affirmatively_successful"
        elif step_label != 1:
            reason = "step_not_affirmatively_successful"
        elif result_ok and not scoped:
            reason = "action_not_proven_read_only_and_scoped"
        events.append(Event(call, outcome, benign, reason))
        statistics["benign_action_events" if benign else "contextual_action_events"] += 1

    candidates: list[Candidate] = []
    for index, event in enumerate(events):
        try:
            payload = {"direction": "tool_call", **action_payload(event)}
        except ProjectionError as exc:
            statistics[f"excluded_{exc.code}"] += 1
            continue
        case = case_base(
            subset=subset,
            revision=revision,
            original_id=original_id,
            trajectory=trajectory,
            split_group=split_group,
            sequence_index=event.call.sequence_index,
            suffix=f"call-{event.call.sequence_index}-{event.call.call_id}",
            benign=event.benign,
            reason=event.reason,
        )
        case["surface"] = "action"
        case["payload"] = payload
        content_digest = digest("agent-process-payload-v1", "action", canonical_json(payload))
        candidates.append(Candidate(f"{subset}:{original_id}:{event.call.sequence_index}:action", content_digest, case))

        if not event.benign:
            continue
        start = index
        while start > 0 and index - start < MAX_EVENTS - 1 and events[start - 1].benign:
            start -= 1
        window = events[start : index + 1]
        if len(window) < 2:
            continue
        stateful_payload = {
            "direction": "tool_call",
            "events": [action_payload(item, with_outcome=True) for item in window],
        }
        for projected_event, source_event in zip(stateful_payload["events"], window, strict=True):
            projected_event["offset_seconds"] = source_event.call.sequence_index - window[0].call.sequence_index
        stateful = case_base(
            subset=subset,
            revision=revision,
            original_id=original_id,
            trajectory=trajectory,
            split_group=split_group,
            sequence_index=event.call.sequence_index,
            suffix=f"window-{window[0].call.sequence_index}-{event.call.sequence_index}",
            benign=True,
            reason="benign",
        )
        stateful["surface"] = "stateful"
        stateful["payload"] = stateful_payload
        stateful["truth"]["categories"] = [
            "agent_process",
            "benign_hard_negative",
            "successful_scoped_sequence",
        ]
        stateful["truth"]["stateful_lens"] = "bounded_completed"
        stateful["truth"]["rule_ids"] = CHAIN_RULE_IDS
        stateful_digest = digest("agent-process-payload-v1", "stateful", canonical_json(stateful_payload))
        candidates.append(
            Candidate(
                f"{subset}:{original_id}:{event.call.sequence_index}:stateful",
                stateful_digest,
                stateful,
            )
        )
        statistics["benign_stateful_windows"] += 1
    return candidates, statistics


def load_rows(path: Path) -> Iterable[Mapping[str, Any]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"invalid or oversized source file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ValueError(f"oversized source line: {path}:{line_number}")
            try:
                row = strict_json(line, "invalid_source_json")
            except ProjectionError as exc:
                raise ValueError(f"invalid source row: {path}:{line_number}:{exc.code}") from exc
            if not isinstance(row, Mapping):
                raise ValueError(f"source row is not an object: {path}:{line_number}")
            yield row


def source_paths(root: Path, *, verify_pinned_files: bool) -> list[tuple[str, Path]]:
    root = root.resolve(strict=True)
    paths: list[tuple[str, Path]] = []
    for relative, (expected_bytes, expected_sha256) in SOURCE_FILES.items():
        candidate = root / relative
        if candidate.is_symlink():
            raise ValueError(f"source file must not be a symlink: {relative}")
        path = candidate.resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"source path escapes input root: {relative}") from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing regular source file: {relative}")
        if verify_pinned_files and (path.stat().st_size != expected_bytes or file_sha256(path) != expected_sha256):
            raise ValueError(f"pinned source identity mismatch: {relative}")
        paths.append((relative, path))
    return paths


def deduplicate(candidates: Sequence[Candidate], statistics: Counter[str]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        grouped[candidate.payload_digest].append(candidate)
    selected: list[Candidate] = []
    for values in grouped.values():
        contracts = {
            (
                candidate.case["truth"]["source_truth"],
                candidate.case["truth"]["applicability"],
                candidate.case["truth"]["expected_disposition"],
            )
            for candidate in values
        }
        if len(contracts) != 1:
            statistics["exact_payload_label_conflicts_excluded"] += len(values)
            continue
        ordered = sorted(values, key=lambda candidate: candidate.source_key)
        selected.append(ordered[0])
        statistics["exact_payload_duplicates_removed"] += len(ordered) - 1
    return sorted((candidate.case for candidate in selected), key=lambda case: str(case["id"]))


def aggregate_source_sha256(paths: Sequence[tuple[str, Path]]) -> str:
    value = hashlib.sha256()
    for relative, path in paths:
        value.update(f"{relative}\0{path.stat().st_size}\0{file_sha256(path)}\n".encode())
    return value.hexdigest()


def normalize_input(
    root: Path,
    *,
    revision: str = SOURCE_REVISION,
    verify_pinned_files: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"AgentProcessBench revision must be pinned to {SOURCE_REVISION}")
    paths = source_paths(root, verify_pinned_files=verify_pinned_files)
    candidates: list[Candidate] = []
    statistics: Counter[str] = Counter()
    for relative, path in paths:
        subset = relative.split("/", 1)[0]
        for row in load_rows(path):
            statistics["source_rows"] += 1
            try:
                projected, row_stats = normalize_row(row, subset=subset, revision=revision)
            except ProjectionError as exc:
                statistics[f"quarantined_{exc.code}"] += 1
                continue
            candidates.extend(projected)
            statistics.update(row_stats)
            statistics["normalized_rows"] += 1
    cases = deduplicate(candidates, statistics)
    output = b"".join((canonical_json(case) + "\n").encode("utf-8") for case in cases)
    source_sha256 = aggregate_source_sha256(paths)
    if verify_pinned_files and (
        sum(path.stat().st_size for _, path in paths) != SOURCE_BYTES or source_sha256 != SOURCE_AGGREGATE_SHA256
    ):
        raise ValueError("aggregate pinned source identity mismatch")
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
            "revision": revision,
            "license": SOURCE_LICENSE,
            "redistribution": SOURCE_REDISTRIBUTION,
            "path": "{bfcl,gaia_dev,hotpotqa,tau2}/test.jsonl",
            "bytes": sum(path.stat().st_size for _, path in paths),
            "sha256": source_sha256,
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
        identifier = str(case["id"])
        if identifier in seen:
            raise ValueError(f"duplicate normalized case ID: {identifier}")
        seen.add(identifier)
        if case["truth"]["source_truth"] == "malicious":
            raise ValueError("AgentProcessBench process labels must never create malicious truth")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_input(args.input_dir, revision=args.revision)
    validate_cases(cases, args.schema)
    output = b"".join((canonical_json(case) + "\n").encode("utf-8") for case in cases)
    atomic_write(args.output, output)
    atomic_write(args.manifest, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps({"cases": len(cases), "output_sha256": manifest["output_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
