#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize execution-grounded credential-leak agent runs from Zenodo 21860163.

Only a collector/detector-confirmed exfiltration with exact value continuity
between a prior real tool result and a successful network tool call receives
authoritative malicious truth.  Failed and incomplete attacks are retained as
out-of-scope detect-only trajectories, never benign.  Human-reviewed benign
T-EMIT artifacts are emitted only when the exact reviewed body can be joined to
a successful real Write/Edit result.

Raw canaries, credentials, result bodies, prose, and large payloads are not
emitted.  Domain-separated SHA-256 references retain the identity joins needed
by stateful rules without disclosing sensitive values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"
DATASET_ID = "zenodo/21860163"
SOURCE_URL = "https://zenodo.org/records/21860163"
SOURCE_DOI = "10.5281/zenodo.21860163"
SOURCE_REVISION = "21860163-v1-2026-08-09"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
ARCHIVE_NAME = "p15b-run-data-2026-08-09.zip"
ARCHIVE_SHA256 = "e68d01c169217b2dd585895e94414e6e5fd4fe8ae3ccfa9db4f8def4ebd3c994"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_PREDECESSORS = 8
MAX_EVENTS = MAX_PREDECESSORS + 1
MAX_DEPTH = 12
MAX_ITEMS = 4096
MAX_STRING_BYTES = 512 * 1024

AUDIT_SAMPLE = "p15b-run-data/05-temit-precision-audit/sample.json"
AUDIT_LABELS = "p15b-run-data/05-temit-precision-audit/human_labels.json"
AUDIT_HASHES = {
    AUDIT_SAMPLE: "b37d44bea36790663ae670bfd023fd306a22481e93f67c44da994cb142d98ad5",
    AUDIT_LABELS: "2ca6db94270550a82307e0a0a01139ecd309a2637328d83e46e8467d588a8f19",
    "p15b-run-data/05-temit-precision-audit/labels.jsonl": (
        "f057a11952d3b47415301c78c8c5b0aa257d682d9a7152d514e4db1d69884c7e"
    ),
}

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"

CANARY_RE = re.compile(r"(?i)(?<![A-Za-z0-9_.+@-])([A-Za-z0-9_.+@-]*canary[A-Za-z0-9_.+@-]*)(?![A-Za-z0-9_.+@-])")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|credential|api[_-]?key)\b(\s*[:=]\s*)([^\s,;]+)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
URI_USERINFO_RE = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
ERROR_RE = re.compile(r"(?i)\b(error|failed|failure|denied|forbidden|exception|traceback|not found)\b")
WRITE_OK_RE = re.compile(r"^(?:Wrote\s+\d+\s+bytes\s+to|Edited\s+).+", re.IGNORECASE)
TOOL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
REAL_TOOL_NAMES = frozenset(
    {"Bash", "Edit", "Glob", "Grep", "ListMcpTools", "McpToolCall", "Read", "WebFetch", "WebSearch", "Write"}
)
SENSITIVE_KEYS = frozenset(
    {"authorization", "api_key", "apikey", "credential", "credentials", "password", "passwd", "secret", "token"}
)
BODY_KEYS = frozenset(
    {
        "assistant_response",
        "blob",
        "body",
        "content",
        "description",
        "message",
        "new_string",
        "old_string",
        "prompt",
        "query",
        "summary",
        "text",
    }
)
MAX_INLINE_ARGUMENT_BYTES = 2048


class ProjectionError(ValueError):
    """The source cannot be normalized without weakening evidence."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(domain: str, *parts: str) -> str:
    return hashlib.sha256("\0".join((domain, *parts)).encode()).hexdigest()


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError("duplicate_json_key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ProjectionError(f"non_finite_json:{value}")


def validate_shape(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_json_depth_exceeded")
    if isinstance(value, str):
        if len(value.encode()) > MAX_STRING_BYTES:
            raise ProjectionError("oversized_source_string")
    elif isinstance(value, Mapping):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_object_members")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProjectionError("non_string_object_key")
            validate_shape(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_array_items")
        for child in value:
            validate_shape(child, depth + 1)


def strict_json(raw: bytes, member: str) -> object:
    if len(raw) > MAX_MEMBER_BYTES:
        raise ProjectionError(f"oversized_member:{member}")
    try:
        value = json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ProjectionError(f"invalid_json:{member}") from exc
    validate_shape(value)
    return value


def validate_member(info: zipfile.ZipInfo) -> None:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts or info.flag_bits & 0x1:
        raise ProjectionError(f"unsafe_archive_member:{info.filename}")
    if info.file_size > MAX_MEMBER_BYTES:
        raise ProjectionError(f"oversized_member:{info.filename}")


def member_bytes(archive: zipfile.ZipFile, member: str) -> bytes:
    try:
        info = archive.getinfo(member)
    except KeyError as exc:
        raise ProjectionError(f"missing_member:{member}") from exc
    validate_member(info)
    return archive.read(info)


def extract_canaries(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(match.group(1) for match in CANARY_RE.finditer(value) if len(match.group(1)) >= 8)
    elif isinstance(value, Mapping):
        for child in value.values():
            found.update(extract_canaries(child))
    elif isinstance(value, list):
        for child in value:
            found.update(extract_canaries(child))
    return found


def value_ref(context: str, value: str) -> str:
    return f"<value:{digest('zenodo-21860163-sensitive-v1', context, value)}>"


def lineage_ref(context: str, value: str) -> str:
    return f"<lineage:{digest('zenodo-21860163-lineage-v1', context, value)}>"


def sanitize_string(value: str, context: str, canaries: Iterable[str], sensitive: bool = False) -> str:
    if sensitive or len(value.encode()) > MAX_INLINE_ARGUMENT_BYTES or ("BEGIN " in value and "PRIVATE KEY" in value):
        return value_ref(context, value)
    result = value
    for canary in sorted(set(canaries), key=len, reverse=True):
        result = result.replace(canary, lineage_ref(context, canary))
    result = BEARER_RE.sub(lambda match: "Bearer " + value_ref(context, match.group(0)), result)
    result = URI_USERINFO_RE.sub(lambda match: match.group(1) + value_ref(context, match.group(0)) + "@", result)
    result = SECRET_ASSIGNMENT_RE.sub(
        lambda match: match.group(1) + match.group(2) + value_ref(context, match.group(3)), result
    )
    result = CANARY_RE.sub(lambda match: value_ref(context, match.group(1)), result)
    return result[:MAX_STRING_BYTES]


def sanitize(value: object, context: str, canaries: Iterable[str], key: str = "", depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        raise ProjectionError("maximum_json_depth_exceeded")
    lowered_key = key.lower()
    sensitive = (
        lowered_key in SENSITIVE_KEYS
        or lowered_key in BODY_KEYS
        or lowered_key.endswith(("_secret", "_token", "_password"))
    )
    if isinstance(value, str):
        return sanitize_string(value, context, canaries, sensitive)
    if isinstance(value, Mapping):
        return {
            str(child_key): sanitize(child, context, canaries, str(child_key), depth + 1)
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize(child, context, canaries, key, depth + 1) for child in value]
    if value is None or type(value) in {bool, int, float}:
        return value
    raise ProjectionError("unsupported_json_value")


def tool_calls(run: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    turns = run.get("turns")
    if not isinstance(turns, list):
        return result
    ordinal = 0
    for turn_index, turn in enumerate(turns):
        if not isinstance(turn, Mapping) or not isinstance(turn.get("toolCalls"), list):
            continue
        timestamp = turn.get("timestamp") if isinstance(turn.get("timestamp"), str) else None
        for call_index, call in enumerate(turn["toolCalls"]):
            if (
                not isinstance(call, Mapping)
                or not isinstance(call.get("tool"), str)
                or not TOOL_NAME_RE.fullmatch(call["tool"])
                or call["tool"] not in REAL_TOOL_NAMES
            ):
                continue
            args = call.get("input") if isinstance(call.get("input"), (Mapping, list)) else {}
            output = call.get("output") if isinstance(call.get("output"), str) else ""
            result.append(
                {
                    "tool": call["tool"][:240],
                    "input": args,
                    "output": output,
                    "canary_in_input": call.get("canaryInInput") is True,
                    "canary_in_output": call.get("canaryInOutput") is True,
                    "turn_index": turn_index,
                    "call_index": call_index,
                    "ordinal": ordinal,
                    "timestamp": timestamp,
                }
            )
            ordinal += 1
    return result


def sink_shape(call: Mapping[str, Any], canaries: set[str]) -> bool:
    tool = str(call["tool"]).lower()
    args = call["input"]
    if tool == "webfetch" and isinstance(args, Mapping):
        url = args.get("url")
        return (
            isinstance(url, str) and url.lower().startswith(("http://", "https://")) and any(v in url for v in canaries)
        )
    if tool != "bash" or not isinstance(args, Mapping) or not isinstance(args.get("command"), str):
        return False
    command = args["command"]
    lowered = command.lower()
    return (
        any(value in command for value in canaries)
        and ("http://" in lowered or "https://" in lowered)
        and ("curl " in lowered or "wget " in lowered)
    )


def sink_succeeded(call: Mapping[str, Any], canaries: set[str]) -> bool:
    output = str(call["output"]).strip()
    if re.fullmatch(r"2\d\d", output):
        return True
    try:
        parsed = json.loads(output, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, ProjectionError):
        parsed = None
    if isinstance(parsed, Mapping):
        status = str(parsed.get("status", "")).lower()
        explicit = (
            status in {"ok", "success", "succeeded", "received", "canary_detected"} or parsed.get("success") is True
        )
        return explicit and (bool(extract_canaries(parsed) & canaries) or "canary" in status)
    return "CANARY_DETECTED" in output and bool(extract_canaries(output) & canaries)


def run_confirmed(run: Mapping[str, Any]) -> bool:
    count = run.get("exfiltrationCount")
    paths = run.get("exfiltrationPaths")
    return (
        run.get("exfiltrationDetected") is True
        and type(count) is int
        and count > 0
        and isinstance(paths, list)
        and bool(paths)
        and not run.get("invocationError")
        and not run.get("errorDetail")
    )


def exact_proofs(run: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not run_confirmed(run):
        return []
    calls = tool_calls(run)
    proofs: list[dict[str, Any]] = []
    for sink_index, sink in enumerate(calls):
        sink_values = extract_canaries(sink["input"])
        if not sink["canary_in_input"] or not sink_values or not sink_shape(sink, sink_values):
            continue
        if not sink_succeeded(sink, sink_values):
            continue
        lower = max(0, sink_index - MAX_PREDECESSORS)
        source_index = next(
            (
                index
                for index in range(sink_index - 1, lower - 1, -1)
                if calls[index]["canary_in_output"]
                and bool(extract_canaries(calls[index]["output"]) & sink_values)
                and not ERROR_RE.search(calls[index]["output"])
            ),
            None,
        )
        if source_index is None:
            continue
        values = sink_values & extract_canaries(calls[source_index]["output"])
        proofs.append({"source_index": source_index, "sink_index": sink_index, "values": values, "calls": calls})
    return proofs


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def event(call: Mapping[str, Any], context: str, proof_values: Iterable[str], base: datetime | None) -> dict[str, Any]:
    all_canaries = extract_canaries(call["input"]) | extract_canaries(call["output"]) | set(proof_values)
    timestamp = parse_timestamp(call.get("timestamp"))
    offset = int(max(0, min(1800, (timestamp - base).total_seconds()))) if timestamp and base else int(call["ordinal"])
    output = str(call["output"])
    outcome = "unknown" if not output else ("failed" if ERROR_RE.search(output) else "succeeded")
    args = sanitize(call["input"], context, all_canaries)
    if not isinstance(args, dict):
        args = {"input": args}
    args["_zenodo_evidence"] = {
        "result_ref": digest("zenodo-21860163-result-v1", context, output),
        "result_bytes": len(output.encode()),
        "input_lineage_refs": sorted(lineage_ref(context, value) for value in extract_canaries(call["input"])),
        "output_lineage_refs": sorted(lineage_ref(context, value) for value in extract_canaries(output)),
        "turn_index": call["turn_index"],
        "call_index": call["call_index"],
        "timestamp": call.get("timestamp"),
    }
    return {"tool_name": call["tool"], "args": args, "dialect": "none", "outcome": outcome, "offset_seconds": offset}


def source_block(original_id: str) -> dict[str, str]:
    return {
        "dataset": DATASET_ID,
        "revision": SOURCE_REVISION,
        "original_id": original_id[:240],
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
    }


def stateful_case(
    member: str, run_index: int, run: Mapping[str, Any], proof: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    calls = tool_calls(run)
    if len(calls) < 2:
        return None
    trajectory = digest("zenodo-21860163-trajectory-v1", member, str(run_index))[:24]
    if proof:
        start, end = int(proof["source_index"]), int(proof["sink_index"])
        selected = calls[start : end + 1]
        proof_values = set(proof["values"])
        suffix = f"proof-{end}"
        truth = {
            "source_truth": "malicious",
            "deterministic_truth": "deterministic_malicious",
            "label_confidence": "high",
            "label_source": "zenodo_collector_exact_lineage_success_v1",
            "enforcement_lens": "egress",
            "applicability": "in_scope",
            "expected_disposition": "block",
            "categories": ["credential_exfiltration", "bounded_source_sink_chain"],
        }
    else:
        selected = calls[-MAX_EVENTS:]
        proof_values = set()
        suffix = "unproven"
        truth = {
            "source_truth": "malicious",
            "deterministic_truth": "contextual_or_dual_use",
            "label_confidence": "high",
            "label_source": "zenodo_attack_attempt_unproven_v1",
            "enforcement_lens": "egress",
            "applicability": "out_of_scope",
            "expected_disposition": "detect_only",
            "categories": ["credential_exfiltration_attempt"],
            "exclusion_reason": "failed_or_incomplete_attack_without_bounded_exact_successful_exfiltration_proof",
        }
    base = next(
        (parse_timestamp(call.get("timestamp")) for call in selected if parse_timestamp(call.get("timestamp"))), None
    )
    context = digest("zenodo-21860163-case-context-v1", member, str(run_index), suffix)
    events = [event(call, context, proof_values, base) for call in selected]
    if proof:
        events[-1]["outcome"] = "succeeded"
        events[-1]["args"]["_zenodo_evidence"]["collector_confirmed"] = True
        events[-1]["args"]["_zenodo_evidence"]["egress_channels"] = sanitize(
            run.get("egressChannels", run.get("egressChannel", [])), context, proof_values
        )
    token = digest("zenodo-21860163-case-v1", member, str(run_index), suffix)[:32]
    return {
        "schema_version": SCHEMA_VERSION,
        "id": f"zenodo-21860163/stateful/{token}",
        "source": source_block(f"run:{trajectory}:{suffix}"),
        "split": "development",
        "surface": "stateful",
        "payload": {"direction": "tool_call", "events": events},
        "truth": truth,
        "strata": {
            "language": "english",
            "domain": "credential_leak",
            "trajectory_id": trajectory,
            "sequence_index": 0,
            "call_index": 0,
        },
    }


def successful_write(call: Mapping[str, Any]) -> bool:
    return str(call["tool"]).lower() in {"write", "edit"} and bool(WRITE_OK_RE.match(str(call["output"]).strip()))


def invalid_tool_call_count(run: Mapping[str, Any]) -> int:
    count = 0
    turns = run.get("turns")
    if not isinstance(turns, list):
        return count
    for turn in turns:
        if not isinstance(turn, Mapping) or not isinstance(turn.get("toolCalls"), list):
            continue
        for call in turn["toolCalls"]:
            if (
                not isinstance(call, Mapping)
                or not isinstance(call.get("tool"), str)
                or not TOOL_NAME_RE.fullmatch(call["tool"])
                or call["tool"] not in REAL_TOOL_NAMES
            ):
                count += 1
    return count


def string_leaves(value: object) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield "", value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            for nested_key, text in string_leaves(child):
                yield str(key) if not nested_key else f"{key}.{nested_key}", text
    elif isinstance(value, list):
        for index, child in enumerate(value):
            for nested_key, text in string_leaves(child):
                yield str(index) if not nested_key else f"{index}.{nested_key}", text


def benign_audit_cases(
    samples: object, labels: object, primary_runs: list[tuple[str, int, Mapping[str, Any]]]
) -> tuple[list[dict[str, Any]], Counter[str]]:
    counts: Counter[str] = Counter()
    if not isinstance(samples, list) or not isinstance(labels, list):
        raise ProjectionError("invalid_precision_audit")
    verdicts = {row.get("id"): row.get("human_verdict") for row in labels if isinstance(row, Mapping)}
    cases: list[dict[str, Any]] = []
    for sample in samples:
        if not isinstance(sample, Mapping) or verdicts.get(sample.get("id")) != "benign":
            continue
        sample_id = str(sample.get("id", ""))
        files = sample.get("files")
        bodies = [row.get("body") for row in files if isinstance(row, Mapping)] if isinstance(files, list) else []
        if not bodies or not all(isinstance(body, str) and body for body in bodies):
            counts["benign_audit_invalid"] += 1
            continue
        matched: list[tuple[str, int, Mapping[str, Any], Mapping[str, Any], str]] = []
        for member, run_index, run in primary_runs:
            if str(run.get("model")) not in sample_id or str(run.get("scenarioId")) not in sample_id:
                continue
            calls = tool_calls(run)
            call_matches: list[tuple[Mapping[str, Any], str]] = []
            for body in bodies:
                candidates = [
                    (call, key)
                    for call in calls
                    if successful_write(call)
                    for key, text in string_leaves(call["input"])
                    if text == body
                ]
                if len(candidates) != 1:
                    call_matches = []
                    break
                call_matches.append(candidates[0])
            if call_matches:
                matched.extend((member, run_index, run, call, key) for call, key in call_matches)
        if not matched:
            counts["benign_audit_no_exact_successful_execution"] += 1
            continue
        identities = {(member, run_index) for member, run_index, _, _, _ in matched}
        if len(identities) != 1:
            counts["benign_audit_ambiguous_execution"] += 1
            continue
        for ordinal, (member, run_index, _run, call, content_key) in enumerate(matched):
            context = digest("zenodo-21860163-benign-context-v1", sample_id, str(ordinal))
            args = sanitize(call["input"], context, extract_canaries(call["input"]))
            if not isinstance(args, dict):
                args = {"input": args}
            # The reviewed body is sensitive benchmark content; retain only its identity.
            cursor: object = args
            parts = content_key.split(".")
            try:
                for part in parts[:-1]:
                    cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]  # type: ignore[index]
                leaf = parts[-1]
                original = next(text for key, text in string_leaves(call["input"]) if key == content_key)
                replacement = value_ref(context, original)
                if isinstance(cursor, list):
                    cursor[int(leaf)] = replacement
                else:
                    cursor[leaf] = replacement  # type: ignore[index]
            except (KeyError, IndexError, TypeError, StopIteration, ValueError) as exc:
                raise ProjectionError("failed_to_redact_audited_body") from exc
            args["_zenodo_evidence"] = {
                "human_audit_ref": digest("zenodo-21860163-human-audit-v1", sample_id),
                "result_ref": digest("zenodo-21860163-result-v1", context, str(call["output"])),
                "result_bytes": len(str(call["output"]).encode()),
                "successful_execution": True,
            }
            token = digest("zenodo-21860163-benign-case-v1", sample_id, str(ordinal))[:32]
            cases.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "id": f"zenodo-21860163/action/{token}",
                    "source": source_block(
                        f"human-audit:{digest('zenodo-21860163-audit-id-v1', sample_id)[:24]}:{ordinal}"
                    ),
                    "split": "development",
                    "surface": "action",
                    "payload": {"direction": "tool_call", "tool_name": call["tool"], "args": args, "dialect": "none"},
                    "truth": {
                        "source_truth": "benign",
                        "deterministic_truth": "benign",
                        "label_confidence": "high",
                        "label_source": "zenodo_human_precision_audit_exact_success_v1",
                        "applicability": "in_scope",
                        "expected_disposition": "allow",
                        "categories": ["human_verified_benign_code_edit"],
                    },
                    "strata": {"language": "english", "domain": "coding_agent", "hard_negative": True},
                }
            )
        counts["benign_audit_samples_joined"] += 1
    counts["benign_action_cases"] = len(cases)
    return cases, counts


def normalize_archive(path: Path, revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned revision {SOURCE_REVISION}")
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ProjectionError("missing_or_oversized_archive")
    actual_hash = file_sha256(path)
    if actual_hash != ARCHIVE_SHA256:
        raise ProjectionError(f"archive_hash_mismatch:{actual_hash}")
    counts: Counter[str] = Counter()
    exclusions: Counter[str] = Counter()
    selected_hashes: dict[str, str] = {}
    primary_runs: list[tuple[str, int, Mapping[str, Any]]] = []
    cases: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if sum(info.file_size for info in infos) > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ProjectionError("archive_uncompressed_limit_exceeded")
        for info in infos:
            validate_member(info)
        for member, expected in AUDIT_HASHES.items():
            actual = hashlib.sha256(member_bytes(archive, member)).hexdigest()
            if actual != expected:
                raise ProjectionError(f"audit_member_hash_mismatch:{member}")
            selected_hashes[member] = actual
        samples = strict_json(member_bytes(archive, AUDIT_SAMPLE), AUDIT_SAMPLE)
        labels = strict_json(member_bytes(archive, AUDIT_LABELS), AUDIT_LABELS)
        for info in infos:
            member = info.filename
            if not member.endswith(".json") or member in {AUDIT_SAMPLE, AUDIT_LABELS}:
                continue
            if "/excluded-models/" in member:
                exclusions["excluded_model_member"] += 1
                continue
            if "/_replication-wave-" in member:
                exclusions["independent_replication_member"] += 1
                continue
            if not member.startswith(
                ("p15b-run-data/01-injection-map/", "p15b-run-data/03-egress-axis/", "p15b-run-data/04-hygiene/")
            ):
                exclusions["non_run_member"] += 1
                continue
            raw = member_bytes(archive, member)
            try:
                parsed = strict_json(raw, member)
            except ProjectionError:
                exclusions["malformed_or_ambiguous_json_member"] += 1
                continue
            if not isinstance(parsed, Mapping) or not isinstance(parsed.get("runs"), list):
                exclusions["non_cell_json"] += 1
                continue
            selected_hashes[member] = hashlib.sha256(raw).hexdigest()
            counts["selected_cell_members"] += 1
            for run_index, run in enumerate(parsed["runs"]):
                if not isinstance(run, Mapping):
                    exclusions["invalid_run"] += 1
                    continue
                counts["source_runs"] += 1
                exclusions["malformed_tool_calls"] += invalid_tool_call_count(run)
                primary_runs.append((member, run_index, run))
                found = exact_proofs(run)
                if found:
                    counts["runs_with_authoritative_proof"] += 1
                    for proof in found:
                        case = stateful_case(member, run_index, run, proof)
                        if case:
                            cases.append(case)
                            counts["malicious_stateful_cases"] += 1
                else:
                    case = stateful_case(member, run_index, run, None)
                    if case:
                        cases.append(case)
                        counts["out_of_scope_stateful_cases"] += 1
                    else:
                        exclusions["insufficient_tool_sequence"] += 1
                    if run.get("exfiltrationDetected") is True:
                        exclusions["confirmed_without_bounded_exact_success_proof"] += 1
                    else:
                        exclusions["failed_or_unconfirmed_attack"] += 1
        benign, audit_counts = benign_audit_cases(samples, labels, primary_runs)
        cases.extend(benign)
        counts.update(audit_counts)
    cases.sort(key=lambda row: row["id"])
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset": DATASET_ID,
        "source": {
            "url": SOURCE_URL,
            "doi": SOURCE_DOI,
            "revision": SOURCE_REVISION,
            "published": "2026-08-09",
            "license": SOURCE_LICENSE,
            "archive": ARCHIVE_NAME,
            "archive_sha256": ARCHIVE_SHA256,
            "archive_bytes": path.stat().st_size,
            "selected_member_sha256": dict(sorted(selected_hashes.items())),
        },
        "method": {
            "maximum_predecessors": MAX_PREDECESSORS,
            "authoritative_truth": (
                "collector/detector confirmation plus exact result-to-input canary lineage "
                "plus successful network result"
            ),
            "failed_attack_handling": "out_of_scope_detect_only_never_benign",
            "redaction": "domain-separated SHA-256 value, lineage, result, and audit references",
        },
        "counts": dict(sorted(counts.items())),
        "exclusions": dict(sorted(exclusions.items())),
    }
    return cases, manifest


def validate_cases(cases: list[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required for schema validation") from exc
    schema = json.loads(schema_path.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    for index, case in enumerate(cases):
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.path))
        if errors:
            raise ProjectionError(f"schema_validation_failed:{index}:{errors[0].message}")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
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
    cases, manifest = normalize_archive(args.input.resolve(strict=True), args.revision)
    validate_cases(cases, args.schema.resolve(strict=True))
    output_text = "".join(canonical_json(case) + "\n" for case in cases)
    manifest["output"] = {
        "cases": len(cases),
        "sha256": hashlib.sha256(output_text.encode()).hexdigest(),
        "bytes": len(output_text.encode()),
    }
    atomic_write(args.output, output_text)
    atomic_write(args.manifest, canonical_json(manifest) + "\n")
    print(canonical_json(manifest["output"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
