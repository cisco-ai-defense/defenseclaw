#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned Toucan SFT executions as unlabeled trajectory candidates."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import tempfile
import uuid
from collections import Counter, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = "1"
DATASET_ID = "Agent-Ark/Toucan-1.5M"
SOURCE_REVISION = "0df3cf37f2abefb380370cfb02eabea2a35ae782"
SOURCE_LICENSE = "Apache-2.0"
SOURCE_REDISTRIBUTION = "download-only"
ADAPTER = "toucan-sft-unlabeled-trajectories-v1"
SOURCE_FILES = (
    "SFT/train-00000-of-00003.parquet",
    "SFT/train-00001-of-00003.parquet",
    "SFT/train-00002-of-00003.parquet",
)
SOURCE_COLUMNS = frozenset({"uuid", "subset_name", "question", "target_tools", "tools", "messages"})

SAFE_TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,239}$")
SAFE_SUBSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
NON_ENGLISH_SCRIPT = re.compile(
    "[\u0370-\u052f\u0590-\u08ff\u0900-\u109f\u1780-\u18af\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
EXPLICIT_FAILURE = re.compile(r"^(?:error|failed|failure)(?:\b|:)", re.IGNORECASE)
EXPLICIT_SUCCESS = re.compile(r"^(?:success|succeeded|completed successfully)(?:\b|:)", re.IGNORECASE)

MAX_EVENTS = 64
CHAIN_OVERLAP = 8
MAX_MESSAGES_BYTES = 16 * 1024 * 1024
MAX_TOOLS_BYTES = 8 * 1024 * 1024
MAX_ARGUMENT_BYTES = 64 * 1024
MAX_VALUE_BYTES = 32 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_QUESTION_BYTES = 256 * 1024
MAX_ITEMS = 1024

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"


class ProjectionError(ValueError):
    """A source row cannot be projected without inventing execution evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PendingCall:
    tool_name: str
    arguments: dict[str, object]
    call_index: int


@dataclass(frozen=True)
class Candidate:
    source_key: tuple[str, int]
    payload_digest: str
    case: dict[str, Any]


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def strict_json(value: object, code: str, *, maximum: int) -> object:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ProjectionError(code)
    try:
        return json.loads(value, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ProjectionError(code) from exc


def bounded(value: object, depth: int = 0) -> object:
    if depth > 24:
        raise ProjectionError("arguments_too_deep")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ProjectionError("non_finite_argument")
        return value
    if isinstance(value, str):
        if "\x00" in value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ProjectionError("invalid_argument_value")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ProjectionError("too_many_argument_items")
        return [bounded(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS or any(not isinstance(key, str) for key in value):
            raise ProjectionError("invalid_arguments")
        return {key: bounded(item, depth + 1) for key, item in value.items()}
    raise ProjectionError("unsupported_argument_type")


def literal_call_envelope(value: object) -> dict[str, str]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_call_envelope")
    try:
        tree = ast.parse(value, mode="eval")
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        raise ProjectionError("invalid_call_envelope") from exc
    if not isinstance(tree.body, ast.Dict) or len(tree.body.keys) != 2:
        raise ProjectionError("invalid_call_envelope")
    keys: list[str] = []
    for node in tree.body.keys:
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            raise ProjectionError("invalid_call_envelope")
        keys.append(node.value)
    if set(keys) != {"name", "arguments"} or len(set(keys)) != len(keys):
        raise ProjectionError("invalid_call_envelope")
    try:
        decoded = ast.literal_eval(tree)
    except (ValueError, TypeError, MemoryError, RecursionError) as exc:
        raise ProjectionError("invalid_call_envelope") from exc
    if not isinstance(decoded, dict) or any(not isinstance(decoded.get(key), str) for key in ("name", "arguments")):
        raise ProjectionError("invalid_call_envelope")
    return {"name": decoded["name"], "arguments": decoded["arguments"]}


def exact_call(value: object, available_tools: frozenset[str], call_index: int) -> PendingCall:
    envelope = literal_call_envelope(value)
    tool_name = envelope["name"]
    if SAFE_TOOL.fullmatch(tool_name) is None or tool_name not in available_tools:
        raise ProjectionError("unknown_or_invalid_tool")
    decoded = strict_json(envelope["arguments"], "invalid_nested_arguments", maximum=MAX_ARGUMENT_BYTES)
    arguments = bounded(decoded)
    if not isinstance(arguments, dict) or len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("invalid_nested_arguments")
    return PendingCall(tool_name=tool_name, arguments=arguments, call_index=call_index)


def available_tool_names(value: object) -> frozenset[str]:
    decoded = strict_json(value, "invalid_available_tools", maximum=MAX_TOOLS_BYTES)
    if not isinstance(decoded, list) or not decoded or len(decoded) > MAX_ITEMS:
        raise ProjectionError("invalid_available_tools")
    names: set[str] = set()
    for tool in decoded:
        if not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
            raise ProjectionError("invalid_available_tools")
        name = tool["function"].get("name")
        if not isinstance(name, str) or SAFE_TOOL.fullmatch(name) is None or name in names:
            raise ProjectionError("invalid_available_tools")
        names.add(name)
    return frozenset(names)


def explicit_outcome(value: object) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ProjectionError("invalid_tool_result")
    stripped = value.strip()
    if EXPLICIT_FAILURE.match(stripped):
        return "failed"
    if EXPLICIT_SUCCESS.match(stripped):
        return "succeeded"
    try:
        decoded = json.loads(stripped, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError):
        return "unknown"
    if not isinstance(decoded, dict):
        return "unknown"
    for key in ("success", "ok"):
        if type(decoded.get(key)) is bool:
            return "succeeded" if decoded[key] else "failed"
    status = decoded.get("status")
    if isinstance(status, str):
        normalized = status.strip().lower()
        if normalized in {"success", "succeeded", "ok", "completed"}:
            return "succeeded"
        if normalized in {"error", "failed", "failure"}:
            return "failed"
    error = decoded.get("error")
    if error is not None and error != "" and error is not False and error != {}:
        return "failed"
    return "unknown"


def english_question(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(re.search(r"[A-Za-z]", value))
        and NON_ENGLISH_SCRIPT.search(value) is None
        and len(value.encode("utf-8")) <= MAX_QUESTION_BYTES
    )


def required_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise ProjectionError("invalid_uuid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProjectionError("invalid_uuid") from exc
    if str(parsed) != value.lower():
        raise ProjectionError("invalid_uuid")
    return str(parsed)


def project_events(
    messages_value: object,
    available_tools: frozenset[str],
) -> tuple[list[dict[str, Any]], Counter[str]]:
    messages = strict_json(messages_value, "invalid_messages", maximum=MAX_MESSAGES_BYTES)
    if not isinstance(messages, list) or not messages or len(messages) > MAX_ITEMS:
        raise ProjectionError("invalid_messages")
    pending: deque[PendingCall] = deque()
    events: list[dict[str, Any]] = []
    statistics: Counter[str] = Counter()
    call_index = 0
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ProjectionError("invalid_message")
        role = message.get("role")
        content = message.get("content")
        if role == "tool_call":
            if pending:
                raise ProjectionError("ambiguous_parallel_pairing")
            pending.append(exact_call(content, available_tools, call_index))
            call_index += 1
            statistics["source_tool_calls"] += 1
            continue
        if role == "tool_response":
            if not pending:
                raise ProjectionError("orphan_tool_result")
            call = pending.popleft()
            outcome = explicit_outcome(content)
            events.append(
                {
                    "args": call.arguments,
                    "dialect": "none",
                    "offset_seconds": call.call_index,
                    "outcome": outcome,
                    "tool_name": call.tool_name,
                }
            )
            statistics["paired_tool_calls"] += 1
            statistics[f"outcome_{outcome}"] += 1
            continue
        if pending:
            raise ProjectionError("interrupted_call_result_block")
        statistics[f"excluded_role_{role}"] += 1
    if pending:
        raise ProjectionError("missing_tool_result")
    return events, statistics


def bounded_chunks(events: Sequence[dict[str, Any]]) -> Iterable[tuple[int, list[dict[str, Any]]]]:
    start = 0
    while start < len(events):
        end = min(len(events), start + MAX_EVENTS)
        chunk = [dict(event, offset_seconds=index) for index, event in enumerate(events[start:end])]
        if len(chunk) >= 2:
            yield start, chunk
        if end == len(events):
            return
        start = end - CHAIN_OVERLAP


def split_group(row_uuid: str) -> str:
    return hashlib.sha256(f"{DATASET_ID}\0{row_uuid}".encode()).hexdigest()[:24]


def split_for(group: str) -> str:
    bucket = int.from_bytes(hashlib.sha256(group.encode()).digest()[:2], "big") % 100
    if bucket < 70:
        return "development"
    if bucket < 85:
        return "validation"
    return "test"


def truth() -> dict[str, Any]:
    return {
        "applicability": "out_of_scope",
        "categories": [
            "unlabeled_candidate",
            "requires_offline_adjudication",
            "real_mcp_execution",
            "bounded_action_sequence",
        ],
        "deterministic_truth": "contextual_or_dual_use",
        "exclusion_reason": "Toucan SFT has no security truth; offline trajectory adjudication is required",
        "expected_disposition": "allow",
        "label_confidence": "low",
        "label_source": "source:toucan_sft_unlabeled",
        "source_truth": "unknown",
    }


def normalize_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    candidates: list[Candidate] = []
    statistics: Counter[str] = Counter()
    seen_rows: set[str] = set()
    for row in rows:
        statistics["source_rows"] += 1
        if not isinstance(row, Mapping):
            statistics["quarantined_invalid_row"] += 1
            continue
        try:
            row_uuid = required_uuid(row.get("uuid"))
            if row_uuid in seen_rows:
                raise ProjectionError("duplicate_uuid")
            subset = row.get("subset_name")
            if not isinstance(subset, str) or SAFE_SUBSET.fullmatch(subset) is None:
                raise ProjectionError("invalid_subset")
            if not english_question(row.get("question")):
                raise ProjectionError("non_english_or_invalid_question")
            tools = available_tool_names(row.get("tools"))
            events, row_statistics = project_events(row.get("messages"), tools)
            chunks = list(bounded_chunks(events))
            if not chunks:
                raise ProjectionError("fewer_than_two_paired_calls")
        except ProjectionError as exc:
            statistics[f"quarantined_{exc.code}"] += 1
            continue
        seen_rows.add(row_uuid)
        statistics.update(row_statistics)
        group = split_group(row_uuid)
        split = split_for(group)
        trajectory = hashlib.sha256(f"{SOURCE_REVISION}\0{row_uuid}".encode()).hexdigest()[:24]
        for chunk_number, (start, chunk) in enumerate(chunks):
            payload = {"direction": "tool_call", "events": chunk}
            case = {
                "id": f"toucan-sft/{trajectory}/chunk-{chunk_number:03d}",
                "payload": payload,
                "schema_version": SCHEMA_VERSION,
                "source": {
                    "dataset": DATASET_ID,
                    "license": SOURCE_LICENSE,
                    "original_id": row_uuid,
                    "redistribution": SOURCE_REDISTRIBUTION,
                    "revision": SOURCE_REVISION,
                },
                "split": split,
                "strata": {
                    "call_index": start + len(chunk) - 1,
                    "domain": subset,
                    "ecosystem": "mcp",
                    "hard_negative": False,
                    "language": "en",
                    "sequence_index": start,
                    "split_group": group,
                    "trajectory_id": trajectory,
                },
                "surface": "stateful",
                "truth": truth(),
            }
            candidates.append(
                Candidate(
                    source_key=(row_uuid, chunk_number),
                    payload_digest=hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
                    case=case,
                )
            )
        statistics["accepted_trajectories"] += 1
        statistics["events"] += len(events)
    cases = deduplicate(candidates, statistics)
    statistics["cases"] = len(cases)
    return cases, statistics


def deduplicate(candidates: Sequence[Candidate], statistics: Counter[str]) -> list[dict[str, Any]]:
    selected: dict[str, Candidate] = {}
    for candidate in sorted(candidates, key=lambda item: item.source_key):
        if candidate.payload_digest in selected:
            statistics["exact_payload_duplicates_removed"] += 1
            continue
        selected[candidate.payload_digest] = candidate
    return sorted((candidate.case for candidate in selected.values()), key=lambda case: str(case["id"]))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_source_metadata(path: Path) -> dict[str, tuple[int, str]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError("source metadata must be a bounded regular non-symlink file")
    decoded = strict_json(path.read_text(encoding="utf-8"), "invalid_source_metadata", maximum=64 * 1024)
    if not isinstance(decoded, dict) or set(decoded) != {"config", "files", "revision"}:
        raise ValueError("source metadata has an unsupported schema")
    if decoded.get("config") != "SFT" or decoded.get("revision") != SOURCE_REVISION:
        raise ValueError("source metadata does not identify the pinned SFT revision")
    files = decoded.get("files")
    if not isinstance(files, dict) or set(files) != set(SOURCE_FILES):
        raise ValueError("source metadata does not identify the exact SFT shards")
    identities: dict[str, tuple[int, str]] = {}
    for relative in SOURCE_FILES:
        identity = files.get(relative)
        if not isinstance(identity, dict) or set(identity) != {"bytes", "sha256"}:
            raise ValueError(f"invalid source identity metadata: {relative}")
        byte_count = identity.get("bytes")
        sha256 = identity.get("sha256")
        if (
            type(byte_count) is not int
            or byte_count <= 0
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise ValueError(f"invalid source identity metadata: {relative}")
        identities[relative] = (byte_count, sha256)
    return identities


def source_paths(root: Path, identities: Mapping[str, tuple[int, str]]) -> list[tuple[str, Path]]:
    resolved_root = root.resolve(strict=True)
    paths: list[tuple[str, Path]] = []
    if set(identities) != set(SOURCE_FILES):
        raise ValueError("source identities do not identify the exact SFT shards")
    for relative in SOURCE_FILES:
        expected_bytes, expected_sha256 = identities[relative]
        candidate = resolved_root / relative
        if candidate.is_symlink():
            raise ValueError(f"source file must not be a symlink: {relative}")
        path = candidate.resolve(strict=True)
        try:
            path.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"source path escapes input root: {relative}") from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing regular source file: {relative}")
        if path.stat().st_size != expected_bytes or file_sha256(path) != expected_sha256:
            raise ValueError(f"pinned source identity mismatch: {relative}")
        paths.append((relative, path))
    return paths


def aggregate_source_sha256(paths: Sequence[tuple[str, Path]]) -> str:
    digest = hashlib.sha256(b"toucan-sft-source-tree-v1\0")
    for relative, path in paths:
        digest.update(f"{relative}\0{path.stat().st_size}\0{file_sha256(path)}\n".encode())
    return digest.hexdigest()


def parquet_rows(paths: Sequence[tuple[str, Path]]) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read Toucan SFT Parquet") from exc
    for _, path in paths:
        source = parquet.ParquetFile(path)
        if frozenset(source.schema_arrow.names) != SOURCE_COLUMNS:
            raise ValueError(f"unexpected Toucan SFT schema: {path.name}")
        for batch in source.iter_batches(batch_size=32, columns=sorted(SOURCE_COLUMNS)):
            yield from batch.to_pylist()


def normalize_input(
    root: Path,
    source_metadata: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    identities = parse_source_metadata(source_metadata)
    paths = source_paths(root, identities)
    cases, statistics = normalize_rows(parquet_rows(paths))
    source_bytes = sum(path.stat().st_size for _, path in paths)
    source_sha256 = aggregate_source_sha256(paths)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    manifest = {
        "adapter_statistics": {ADAPTER: {key: int(value) for key, value in sorted(statistics.items())}},
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "datasets": [DATASET_ID],
        "exact_payload_duplicates_removed": int(statistics["exact_payload_duplicates_removed"]),
        "label_conflicts_excluded": 0,
        "output_sha256": hashlib.sha256(body).hexdigest(),
        "schema_version": SCHEMA_VERSION,
        "source": {
            "bytes": source_bytes,
            "dataset": DATASET_ID,
            "license": SOURCE_LICENSE,
            "path": "SFT/train-*-of-00003.parquet",
            "redistribution": SOURCE_REDISTRIBUTION,
            "revision": SOURCE_REVISION,
            "sha256": source_sha256,
        },
    }
    return cases, manifest


def validate_cases(cases: Iterable[dict[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen_ids: set[str] = set()
    for case in cases:
        case_id = str(case.get("id", ""))
        if case_id in seen_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen_ids.add(case_id)
        errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(item) for item in errors[0].absolute_path) or "<root>"
            raise ValueError(f"{case_id}:{location}: {errors[0].message}")
        truth_value = case["truth"]
        if (
            truth_value["source_truth"] != "unknown"
            or truth_value["deterministic_truth"] != "contextual_or_dual_use"
            or truth_value["applicability"] != "out_of_scope"
        ):
            raise ValueError(f"{case_id}: unlabeled Toucan cases must remain out of scope")


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--source-metadata", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--split", choices=("development", "validation", "test"))
    return parser.parse_args()


def select_split(
    cases: Sequence[dict[str, Any]],
    manifest: dict[str, Any],
    split: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if split is None:
        return list(cases), manifest
    selected = [case for case in cases if case["split"] == split]
    body = "".join(canonical_json(case) + "\n" for case in selected).encode("utf-8")
    selected_manifest = dict(manifest)
    selected_manifest["cases"] = len(selected)
    selected_manifest["counts"] = {DATASET_ID: len(selected)}
    selected_manifest["output_sha256"] = hashlib.sha256(body).hexdigest()
    selected_manifest["split"] = split
    return selected, selected_manifest


def main() -> int:
    args = parse_args()
    cases, manifest = normalize_input(args.input_root, args.source_metadata)
    cases, manifest = select_split(cases, manifest, args.split)
    validate_cases(cases, args.schema)
    body = "".join(canonical_json(case) + "\n" for case in cases).encode("utf-8")
    if hashlib.sha256(body).hexdigest() != manifest["output_sha256"]:
        raise ValueError("normalization manifest does not bind output bytes")
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    atomic_write(args.output, body)
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps({"manifest": str(manifest_path), "output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
