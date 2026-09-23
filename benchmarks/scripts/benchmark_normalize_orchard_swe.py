#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize pinned Microsoft Orchard SWE trajectories as benign hard negatives.

Only English trajectories whose hidden verification suite resolved successfully
are eligible. The projection retains structured tool names and bounded decoded
arguments, plus explicit return-code outcomes in windows of at most eight calls.
Prompts, reasoning, response bodies, and unresolved trajectories are excluded.

The source release is English and MIT licensed at the pinned Hugging Face commit.
This adapter emits development-only benign/FPR cases and never malicious truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

DATASET_ID = "microsoft/Orchard"
DATASET_CONFIG = "swe"
SOURCE_REVISION = "70c05ec1f20f823ae6adc60374922e9271bb74e2"
SOURCE_LICENSE = "MIT"
SOURCE_LANGUAGE = "en"
SOURCE_TRAJECTORIES = 107_185
SOURCE_RESOLVED = 74_649
SOURCE_UNRESOLVED = 32_536
SOURCE_SHARDS = 19
SCHEMA_VERSION = "1"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / "benchmarks/schema/case-v1.schema.json"
SUPPORTED_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson", ".parquet"})
REQUIRED_COLUMNS = frozenset({"tools", "messages", "metadata"})
SAFE_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
RETURN_CODE = re.compile(r"<returncode>\s*(-?\d+)\s*</returncode>", re.IGNORECASE)
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|"
    r"aws_secret_access_key|aws_session_token)\s*=\s*)([^\s;&|]+)"
)
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
SENSITIVE_KEYS = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|authorization|auth[_-]?token|cookie|credential|"
    r"password|passwd|private[_-]?key|secret|session[_-]?token|access[_-]?token)(?:$|[_-])"
)

MAX_MESSAGES = 512
MAX_TOOL_CALLS = 512
MAX_EVENTS = 8
MAX_DEPTH = 12
MAX_NODES = 2_048
MAX_COLLECTION_ITEMS = 256
MAX_STRING_BYTES = 16_384
MAX_ARGUMENT_BYTES = 65_536
MAX_JSON_RECORD_BYTES = 8 * 1024 * 1024
JSON_CHUNK_CHARS = 64 * 1024


class ProjectionError(ValueError):
    """A source record cannot be projected without weakening the contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True, help="Local shard; repeatable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--revision", default=SOURCE_REVISION)
    parser.add_argument("--sample-modulus", type=int, default=1)
    parser.add_argument("--sample-remainder", type=int, default=0)
    parser.add_argument(
        "--max-trajectories",
        type=int,
        default=0,
        help="Deterministic cap after hash sharding; zero means unlimited",
    )
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_digest(*parts: object) -> str:
    material = "\x00".join(str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _reject_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


JSON_DECODER = json.JSONDecoder(object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def strict_json_loads(raw: str, *, code: str) -> Any:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_JSON_RECORD_BYTES:
        raise ProjectionError(code)
    try:
        value, end = JSON_DECODER.raw_decode(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProjectionError(code) from exc
    if raw[end:].strip():
        raise ProjectionError(code)
    return value


def decoded_mapping(raw: object, *, code: str) -> Mapping[str, Any]:
    if isinstance(raw, str):
        raw = strict_json_loads(raw, code=code)
    if not isinstance(raw, Mapping):
        raise ProjectionError(code)
    return raw


def decoded_list(raw: object, *, code: str) -> Sequence[Any]:
    if isinstance(raw, str):
        raw = strict_json_loads(raw, code=code)
    if not isinstance(raw, list):
        raise ProjectionError(code)
    return raw


def redact_string(value: str) -> str:
    if PRIVATE_KEY_MARKER.search(value):
        return "<redacted-private-key>"
    value = BEARER.sub(r"\1<redacted>", value)
    value = URL_USERINFO.sub(r"\1<redacted>:<redacted>@", value)
    value = SECRET_ASSIGNMENT.sub(r"\1<redacted>", value)
    return EMAIL.sub("<redacted-email>", value)


def bounded_value(value: object, *, key: str = "", depth: int = 0, budget: list[int] | None = None) -> Any:
    """Copy a JSON value while enforcing shape bounds and redacting secrets."""

    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise ProjectionError("arguments_exceed_shape_bound")
    if SENSITIVE_KEYS.search(key):
        return "<redacted>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ProjectionError("arguments_non_finite_number")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ProjectionError("arguments_string_too_large")
        return redact_string(value)
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProjectionError("arguments_collection_too_large")
        return [bounded_value(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProjectionError("arguments_collection_too_large")
        projected: dict[str, Any] = {}
        for child_key in sorted(value):
            if not isinstance(child_key, str) or not child_key:
                raise ProjectionError("arguments_invalid_key")
            projected[child_key] = bounded_value(value[child_key], key=child_key, depth=depth + 1, budget=budget)
        return projected
    raise ProjectionError("arguments_non_json_value")


def projected_arguments(raw: object) -> dict[str, Any]:
    arguments = decoded_mapping(raw, code="invalid_arguments_json")
    projected = bounded_value(arguments)
    if not isinstance(projected, dict):
        raise ProjectionError("arguments_not_object")
    if len(canonical_json(projected).encode("utf-8")) > MAX_ARGUMENT_BYTES:
        raise ProjectionError("arguments_too_large")
    return projected


def declared_tools(raw: object) -> frozenset[str]:
    definitions = decoded_list(raw, code="invalid_tools_json")
    names: set[str] = set()
    for definition in definitions:
        if not isinstance(definition, Mapping):
            raise ProjectionError("invalid_tool_definition")
        function = definition.get("function")
        if not isinstance(function, Mapping):
            raise ProjectionError("invalid_tool_definition")
        name = function.get("name")
        if not isinstance(name, str) or not SAFE_TOOL_NAME.fullmatch(name):
            raise ProjectionError("invalid_tool_definition_name")
        names.add(name)
    if not names:
        raise ProjectionError("empty_tool_definitions")
    return frozenset(names)


def trajectory_metadata(row: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = decoded_mapping(row.get("metadata"), code="invalid_metadata_json")
    status = metadata.get("verify_status")
    if status not in {"resolved", "unresolved"}:
        raise ProjectionError("invalid_verify_status")
    language = metadata.get("language", row.get("language", SOURCE_LANGUAGE))
    if not isinstance(language, str) or language.casefold() not in {"en", "eng", "english"}:
        raise ProjectionError("non_english")
    return metadata


def trajectory_key(metadata: Mapping[str, Any]) -> str:
    instance_id = metadata.get("instance_id")
    sample_index = metadata.get("sample_idx")
    source = metadata.get("source")
    if not isinstance(instance_id, str) or not instance_id or len(instance_id) > 512:
        raise ProjectionError("invalid_instance_id")
    if not isinstance(sample_index, int) or isinstance(sample_index, bool) or sample_index < 0:
        raise ProjectionError("invalid_sample_index")
    if not isinstance(source, str) or not source or len(source) > 160:
        raise ProjectionError("invalid_source_pool")
    return f"{source}\x00{instance_id}\x00{sample_index}"


def sample_bucket(key: str, modulus: int) -> int:
    value = hashlib.sha256(f"orchard-swe-sampling-v1\x00{key}".encode()).digest()
    return int.from_bytes(value[:8], "big") % modulus


def validate_sampling(modulus: int, remainder: int, max_trajectories: int) -> None:
    if modulus < 1:
        raise ValueError("sample modulus must be positive")
    if remainder < 0 or remainder >= modulus:
        raise ValueError("sample remainder must be in [0, sample modulus)")
    if max_trajectories < 0:
        raise ValueError("max trajectories must be non-negative")


def explicit_outcome(content: object) -> str:
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_JSON_RECORD_BYTES:
        raise ProjectionError("invalid_tool_result")
    matches = RETURN_CODE.findall(content)
    if not matches:
        return "unknown"
    if len(set(matches)) != 1:
        raise ProjectionError("ambiguous_returncode")
    return "succeeded" if int(matches[0]) == 0 else "failed"


def projected_events(row: Mapping[str, Any], declared: frozenset[str]) -> list[dict[str, Any]]:
    messages = row.get("messages")
    if not isinstance(messages, list) or not messages or len(messages) > MAX_MESSAGES:
        raise ProjectionError("invalid_messages")
    calls: list[dict[str, Any]] = []
    call_by_id: dict[str, dict[str, Any]] = {}
    for message in messages:
        if not isinstance(message, Mapping):
            raise ProjectionError("invalid_message")
        role = message.get("role")
        if role == "assistant":
            tool_calls = message.get("tool_calls") or []
            if not isinstance(tool_calls, list):
                raise ProjectionError("invalid_tool_calls")
            for call in tool_calls:
                if len(calls) >= MAX_TOOL_CALLS or not isinstance(call, Mapping):
                    raise ProjectionError("invalid_tool_call")
                call_id = call.get("id")
                function = call.get("function")
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or len(call_id) > 240
                    or call_id in call_by_id
                    or not isinstance(function, Mapping)
                ):
                    raise ProjectionError("invalid_tool_call")
                name = function.get("name")
                if not isinstance(name, str) or not SAFE_TOOL_NAME.fullmatch(name) or name not in declared:
                    raise ProjectionError("undeclared_or_invalid_tool_name")
                arguments = projected_arguments(function.get("arguments"))
                event: dict[str, Any] = {
                    "tool_name": name,
                    "args": arguments,
                    "dialect": "posix" if name.casefold() == "bash" else "none",
                    "outcome": "unknown",
                    "offset_seconds": len(calls),
                }
                command = arguments.get("command")
                if name.casefold() == "bash":
                    if not isinstance(command, str) or not command:
                        raise ProjectionError("bash_missing_command")
                    event["command"] = command
                calls.append(event)
                call_by_id[call_id] = event
        elif role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or call_id not in call_by_id:
                raise ProjectionError("orphan_tool_result")
            event = call_by_id[call_id]
            if event["outcome"] != "unknown":
                raise ProjectionError("duplicate_tool_result")
            event["outcome"] = explicit_outcome(message.get("content"))
    if not calls:
        raise ProjectionError("trajectory_has_no_tool_calls")
    return calls


def bounded_windows(events: Sequence[Mapping[str, Any]]) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    for start in range(0, len(events), MAX_EVENTS):
        window = [dict(event) for event in events[start : start + MAX_EVENTS]]
        if len(window) >= 2:
            yield start, window


def benign_truth(*, stateful: bool) -> dict[str, Any]:
    return {
        "source_truth": "benign",
        "deterministic_truth": "benign",
        "label_confidence": "high",
        "label_source": "source:hidden_tests_resolved",
        "applicability": "in_scope",
        "expected_disposition": "allow",
        "categories": [
            "orchard_swe",
            "resolved_trajectory",
            "benign_hard_negative",
            "bounded_action_sequence" if stateful else "atomic_tool_call",
        ],
    }


def project_trajectory(
    row: Mapping[str, Any], *, metadata: Mapping[str, Any], key: str
) -> tuple[list[dict[str, Any]], Counter[str]]:
    declared = declared_tools(row.get("tools"))
    events = projected_events(row, declared)
    identity = stable_digest(DATASET_ID, SOURCE_REVISION, key)[:24]
    source_pool = str(metadata["source"])
    base = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "dataset": DATASET_ID,
            "revision": SOURCE_REVISION,
            "original_id": f"trajectory:{identity}",
            "license": SOURCE_LICENSE,
            "redistribution": "download-only",
        },
        "split": "development",
    }
    strata = {
        "language": SOURCE_LANGUAGE,
        "ecosystem": "coding-agent",
        "campaign": source_pool,
        "domain": "software-engineering",
        "hard_negative": True,
        "split_group": identity,
        "trajectory_id": identity,
    }
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for index, event in enumerate(events):
        payload = {key: event[key] for key in ("tool_name", "command", "args", "dialect") if key in event}
        cases.append(
            {
                **base,
                "id": f"orchard-swe/{identity}/call-{index:03d}",
                "surface": "action",
                "payload": {"direction": "tool_call", **payload},
                "truth": benign_truth(stateful=False),
                "strata": {**strata, "sequence_index": index, "call_index": index},
            }
        )
        counts["action_cases"] += 1
        counts[f"tool_{event['tool_name']}"] += 1
        counts[f"outcome_{event['outcome']}"] += 1
    for window_index, (start, window) in enumerate(bounded_windows(events)):
        end = start + len(window)
        cases.append(
            {
                **base,
                "id": f"orchard-swe/{identity}/window-{window_index:03d}",
                "surface": "stateful",
                "payload": {"direction": "tool_call", "events": window},
                "truth": benign_truth(stateful=True),
                "strata": {**strata, "sequence_index": start, "call_index": end - 1},
            }
        )
        counts["stateful_cases"] += 1
    return cases, counts


def normalize(
    rows: Iterable[Mapping[str, Any]],
    *,
    revision: str = SOURCE_REVISION,
    sample_modulus: int = 1,
    sample_remainder: int = 0,
    max_trajectories: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Normalize a bounded iterable, primarily for focused tests."""

    if revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned source revision {SOURCE_REVISION}")
    validate_sampling(sample_modulus, sample_remainder, max_trajectories)
    cases: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    seen: set[str] = set()
    for row in rows:
        counts["source_trajectories"] += 1
        if not isinstance(row, Mapping):
            skipped["invalid_source_row"] += 1
            continue
        try:
            metadata = trajectory_metadata(row)
            if metadata["verify_status"] != "resolved":
                skipped["unresolved"] += 1
                continue
            key = trajectory_key(metadata)
            if key in seen:
                skipped["duplicate_trajectory"] += 1
                continue
            seen.add(key)
            if sample_bucket(key, sample_modulus) != sample_remainder:
                skipped["sampling_partition"] += 1
                continue
            if max_trajectories and counts["selected_trajectories"] >= max_trajectories:
                skipped["maximum_trajectories"] += 1
                continue
            projected, projected_counts = project_trajectory(row, metadata=metadata, key=key)
        except ProjectionError as exc:
            skipped[exc.code] += 1
            continue
        cases.extend(projected)
        counts.update(projected_counts)
        counts["selected_trajectories"] += 1
    manifest = build_manifest(counts, skipped, sample_modulus, sample_remainder, max_trajectories)
    return cases, manifest


def build_manifest(
    counts: Counter[str],
    skipped: Counter[str],
    sample_modulus: int,
    sample_remainder: int,
    max_trajectories: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_id": DATASET_ID,
        "source_config": DATASET_CONFIG,
        "source_revision": SOURCE_REVISION,
        "source_license": SOURCE_LICENSE,
        "source_language": SOURCE_LANGUAGE,
        "source_metadata": {
            "trajectories": SOURCE_TRAJECTORIES,
            "resolved": SOURCE_RESOLVED,
            "unresolved": SOURCE_UNRESOLVED,
            "parquet_shards": SOURCE_SHARDS,
        },
        "sampling": {
            "algorithm": "sha256-first-64-bits-modulo-v1",
            "modulus": sample_modulus,
            "remainder": sample_remainder,
            "max_trajectories": max_trajectories,
        },
        "counts": dict(sorted(counts.items())),
        "skipped": dict(sorted(skipped.items())),
        "cases": counts["action_cases"] + counts["stateful_cases"],
        "normalization": (
            "resolved English SWE trajectories only; exact declared tool names, redacted bounded JSON "
            "arguments, explicit return-code outcomes, and source ordering in windows of at most 8"
        ),
        "label_limitation": (
            "Development-only benign FPR/hard-negative data. Hidden-test resolution establishes a "
            "successful software-engineering workflow, not universal safety of each dual-use command. "
            "Unresolved trajectories are excluded and this adapter emits no malicious labels."
        ),
    }


def parquet_rows(path: Path) -> Iterator[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to stream Orchard Parquet shards") from exc
    source = parquet.ParquetFile(path)
    missing = sorted(REQUIRED_COLUMNS - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=16, columns=sorted(REQUIRED_COLUMNS)):
        yield from batch.to_pylist()


def json_lines(path: Path) -> Iterator[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > MAX_JSON_RECORD_BYTES:
                raise ValueError(f"{path}:{line_number}: JSON record exceeds byte bound")
            try:
                row = strict_json_loads(line, code="malformed_json_record")
            except ProjectionError as exc:
                raise ValueError(f"{path}:{line_number}: malformed JSON record") from exc
            if not isinstance(row, Mapping):
                raise ValueError(f"{path}:{line_number}: JSON record must be an object")
            yield row


def json_array(path: Path) -> Iterator[Mapping[str, Any]]:
    """Incrementally parse one JSON object or a top-level JSON array."""

    with path.open("r", encoding="utf-8") as handle:
        buffer = ""
        eof = False

        def fill() -> None:
            nonlocal buffer, eof
            chunk = handle.read(JSON_CHUNK_CHARS)
            if chunk:
                buffer += chunk
            else:
                eof = True

        fill()
        while not buffer.strip() and not eof:
            fill()
        stripped = buffer.lstrip()
        if not stripped:
            raise ValueError(f"{path}: empty JSON input")
        if stripped[0] == "{":
            while not eof:
                fill()
                if len(buffer.encode("utf-8")) > MAX_JSON_RECORD_BYTES:
                    raise ValueError(f"{path}: JSON record exceeds byte bound")
            try:
                row = strict_json_loads(buffer, code="malformed_json_record")
            except ProjectionError as exc:
                raise ValueError(f"{path}: malformed JSON object") from exc
            if not isinstance(row, Mapping):
                raise ValueError(f"{path}: JSON record must be an object")
            yield row
            return
        if stripped[0] != "[":
            raise ValueError(f"{path}: JSON must be an object or top-level array")
        buffer = stripped[1:]
        expect_value = True
        index = 0
        while True:
            buffer = buffer.lstrip()
            while not buffer and not eof:
                fill()
                buffer = buffer.lstrip()
            if not buffer:
                raise ValueError(f"{path}: unterminated JSON array")
            if expect_value and buffer[0] == "]":
                buffer = buffer[1:]
                break
            if not expect_value:
                if buffer[0] == "]":
                    buffer = buffer[1:]
                    break
                if buffer[0] != ",":
                    raise ValueError(f"{path}: expected comma after array item {index}")
                buffer = buffer[1:].lstrip()
            while True:
                try:
                    row, end = JSON_DECODER.raw_decode(buffer)
                    break
                except json.JSONDecodeError as exc:
                    if eof or len(buffer.encode("utf-8")) > MAX_JSON_RECORD_BYTES:
                        raise ValueError(f"{path}: malformed JSON array item {index}") from exc
                    fill()
                except ValueError as exc:
                    raise ValueError(f"{path}: malformed JSON array item {index}") from exc
            if len(buffer[:end].encode("utf-8")) > MAX_JSON_RECORD_BYTES:
                raise ValueError(f"{path}: JSON array item {index} exceeds byte bound")
            if not isinstance(row, Mapping):
                raise ValueError(f"{path}: JSON array item {index} must be an object")
            yield row
            index += 1
            buffer = buffer[end:]
            expect_value = False
        while not eof:
            fill()
        if buffer.strip():
            raise ValueError(f"{path}: trailing data after JSON array")


def source_rows(path: Path) -> Iterator[Mapping[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"input must be a regular non-symlink file: {path}")
    suffix = path.suffix.casefold()
    if suffix not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported input suffix: {path.suffix}")
    if suffix == ".parquet":
        yield from parquet_rows(path)
    elif suffix in {".jsonl", ".ndjson"}:
        yield from json_lines(path)
    else:
        yield from json_array(path)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_case(case: Mapping[str, Any], validator: Any) -> None:
    errors = sorted(validator.iter_errors(case), key=lambda error: list(error.absolute_path))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        raise ValueError(f"{case.get('id', '<unknown>')}:{location or '<root>'}: {errors[0].message}")
    if case["truth"]["source_truth"] != "benign":
        raise ValueError("Orchard SWE adapter may emit only benign truth")
    if case["surface"] == "stateful" and not 2 <= len(case["payload"]["events"]) <= MAX_EVENTS:
        raise ValueError("stateful case exceeds the eight-event bound")


def validate_cases(cases: Iterable[Mapping[str, Any]], schema_path: Path = DEFAULT_SCHEMA) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    seen: set[str] = set()
    for case in cases:
        case_id = str(case.get("id", ""))
        if case_id in seen:
            raise ValueError(f"duplicate case ID: {case_id}")
        seen.add(case_id)
        validate_case(case, validator)


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.revision != SOURCE_REVISION:
        raise ValueError(f"revision must equal pinned source revision {SOURCE_REVISION}")
    validate_sampling(args.sample_modulus, args.sample_remainder, args.max_trajectories)
    inputs = sorted({path.resolve() for path in args.input}, key=str)
    output = args.output.resolve()
    manifest_path = (args.manifest or args.output.with_suffix(".manifest.json")).resolve()
    if output in inputs or manifest_path in inputs:
        raise ValueError("output and manifest must not overwrite an input shard")
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to validate benchmark cases") from exc
    validator = jsonschema.Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    input_files = [{"path": str(path), "bytes": path.stat().st_size, "sha256": file_sha256(path)} for path in inputs]
    counts: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    seen_trajectories: set[str] = set()
    seen_cases: set[str] = set()
    output_hash = hashlib.sha256()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            for path in inputs:
                for row in source_rows(path):
                    counts["source_trajectories"] += 1
                    if not isinstance(row, Mapping):
                        skipped["invalid_source_row"] += 1
                        continue
                    try:
                        metadata = trajectory_metadata(row)
                        if metadata["verify_status"] != "resolved":
                            skipped["unresolved"] += 1
                            continue
                        key = trajectory_key(metadata)
                        if key in seen_trajectories:
                            skipped["duplicate_trajectory"] += 1
                            continue
                        seen_trajectories.add(key)
                        if sample_bucket(key, args.sample_modulus) != args.sample_remainder:
                            skipped["sampling_partition"] += 1
                            continue
                        if args.max_trajectories and counts["selected_trajectories"] >= args.max_trajectories:
                            skipped["maximum_trajectories"] += 1
                            continue
                        cases, projected_counts = project_trajectory(row, metadata=metadata, key=key)
                    except ProjectionError as exc:
                        skipped[exc.code] += 1
                        continue
                    for case in cases:
                        case_id = str(case["id"])
                        if case_id in seen_cases:
                            raise ValueError(f"duplicate case ID: {case_id}")
                        seen_cases.add(case_id)
                        validate_case(case, validator)
                        line = (canonical_json(case) + "\n").encode("utf-8")
                        handle.write(line)
                        output_hash.update(line)
                    counts.update(projected_counts)
                    counts["selected_trajectories"] += 1
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    manifest = build_manifest(counts, skipped, args.sample_modulus, args.sample_remainder, args.max_trajectories)
    manifest["input_files"] = input_files
    manifest["output"] = {
        "path": str(output),
        "bytes": output.stat().st_size,
        "sha256": output_hash.hexdigest(),
    }
    atomic_write_json(manifest_path, manifest)
    return manifest


def main() -> int:
    manifest = run(parse_args())
    print(canonical_json(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
