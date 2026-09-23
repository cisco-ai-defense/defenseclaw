#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize Trace Commons coding-agent tool calls as benign hard negatives.

Only structured tool names and bounded, secret-safe argument objects are
retained. Prompts, assistant prose, reasoning, tool results, and file snapshots
are excluded. Sensitive-key values and common identity/credential fragments
are deterministically redacted. The source consists of voluntarily donated,
contributor-reviewed public coding-agent sessions, so this projection measures
UX noise; it is not a claim that every literal operation is safe in every
deployment context. The adapter emits a staging split and leaves all final
session-group assignments to ``benchmark_partition.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
ACTION_TOOLS = frozenset({"Bash", "Edit", "Glob", "Grep", "PowerShell", "Read", "WebFetch", "Write"})
MAX_ARGUMENT_BYTES = 65_536
DATASET_ID = "trace-commons-agent-traces"
ADAPTER = "trace-commons-agent-traces-secret-safe-v2"
SOURCE_REVISION = "112ebd4d03ce852b00e935d523107c3d0c9a65bf"
SOURCE_PATH = "train-00000-of-00001.parquet"
SOURCE_BYTES = 70_202_603
SOURCE_SHA256 = "7c2c6ee4342ff014c47b906425501b4dc4f368df8af5280c158e827944da11e7"
SOURCE_ROWS = 30
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"
PRE_PARTITION_SPLIT = "smoke"

SECRET_KEY = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|authorization|authentication|bearer|client[_-]?secret|cookie|"
    r"credential|pass(?:word|wd)?|private[_-]?key|secret|session[_-]?key|token|webhook)"
)
INLINE_SECRET = re.compile(
    r"(?i)(\b(?:authorization|bearer|cookie|pass(?:word|wd)?|secret|token|webhook)\b\s*(?:=|:)\s*)"
    r"([^\s,;]+)"
)
COMMAND_SECRET = re.compile(
    r"(?i)((?:--?(?:password|passwd|secret|token))\s+)([^\s,;]+)"
)
BEARER_SECRET = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]+")
AUTH_HEADER_SECRET = re.compile(
    r"(?i)(\bauthorization\s*:\s*(?:(?:basic|digest|apikey)\s+)?)[^\s'\"]+"
)
COOKIE_HEADER_SECRET = re.compile(r"(?i)(\bcookie\s*:\s*)[^\r\n'\"]+")
URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
POSIX_HOME = re.compile(r"(?P<prefix>/(?:home|Users)/)[^/\s]+")
WINDOWS_HOME = re.compile(r"(?i)(?P<prefix>[A-Z]:\\Users\\)[^\\\s]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
    return parser.parse_args()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def redact_string(value: str, *, sensitive_key: bool, statistics: Counter[str]) -> str:
    if sensitive_key:
        statistics["redacted_sensitive_values"] += 1
        return "<redacted:secret>"
    projected = BEARER_SECRET.sub(r"\1<redacted:secret>", value)
    projected = AUTH_HEADER_SECRET.sub(r"\1<redacted:secret>", projected)
    projected = COOKIE_HEADER_SECRET.sub(r"\1<redacted:secret>", projected)
    projected = INLINE_SECRET.sub(r"\1<redacted:secret>", projected)
    projected = COMMAND_SECRET.sub(r"\1<redacted:secret>", projected)
    projected = URL_USERINFO.sub(r"\1<redacted-user>:<redacted:secret>@", projected)
    projected = EMAIL.sub("<redacted-email>", projected)
    projected = POSIX_HOME.sub(r"\g<prefix><redacted-user>", projected)
    projected = WINDOWS_HOME.sub(r"\g<prefix><redacted-user>", projected)
    if projected != value:
        statistics["redacted_string_values"] += 1
    return projected


def secret_safe(value: object, statistics: Counter[str], key: str = "", depth: int = 0) -> object:
    if depth > 32:
        raise ValueError("argument nesting exceeds 32 levels")
    sensitive_key = bool(SECRET_KEY.search(key))
    if type(value) is float and not math.isfinite(value):
        raise ValueError("argument contains a non-finite number")
    if value is None or type(value) in {bool, int, float}:
        if sensitive_key and value is not None:
            statistics["redacted_sensitive_values"] += 1
            return "<redacted:secret>"
        return value
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("argument string contains NUL")
        return redact_string(value, sensitive_key=sensitive_key, statistics=statistics)
    if isinstance(value, list):
        if len(value) > 4096:
            raise ValueError("argument list exceeds 4096 items")
        return [secret_safe(item, statistics, key, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 4096 or any(not isinstance(child_key, str) or "\x00" in child_key for child_key in value):
            raise ValueError("invalid argument object")
        return {
            child_key: secret_safe(item, statistics, child_key, depth + 1)
            for child_key, item in sorted(value.items())
        }
    raise ValueError("unsupported argument value")


def decoded_message(raw: object) -> dict[str, Any] | None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw, object_pairs_hook=strict_object, parse_constant=reject_nonfinite)
        except (json.JSONDecodeError, ValueError):
            return None
    return raw if isinstance(raw, dict) else None


def normalize(rows: Iterable[dict[str, Any]], revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if revision != SOURCE_REVISION:
        raise ValueError("Trace Commons revision differs from datasets.lock.json")
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    privacy: Counter[str] = Counter()
    source_rows = 0
    source_calls = 0
    selected_tools: Counter[str] = Counter()
    for source_row, row in enumerate(rows, start=1):
        source_rows += 1
        messages = row.get("messages")
        session_id = row.get("session_id")
        if not isinstance(messages, list) or not isinstance(session_id, str) or not session_id:
            skipped["invalid_row"] += 1
            continue
        trajectory_id = digest(f"{revision}\x00{session_id}")[:24]
        call_index = 0
        for raw_message in messages:
            message = decoded_message(raw_message)
            if message is None:
                skipped["invalid_message"] += 1
                continue
            calls = message.get("tool_calls")
            if calls is None:
                continue
            if not isinstance(calls, list):
                skipped["invalid_tool_calls"] += 1
                continue
            for call in calls:
                source_calls += 1
                sequence_index = call_index
                call_index += 1
                if not isinstance(call, dict):
                    skipped["invalid_tool_call"] += 1
                    continue
                function = call.get("function")
                if not isinstance(function, dict):
                    function = call
                name = function.get("name")
                arguments = function.get("arguments")
                if not isinstance(name, str) or not SAFE_TOOL.fullmatch(name):
                    skipped["invalid_tool_name"] += 1
                    continue
                if name not in ACTION_TOOLS:
                    skipped["non_action_tool"] += 1
                    continue
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(
                            arguments,
                            object_pairs_hook=strict_object,
                            parse_constant=reject_nonfinite,
                        )
                    except (json.JSONDecodeError, ValueError):
                        skipped["invalid_arguments"] += 1
                        continue
                if not isinstance(arguments, dict):
                    skipped["invalid_arguments"] += 1
                    continue
                if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENT_BYTES:
                    skipped["oversized_arguments"] += 1
                    continue
                try:
                    arguments = secret_safe(arguments, privacy)
                except ValueError:
                    skipped["invalid_argument_value"] += 1
                    continue
                payload: dict[str, Any] = {
                    "tool_name": name,
                    "args": arguments,
                    "dialect": "none",
                }
                command = arguments.get("command")
                if isinstance(command, str) and command:
                    if name == "Bash":
                        payload.update({"command": command, "dialect": "posix"})
                    elif name == "PowerShell":
                        payload.update({"command": command, "dialect": "powershell"})
                selected_tools[name] += 1
                identity = digest(f"{revision}\x00{session_id}\x00{sequence_index}\x00{name}")
                cases.append(
                    {
                        "schema_version": "1",
                        "id": f"trace-commons-agent-traces/{identity[:24]}",
                        "source": {
                            "dataset": DATASET_ID,
                            "revision": revision,
                            "original_id": f"session:{trajectory_id}#call-{sequence_index}",
                            "license": SOURCE_LICENSE,
                            "redistribution": SOURCE_REDISTRIBUTION,
                        },
                        "split": PRE_PARTITION_SPLIT,
                        "surface": "action",
                        "payload": payload,
                        "truth": {
                            "source_truth": "benign",
                            "deterministic_truth": "benign",
                            "label_confidence": "medium",
                            "label_source": "source:contributor_reviewed_public_coding_agent_trace",
                            "applicability": "in_scope",
                            "expected_disposition": "allow",
                            "categories": ["coding_agent_trace", "benign_hard_negative", "privacy_projection_v2"],
                        },
                        "strata": {
                            "domain": "structured_tool_call",
                            "hard_negative": True,
                            "split_group": trajectory_id,
                            "trajectory_id": trajectory_id,
                            "sequence_index": sequence_index,
                            "call_index": sequence_index,
                        },
                    }
                )
    cases.sort(key=lambda case: str(case["id"]))
    adapter_statistics = {
        "source_rows": source_rows,
        "source_tool_calls": source_calls,
        "cases": len(cases),
        **{f"selected_tool_{name.lower()}": count for name, count in sorted(selected_tools.items())},
        **{f"privacy_{reason}": count for reason, count in sorted(privacy.items())},
        **{f"skipped_{reason}": count for reason, count in sorted(skipped.items())},
    }
    manifest = {
        "schema_version": "1",
        "datasets": [DATASET_ID],
        "cases": len(cases),
        "counts": {DATASET_ID: len(cases)},
        "exact_payload_duplicates_removed": 0,
        "label_conflicts_excluded": 0,
        "adapter_statistics": {ADAPTER: adapter_statistics},
    }
    return cases, manifest


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read Trace Commons Parquet") from exc
    source = parquet.ParquetFile(path)
    required = {"session_id", "messages"}
    missing = sorted(required - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"input parquet is missing columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=16, columns=sorted(required)):
        yield from batch.to_pylist()


def validate_cases(rows: Iterable[dict[str, Any]], schema_path: Path) -> None:
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for row in rows:
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.absolute_path))
        if errors:
            location = ".".join(str(part) for part in errors[0].absolute_path)
            raise ValueError(f"{row.get('id', '<unknown>')}:{location}: {errors[0].message}")
        if row["split"] != PRE_PARTITION_SPLIT:
            raise ValueError("Trace Commons normalization must remain in smoke staging split")


def main() -> int:
    args = parse_args()
    if args.revision != SOURCE_REVISION:
        raise ValueError("Trace Commons revision differs from datasets.lock.json")
    if args.input.is_symlink() or not args.input.is_file():
        raise ValueError(f"invalid source file: {args.input}")
    if (
        args.input.name != SOURCE_PATH
        or args.input.stat().st_size != SOURCE_BYTES
        or file_sha256(args.input) != SOURCE_SHA256
    ):
        raise ValueError("pinned Trace Commons source identity mismatch")
    cases, manifest = normalize(parquet_rows(args.input), args.revision)
    if manifest["adapter_statistics"][ADAPTER]["source_rows"] != SOURCE_ROWS:
        raise ValueError("pinned Trace Commons source row count mismatch")
    validate_cases(cases, args.schema)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = "".join(canonical_json(case) + "\n" for case in cases)
    args.output.write_text(output, encoding="utf-8")
    manifest["output_sha256"] = hashlib.sha256(output.encode("utf-8")).hexdigest()
    manifest["source"] = {
        "dataset": DATASET_ID,
        "revision": args.revision,
        "license": SOURCE_LICENSE,
        "redistribution": SOURCE_REDISTRIBUTION,
        "path": args.input.name,
        "bytes": args.input.stat().st_size,
        "sha256": file_sha256(args.input),
    }
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
