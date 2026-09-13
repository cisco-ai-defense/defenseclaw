#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize Trace Commons coding-agent tool calls as benign hard negatives.

Only structured tool names and argument objects are retained. Prompts,
assistant prose, reasoning, tool results, and file snapshots are excluded. The
dataset represents ordinary public coding-agent sessions, so this development
projection measures UX noise; it is not a claim that every literal operation
would be safe in every deployment context.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
ACTION_TOOLS = frozenset({"Bash", "Edit", "Glob", "Grep", "PowerShell", "Read", "WebFetch", "Write"})
MAX_ARGUMENT_BYTES = 65_536
DATASET_ID = "trace-commons-agent-traces"
ADAPTER = "trace-commons-agent-traces-v1"
SOURCE_LICENSE = "CC-BY-4.0"
SOURCE_REDISTRIBUTION = "download-only"


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


def decoded_message(raw: object) -> dict[str, Any] | None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    return raw if isinstance(raw, dict) else None


def normalize(rows: Iterable[dict[str, Any]], revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
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
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        skipped["invalid_arguments"] += 1
                        continue
                if not isinstance(arguments, dict):
                    skipped["invalid_arguments"] += 1
                    continue
                if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENT_BYTES:
                    skipped["oversized_arguments"] += 1
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
                        "split": "development",
                        "surface": "action",
                        "payload": payload,
                        "truth": {
                            "source_truth": "benign",
                            "deterministic_truth": "benign",
                            "label_confidence": "medium",
                            "label_source": "source:ordinary_public_coding_agent_trace",
                            "applicability": "in_scope",
                            "expected_disposition": "allow",
                            "categories": ["coding_agent_trace", "benign_hard_negative"],
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


def main() -> int:
    args = parse_args()
    cases, manifest = normalize(parquet_rows(args.input), args.revision)
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
