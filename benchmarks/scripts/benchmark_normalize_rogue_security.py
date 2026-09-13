#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize Rogue Security coding-agent tool calls for diagnostics.

The source stores Python literal representations. They are parsed only with
``ast.literal_eval``; source text is never executed. Tool arguments are kept,
while surrounding model/user prose and tool responses are excluded. Non-safe
source categories remain contextual until an independent deterministic proof
finalizer accepts them.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")
MAX_SOURCE_BYTES = 1_048_576
MAX_ARGUMENT_BYTES = 65_536


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("benchmarks/schema/case-v1.schema.json"))
    return parser.parse_args()


def source_calls(value: object) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("tool_name"), str):
        arguments = value.get("arguments")
        return [(value["tool_name"], arguments)] if isinstance(arguments, dict) else []
    calls = value.get("tool_calls")
    if isinstance(calls, list):
        result: list[tuple[str, dict[str, Any]]] = []
        for call in calls:
            if not isinstance(call, dict) or not isinstance(call.get("name"), str):
                return []
            arguments = call.get("arguments")
            if not isinstance(arguments, dict):
                return []
            result.append((call["name"], arguments))
        return result
    call = value.get("tool_call")
    if isinstance(call, dict) and isinstance(call.get("name"), str):
        arguments = call.get("input")
        return [(call["name"], arguments)] if isinstance(arguments, dict) else []
    return []


def normalize(rows: Iterable[dict[str, Any]], revision: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    source_rows = 0
    for row_index, row in enumerate(rows):
        source_rows += 1
        if row.get("message_type") != "tool call":
            skipped["non_tool_call"] += 1
            continue
        raw = row.get("data_to_evaluate")
        category = row.get("category_and_criticality")
        if not isinstance(raw, str) or not isinstance(category, str) or not category:
            skipped["invalid_row"] += 1
            continue
        if len(raw.encode("utf-8")) > MAX_SOURCE_BYTES:
            skipped["oversized_source"] += 1
            continue
        try:
            value = ast.literal_eval(raw)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            skipped["invalid_literal"] += 1
            continue
        calls = source_calls(value)
        if not calls:
            skipped["invalid_tool_shape"] += 1
            continue
        row_identity = digest(f"{revision}\x00{row_index}\x00{raw}")
        source_benign = category == "Safe"
        for call_index, (name, arguments) in enumerate(calls):
            if not SAFE_TOOL.fullmatch(name):
                skipped["invalid_tool_name"] += 1
                continue
            if len(canonical_json(arguments).encode("utf-8")) > MAX_ARGUMENT_BYTES:
                skipped["oversized_arguments"] += 1
                continue
            identity = digest(f"{row_identity}\x00{call_index}\x00{name}")
            categories[category] += 1
            tools[name] += 1
            cases.append(
                {
                    "schema_version": "1",
                    "id": f"rogue-coding-agent-security/{identity[:24]}",
                    "source": {
                        "dataset": "rogue-coding-agent-security",
                        "revision": revision,
                        "original_id": f"row:{row_identity[:24]}#call-{call_index}",
                        "license": "CC-BY-NC-4.0",
                        "redistribution": "download-only",
                    },
                    "split": "development",
                    "surface": "action",
                    "payload": {"tool_name": name, "args": arguments, "dialect": "none"},
                    "truth": {
                        "source_truth": "benign" if source_benign else "malicious",
                        "deterministic_truth": "benign" if source_benign else "contextual_or_dual_use",
                        "label_confidence": "high" if source_benign else "low",
                        "label_source": "source:rogue_security_category",
                        "applicability": "in_scope",
                        "expected_disposition": "allow" if source_benign else "detect_only",
                        "categories": [
                            "rogue_security_tool_call",
                            "source_safe" if source_benign else "source_security_positive",
                            re.sub(r"[^a-z0-9]+", "_", category.lower()).strip("_"),
                        ],
                    },
                    "strata": {
                        "domain": "structured_tool_call",
                        "hard_negative": source_benign,
                        "split_group": row_identity[:24],
                        "trajectory_id": row_identity[:24],
                        "sequence_index": call_index,
                        "call_index": call_index,
                    },
                }
            )
    cases.sort(key=lambda case: str(case["id"]))
    manifest = {
        "schema_version": "1",
        "source_id": "rogue-coding-agent-security",
        "source_revision": revision,
        "source_license": "CC-BY-NC-4.0",
        "source_rows": source_rows,
        "cases": len(cases),
        "row_count": len(cases),
        "categories": dict(sorted(categories.items())),
        "tools": dict(sorted(tools.items())),
        "skipped": dict(sorted(skipped.items())),
        "normalization": (
            "bounded ast.literal_eval of source representation; structured tool names and arguments only; "
            "surrounding prose and responses excluded"
        ),
        "label_limitation": (
            "Non-safe source categories are contextual candidates, not deterministic truth. This "
            "CC-BY-NC-4.0 development corpus is diagnostic and is not a population estimate."
        ),
    }
    return cases, manifest


def parquet_rows(path: Path) -> Iterable[dict[str, Any]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read Rogue Security Parquet") from exc
    source = parquet.ParquetFile(path)
    columns = ["data_to_evaluate", "message_type", "category_and_criticality"]
    missing = sorted(set(columns) - set(source.schema_arrow.names))
    if missing:
        raise ValueError(f"input parquet is missing columns: {', '.join(missing)}")
    for batch in source.iter_batches(batch_size=64, columns=columns):
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
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
