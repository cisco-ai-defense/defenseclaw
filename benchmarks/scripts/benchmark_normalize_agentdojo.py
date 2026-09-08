#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Statically normalize AgentDojo ground-truth multi-tool plans.

Only literal FunctionCall names are retained. Source modules are parsed as AST
and are never imported or executed; prompts, arguments, and environment values
are excluded.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=("development", "validation", "test"), default="development")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal_function_calls(method: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[int, str]]:
    calls: list[tuple[int, str]] = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "FunctionCall":
            continue
        for keyword in node.keywords:
            if keyword.arg == "function" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                calls.append((node.lineno, keyword.value.value))
                break
    return sorted(calls)


def normalize(root: Path, revision: str, split: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    source_files: list[dict[str, Any]] = []
    paths = sorted(root.glob("*/user_tasks.py")) + sorted(root.glob("*/injection_tasks.py"))
    for path in paths:
        source_files.append({"path": str(path.relative_to(root)), "sha256": sha256_file(path)})
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        task_kind = "malicious" if path.name == "injection_tasks.py" else "benign"
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            method = next(
                (
                    item
                    for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "ground_truth"
                ),
                None,
            )
            if method is None:
                continue
            tools = [name for _, name in literal_function_calls(method)]
            if len(tools) < 2:
                skipped[f"{task_kind}_single_tool"] += 1
                continue
            if len(tools) > 64:
                skipped[f"{task_kind}_over_limit"] += 1
                continue
            suite = path.parent.name
            material = f"{suite}\x00{path.name}\x00{node.name}\x00" + "\x00".join(tools)
            digest = hashlib.sha256(material.encode()).hexdigest()
            rows.append(
                {
                    "schema_version": "1",
                    "id": f"agentdojo/{digest[:24]}",
                    "source": {
                        "dataset": "agentdojo",
                        "revision": revision,
                        "original_id": f"v1/{suite}/{path.name}:{node.name}",
                        "license": "MIT",
                        "redistribution": "download-only",
                    },
                    "split": split,
                    "surface": "stateful",
                    "payload": {
                        "events": [
                            {"tool_name": tool, "args": {}, "dialect": "none", "offset_seconds": index}
                            for index, tool in enumerate(tools)
                        ]
                    },
                    "truth": {
                        "source_truth": task_kind,
                        "applicability": "in_scope",
                        "expected_disposition": "detect_only" if task_kind == "malicious" else "allow",
                        "categories": ["agentdojo", "multi_tool_chain", f"{task_kind}_ground_truth"],
                    },
                    "strata": {
                        "campaign": f"agentdojo_{suite}_{task_kind}",
                        "domain": "structured_tool_call",
                        "hard_negative": task_kind == "benign",
                        "split_group": hashlib.sha256("\x00".join(tools).encode()).hexdigest()[:24],
                    },
                }
            )
    rows.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": "1",
        "source_id": "agentdojo",
        "source_revision": revision,
        "source_license": "MIT",
        "split": split,
        "row_count": len(rows),
        "truth_counts": dict(sorted(Counter(row["truth"]["source_truth"] for row in rows).items())),
        "skipped": dict(sorted(skipped.items())),
        "source_files": source_files,
        "normalization": "literal FunctionCall names from AST only; source code never executed",
    }
    return rows, manifest


def main() -> int:
    args = parse_args()
    rows, manifest = normalize(args.input_dir, args.revision, args.split)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    manifest["output_sha256"] = sha256_file(args.output)
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
