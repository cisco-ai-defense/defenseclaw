#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Normalize InjecAgent's labeled attacker tool chains without executing source code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--split", choices=("development", "validation", "test"), default="development")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_attack_type(value: object) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")
    return normalized[:100] or "unknown"


def load_source_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise ValueError(f"{path}: expected an array of objects")
        return value
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: row must be an object")
            rows.append(row)
    return rows


def normalize(path: Path, revision: str, split: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    for line_number, source in enumerate(load_source_rows(path), 1):
        attacker_tools = source.get("Attacker Tools")
        user_tool = source.get("User Tool")
        tools = ([user_tool] if isinstance(user_tool, str) else []) + (
            attacker_tools if isinstance(attacker_tools, list) else []
        )
        if not isinstance(tools, list) or len(tools) < 2:
            skipped["not_multi_tool"] += 1
            continue
        if len(tools) > 64 or any(not isinstance(tool, str) or not SAFE_TOOL.fullmatch(tool) for tool in tools):
            skipped["invalid_tool_chain"] += 1
            continue
        material = json.dumps(
            {"line": line_number, "tools": tools, "attack_type": source.get("Attack Type", "")},
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(material.encode()).hexdigest()
        attack_type = normalized_attack_type(source.get("Attack Type"))
        rows.append(
            {
                "schema_version": "1",
                "id": f"injecagent/{digest[:24]}",
                "source": {
                    "dataset": "injecagent",
                    "revision": revision,
                    "original_id": str(line_number),
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
                    "source_truth": "malicious",
                    "applicability": "in_scope",
                    "expected_disposition": "detect_only",
                    "categories": ["indirect_prompt_injection", "multi_tool_chain", attack_type],
                },
                "strata": {
                    "campaign": attack_type,
                    "domain": "structured_tool_call",
                    "split_group": hashlib.sha256("\x00".join(tools).encode()).hexdigest()[:24],
                },
            }
        )
    rows.sort(key=lambda row: str(row["id"]))
    manifest = {
        "schema_version": "1",
        "source_id": "injecagent",
        "source_revision": revision,
        "source_license": "MIT",
        "source_sha256": sha256_file(path),
        "split": split,
        "row_count": len(rows),
        "skipped": dict(sorted(skipped.items())),
        "normalization": "user-tool plus attacker-tool names only; instructions, responses, and parameter values excluded",
    }
    return rows, manifest


def main() -> int:
    args = parse_args()
    rows, manifest = normalize(args.input, args.revision, args.split)
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
