#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Add pinned public TerminalBench task instructions to normalized cases.

The deterministic adapter intentionally hashes task identity and excludes
messages. The production LLM judge sees the latest authenticated user prompt,
so this projection restores only ``instruction.md`` as ``payload.content``.
Reasoning, observations, tool results, tests, and solutions remain excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

DATASET = "yoonholee/terminalbench-trajectories"


def stable_digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def task_contexts(source_root: Path, task_root: Path | None = None) -> dict[str, str]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pyarrow is required to read TerminalBench") from exc

    names: dict[str, str] = {}
    for path in sorted((source_root / "data").glob("*.parquet")):
        for row in parquet.read_table(path, columns=["task_name"]).to_pylist():
            name = row.get("task_name")
            if not isinstance(name, str) or not name.strip():
                continue
            name = name.strip()
            group = stable_digest("terminalbench-task-v1", DATASET, name)[:24]
            context = name
            if task_root is not None:
                instruction = task_root / name / "instruction.md"
                if not instruction.is_file():
                    raise ValueError(f"missing TerminalBench instruction: {instruction}")
                context = instruction.read_text(encoding="utf-8").strip()
            prior = names.setdefault(group, context)
            if prior != context:
                raise ValueError(f"TerminalBench task hash collision: {group}")
    if not names:
        raise ValueError("no TerminalBench task names found")
    return names


def contextualize(rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        if row.get("source", {}).get("dataset") != DATASET:
            raise ValueError(f"{row.get('id')}: not a TerminalBench case")
        group = row.get("strata", {}).get("split_group")
        if group not in names:
            raise ValueError(f"{row.get('id')}: task group is absent from pinned source")
        payload = row.get("payload")
        if not isinstance(payload, dict):
            raise ValueError(f"{row.get('id')}: missing payload")
        copy = dict(row)
        copy["payload"] = dict(payload)
        copy["payload"]["content"] = names[group]
        output.append(copy)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--task-root", type=Path)
    parser.add_argument("--task-revision")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    output = contextualize(rows, task_contexts(args.source_root, args.task_root))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in output)
    args.output.write_text(data, encoding="utf-8")
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    manifest = {
        "schema_version": "1",
        "kind": "terminalbench-llm-judge-context-v1",
        "input": str(args.input),
        "input_sha256": sha256_file(args.input),
        "source_root": str(args.source_root),
        "task_root": str(args.task_root) if args.task_root else None,
        "task_revision": args.task_revision,
        "row_count": len(output),
        "context_field": "payload.content",
        "context_source": "pinned public TerminalBench instruction.md" if args.task_root else "public TerminalBench task_name",
        "output_sha256": hashlib.sha256(data.encode()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
