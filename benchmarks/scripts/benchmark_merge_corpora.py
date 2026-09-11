#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Merge normalized benchmark JSONL files with payload-level deduplication."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

if __package__:
    from .benchmark_normalize import write_outputs
else:
    from benchmark_normalize import write_outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rows(paths: list[Path]) -> Iterator[dict[str, object]]:
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number}: expected an object")
                yield row


def main() -> int:
    args = parse_args()
    output = args.output
    manifest_path = args.manifest or output.with_suffix(".manifest.json")
    inputs = sorted(set(args.input))
    selected: set[str] = set()
    for row in rows(inputs):
        source = row.get("source")
        if isinstance(source, dict) and isinstance(source.get("dataset"), str):
            selected.add(str(source["dataset"]))
    counts: dict[str, int] = {}
    write_outputs(output, manifest_path, sorted(selected), rows(inputs), counts)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"] = [
        {"sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in inputs
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(output),
                "cases": manifest["cases"],
                "counts": manifest["counts"],
                "duplicates_removed": manifest["exact_payload_duplicates_removed"],
                "output_sha256": manifest["output_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
