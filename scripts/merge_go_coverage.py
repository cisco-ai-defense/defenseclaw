#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Merge disjoint or sharded Go coverprofiles without losing hit counts."""

from __future__ import annotations

import argparse
from pathlib import Path


def merge_profiles(paths: list[Path]) -> tuple[str, dict[str, int]]:
    mode: str | None = None
    blocks: dict[str, int] = {}
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines or not lines[0].startswith("mode: "):
            raise ValueError(f"invalid Go coverprofile: {path}")
        current_mode = lines[0].removeprefix("mode: ")
        if mode is None:
            mode = current_mode
        elif current_mode != mode:
            raise ValueError(f"coverage mode mismatch in {path}")
        for line in lines[1:]:
            block, separator, count_text = line.rpartition(" ")
            if not separator:
                raise ValueError(f"invalid coverage row in {path}: {line!r}")
            count = int(count_text)
            if current_mode == "set":
                blocks[block] = max(blocks.get(block, 0), count)
            else:
                blocks[block] = blocks.get(block, 0) + count
    if mode is None:
        raise ValueError("at least one coverprofile is required")
    return mode, blocks


def write_profile(output: Path, mode: str, blocks: dict[str, int]) -> None:
    lines = [f"mode: {mode}"]
    lines.extend(f"{block} {blocks[block]}" for block in sorted(blocks))
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("profiles", nargs="+", type=Path)
    args = parser.parse_args()
    mode, blocks = merge_profiles(args.profiles)
    write_profile(args.output, mode, blocks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
