#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Compare private D1 replay verdicts without printing corpus content."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

CELLS = {"claudecode/oss", "claudecode/managed-balanced", "codex/oss", "codex/managed-balanced"}
DECISIONS = {"allow", "alert", "block", "ask", "confirm", "error"}


def read_verdicts(
    path: Path, shard_index: int | None = None, shard_count: int = 1
) -> dict[tuple[str, str], tuple[str, str]]:
    rows: dict[tuple[str, str], tuple[str, str]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream, delimiter="\t"):
            if len(row) != 4 or not row[0] or row[1] not in CELLS or row[2] not in DECISIONS:
                raise ValueError(f"invalid D1 verdict row in {path.name}")
            key = row[0], row[1]
            if (
                shard_index is not None
                and int.from_bytes(hashlib.sha256(row[0].encode()).digest()[:4], "big") % shard_count != shard_index
            ):
                continue
            if key in rows:
                raise ValueError(f"duplicate D1 verdict in {path.name}: {key[0]} {key[1]}")
            rows[key] = row[2], row[3]
    if not rows:
        raise ValueError(f"empty D1 verdicts in {path.name}")
    return rows


def regressions(base: dict, head: dict, ratified: set[tuple[str, str]]) -> list[tuple[str, str, str, str]]:
    if base.keys() != head.keys():
        missing = base.keys() - head.keys()
        added = head.keys() - base.keys()
        raise ValueError(f"D1 row sets differ: {len(missing)} missing, {len(added)} added")
    failures = []
    for key in sorted(base):
        before, _ = base[key]
        after, rule = head[key]
        if after == "error" or (before in {"allow", "alert"} and after not in {"allow", "alert"}):
            if key not in ratified:
                failures.append((*key, after, rule))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("head", type=Path)
    parser.add_argument("--ratified", type=Path)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int, default=1)
    args = parser.parse_args()
    if args.shard_count < 1 or args.shard_index is not None and not 0 <= args.shard_index < args.shard_count:
        parser.error("invalid shard")
    try:
        approved = set()
        if args.ratified:
            for row in csv.reader(args.ratified.open(encoding="utf-8"), delimiter="\t"):
                if len(row) != 2 or row[1] not in CELLS:
                    raise ValueError("invalid ratified D1 cell")
                approved.add((row[0], row[1]))
        failures = regressions(
            read_verdicts(args.base, args.shard_index, args.shard_count),
            read_verdicts(args.head, args.shard_index, args.shard_count),
            approved,
        )
        for row_id, cell, decision, rule_id in failures:
            print(f"{row_id}\t{cell}\t{decision}\t{rule_id}")
        if failures:
            print(f"D1 benign regressions: {len(failures)}", file=sys.stderr)
            return 1
        print("D1 benign replay: no unratified allow-to-refusal changes or errors")
        return 0
    except ValueError as exc:
        print(f"D1 diff: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
