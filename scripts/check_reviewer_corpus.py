#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Check the reviewer corpus verdict table from verbose `go test -json` output."""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

PREFIX = re.compile(r"^\s*(?:\S+_test\.go:\d+:\s*)?")
MARKER = re.compile(
    r"^(RVROW[2-7]?[|\t]|HP[0-9A-Z]+ROW\s|"
    r"(?:TAILBENIGN|COMMENTDATA|BENIGN2?|CMT3?|SKIP|NEIGHBOR|TOKEN|TAIL)\s)"
)
ACTION = re.compile(r"\baction=(allow|block|ask|error|other)\b")
NEIGHBOR_ACTION = re.compile(r"\s+(allow|block|ask|error|other)\s+ids=")


def verdict_key(test: str, output: str) -> str | None:
    line = PREFIX.sub("", output.strip())
    marker = MARKER.match(line)
    if not marker:
        return None
    if line.startswith("RVROW"):
        fields = re.split(r"[|\t]", line, maxsplit=7)
        if len(fields) < 7:
            raise ValueError("incomplete reviewer row")
        detail = "|".join(fields[:7])
    elif line.startswith("HP"):
        fields = [field.strip() for field in line.split("|")]
        if len(fields) < 2:
            return None
        detail = "|".join(fields[:2])
    else:
        action = ACTION.search(line) or NEIGHBOR_ACTION.search(line)
        if action is None:
            raise ValueError("missing Windows lexer verdict")
        detail = re.sub(r"\s+", " ", line[: action.start()].strip()) + "|" + action.group(1)
        rule_ids = re.search(r"\bids=(\[[^]]*\])", line)
        if rule_ids:
            detail += "|" + rule_ids.group(1)
    return test.split("/", 1)[0] + "\t" + detail


def collect(lines: list[str]) -> collections.Counter[str]:
    counts: collections.Counter[str] = collections.Counter()
    for raw in lines:
        event = json.loads(raw)
        if event.get("Action") != "output":
            continue
        for output in event.get("Output", "").splitlines():
            key = verdict_key(event.get("Test", ""), output)
            if key is not None:
                counts[key] += 1
    if not counts:
        raise ValueError("no reviewer corpus verdicts were produced")
    return counts


def table_text(counts: collections.Counter[str]) -> str:
    return "".join(f"{key}\t{count}\n" for key, count in sorted(counts.items()))


def read_table(path: Path) -> collections.Counter[str]:
    result: collections.Counter[str] = collections.Counter()
    for row in path.read_text(encoding="utf-8").splitlines():
        key, count = row.rsplit("\t", 1)
        if key in result:
            raise ValueError("duplicate expected reviewer key")
        result[key] = int(count)
    if not result:
        raise ValueError("empty expected reviewer table")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--write", type=Path)
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    if (args.expected is None) == (args.write is None):
        parser.error("choose exactly one of --expected and --write")
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    try:
        actual = collect(sys.stdin)
        if args.write is not None:
            args.write.write_text(table_text(actual), encoding="utf-8")
            print(f"recorded {sum(actual.values())} verdicts in {len(actual)} rows")
            return 0
        expected = read_table(args.expected)
        changed = [key for key in actual.keys() | expected.keys() if actual[key] != expected[key] * args.repeat]
        if changed:
            print(f"reviewer corpus changed: {len(changed)} rows", file=sys.stderr)
            for key in sorted(changed)[:30]:
                print(f"{key}: expected {expected[key] * args.repeat}, got {actual[key]}", file=sys.stderr)
            return 1
        print(f"reviewer corpus: {len(expected)} rows, {sum(actual.values())} verdicts matched")
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"reviewer corpus: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
