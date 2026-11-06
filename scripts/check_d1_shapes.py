#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Require the public D1 subset to contain only synthetic identifiers and paths."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ALLOWED_KEYS = {"id", "kind", "tool_name", "cc_tool", "command", "args", "expected"}
BAD_TEXT = (
    re.compile(
        r"(?<![A-Za-z0-9])/(?:home|Users|root|tmp|var|workspace|mnt|opt|etc|usr|proc|run|private|app)(?:/|\b)", re.I
    ),
    re.compile(r"[A-Za-z]:\\"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.invalid\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"https?://(?!example\.invalid(?:/|\b))", re.I),
    re.compile(r"\b[A-Za-z0-9_-]+\.(?:com|net|org|io|ai|edu|gov|local|internal)\b", re.I),
    re.compile(r"(?i)\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|secret)\s*[=:]\s*(?!sample\b)"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),
)


def check(path: Path) -> list[str]:
    errors = []
    seen = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"line {number}: invalid JSON")
            continue
        row_id = row.get("id", "")
        if not re.fullmatch(r"d1-\d{4}", row_id) or row_id in seen:
            errors.append(f"line {number}: invalid or repeated id")
        seen.add(row_id)
        if set(row) - ALLOWED_KEYS:
            errors.append(f"line {number}: private metadata fields")
        text = json.dumps({k: v for k, v in row.items() if k in ("command", "args")}, ensure_ascii=False)
        if any(pattern.search(text) for pattern in BAD_TEXT):
            errors.append(f"line {number}: unsanitized content")
    if len(seen) < 250:
        errors.append(f"public subset has only {len(seen)} rows")
    return errors


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("internal/gateway/testdata/d1-shapes.jsonl")
    errors = check(path)
    for error in errors[:25]:
        print(error, file=sys.stderr)
    if errors:
        print(f"D1 scrub check: {len(errors)} issue(s)", file=sys.stderr)
        return 1
    print("D1 scrub check: public subset contains synthetic identifiers and paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
