#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501  (the checked-in benchmark tooling has always been long-line)
"""Consistent address redaction between the task and the calls of a case (rel-1-0-10 GAP-1280).

The public-set builder redacted every e-mail address in a call's arguments to the placeholder user@example.com but left the real address in the task text
(payload.content / payload.user_intent). A judge that reads both then sees "the agent mailed user@example.com although the user asked for an address it can
also read" and reports a wrong recipient: 69 of the 388 AgentDojo benign cases the alignment lane flagged on the tune side were this artifact.

  addr_consistency.py check IN [IN ...]        lists the case ids whose calls hold the placeholder while their task holds a real address; exit 1 when there are any
                                               (several files: one count line per file, ids are listed per file, exit 1 when any file is red: run it on every corpus
                                               version a build registers, GAP-1585)
  addr_consistency.py fix   IN OUT             writes OUT: those cases with the task's addresses redacted the same way (rows that need nothing stay byte-identical;
                                               ids, labels, strata and calls never change); refuses an OUT that exists (a corpus file is never rewritten in place: OUT is a
                                               new file, registered as a new version with `s7gate.py register-corpus`)

Prints counts and case ids only, never an address or any case text.
"""

from __future__ import annotations

import json
import os
import re
import sys

PLACEHOLDER = "user@example.com"
# the same address and UPN shapes the builder redacts (jobs/s7-corpus/common.py: EMAIL and UPN); example.com addresses are already placeholders
EMAIL = re.compile(r"\b[\w.+-]+@(?!example\.com\b)[\w-]+(?:\.[\w-]+)+\b")
TASK_FIELDS = ("content", "user_intent")
CALL_FIELDS = ("args", "command")


def redact_addresses(text: str) -> str:
    return EMAIL.sub(PLACEHOLDER, text)


def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def _calls(payload):
    """Every call-side value of a case: the call fields of the payload and of each event."""
    for holder in [payload, *[e for e in payload.get("events") or [] if isinstance(e, dict)]]:
        for k in CALL_FIELDS:
            if k in holder:
                yield holder[k]


def _tasks(payload):
    """(holder, field) of every task string of a case: payload.content / user_intent, and the same on each event."""
    for holder in [payload, *[e for e in payload.get("events") or [] if isinstance(e, dict)]]:
        for k in TASK_FIELDS:
            if isinstance(holder.get(k), str):
                yield holder, k


def needs_fix(row: dict) -> bool:
    p = row.get("payload")
    if not isinstance(p, dict) or not any(PLACEHOLDER in s for c in _calls(p) for s in _strings(c)):
        return False
    return any(EMAIL.search(h[k]) for h, k in _tasks(p))


def fixed(row: dict) -> dict:
    """The case with the task's addresses redacted; calls, ids, labels and strata untouched."""
    out = json.loads(json.dumps(row))
    for h, k in _tasks(out["payload"]):
        h[k] = redact_addresses(h[k])
    return out


def dumps(row: dict, ascii_: bool) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_)


def canonical_form(line: str, row: dict):
    """The ensure_ascii spelling the row was written with; None when the line is not canonical compact sorted JSON."""
    return next((a for a in (True, False) if dumps(row, a) == line), None)


def cmd_check(path: str) -> int:
    ids, n = [], 0
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        n += 1
        row = json.loads(line)
        if needs_fix(row):
            ids.append(row["id"])
    print("\n".join(ids))
    print(f"addr_consistency: {len(ids)} of {n} cases hold the placeholder in a call and a real address in the task")
    return 1 if ids else 0


def cmd_fix(src: str, dst: str) -> int:
    if os.path.abspath(src) == os.path.abspath(dst) or os.path.exists(dst):
        print(
            f"addr_consistency: {dst} exists or is the input: a corpus file is never rewritten in place; write a new file and register it as a new version",
            file=sys.stderr,
        )
        return 4
    out, changed = [], []
    for line in open(src, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line:
            continue
        row = json.loads(line)
        if not needs_fix(row):
            out.append(line)
            continue
        form = canonical_form(line, row)
        if form is None:
            print(f"addr_consistency: case {row['id']} is not in the canonical compact form; refusing", file=sys.stderr)
            return 4
        new = fixed(row)
        if (
            any(new.get(k) != row.get(k) for k in row if k != "payload")
            or new["payload"].keys() != row["payload"].keys()
        ):
            print(
                f"addr_consistency: the fix changed more than the task text of {row['id']}; refusing", file=sys.stderr
            )
            return 4
        out.append(dumps(new, form))
        changed.append(row["id"])
    with open(dst + ".tmp", "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(dst + ".tmp", dst)
    print("\n".join(changed))
    print(f"addr_consistency: {len(out)} rows written to {dst}; task addresses redacted in {len(changed)}")
    return 0


def main(argv) -> int:
    if len(argv) >= 3 and argv[1] == "check":
        return max(cmd_check(p) for p in argv[2:])
    if len(argv) == 4 and argv[1] == "fix":
        return cmd_fix(argv[2], argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
