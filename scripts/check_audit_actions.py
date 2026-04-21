#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fail CI when Go ``internal/audit/actions.go``, Python
``cli/defenseclaw/audit_actions.py``, and the ``action`` enum inside
``schemas/audit-event.json`` disagree on the set of known audit
actions.

This is the load-bearing parity gate for v7: downstream consumers
(Splunk, the REST API, and the TUI) rely on every emitted audit
event's ``action`` being a member of a stable enum that is mirrored
across all three surfaces. If any one drifts, the others will
silently under- or over-match.

Run via ``make check-audit-actions``; exit non-zero on drift with a
diff designed to be readable in CI logs.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GO_FILE = ROOT / "internal" / "audit" / "actions.go"
PY_FILE = ROOT / "cli" / "defenseclaw" / "audit_actions.py"
SCHEMA_FILE = ROOT / "schemas" / "audit-event.json"

# Capture ``ActionFoo Action = "foo-bar"`` — tolerant of spacing so a
# future ``gofmt`` change does not silently disable the check.
GO_PATTERN = re.compile(
    r'Action\w+\s+Action\s*=\s*"([a-z0-9-]+)"',
    re.MULTILINE,
)

# Capture ``ACTION_FOO: Final[str] = "foo-bar"`` — deliberately also
# tolerant of the ``Final[str]`` annotation so a ``from __future__
# import annotations`` change does not break the check.
PY_PATTERN = re.compile(
    r'ACTION_\w+\s*(?::\s*Final\[str\])?\s*=\s*"([a-z0-9-]+)"',
)


def load_go_actions() -> set[str]:
    text = GO_FILE.read_text(encoding="utf-8")
    return set(GO_PATTERN.findall(text))


def load_python_actions() -> set[str]:
    text = PY_FILE.read_text(encoding="utf-8")
    return set(PY_PATTERN.findall(text))


def load_schema_actions() -> set[str]:
    doc = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    enum = doc["properties"]["action"]["enum"]
    if not isinstance(enum, list):
        raise SystemExit("schemas/audit-event.json: action.enum is not a list")
    return set(enum)


def dump_diff(label: str, missing: set[str], extra: set[str]) -> None:
    if missing:
        print(f"[{label}] missing actions (present elsewhere):", file=sys.stderr)
        for a in sorted(missing):
            print(f"  - {a}", file=sys.stderr)
    if extra:
        print(f"[{label}] extra actions (absent elsewhere):", file=sys.stderr)
        for a in sorted(extra):
            print(f"  + {a}", file=sys.stderr)


def main() -> int:
    try:
        go = load_go_actions()
        py = load_python_actions()
        schema = load_schema_actions()
    except FileNotFoundError as exc:
        print(f"check_audit_actions: missing source file: {exc}", file=sys.stderr)
        return 2

    if not go:
        print("check_audit_actions: parsed ZERO actions from Go file — regex may be broken", file=sys.stderr)
        return 2
    if not py:
        print("check_audit_actions: parsed ZERO actions from Python file", file=sys.stderr)
        return 2
    if not schema:
        print("check_audit_actions: schema enum is empty", file=sys.stderr)
        return 2

    union = go | py | schema
    ok = True

    go_missing = union - go
    go_extra = go - union  # always empty by construction, kept for symmetry
    if go_missing or go_extra:
        ok = False
        dump_diff("go", go_missing, go_extra)

    py_missing = union - py
    py_extra = py - union
    if py_missing or py_extra:
        ok = False
        dump_diff("python", py_missing, py_extra)

    schema_missing = union - schema
    schema_extra = schema - union
    if schema_missing or schema_extra:
        ok = False
        dump_diff("schema", schema_missing, schema_extra)

    if not ok:
        print("\ncheck_audit_actions: drift between Go, Python, and JSON schema", file=sys.stderr)
        print("  source of truth: internal/audit/actions.go", file=sys.stderr)
        print("  mirror:          cli/defenseclaw/audit_actions.py", file=sys.stderr)
        print("  schema:          schemas/audit-event.json (action.enum)", file=sys.stderr)
        return 1

    print(f"check_audit_actions: {len(go)} actions, all three surfaces agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
