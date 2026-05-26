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

"""Fail CI on raw audit-event action literals in Go production code.

The registry in ``internal/audit/actions.go`` is the source of truth for audit
actions. Production code constructing an ``audit.Event`` should use typed
constants such as ``string(audit.ActionGuardrailVerdict)`` rather than raw
``Action: "guardrail-verdict"`` literals. This check intentionally ignores
non-audit verdict structs plus maps in lower-level packages that cannot import
``internal/audit`` without creating an import cycle.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INTERNAL = ROOT / "internal"

RAW_ACTION_RE = re.compile(r'Action\s*:\s*"([a-z0-9._-]+)"')
AUDIT_EVENT_START_RE = re.compile(r'(?:audit\.)?Event\s*\{')


def iter_go_files() -> list[Path]:
    return [
        path
        for path in sorted(INTERNAL.rglob("*.go"))
        if not path.name.endswith("_test.go")
    ]


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def package_name(text: str) -> str:
    match = re.search(r"(?m)^\s*package\s+(\w+)\s*$", text)
    return match.group(1) if match else ""


def in_audit_event_literal(text: str, pos: int, pkg: str) -> bool:
    """Return True if ``pos`` appears inside an audit.Event literal.

    We use a narrow textual heuristic rather than a full Go parser so the
    script stays dependency-free in CI. The lookback stops at a blank line or a
    completed statement, which is enough for the compact audit.Event literals
    used throughout the codebase.
    """
    lookback_start = max(
        text.rfind("\n\n", 0, pos),
        text.rfind("}\n", 0, pos),
        text.rfind(")\n", 0, pos),
        0,
    )
    window = text[lookback_start:pos]
    if "audit.Event{" in window:
        return True
    return pkg == "audit" and AUDIT_EVENT_START_RE.search(window) is not None


def main() -> int:
    violations: list[tuple[Path, int, str, str]] = []
    for path in iter_go_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        pkg = package_name(text)
        for match in RAW_ACTION_RE.finditer(text):
            if not in_audit_event_literal(text, match.start(), pkg):
                continue
            line = line_number(text, match.start())
            src = text.splitlines()[line - 1].rstrip()
            violations.append((path, line, match.group(1), src))

    if not violations:
        print("check_audit_no_raw_literals: no raw audit.Event action literals found.")
        return 0

    print("check_audit_no_raw_literals: raw audit.Event action literals found", file=sys.stderr)
    print("Use string(audit.ActionFoo) / string(ActionFoo) from internal/audit/actions.go.", file=sys.stderr)
    for path, line, action, src in violations:
        rel = path.relative_to(ROOT)
        print(f"\n--- {rel}:{line}", file=sys.stderr)
        print(f"- {src}", file=sys.stderr)
        print(f"+ Action: string(audit.Action...), // {action}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
