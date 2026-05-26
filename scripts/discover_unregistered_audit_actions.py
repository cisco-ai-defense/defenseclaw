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

"""List audit actions emitted by production code but absent from the registry.

This is a developer aid for expanding the v7 audit-action registry. It scans
production Go and Python call sites that construct or log audit events, compares
the discovered literal action names with ``internal/audit/actions.go``, and
prints the missing names in canonical sorted order.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GO_REGISTRY = ROOT / "internal" / "audit" / "actions.go"
GO_ROOT = ROOT / "internal"
PY_ROOT = ROOT / "cli" / "defenseclaw"

ACTION_RE = r"([a-z0-9._-]+)"
GO_REGISTRY_RE = re.compile(rf'Action\w+\s+Action\s*=\s*"{ACTION_RE}"')

GO_CALL_PATTERNS = (
    re.compile(rf'\.LogAction\(\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'\.LogActionWithTrace\(\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'\.LogActionWithCorrelation\(\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'\.LogActionWithEnforcement\(\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'\.LogActionCtx\([^\n,]+,\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'logStreamAction\([^\n,]+,\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'logStreamToolAction\([^\n,]+,\s*"{ACTION_RE}"\s*,'),
    re.compile(rf'dispatchHealthEvent\([^\n,]+,\s*"{ACTION_RE}"\s*,'),
)

GO_EVENT_LITERAL_RE = re.compile(
    rf'(?:audit\.)?Event\s*\{{[^{{}}]*?Action\s*:\s*"{ACTION_RE}"',
    re.DOTALL,
)
GO_AUDIT_ACTION_ASSIGN_RE = re.compile(rf'auditAction\s*=\s*"{ACTION_RE}"')

PY_LOG_ACTION_RE = re.compile(rf'\.log_action\(\s*"{ACTION_RE}"\s*,')
PY_LOG_ACTIVITY_RE = re.compile(
    rf'\.log_activity\([^)]*?action\s*=\s*"{ACTION_RE}"',
    re.DOTALL,
)
PY_EVENT_ACTION_RE = re.compile(rf'Event\([^)]*?action\s*=\s*"{ACTION_RE}"', re.DOTALL)


def load_registered_actions() -> set[str]:
    text = GO_REGISTRY.read_text(encoding="utf-8")
    return set(GO_REGISTRY_RE.findall(text))


def iter_go_files() -> list[Path]:
    return [
        path
        for path in sorted(GO_ROOT.rglob("*.go"))
        if not path.name.endswith("_test.go")
    ]


def iter_python_files() -> list[Path]:
    return [
        path
        for path in sorted(PY_ROOT.rglob("*.py"))
        if "tests" not in path.relative_to(PY_ROOT).parts
    ]


def discover_go_actions() -> set[str]:
    actions: set[str] = set()
    for path in iter_go_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in GO_CALL_PATTERNS:
            actions.update(match.group(1) for match in pattern.finditer(text))
        actions.update(match.group(1) for match in GO_EVENT_LITERAL_RE.finditer(text))
        actions.update(match.group(1) for match in GO_AUDIT_ACTION_ASSIGN_RE.finditer(text))
    return actions


def discover_python_actions() -> set[str]:
    actions: set[str] = set()
    for path in iter_python_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        actions.update(match.group(1) for match in PY_LOG_ACTION_RE.finditer(text))
        actions.update(match.group(1) for match in PY_LOG_ACTIVITY_RE.finditer(text))
        actions.update(match.group(1) for match in PY_EVENT_ACTION_RE.finditer(text))
    return actions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--include-registered",
        action="store_true",
        help="print every discovered production action instead of only missing entries",
    )
    args = parser.parse_args(argv)

    registered = load_registered_actions()
    discovered = discover_go_actions() | discover_python_actions()
    out = discovered if args.include_registered else discovered - registered

    for action in sorted(out):
        print(action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
