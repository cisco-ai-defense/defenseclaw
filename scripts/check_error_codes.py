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

"""Fail CI when Go ``internal/gatewaylog/error_codes.go`` and Python
``cli/defenseclaw/gateway_error_codes.py`` disagree on the set of
registered error codes or subsystems.

Run via ``make check-error-codes``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GO_FILE = ROOT / "internal" / "gatewaylog" / "error_codes.go"
PY_FILE = ROOT / "cli" / "defenseclaw" / "gateway_error_codes.py"

GO_ERROR_PATTERN = re.compile(
    r'ErrCode\w+\s+ErrorCode\s*=\s*"([A-Z0-9_]+)"',
    re.MULTILINE,
)
GO_SUBSYSTEM_PATTERN = re.compile(
    r'Subsystem\w+\s+Subsystem\s*=\s*"([a-z0-9_\-]+)"',
    re.MULTILINE,
)

PY_ERROR_PATTERN = re.compile(
    r'ERR_\w+\s*(?::\s*Final\[str\])?\s*=\s*"([A-Z0-9_]+)"',
)
PY_SUBSYSTEM_PATTERN = re.compile(
    r'SUBSYSTEM_\w+\s*(?::\s*Final\[str\])?\s*=\s*"([a-z0-9_\-]+)"',
)


def load(path: Path, pattern: re.Pattern[str]) -> set[str]:
    if not path.exists():
        raise SystemExit(f"check_error_codes: {path} not found")
    return set(pattern.findall(path.read_text(encoding="utf-8")))


def dump_diff(label: str, missing: set[str], extra: set[str]) -> None:
    if missing:
        print(f"[{label}] missing (present elsewhere):", file=sys.stderr)
        for x in sorted(missing):
            print(f"  - {x}", file=sys.stderr)
    if extra:
        print(f"[{label}] extra (absent elsewhere):", file=sys.stderr)
        for x in sorted(extra):
            print(f"  + {x}", file=sys.stderr)


def check(name: str, go_set: set[str], py_set: set[str]) -> bool:
    if not go_set:
        print(f"check_error_codes: parsed ZERO {name} from Go — regex broken", file=sys.stderr)
        return False
    if not py_set:
        print(f"check_error_codes: parsed ZERO {name} from Python", file=sys.stderr)
        return False
    if go_set == py_set:
        print(f"check_error_codes: {len(go_set)} {name} parity OK")
        return True
    dump_diff(f"{name}/go", py_set - go_set, go_set - py_set)
    dump_diff(f"{name}/python", go_set - py_set, py_set - go_set)
    return False


def main() -> int:
    go_errors = load(GO_FILE, GO_ERROR_PATTERN)
    py_errors = load(PY_FILE, PY_ERROR_PATTERN)
    go_subs = load(GO_FILE, GO_SUBSYSTEM_PATTERN)
    py_subs = load(PY_FILE, PY_SUBSYSTEM_PATTERN)

    ok_errors = check("error codes", go_errors, py_errors)
    ok_subs = check("subsystems", go_subs, py_subs)

    if ok_errors and ok_subs:
        return 0
    print("\ncheck_error_codes: drift between Go and Python", file=sys.stderr)
    print("  source of truth: internal/gatewaylog/error_codes.go", file=sys.stderr)
    print("  mirror:          cli/defenseclaw/gateway_error_codes.py", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
