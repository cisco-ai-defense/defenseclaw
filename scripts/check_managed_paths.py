#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify that the managed path manifest covers the managed code.

.github/managed-paths.txt lists the paths whose change runs the managed-mode
CI (scripts/ci_changes.py, spec 008). This check fails when:

* a manifest pattern matches no tracked file (a stale entry);
* a tracked file whose path looks managed is in no manifest section, so a new
  managed file cannot land without running the managed lanes;
* a tracked file is in [excluded] and in [managed] or [managed_impacting].

Standard-library Python and git only.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# A path containing any of these words looks managed.
MANAGED_LOOKING = re.compile(
    r"enterprise|managed|secure[_-]?client|standalone|mdm|cmid",
    re.IGNORECASE,
)


def _ci_changes():
    spec = importlib.util.spec_from_file_location("ci_changes", ROOT / "scripts" / "ci_changes.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return [line for line in result.stdout.splitlines() if line]


def problems(sections: dict[str, tuple[str, ...]], files: list[str], matches) -> list[str]:
    """Return one message per manifest problem; empty when the manifest is sound."""

    found = []
    for name, patterns in sections.items():
        for pattern in patterns:
            if not any(matches(path, pattern) for path in files):
                found.append(f"[{name}] {pattern}: matches no tracked file")

    included = sections["managed"] + sections["managed_impacting"]
    for path in files:
        is_included = any(matches(path, pattern) for pattern in included)
        is_excluded = any(matches(path, pattern) for pattern in sections["excluded"])
        if is_included and is_excluded:
            found.append(f"{path}: in [excluded] and in a managed section")
        elif not is_included and not is_excluded and MANAGED_LOOKING.search(path):
            found.append(
                f"{path}: looks managed but is in no section; add it to [managed] "
                "(or [excluded] when it does not change managed behavior)"
            )
    return found


def main() -> int:
    ci_changes = _ci_changes()
    manifest = ROOT / ci_changes.MANAGED_MANIFEST
    try:
        sections = ci_changes.parse_managed_manifest(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"check-managed-paths: {exc}", file=sys.stderr)
        return 1
    found = problems(sections, tracked_files(), ci_changes._matches)
    if found:
        print(f"check-managed-paths: {ci_changes.MANAGED_MANIFEST} is out of date:", file=sys.stderr)
        for message in found:
            print(f"  {message}", file=sys.stderr)
        return 1
    print("check-managed-paths: the manifest covers every managed-looking path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
