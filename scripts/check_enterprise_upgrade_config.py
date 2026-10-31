#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check that an enterprise upgrade kept the administrator's config intent.

The enterprise upgrade lanes install the previous 1.x release with its
administrator config (version 9, or version 8 for a release older than the first
that reads 9), then upgrade to this build. Every value must stay at its path
with the same value, and the upgraded config must be version 9.

It needs PyYAML (CI runs it with `uv run --with pyyaml`).

Exit codes: 0 intent kept, 1 a value was lost or changed, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

MISSING = object()


def leaves(node: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (dotted path, value) for every scalar or list in a mapping tree."""
    if isinstance(node, dict) and node:
        for key, value in node.items():
            yield from leaves(value, f"{prefix}.{key}" if prefix else str(key))
    else:
        yield prefix, node


def lookup(document: Any, path: str) -> Any:
    node = document
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return MISSING
        node = node[part]
    return node


def problems(before: Any, after: Any) -> list[str]:
    source_version = lookup(before, "config_version")
    if source_version not in (8, 9):
        return [f"source config_version is {source_version!r}, want 8 or 9 (the lanes upgrade from 1.x)"]
    found = []
    if lookup(after, "config_version") != 9:
        found.append(f"config_version is {lookup(after, 'config_version')!r}, want 9")
    for path, value in leaves(before):
        if path == "config_version":
            continue
        kept = lookup(after, path)
        if kept is MISSING:
            found.append(f"{path} is gone")
        elif kept != value:
            found.append(f"{path} changed from {value!r} to {kept!r}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--before", type=Path, required=True, help="the administrator config the lane applied")
    parser.add_argument("--after", type=Path, required=True, help="the config.yaml the upgrade left")
    parser.add_argument("--label", default="upgrade-config")
    args = parser.parse_args(argv)
    try:
        before = yaml.safe_load(args.before.read_bytes())
        after = yaml.safe_load(args.after.read_bytes())
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"FAIL {args.label}: {exc}", file=sys.stderr)
        return 2
    found = problems(before, after)
    if found:
        print(f"FAIL {args.label}: the upgrade did not keep the administrator config", file=sys.stderr)
        for problem in found:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"ok   {args.label}: every administrator value kept")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
