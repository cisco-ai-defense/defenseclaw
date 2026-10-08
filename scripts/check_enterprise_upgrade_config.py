#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Check that an enterprise upgrade kept the administrator's config intent.

The enterprise upgrade lanes install the previous release with a v8 test
config, upgrade to this build, and save three files: the v8 config they
applied, the config.yaml the upgrade left (config_version 9) and the
migration-v9.json evidence record beside it. This script passes only when the
record reports no conflict and every value of the v8 config is either still at
the same path with the same value, or listed in the record as moved (and
present at its new path) or removed.

It needs PyYAML (CI runs it with `uv run --with pyyaml`).

Exit codes: 0 intent kept, 1 a value was lost or changed, 2 unreadable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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


def problems(before_raw: bytes, after: Any, record: dict[str, Any]) -> list[str]:
    before = yaml.safe_load(before_raw)
    found = []
    if record.get("from_version") != 8 or record.get("to_version") != 9:
        found.append(f"the record migrates {record.get('from_version')} -> {record.get('to_version')}, want 8 -> 9")
    if record.get("source_sha256") != hashlib.sha256(before_raw).hexdigest():
        found.append("the record's source_sha256 is not the applied v8 config")
    for conflict in record.get("conflicts") or []:
        found.append(f"migration conflict at {conflict.get('to')}: {conflict.get('reason')}")
    if lookup(after, "config_version") != 9:
        found.append(f"config_version is {lookup(after, 'config_version')!r}, want 9")
    moved = {move.get("from"): move.get("to") for move in record.get("moved") or []}
    removed = set(record.get("removed") or [])
    for path, value in leaves(before):
        if path == "config_version" or path in removed:
            continue
        if path in moved:
            kept = lookup(after, moved[path])
            if kept is MISSING:
                found.append(f"{path} moved to {moved[path]}, which the upgraded config does not set")
            elif kept != value:
                found.append(f"{path} changed from {value!r} to {kept!r} at {moved[path]}")
            continue
        kept = lookup(after, path)
        if kept is MISSING:
            found.append(f"{path} is gone and the record does not say where it went")
        elif kept != value:
            found.append(f"{path} changed from {value!r} to {kept!r}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--before", type=Path, required=True, help="the v8 config the lane applied")
    parser.add_argument("--after", type=Path, required=True, help="the config.yaml the upgrade left")
    parser.add_argument("--record", type=Path, required=True, help="the migration-v9.json evidence record")
    parser.add_argument("--label", default="upgrade-config")
    args = parser.parse_args(argv)
    try:
        before_raw = args.before.read_bytes()
        after = yaml.safe_load(args.after.read_bytes())
        record = json.loads(args.record.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"FAIL {args.label}: {exc}", file=sys.stderr)
        return 2
    found = problems(before_raw, after, record)
    if found:
        print(f"FAIL {args.label}: the upgrade did not keep the administrator config", file=sys.stderr)
        for problem in found:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"ok   {args.label}: every v8 value kept or recorded ({len(record.get('moved') or [])} moved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
