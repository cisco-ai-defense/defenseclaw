#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Keep the dependency-free v2 adapter identical in every shipped bridge."""

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "// BEGIN GENERATED OPENCODE V2 ADAPTER\n"
END = "// END GENERATED OPENCODE V2 ADAPTER"
TARGETS = (
    "internal/gateway/connector/hooks/opencode-plugin.js",
    "internal/enterprisepolicy/opencode_managed_plugin.js",
    "internal/gateway/connector/hooks/opencode-plugin-secure-client.js",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    adapter = (ROOT / "internal/opencodebridge/adapter.js").read_text(encoding="utf-8")
    stale = False
    for target in TARGETS:
        path = ROOT / target
        current = path.read_text(encoding="utf-8")
        before, rest = current.split(BEGIN)
        _, after = rest.split(END)
        expected = before + BEGIN + adapter.rstrip() + "\n" + END + after
        if current == expected:
            continue
        if args.check:
            print(f"Stale OpenCode v2 adapter: {target}")
            stale = True
        else:
            path.write_text(expected, encoding="utf-8", newline="\n")
    return int(stale)


if __name__ == "__main__":
    raise SystemExit(main())
