#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Generate the macOS app command palette table from the TUI registry.

cli/defenseclaw/tui/registry_data.py is the single source of the command
palette. This rewrites `CommandRegistry.all` in the macOS app from it (the
numeric id is the entry's position there), or with --check fails when the
two have drifted. Run it after an upstream app import or a registry change.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "cli/defenseclaw/tui/registry_data.py"
SWIFT = ROOT / "macos/DefenseClawMac/DefenseClawMac/DataLayer/CommandRegistry.swift"
TABLE_START = "    static let all: [CommandDefinition] = ["
TABLE_END = "    ]"


def registry_entries(path: Path) -> tuple[tuple, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "GO_PARITY_REGISTRY"
        ):
            return ast.literal_eval(node.value)
    raise SystemExit(f"GO_PARITY_REGISTRY not found in {path}")


def swift_string(value: str) -> str:
    out = []
    for char in value:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"\\u{{{ord(char):x}}}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def swift_row(index: int, entry: tuple) -> str:
    title, binary, arguments, summary, category, requires_input, usage = entry
    args = ", ".join(swift_string(a) for a in arguments)
    return (
        f"        CommandDefinition(id: {index}, title: {swift_string(title)}, binary: {swift_string(binary)}, "
        f"arguments: [{args}], summary: {swift_string(summary)}, category: {swift_string(category)}, "
        f"requiresInput: {'true' if requires_input else 'false'}, usage: {swift_string(usage)}),"
    )


def render(swift_text: str, entries: tuple[tuple, ...]) -> str:
    lines = swift_text.split("\n")
    try:
        start = lines.index(TABLE_START)
        end = lines.index(TABLE_END, start + 1)
    except ValueError:
        raise SystemExit("CommandRegistry.all table markers not found") from None
    rows = [swift_row(i, e) for i, e in enumerate(entries)]
    return "\n".join(lines[: start + 1] + rows + lines[end:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the Swift table differs")
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--swift", type=Path, default=SWIFT)
    args = parser.parse_args()

    entries = registry_entries(args.registry)
    current = args.swift.read_text(encoding="utf-8")
    wanted = render(current, entries)
    if current == wanted:
        print(f"macOS command registry matches registry_data.py ({len(entries)} commands)")
        return 0
    if args.check:
        print(
            f"{args.swift} is out of date with {args.registry}; "
            "run scripts/sync-macos-command-registry.py",
            file=sys.stderr,
        )
        return 1
    args.swift.write_text(wanted, encoding="utf-8")
    print(f"wrote {len(entries)} commands to {args.swift}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
