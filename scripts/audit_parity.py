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
"""Emit a JSON manifest of every ``defenseclaw`` Click subcommand + option.

This is the source-of-truth feed for ``internal/tui/cli_parity_test.go``,
which verifies every entry in ``tui.BuildRegistry()`` actually maps to a
real CLI command and uses real flags.  The output schema is deliberately
small and stable:

    {
      "binary": "defenseclaw",
      "commands": [
        {"path": ["skill", "scan"], "options": ["--all", "--non-interactive"]},
        ...
      ]
    }

Subgroups themselves are emitted (with no ``options`` beyond ``--help``)
so callers can verify that an intermediate path like ``["policy", "edit"]``
also exists.

Usage:

    python scripts/audit_parity.py                # -> stdout
    python scripts/audit_parity.py --out file.json
    python scripts/audit_parity.py --pretty
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ensure_cli_on_path() -> None:
    """Prepend ``cli/`` so ``import defenseclaw`` works when the package
    isn't installed (e.g. when this script is invoked straight from a
    checkout in CI before ``pip install -e .``)."""
    root = _project_root()
    cli_dir = os.path.join(root, "cli")
    if cli_dir not in sys.path:
        sys.path.insert(0, cli_dir)


def _walk(cmd: Any, path: list[str]) -> list[dict[str, Any]]:
    import click

    out: list[dict[str, Any]] = []
    options: list[str] = []
    arguments: list[str] = []
    short_help = ""

    if isinstance(cmd, click.Command):
        for p in getattr(cmd, "params", []):
            if isinstance(p, click.Option):
                options.extend(p.opts)
                options.extend(p.secondary_opts)
            elif isinstance(p, click.Argument):
                arguments.append(p.name)
        if cmd.help:
            short_help = cmd.help.splitlines()[0].strip()
        elif cmd.short_help:
            short_help = cmd.short_help

    out.append(
        {
            "path": list(path),
            "options": sorted(set(options)),
            "arguments": arguments,
            "is_group": isinstance(cmd, click.Group),
            "help": short_help,
        }
    )

    if isinstance(cmd, click.Group):
        # Sort children for deterministic JSON
        for name in sorted(cmd.commands.keys()):
            child = cmd.commands[name]
            out.extend(_walk(child, path + [name]))

    return out


def build_manifest() -> dict[str, Any]:
    _ensure_cli_on_path()
    # Importing defenseclaw.main eagerly registers every subcommand on the
    # `cli` group via @cli.add_command — no need to invoke `cli()`.
    from defenseclaw.main import cli as root

    return {
        "binary": "defenseclaw",
        "commands": _walk(root, []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="Write JSON to file instead of stdout")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Indent JSON output (default: compact for diff-friendly storage)",
    )
    args = parser.parse_args()

    manifest = build_manifest()
    indent = 2 if args.pretty else None
    text = json.dumps(manifest, indent=indent, sort_keys=True)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
            if indent is not None:
                fh.write("\n")
    else:
        sys.stdout.write(text)
        if indent is not None:
            sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
