# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Exit code inventory → MDX AUTOGEN block."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

from . import mdx, splice


PAGE = Path("docs-site/reference/exit-codes.mdx")

SYS_EXIT = re.compile(r'(?:sys\.|ctx\.)exit\(\s*(\d+)\s*\)')
CLICK_EXIT = re.compile(r'raise\s+click\.exceptions\.Exit\(\s*(\d+)\s*\)')
GO_EXIT = re.compile(r'os\.Exit\(\s*(\d+)\s*\)')

SEARCH_ROOTS = [Path("cli"), Path("internal"), Path("cmd"), Path("extensions")]


def _scan() -> Dict[int, Set[Tuple[str, int]]]:
    """Return {code: {(relpath, line), …}}."""
    hits: Dict[int, Set[Tuple[str, int]]] = defaultdict(set)
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".go"}:
                continue
            if any(p in {"__pycache__", "node_modules", ".venv", "dist", "build"}
                   for p in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pat in (SYS_EXIT, CLICK_EXIT, GO_EXIT):
                for m in pat.finditer(text):
                    code = int(m.group(1))
                    line = text.count("\n", 0, m.start()) + 1
                    hits[code].add((str(path), line))
    return hits


CANONICAL = {
    0: ("Success", "Command completed normally."),
    1: ("Generic failure", "Unhandled error, runtime exception, or unspecified failure."),
    2: ("Usage error", "Click / argparse rejects invalid flags or arguments."),
    3: ("Configuration error", "config.yaml missing, malformed, or fails schema validation."),
    4: ("Policy violation / scan-gate blocked", "Scanner or policy blocked the operation (e.g. `skill install` denied)."),
    5: ("Daemon not running", "Operation required the gateway sidecar but it is down."),
    6: ("Already running", "Gateway daemon start requested while it is already running."),
    7: ("Resource not found", "Skill, MCP server, plugin, or audit row not found."),
    8: ("Permission denied", "Insufficient privileges (sandbox, filesystem, elevated ops)."),
    9: ("Provider / upstream failure", "LLM provider, webhook, or external API returned an error after retries."),
    10: ("Sandbox error", "openshell-sandbox subsystem misbehaved."),
    100: ("Feature disabled", "Attempted to use a guardrailed/gated feature that is off."),
}


def _render_block(hits: Dict[int, Set[Tuple[str, int]]]) -> str:
    all_codes = sorted(set(hits) | set(CANONICAL))
    rows: List[List[str]] = []
    for code in all_codes:
        name, desc = CANONICAL.get(code, ("Command-specific", "Defined by the calling command; consult the linked source."))
        sites = sorted(hits.get(code, []))
        refs = ", ".join(f"`{p}:{ln}`" for p, ln in sites[:4])
        if len(sites) > 4:
            refs += f" (+{len(sites) - 4} more)"
        rows.append([str(code), name, mdx.escape_pipe(desc),
                     mdx.escape_pipe(refs) if refs else "—"])
    body = ["_Canonical code table plus every call-site discovered by AST scan._", ""]
    body.append(mdx.render_table(["Code", "Label", "Meaning", "Call-sites"], rows))
    return "\n".join(body) + "\n"


def _template() -> str:
    return """---
title: "Exit codes"
description: "Canonical exit code table for every DefenseClaw CLI surface, with source call-site pointers."
order: 3
---

## Overview

DefenseClaw CLIs use a small, stable set of exit codes. Automation should
branch on the numeric code — messages may be localized or wrapped by the
outer shell.

<Callout type="tip">
  Use `--json` wherever supported for machine-readable output alongside
  the exit code. Most commands emit structured errors as JSON when
  piped to a non-tty.
</Callout>

## Reference

<!-- BEGIN AUTOGEN:exit_codes:all -->
<!-- END AUTOGEN:exit_codes:all -->

## Related

- [Environment variables](/docs-site/reference/env-vars)
- [Automation](/docs-site/cli/automation)

---

<!-- generated-from: cli/, internal/, cmd/, extensions/ -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    ch = splice.splice(PAGE, "exit_codes", "all", _render_block(_scan()))
    return [(str(PAGE), ch)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
