# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Gateway HTTP route inventory -> MDX AUTOGEN block."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from . import mdx, splice


PAGE = Path("docs-site/api/endpoints.mdx")
API_GO = Path("internal/gateway/api.go")
PROXY_GO = Path("internal/gateway/proxy.go")

HANDLE = re.compile(r'mux\.HandleFunc\("([^"]+)",\s*([^)]+)\)')
FUNC = re.compile(r"func \([^)]*\)\s+(handle[A-Za-z0-9_]+)\(w http\.ResponseWriter, r \*http\.Request\) \{")
METHOD_NE = re.compile(r"r\.Method\s*!=\s*http\.Method([A-Za-z]+)")
METHOD_EQ = re.compile(r"r\.Method\s*==\s*http\.Method([A-Za-z]+)")


def _func_bodies(path: Path) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8")
    bodies: Dict[str, str] = {}
    matches = list(FUNC.finditer(text))
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        bodies[m.group(1)] = text[start:end]
    return bodies


def _methods(handler: str, bodies: Dict[str, str]) -> str:
    body = bodies.get(handler, "")
    found = {m.group(1).upper() for m in METHOD_NE.finditer(body)}
    found |= {m.group(1).upper() for m in METHOD_EQ.finditer(body)}
    if found:
        return ", ".join(sorted(found))
    return "ANY"


def _routes(path: Path, surface: str) -> Iterable[List[str]]:
    text = path.read_text(encoding="utf-8")
    bodies = _func_bodies(path)
    for route, raw_handler in HANDLE.findall(text):
        handler = raw_handler.strip()
        if handler.startswith("p."):
            handler = handler[2:]
        elif handler.startswith("a."):
            handler = handler[2:]
        yield [
            mdx.md_code(route),
            surface,
            mdx.md_code(_methods(handler, bodies)),
            mdx.md_code(handler),
            mdx.md_code(str(path)),
        ]


def _render_block() -> str:
    rows = list(_routes(API_GO, "sidecar REST")) + list(_routes(PROXY_GO, "guardrail proxy"))
    rows.sort(key=lambda r: (r[1], r[0]))
    return mdx.render_table(["Path", "Surface", "Method(s)", "Handler", "Source"], rows) + "\n"


def _template() -> str:
    return """---
title: "REST endpoints"
description: "Code-generated HTTP route inventory for the DefenseClaw sidecar and guardrail proxy."
order: 2
---

## Overview

This page is generated from the Go HTTP mux registrations. If a route is not listed in the reference table, it is not exposed by the current binary.

## Reference

<!-- BEGIN AUTOGEN:api_routes:all -->
<!-- END AUTOGEN:api_routes:all -->

## Related

- [API overview](/docs-site/api/index)
- [Authentication](/docs-site/api/auth)
- [Schemas](/docs-site/api/schemas)

---

<!-- generated-from: internal/gateway/api.go, internal/gateway/proxy.go -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    ch = splice.splice(PAGE, "api_routes", "all", _render_block())
    return [(str(PAGE), ch)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
