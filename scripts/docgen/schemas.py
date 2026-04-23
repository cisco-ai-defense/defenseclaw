# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""JSON Schema → MDX AUTOGEN blocks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import mdx, splice


SCHEMAS_DIR = Path("schemas")
PAGE = Path("docs-site/api/schemas.mdx")

TARGETS = [
    ("audit_event",        "audit-event.json",        "Audit event"),
    ("scan_event",         "scan-event.json",         "Scan event"),
    ("scan_finding_event", "scan-finding-event.json", "Scan finding event"),
    ("activity_event",     "activity-event.json",     "Activity event"),
    ("gateway_envelope",   "gateway-event-envelope.json", "Gateway event envelope"),
    ("network_egress",     "network-egress-event.json",   "Network egress event"),
    ("scan_result",        "scan-result.json",        "Scan result"),
]


def _walk_props(props: dict, required: List[str], prefix: str = "") -> List[List[str]]:
    rows: List[List[str]] = []
    for name, spec in props.items():
        full = f"{prefix}{name}"
        t = spec.get("type", "")
        if isinstance(t, list):
            t = " \\| ".join(t)
        if "enum" in spec:
            t = "enum (" + ", ".join(f"`{e}`" for e in spec["enum"]) + ")"
        elif spec.get("const") is not None:
            t = f"const `{spec['const']}`"
        elif spec.get("$ref"):
            t = spec["$ref"]
        fmt = spec.get("format", "")
        req = "yes" if name in (required or []) else "no"
        desc = (spec.get("description") or "").replace("\n", " ")
        rows.append([
            mdx.md_code(full),
            mdx.escape_pipe(str(t) + (f" ({fmt})" if fmt else "")),
            req,
            mdx.escape_pipe(desc)[:400],
        ])
        # One level deep for nested objects
        if spec.get("type") == "object" and isinstance(spec.get("properties"), dict):
            rows.extend(_walk_props(spec["properties"], spec.get("required", []),
                                    prefix=f"{full}."))
    return rows


def _render_schema_block(schema: dict) -> str:
    body: List[str] = []
    if schema.get("title"):
        body.append(f"**{schema['title']}**")
        body.append("")
    if schema.get("description"):
        body.append(schema["description"].strip())
        body.append("")
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    if props:
        body.append(mdx.render_table(
            ["Field", "Type", "Required", "Description"],
            _walk_props(props, required),
        ))
        body.append("")
    one_of = schema.get("oneOf")
    if one_of:
        body.append("**Variants (`oneOf`)**")
        body.append("")
        for i, variant in enumerate(one_of):
            body.append(f"- Variant {i + 1}: {variant.get('description', '')}")
        body.append("")
    if "$defs" in schema:
        body.append("**Definitions**")
        body.append("")
        for defname, defspec in schema["$defs"].items():
            body.append(f"*`{defname}`*")
            body.append("")
            if isinstance(defspec.get("properties"), dict):
                body.append(mdx.render_table(
                    ["Field", "Type", "Required", "Description"],
                    _walk_props(defspec["properties"], defspec.get("required", [])),
                ))
                body.append("")
    return "\n".join(body).rstrip() + "\n"


def _template() -> str:
    return """---
title: "Schemas"
description: "Reference for DefenseClaw audit, scan, activity, and network event JSON schemas."
order: 6
---

## Overview

Every event that leaves the gateway — audit rows, scanner findings,
activity snapshots, network egress records — conforms to a versioned
JSON Schema under [`schemas/`](https://github.com/cisco-ai-defense/defenseclaw/tree/main/schemas)
in the repo. These schemas are validated at write time (`audit.Logger`
and sink adapters) and at export time (`defenseclaw audit export`).

Ruby-stamp SLA: _schema evolution is additive only within a major
version_. New fields are always optional. Removing or retyping a field
requires a major version bump.

""" + "\n".join(
        f"""## {title}

<!-- BEGIN AUTOGEN:schemas:{key} -->
<!-- END AUTOGEN:schemas:{key} -->
"""
        for key, _, title in TARGETS
    ) + """

---

<!-- generated-from: schemas/audit-event.json, schemas/scan-event.json, schemas/scan-finding-event.json, schemas/activity-event.json, schemas/gateway-event-envelope.json, schemas/network-egress-event.json, schemas/scan-result.json -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    results: List[Tuple[str, bool]] = []
    for key, filename, _title in TARGETS:
        schema_path = SCHEMAS_DIR / filename
        if not schema_path.exists():
            continue
        schema = json.loads(schema_path.read_text())
        block = _render_schema_block(schema)
        ch = splice.splice(PAGE, "schemas", key, block)
        results.append((f"{PAGE} [{key}]", ch))
    return results


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
