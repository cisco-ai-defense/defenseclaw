# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Rego module signatures & data.json shape → MDX AUTOGEN blocks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

from . import mdx, splice


REGO_DIR = Path("policies/rego")
MOD_PAGE = Path("docs-site/policy/writing-rego.mdx")
DATA_PAGE = Path("docs-site/policy/data-json.mdx")

PKG = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)", re.MULTILINE)
RULE = re.compile(r"^\s*(allow|deny|verdict|action|block|quarantine|audit|[a-z_][a-z0-9_]*)\s+"
                  r"(?:if|contains|:=)\s", re.MULTILINE)
IMPORT = re.compile(r"^\s*import\s+([a-zA-Z0-9_.]+)", re.MULTILINE)
COMMENT_HEAD = re.compile(r"(?:^#[^\n]*\n)+", re.MULTILINE)


def _render_modules() -> str:
    body: List[str] = []
    files = sorted(REGO_DIR.glob("*.rego"))
    non_test = [f for f in files if not f.name.endswith("_test.rego")]
    body.append(f"_{len(non_test)} Rego modules discovered under `policies/rego/`._")
    body.append("")
    for f in non_test:
        text = f.read_text()
        pkg_m = PKG.search(text)
        pkg = pkg_m.group(1) if pkg_m else "?"
        imports = sorted({m.group(1) for m in IMPORT.finditer(text)})
        rules = sorted({m.group(1) for m in RULE.finditer(text)})
        body.append(f"### `{f.name}`")
        body.append("")
        body.append(f"- **package:** `{pkg}`")
        if imports:
            body.append(f"- **imports:** {', '.join(mdx.md_code(i) for i in imports)}")
        if rules:
            body.append(f"- **top-level rules:** {', '.join(mdx.md_code(r) for r in rules[:20])}"
                        + ("…" if len(rules) > 20 else ""))
        # Show leading comment block (top-of-file spec).
        # Skip past the license header (first 15 lines of #).
        lines = text.splitlines()
        header_end = 0
        for i, ln in enumerate(lines):
            if not ln.lstrip().startswith("#"):
                header_end = i
                break
        # Find the next comment cluster after the license header.
        spec_start = None
        for i in range(header_end, len(lines)):
            s = lines[i].lstrip()
            if s.startswith("#"):
                spec_start = i
                break
            if s and not s.startswith("#"):
                # Hit code; keep scanning for the first comment above a rule.
                continue
        if spec_start is not None:
            spec: List[str] = []
            for ln in lines[spec_start:]:
                s = ln.lstrip()
                if s.startswith("#"):
                    spec.append(s.lstrip("#").rstrip())
                elif not s:
                    if spec:
                        spec.append("")
                    continue
                else:
                    break
            spec_text = "\n".join(spec).strip()
            if spec_text:
                body.append("")
                body.append("```text")
                body.append(spec_text)
                body.append("```")
        body.append("")
    return "\n".join(body).rstrip() + "\n"


def _render_data_json() -> str:
    data_path = REGO_DIR / "data.json"
    if not data_path.exists():
        return "_`policies/rego/data.json` not present._"
    data = json.loads(data_path.read_text())
    body: List[str] = []
    body.append("`policies/rego/data.json` is the static policy input — merged with request data "
                "at admission time. The keys below are the current shape.")
    body.append("")
    body.append("```json")
    body.append(json.dumps(data, indent=2, sort_keys=True))
    body.append("```")
    return "\n".join(body) + "\n"


def _modules_template() -> str:
    return """---
title: "Writing Rego"
description: "Guide to writing admission, audit, firewall, and guardrail Rego policies for DefenseClaw."
order: 4
---

## Overview

DefenseClaw ships four Rego modules under `policies/rego/`:

- `admission.rego` — install-time gate for skills, MCP servers, and plugins.
- `audit.rego` — tags audit rows with severity and routing hints for sinks.
- `firewall.rego` — evaluates network egress decisions against the rule compiler.
- `guardrail.rego` — maps guardrail verdicts to block/quarantine/allow actions.

Tests live alongside each module (`*_test.rego`). The policy engine
(`internal/policy/`) loads them with OPA's embedded runtime — no
external `opa` binary is required.

## Module signatures

<!-- BEGIN AUTOGEN:rego:modules -->
<!-- END AUTOGEN:rego:modules -->

## Related

- [data.json](/docs-site/policy/data-json)
- [Policy lifecycle](/docs-site/policy/lifecycle)
- [Testing policies](/docs-site/policy/testing)

---

<!-- generated-from: policies/rego/admission.rego, policies/rego/audit.rego, policies/rego/firewall.rego, policies/rego/guardrail.rego -->
"""


def _data_template() -> str:
    return """---
title: "data.json"
description: "Static policy input for DefenseClaw Rego modules — schema and semantics."
order: 5
---

## Overview

`policies/rego/data.json` is the static companion to the Rego modules.
It supplies severity tables, action maps, trust lists, and default
thresholds that admission and audit rules consult. The engine merges it
under the `data.*` tree at policy-load time.

Operators can override by placing `~/.defenseclaw/policy/data.json`
(loaded by `defenseclaw policy reload`). Structure must match the
built-in shape below.

## Reference

<!-- BEGIN AUTOGEN:rego:data_json -->
<!-- END AUTOGEN:rego:data_json -->

## Related

- [Writing Rego](/docs-site/policy/writing-rego)
- [Actions matrix](/docs-site/policy/actions-matrix)

---

<!-- generated-from: policies/rego/data.json -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(MOD_PAGE, _modules_template())
    splice.ensure_scaffold(DATA_PAGE, _data_template())
    c1 = splice.splice(MOD_PAGE, "rego", "modules", _render_modules())
    c2 = splice.splice(DATA_PAGE, "rego", "data_json", _render_data_json())
    return [(str(MOD_PAGE), c1), (str(DATA_PAGE), c2)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
