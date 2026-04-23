# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Guardrail rule-pack inventory → MDX AUTOGEN block."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from . import mdx, splice


PAGE = Path("docs-site/guardrail/rule-packs.mdx")
PACKS_DIR = Path("policies/guardrail")
PACKS = ["default", "strict", "permissive"]


def _load_pack(pack: str) -> Dict[str, List[dict]]:
    """Return {category: [rule, ...]} for a pack."""
    out: Dict[str, List[dict]] = {}
    pack_dir = PACKS_DIR / pack / "rules"
    if not pack_dir.exists():
        return out
    for yml in sorted(pack_dir.glob("*.yaml")):
        data = yaml.safe_load(yml.read_text()) or {}
        cat = data.get("category") or yml.stem
        out[cat] = data.get("rules", []) or []
    return out


def _suppressions_for(pack: str) -> List[dict]:
    supp_path = PACKS_DIR / pack / "suppressions.yaml"
    if not supp_path.exists():
        return []
    data = yaml.safe_load(supp_path.read_text()) or {}
    return data.get("suppressions") or []


def _render_packs_diff() -> str:
    loaded = {pack: _load_pack(pack) for pack in PACKS}
    suppressions = {pack: _suppressions_for(pack) for pack in PACKS}

    all_categories = sorted({c for pack in loaded.values() for c in pack})
    body: List[str] = []
    body.append("**Rule counts by pack**")
    body.append("")
    rows = []
    for cat in all_categories:
        row = [mdx.md_code(cat)]
        for pack in PACKS:
            n = len(loaded[pack].get(cat, []))
            row.append(str(n) if n else "—")
        rows.append(row)
    total_row = ["**Total rules**"]
    for pack in PACKS:
        total_row.append(f"**{sum(len(v) for v in loaded[pack].values())}**")
    rows.append(total_row)
    supp_row = ["**Suppressions**"]
    for pack in PACKS:
        supp_row.append(str(len(suppressions[pack])))
    rows.append(supp_row)
    body.append(mdx.render_table(["Category", "default", "strict", "permissive"], rows))
    body.append("")
    return "\n".join(body).rstrip() + "\n"


def _render_default_rules() -> str:
    loaded = _load_pack("default")
    body: List[str] = []
    body.append("Every rule in the `default` pack. The `strict` pack adds extra rules and "
                "tightens thresholds; the `permissive` pack is a subset. See "
                "[Configuration](/docs-site/guardrail/configuration) for `defenseclaw_profile` "
                "and per-rule `sample_inline_with_judge` overrides.")
    body.append("")
    for cat in sorted(loaded):
        rules = loaded[cat]
        body.append(f"### Category `{cat}` — {len(rules)} rules")
        body.append("")
        rows = []
        for r in rules:
            severity = r.get("severity", "")
            conf = r.get("confidence", "")
            conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf or "")
            tags = ", ".join(r.get("tags", []) or [])
            rows.append([
                mdx.md_code(r.get("id", "")),
                severity,
                conf_s or "—",
                mdx.escape_pipe(r.get("title", ""))[:200] or "—",
                mdx.escape_pipe(tags) or "—",
            ])
        body.append(mdx.render_table(
            ["Rule ID", "Severity", "Confidence", "Title", "Tags"],
            rows,
        ))
        body.append("")
    return "\n".join(body).rstrip() + "\n"


def _template() -> str:
    return """---
title: "Rule packs"
description: "DefenseClaw guardrail rule-pack catalog: default, strict, and permissive."
order: 4
---

## Overview

Rule packs are YAML bundles under `policies/guardrail/<pack>/rules/*.yaml`.
Each file covers one category — C2 exfil, cognitive-load attacks, dangerous
commands, enterprise data, local patterns, secrets, sensitive filesystem
paths, and trust-exploit patterns.

A pack is selected at runtime via `guardrail.profile` in config.yaml
(values: `default`, `strict`, `permissive`) and loaded by
`internal/guardrail/rulepack.go`.

<Callout type="tip">
  You can layer custom rules on top of a built-in pack by adding a file
  under `~/.defenseclaw/guardrail/rules/` — it merges at load time.
  See [Writing rules](/docs-site/guardrail/writing-rules) for the full
  schema.
</Callout>

## Reference — pack diff

<!-- BEGIN AUTOGEN:rules:packs_diff -->
<!-- END AUTOGEN:rules:packs_diff -->

## Reference — default pack, all rules

<!-- BEGIN AUTOGEN:rules:default_rules -->
<!-- END AUTOGEN:rules:default_rules -->

## Related

- [Writing rules](/docs-site/guardrail/writing-rules)
- [Suppressions](/docs-site/guardrail/suppressions)
- [Judge vs regex](/docs-site/guardrail/judge-vs-regex)
- [Tuning](/docs-site/guardrail/tuning)

---

<!-- generated-from: policies/guardrail/default/rules/, policies/guardrail/strict/rules/, policies/guardrail/permissive/rules/, policies/guardrail/default/suppressions.yaml -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    ch1 = splice.splice(PAGE, "rules", "packs_diff", _render_packs_diff())
    ch2 = splice.splice(PAGE, "rules", "default_rules", _render_default_rules())
    return [(str(PAGE) + " [packs_diff]", ch1), (str(PAGE) + " [default_rules]", ch2)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
