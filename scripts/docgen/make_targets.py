# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Makefile target inventory -> MDX AUTOGEN block."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from . import mdx, splice


PAGE = Path("docs-site/installation/make-install.mdx")
MAKEFILE = Path("Makefile")
TARGET = re.compile(r"^([A-Za-z0-9_.-]+):(?:\s|$)", re.M)
PHONY = re.compile(r"^\.PHONY:\s+(.+)$", re.M)


def _phony_targets(text: str) -> set[str]:
    out: set[str] = set()
    for m in PHONY.finditer(text):
        out.update(m.group(1).split())
    return out


def _render_block() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    phony = _phony_targets(text)
    rows = []
    for name in sorted(set(TARGET.findall(text))):
        if name.startswith("."):
            continue
        rows.append([
            mdx.md_code(name),
            "yes" if name in phony else "no",
        ])
    return mdx.render_table(["Target", "Phony"], rows) + "\n"


def _template() -> str:
    return """---
title: "Make install"
description: "Code-generated Makefile target reference for building and installing DefenseClaw."
order: 4
---

## Overview

Use this page as the current Makefile reference. The target table is generated from the repository `Makefile`.

## Reference

<!-- BEGIN AUTOGEN:make_targets:all -->
<!-- END AUTOGEN:make_targets:all -->

## Related

- [Build from source](/docs-site/installation/build-from-source)
- [Developer building](/docs-site/developer/building)

---

<!-- generated-from: Makefile -->
"""


def run() -> List[Tuple[str, bool]]:
    splice.ensure_scaffold(PAGE, _template())
    ch = splice.splice(PAGE, "make_targets", "all", _render_block())
    return [(str(PAGE), ch)]


if __name__ == "__main__":
    for p, ch in run():
        print(("CHANGED " if ch else "ok      ") + p)
