#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Walk all MDX under docs-site/ and verify every internal link resolves.

Covers:
  - Markdown links: [text](/docs-site/foo/bar)
  - Markdown links: [text](../bar), [text](./bar), [text](bar)
  - Anchor fragments: /docs-site/foo/bar#anchor-x → ignored (page existence only)

Exit code 0 on success; non-zero with a list of broken targets otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple


LINK = re.compile(r"\[([^\]]+)\]\((/[^)]+|\.{1,2}/[^)]+|[a-z][^)/: \t]*)\)", re.IGNORECASE)


def _candidate_files(target: str, page: Path) -> List[Path]:
    """Compute possible filesystem paths for a link target."""
    t = target.split("#", 1)[0]
    if t.startswith("/docs-site/"):
        rel = Path(t[len("/docs-site/"):])
        base = Path("docs-site")
    elif t.startswith("../") or t.startswith("./"):
        base = page.parent
        rel = Path(t)
        rel = (base / rel).resolve()
        base = rel.parent
        rel = Path(rel.name)
    else:
        # Bare (e.g. "troubleshooting" → sibling page)
        base = page.parent
        rel = Path(t)
    candidates = [
        base / rel if isinstance(rel, Path) and not rel.is_absolute() else Path(rel),
    ]
    # Add .mdx + /index.mdx variants
    stem = candidates[0]
    return [stem, stem.with_suffix(".mdx"), stem / "index.mdx"]


def _is_external(target: str) -> bool:
    return (
        target.startswith("http://")
        or target.startswith("https://")
        or target.startswith("mailto:")
        or target.startswith("tel:")
    )


def walk(root: Path) -> Iterable[Tuple[Path, str, str]]:
    for mdx in root.rglob("*.mdx"):
        text = mdx.read_text(encoding="utf-8")
        for m in LINK.finditer(text):
            label, target = m.group(1), m.group(2)
            if _is_external(target):
                continue
            yield mdx, label, target


def check(root: Path) -> int:
    broken: List[Tuple[str, str]] = []
    total = 0
    for page, _label, target in walk(root):
        total += 1
        if target.startswith("#"):
            continue  # in-page anchor
        candidates = _candidate_files(target, page)
        if not any(c.exists() for c in candidates):
            broken.append((str(page), target))
    if broken:
        print(f"BROKEN links: {len(broken)} of {total}")
        for page, target in broken:
            print(f"  {page} → {target}")
        return 1
    print(f"OK: {total} internal links verified under {root}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path, default=Path("docs-site"), nargs="?")
    args = ap.parse_args()
    return check(args.root)


if __name__ == "__main__":
    sys.exit(main())
