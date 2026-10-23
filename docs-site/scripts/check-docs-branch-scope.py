#!/usr/bin/env python3
"""Fail when a docs-only branch changes product files relative to its base."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def changed_paths(base: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", base, "--"],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    return [path.decode() for path in result.stdout.split(b"\0") if path]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-docs-branch-scope.py <base-commit>", file=sys.stderr)
        return 2
    forbidden = [
        path
        for path in changed_paths(sys.argv[1])
        if path != "CHANGELOG.md" and not path.startswith(("docs/", "docs-site/"))
    ]
    claims = (ROOT / "docs-site/scripts/test-docs-claims.ts").read_text(encoding="utf-8")
    compiled_product = "node:child_process" in claims or "execFileSync" in claims
    if forbidden or compiled_product:
        for path in forbidden:
            print(f"product path changed: {path}", file=sys.stderr)
        if compiled_product:
            print("docs-claims compiles product code", file=sys.stderr)
        return 1
    print("docs-only scope: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
