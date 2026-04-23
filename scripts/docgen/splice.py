# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""AUTOGEN sentinel splicer.

Finds ``<!-- BEGIN AUTOGEN:<generator>:<key> -->`` / ``<!-- END AUTOGEN:<generator>:<key> -->``
pairs in MDX files and replaces the content between them. If the file does not
exist, it is created from an optional ``template``.

See ``docs-site/_meta/AUTOGEN.md``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


HEADER_COMMENT = "<!-- Do not edit by hand. Regenerate with `make docs-gen`. -->"


class MissingSentinelError(RuntimeError):
    pass


def _begin(generator: str, key: str) -> str:
    return f"<!-- BEGIN AUTOGEN:{generator}:{key} -->"


def _end(generator: str, key: str) -> str:
    return f"<!-- END AUTOGEN:{generator}:{key} -->"


def splice(
    path: Path,
    generator: str,
    key: str,
    new_block: str,
    *,
    template: Optional[str] = None,
) -> bool:
    """Rewrite the AUTOGEN block at ``(generator, key)`` in ``path``.

    Returns True if the file changed on disk.
    """
    begin = _begin(generator, key)
    end = _end(generator, key)

    if not path.exists():
        if template is None:
            raise FileNotFoundError(f"{path} does not exist and no template provided")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(template, encoding="utf-8")

    text = path.read_text(encoding="utf-8")

    if begin not in text or end not in text:
        raise MissingSentinelError(
            f"{path}: missing sentinel pair for {generator}:{key}. "
            f"Expected {begin!r} / {end!r}"
        )

    pre, _, rest = text.partition(begin)
    old_between, _, post = rest.partition(end)

    body = new_block.strip("\n")
    new_between = f"\n{HEADER_COMMENT}\n\n{body}\n\n"
    new_text = f"{pre}{begin}{new_between}{end}{post}"

    if new_text == text:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def ensure_scaffold(path: Path, content: str) -> bool:
    """Create the file if missing; never overwrite an existing file."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True
