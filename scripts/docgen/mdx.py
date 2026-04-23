# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""MDX helpers: table rendering, callout rendering, text sanitization."""

from __future__ import annotations

from typing import Iterable, Sequence


def escape_pipe(s: str) -> str:
    """Escape pipe characters for GFM tables without destroying literal backslashes."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def md_code(s: str) -> str:
    """Wrap short code span in backticks, escaping any embedded backticks."""
    s = s.replace("`", "'")
    return f"`{s}`" if s else "—"


def render_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    """Render a GFM table. Caller is responsible for cell-escaping with ``escape_pipe``."""
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    n = 0
    for row in rows:
        cells = [c if c is not None else "" for c in row]
        out.append("| " + " | ".join(cells) + " |")
        n += 1
    if n == 0:
        out.append("| " + " | ".join(["—"] * len(headers)) + " |")
    return "\n".join(out)


def callout(kind: str, title: str, body: str) -> str:
    """Render a ``<Callout>`` block. ``kind`` ∈ {tip,info,warning,danger}."""
    if kind not in {"tip", "info", "warning", "danger"}:
        raise ValueError(f"invalid callout kind: {kind!r}")
    title_attr = f' title="{title}"' if title else ""
    return f"<Callout type=\"{kind}\"{title_attr}>\n  {body}\n</Callout>"


def code_fence(lang: str, body: str) -> str:
    return f"```{lang}\n{body.rstrip()}\n```"
