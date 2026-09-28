# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Fit the top tab strip into the terminal width.

Fifteen tabs with full names need about 170 columns. ``fit_tab_labels``
picks the richest labelling that fits: full names, then short names, then
the key letter alone. The active tab always keeps its full name, every tab
keeps its key letter, and unread badges stay. PANELS order never changes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# Every Textual Tab has one cell of padding on each side.
TAB_GUTTER = 2

SHORT_LABELS: dict[str, str] = {
    "overview": "Over",
    "alerts": "Alerts",
    "skills": "Skills",
    "mcps": "MCPs",
    "plugins": "Plug",
    "inventory": "Inv",
    "sandboxes": "Sbox",
    "logs": "Logs",
    "audit": "Audit",
    "activity": "Act",
    "ai": "AI",
    "runtime": "Run",
    "registries": "Reg",
    "policies": "Pol",
    "setup": "Setup",
}


def _label(key: str, name: str, unread: int) -> str:
    """``"2 Alerts (3)"``, or ``"2(3)"`` when ``name`` is empty."""

    if not name:
        return f"{key}({unread})" if unread else key
    return f"{key} {name} ({unread})" if unread else f"{key} {name}"


def strip_width(labels: Sequence[str]) -> int:
    return sum(len(label) + TAB_GUTTER for label in labels)


def fit_tab_labels(
    panels: Sequence[tuple[str, str, str]],
    active: str,
    unread: Mapping[str, int],
    width: int,
) -> dict[str, str]:
    """Label per panel name for a strip ``width`` cells wide.

    ``panels`` is the visible ``(name, key, label)`` rows in order. A width
    of 0 or less means "unknown" and returns full labels.
    """

    full = {name: _label(key, label, unread.get(name, 0)) for name, key, label in panels}
    if width <= 0 or strip_width(tuple(full.values())) <= width:
        return full
    short = {
        name: full[name] if name == active else _label(key, SHORT_LABELS.get(name, label[:4]), unread.get(name, 0))
        for name, key, label in panels
    }
    if strip_width(tuple(short.values())) <= width:
        return short
    return {
        name: full[name] if name == active else _label(key, "", unread.get(name, 0)) for name, key, _label_ in panels
    }


__all__ = ["SHORT_LABELS", "TAB_GUTTER", "fit_tab_labels", "strip_width"]
