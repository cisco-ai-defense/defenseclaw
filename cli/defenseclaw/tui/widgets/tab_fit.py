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

Sixteen tabs with full names need about 180 columns. ``fit_tab_labels``
starts from the key letter alone and then gives tabs a short name, and then
their full name, in order of importance (``LABEL_PRIORITY``), stopping at the
first tab that no longer fits. That choice depends on the width only, so
labels stay put as you switch panels or badges change. The active tab always
shows its full name, every tab keeps its key letter, and unread badges stay
unless even letter-only tabs with badges overflow. PANELS order never changes.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

# Every Textual Tab has one cell of padding on each side.
TAB_GUTTER = 2

# Natural short names, used before a tab falls back to its full name. Tabs
# that aren't listed use their full label.
SHORT_LABELS: dict[str, str] = {
    "ai": "AI",
    "sandboxes": "Sandbox",
    "registries": "Registry",
}


# Which tabs get a readable name first when the strip is tight.
LABEL_PRIORITY: tuple[str, ...] = (
    "overview",
    "alerts",
    "policies",
    "setup",
    "skills",
    "mcps",
    "plugins",
    "tools",
    "sandboxes",
    "logs",
    "audit",
    "inventory",
    "activity",
    "ai",
    "runtime",
    "registries",
)


_SUPERSCRIPT = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")
# Windows console fonts lack most superscript digits and draw them as
# degree-like glyphs, so letter-only tabs there show a plain "8(3)" badge.
_PLAIN_BADGE = os.name == "nt"


def _label(key: str, name: str, unread: int) -> str:
    """``"2 Alerts (3)"``, or ``"2³"`` when ``name`` is empty.

    A letter-only tab shows its unread count as superscript digits, so the
    badge costs one cell per digit instead of ``"(3)"``'s three.
    """

    if not name:
        if not unread:
            return key
        return f"{key}({unread})" if _PLAIN_BADGE else f"{key}{str(unread).translate(_SUPERSCRIPT)}"
    return f"{key} {name} ({unread})" if unread else f"{key} {name}"


def strip_width(labels: Sequence[str]) -> int:
    return sum(len(label) + TAB_GUTTER for label in labels)


# Cells kept free when choosing which tabs get a name, so the names don't
# change as unread badges come and go (GAP-1155).
BADGE_RESERVE = 6


def fit_tab_labels(
    panels: Sequence[tuple[str, str, str]],
    active: str,
    unread: Mapping[str, int],
    width: int,
) -> dict[str, str]:
    """Label per panel name for a strip ``width`` cells wide.

    ``panels`` is the visible ``(name, key, label)`` rows in order. A width
    of 0 or less means "unknown" and returns full labels.

    Which tabs get a name depends only on the width (badges come out of a
    fixed reserve), so moving between panels or a new badge never renames
    another tab. The active tab shows its full name when the room left over
    allows it.
    """

    full = {name: _label(key, label, unread.get(name, 0)) for name, key, label in panels}
    if width <= 0 or strip_width(tuple(full.values())) <= width:
        return full
    keys = {name: key for name, key, _label in panels}
    plain_full = {name: _label(key, label, 0) for name, key, label in panels}
    plain_short = {name: _label(key, SHORT_LABELS.get(name, label), 0) for name, key, label in panels}
    ranked = sorted(
        (name for name, _key, _label in panels),
        key=lambda name: LABEL_PRIORITY.index(name) if name in LABEL_PRIORITY else len(LABEL_PRIORITY),
    )
    # 1. Names from the width alone. Stop at the first tab that doesn't fit,
    #    so a named tab is always more important than every letter-only one.
    budget = width - BADGE_RESERVE
    names = dict(keys)
    for tier in (plain_short, plain_full):
        for name in ranked:
            candidate = {**names, name: tier[name]}
            if strip_width(tuple(candidate.values())) > budget:
                break
            names = candidate
    # 2. Badges go on every tab.
    named = {name: names[name] != keys[name] for name in names}
    tier_label = {name: plain_full[name] == names[name] for name in names}
    labels: dict[str, str] = {}
    for name, key, label in panels:
        if tier_label[name]:
            labels[name] = _label(key, label, unread.get(name, 0))
        elif named[name]:
            labels[name] = _label(key, SHORT_LABELS.get(name, label), unread.get(name, 0))
        else:
            labels[name] = _label(key, "", unread.get(name, 0))
    # 3. The active tab gets its full name from the room that is left, so
    #    no other tab changes for it.
    if active in labels:
        key, label = keys[active], next(label for name, _key, label in panels if name == active)
        candidate = {**labels, active: _label(key, label, unread.get(active, 0))}
        if strip_width(tuple(candidate.values())) <= width:
            labels = candidate
    # 4. Only when the reserve is not enough (many large badges on a tiny
    #    terminal): drop the least important badges, then names.
    for name in reversed(ranked):
        if strip_width(tuple(labels.values())) <= width:
            return labels
        if name != active and unread.get(name, 0):
            labels[name] = names[name] if named[name] else keys[name]
    for name in reversed(ranked):
        if strip_width(tuple(labels.values())) <= width:
            break
        if name != active:
            labels[name] = keys[name]
    return labels


__all__ = ["BADGE_RESERVE", "LABEL_PRIORITY", "SHORT_LABELS", "TAB_GUTTER", "fit_tab_labels", "strip_width"]
