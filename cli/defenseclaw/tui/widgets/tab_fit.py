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
starts from the key letter alone and then gives tabs a short name, and then
their full name, in order of importance (``LABEL_PRIORITY``), stopping at the
first tab that no longer fits. The active tab always keeps its full name, every tab
keeps its key letter, and unread badges stay. PANELS order never changes.
"""

from __future__ import annotations

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
    "sandboxes",
    "logs",
    "audit",
    "inventory",
    "activity",
    "ai",
    "runtime",
    "registries",
)


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
    short = {name: _label(key, SHORT_LABELS.get(name, label), unread.get(name, 0)) for name, key, label in panels}
    labels = {name: full[name] if name == active else _label(key, "", unread.get(name, 0)) for name, key, _ in panels}
    # Upgrade the most useful tabs first, so the labels you see stay the same
    # as you move between panels instead of shifting with the active tab.
    names = [name for name, _key, _label in panels if name != active]
    ranked = sorted(names, key=lambda name: LABEL_PRIORITY.index(name) if name in LABEL_PRIORITY else len(names))
    # Stop at the first tab that doesn't fit, so a named tab is always more
    # important than every letter-only one.
    for tier in (short, full):
        for name in ranked:
            candidate = {**labels, name: tier[name]}
            if strip_width(tuple(candidate.values())) > width:
                break
            labels = candidate
    return labels


__all__ = ["LABEL_PRIORITY", "SHORT_LABELS", "TAB_GUTTER", "fit_tab_labels", "strip_width"]
