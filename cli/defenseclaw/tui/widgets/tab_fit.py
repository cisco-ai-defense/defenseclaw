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
starts from the key letter alone and then gives tabs a tiny name ("Inv"),
a short name and then their full name, in order of importance
(``LABEL_PRIORITY``), stopping at the first tab that no longer fits. That choice depends on the width only, so
labels stay put as you switch panels or badges change. The active tab always
shows its full name, every tab keeps its key letter, and unread badges stay
unless even letter-only tabs with badges overflow. PANELS order never changes.
Badges show the real count up to 999 and "999+" above that.
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

# The shortest readable names, which every tab gets before any tab gets its
# short name, so at 160 columns no tab is a bare key letter (GAP-1544).
# Tabs that aren't listed use their short name.
TINY_LABELS: dict[str, str] = {
    "inventory": "Inv",
    "sandboxes": "Sbox",
    "activity": "Act",
    "runtime": "Run",
    "registries": "Reg",
    "policies": "Policy",
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


_SUPERSCRIPT = str.maketrans("0123456789+", "⁰¹²³⁴⁵⁶⁷⁸⁹⁺")
# Windows console fonts lack most superscript digits and draw them as
# degree-like glyphs, so letter-only tabs there show a plain "8(3)" badge.
_PLAIN_BADGE = os.name == "nt"


def _label(key: str, name: str, unread: int, compact: bool = False) -> str:
    """``"2 Alerts (3)"``, or ``"2³"`` when ``name`` is empty.

    A letter-only tab shows its unread count as superscript digits, so the
    badge costs one cell per digit instead of ``"(3)"``'s three. A named tab
    does the same when ``compact`` (``"8 Logs²"``).
    """

    count = _badge(unread)
    if not unread:
        return f"{key} {name}" if name else key
    small = f"({count})" if _PLAIN_BADGE else count.translate(_SUPERSCRIPT)
    if not name:
        return f"{key}{small}"
    return f"{key} {name}{small}" if compact else f"{key} {name} ({count})"


# Badges show the real count, so the Alerts tab reads the same number as
# Overview and the status bar (GAP-0978); only very large counts are capped,
# and then visibly ("999+"), never silently.
BADGE_MAX = 999


def _badge(unread: int) -> str:
    return f"{BADGE_MAX}+" if unread > BADGE_MAX else str(unread)


def strip_width(labels: Sequence[str]) -> int:
    return sum(len(label) + TAB_GUTTER for label in labels)


# Badges shortened or dropped only after every other tab's.
KEEP_BADGE = frozenset({"alerts"})

# Strip cells at an 80-column terminal (80 less the header padding and the
# ":" and "?" buttons). Narrower strips give the active tab's name priority
# over the other tabs' minor badges (GAP-1998).
NARROW_STRIP = 66

# Cells kept free when choosing which tabs get a name, so the names don't
# change as unread badges come and go (GAP-1155).
BADGE_RESERVE = 6


def _names(name: str, label: str) -> tuple[str, str, str]:
    """The tiny, short and full name of one tab."""

    short = SHORT_LABELS.get(name, label)
    return TINY_LABELS.get(name, short), short, label


def _abbreviated(text: str, label: str) -> str:
    """``text`` with a trailing "…" when it is a shortened ``label``."""

    return text if text == label else f"{text}\u2026"


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
    allows it, and a shortened active name ends with "…" (GAP-1541).
    """

    full = {name: _label(key, label, unread.get(name, 0)) for name, key, label in panels}
    if width <= 0 or strip_width(tuple(full.values())) <= width:
        return full
    keys = {name: key for name, key, _label in panels}
    titles = {name: label for name, _key, label in panels}
    ranked = sorted(
        keys,
        key=lambda name: LABEL_PRIORITY.index(name) if name in LABEL_PRIORITY else len(LABEL_PRIORITY),
    )
    no_badge: set[str] = set()
    compact: set[str] = set()

    def render(chosen: Mapping[str, str], badges: bool = True) -> dict[str, str]:
        return {
            name: _label(
                keys[name],
                chosen[name],
                unread.get(name, 0) if badges and name not in no_badge else 0,
                name in compact,
            )
            for name in keys
        }

    def width_of(chosen: Mapping[str, str], badges: bool = True) -> int:
        return strip_width(tuple(render(chosen, badges).values()))

    def _squeeze(candidate: dict[str, str]) -> tuple[int, dict[str, str], set[str]] | None:
        """Fit ``candidate`` by naming fewer other tabs, then dropping badges."""

        candidate = dict(candidate)
        cost = 0
        for name in reversed(ranked):
            if width_of(candidate) <= width:
                break
            if name != active and candidate[name]:
                candidate[name] = ""
                cost += 1
        # Large badges (Windows draws them as "8(99)") can still leave no
        # room: the active tab's name beats the badges of the least
        # important other tabs, or it showed a bare key (GAP-1457).
        dropped: set[str] = set()
        for name in reversed(ranked):
            if width_of(candidate) <= width:
                break
            if name != active and unread.get(name, 0):
                no_badge.add(name)
                dropped.add(name)
                cost += 1
        fits = width_of(candidate) <= width
        no_badge.difference_update(dropped)
        return (cost, candidate, dropped) if fits else None

    # 1. Names from the width alone: every tab first gets its tiny name
    #    ("Inv", "Run"; GAP-1544), then its short and full name, in order of
    #    importance. Stop at the first tab that doesn't fit, so a named tab
    #    is always more important than every letter-only one.
    budget = width - BADGE_RESERVE
    chosen = dict.fromkeys(keys, "")
    for tier in range(3):
        for name in ranked:
            candidate = {**chosen, name: _names(name, titles[name])[tier]}
            if width_of(candidate, badges=False) > budget:
                break
            chosen = candidate
    named = {name for name in keys if chosen[name]}

    def fit_badges(chosen: Mapping[str, str], steps: Sequence[tuple[set[str], bool]]) -> bool:
        for shrink, kept in steps:
            for name in reversed(ranked):
                if width_of(chosen) <= width:
                    return True
                if name != active and unread.get(name, 0) and (name in KEEP_BADGE) == kept:
                    shrink.add(name)
        return width_of(chosen) <= width

    def longest_active_name(chosen: dict[str, str]) -> dict[str, str]:
        """6. Below 80 columns the active tab reads as much of its name as fits.

        The steps above could leave "R Reg…" there while the Logs badge
        stayed, or drop the Alerts count for "R Reg" (GAP-1998). Try the full
        name, then ever shorter "Regis…" prefixes; for each, shrink and then
        drop the other tabs' minor badges, then drop their names, and last
        shrink (never drop) the Alerts count. The first that fits wins. From
        80 columns up this only runs when the active tab has no name or the
        Alerts count was dropped.
        """

        title = titles[active]
        alerts_badge = "alerts" in keys and active != "alerts" and unread.get("alerts", 0) > 0
        intact = bool(chosen[active]) and not (alerts_badge and "alerts" in no_badge)
        if intact and (chosen[active] == title or width >= NARROW_STRIP):
            return chosen
        saved = (set(compact), set(no_badge))
        minor = [n for n in reversed(ranked) if n not in {active, "alerts"} and unread.get(n, 0)]
        wants = [title] + [f"{title[:n].rstrip()}…" for n in range(len(title) - 2, 1, -1)]
        for want in dict.fromkeys(wants):
            compact.clear()
            compact.update(saved[0])
            no_badge.clear()
            no_badge.update(saved[1] - {"alerts"})
            trial = {**chosen, active: want}
            for shrink in (compact, no_badge):
                for name in minor:
                    if width_of(trial) <= width:
                        break
                    shrink.add(name)
            for name in reversed(ranked):
                if width_of(trial) <= width:
                    break
                if name != active:
                    trial[name] = ""
            if alerts_badge and width_of(trial) > width:
                compact.add("alerts")
            if width_of(trial) <= width:
                return trial
        # No room for any name (about 66 columns and less): every tab is a key
        # letter, and the panel title names the active panel. The Alerts
        # count stays whenever it fits.
        trial = dict.fromkeys(keys, "")
        compact.update(name for name in keys if unread.get(name, 0))
        no_badge.clear()
        no_badge.update(saved[1] - {"alerts"})
        for name in [*minor, "alerts"]:
            if width_of(trial) <= width:
                break
            no_badge.add(name)
        return trial

    # 2. Badges go on every tab. 3. The active tab always shows a name. It
    #    takes its full (or a shortened) name from the room that is left, so
    #    no other tab changes for it; only when it has no name at all do the
    #    least important other tabs fall back to their key letter (GAP-1327:
    #    "A" alone on Activity).
    if active in keys:
        title = titles[active]
        short = _names(active, title)[1]
        wanted = list(dict.fromkeys((title, _abbreviated(short, title), short)))
        if width_of({**chosen, active: title}) > width:
            # The tab you are on reads in full before other tabs keep their
            # least important badges: "R Registry…" showed on a 200-column
            # screen for want of one cell (GAP-1751). Alerts keeps its count.
            saved = (set(compact), set(no_badge))
            if fit_badges({**chosen, active: title}, ((compact, False), (no_badge, False))):
                chosen = {**chosen, active: title}
            else:
                compact.clear()
                compact.update(saved[0])
                no_badge.clear()
                no_badge.update(saved[1])
        if chosen[active] != title and width >= NARROW_STRIP:
            # Still short of its full name: the least important other tabs
            # take their shorter names ("Policy", then "Inv"), then the Alerts
            # count its compact form, and only then do tabs lose their name.
            # So a wider strip never reads "R Reg\u2026" where a narrower one
            # reads "R Registries" (GAP-2020), and no tab is a bare letter
            # at 160 columns (GAP-1544).
            saved = (set(compact), set(no_badge))

            def room(trial: dict[str, str], alerts: bool = False) -> bool:
                steps = [(compact, False), (no_badge, False)] + ([(compact, True)] if alerts else [])
                if fit_badges(trial, steps):
                    return True
                compact.clear()
                compact.update(saved[0])
                no_badge.clear()
                no_badge.update(saved[1])
                return False

            trial = {**chosen, active: title}
            done = room(trial)
            for tier in (1, 0):
                for name in reversed(ranked):
                    shorter = _names(name, titles[name])[tier]
                    if not done and name != active and trial[name] and len(shorter) < len(trial[name]):
                        trial[name] = shorter
                        done = room(trial)
            if done or room(trial, alerts=True):
                chosen = trial
            else:
                squeezed = _squeeze({**chosen, active: title})
                if squeezed is not None and not KEEP_BADGE & squeezed[2]:
                    chosen = squeezed[1]
                    no_badge.update(squeezed[2])
        if chosen[active] == title:
            wanted = [title]
        elif chosen[active]:
            # Never trade a name for a shorter one; keep the plain
            # abbreviation when even its "…" doesn't fit.
            current = chosen[active]
            wanted = [text for text in wanted if len(text) > len(current)]
            wanted += list(dict.fromkeys((_abbreviated(current, title), current)))
        for want in wanted:
            candidate = {**chosen, active: want}
            if width_of(candidate) <= width:
                chosen = candidate
                break
        else:
            if active not in named:
                # The full name first when other tabs' names and minor badges
                # make room for it and the Alerts count stays ("R Registry…"
                # with room left at 80 columns, GAP-1751). Then prefer
                # "Sandbox…"; keep plain "Sandbox" when the "…" would cost
                # another tab its name.
                tiny, short, _title = _names(active, title)
                best: tuple[int, dict[str, str], set[str]] | None = _squeeze({**chosen, active: title})
                if best is not None and KEEP_BADGE & best[2]:
                    best = None
                for name_text in dict.fromkeys((short, tiny)) if best is None else ():
                    for want in dict.fromkeys((_abbreviated(name_text, title), name_text)):
                        squeezed = _squeeze({**chosen, active: want})
                        if squeezed is not None and (best is None or squeezed[0] < best[0]):
                            best = squeezed
                    if best is not None:
                        break
                if best is not None:
                    chosen = best[1]
                    no_badge.update(best[2])
    # 4. Only when the reserve is not enough (many badges): shrink the least
    #    important badges to superscript ("8 Logs²"), then drop them, then
    #    names. The Alerts count goes last: it is the open-alert count that
    #    Overview and the status bar show.
    if not fit_badges(chosen, ((compact, False), (no_badge, False), (compact, True), (no_badge, True))):
        for name in reversed(ranked):
            if width_of(chosen) <= width:
                break
            if name != active:
                chosen[name] = ""
    # 5. A shortened active name always ends with "…": shrink or drop other
    #    tabs' badges for it (never the Alerts count), so "7 Sandbox" is never
    #    shown as if it were the full name while Logs/Audit badges are up
    #    (GAP-1541).
    #    When no badge is left to give, use the tiny name ("Reg…") and, last,
    #    the least important other tabs' names.
    current = chosen.get(active, "")
    if current and current != titles[active] and not current.endswith("\u2026"):
        saved = (set(compact), set(no_badge))
        tiny = _names(active, titles[active])[0]
        for text in dict.fromkeys((current, tiny)):
            candidate = {**chosen, active: _abbreviated(text, titles[active])}
            if fit_badges(candidate, ((compact, False), (no_badge, False), (compact, True))):
                chosen = candidate
                break
            compact.clear()
            compact.update(saved[0])
            no_badge.clear()
            no_badge.update(saved[1])
        else:
            candidate = {**chosen, active: _abbreviated(current, titles[active])}
            for name in reversed(ranked):
                if width_of(candidate) <= width:
                    break
                if name != active:
                    candidate[name] = ""
            chosen = candidate
    if active in keys:
        chosen = longest_active_name(chosen)
    return render(chosen)


__all__ = [
    "BADGE_MAX",
    "BADGE_RESERVE",
    "LABEL_PRIORITY",
    "SHORT_LABELS",
    "TAB_GUTTER",
    "TINY_LABELS",
    "fit_tab_labels",
    "strip_width",
]
