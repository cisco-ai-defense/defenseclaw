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

Wider than ``NARROW_STRIP`` (80 columns and up) every other tab keeps one
label whichever panel is open, so switching panels changes only the tab you
leave and the tab you open (GAP-2078). Below about 160 columns other tabs
give up their names before their unread counts (GAP-2077), and a tab stays a
bare key only when even its shortest name doesn't fit (GAP-2150, GAP-2180);
see ``_wide_labels``. Once every tab fits a name the names come from the
width alone, so a badge never blanks or renames another tab and a count
that doesn't fit waits (GAP-2301); see ``_every_tab_named``.
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

# One cell more, used only when even the tiny names, the dropped minor
# badges and the compact Alerts count leave the active tab short of its full
# name: "8 Log" reads better than three bare key letters (GAP-2086).
SINGULAR_LABELS: dict[str, str] = {
    "logs": "Log",
    "tools": "Tool",
    "plugins": "Plugin",
    "mcps": "MCP",
    "skills": "Skill",
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
    """``"2 Alerts (3)"``, or ``"2(3)"`` when ``name`` is empty.

    With ``compact`` the count is superscript digits (``"8 Logs²"``, ``"2³"``),
    so the badge costs one cell per digit instead of ``"(3)"``'s three. A
    letter-only tab uses that only when the brackets don't fit: superscript
    digits glued to a digit key read as an exponent ("2²²" for 22 alerts,
    GAP-2247).
    """

    count = _badge(unread)
    if not unread:
        return f"{key} {name}" if name else key
    small = f"({count})" if _PLAIN_BADGE or not compact else count.translate(_SUPERSCRIPT)
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

# Wider than NARROW_STRIP these most important tabs get a name first; the
# rest follow cheapest name first, so the most tabs get one (GAP-2180).
NAMED_FIRST = 3

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
    of 0 or less means "unknown" and returns full labels. Up to
    ``NARROW_STRIP`` cells the labels are fitted for the active tab
    (``_fit_for_active``). Wider strips, where other tabs keep one label
    whichever tab is open (GAP-2078), use ``_every_tab_named`` once every tab
    fits a name (about 160 columns) and ``_wide_labels`` below that.
    """

    names = [name for name, _key, _title in panels]
    if width <= NARROW_STRIP or active not in names or len(names) < 2:
        return _fit_for_active(panels, active, unread, width)
    full = {name: _label(key, label, unread.get(name, 0)) for name, key, label in panels}
    if strip_width(tuple(full.values())) <= width:
        return full
    # Cached: the strip is redrawn on every render.
    if (tuple(panels), width, _PLAIN_BADGE) not in _NAMES_CACHE:
        _remember(_NAMES_CACHE, (tuple(panels), width, _PLAIN_BADGE), _every_tab_named(panels, width))
    named = _NAMES_CACHE[(tuple(panels), width, _PLAIN_BADGE)]
    if named is not None:
        return _named_fit(panels, active, unread, width, named)
    key = (tuple(panels), tuple(unread.get(name, 0) for name in names), width, _PLAIN_BADGE)
    stable = _WIDE_CACHE.get(key)
    if stable is None:
        stable = _wide_labels(panels, unread, width)
        _remember(_WIDE_CACHE, key, stable)
    others, actives = stable
    return {**others, active: actives[active]}


def _remember(cache: dict[tuple[object, ...], object], key: tuple[object, ...], value: object) -> None:
    if len(cache) >= 64:
        cache.clear()
    cache[key] = value


def _rank(name: str) -> int:
    return LABEL_PRIORITY.index(name) if name in LABEL_PRIORITY else len(LABEL_PRIORITY)


def _shortest(name: str, label: str) -> str:
    """The shortest readable name of one tab ("Log", "Inv")."""

    tiny = _names(name, label)[0]
    fewer = SINGULAR_LABELS.get(name, "")
    return fewer if fewer and len(fewer) < len(tiny) else tiny


def _wide_labels(
    panels: Sequence[tuple[str, str, str]],
    unread: Mapping[str, int],
    width: int,
) -> tuple[dict[str, str], dict[str, str]]:
    """``(others, actives)`` for a strip wider than ``NARROW_STRIP``.

    ``others`` is each tab's label while another tab is open and ``actives``
    its label while it is open, so switching panels changes only the tab you
    leave and the tab you open (GAP-2078). Counts are compact ("8 Logs⁶⁴",
    "8(64)"). Labels grow in this order, and a step is kept only while the
    strip still fits with any tab open under its full name:

    1. every unread count: other tabs give up their names before their
       counts (GAP-2077); only if even bare keys overflow do the least
       important counts go, never the Alerts count;
    2. each tab's shortest name ("Log", "Inv"): Overview, Alerts and
       Policies first, then the cheapest names, so as many tabs as fit get
       one (GAP-2150, GAP-2180). The order doesn't depend on the width, so a
       wider strip never names fewer tabs;
    3. the tiny, short and full names, most important first.

    Keeping one label per tab costs room: the strip keeps enough free for
    the longest full name ("V AI Discovery"), so a panel with a short name
    shows those cells free while the least important tabs are bare keys
    (GAP-2179).

    The open tab shows its full name, or the longest "Regis…" that fits.
    """

    keys = {name: key for name, key, _title in panels}
    titles = {name: title for name, _key, title in panels}
    ranked = sorted(keys, key=_rank)
    counted = {name for name in keys if unread.get(name, 0)}

    def label(name: str, text: str) -> str:
        # Named tabs take superscript counts ("8 Logs⁶⁴"); bare keys keep
        # brackets ("8(64)"), as "2²²" reads as an exponent (GAP-2247).
        return _label(keys[name], text, unread.get(name, 0) if name in counted else 0, bool(text))

    def cost(chosen: Mapping[str, str]) -> int:
        labels = {name: label(name, chosen[name]) for name in keys}
        reserve = max(len(label(name, titles[name])) - len(labels[name]) for name in keys)
        return strip_width(tuple(labels.values())) + reserve

    chosen = dict.fromkeys(keys, "")
    for name in reversed(ranked):
        if cost(chosen) <= width:
            break
        if name not in KEEP_BADGE:
            counted.discard(name)

    def grow(name: str, text: str) -> bool:
        before = chosen[name]
        if len(text) > len(before):
            chosen[name] = text
            if cost(chosen) > width:
                chosen[name] = before
                return False
        return True

    # Names wait until every count shows, so cells freed by a dropped count
    # never name a tab that a wider strip would leave bare again.
    if counted == {name for name in keys if unread.get(name, 0)}:
        order = [
            *ranked[:NAMED_FIRST],
            *sorted(ranked[NAMED_FIRST:], key=lambda name: len(_shortest(name, titles[name]))),
        ]
        for name in order:
            if not grow(name, _shortest(name, titles[name])):
                break
    for tier in range(3):
        for name in ranked:
            if chosen[name]:
                grow(name, _names(name, titles[name])[tier])
    others = {name: label(name, chosen[name]) for name in keys}
    used = strip_width(tuple(others.values()))
    actives: dict[str, str] = {}
    for name in keys:
        room = width - used + len(others[name])
        title = titles[name]
        wants = [title] + [f"{title[:n].rstrip()}\u2026" for n in range(len(title) - 1, 1, -1)]
        texts = (label(name, want) for want in wants)
        actives[name] = next((text for text in texts if len(others[name]) < len(text) <= room), others[name])
    return others, actives


def _every_tab_named(panels: Sequence[tuple[str, str, str]], width: int) -> dict[str, str] | None:
    """Each tab's name when every tab fits one beside a one-digit Alerts count, else None.

    From about 160 columns every tab keeps a name, so the names come from
    the width alone: a badge coming or going never blanks or renames another
    tab ("4 MCP  5 Plugin" became "4 MCPs  5", GAP-2301). The strip keeps
    room for the longest full name ("V AI Discovery"), so with few counts any
    tab opens under its full name. Every tab gets its shortest name ("Log",
    "Inv"), then the tiny, short and full names grow, most important first,
    while ``BADGE_RESERVE`` cells stay free for the counts.
    """

    keys = {name: key for name, key, _title in panels}
    titles = {name: title for name, _key, title in panels}
    chosen = {name: _shortest(name, titles[name]) for name in keys}

    def cost() -> int:
        labels = {name: _label(keys[name], chosen[name], 0) for name in keys}
        reserve = max(len(_label(keys[name], titles[name], 0)) - len(labels[name]) for name in keys)
        alerts = (
            len(_label(keys["alerts"], chosen["alerts"], 1, True)) - len(labels["alerts"]) if "alerts" in keys else 0
        )
        return strip_width(tuple(labels.values())) + reserve + alerts

    if cost() > width:
        return None
    for tier in range(3):
        for name in sorted(keys, key=_rank):
            before = chosen[name]
            chosen[name] = max(before, _names(name, titles[name])[tier], key=len)
            if cost() + BADGE_RESERVE > width:
                chosen[name] = before
    return chosen


def _named_fit(
    panels: Sequence[tuple[str, str, str]],
    active: str,
    unread: Mapping[str, int],
    width: int,
    named: Mapping[str, str],
) -> dict[str, str]:
    """Labels for the open ``active`` tab over the names in ``named``.

    Counts are compact ("8 Logs⁶⁴"). The Alerts count always shows; the
    other counts take the cells the names leave free, most important tab
    first, Logs and Audit before the rest. Only the Alerts, Logs and Audit
    counts may take the room kept for a long open name (GAP-2077); every
    other count takes room only while every tab still opens under its full
    name: an Activity count (GAP-2372), and Skills, MCPs and Plugins counts
    beside a Logs and Audit backlog (GAP-2403), turned the open
    "R Registries" into "R Registri…". A count that doesn't fit waits; it
    never costs a name. The counts don't depend on the open tab, so switching
    panels never relabels a third tab. The open tab reads in full, or
    "V AI Disco…" when the Alerts, Logs or Audit count took that room: it is
    the one label that may change, and its panel title names it.
    """

    keys = {name: key for name, key, _title in panels}
    titles = {name: title for name, _key, title in panels}

    def render(texts: Mapping[str, str], shown: set[str]) -> dict[str, str]:
        return {
            name: _label(keys[name], texts[name], unread.get(name, 0) if name in shown else 0, True) for name in keys
        }

    # The longest full name of an open tab, and one cell for the "…" of a
    # shortened one (GAP-1541).
    reserve = max(len(titles[name]) - len(named[name]) for name in keys)
    spare = 1 if reserve else 0
    shown: set[str] = set()
    for name in sorted(
        (name for name in keys if unread.get(name, 0)),
        key=lambda name: (name != "alerts", name not in _OPEN_NAME_COUNTS, _rank(name)),
    ):
        room = spare if name in _OPEN_NAME_COUNTS else reserve
        if name == "alerts" or strip_width(tuple(render(named, shown | {name}).values())) + room <= width:
            shown.add(name)
    title = titles[active]
    wants = [title] + [f"{title[:n].rstrip()}…" for n in range(len(title) - 1, 1, -1)]
    for want in [want for want in wants if len(want) > len(named[active])] + [named[active]]:
        labels = render({**named, active: want}, shown)
        if strip_width(tuple(labels.values())) <= width:
            return labels
    return render(named, shown - {"alerts"})


# The counts that may shorten the open tab's name (GAP-2077, GAP-2403).
_OPEN_NAME_COUNTS = frozenset({"alerts", "logs", "audit"})
_WIDE_CACHE: dict[tuple[object, ...], tuple[dict[str, str], dict[str, str]]] = {}
_NAMES_CACHE: dict[tuple[object, ...], dict[str, str] | None] = {}


def _fit_for_active(
    panels: Sequence[tuple[str, str, str]],
    active: str,
    unread: Mapping[str, int],
    width: int,
) -> dict[str, str]:
    """Label per panel name for a strip ``width`` cells wide with ``active`` open.

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
        # A bare key's count stays in brackets ("9(1)", not "9¹"); only the
        # Alerts count goes superscript, and only when nothing else fits
        # (GAP-2247).
        return {
            name: _label(
                keys[name],
                chosen[name],
                unread.get(name, 0) if badges and name not in no_badge else 0,
                name in compact and (bool(chosen[name]) or name in KEEP_BADGE),
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
            done = done or room(trial, alerts=True)
            for name in reversed(ranked):
                fewer = SINGULAR_LABELS.get(name, "")
                if not done and name != active and fewer and len(fewer) < len(trial[name]):
                    trial[name] = fewer
                    done = room(trial, alerts=True)
            if done:
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
    # 7. A bare Alerts key keeps its count in brackets ("2(22)") on every
    #    panel, as on Overview: other tabs give up their names first, and
    #    "2²²", which reads as an exponent, is left only when even bare keys
    #    don't fit (GAP-2247, GAP-2301).
    if "alerts" in compact and "alerts" in keys and not chosen["alerts"]:
        compact.discard("alerts")
        trial = dict(chosen)
        for name in reversed(ranked):
            if width_of(trial) <= width:
                break
            if name != active:
                trial[name] = ""
        if width_of(trial) <= width:
            chosen = trial
        else:
            compact.add("alerts")
    # 8. Counts dropped or shrunk to make room for a name that later went
    #    (step 7 frees cells) come back while they fit, most important tab
    #    first: "0 Setup" showed a bare "8" with 8 cells free (GAP-2342).
    #    A dropped count takes other tabs' names, least important first,
    #    when that is the only way it fits (GAP-2077): Skills read
    #    "1 Overview ... A" where "1 ... A(1)" fits. The open tab keeps its
    #    name.
    for name in ranked:
        for shrunk in (no_badge, compact):
            if name in shrunk and unread.get(name, 0):
                shrunk.discard(name)
                trial = dict(chosen)
                for other in reversed(ranked) if shrunk is no_badge else ():
                    if width_of(trial) <= width:
                        break
                    if other != active:
                        trial[other] = ""
                if width_of(trial) <= width:
                    chosen = trial
                else:
                    shrunk.add(name)
    return render(chosen)


__all__ = [
    "BADGE_MAX",
    "BADGE_RESERVE",
    "LABEL_PRIORITY",
    "SHORT_LABELS",
    "SINGULAR_LABELS",
    "TAB_GUTTER",
    "TINY_LABELS",
    "fit_tab_labels",
    "strip_width",
]
