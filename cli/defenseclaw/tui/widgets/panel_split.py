# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A navigation list left of the shared panel table and a detail pane right of it.

Every panel renders into one shared surface. ``DefenseClawTUI.compose`` wraps
the shared table area in ``Horizontal(#panel-split)``:

    #panel-nav (PanelNav, ~24 cols) | #panel-main (#panel-table, #detail-panel) | #panel-aside (~40%)

A panel opts in through three app hooks (if-chains like the rest of app.py):

* ``_panel_nav(panel) -> tuple[NavItem, ...]``: the panel's views or groups,
  empty for no nav. Shown at ``NAV_MIN_WIDTH`` columns and wider; narrower
  terminals use the panel's own one-line switcher in ``#body``
  (``nav_switcher`` builds one from the same items).
* ``_panel_aside(panel) -> RenderableType | None``: detail for the selected
  row, None for no aside. Shown right of the table at ``ASIDE_MIN_WIDTH``
  columns and wider; narrower terminals show the same content in
  ``#detail-panel`` below the table (when ``_detail_text()`` has nothing of
  its own). Return ``Aside(title, body)`` to give the pane a title.
* ``_select_panel_nav(panel, key) -> bool``: a nav item (or switcher
  segment) was clicked; ``key`` is the item's ``NavItem.key``. Panels call it
  from their own keys too, so a click and a key do the same thing.

The hooks run on every render (the 2 s refresh too), so they must be pure
and cheap. Everything here is pure except ``PanelNav``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from rich.console import Console, ConsoleOptions, RenderableType, RenderResult
from rich.markup import escape
from rich.text import Text
from textual import events
from textual.message import Message
from textual.widgets import Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS

# Terminal columns from which the nav list / right-hand aside are shown.
NAV_MIN_WIDTH = 100
ASIDE_MIN_WIDTH = 120
# #panel-nav is 24 columns wide: a round border and one column of padding
# each side leave 20 for the items (keep in sync with the app CSS).
NAV_WIDTH = 24
NAV_CONTENT_WIDTH = NAV_WIDTH - 4

_ACTIVE_MARKER = "▸ "
_MARKER_WIDTH = len(_ACTIVE_MARKER)
_SWITCHER_SEPARATOR = " · "


@dataclass(frozen=True)
class NavItem:
    """One entry of a panel's navigation list.

    ``key`` is handed back to ``_select_panel_nav`` when the item is chosen.
    ``badge`` is drawn right-aligned in muted text; a ``!`` in it is drawn as
    an attention mark. Consecutive items that share a non-empty ``group`` sit
    under one group heading. One item should be ``active``.
    """

    key: str
    label: str
    badge: str = ""
    active: bool = False
    group: str = ""


@dataclass(frozen=True)
class SplitLayout:
    """Which parts of the split are on screen at a given width."""

    nav: bool = False
    aside: bool = False
    aside_below: bool = False


def split_layout(width: int, *, has_nav: bool, has_aside: bool) -> SplitLayout:
    """Width rules: nav from ``NAV_MIN_WIDTH``, aside from ``ASIDE_MIN_WIDTH``.

    An aside that doesn't fit on the right goes below the table instead.
    ``width`` 0 (not laid out yet) counts as narrow.
    """

    aside = has_aside and width >= ASIDE_MIN_WIDTH
    return SplitLayout(
        nav=has_nav and width >= NAV_MIN_WIDTH,
        aside=aside,
        aside_below=has_aside and not aside,
    )


def active_item(items: Sequence[NavItem]) -> NavItem | None:
    return next((item for item in items if item.active), None)


def step_nav(items: Sequence[NavItem], delta: int, *, wrap: bool = True) -> str | None:
    """Key of the item ``delta`` steps from the active one (keyboard helper)."""

    if not items:
        return None
    index = next((i for i, item in enumerate(items) if item.active), 0) + delta
    if wrap:
        return items[index % len(items)].key
    return items[max(0, min(index, len(items) - 1))].key


@dataclass(frozen=True)
class Aside:
    """Detail content with a title; the pane shows ``title`` in its border."""

    title: str
    body: RenderableType

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield Text(self.title, style=f"bold {TOKENS.accent_violet}")
        yield self.body


def split_aside(content: RenderableType) -> tuple[str, RenderableType]:
    """``(title, body)`` for a pane; plain renderables have no title."""

    if isinstance(content, Aside):
        return content.title, content.body
    return "", content


# --- nav list ---------------------------------------------------------------


@dataclass(frozen=True)
class NavLine:
    """One drawn line of the nav list; ``key`` is None for headings and markers."""

    text: Text
    key: str | None = None


def _clip(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    return value[: width - 1] + "…" if width > 1 else value[:width]


def _badge_text(badge: str) -> Text:
    text = Text()
    for char in badge:
        if char == "!":
            text.append(char, style=f"bold {TOKENS.accent_amber}")
        else:
            text.append(char, style=TOKENS.text_muted)
    return text


def _item_line(item: NavItem, width: int) -> NavLine:
    badge = item.badge.strip()
    room = width - _MARKER_WIDTH - (len(badge) + 1 if badge else 0)
    label = _clip(" ".join(item.label.split()), max(1, room))
    line = Text(no_wrap=True, overflow="crop")
    if item.active:
        line.append(_ACTIVE_MARKER, style=f"bold {TOKENS.accent_cyan}")
        line.append(label, style=f"bold {TOKENS.accent_cyan}")
    else:
        line.append(" " * _MARKER_WIDTH)
        line.append(label, style=TOKENS.text_primary)
    if badge:
        gap = max(1, width - _MARKER_WIDTH - len(label) - len(badge))
        line.append(" " * gap)
        line.append_text(_badge_text(badge))
    if item.active:
        line.pad_right(max(0, width - line.cell_len))
        line.stylize(f"on {TOKENS.surface_selected}")
    return NavLine(line, item.key)


def nav_lines(items: Sequence[NavItem], width: int = NAV_CONTENT_WIDTH, height: int = 0) -> tuple[NavLine, ...]:
    """The nav list as lines, with group headings.

    When ``height`` is positive and the list is taller, only a window around
    the active item is kept, with "↑ N more" / "↓ N more" markers, so the
    active item is always on screen.
    """

    width = max(4, width)
    lines: list[NavLine] = []
    active_line = 0
    group = ""
    for item in items:
        if item.group and item.group != group:
            lines.append(NavLine(Text(_clip(item.group, width), style=f"bold {TOKENS.text_muted}")))
        group = item.group
        if item.active:
            active_line = len(lines)
        lines.append(_item_line(item, width))
    if height <= 0 or len(lines) <= height:
        return tuple(lines)
    size = max(3, height)
    start = max(0, min(active_line - size // 2, len(lines) - size))
    end = start + size
    window = lines[start:end]
    if start > 0:
        window[0] = NavLine(Text(f"  ↑ {start + 1} more", style=TOKENS.text_muted))
    if end < len(lines):
        window[-1] = NavLine(Text(f"  ↓ {len(lines) - end + 1} more", style=TOKENS.text_muted))
    return tuple(window)


def render_nav(lines: Sequence[NavLine]) -> Text:
    return Text("\n").join(line.text for line in lines)


def nav_key_at(lines: Sequence[NavLine], row: int) -> str | None:
    """Item key drawn on content ``row`` (None for headings, markers, gaps)."""

    if 0 <= row < len(lines):
        return lines[row].key
    return None


# --- one-line switcher (narrow terminals) ------------------------------------


@dataclass(frozen=True)
class NavSwitcher:
    """A one-line view switcher for ``#body``: markup plus click targets.

    ``hits`` are ``(start, end, key)`` column ranges on the line.
    """

    markup: str
    hits: tuple[tuple[int, int, str], ...] = ()

    def key_at(self, column: int) -> str | None:
        for start, end, key in self.hits:
            if start <= column < end:
                return key
        return None


def _switcher_label(item: NavItem) -> str:
    label = " ".join(item.label.split())
    mark = " !" if "!" in item.badge else ""
    return f"{_ACTIVE_MARKER.strip()}{label}{mark}" if item.active else f"{label}{mark}"


def _window_width(labels: Sequence[str], start: int, end: int) -> int:
    width = sum(len(label) for label in labels[start:end]) + len(_SWITCHER_SEPARATOR) * (end - start - 1)
    if start > 0:
        width += 2
    if end < len(labels):
        width += 2
    return width


def nav_switcher(items: Sequence[NavItem], width: int) -> NavSwitcher:
    """``Get protected · ▸Guardrail & scanning ! · Alerts & telemetry ›``.

    Every item fits when it can; otherwise the items around the active one
    are kept and ``‹`` / ``›`` stand for the rest (clicking them selects the
    nearest hidden item). Badges are left out except the ``!`` mark.
    """

    if not items:
        return NavSwitcher("")
    labels = [_switcher_label(item) for item in items]
    active = next((i for i, item in enumerate(items) if item.active), 0)
    start, end = active, active + 1
    if _window_width(labels, 0, len(labels)) <= width:
        start, end = 0, len(labels)
    else:
        grew = True
        while grew:
            grew = False
            for candidate in ((start, end + 1), (start - 1, end)):
                lo, hi = candidate
                if lo < 0 or hi > len(labels) or _window_width(labels, lo, hi) > width:
                    continue
                start, end = lo, hi
                grew = True
    if _window_width(labels, start, end) > width:
        labels[active] = _clip(labels[active], max(4, width - 4))
    parts: list[str] = []
    hits: list[tuple[int, int, str]] = []
    column = 0
    if start > 0:
        parts.append(f"[{TOKENS.text_muted}]‹[/] ")
        hits.append((0, 1, items[start - 1].key))
        column = 2
    for index in range(start, end):
        if index > start:
            parts.append(f"[{TOKENS.text_muted}]{_SWITCHER_SEPARATOR}[/]")
            column += len(_SWITCHER_SEPARATOR)
        label = labels[index]
        if items[index].active:
            parts.append(f"[bold {TOKENS.accent_cyan}]{escape(label)}[/]")
        elif label.endswith(" !"):
            parts.append(f"[{TOKENS.text_secondary}]{escape(label[:-2])}[/] [bold {TOKENS.accent_amber}]![/]")
        else:
            parts.append(f"[{TOKENS.text_secondary}]{escape(label)}[/]")
        hits.append((column, column + len(label), items[index].key))
        column += len(label)
    if end < len(labels):
        parts.append(f" [{TOKENS.text_muted}]›[/]")
        hits.append((column + 1, column + 2, items[end].key))
    return NavSwitcher("".join(parts), tuple(hits))


# --- widget -------------------------------------------------------------------


class PanelNav(Static):
    """``#panel-nav``: draws a panel's ``NavItem`` list and reports clicks."""

    class Selected(Message):
        """A nav item was clicked."""

        def __init__(self, key: str) -> None:
            super().__init__()
            self.key = key

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__("", *args, **kwargs)  # type: ignore[arg-type]
        self._lines: tuple[NavLine, ...] = ()
        self._signature: tuple[object, ...] | None = None

    @property
    def lines(self) -> tuple[NavLine, ...]:
        return self._lines

    def _available_height(self) -> int:
        parent = self.parent
        height = int(getattr(getattr(parent, "content_size", None), "height", 0) or 0)
        if height <= 0:
            return 0
        return max(3, height - self.styles.gutter.height)

    def show_items(self, items: Sequence[NavItem]) -> None:
        width = int(self.content_size.width or 0) or NAV_CONTENT_WIDTH
        height = self._available_height()
        signature = (tuple(items), width, height)
        if signature == self._signature:
            return
        self._signature = signature
        self._lines = nav_lines(items, width, height)
        self.update(render_nav(self._lines))

    def clear_items(self) -> None:
        if self._signature is None and not self._lines:
            return
        self._signature = None
        self._lines = ()
        self.update("")

    def on_click(self, event: events.Click) -> None:
        offset = event.get_content_offset(self)
        if offset is None:
            return
        key = nav_key_at(self._lines, offset.y)
        if key is not None:
            event.stop()
            self.post_message(self.Selected(key))


__all__ = [
    "ASIDE_MIN_WIDTH",
    "NAV_CONTENT_WIDTH",
    "NAV_MIN_WIDTH",
    "NAV_WIDTH",
    "Aside",
    "NavItem",
    "NavLine",
    "NavSwitcher",
    "PanelNav",
    "SplitLayout",
    "active_item",
    "nav_key_at",
    "nav_lines",
    "nav_switcher",
    "render_nav",
    "split_aside",
    "split_layout",
    "step_nav",
]
