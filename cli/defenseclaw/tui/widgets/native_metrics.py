# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native Textual metric widgets for polished dashboard surfaces."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from rich.text import Span, Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.renderables.digits import DIGITS
from textual.widgets import Digits, ProgressBar, Sparkline, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS

_DETAIL_SEPARATOR = " · "
_MORE = " …"
# The last word of an item that holds its number: "380", "x11", "15".
_TRAILING_COUNT = re.compile(r"\S*\d\S*$")


def fit_metric_title(label: str, width: int) -> str:
    """``label`` for a tile ``width`` cells wide, dropping words, never a cut.

    "Hook Calls (4 connectors)" becomes "Hook Calls (4)", then "Hook Calls";
    the plain ellipsis read "Hook Calls (…" at 80x24 (GAP-2443).
    """

    if width <= 0 or len(label) <= width:
        return label
    match = re.fullmatch(r"(.*?) \((.*)\)", label)
    if match is None:
        return label
    base, inner = match.groups()
    first = inner.split()[0] if inner.split() else ""
    if first.isdigit() and len(f"{base} ({first})") <= width:
        return f"{base} ({first})"
    return base


def fit_metric_detail(detail: str, width: int) -> str | Text:
    """``detail`` for a tile ``width`` cells wide, cut only between items.

    The line is "item · item · item". Items that don't fit are dropped whole
    and " …" marks that more were left out, so a count is never cut into a
    different number ("UserPromptSubmit x1…" for x11, "claudecode 3…" for
    380, GAP-2430). When even the first item doesn't fit, its label stays
    whole (GAP-0341): a count of 1000 or more is written short ("12k"), and
    if the item still doesn't fit the count gives way ("claudecode …"); the
    tile's big digits and the panels keep every number. A phrase keeps its
    whole leading words ("skill+mcp …").
    """

    if width <= 0 or not detail:
        return detail
    text = Text.from_markup(detail)
    if text.cell_len <= width:
        return text
    plain = text.plain
    ends: list[int] = []
    start = plain.find(_DETAIL_SEPARATOR)
    while start >= 0:
        ends.append(start)
        start = plain.find(_DETAIL_SEPARATOR, start + len(_DETAIL_SEPARATOR))
    for end in reversed(ends):
        kept = text[:end]
        if kept.cell_len + len(_MORE) <= width:
            kept.append(_MORE, style=TOKENS.text_muted)
            return kept
    first = text[: ends[0]] if ends else text
    if ends and first.cell_len <= width:
        # No room for the " …" marker beside the first item: keep that item
        # whole ("claudecode 59") rather than cutting its label (GAP-0341).
        return first
    more = bool(ends)
    for tenths in (True, False):
        short = _with_short_counts(first, tenths=tenths)
        if short is not None and short.cell_len <= width:
            if more and short.cell_len + len(_MORE) <= width:
                short.append(_MORE, style=TOKENS.text_muted)
            return short
    count = _TRAILING_COUNT.search(first.plain)
    if count is not None and count.start() > 0:
        label = first[: count.start()]
        label.rstrip()
        if label.cell_len + len(_MORE) <= width:
            label.append(_MORE, style=TOKENS.text_muted)
            return label
        if label.cell_len <= width:
            return label
    # A phrase ("skill+mcp scans", "gateway status pending") keeps whole
    # words; only a single word wider than the tile is cut.
    words = [index for index, char in enumerate(first.plain) if char == " "]
    for index in reversed(words):
        head = first[:index]
        head.rstrip()
        for marker in (_MORE, "\u2026"):
            if head.plain and head.cell_len + len(marker) <= width:
                head.append(marker, style=TOKENS.text_muted)
                return head
    first.truncate(width, overflow="ellipsis")
    return first


_COUNT_WORD = re.compile(r"(?<!\S)(\D*?)(\d{4,})(?!\S)")


def _short_count(value: int, *, tenths: bool = True) -> str:
    """1234 -> "1.2k" ("1k" without tenths), 12345 -> "12k", 1234567 -> "1.2M" (rounded down)."""

    for unit, size in (("M", 1_000_000), ("k", 1_000)):
        if value >= size:
            whole, rest = divmod(value, size)
            tenth = rest * 10 // size
            return f"{whole}.{tenth}{unit}" if tenths and whole < 10 and tenth else f"{whole}{unit}"
    return str(value)


def _with_short_counts(item: Text, *, tenths: bool = True) -> Text | None:
    """``item`` with every count of 1000 or more written short; None if it has none."""

    plain = item.plain
    matches = list(_COUNT_WORD.finditer(plain))
    if not matches:
        return None
    out = Text()
    last = 0
    for match in matches:
        start, end = match.start(2), match.end(2)
        out.append_text(item[last:start])
        short = _short_count(int(match.group(2)), tenths=tenths)
        # Keep the number's colour (the spans of its slice cover it whole).
        out.append_text(Text(short, spans=[Span(0, len(short), span.style) for span in item[start:end].spans]))
        last = end
    out.append_text(item[last:])
    return out


@dataclass(frozen=True)
class MetricDatum:
    """One native dashboard metric.

    ``target_panel`` is the panel id (e.g. ``"alerts"``) that the tile
    deep-links to when clicked. Empty disables click routing.
    ``value_text`` overrides ``value`` for the digits row when set (used
    for short status labels like ``"ON"`` / ``"OFF"`` where a number is
    not meaningful).
    """

    key: str
    label: str
    value: int
    progress: float
    detail: str
    trend: tuple[float, ...] = ()
    state: str = "neutral"
    target_panel: str = ""
    value_text: str = ""


class MetricTile(Vertical):
    """A compact, clickable metric card built from native Textual widgets."""

    class Clicked(Message):
        """Posted when the user clicks the tile body."""

        def __init__(self, key: str, target_panel: str) -> None:
            super().__init__()
            self.key = key
            self.target_panel = target_panel

    DEFAULT_CSS = f"""
    MetricTile {{
        width: 1fr;
        height: 8;
        min-width: 16;
        margin-right: 1;
        padding: 0 1;
        border: round {TOKENS.border_muted};
        background: {TOKENS.surface_panel};
    }}

    MetricTile.tile-clickable {{
        link-color: {TOKENS.accent_cyan};
    }}

    MetricTile.tile-clickable:hover {{
        background: {TOKENS.surface_hover};
        border: round {TOKENS.border_active};
    }}

    MetricTile:last-child {{
        margin-right: 0;
    }}

    MetricTile.metric-ok {{
        border: round {TOKENS.accent_green};
    }}

    MetricTile.metric-warn {{
        border: round {TOKENS.accent_amber};
    }}

    MetricTile.metric-error {{
        border: round {TOKENS.accent_red};
    }}

    /* Narrow tiles end long titles and details with "…" instead of
       cutting them mid-word ("Hook Calls (5") (GAP-1166). */
    MetricTile .metric-title {{
        height: 1;
        color: {TOKENS.accent_cyan};
        text-style: bold;
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }}

    MetricTile .metric-digits {{
        height: 3;
        color: {TOKENS.text_primary};
    }}

    MetricTile .metric-word {{
        height: 3;
        content-align: left middle;
        color: {TOKENS.text_primary};
        text-style: bold;
    }}

    /* The tile is 8 rows: border (2) + title, digits (3), sparkline and
       detail. The progress bar used to take the detail's row, so the
       severity breakdown / guardrail mode line was always clipped. It
       stays mounted (and updated) but is not drawn. */
    MetricTile .metric-progress {{
        display: none;
        height: 1;
        margin-top: 0;
    }}

    MetricTile .metric-sparkline {{
        height: 1;
        color: {TOKENS.accent_violet};
    }}

    MetricTile .metric-detail {{
        height: 1;
        color: {TOKENS.text_secondary};
        text-wrap: nowrap;
        text-overflow: ellipsis;
    }}
    """

    def __init__(self, metric: MetricDatum, **kwargs: object) -> None:
        super().__init__(id=f"overview-{metric.key}-metric", **kwargs)
        self.metric = metric
        self._rendered_metric: MetricDatum | None = None
        self._title = Static(metric.label, classes="metric-title")
        self._digits = Digits(self._digits_text(metric), classes="metric-digits")
        # Digits only draws 0-9, A-F and a few symbols; a status word such
        # as "ON" / "OFF" came out as a jumble of glyph fragments, so words
        # are shown as plain bold text of the same height instead.
        self._word = Static("", classes="metric-word", markup=False)
        self._progress = ProgressBar(
            total=100,
            show_eta=False,
            show_percentage=False,
            classes="metric-progress",
        )
        self._sparkline = Sparkline(metric.trend or (0,), classes="metric-sparkline")
        self._detail = Static(metric.detail, classes="metric-detail", markup=True)

    def compose(self) -> ComposeResult:
        yield self._title
        yield self._digits
        yield self._word
        yield self._progress
        yield self._sparkline
        yield self._detail

    def on_mount(self) -> None:
        self.refresh_metric(self.metric)

    def refresh_metric(self, metric: MetricDatum) -> None:
        """Update the tile without rebuilding the widget tree."""

        previous = self._rendered_metric
        self.metric = metric
        if previous == metric:
            return

        if previous is None or previous.label != metric.label:
            self._title.update(fit_metric_title(metric.label, self.content_size.width))

        digits_text = self._digits_text(metric)
        if previous is None or self._digits_text(previous) != digits_text:
            as_word = not self.digits_renderable(digits_text)
            self._digits.display = not as_word
            self._word.display = as_word
            if as_word:
                self._word.update(digits_text)
            else:
                self._digits.update(digits_text)

        progress = _clamp(metric.progress)
        if previous is None or _clamp(previous.progress) != progress:
            self._progress.update(total=100, progress=progress)

        trend = metric.trend or (0,)
        if previous is None or (previous.trend or (0,)) != trend:
            self._sparkline.data = trend

        if previous is None or previous.detail != metric.detail:
            self._detail.update(fit_metric_detail(metric.detail, self.content_size.width))

        class_map = self._class_map(metric)
        if previous is None or self._class_map(previous) != class_map:
            self._apply_class_map(class_map)

        tooltip = self._tooltip_text(metric)
        if previous is None or self._tooltip_text(previous) != tooltip:
            self.tooltip = tooltip

        self._rendered_metric = metric

    def on_resize(self, _event: events.Resize) -> None:
        # The title and detail are fitted to the tile width (GAP-2430).
        width = self.content_size.width
        self._title.update(fit_metric_title(self.metric.label, width))
        self._detail.update(fit_metric_detail(self.metric.detail, width))

    def _apply_class_map(self, classes: dict[str, bool]) -> None:
        """Apply a class map atomically using the Textual 8 API."""

        self.update_classes(classes)

    def on_click(self, event: events.Click) -> None:
        if not self.metric.target_panel:
            return
        event.stop()
        self.post_message(self.Clicked(self.metric.key, self.metric.target_panel))

    @staticmethod
    def _digits_text(metric: MetricDatum) -> str:
        if metric.value_text:
            return metric.value_text
        return str(max(metric.value, 0))

    @staticmethod
    def digits_renderable(text: str) -> bool:
        """True when every character has a Digits glyph."""

        return all(character in DIGITS or character == "." for character in text)

    @staticmethod
    def _class_map(metric: MetricDatum) -> dict[str, bool]:
        return {
            "metric-ok": metric.state == "ok",
            "metric-warn": metric.state == "warn",
            "metric-error": metric.state == "error",
            "tile-clickable": bool(metric.target_panel),
        }

    @staticmethod
    def _tooltip_text(metric: MetricDatum) -> str | None:
        if metric.target_panel:
            return f"Open {metric.target_panel.title()}"
        return None


class OverviewMetrics(Horizontal):
    """Native Textual metric row for the Overview panel."""

    DEFAULT_CSS = f"""
    OverviewMetrics {{
        height: 8;
        margin-bottom: 1;
        background: {TOKENS.surface_base};
    }}

    OverviewMetrics.hidden {{
        display: none;
    }}
    """

    def __init__(self, metrics: Sequence[MetricDatum] = (), **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.metrics = tuple(metrics)
        self._tiles: dict[str, MetricTile] = {}

    def compose(self) -> ComposeResult:
        for metric in self.metrics:
            tile = MetricTile(metric)
            self._tiles[metric.key] = tile
            yield tile

    def refresh_metrics(self, metrics: Sequence[MetricDatum]) -> None:
        """Refresh an already-mounted metric row."""

        incoming = tuple(metrics)
        if incoming == self.metrics:
            return

        for metric in incoming:
            tile = self._tiles.get(metric.key)
            if tile is not None:
                tile.refresh_metric(metric)
        self.metrics = incoming


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))
