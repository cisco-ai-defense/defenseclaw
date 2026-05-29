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

from collections.abc import Sequence
from dataclasses import dataclass

from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Digits, ProgressBar, Sparkline, Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS


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

    MetricTile .metric-title {{
        height: 1;
        color: {TOKENS.accent_cyan};
        text-style: bold;
    }}

    MetricTile .metric-digits {{
        height: 3;
        color: {TOKENS.text_primary};
    }}

    MetricTile .metric-progress {{
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
    }}
    """

    def __init__(self, metric: MetricDatum, **kwargs: object) -> None:
        super().__init__(id=f"overview-{metric.key}-metric", **kwargs)
        self.metric = metric
        self._title = Static(metric.label, classes="metric-title")
        self._digits = Digits(self._digits_text(metric), classes="metric-digits")
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
        yield self._progress
        yield self._sparkline
        yield self._detail

    def on_mount(self) -> None:
        self.refresh_metric(self.metric)

    def refresh_metric(self, metric: MetricDatum) -> None:
        """Update the tile without rebuilding the widget tree."""

        self.metric = metric
        self._title.update(metric.label)
        self._digits.update(self._digits_text(metric))
        self._progress.update(total=100, progress=_clamp(metric.progress))
        self._sparkline.data = metric.trend or (0,)
        self._detail.update(metric.detail)
        # Textual >=8.2.4 ``DOM.update_classes`` swaps a whole class
        # mapping in a single style-recomputation pass. The previous
        # four ``set_class`` calls each triggered an independent
        # restyle of the tile + its descendants; the tile is rendered
        # on every metric refresh, so the cost was real.
        self.update_classes(
            {
                "metric-ok": metric.state == "ok",
                "metric-warn": metric.state == "warn",
                "metric-error": metric.state == "error",
                "tile-clickable": bool(metric.target_panel),
            }
        )
        if metric.target_panel:
            self.tooltip = f"Open {metric.target_panel.title()}"
        else:
            self.tooltip = None

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

        self.metrics = tuple(metrics)
        for metric in self.metrics:
            tile = self._tiles.get(metric.key)
            if tile is not None:
                tile.refresh_metric(metric)


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))
