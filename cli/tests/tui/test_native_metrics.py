# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile, OverviewMetrics


class _Textual7MetricTile(MetricTile):
    update_classes = None


def test_metric_tile_class_map_falls_back_to_set_class(monkeypatch) -> None:
    tile = _Textual7MetricTile(
        MetricDatum(
            key="hook_calls",
            label="Hook Calls",
            value=0,
            progress=0.0,
            detail="gateway offline",
            state="error",
            target_panel="logs",
        )
    )
    calls: list[tuple[bool, str]] = []

    monkeypatch.setattr(
        tile,
        "set_class",
        lambda enabled, class_name: calls.append((enabled, class_name)),
    )

    tile._apply_class_map(
        {
            "metric-ok": False,
            "metric-warn": False,
            "metric-error": True,
            "tile-clickable": True,
        }
    )

    assert calls == [
        (False, "metric-ok"),
        (False, "metric-warn"),
        (True, "metric-error"),
        (True, "tile-clickable"),
    ]


def test_metric_tile_skips_all_child_updates_for_identical_metric(monkeypatch) -> None:
    metric = MetricDatum(
        key="hook_calls",
        label="Hook Calls",
        value=12,
        progress=24.0,
        detail="12 calls",
        trend=(3.0, 6.0, 12.0),
        state="ok",
        target_panel="logs",
    )
    tile = MetricTile(metric)
    tile.refresh_metric(metric)

    def unexpected_update(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"unexpected child update: {args!r} {kwargs!r}")

    monkeypatch.setattr(tile._title, "update", unexpected_update)
    monkeypatch.setattr(tile._digits, "update", unexpected_update)
    monkeypatch.setattr(tile._progress, "update", unexpected_update)
    monkeypatch.setattr(tile._detail, "update", unexpected_update)
    monkeypatch.setattr(tile, "_apply_class_map", unexpected_update)
    original_sparkline_data = tile._sparkline.data

    tile.refresh_metric(metric)

    assert tile._sparkline.data == original_sparkline_data


def test_metric_tile_only_updates_changed_rendered_field(monkeypatch) -> None:
    metric = MetricDatum(
        key="hook_calls",
        label="Hook Calls",
        value=12,
        progress=24.0,
        detail="12 calls",
        trend=(3.0, 6.0, 12.0),
        state="ok",
        target_panel="logs",
    )
    tile = MetricTile(metric)
    tile.refresh_metric(metric)
    updates: list[tuple[str, object]] = []

    monkeypatch.setattr(tile._title, "update", lambda value: updates.append(("title", value)))
    monkeypatch.setattr(tile._digits, "update", lambda value: updates.append(("digits", value)))
    monkeypatch.setattr(
        tile._progress,
        "update",
        lambda **values: updates.append(("progress", values)),
    )
    monkeypatch.setattr(tile._detail, "update", lambda value: updates.append(("detail", value)))
    monkeypatch.setattr(tile, "_apply_class_map", lambda value: updates.append(("classes", value)))

    tile.refresh_metric(
        MetricDatum(
            key="hook_calls",
            label="Hook Calls",
            value=12,
            progress=24.0,
            detail="updated detail",
            trend=(3.0, 6.0, 12.0),
            state="ok",
            target_panel="logs",
        )
    )

    assert updates == [("detail", "updated detail")]


def test_overview_metrics_skips_tiles_for_identical_tuple() -> None:
    metric = MetricDatum(
        key="hook_calls",
        label="Hook Calls",
        value=12,
        progress=24.0,
        detail="12 calls",
    )
    metrics = OverviewMetrics((metric,))
    calls: list[MetricDatum] = []
    metrics._tiles[metric.key] = SimpleNamespace(refresh_metric=calls.append)

    metrics.refresh_metrics((metric,))

    assert calls == []
