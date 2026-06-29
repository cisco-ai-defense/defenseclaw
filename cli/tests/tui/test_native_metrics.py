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

from defenseclaw.tui.widgets.native_metrics import MetricDatum, MetricTile


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
