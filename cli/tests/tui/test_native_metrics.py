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


def test_metric_tile_class_map_uses_atomic_update(monkeypatch) -> None:
    tile = MetricTile(
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
    calls: list[dict[str, bool]] = []

    monkeypatch.setattr(
        tile,
        "update_classes",
        lambda classes: calls.append(classes),
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
        {
            "metric-ok": False,
            "metric-warn": False,
            "metric-error": True,
            "tile-clickable": True,
        }
    ]
