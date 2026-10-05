# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert Overview with the gateway stopped, batch 37 (GAP-2586)."""

from __future__ import annotations

from defenseclaw.observability.v8_status import V8BucketStatus, V8DestinationStatus, V8OperatorStatus
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.services.overview_state import (
    ConnectorHealth,
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)


def _destination(name: str, kind: str) -> V8DestinationStatus:
    return V8DestinationStatus(
        name=name,
        kind=kind,
        enabled=True,
        generated=kind == "sqlite",
        capabilities=("logs",),
        selected_signals=("logs",),
        policy_form="implicit_local" if kind == "sqlite" else "explicit",
        endpoint="/tmp/dc/audit.db" if kind == "sqlite" else "https://otlp.example:4318",
        route_count=1,
        buckets=("compliance.activity",),
        redaction_profiles=("none",),
    )


def test_overview_drops_live_connector_and_destination_health_once_the_gateway_stops() -> None:
    # GAP-2586: with the gateway stopped CONNECTORS kept "● running" and the
    # destinations kept "healthy", "controller=healthy" and "19/4096 items".
    cfg = OverviewConfig(
        guardrail_enabled=True,
        guardrail_mode="action",
        connector_modes=(("codex", "action"), ("claudecode", "action")),
    )
    model = OverviewPanelModel(cfg, version="test")
    model.set_observability_status(
        V8OperatorStatus(
            source="/tmp/config.yaml",
            data_dir="/tmp/dc",
            plan_digest="a" * 64,
            bucket_catalog_version=1,
            retention_days=7,
            local_path="/tmp/dc/audit.db",
            judge_bodies_path="",
            destinations=(_destination("local-sqlite", "sqlite"), _destination("manual-o11y", "otlp")),
            buckets=(V8BucketStatus("compliance.activity", ("logs",), "none"),),
            warnings=(),
        )
    )
    details = {
        "retention_state": "healthy",
        "destinations": [
            {"name": "local-sqlite", "health_state": "healthy", "reason": "activated"},
            {"name": "manual-o11y", "health_state": "healthy", "queue_items": 19, "queue_capacity": 4096},
        ],
    }
    model.set_health(
        HealthSnapshot(
            telemetry=SubsystemHealth(state="running", details=details),
            connectors=(
                ConnectorHealth(name="codex", state="running"),
                ConnectorHealth(name="claudecode", state="running"),
            ),
        )
    )
    app = DefenseClawTUI(overview_model=model)
    model.set_gateway_probe("running")
    assert {row.status for row in app._overview_connector_rows()} == {"running"}  # noqa: SLF001
    assert [row.health_label for row in model.observability_destination_rows()] == ["healthy", "healthy"]
    assert model.observability_storage_status().retention_health == "healthy"

    model.set_gateway_probe("stopped")
    statuses = {row.status for row in app._overview_connector_rows()}  # noqa: SLF001
    assert statuses == {"offline (gateway not running)"}, statuses
    rows = model.observability_destination_rows()
    assert [row.health_label for row in rows] == ["offline (gateway not running)"] * 2
    assert {row.queue for row in rows} == {"unavailable"}
    storage = model.observability_storage_status()
    assert (storage.retention_health, storage.retention_failure) == ("offline", "gateway not running")
    text = app._overview_observability_text()  # noqa: SLF001
    assert "controller=offline (gateway not running)" in text and "healthy" not in text, text
