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

import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.observability.v8_config import V8ConfigError
from defenseclaw.observability.v8_status import (
    V8BucketStatus,
    V8DestinationHealth,
    V8DestinationStatus,
    V8OperatorStatus,
    destination_health_from_gateway,
    inspect_v8_operator_status,
    operator_status_from_effective,
    retention_health_from_gateway,
    source_is_v8,
)


def _effective() -> dict[str, object]:
    bucket_names = ("compliance.activity", "model.io", "platform.health")
    return {
        "bucket_catalog_version": 1,
        "local": {
            "path": "/var/lib/defenseclaw/audit.db",
            "judge_bodies_path": "/var/lib/defenseclaw/judge.db",
            "retention_days": 90,
        },
        "buckets": [
            {
                "bucket": name,
                "collect": {
                    "logs": True,
                    "traces": name != "model.io",
                    "metrics": True,
                },
                "redaction_profile": "none" if name != "model.io" else "sensitive",
            }
            for name in bucket_names
        ],
        "destinations": [
            {
                "name": "local-sqlite",
                "kind": "sqlite",
                "enabled": True,
                "generated": True,
                "capabilities": {"signals": ["logs"]},
                "selected_signals": ["logs"],
                "policy_form": "implicit_local",
                "routes": [
                    {
                        "action": "send",
                        "selector": {"bucket_wildcard": True},
                        "redaction_profile_by_bucket": {
                            "compliance.activity": "none",
                            "model.io": "sensitive",
                            "platform.health": "none",
                        },
                    }
                ],
                "transport": {"path": "/var/lib/defenseclaw/audit.db"},
            },
            {
                "name": "collector",
                "kind": "otlp",
                "enabled": True,
                "generated": False,
                "capabilities": {"signals": ["logs", "traces", "metrics"]},
                "selected_signals": ["logs", "traces", "metrics"],
                "policy_form": "capability_default",
                "routes": [
                    {
                        "action": "send",
                        "selector": {"bucket_wildcard": True},
                        "redaction_profile_by_bucket": {
                            "compliance.activity": "none",
                            "model.io": "none",
                            "platform.health": "none",
                        },
                    }
                ],
                "transport": {
                    "endpoint": "https://collector.example.test",
                    "headers": {"authorization": "<masked>"},
                    "batch": {
                        "max_queue_size": 2048,
                        "max_queue_bytes": 67_108_864,
                        "max_export_batch_size": 512,
                        "max_export_batch_bytes": 8_388_608,
                        "scheduled_delay_ms": 5000,
                    },
                },
            },
            {
                "name": "strict-jsonl",
                "kind": "jsonl",
                "enabled": False,
                "generated": False,
                "capabilities": {"signals": ["logs"]},
                "selected_signals": ["logs"],
                "policy_form": "advanced_routes",
                "routes": [
                    {
                        "action": "drop",
                        "selector": {"buckets": ["model.io"]},
                    },
                    {
                        "action": "send",
                        "selector": {"buckets": ["compliance.activity"]},
                        "redaction_profile_by_bucket": {"compliance.activity": "strict"},
                    },
                ],
                "transport": {"path": "/tmp/events.jsonl"},
            },
        ],
        "warnings": [
            {
                "code": "unbounded_retention",
                "path": "observability.local.retention_days",
                "summary": "retention is unbounded",
            }
        ],
    }


def test_operator_status_preserves_effective_capabilities_routes_and_redaction() -> None:
    effective = _effective()
    assert isinstance(effective["destinations"], list)
    effective["destinations"][1]["transport"]["endpoint"] = (
        "https://user:secret@collector.example.test/v1/traces?token=must-not-render"
    )
    effective["destinations"][1]["preset"] = "galileo"
    status = operator_status_from_effective(
        effective,
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
    )

    assert status.bucket_catalog_version == 1
    assert status.retention_days == 90
    assert not status.unbounded_retention
    assert status.local_path.endswith("audit.db")
    assert [bucket.name for bucket in status.buckets] == [
        "compliance.activity",
        "model.io",
        "platform.health",
    ]
    assert status.buckets[1].collected_signals == ("logs", "metrics")
    assert status.buckets[1].redaction_profile == "sensitive"

    local, collector, jsonl = status.destinations
    assert local.generated and local.kind == "sqlite"
    assert local.redaction_label == "mixed: none, sensitive"
    assert collector.selected_signals == ("logs", "traces", "metrics")
    assert collector.preset == "galileo"
    assert collector.buckets == (
        "compliance.activity",
        "model.io",
        "platform.health",
    )
    assert collector.redaction_label == "unredacted (none)"
    assert collector.endpoint == "https://collector.example.test/v1/traces"
    assert collector.delivery_limits_label == ("queue=2048 items/64.0 MiB; batch=512 items/8.0 MiB; delay=5000ms")
    assert local.delivery_limits_label == "not-applicable"
    assert jsonl.route_count == 2
    assert jsonl.buckets == ("compliance.activity",)
    assert jsonl.redaction_label == "redacted: strict"
    assert "authorization" not in repr(status)
    assert "must-not-render" not in repr(status)
    assert "user:secret" not in repr(status)


def test_operator_status_reports_unbounded_retention() -> None:
    effective = _effective()
    assert isinstance(effective["local"], dict)
    effective["local"]["retention_days"] = 0
    status = operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")
    assert status.unbounded_retention


def test_destination_health_accepts_only_bounded_content_free_fields() -> None:
    health = destination_health_from_gateway(
        {
            "telemetry": {
                "details": {
                    "destinations": [
                        {
                            "name": "collector",
                            "state": "degraded",
                            "reason": "queue_full",
                            "queue": {
                                "items": 7,
                                "max_items": 20,
                                "bytes": 2048,
                                "max_bytes": 4096,
                            },
                            "counters": {"dropped": 3},
                            "last_success_at": "2026-07-06T12:00:00Z",
                            "last_failure_at": "2026-07-06T12:01:00Z",
                            "last_error_code": "retryable_delivery",
                            "last_error": "Authorization: Bearer must-not-render",
                            "headers": {"authorization": "must-not-render"},
                            "endpoint": "https://user:secret@example.test/?token=secret",
                        }
                    ]
                }
            }
        }
    )

    assert health == {
        "collector": V8DestinationHealth(
            name="collector",
            state="degraded",
            reason="queue_full",
            queue_items=7,
            queue_bytes=2048,
            queue_max_items=20,
            queue_max_bytes=4096,
            dropped=3,
            last_success="2026-07-06T12:00:00Z",
            last_failure="2026-07-06T12:01:00Z",
            last_error_class="retryable_delivery",
        )
    }
    assert health["collector"].queue_label == "7/20 items, 2.0 KiB/4.0 KiB, 3 dropped"
    assert health["collector"].activity_label == (
        "ok 2026-07-06T12:00:00Z; error 2026-07-06T12:01:00Z (retryable_delivery)"
    )
    assert "must-not-render" not in repr(health)
    assert "secret" not in repr(health)


@pytest.mark.parametrize("fraction_digits", [1, 2, 4, 5, 7, 8, 9])
def test_destination_health_accepts_every_rfc3339nano_fraction_width(fraction_digits: int) -> None:
    timestamp = "2026-07-06T12:00:00." + ("1" * fraction_digits) + "Z"
    health = destination_health_from_gateway(
        {
            "telemetry": {
                "details": {
                    "destinations": [
                        {
                            "name": "collector",
                            "last_success_at": timestamp,
                        }
                    ]
                }
            }
        }
    )

    assert health["collector"].last_success == timestamp


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-06T12:00:00.Z",
        "2026-07-06T12:00:00.1234567890Z",
        "2026-07-06T12:00:00,1Z",
        "2026-07-06 12:00:00.1Z",
        "2026-07-06T12:00:00.1",
        "2026-07-06T12:00:00.1z",
        "2026-07-06T12:00:00.1+24:00",
        "2026-07-06T12:00:00.1+01:60",
        "2026-02-30T12:00:00.1Z",
    ],
)
def test_destination_health_rejects_malformed_rfc3339nano_timestamps(timestamp: str) -> None:
    health = destination_health_from_gateway(
        {
            "telemetry": {
                "details": {
                    "destinations": [
                        {
                            "name": "collector",
                            "last_success_at": timestamp,
                        }
                    ]
                }
            }
        }
    )

    assert health["collector"].last_success == ""


def test_destination_health_current_transition_and_retention_are_not_inferred() -> None:
    payload = {
        "telemetry": {
            "state": "running",
            "last_error": "https://secret.example.test",
            "details": {
                "destination": "galileo",
                "state": "failing",
                "failure": "partial_success",
                "retention_state": "degraded",
                "retention_failure": "run_failed",
            },
        }
    }
    result = destination_health_from_gateway(payload)
    assert result["galileo"].state == "failing"
    assert result["galileo"].last_error_class == "partial_success"
    assert result["galileo"].queue_label == "unavailable"
    assert result["galileo"].activity_label == "error partial_success"
    assert retention_health_from_gateway(payload) == ("degraded", "run_failed")

    assert destination_health_from_gateway({"telemetry": {"state": "running", "details": {}}}) == {}


def test_destination_health_redacts_legacy_delivery_error_but_preserves_times() -> None:
    result = destination_health_from_gateway(
        {
            "details": {
                "destinations": [
                    {
                        "name": "galileo",
                        "delivery": {
                            "last_attempt_at": "2026-07-06T12:01:00Z",
                            "last_success_at": "2026-07-06T12:00:00Z",
                            "last_error": ("rpc failed for https://user:secret@example.test/?token=must-not-render"),
                        },
                    }
                ]
            }
        }
    )["galileo"]

    assert result.last_success == "2026-07-06T12:00:00Z"
    assert result.last_failure == "2026-07-06T12:01:00Z"
    assert result.last_error_class == "details_redacted"
    assert result.activity_label == ("ok 2026-07-06T12:00:00Z; error 2026-07-06T12:01:00Z (details_redacted)")
    assert "must-not-render" not in repr(result)
    assert "user:secret" not in repr(result)


def test_destination_health_rejects_unbounded_or_malformed_values() -> None:
    result = destination_health_from_gateway(
        {
            "details": {
                "destination": "collector",
                "state": "RUNNING",
                "reason": "contains spaces and https://secret.example.test",
                "queue_items": -1,
                "queue_bytes": "4",
                "last_success": "yesterday",
                "last_error": "must-not-render",
            }
        }
    )["collector"]
    assert result.state == ""
    assert result.reason == ""
    assert result.queue_label == "unavailable"
    assert result.activity_label == "unavailable"


def test_operator_status_accepts_canonical_null_warning_slice() -> None:
    effective = _effective()
    effective["warnings"] = None
    status = operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")
    assert status.warnings == ()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("local"), "local"),
        (lambda value: value["buckets"][0]["collect"].update(logs="yes"), "collect.logs"),
        (lambda value: value["destinations"][0].update(enabled="yes"), "enabled"),
        (lambda value: value["destinations"][0].update(selected_signals="logs"), "selected_signals"),
        (lambda value: value["destinations"][0]["routes"][0].update(action=""), "action"),
    ],
)
def test_operator_status_fails_closed_on_malformed_canonical_wire(mutation, message: str) -> None:
    effective = copy.deepcopy(_effective())
    mutation(effective)
    with pytest.raises(ValueError, match=message):
        operator_status_from_effective(effective, source="x", data_dir="y", plan_digest="z")


def test_source_is_v8_distinguishes_exact_v7_and_valid_v8(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 7\n")
    assert not source_is_v8(path)
    path.write_text("config_version: 8\nobservability: {}\n")
    assert source_is_v8(path)


def test_source_is_v8_does_not_downgrade_invalid_v8_to_v7(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 8\nobservability:\n  destinations: wrong\n")
    with pytest.raises(V8ConfigError):
        source_is_v8(path)


def test_missing_source_is_not_v8(tmp_path: Path) -> None:
    assert not source_is_v8(tmp_path / "missing.yaml")


def test_inspect_status_preserves_effective_judge_capture_default_and_override(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    wire = SimpleNamespace(
        effective=_effective(),
        source=str(path),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
    )
    with patch("defenseclaw.observability.v8_status.inspect_v8_config", return_value=wire):
        path.write_text("config_version: 8\nobservability: {}\n")
        assert inspect_v8_operator_status(path).judge_bodies_enabled is True

        path.write_text("config_version: 8\nguardrail:\n  retain_judge_bodies: false\nobservability: {}\n")
        assert inspect_v8_operator_status(path).judge_bodies_enabled is False


def test_inspect_status_compiles_exact_snapshot_across_concurrent_atomic_replace(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    original = b"config_version: 8\nguardrail: {retain_judge_bodies: false}\nobservability: {}\n"
    replacement = tmp_path / "replacement.yaml"
    replacement.write_bytes(b"config_version: 8\nguardrail: {retain_judge_bodies: true}\nobservability: {}\n")
    path.write_bytes(original)
    inspected_sources: list[bytes] = []
    snapshot_paths: list[Path] = []

    def inspect_snapshot(_operation: str, *, config_path: str):
        snapshot = Path(config_path)
        snapshot_paths.append(snapshot)
        replacement.replace(path)
        inspected_sources.append(snapshot.read_bytes())
        return SimpleNamespace(
            effective=_effective(),
            source=str(snapshot),
            data_dir=str(tmp_path),
            plan_digest="b" * 64,
        )

    with patch("defenseclaw.observability.v8_status.inspect_v8_config", side_effect=inspect_snapshot):
        status = inspect_v8_operator_status(path)

    assert inspected_sources == [original]
    assert status.judge_bodies_enabled is False
    assert status.source == str(path.absolute())
    assert path.read_bytes() != original
    assert all(not snapshot.exists() for snapshot in snapshot_paths)


def test_inspect_status_fails_closed_if_private_snapshot_changes(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 8\nobservability: {}\n")
    snapshot_paths: list[Path] = []

    def mutate_snapshot(_operation: str, *, config_path: str):
        snapshot = Path(config_path)
        snapshot_paths.append(snapshot)
        snapshot.write_text("config_version: 8\nobservability: {defaults: {redaction_profile: none}}\n")
        return SimpleNamespace(
            effective=_effective(),
            source=str(snapshot),
            data_dir=str(tmp_path),
            plan_digest="c" * 64,
        )

    with (
        patch("defenseclaw.observability.v8_status.inspect_v8_config", side_effect=mutate_snapshot),
        pytest.raises(ValueError, match="snapshot changed"),
    ):
        inspect_v8_operator_status(path)

    assert all(not snapshot.exists() for snapshot in snapshot_paths)


def test_doctor_v8_dispatch_renders_retention_destinations_and_warnings(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_doctor import _check_observability, _DoctorResult

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n")
    status = V8OperatorStatus(
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=0,
        local_path=str(tmp_path / "audit.db"),
        judge_bodies_path=str(tmp_path / "judge.db"),
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint=str(tmp_path / "audit.db"),
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
            V8DestinationStatus(
                name="collector",
                kind="otlp",
                enabled=False,
                generated=False,
                capabilities=("logs", "traces", "metrics"),
                selected_signals=("logs", "traces", "metrics"),
                policy_form="capability_default",
                endpoint="https://collector.example.test",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("strict",),
            ),
        ),
        buckets=(V8BucketStatus("compliance.activity", ("logs",), "none"),),
        warnings=(
            (
                "unbounded_retention",
                "observability.local.retention_days",
                "capacity may grow",
            ),
        ),
    )
    result = _DoctorResult()
    with patch(
        "defenseclaw.observability.v8_status.inspect_v8_operator_status",
        return_value=status,
    ):
        _check_observability(SimpleNamespace(data_dir=str(tmp_path)), result)

    checks = {item["label"]: item for item in result.checks}
    assert checks["Local SQLite"]["status"] == "warn"
    assert "retention=unbounded" in checks["Local SQLite"]["detail"]
    assert checks["Destination: local-sqlite"]["status"] == "pass"
    assert "redaction=unredacted (none)" in checks["Destination: local-sqlite"]["detail"]
    assert checks["Destination: collector"]["status"] == "skip"
    assert checks["Bucket catalog"]["detail"] == "version=1; collected=1/1"
    assert checks["Observability warning: unbounded_retention"]["status"] == "warn"


def test_doctor_invalid_v8_never_falls_back_to_legacy_destination_reader(tmp_path: Path) -> None:
    from defenseclaw import observability
    from defenseclaw.commands.cmd_doctor import _check_observability, _DoctorResult

    (tmp_path / "config.yaml").write_text("config_version: 8\nobservability:\n  destinations: wrong\n")
    result = _DoctorResult()
    assert not hasattr(observability, "list_destinations")
    _check_observability(SimpleNamespace(data_dir=str(tmp_path)), result)
    assert result.failed == 1
    assert result.checks[0]["label"] == "Observability v8 effective plan"


def test_doctor_v8_renders_bounded_live_health_and_never_raw_error_text() -> None:
    from defenseclaw.commands.cmd_doctor import (
        _check_observability_v8_status,
        _DoctorResult,
    )

    status = V8OperatorStatus(
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=30,
        local_path="/tmp/audit.db",
        judge_bodies_path="/tmp/judge.db",
        destinations=(
            V8DestinationStatus(
                name="collector",
                kind="otlp",
                enabled=True,
                generated=False,
                capabilities=("logs", "traces", "metrics"),
                selected_signals=("logs", "traces", "metrics"),
                policy_form="capability_default",
                endpoint="https://collector.example.test",
                route_count=1,
                buckets=("platform.health",),
                redaction_profiles=("none",),
                queue_max_items=2048,
                queue_max_bytes=67_108_864,
                export_batch_max_items=512,
                export_batch_max_bytes=8_388_608,
                scheduled_delay_ms=5000,
            ),
        ),
        buckets=(V8BucketStatus("platform.health", ("logs", "traces", "metrics"), "none"),),
        warnings=(),
        judge_bodies_enabled=False,
    )
    result = _DoctorResult()
    _check_observability_v8_status(
        status,
        result,
        live_health={
            "telemetry": {
                "last_error": "Authorization Bearer must-not-render",
                "details": {
                    "destinations": [
                        {
                            "name": "collector",
                            "state": "degraded",
                            "reason": "queue_full",
                            "queue_items": 2,
                            "max_queue_items": 10,
                            "last_failure": "2026-07-06T12:00:00Z",
                            "last_error_class": "retryable_delivery",
                            "last_error": "must-not-render",
                        }
                    ],
                    "retention_state": "degraded",
                    "retention_failure": "run_failed",
                },
            }
        },
    )

    checks = {item["label"]: item for item in result.checks}
    assert checks["Judge-body store"]["detail"] == ("capture=disabled; retention=30 days; path=/tmp/judge.db")
    destination = checks["Destination: collector"]
    assert destination["status"] == "warn"
    assert "health=degraded/queue_full" in destination["detail"]
    assert "limits=queue=2048 items/64.0 MiB; batch=512 items/8.0 MiB; delay=5000ms" in destination["detail"]
    assert "queue=2/10 items" in destination["detail"]
    assert "last=error 2026-07-06T12:00:00Z (retryable_delivery)" in destination["detail"]
    assert checks["Retention controller"] == {
        "status": "warn",
        "label": "Retention controller",
        "detail": "degraded; failure=run_failed",
    }
    assert "must-not-render" not in repr(result.checks)


def test_doctor_enabled_galileo_emits_and_renders_real_runtime_canary() -> None:
    from defenseclaw.commands.cmd_doctor import (
        _check_galileo_trace_canaries,
        _DoctorResult,
    )
    from defenseclaw.observability.trace_canary import TraceCanaryResult

    destination = V8DestinationStatus(
        name="galileo",
        kind="otlp",
        enabled=True,
        generated=False,
        capabilities=("traces",),
        selected_signals=("traces",),
        policy_form="capability_default",
        endpoint="https://api.galileo.ai/otel/traces",
        route_count=1,
        buckets=("agent.lifecycle", "model.io"),
        redaction_profiles=("none",),
        preset="galileo",
    )
    result = _DoctorResult()
    with patch(
        "defenseclaw.observability.trace_canary.run_trace_canary",
        return_value=TraceCanaryResult(
            destination="galileo",
            trace_id="0123456789abcdef0123456789abcdef",
            generation=12,
            acknowledged=True,
        ),
    ) as canary:
        _check_galileo_trace_canaries(
            SimpleNamespace(destinations=(destination,)),
            result,
            config_path="/data/config.yaml",
            data_dir="/data",
        )

    canary.assert_called_once_with(
        destination="galileo",
        config_path="/data/config.yaml",
        data_dir="/data",
        timeout=15.0,
    )
    assert result.checks == [
        {
            "status": "pass",
            "label": "Galileo canary: galileo",
            "detail": ("acknowledged; trace_id=0123456789abcdef0123456789abcdef; generation=12"),
        }
    ]


def test_doctor_observability_dispatches_canary_from_compiled_galileo_preset(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_doctor import _check_observability, _DoctorResult
    from defenseclaw.observability.trace_canary import TraceCanaryResult

    config_path = tmp_path / "config.yaml"
    status = V8OperatorStatus(
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=30,
        local_path=str(tmp_path / "audit.db"),
        judge_bodies_path="",
        destinations=(
            V8DestinationStatus(
                name="galileo",
                kind="otlp",
                enabled=True,
                generated=False,
                capabilities=("traces",),
                selected_signals=("traces",),
                policy_form="capability_default",
                endpoint="https://api.galileo.ai/otel/traces",
                route_count=1,
                buckets=("agent.lifecycle", "model.io"),
                redaction_profiles=("none",),
                preset="galileo",
            ),
        ),
        buckets=(),
        warnings=(),
    )
    result = _DoctorResult()
    with (
        patch(
            "defenseclaw.observability.v8_status.inspect_v8_operator_status",
            return_value=status,
        ),
        patch(
            "defenseclaw.observability.trace_canary.run_trace_canary",
            return_value=TraceCanaryResult(
                destination="galileo",
                trace_id="0123456789abcdef0123456789abcdef",
                generation=2,
                acknowledged=True,
            ),
        ) as canary,
    ):
        _check_observability(SimpleNamespace(data_dir=str(tmp_path)), result)

    canary.assert_called_once_with(
        destination="galileo",
        config_path=str(config_path),
        data_dir=str(tmp_path),
        timeout=15.0,
    )
    assert any(item["label"] == "Galileo canary: galileo" for item in result.checks)


def test_doctor_galileo_canary_fails_safely_and_skips_disabled_routes() -> None:
    from defenseclaw.commands.cmd_doctor import (
        _check_galileo_trace_canaries,
        _DoctorResult,
    )
    from defenseclaw.observability.trace_canary import TraceCanaryError

    enabled = V8DestinationStatus(
        name="galileo-security",
        kind="otlp",
        enabled=True,
        generated=False,
        capabilities=("traces",),
        selected_signals=("traces",),
        policy_form="capability_default",
        endpoint="https://api.galileo.ai/otel/traces",
        route_count=1,
        buckets=("agent.lifecycle", "model.io"),
        redaction_profiles=("none",),
        preset="galileo",
    )
    disabled = replace(enabled, name="galileo-disabled", enabled=False)
    result = _DoctorResult()
    with patch(
        "defenseclaw.observability.trace_canary.run_trace_canary",
        side_effect=TraceCanaryError("gateway_rejected"),
    ) as canary:
        _check_galileo_trace_canaries(
            SimpleNamespace(destinations=(enabled, disabled)),
            result,
            config_path="/data/config.yaml",
            data_dir="/data",
        )

    assert canary.call_count == 1
    assert result.checks == [
        {
            "status": "fail",
            "label": "Galileo canary: galileo-security",
            "detail": ("gateway_rejected: the running gateway did not acknowledge the destination canary"),
        }
    ]


def test_doctor_caps_automatic_galileo_canaries_and_warns_for_remaining_routes() -> None:
    from defenseclaw.commands.cmd_doctor import (
        _check_galileo_trace_canaries,
        _DoctorResult,
    )
    from defenseclaw.observability.trace_canary import TraceCanaryResult

    template = V8DestinationStatus(
        name="galileo-0",
        kind="otlp",
        enabled=True,
        generated=False,
        capabilities=("traces",),
        selected_signals=("traces",),
        policy_form="capability_default",
        endpoint="https://api.galileo.ai/otel/traces",
        route_count=1,
        buckets=("agent.lifecycle", "model.io"),
        redaction_profiles=("none",),
        preset="galileo",
    )
    enabled = tuple(replace(template, name=f"galileo-{index}") for index in range(6))
    disabled = replace(template, name="galileo-disabled", enabled=False)
    non_galileo = replace(template, name="generic-otlp", preset="")
    result = _DoctorResult()

    def acknowledge(**kwargs):
        return TraceCanaryResult(
            destination=kwargs["destination"],
            trace_id="0123456789abcdef0123456789abcdef",
            generation=3,
            acknowledged=True,
        )

    with patch(
        "defenseclaw.observability.trace_canary.run_trace_canary",
        side_effect=acknowledge,
    ) as canary:
        _check_galileo_trace_canaries(
            SimpleNamespace(destinations=(*enabled, disabled, non_galileo)),
            result,
            config_path="/data/config.yaml",
            data_dir="/data",
        )

    assert [call.kwargs["destination"] for call in canary.call_args_list] == [
        "galileo-0",
        "galileo-1",
        "galileo-2",
        "galileo-3",
    ]
    assert [item["label"] for item in result.checks] == [
        "Galileo canary: galileo-0",
        "Galileo canary: galileo-1",
        "Galileo canary: galileo-2",
        "Galileo canary: galileo-3",
        "Galileo canary coverage",
    ]
    assert result.checks[-1] == {
        "status": "warn",
        "label": "Galileo canary coverage",
        "detail": ("untested=2; automatic_limit=4; remaining enabled routes retain bounded runtime-health checks"),
    }
