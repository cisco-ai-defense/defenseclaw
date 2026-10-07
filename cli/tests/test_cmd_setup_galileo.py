# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_galileo import (
    _resolve_trace_endpoint,
    _validate_https_endpoint,
    galileo,
)
from defenseclaw.context import AppContext
from defenseclaw.observability.trace_canary import TraceCanaryError, TraceCanaryResult
from defenseclaw.observability.v8_status import V8DestinationStatus


def _app(tmp_path, monkeypatch) -> AppContext:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("GALILEO_API_KEY", raising=False)
    (tmp_path / "config.yaml").write_text(
        "# operator comment\nconfig_version: 8\nobservability:\n  destinations: []\n",
        encoding="utf-8",
    )
    app = AppContext()
    app.cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        gateway=SimpleNamespace(api_bind="127.0.0.1", api_port=18970),
    )
    return app


def _status(*, configured: bool = False, enabled: bool = True):
    destinations = ()
    if configured:
        destinations = (
            V8DestinationStatus(
                name="galileo",
                kind="otlp",
                enabled=enabled,
                generated=False,
                capabilities=("traces",),
                selected_signals=("traces",),
                policy_form="capability_default",
                endpoint="https://api.galileo.ai/otel/traces",
                route_count=1,
                buckets=("*",),
                redaction_profiles=("none",),
                preset="galileo",
            ),
        )
    return SimpleNamespace(destinations=destinations)


def test_v8_setup_writes_trace_destination_and_secret_outside_yaml(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "must-never-print")
    arguments = [
        "--non-interactive",
        "--project",
        "defenseclaw-tests",
        "--logstream",
        "default",
        "--persist-api-key",
    ]
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status()),
        patch("defenseclaw.observability.v8_writer._validate_candidate"),
    ):
        result = CliRunner().invoke(galileo, arguments, obj=app)

    assert result.exit_code == 0, result.output
    assert "Action:      ADD" in result.output
    assert "Config:      config.yaml (changed)" in result.output  # GAP-0155: no retired version label
    assert "not saved" not in result.output
    source = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert "must-never-print" not in source + result.output
    assert "# operator comment" in source
    assert "must-never-print" in (tmp_path / ".env").read_text(encoding="utf-8")
    destination = yaml.safe_load(source)["observability"]["destinations"][0]
    assert destination == {
        "name": "galileo",
        "kind": "otlp",
        "enabled": True,
        "preset": "galileo",
        "endpoint": "https://api.galileo.ai/otel/traces",
        "protocol": "http/protobuf",
        "batch": {"scheduled_delay_ms": 1000},
        "headers": {
            "Galileo-API-Key": {"env": "GALILEO_API_KEY"},
            "project": "defenseclaw-tests",
            "logstream": "default",
        },
    }


def test_v8_setup_is_idempotent_and_reports_update(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "test-key")
    arguments = ["--non-interactive", "--project", "project", "--logstream", "stream"]
    with (
        patch(
            "defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status",
            side_effect=[_status(), _status(configured=True)],
        ),
        patch("defenseclaw.observability.v8_writer._validate_candidate"),
    ):
        first = CliRunner().invoke(galileo, arguments, obj=app)
        after_first = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        second = CliRunner().invoke(galileo, arguments, obj=app)

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert "Action:      ADD" in first.output
    # GAP-1299: an environment-only key is not saved; say so and how to fix it.
    assert "GALILEO_API_KEY was read from this shell and not saved" in first.output
    assert "defenseclaw keys set GALILEO_API_KEY" in first.output
    assert "Action:      UPDATE" in second.output
    assert "already configured" in second.output
    assert (tmp_path / "config.yaml").read_text(encoding="utf-8") == after_first


def test_v8_setup_rerun_removes_prior_generated_concise_send(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "test-key")
    (tmp_path / "config.yaml").write_text(
        """config_version: 8
observability:
  destinations:
    - name: galileo
      kind: otlp
      enabled: true
      preset: galileo
      endpoint: https://api.galileo.ai/otel/traces
      protocol: http/protobuf
      batch:
        scheduled_delay_ms: 1000
      headers:
        Galileo-API-Key:
          env: GALILEO_API_KEY
        project: old-project
        logstream: old-stream
      send:
        signals: [traces]
        buckets: ['*']
        redaction_profile: none
""",
        encoding="utf-8",
    )

    with (
        patch(
            "defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status",
            return_value=_status(configured=True),
        ),
        patch("defenseclaw.observability.v8_writer._validate_candidate"),
    ):
        result = CliRunner().invoke(
            galileo,
            ["--non-interactive", "--project", "new-project", "--logstream", "new-stream"],
            obj=app,
        )

    assert result.exit_code == 0, result.output
    destination = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))[
        "observability"
    ]["destinations"][0]
    assert "send" not in destination
    assert destination["headers"]["project"] == "new-project"
    assert destination["headers"]["logstream"] == "new-stream"


def test_v8_status_uses_masked_plan_and_sanitized_health(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "do-not-print")
    health = {
        "telemetry": {
            "details": {
                "destinations": [
                    {
                        "name": "galileo",
                        "state": "healthy",
                        "reason": "export_success",
                        "queue": {"items": 2, "max_items": 2048, "dropped": 0},
                        "last_success": "2026-07-06T12:00:00Z",
                        "last_error": "Bearer secret-value",
                        "headers": {"Galileo-API-Key": "secret-value"},
                    }
                ]
            }
        }
    }
    with (
        patch(
            "defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status",
            return_value=_status(configured=True),
        ),
        patch("defenseclaw.commands.cmd_setup_galileo._gateway_health_snapshot", return_value=health),
    ):
        result = CliRunner().invoke(galileo, ["status", "--json"], obj=app)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["config_version"] == 8
    assert payload["signals"] == {"traces": True, "metrics": False, "logs": False}
    assert payload["health"] == {
        "state": "healthy",
        "reason": "export_success",
        "queue_items": 2,
        "queue_max_items": 2048,
        "dropped": 0,
        "last_success": "2026-07-06T12:00:00Z",
    }
    assert payload["api_key"] == "configured"
    assert "secret-value" not in result.output
    assert "do-not-print" not in result.output


def test_v8_status_text_is_readable_and_names_next_step_when_failing(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "do-not-print")
    health = {
        "telemetry": {
            "details": {
                "destinations": [
                    {
                        "name": "galileo",
                        "state": "failing",
                        "reason": "circuit_open",
                        "queue": {"items": 0, "max_items": 2048, "dropped": 0},
                        "last_failure": "2026-10-02T05:03:18Z",
                        "last_error_class": "queue_rejected",
                    }
                ]
            }
        }
    }
    with (
        patch(
            "defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status",
            return_value=_status(configured=True),
        ),
        patch("defenseclaw.commands.cmd_setup_galileo._gateway_health_snapshot", return_value=health),
    ):
        result = CliRunner().invoke(galileo, ["status"], obj=app)

    assert result.exit_code == 0, result.output
    out = result.output
    assert "{" not in out and "True" not in out
    assert "Signals         traces" in out
    assert "Config version  8" in out
    assert "Health          failing (circuit_open)" in out
    assert "Queue           0 / 2048 items, 0 dropped" in out
    assert "Last failure    2026-10-02T05:03:18Z (queue_rejected)" in out
    assert "Next step:" in out and "defenseclaw setup galileo test" in out
    assert "do-not-print" not in out


@pytest.mark.parametrize(
    ("arguments", "helper", "expected"),
    [
        (["enable"], "_set_v8_destination_enabled", ("galileo", True)),
        (["disable"], "_set_v8_destination_enabled", ("galileo", False)),
        (["remove", "--yes"], "_remove_v8_destination", ("galileo",)),
    ],
)
def test_management_dispatches_to_canonical_mutators(
    tmp_path,
    monkeypatch,
    arguments: list[str],
    helper: str,
    expected: tuple,
) -> None:
    app = _app(tmp_path, monkeypatch)
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status(configured=True)),
        patch(f"defenseclaw.commands.cmd_setup_galileo.{helper}") as canonical,
    ):
        result = CliRunner().invoke(galileo, arguments, obj=app)

    assert result.exit_code == 0, result.output
    canonical.assert_called_once_with(app.cfg.data_dir, *expected)


def test_destination_test_uses_generation_owned_runtime_canary(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status(configured=True)),
        patch(
            "defenseclaw.commands.cmd_setup_galileo.run_trace_canary",
            return_value=TraceCanaryResult(
                destination="galileo",
                trace_id="0123456789abcdef0123456789abcdef",
                generation=4,
                acknowledged=True,
            ),
        ) as canary,
    ):
        result = CliRunner().invoke(galileo, ["test", "--timeout", "7"], obj=app)

    assert result.exit_code == 0, result.output
    canary.assert_called_once_with(
        destination="galileo",
        config_path=str(tmp_path / "config.yaml"),
        data_dir=app.cfg.data_dir,
        timeout=7.0,
    )
    assert "runtime canary acknowledged" in result.output
    assert "0123456789abcdef0123456789abcdef" in result.output
    assert "generation=4" in result.output


def test_destination_test_fails_safely_when_runtime_does_not_acknowledge(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status(configured=True)),
        patch(
            "defenseclaw.commands.cmd_setup_galileo.run_trace_canary",
            side_effect=TraceCanaryError("gateway_rejected"),
        ),
    ):
        result = CliRunner().invoke(galileo, ["test"], obj=app)

    assert result.exit_code != 0
    assert "gateway_rejected" in result.output
    assert "did not acknowledge" in result.output
    assert "--deployment self-hosted --trace-endpoint" in result.output


def test_destination_test_names_the_delivery_failure_the_gateway_recorded(tmp_path, monkeypatch) -> None:
    # GAP-1318: a DNS failure was reported with the API-key hint.
    from datetime import datetime, timedelta, timezone

    app = _app(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    # Date the config change a minute back: Windows can stamp the file just
    # after "now", which would hide this run's alerts.
    changed = (now - timedelta(minutes=1)).timestamp()
    os.utime(tmp_path / "config.yaml", (changed, changed))
    app.store = SimpleNamespace(
        list_alerts=lambda _limit: [
            SimpleNamespace(details="observability_runtime failed: reload_initialization_failed", timestamp=now),
            SimpleNamespace(details="galileo/traces failed: resolution_failed", timestamp=now),
            SimpleNamespace(details="galileo/traces failed: http_authentication", timestamp=now - timedelta(hours=2)),
        ]
    )
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status(configured=True)),
        patch(
            "defenseclaw.commands.cmd_setup_galileo.run_trace_canary",
            side_effect=TraceCanaryError("gateway_rejected"),
        ),
    ):
        result = CliRunner().invoke(galileo, ["test"], obj=app)

    assert result.exit_code != 0
    assert "export failure" in result.output and "resolution_failed" in result.output
    assert "check the endpoint and DNS" in result.output
    assert "API key" not in result.output


def test_destination_test_ignores_alerts_from_before_the_config_change_and_waits(tmp_path, monkeypatch) -> None:
    # GAP-1318 reopen: an alert from the previous config was named, and this
    # run's alert landed just after the CLI looked.
    import os
    from datetime import datetime, timedelta, timezone

    app = _app(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    os.utime(tmp_path / "config.yaml", (now.timestamp() - 60, now.timestamp() - 60))
    old = SimpleNamespace(details="galileo/traces failed: http_authentication", timestamp=now - timedelta(minutes=3))
    new = SimpleNamespace(details="galileo/traces failed: resolution_failed", timestamp=now)
    calls = []

    def list_alerts(_limit):
        calls.append(1)
        return [new, old] if len(calls) > 1 else [old]

    app.store = SimpleNamespace(list_alerts=list_alerts)
    monkeypatch.setattr("defenseclaw.commands.cmd_setup_galileo._GALILEO_ALERT_WAIT_SECONDS", 2.0)
    with (
        patch("defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status", return_value=_status(configured=True)),
        patch(
            "defenseclaw.commands.cmd_setup_galileo.run_trace_canary",
            side_effect=TraceCanaryError("gateway_rejected"),
        ),
    ):
        result = CliRunner().invoke(galileo, ["test"], obj=app)

    assert result.exit_code != 0
    assert "resolution_failed" in result.output and "http_authentication" not in result.output
    assert len(calls) >= 2


def test_destination_test_refuses_disabled_galileo_before_canary(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_galileo._require_v8_operator_status",
            return_value=_status(configured=True, enabled=False),
        ),
        patch("defenseclaw.commands.cmd_setup_galileo.run_trace_canary") as canary,
    ):
        result = CliRunner().invoke(galileo, ["test"], obj=app)

    assert result.exit_code != 0
    assert "Galileo is disabled" in result.output
    canary.assert_not_called()


def test_non_interactive_requires_secret_without_writing(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        galileo,
        ["--non-interactive", "--project", "p", "--logstream", "l"],
        obj=app,
    )
    assert result.exit_code != 0
    assert "GALILEO_API_KEY is not set" in result.output
    assert not (tmp_path / ".env").exists()


def test_project_and_logstream_reject_environment_expansion(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "test-key")
    result = CliRunner().invoke(
        galileo,
        ["--non-interactive", "--project", "${HOME}", "--logstream", "default"],
        obj=app,
    )
    assert result.exit_code != 0
    assert "must not contain '$'" in result.output
    assert yaml.safe_load((tmp_path / "config.yaml").read_text())["observability"]["destinations"] == []


def test_self_hosted_endpoint_derivation_and_validation() -> None:
    assert (
        _resolve_trace_endpoint("self-hosted", "https://console.galileo.example.com", None)
        == "https://api.galileo.example.com/otel/traces"
    )
    assert (
        _resolve_trace_endpoint("self-hosted", "https://console-galileo.apps.example.com/platform", None)
        == "https://api-galileo.apps.example.com/platform/otel/traces"
    )
    with pytest.raises(click.ClickException, match="credential-free https"):
        _validate_https_endpoint("https://user:password@api.galileo.example/otel/traces")
    for endpoint in (
        "https://api.galileo.example/otel/traces?token=secret",
        "https://api.galileo.example/otel/traces#secret",
        "https://:443/otel/traces",
    ):
        with pytest.raises(click.ClickException, match="without query or fragment"):
            _validate_https_endpoint(endpoint)
