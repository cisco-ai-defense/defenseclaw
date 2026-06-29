# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json

import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_galileo import (
    _canary_request,
    _resolve_trace_endpoint,
    _validate_https_endpoint,
    galileo,
)
from defenseclaw.context import AppContext
from defenseclaw.observability import apply_preset


def _app(tmp_path, monkeypatch) -> AppContext:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    # Keep gateway-token precedence tests hermetic when the developer running
    # the suite already has a live sidecar token in their shell.
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    monkeypatch.delenv("OPENCLAW_GATEWAY_TOKEN", raising=False)
    (tmp_path / "config.yaml").write_text("claw:\n  mode: openclaw\n")
    from defenseclaw import config

    app = AppContext()
    app.cfg = config.load()
    return app


def test_cloud_non_interactive_writes_named_trace_destination(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "test-key")
    result = CliRunner().invoke(
        galileo,
        [
            "--non-interactive",
            "--project",
            "defenseclaw-tests",
            "--logstream",
            "default",
            "--persist-api-key",
        ],
        obj=app,
    )
    assert result.exit_code == 0, result.output
    assert "Action:      ADD" in result.output

    raw = yaml.safe_load((tmp_path / "config.yaml").read_text())
    destinations = raw["otel"]["destinations"]
    assert [d["name"] for d in destinations] == ["galileo"]
    destination = destinations[0]
    assert destination["endpoint"] == "https://api.galileo.ai/otel/traces"
    assert destination["headers"] == {
        "Galileo-API-Key": "${GALILEO_API_KEY}",
        "project": "defenseclaw-tests",
        "logstream": "default",
    }
    assert destination["traces"]["enabled"] is True
    assert destination["metrics"]["enabled"] is False
    assert destination["logs"]["enabled"] is False
    assert destination["batch"]["scheduled_delay_ms"] == 1000
    assert destination["span_filter"]["operations"] == [
        {
            "name": "chat",
            "require_attributes": [
                "gen_ai.operation.name",
                "gen_ai.provider.name",
                "gen_ai.request.model",
                "gen_ai.input.messages",
                "gen_ai.output.messages",
            ],
        },
        {
            "name": "invoke_agent",
            "require_attributes": [
                "gen_ai.operation.name",
                "gen_ai.agent.name",
                "gen_ai.provider.name",
                "openinference.span.kind",
                "gen_ai.input.messages",
                "gen_ai.output.messages",
            ],
        },
        {
            "name": "execute_tool",
            "require_attributes": [
                "gen_ai.operation.name",
                "gen_ai.tool.name",
                "openinference.span.kind",
                "gen_ai.tool.call.arguments",
                "gen_ai.tool.call.result",
                "gen_ai.input.messages",
                "gen_ai.output.messages",
            ],
        },
    ]
    assert "test-key" not in (tmp_path / "config.yaml").read_text()
    assert "test-key" in (tmp_path / ".env").read_text()

    # The modeled Python config must preserve the named destination across a
    # later unrelated Config.save() call.
    from defenseclaw import config

    reloaded = config.load()
    reloaded.save()
    after_save = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert [d["name"] for d in after_save["otel"]["destinations"]] == ["galileo"]
    assert after_save["otel"]["destinations"][0]["span_filter"] == destination["span_filter"]
    assert "enabled" not in (after_save["otel"].get("traces") or {})
    assert "enabled" not in (after_save["otel"].get("logs") or {})
    assert "enabled" not in (after_save["otel"].get("metrics") or {})


def test_rerun_reports_update_without_duplicating_destination(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "test-key")
    args = ["--non-interactive", "--project", "p", "--logstream", "l"]

    first = CliRunner().invoke(galileo, args, obj=app)
    assert first.exit_code == 0, first.output
    second = CliRunner().invoke(galileo, args, obj=app)
    assert second.exit_code == 0, second.output
    assert "Action:      UPDATE" in second.output
    assert "overwriting existing OTel destination 'galileo'" in second.output

    raw = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert [item["name"] for item in raw["otel"]["destinations"]] == ["galileo"]


def test_status_json_redacts_api_key(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "do-not-print")
    setup = CliRunner().invoke(
        galileo,
        ["--non-interactive", "--project", "p", "--logstream", "l"],
        obj=app,
    )
    assert setup.exit_code == 0, setup.output
    status = CliRunner().invoke(galileo, ["status", "--json"], obj=app)
    assert status.exit_code == 0, status.output
    payload = json.loads(status.output)
    assert payload["configured"] is True
    assert payload["api_key"] == "configured"
    assert "do-not-print" not in status.output


def test_self_hosted_endpoint_derivation() -> None:
    assert (
        _resolve_trace_endpoint("self-hosted", "https://console.galileo.example.com", None)
        == "https://api.galileo.example.com/otel/traces"
    )
    assert (
        _resolve_trace_endpoint("self-hosted", "https://console-galileo.apps.example.com/platform", None)
        == "https://api-galileo.apps.example.com/platform/otel/traces"
    )


def test_trace_endpoint_rejects_userinfo() -> None:
    import click
    import pytest

    with pytest.raises(click.ClickException, match="credential-free https"):
        _validate_https_endpoint("https://user:password@api.galileo.example/otel/traces")

    for endpoint in (
        "https://api.galileo.example/otel/traces?token=secret",
        "https://api.galileo.example/otel/traces#secret",
        "https://:443/otel/traces",
    ):
        with pytest.raises(click.ClickException, match="without query or fragment"):
            _validate_https_endpoint(endpoint)


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
    raw = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert "otel" not in raw


def test_canary_request_is_otlp_protobuf() -> None:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    trace_id, body = _canary_request()
    decoded = ExportTraceServiceRequest.FromString(body)
    span = decoded.resource_spans[0].scope_spans[0].spans[0]
    attributes = {item.key: item.value for item in span.attributes}
    assert trace_id == span.trace_id.hex()
    assert span.name == "defenseclaw.galileo.canary"
    assert span.kind == 3
    assert attributes["gen_ai.operation.name"].string_value == "chat"
    assert attributes["gen_ai.provider.name"].string_value == "openai"
    assert attributes["gen_ai.request.model"].string_value
    assert attributes["openinference.span.kind"].string_value == "LLM"
    assert attributes["gen_ai.input.messages"].string_value
    assert attributes["gen_ai.output.messages"].string_value
    assert len(bytes.fromhex(trace_id)) == 16


def test_management_commands_report_missing_destination_without_traceback(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    for args in (["enable"], ["disable"], ["remove", "--yes"]):
        result = CliRunner().invoke(galileo, args, obj=app)
        assert result.exit_code != 0
        assert "no destination named 'galileo'" in result.output
        assert "Traceback" not in result.output


def test_non_interactive_requires_secret(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.delenv("GALILEO_API_KEY", raising=False)
    result = CliRunner().invoke(
        galileo,
        ["--non-interactive", "--project", "p", "--logstream", "l"],
        obj=app,
    )
    assert result.exit_code != 0
    assert "GALILEO_API_KEY is not set" in result.output
    assert not (tmp_path / ".env").exists()


def test_canary_revalidates_persisted_endpoint_before_sending_secret(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "do-not-forward")
    (tmp_path / "config.yaml").write_text(
        """\
otel:
  enabled: true
  destinations:
    - name: galileo
      preset: galileo
      enabled: true
      protocol: http
      endpoint: http://collector.example.test/otel/traces
      headers:
        Galileo-API-Key: ${GALILEO_API_KEY}
        project: p
        logstream: l
      traces:
        enabled: true
      metrics:
        enabled: false
      logs:
        enabled: false
"""
    )

    result = CliRunner().invoke(galileo, ["test"], obj=app)
    assert result.exit_code != 0
    assert "must be credential-free https://" in result.output
    assert "do-not-forward" not in result.output


def test_canary_uses_runtime_gateway_path_by_default(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("GALILEO_API_KEY", "galileo-secret")
    setup = CliRunner().invoke(
        galileo,
        ["--non-interactive", "--project", "p", "--logstream", "l"],
        obj=app,
    )
    assert setup.exit_code == 0, setup.output
    app.cfg.gateway.token = "gateway-secret"
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps(
                {
                    "trace_id": "1" * 32,
                    "acknowledged": True,
                    "delivery": {"attempted": 2, "delivered": 2, "rejected": 0, "failed": 0},
                }
            ).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.headers.get("Authorization")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = CliRunner().invoke(galileo, ["test"], obj=app)
    assert result.exit_code == 0, result.output
    assert captured["url"].endswith("/api/v1/telemetry/canary")
    assert captured["authorization"] == "Bearer gateway-secret"
    assert "runtime trace" in result.output
    assert "gateway-secret" not in result.output
    assert "galileo-secret" not in result.output


def test_disabling_splunk_does_not_disable_galileo(tmp_path, monkeypatch) -> None:
    app = _app(tmp_path, monkeypatch)
    apply_preset(
        "galileo",
        {
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "p",
            "logstream": "l",
        },
        str(tmp_path),
    )
    apply_preset(
        "splunk-o11y",
        {"realm": "us1"},
        str(tmp_path),
        name="splunk-cloud",
    )

    from defenseclaw.commands.cmd_setup import _disable_splunk

    _disable_splunk(app, True, False, False, True)
    raw = yaml.safe_load((tmp_path / "config.yaml").read_text())
    destinations = {d["name"]: d for d in raw["otel"]["destinations"]}
    assert raw["otel"]["enabled"] is True
    assert destinations["galileo"]["enabled"] is True
    assert destinations["splunk-cloud"]["enabled"] is False


def test_splunk_status_lists_every_named_destination(
    tmp_path, monkeypatch, capsys
) -> None:
    app = _app(tmp_path, monkeypatch)
    apply_preset("splunk-o11y", {"realm": "us1"}, str(tmp_path), name="splunk-us1")
    apply_preset("splunk-o11y", {"realm": "eu0"}, str(tmp_path), name="splunk-eu0")

    from defenseclaw import config
    from defenseclaw.commands.cmd_setup import _print_splunk_status

    app.cfg = config.load()
    _print_splunk_status(app)
    output = capsys.readouterr().out
    assert "Splunk Observability Cloud (OTLP) [splunk-us1]" in output
    assert "Splunk Observability Cloud (OTLP) [splunk-eu0]" in output
    assert "Realm:       us1" in output
    assert "Realm:       eu0" in output
