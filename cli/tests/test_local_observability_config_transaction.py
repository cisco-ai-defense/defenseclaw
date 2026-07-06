# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Readiness-before-config and byte-exact rollback regressions."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from click.testing import CliRunner
from defenseclaw import config
from defenseclaw.context import AppContext
from defenseclaw.observability.local_stack import CONTRACT, LocalStackError, UpResult


def _app(data_dir: Path) -> AppContext:
    data_dir.mkdir()
    app = AppContext()
    app.cfg = config.Config(data_dir=str(data_dir))
    return app


def _controller(*, ready: bool = True) -> MagicMock:
    controller = MagicMock()
    controller.up.return_value = UpResult(dict(CONTRACT), readiness_verified=ready)
    return controller


def test_no_wait_never_enables_otlp(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    app = _app(tmp_path / "state")
    config_path = Path(app.cfg.data_dir) / "config.yaml"
    original = b"config_version: 4\ncustom: keep-me\n"
    config_path.write_bytes(original)
    controller = _controller(ready=False)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ),
        patch(
            "defenseclaw.commands.cmd_setup_local_observability"
            "._apply_local_observability_config_transaction"
        ) as apply_config,
    ):
        result = CliRunner().invoke(
            local_observability,
            ["up", "--no-wait", "--no-refresh-bundle"],
            obj=app,
        )
    assert result.exit_code == 0, result.output
    assert "config.yaml was not changed" in result.output
    assert config_path.read_bytes() == original
    apply_config.assert_not_called()


def test_readiness_failure_leaves_config_hash_unchanged(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    app = _app(tmp_path / "state")
    config_path = Path(app.cfg.data_dir) / "config.yaml"
    original = b"config_version: 4\notel:\n  enabled: false\ncustom: keep-me\n"
    config_path.write_bytes(original)
    before = hashlib.sha256(original).hexdigest()
    controller = _controller()
    controller.up.side_effect = LocalStackError("readiness timeout after 2s")
    with patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
        return_value=controller,
    ):
        result = CliRunner().invoke(
            local_observability,
            ["up", "--no-refresh-bundle"],
            obj=app,
        )
    assert result.exit_code != 0
    assert "readiness timeout" in result.output
    assert hashlib.sha256(config_path.read_bytes()).hexdigest() == before


def test_transaction_validation_failure_preserves_exact_bytes(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    app = _app(tmp_path / "state")
    config_path = Path(app.cfg.data_dir) / "config.yaml"
    original = (
        b"config_version: 4\r\n"
        b"custom: keep-me\r\n"
        b"audit_sinks:\r\n"
        b"  - name: remote\r\n"
        b"    kind: webhook\r\n"
        b"    url: https://example.test/events\r\n"
    )
    config_path.write_bytes(original)
    controller = _controller()

    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ),
        patch(
            "defenseclaw.observability.writer._apply_audit_sink_preset",
            side_effect=ValueError("conflicting sink"),
        ),
    ):
        result = CliRunner().invoke(
            local_observability,
            ["up", "--no-refresh-bundle"],
            obj=app,
        )
    assert result.exit_code != 0
    assert "config.yaml is unchanged" in result.output
    assert config_path.read_bytes() == original


def test_success_preserves_unrelated_destination_semantics(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    app = _app(tmp_path / "state")
    config_path = Path(app.cfg.data_dir) / "config.yaml"
    config_path.write_text(
        """config_version: 4
otel:
  destinations:
    - name: remote-otlp
      kind: otlp
      enabled: true
      endpoint: collector.example.test:4317
      protocol: grpc
      signals: [traces]
audit_sinks:
  - name: remote-webhook
    kind: webhook
    enabled: true
    url: https://example.test/events
""",
        encoding="utf-8",
    )
    controller = _controller()
    with patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
        return_value=controller,
    ):
        result = CliRunner().invoke(
            local_observability,
            ["up", "--no-refresh-bundle"],
            obj=app,
        )
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    destinations = {item["name"]: item for item in raw["otel"]["destinations"]}
    sinks = {item["name"]: item for item in raw["audit_sinks"]}
    assert destinations["remote-otlp"]["endpoint"] == "collector.example.test:4317"
    assert destinations["local-observability"]["enabled"] is True
    assert sinks["remote-webhook"]["url"] == "https://example.test/events"
    assert sinks["local-otlp-logs"]["enabled"] is True
