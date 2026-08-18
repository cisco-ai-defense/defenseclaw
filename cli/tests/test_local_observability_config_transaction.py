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
    original = b"config_version: 8\nobservability:\n  local:\n    retention_days: 37\n"
    config_path.write_bytes(original)
    controller = _controller(ready=False)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ),
        patch("defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_config") as apply_config,
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
    original = b"config_version: 8\nobservability:\n  local:\n    retention_days: 37\n"
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
    original = b"config_version: 8\r\nobservability:\r\n  local:\r\n    retention_days: 37\r\n"
    config_path.write_bytes(original)
    controller = _controller()

    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=object(),
        ),
        patch(
            "defenseclaw.observability.v8_writer._validate_candidate",
            side_effect=RuntimeError("candidate rejected"),
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
        """config_version: 8
observability:
  local:
    retention_days: 37
  destinations:
    - name: remote-otlp
      kind: otlp
      enabled: true
      endpoint: https://collector.example.test
      protocol: grpc
      send:
        signals: [traces]
        buckets: ['*']
    - name: remote-webhook
      kind: http_jsonl
      enabled: true
      endpoint: https://example.test/events
      method: POST
""",
        encoding="utf-8",
    )
    controller = _controller()
    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
            return_value=controller,
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=object(),
        ),
        patch(
            "defenseclaw.observability.v8_writer._validate_candidate",
            return_value=None,
        ),
    ):
        result = CliRunner().invoke(
            local_observability,
            ["up", "--no-refresh-bundle"],
            obj=app,
        )
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    destinations = {item["name"]: item for item in raw["observability"]["destinations"]}
    assert destinations["remote-otlp"]["endpoint"] == "https://collector.example.test"
    assert destinations["local-observability"]["enabled"] is True
    assert destinations["remote-webhook"]["endpoint"] == "https://example.test/events"
    assert destinations["local-observability"]["send"]["signals"] == [
        "traces",
        "metrics",
        "logs",
    ]
    assert raw["observability"]["local"]["retention_days"] == 37
    assert raw["observability"]["resource"]["attributes"]["service.name"] == "defenseclaw"
