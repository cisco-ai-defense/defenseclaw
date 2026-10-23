# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Webhook test payloads and scoped setup must behave like the runtime."""

import hashlib
import hmac
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_webhook import _apply_webhook_to_connector, webhook
from defenseclaw.context import AppContext
from defenseclaw.webhooks import apply_webhook, list_webhooks, send_synthetic


def test_synthetic_hmac_payload_attributes_the_sending_host(monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
    monkeypatch.setattr("defenseclaw.webhooks.dispatch.socket.gethostname", lambda: "test-workstation")
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.getcode.return_value = 200
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr("defenseclaw.webhooks.dispatch.urllib.request.build_opener", lambda *a: opener)
    key = "synthetic HMAC fixture"
    ids = set()
    for _ in range(2):
        result = send_synthetic(webhook_type="generic", url="http://127.0.0.1/events", secret=key)
        assert result.ok
        request = opener.open.call_args.args[0]
        event = json.loads(request.data)["event"]
        assert event["host"] == "test-workstation"
        ids.add(event["id"])
        signature = "sha256=" + hmac.new(key.encode(), request.data, hashlib.sha256).hexdigest()
        assert request.get_header("X-hub-signature-256") == signature
    assert len(ids) == 2


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("name", [None, "scoped-local"])
def test_scoped_add_ignores_global_webhook_identity(tmp_path, monkeypatch, dry_run, name):
    monkeypatch.setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
    data_dir = str(tmp_path)
    url = "http://127.0.0.1/events"
    apply_webhook(name="global-local", type_="generic", url=url, data_dir=data_dir, enabled=False)
    result = _apply_webhook_to_connector(
        data_dir, "codex", name=name, type_="generic", url=url,
        secret_env=None, room_id=None, min_severity=None, events=None,
        timeout_seconds=None, cooldown_seconds=None, enabled=False, dry_run=dry_run,
    )
    assert result.warnings == []
    assert result.name == (name or "generic-127-0-0-1")
    assert [entry.name for entry in list_webhooks(data_dir)] == ["global-local"]


@pytest.mark.parametrize("dry_run", [False, True])
def test_pagerduty_missing_key_is_a_cli_error(tmp_path, monkeypatch, dry_run):
    monkeypatch.delenv("W4_PD_KEY", raising=False)
    view = SimpleNamespace(name="pd", type="pagerduty", url="https://events.pagerduty.com/v2/enqueue",
                           secret_env="W4_PD_KEY", room_id="", min_severity="HIGH")
    monkeypatch.setattr("defenseclaw.commands.cmd_setup_webhook.list_webhooks", lambda *a: [view])
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    result = CliRunner().invoke(webhook, ["test", "pd"] + (["--dry-run"] if dry_run else []), obj=app)
    assert result.exit_code == 2, result.output
    assert "W4_PD_KEY" in result.output and "unset" in result.output
    assert "--dry-run" not in result.output
    assert not isinstance(result.exception, ValueError)


def test_show_keeps_secret_url_parts_redacted(tmp_path, monkeypatch):
    view = SimpleNamespace(name="siem", type="generic", url="https://siem.example.com/private-path?key=fixture",
                           secret_env="", room_id="", min_severity="HIGH", events=[],
                           timeout_seconds=10, cooldown_seconds=None, enabled=True)
    monkeypatch.setattr("defenseclaw.commands.cmd_setup_webhook.list_webhooks", lambda *a: [view])
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    for args in [["show", "siem"], ["show", "siem", "--json"]]:
        result = CliRunner().invoke(webhook, args, obj=app)
        assert result.exit_code == 0, result.output
        assert "https://siem.example.com/***" in result.output
        assert "private-path" not in result.output and "fixture" not in result.output
