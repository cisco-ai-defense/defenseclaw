# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Security regressions for the connector / webhook / observability fixes.

One focused test per finding (F-0041, F-0402, F-0403, F-0404, F-0441,
F-0443, F-0221, F-0181, F-0184, F-0186, F-0187, F-0261). Each test
reproduces the pre-fix exploit shape and asserts the patched behaviour:
the secret never crosses the trust boundary and symlink/predictable-temp
tricks no longer redirect or clobber files.
"""

from __future__ import annotations

import json
import os
import stat

import click
import pytest
from defenseclaw.commands.cmd_agent import _resolve_gateway_target
from defenseclaw.commands.cmd_config import _config_to_masked_dict
from defenseclaw.commands.cmd_setup_splunk_o11y_dashboards import _validate_api_url
from defenseclaw.commands.cmd_setup_webhook import _view_to_dict
from defenseclaw.config import OTelDestinationConfig, WebhookConfig, default_config
from defenseclaw.connector_paths import _atomic_json_merge
from defenseclaw.openclaw_guardrail import (
    _backup,
    _backup_index_path,
    _write_backup_index,
    record_pristine_backup,
)
from defenseclaw.webhooks import WebhookView
from defenseclaw.webhooks.dispatch import _redact_payload_preview
from defenseclaw.webhooks.writer import _write_yaml, redact_webhook_url

from tests.permissions import assert_owner_only_file


# ---------------------------------------------------------------------------
# F-0041 — connector_paths._atomic_json_merge must not follow a symlinked
# config path (else a planted .mcp.json symlink discloses its target).
# ---------------------------------------------------------------------------
def test_f0041_atomic_json_merge_refuses_symlinked_config(tmp_path):
    secret = tmp_path / "operator_private.json"
    secret.write_text(json.dumps({"private_token": "F0041_LEAK"}), encoding="utf-8")
    mcp = tmp_path / ".mcp.json"
    mcp.symlink_to(secret)

    with pytest.raises(ValueError, match="symlink"):
        _atomic_json_merge(str(mcp), ("mcpServers", "demo"), {"command": "uvx"})

    # The link was not rewritten and the private target is untouched.
    assert mcp.is_symlink()
    assert json.loads(secret.read_text(encoding="utf-8")) == {"private_token": "F0041_LEAK"}


# ---------------------------------------------------------------------------
# F-0402 — record_pristine_backup must reject a symlinked source instead of
# copying the link target into the (discoverable) backup dir.
# ---------------------------------------------------------------------------
def test_f0402_pristine_backup_rejects_symlinked_source(tmp_path):
    secret = tmp_path / "outside_secret.json"
    secret.write_text('{"aws_secret": "F0402_LEAK"}', encoding="utf-8")
    cfg_link = tmp_path / "openclaw.json"
    cfg_link.symlink_to(secret)
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    result = record_pristine_backup(str(cfg_link), str(data_dir))

    assert result is None
    # No pristine snapshot of the link target was written anywhere.
    pristines = [
        name
        for _root, _dirs, files in os.walk(data_dir)
        for name in files
        if name.endswith(".pristine")
    ]
    assert pristines == []


# ---------------------------------------------------------------------------
# F-0403 — _write_backup_index must not write through a predictable
# "<index>.tmp" path that an attacker can pre-symlink.
# ---------------------------------------------------------------------------
def test_f0403_backup_index_ignores_predictable_tmp_symlink(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    index = _backup_index_path(str(data_dir))

    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("SENTINEL", encoding="utf-8")
    # Plant the legacy predictable temp name as a symlink to the sentinel.
    os.symlink(sentinel, index + ".tmp")

    doc = {"version": 1, "entries": {"/x": {"pristine": "/y"}}}
    _write_backup_index(str(data_dir), doc)

    # Sentinel untouched; index written with the real content.
    assert sentinel.read_text(encoding="utf-8") == "SENTINEL"
    assert json.loads(open(index, encoding="utf-8").read()) == doc


# ---------------------------------------------------------------------------
# F-0404 — _backup must detect a *broken* symlink at "<path>.bak" (lexists)
# and never write through it to the attacker-chosen target.
# ---------------------------------------------------------------------------
def test_f0404_backup_does_not_write_through_broken_symlink(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("REAL_CONFIG", encoding="utf-8")
    redirect_target = tmp_path / "attacker-chosen-new-file"
    # Broken symlink: target does not exist yet.
    os.symlink(redirect_target, str(path) + ".bak")

    _backup(str(path))

    # The redirect target was never created (no write through the symlink).
    assert not redirect_target.exists()
    # A real backup landed in the rotated slot instead.
    rotated = tmp_path / "config.json.bak.1"
    assert rotated.is_file() and not rotated.is_symlink()
    assert rotated.read_text(encoding="utf-8") == "REAL_CONFIG"


# ---------------------------------------------------------------------------
# F-0441 — webhooks/writer._write_yaml must write 0600 via mkstemp and not
# follow a predictable "<path>.tmp" symlink.
# ---------------------------------------------------------------------------
def test_f0441_write_yaml_is_0600_and_ignores_tmp_symlink(tmp_path):
    target = tmp_path / "webhooks.yaml"
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("SENTINEL", encoding="utf-8")
    os.symlink(sentinel, str(target) + ".tmp")

    _write_yaml(str(target), {"webhooks": [{"name": "x"}]})

    if os.name == "nt":
        assert_owner_only_file(target)
    else:
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
    assert sentinel.read_text(encoding="utf-8") == "SENTINEL"
    assert "name: x" in target.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# F-0443 — _redact_payload_preview must redact a secret value even when it is
# longer than the preview window (redact-before-truncate).
# ---------------------------------------------------------------------------
def test_f0443_overlong_routing_key_is_redacted():
    secret = "S" * 500
    payload = json.dumps(
        {"routing_key": secret, "event_action": "trigger"},
    ).encode()

    preview = _redact_payload_preview(payload, "pagerduty", secret="")

    assert "S" * 20 not in preview
    assert "<redacted>" in preview


# ---------------------------------------------------------------------------
# F-0221 — config show (masked dict) must redact OTel header secrets and
# webhook URLs, not just suffix-matched secret fields.
# ---------------------------------------------------------------------------
def test_f0221_masked_dict_redacts_headers_and_webhook_urls():
    cfg = default_config()
    cfg.otel.destinations = [OTelDestinationConfig(
        name="test",
        headers={
            "Authorization": "Bearer F0221_OTEL_SECRET",
            "x-honeycomb-team": "F0221_HONEYCOMB_SECRET",
        },
    )]
    cfg.webhooks = [
        WebhookConfig(
            name="slack-alerts",
            type="slack",
            url="https://hooks.slack.com/services/T0/B0/F0221_SLACK_SECRET",
            enabled=True,
        ),
    ]

    masked = _config_to_masked_dict(cfg, reveal=False)
    blob = json.dumps(masked)

    assert "F0221_OTEL_SECRET" not in blob
    assert "F0221_HONEYCOMB_SECRET" not in blob
    assert "F0221_SLACK_SECRET" not in blob
    # The masked URL keeps the host for context but drops the secret path.
    assert "hooks.slack.com" in blob
    assert "***" in blob


# ---------------------------------------------------------------------------
# F-0181 — webhook list/show output (and shared helper) must redact the
# secret-bearing parts of webhook URLs.
# ---------------------------------------------------------------------------
def test_f0181_webhook_url_redaction():
    assert (
        redact_webhook_url("https://hooks.slack.com/services/T0/B0/secret")
        == "https://hooks.slack.com/***"
    )
    # userinfo and query secrets are stripped too.
    assert redact_webhook_url("https://user:pass@host.example/p?token=abc") == (
        "https://***@host.example/***?***"
    )

    view = WebhookView(
        name="poc",
        type="slack",
        url="https://hooks.slack.com/services/T0/B0/secret",
        secret_env="",
        room_id="",
        min_severity="HIGH",
        events=["block"],
        timeout_seconds=10,
        cooldown_seconds=None,
        enabled=True,
    )
    rendered = _view_to_dict(view)
    assert "secret" not in rendered["url"]
    assert rendered["url"] == "https://hooks.slack.com/***"


# ---------------------------------------------------------------------------
# F-0187 — an explicitly-supplied O11y api_url must pass the same allowlist
# before the X-SF-TOKEN is attached.
# ---------------------------------------------------------------------------
def test_f0187_api_url_allowlist():
    # Legitimate Splunk O11y API hosts are accepted and normalised.
    assert _validate_api_url("https://api.realm.signalfx.com") == "https://api.realm.signalfx.com"
    assert (
        _validate_api_url("https://api.us1.observability.splunkcloud.com/extra?x=1")
        == "https://api.us1.observability.splunkcloud.com"
    )

    # Attacker host, wrong scheme, and ingest (non-api) host are rejected.
    for bad in (
        "https://attacker.example",
        "http://api.realm.signalfx.com",
        "https://ingest.realm.signalfx.com",
        "https://api.realm.signalfx.com.evil.test",
    ):
        with pytest.raises(click.ClickException):
            _validate_api_url(bad)


# ---------------------------------------------------------------------------
# F-0261 — the gateway bearer token is only attached to a loopback target.
# ---------------------------------------------------------------------------
class _StubGateway:
    def __init__(self, host: str) -> None:
        self.host = host
        self.api_port = 18970
        self.token = ""
        self.token_env = ""

    def resolved_token(self) -> str:
        return "F0261_GATEWAY_TOKEN"


class _StubApp:
    def __init__(self, host: str) -> None:
        self.cfg = type("Cfg", (), {"gateway": _StubGateway(host)})()


def test_f0261_token_only_for_loopback(monkeypatch):
    for var in ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"):
        monkeypatch.delenv(var, raising=False)

    # Loopback → token preserved.
    _, _, token = _resolve_gateway_target(
        _StubApp("127.0.0.1"),
        gateway_host="127.0.0.1",
        gateway_port=None,
        gateway_token_env=None,
    )
    assert token == "F0261_GATEWAY_TOKEN"

    # Non-loopback (configured host or CLI override) → token withheld.
    for remote in ("203.0.113.66", "evil.example.com", "0.0.0.0"):
        _, _, token = _resolve_gateway_target(
            _StubApp(remote),
            gateway_host=remote,
            gateway_port=None,
            gateway_token_env=None,
        )
        assert token == "", f"token must be dropped for non-loopback host {remote!r}"
