# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""No part of a webhook secret reaches a payload preview, whatever it holds (rel-1-0-4 GAP-0579).

``W4_PD_KEY='ab"cdSECRETTAIL' defenseclaw setup webhook test pd-prod --dry-run``
printed ``"routing_key": "<redacted>"cdSECRETTAIL",...``: the preview regex
stopped at the escaped quote in the encoded key, and the literal-secret sweep
looked for the raw key, which the encoded body does not hold.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_webhook import webhook
from defenseclaw.context import AppContext
from defenseclaw.webhooks.dispatch import format_pagerduty_payload, send_synthetic, synthetic_event

_TAIL = "SECRETTAIL"

# Each key ends in the same tail so the test can look for any piece of it.
_KEYS = [
    pytest.param('ab"cd' + _TAIL, id="quote"),
    pytest.param("ab\\cd" + _TAIL, id="backslash"),
    pytest.param('ab\\"cd' + _TAIL, id="backslash-quote"),
    pytest.param("ab\ncd" + _TAIL, id="newline"),
    pytest.param("ab\tcd\x01" + _TAIL, id="control"),
    pytest.param("abé cd" + _TAIL, id="unicode"),
    pytest.param('"}, "x": "' + _TAIL, id="json-breakout"),
    pytest.param("S" * 500 + _TAIL, id="overlong"),
    pytest.param("Rk7QwXzPmN2vT9sLhY4cJ8gF6dB3nV1x", id="plain-32"),
]


def _fragments(secret: str) -> list[str]:
    # Every 6-character piece of the key, raw and as JSON writes it.
    encoded = json.dumps(secret, ensure_ascii=False)[1:-1]
    return sorted({text[i : i + 6] for text in (secret, encoded) for i in range(len(text) - 5)} - {"SSSSSS"})


def _assert_no_part_of(secret: str, text: str) -> None:
    leaked = [piece for piece in _fragments(secret) if piece in text]
    assert not leaked, (leaked, text)


@pytest.mark.parametrize("secret", _KEYS)
def test_the_pagerduty_payload_is_valid_json_for_any_routing_key(secret):
    body = format_pagerduty_payload(synthetic_event(), secret)
    assert json.loads(body.decode("utf-8"))["routing_key"] == secret


@pytest.mark.parametrize("secret", _KEYS)
def test_the_preview_redacts_the_whole_routing_key(secret):
    result = send_synthetic(
        webhook_type="pagerduty",
        url="https://events.pagerduty.com/v2/enqueue",
        secret=secret,
        preview_only=True,
    )
    assert result.request_body_preview.startswith('{"routing_key":"<redacted>","event_action":"trigger",')
    _assert_no_part_of(secret, result.request_body_preview)
    _assert_no_part_of(secret, json.dumps(result.request_headers))


@pytest.mark.parametrize("webhook_type", ["generic", "webex", "slack"])
@pytest.mark.parametrize("secret", _KEYS)
def test_a_secret_in_any_payload_text_is_redacted(webhook_type, secret):
    event = synthetic_event(details=f"operator pasted {secret} here")
    result = send_synthetic(
        webhook_type=webhook_type,
        url="https://ops.example.com/hooks",
        secret=secret,
        room_id="room",
        event=event,
        preview_only=True,
    )
    _assert_no_part_of(secret, result.request_body_preview)


@pytest.mark.parametrize("secret", _KEYS)
def test_webhook_test_dry_run_prints_no_part_of_the_routing_key(tmp_path, monkeypatch, secret):
    monkeypatch.setenv("W4_PD_KEY", secret)
    view = SimpleNamespace(
        name="pd-prod",
        type="pagerduty",
        url="https://events.pagerduty.com/v2/enqueue",
        secret_env="W4_PD_KEY",
        room_id="",
        min_severity="HIGH",
    )
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    with patch("defenseclaw.commands.cmd_setup_webhook.list_webhooks", return_value=[view]):
        result = CliRunner().invoke(webhook, ["test", "pd-prod", "--dry-run"], obj=app)
    assert result.exit_code == 0, result.output
    assert '"routing_key":"<redacted>"' in result.output
    _assert_no_part_of(secret, result.output)
