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

"""Tests for the ``defenseclaw.webhooks`` package.

Covers four slices the plan called out explicitly:

* ``writer.apply_webhook`` round-trip (per type) — config.yaml load/save
  is lossless and the cooldown tri-state survives.
* ``writer.validate_webhook_url`` SSRF guard — parity with
  ``internal/gateway/webhook.go::validateWebhookURL``.
* ``dispatch.format_*_payload`` structural parity with the Go
  formatters. Both emit compact JSON (no whitespace) and share an
  HMAC-SHA256 known vector; raw byte equality is not asserted
  because Go's ``encoding/json`` sorts map keys alphabetically while
  Python preserves insertion order. Drift in either codebase is
  still caught via the required-field invariants.
* ``cmd_doctor._check_webhooks`` — the doctor probe must NOT dispatch
  live events and must surface SSRF / missing-secret failures.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import _check_webhooks, _DoctorResult
from defenseclaw.config import Config
from defenseclaw.webhooks import (
    WebhookView,
    apply_webhook,
    compute_hmac,
    format_generic_payload,
    format_pagerduty_payload,
    format_slack_payload,
    format_webex_payload,
    list_webhooks,
    remove_webhook,
    send_synthetic,
    set_webhook_enabled,
    synthetic_event,
    validate_webhook_url,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fixed_event():
    return synthetic_event(
        action="webhook.test",
        target="synthetic-webhook",
        severity="HIGH",
        actor="defenseclaw-cli",
        details="Synthetic test event",
        event_id="synthetic-test-fixture",
        timestamp="2026-04-14T00:00:00Z",
    )


def _write_cfg(tmpdir: str, webhooks: list[dict] | None = None) -> None:
    cfg_path = os.path.join(tmpdir, "config.yaml")
    data: dict = {}
    if webhooks is not None:
        data["webhooks"] = webhooks
    with open(cfg_path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# writer.apply_webhook round-trip
# ---------------------------------------------------------------------------


class ApplyWebhookRoundTripTests(unittest.TestCase):
    def _run(self, type_: str, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            kwargs.setdefault("name", None)
            res = apply_webhook(data_dir=td, type_=type_, **kwargs)
            self.assertFalse(res.dry_run)
            views = list_webhooks(td)
            self.assertEqual(len(views), 1)
            return views[0], td

    def test_slack(self):
        v, _ = self._run(
            "slack",
            url="https://hooks.slack.com/services/T0/B0/xxx",
            events=["block", "scan"],
        )
        self.assertEqual(v.type, "slack")
        self.assertEqual(v.min_severity, "HIGH")
        self.assertEqual(v.events, ["block", "scan"])
        self.assertEqual(v.timeout_seconds, 10)
        self.assertIsNone(v.cooldown_seconds)
        self.assertTrue(v.enabled)

    def test_pagerduty_requires_secret_env(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            with self.assertRaises(ValueError) as cm:
                apply_webhook(
                    data_dir=td,
                    name=None,
                    type_="pagerduty",
                    url="https://events.pagerduty.com/v2/enqueue",
                )
            self.assertIn("secret-env", str(cm.exception))

    def test_pagerduty_with_secret(self):
        v, _ = self._run(
            "pagerduty",
            url="https://events.pagerduty.com/v2/enqueue",
            secret_env="PD_ROUTING_KEY",
        )
        self.assertEqual(v.type, "pagerduty")
        self.assertEqual(v.secret_env, "PD_ROUTING_KEY")

    def test_webex_requires_room_id(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            with self.assertRaises(ValueError) as cm:
                apply_webhook(
                    data_dir=td,
                    name=None,
                    type_="webex",
                    url="https://webexapis.com/v1/messages",
                    secret_env="WEBEX_BOT",
                )
            self.assertIn("room_id", str(cm.exception).lower().replace("-", "_"))

    def test_webex_happy_path(self):
        v, _ = self._run(
            "webex",
            url="https://webexapis.com/v1/messages",
            secret_env="WEBEX_BOT_TOKEN",
            room_id="Y2lzY29zcGFyazovL3VzL1JPT00v",
        )
        self.assertEqual(v.type, "webex")
        self.assertEqual(v.secret_env, "WEBEX_BOT_TOKEN")
        self.assertTrue(v.room_id)

    def test_generic_with_hmac(self):
        v, _ = self._run(
            "generic",
            url="https://ops.example.com/hooks",
            secret_env="OPS_HMAC_KEY",
        )
        self.assertEqual(v.type, "generic")
        self.assertEqual(v.secret_env, "OPS_HMAC_KEY")

    def test_cooldown_tristate_roundtrip(self):
        """None / 0 / >0 must survive load → save → load unchanged."""
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            apply_webhook(
                data_dir=td,
                name="a",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/aaa",
            )
            apply_webhook(
                data_dir=td,
                name="b",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/bbb",
                cooldown_seconds=0,
            )
            apply_webhook(
                data_dir=td,
                name="c",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/ccc",
                cooldown_seconds=45,
            )

            views = {v.name: v for v in list_webhooks(td)}
            self.assertIsNone(views["a"].cooldown_seconds)
            self.assertEqual(views["b"].cooldown_seconds, 0)
            self.assertEqual(views["c"].cooldown_seconds, 45)

            with open(os.path.join(td, "config.yaml")) as fh:
                raw = yaml.safe_load(fh)
            by_name = {e["name"]: e for e in raw["webhooks"]}
            self.assertNotIn(
                "cooldown_seconds", by_name["a"],
                "None cooldown must be omitted so Go uses its default",
            )
            self.assertEqual(by_name["b"]["cooldown_seconds"], 0)
            self.assertEqual(by_name["c"]["cooldown_seconds"], 45)

    def test_rejects_negative_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            with self.assertRaises(ValueError):
                apply_webhook(
                    data_dir=td,
                    name=None,
                    type_="slack",
                    url="https://hooks.slack.com/services/A/B/x",
                    cooldown_seconds=-1,
                )

    def test_update_existing_preserves_cooldown(self):
        """Editing other fields must NOT reset a previously-set cooldown."""
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            apply_webhook(
                data_dir=td,
                name="svc",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/xxx",
                cooldown_seconds=120,
            )
            apply_webhook(
                data_dir=td,
                name="svc",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/xxx",
                min_severity="CRITICAL",
            )
            views = list_webhooks(td)
            self.assertEqual(len(views), 1)
            self.assertEqual(views[0].cooldown_seconds, 120)
            self.assertEqual(views[0].min_severity, "CRITICAL")

    def test_name_survives_full_config_roundtrip(self):
        """Regression: Config.save() must not drop the ``name`` field.

        Prior to the fix, WebhookConfig lacked a ``name`` attribute,
        so loading config.yaml into the dataclass and saving it back
        silently renamed every webhook to ``<type>-<host>``, breaking
        ``defenseclaw setup webhook enable <name>`` in the process.
        """
        from defenseclaw import config as cfg_mod
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            apply_webhook(
                data_dir=td,
                name="ops-primary",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/roundtrip",
            )
            with patch.object(cfg_mod, "default_data_path", return_value=td):
                cfg = cfg_mod.load()
                self.assertEqual(cfg.webhooks[0].name, "ops-primary")
                cfg.save()
                reloaded = cfg_mod.load()
                self.assertEqual(reloaded.webhooks[0].name, "ops-primary")
            with open(os.path.join(td, "config.yaml")) as fh:
                raw = yaml.safe_load(fh)
            self.assertEqual(raw["webhooks"][0]["name"], "ops-primary")

    def test_url_match_preserves_operator_name(self):
        """Regression: re-adding a URL without --name must not rename it.

        When an operator seeded ``name: ops-primary`` and later re-ran
        ``setup webhook add slack --url <same>`` (no name), the writer
        used to overwrite ``name`` with the ``type+host`` slug. The
        fix preserves the explicit name and surfaces a warning instead.
        """
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            apply_webhook(
                data_dir=td,
                name="ops-primary",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/match",
            )
            res = apply_webhook(
                data_dir=td,
                name=None,
                type_="slack",
                url="https://hooks.slack.com/services/A/B/match",
                min_severity="CRITICAL",
            )
            self.assertEqual(res.name, "ops-primary")
            self.assertTrue(
                any("preserving existing name" in w for w in res.warnings),
                f"expected url-match warning, got {res.warnings!r}",
            )
            views = list_webhooks(td)
            self.assertEqual(len(views), 1)
            self.assertEqual(views[0].name, "ops-primary")
            self.assertEqual(views[0].min_severity, "CRITICAL")

    def test_rejects_url_with_embedded_credentials(self):
        """Regression: user:password@host must not leak into config.yaml."""
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            with self.assertRaises(ValueError) as cm:
                apply_webhook(
                    data_dir=td,
                    name=None,
                    type_="generic",
                    url="https://admin:hunter2@ops.example.com/hook",
                )
            self.assertIn("credentials", str(cm.exception).lower())

    def test_enable_disable_remove_flow(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td)
            apply_webhook(
                data_dir=td,
                name="svc",
                type_="slack",
                url="https://hooks.slack.com/services/A/B/xxx",
            )
            set_webhook_enabled("svc", False, td)
            self.assertFalse(list_webhooks(td)[0].enabled)
            set_webhook_enabled("svc", True, td)
            self.assertTrue(list_webhooks(td)[0].enabled)
            remove_webhook("svc", td)
            self.assertEqual(list_webhooks(td), [])


# ---------------------------------------------------------------------------
# SSRF guard parity with Go
# ---------------------------------------------------------------------------


class SSRFValidationTests(unittest.TestCase):
    def test_accepts_public_https(self):
        validate_webhook_url("https://hooks.slack.com/services/X/Y/Z")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            validate_webhook_url("")

    def test_rejects_non_http_schemes(self):
        for bad in (
            "file:///etc/passwd",
            "ftp://example.com/",
            "gopher://example.com/",
            "data:application/json,{}",
        ):
            with self.assertRaises(ValueError):
                validate_webhook_url(bad)

    def test_rejects_localhost_by_default(self):
        env = os.environ.copy()
        env.pop("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", None)
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                validate_webhook_url("http://localhost:8080/hook")
            with self.assertRaises(ValueError):
                validate_webhook_url("http://127.0.0.1/hook")

    def test_allow_localhost_env(self):
        with patch.dict(
            os.environ, {"DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST": "1"},
        ):
            validate_webhook_url("http://localhost:8080/hook")
            validate_webhook_url("http://127.0.0.1:9090/hook")

    def test_rejects_private_ipv4(self):
        for bad in (
            "http://10.0.0.1/hook",
            "http://172.16.5.5/hook",
            "http://192.168.0.1/hook",
            "http://169.254.169.254/latest/meta-data",   # AWS metadata
        ):
            with self.assertRaises(ValueError):
                validate_webhook_url(bad)

    def test_rejects_ipv6_loopback(self):
        with self.assertRaises(ValueError):
            validate_webhook_url("http://[::1]/hook")


# ---------------------------------------------------------------------------
# Formatter parity (structural + compactness + HMAC)
# ---------------------------------------------------------------------------


class FormatterParityTests(unittest.TestCase):
    """Self-describing snapshots of each formatter.

    Both codebases emit compact JSON (no trailing newline, no spaces
    after separators). ``internal/gateway`` has a sibling test that
    asserts the same structural invariants, so drift on either side
    trips both tests. We do **not** assert byte equality because
    ``encoding/json`` in Go sorts map keys alphabetically while
    Python preserves insertion order.
    """

    def test_compact_json_no_whitespace(self):
        """Go's encoding/json emits compact JSON. Our Python formatters
        must do the same so HMAC signatures line up across codebases.
        We can't just search for ``b": "`` because webex/slack bodies
        contain user-visible markdown like ``*Severity:* HIGH`` — but
        we CAN pin the separator shape by reparsing and re-dumping
        with compact separators, which must equal the formatter output
        byte-for-byte.
        """
        evt = _fixed_event()
        for fn in (
            lambda: format_slack_payload(evt),
            lambda: format_pagerduty_payload(evt, "routing-key"),
            lambda: format_webex_payload(evt, "room-id"),
            lambda: format_generic_payload(evt),
        ):
            data = fn()
            self.assertIsInstance(data, bytes)
            self.assertFalse(data.endswith(b"\n"))
            roundtrip = json.dumps(
                json.loads(data),
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            self.assertEqual(data, roundtrip)

    def test_slack_structure(self):
        payload = json.loads(format_slack_payload(_fixed_event()))
        self.assertIn("attachments", payload)
        attachment = payload["attachments"][0]
        self.assertEqual(attachment["color"], "#FF6600")  # HIGH
        blocks = attachment["blocks"]
        self.assertEqual(blocks[0]["type"], "header")
        self.assertIn("webhook.test", blocks[0]["text"]["text"])

    def test_pagerduty_structure(self):
        payload = json.loads(
            format_pagerduty_payload(_fixed_event(), "routing-xyz"),
        )
        self.assertEqual(payload["routing_key"], "routing-xyz")
        self.assertEqual(payload["event_action"], "trigger")
        self.assertIn("dedup_key", payload)
        self.assertEqual(payload["payload"]["severity"], "error")  # HIGH -> error

    def test_webex_structure(self):
        payload = json.loads(
            format_webex_payload(_fixed_event(), "room-id-abc"),
        )
        self.assertEqual(payload["roomId"], "room-id-abc")
        self.assertIn("DefenseClaw: webhook.test", payload["markdown"])

    def test_generic_payload_has_wrapper(self):
        payload = json.loads(format_generic_payload(_fixed_event()))
        self.assertEqual(payload["webhook_type"], "defenseclaw_enforcement")
        self.assertEqual(payload["defenseclaw_version"], "1.0")
        self.assertEqual(payload["event"]["id"], "synthetic-test-fixture")
        self.assertEqual(payload["event"]["severity"], "HIGH")

    def test_generic_payload_adds_block_fields(self):
        evt = _fixed_event()
        evt.action = "scan.block"
        evt.details = "blocked by policy"
        payload = json.loads(format_generic_payload(evt))
        self.assertTrue(payload["event"]["defenseclaw_blocked"])
        self.assertEqual(
            payload["event"]["defenseclaw_reason"], "blocked by policy",
        )

    def test_hmac_matches_known_vector(self):
        # HMAC-SHA256(key="k", data=b"hello world") — any conforming
        # impl (Python stdlib, Go crypto/hmac, openssl dgst) converges
        # on the same hex string. Pinning the hex here means a regression
        # in either our Python dispatcher or the Go gateway will blow up
        # this test + the sibling Go one.
        self.assertEqual(
            compute_hmac(b"hello world", "k"),
            "67eedc5d50852aacd055cc940b52edde89eba69b15902b2a9a82483eab70d12d",
        )

    def test_preview_only_does_not_dispatch(self):
        res = send_synthetic(
            webhook_type="slack",
            url="https://hooks.slack.com/services/A/B/xxx",
            preview_only=True,
        )
        self.assertTrue(res.ok)
        self.assertIsNone(res.status_code)
        self.assertGreater(res.payload_bytes, 0)

    def test_preview_redacts_auth_header(self):
        res = send_synthetic(
            webhook_type="generic",
            url="https://ops.example.com/hooks",
            secret="hmac-key",
            preview_only=True,
        )
        self.assertEqual(
            res.request_headers.get("X-Hub-Signature-256"),
            "<redacted>",
        )

    def test_send_synthetic_rejects_localhost_without_flag(self):
        """Regression: ``send_synthetic`` is a public entry point and
        must not rely solely on upstream callers to guard SSRF."""
        prev = os.environ.pop("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", None)
        try:
            with self.assertRaises(ValueError):
                send_synthetic(
                    webhook_type="generic",
                    url="http://127.0.0.1:9999/hook",
                    preview_only=True,
                )
        finally:
            if prev is not None:
                os.environ["DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST"] = prev


# ---------------------------------------------------------------------------
# Doctor probe: must never dispatch + must surface SSRF / missing secrets
# ---------------------------------------------------------------------------


class DoctorWebhookProbeTests(unittest.TestCase):
    def _make_cfg(self, td: str) -> Config:
        from defenseclaw.config import load
        env = os.environ.copy()
        env["DEFENSECLAW_HOME"] = td
        with patch.dict(os.environ, env, clear=False):
            with patch(
                "defenseclaw.config.default_data_path",
                return_value=os.path.abspath(td),
            ):
                return load()

    def test_no_webhooks_reports_skip(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td, webhooks=[])
            cfg = self._make_cfg(td)
            r = _DoctorResult()
            _check_webhooks(cfg, r)
            skip_labels = [c["label"] for c in r.checks if c["status"] == "skip"]
            self.assertIn("Webhooks", skip_labels)

    def test_disabled_entry_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td, webhooks=[{
                "name": "svc",
                "type": "slack",
                "url": "https://hooks.slack.com/services/A/B/xxx",
                "enabled": False,
            }])
            cfg = self._make_cfg(td)
            r = _DoctorResult()
            _check_webhooks(cfg, r)
            self.assertEqual(r.failed, 0)
            skip_details = [c["detail"] for c in r.checks if c["status"] == "skip"]
            self.assertTrue(any("disabled" in d for d in skip_details))

    def test_ssrf_rejection_surfaces_as_fail(self):
        env = os.environ.copy()
        env.pop("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", None)
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ, env, clear=False,
        ):
            _write_cfg(td, webhooks=[{
                "name": "svc",
                "type": "slack",
                "url": "http://127.0.0.1:9/hook",
                "enabled": True,
            }])
            cfg = self._make_cfg(td)
            r = _DoctorResult()
            _check_webhooks(cfg, r)
            self.assertGreaterEqual(r.failed, 1)

    def test_missing_pagerduty_secret_fails(self):
        env = os.environ.copy()
        env.pop("PD_MISSING_KEY", None)
        with tempfile.TemporaryDirectory() as td, patch.dict(
            os.environ, env, clear=False,
        ):
            _write_cfg(td, webhooks=[{
                "name": "pd",
                "type": "pagerduty",
                "url": "https://events.pagerduty.com/v2/enqueue",
                "secret_env": "PD_MISSING_KEY",
                "enabled": True,
            }])
            cfg = self._make_cfg(td)
            r = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                return_value=(0, "unused"),
            ):
                _check_webhooks(cfg, r)
            fail_details = [c["detail"] for c in r.checks if c["status"] == "fail"]
            self.assertTrue(any("empty" in d.lower() for d in fail_details))

    def test_probe_does_not_dispatch_body(self):
        """The doctor uses OPTIONS — it must never POST a payload."""
        calls: list[str] = []

        def fake_probe(url, method="GET", timeout=5.0, **_):
            calls.append(method)
            return 200, "ok"

        with tempfile.TemporaryDirectory() as td:
            _write_cfg(td, webhooks=[{
                "name": "svc",
                "type": "slack",
                "url": "https://hooks.slack.com/services/A/B/xxx",
                "enabled": True,
            }])
            cfg = self._make_cfg(td)
            r = _DoctorResult()
            with patch(
                "defenseclaw.commands.cmd_doctor._http_probe",
                side_effect=fake_probe,
            ):
                _check_webhooks(cfg, r)
        self.assertIn("OPTIONS", calls, f"expected OPTIONS probe, got {calls}")
        self.assertNotIn(
            "POST", calls,
            "doctor must never POST to a webhook (would fire real events)",
        )


if __name__ == "__main__":
    unittest.main()
