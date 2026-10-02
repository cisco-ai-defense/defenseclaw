"""GAP-1146: ``setup webhook test`` masks the URL like list/show do."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup_webhook import webhook
from defenseclaw.context import AppContext

SECRET_PART = "XyzSecretPart0123456789"
URL = f"https://hooks.slack.com/services/T0DUMMY/B0DUMMY/{SECRET_PART}"


class WebhookTestMasksUrl(unittest.TestCase):
    def test_dry_run_prints_redacted_url(self):
        view = SimpleNamespace(
            name="gap1146", type="slack", url=URL, secret_env="", room_id="", min_severity="HIGH",
        )
        with tempfile.TemporaryDirectory() as tmp:
            app = AppContext()
            app.cfg = SimpleNamespace(data_dir=tmp)
            with patch("defenseclaw.commands.cmd_setup_webhook.list_webhooks", return_value=[view]):
                result = CliRunner().invoke(webhook, ["test", "gap1146", "--dry-run"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("https://hooks.slack.com/***", result.output)
        self.assertNotIn(SECRET_PART, result.output)


class WebhookAddWithGatewayStopped(unittest.TestCase):
    """GAP-1399: a saved webhook must not end in a traceback and rc=1."""

    def test_add_saves_and_warns_when_audit_is_unavailable(self):
        from defenseclaw.logger import CanonicalObservabilityUnavailableError

        logger = SimpleNamespace(
            log_action=lambda *a, **k: (_ for _ in ()).throw(
                CanonicalObservabilityUnavailableError("gateway authentication is unavailable")
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            app = AppContext()
            app.cfg = SimpleNamespace(data_dir=tmp)
            app.logger = logger
            result = CliRunner().invoke(
                webhook,
                ["add", "slack", "--name", "gap1399", "--url", URL, "--non-interactive", "--disabled"],
                obj=app,
            )
            listed = CliRunner().invoke(webhook, ["list"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNone(result.exception)
        self.assertIn("audit event was not recorded", result.output)
        self.assertIn("gap1399", listed.output)
