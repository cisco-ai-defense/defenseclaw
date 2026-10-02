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
