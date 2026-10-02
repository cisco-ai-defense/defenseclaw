"""GAP-1132: ``defenseclaw keys remove`` deletes a stored key from .env."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_keys import keys_cmd

from tests.test_cmd_keys import _make_app_context


class KeysRemoveTests(unittest.TestCase):
    def test_remove_drops_only_that_key_and_list_names_unregistered(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            dotenv = os.path.join(tmp, ".env")
            with open(dotenv, "w", encoding="utf-8") as fh:
                fh.write("# keep me\nNOT_A_KNOWN_KEY=x1\nVIRUSTOTAL_API_KEY=v1\n")
            env = {k: v for k, v in os.environ.items() if k not in ("NOT_A_KNOWN_KEY", "VIRUSTOTAL_API_KEY")}
            runner = CliRunner()
            with patch.dict(os.environ, env, clear=True):
                listed = runner.invoke(keys_cmd, ["list"], obj=app)
                self.assertEqual(listed.exit_code, 0, listed.output)
                self.assertIn("NOT_A_KNOWN_KEY", listed.output)
                self.assertNotIn("x1", listed.output)

                declined = runner.invoke(keys_cmd, ["remove", "NOT_A_KNOWN_KEY"], obj=app, input="n\n")
                self.assertNotEqual(declined.exit_code, 0)
                with open(dotenv, encoding="utf-8") as fh:
                    self.assertIn("NOT_A_KNOWN_KEY=x1", fh.read())

                removed = runner.invoke(keys_cmd, ["remove", "NOT_A_KNOWN_KEY", "--yes"], obj=app)
                self.assertEqual(removed.exit_code, 0, removed.output)
                self.assertIn("Removed NOT_A_KNOWN_KEY", removed.output)
                with open(dotenv, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "# keep me\nVIRUSTOTAL_API_KEY=v1\n")

                again = runner.invoke(keys_cmd, ["remove", "NOT_A_KNOWN_KEY", "--yes"], obj=app)
                self.assertEqual(again.exit_code, 0, again.output)
                self.assertIn("nothing removed", again.output)

                listed = runner.invoke(keys_cmd, ["list"], obj=app)
                self.assertNotIn("NOT_A_KNOWN_KEY", listed.output)

    def test_empty_set_points_to_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            result = CliRunner().invoke(keys_cmd, ["set", "SPLUNK_ACCESS_TOKEN", "--value", ""], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("defenseclaw keys remove SPLUNK_ACCESS_TOKEN", result.output)
