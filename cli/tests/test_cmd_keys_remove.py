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
from defenseclaw.config import GuardrailConfig

from tests.test_cmd_keys import _make_app_context


class KeysRemoveTests(unittest.TestCase):
    def test_remove_warns_when_destination_still_references_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with open(os.path.join(tmp, "config.yaml"), "w", encoding="utf-8") as stream:
                stream.write(
                    "config_version: 9\nobservability:\n  destinations:\n"
                    "    - name: audit-hec\n      kind: splunk_hec\n"
                    "      token_env: DEFENSECLAW_SPLUNK_HEC_TOKEN\n"
                )
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as stream:
                stream.write("DEFENSECLAW_SPLUNK_HEC_TOKEN=test-value\n")
            result = CliRunner().invoke(
                keys_cmd, ["remove", "DEFENSECLAW_SPLUNK_HEC_TOKEN", "--yes"], obj=app
            )
            self.assertIn("still used by observability destination audit-hec", result.output)
            self.assertIn("setup observability remove audit-hec --yes", result.output)

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

    def test_remove_of_dotenv_loaded_key_does_not_claim_shell_export(self):
        from defenseclaw import credential_provenance
        from defenseclaw.config import _load_dotenv_into_os

        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("NOT_A_KNOWN_KEY=x1\nSHELL_KEY=from-file\n")
            env = {k: v for k, v in os.environ.items() if k not in ("NOT_A_KNOWN_KEY", "SHELL_KEY")}
            env["SHELL_KEY"] = "from-shell"
            credential_provenance._reset_for_tests()
            with patch.dict(os.environ, env, clear=True):
                _load_dotenv_into_os(tmp)
                runner = CliRunner()
                removed = runner.invoke(keys_cmd, ["remove", "NOT_A_KNOWN_KEY", "--yes"], obj=app)
                self.assertEqual(removed.exit_code, 0, removed.output)
                self.assertNotIn("still exported", removed.output)
                self.assertNotIn("NOT_A_KNOWN_KEY", os.environ)
                removed = runner.invoke(keys_cmd, ["remove", "SHELL_KEY", "--yes"], obj=app)
                self.assertEqual(removed.exit_code, 0, removed.output)
                self.assertIn("SHELL_KEY is still exported", removed.output)

    def test_gateway_token_is_marked_managed_and_not_removable(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            dotenv = os.path.join(tmp, ".env")
            with open(dotenv, "w", encoding="utf-8") as fh:
                fh.write("DEFENSECLAW_GATEWAY_TOKEN=t1\nNOT_A_KNOWN_KEY=x1\n")
            env = {k: v for k, v in os.environ.items() if k not in ("DEFENSECLAW_GATEWAY_TOKEN", "NOT_A_KNOWN_KEY")}
            runner = CliRunner()
            with patch.dict(os.environ, env, clear=True):
                listed = runner.invoke(keys_cmd, ["list"], obj=app)
                self.assertEqual(listed.exit_code, 0, listed.output)
                other = [line for line in listed.output.splitlines() if "Other entries" in line]
                self.assertEqual(len(other), 1, listed.output)
                self.assertNotIn("DEFENSECLAW_GATEWAY_TOKEN", other[0])
                self.assertIn("Managed by DefenseClaw", listed.output)
                refused = runner.invoke(keys_cmd, ["remove", "DEFENSECLAW_GATEWAY_TOKEN", "--yes"], obj=app)
                self.assertNotEqual(refused.exit_code, 0)
                self.assertIn("gateway auth token", refused.output)
                with open(dotenv, encoding="utf-8") as fh:
                    self.assertIn("DEFENSECLAW_GATEWAY_TOKEN=t1", fh.read())

    def test_remove_of_required_key_names_the_feature_it_breaks(self):
        # GAP-2254: removing a key the config REQUIRES gave only a generic confirm.
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp, guardrail=GuardrailConfig(enabled=True, scanner_mode="remote"))
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("CISCO_AI_DEFENSE_API_KEY=c1\nNOT_A_KNOWN_KEY=x1\n")
            env = {k: v for k, v in os.environ.items() if k not in ("CISCO_AI_DEFENSE_API_KEY", "NOT_A_KNOWN_KEY")}
            runner = CliRunner()
            with patch.dict(os.environ, env, clear=True):
                declined = runner.invoke(keys_cmd, ["remove", "CISCO_AI_DEFENSE_API_KEY"], obj=app, input="n\n")
                self.assertNotEqual(declined.exit_code, 0)
                self.assertIn("CISCO_AI_DEFENSE_API_KEY is REQUIRED by guardrail.remote", declined.output)
                removed = runner.invoke(keys_cmd, ["remove", "CISCO_AI_DEFENSE_API_KEY", "--yes"], obj=app)
                self.assertEqual(removed.exit_code, 0, removed.output)
                self.assertIn("guardrail.remote stops working", removed.output)
                other = runner.invoke(keys_cmd, ["remove", "NOT_A_KNOWN_KEY", "--yes"], obj=app)
                self.assertEqual(other.exit_code, 0, other.output)
                self.assertNotIn("REQUIRED", other.output)
