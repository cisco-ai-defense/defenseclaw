#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for first-class connector setup aliases and non-interactive LLM setup."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup as setup_group

from tests.helpers import cleanup_app, make_app_context


def _invoke(args: list[str], app):
    runner = CliRunner()
    return runner.invoke(setup_group, args, obj=app, catch_exceptions=False)


class TestGuardrailConnectorAliases(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run_alias(self, connector: str):
        with patch(
            "defenseclaw.commands.cmd_setup.execute_guardrail_setup",
            return_value=(True, []),
        ) as setup_mock, patch(
            "defenseclaw.commands.cmd_setup._restart_services",
            return_value=None,
        ):
            result = _invoke(
                [
                    connector,
                    "--yes",
                    "--mode",
                    "action",
                    "--scanner-mode",
                    "local",
                    "--no-restart",
                    "--no-verify",
                ],
                self.app,
            )
        return result, setup_mock

    def test_openclaw_alias_pins_connector_and_runs_guardrail_backend(self):
        result, setup_mock = self._run_alias("openclaw")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(setup_mock.called)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")
        self.assertTrue(self.app.cfg.guardrail.enabled)
        self.assertEqual(self.app.cfg.guardrail.mode, "action")
        self.assertEqual(self.app.cfg.guardrail.scanner_mode, "local")

    def test_zeptoclaw_alias_pins_connector_and_runs_guardrail_backend(self):
        result, setup_mock = self._run_alias("zeptoclaw")
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertTrue(setup_mock.called)
        self.assertEqual(self.app.cfg.claw.mode, "zeptoclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "zeptoclaw")
        self.assertTrue(self.app.cfg.guardrail.enabled)

    def test_setup_help_lists_guardrail_connectors(self):
        result = _invoke(["--help"], self.app)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("openclaw", result.output)
        self.assertIn("zeptoclaw", result.output)


class TestSetupLLMNonInteractive(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.env_name = "DEFENSECLAW_TEST_LLM_KEY"
        os.environ.pop(self.env_name, None)

    def tearDown(self):
        os.environ.pop(self.env_name, None)
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_non_interactive_stores_secret_in_dotenv_not_config(self):
        result = _invoke(
            [
                "llm",
                "--non-interactive",
                "--provider",
                "openai",
                "--model",
                "gpt-4o-mini",
                "--api-key-env",
                self.env_name,
                "--api-key",
                "sk-test-secret",
                "--base-url",
                "https://api.openai.example/v1",
                "--timeout",
                "45",
                "--max-retries",
                "4",
            ],
            self.app,
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)

        llm = self.app.cfg.llm
        self.assertEqual(llm.provider, "openai")
        self.assertEqual(llm.model, "gpt-4o-mini")
        self.assertEqual(llm.api_key_env, self.env_name)
        self.assertEqual(llm.api_key, "")
        self.assertEqual(llm.base_url, "https://api.openai.example/v1")
        self.assertEqual(llm.timeout, 45)
        self.assertEqual(llm.max_retries, 4)
        self.assertEqual(os.environ.get(self.env_name), "sk-test-secret")

        dotenv_path = os.path.join(self.app.cfg.data_dir, ".env")
        with open(dotenv_path, encoding="utf-8") as fh:
            dotenv = fh.read()
        self.assertIn(f"{self.env_name}=sk-test-secret", dotenv)

        config_path = os.path.join(self.app.cfg.data_dir, "config.yaml")
        with open(config_path, encoding="utf-8") as fh:
            rendered = fh.read()
        self.assertNotIn("sk-test-secret", rendered)

    def test_non_interactive_local_provider_skips_api_key(self):
        result = _invoke(
            [
                "llm",
                "--non-interactive",
                "--provider",
                "ollama",
                "--model",
                "llama3.1",
            ],
            self.app,
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(self.app.cfg.llm.provider, "ollama")
        self.assertEqual(self.app.cfg.llm.api_key_env, "")
        self.assertEqual(self.app.cfg.llm.api_key, "")
        self.assertEqual(self.app.cfg.llm.base_url, "http://127.0.0.1:11434")


if __name__ == "__main__":
    unittest.main()
