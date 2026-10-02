# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""LLM judge on Bedrock: setup llm, the guardrail wizard, init and doctor."""

from __future__ import annotations

import json
import os
import sqlite3
import unittest
from contextlib import closing
from unittest import mock

import yaml
from click.testing import CliRunner

from defenseclaw.bootstrap import FirstRunOptions, StepResult, targeted_readiness
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.config import BedrockKeyConfig, LLMConfig

HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def _instance_role_llm() -> LLMConfig:
    return LLMConfig(
        provider="bedrock",
        model=HAIKU,
        bedrock=BedrockKeyConfig(region="us-east-1", auth_mode="instance_role"),
    )


class JudgeBedrockSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.helpers import cleanup_app, make_app_context

        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.addCleanup(cleanup_app, self.app, self.db_path, self.tmp_dir)
        env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_LLM_KEY"}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_bedrock_credential_auth_needs_no_api_key(self) -> None:
        self.assertFalse(_instance_role_llm().needs_api_key())
        keyed = _instance_role_llm()
        keyed.bedrock.auth_mode = "api_key"
        self.assertTrue(keyed.needs_api_key())
        self.assertTrue(LLMConfig(provider="openai", model="gpt-4o").needs_api_key())

    def test_setup_llm_role_judge_instance_role_saves_without_key_warning(self) -> None:
        """GAP-1122: no 'Save without a key?' prompt and a judge heading."""
        self.app.cfg.llm.api_key_env = "DEFENSECLAW_LLM_KEY"

        def fake_configure(cfg, _data_dir, *, target_path="", _pending_secrets=None):
            self.assertEqual(target_path, "guardrail.judge")
            cfg.guardrail.judge.llm = _instance_role_llm()

        with (
            mock.patch.object(cmd_setup, "_maybe_inherit_existing_llm", return_value=None),
            mock.patch.object(cmd_setup, "_configure_llm", side_effect=fake_configure),
            mock.patch.object(self.app.cfg, "save") as save,
        ):
            res = CliRunner().invoke(setup, ["llm", "--role", "judge"], obj=self.app, input="", catch_exceptions=False)

        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("Judge LLM configuration", res.output)
        self.assertNotIn("Unified LLM configuration", res.output)
        self.assertNotIn("has no value", res.output)
        save.assert_called_once()

    def test_guardrail_wizard_reuses_judge_llm_and_writes_v5_shape(self) -> None:
        """GAP-1121: the configured judge LLM is the default; no v4 fields."""
        gc = self.app.cfg.guardrail
        gc.judge.llm = _instance_role_llm()
        gc.judge.model = f"bedrock/{HAIKU}"
        gc.judge.api_key_env = "DEFENSECLAW_LLM_KEY"

        with (
            mock.patch.object(cmd_setup.click, "confirm", side_effect=[True, False]) as confirm,
            mock.patch.object(cmd_setup, "_configure_llm") as configure,
            mock.patch.object(cmd_setup.click, "prompt") as prompt,
        ):
            cmd_setup._prompt_judge_model_config(self.app, gc)

        self.assertEqual(confirm.call_args_list[0].args[0], "  Use this LLM for the judge?")
        configure.assert_not_called()
        prompt.assert_not_called()
        self.assertEqual((gc.judge.model, gc.judge.api_base, gc.judge.api_key_env), ("", "", ""))
        self.app.cfg.save()
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            judge = yaml.safe_load(fh)["guardrail"]["judge"]
        self.assertNotIn("model", judge)
        self.assertNotIn("api_key_env", judge)
        self.assertEqual(judge["llm"]["bedrock"]["auth_mode"], "instance_role")

    def test_guardrail_wizard_without_judge_llm_runs_the_v5_wizard(self) -> None:
        gc = self.app.cfg.guardrail
        self.app.cfg.llm = LLMConfig()
        with (
            mock.patch.object(cmd_setup.click, "confirm", return_value=False),
            mock.patch.object(cmd_setup, "_configure_llm") as configure,
        ):
            cmd_setup._prompt_judge_model_config(self.app, gc)

        configure.assert_called_once()
        self.assertEqual(configure.call_args.kwargs["target_path"], "guardrail.judge")

    def test_init_readiness_missing_key_is_a_warning_not_a_rollback(self) -> None:
        """GAP-1057: a missing key keeps config and connectors, names the fix."""
        cfg = self.app.cfg
        cfg.guardrail.enabled = True
        cfg.llm = LLMConfig(provider="bedrock", model=HAIKU, api_key_env="DEFENSECLAW_LLM_KEY")
        failed = StepResult("LLM API key", "fail", "DEFENSECLAW_LLM_KEY not set", "defenseclaw doctor")
        with mock.patch("defenseclaw.bootstrap._doctor_check", return_value=failed):
            steps = targeted_readiness(cfg, FirstRunOptions(connector="codex", start_gateway=False))

        row = next(s for s in steps if s.name == "LLM API key")
        self.assertEqual(row.status, "warn")
        self.assertEqual(row.next_command, "defenseclaw keys set DEFENSECLAW_LLM_KEY")

    def test_doctor_reports_failing_judge_calls(self) -> None:
        """GAP-1120: a judge that errors on every call is a doctor failure."""
        cfg = self.app.cfg
        cfg.guardrail.enabled = True
        cfg.guardrail.judge.enabled = True
        error = "gateway: bifrost: 400 tools.0.custom.input_schema.properties: Property keys should match pattern"

        def add(row_id: str, payload: dict) -> None:
            with closing(sqlite3.connect(cfg.audit_db)) as db:
                db.execute(
                    "INSERT INTO audit_events (id, timestamp, action, structured_json) VALUES (?, ?, ?, ?)",
                    (row_id, f"2099-01-01T00:00:0{row_id}Z", "llm-judge-response", json.dumps(payload)),
                )
                db.commit()

        def run() -> _DoctorResult:
            r = _DoctorResult()
            with mock.patch.object(cmd_doctor, "_json_mode", True):
                cmd_doctor._check_judge_calls(cfg, r)
            return r

        add("1", {"defenseclaw.judge.action": "error", "defenseclaw.judge.error_summary": error})
        r = run()
        self.assertEqual(r.failed, 1, r.checks)
        self.assertIn("Property keys should match pattern", r.checks[0]["detail"])

        add("2", {"defenseclaw.judge.action": "allow"})
        r = run()
        self.assertEqual((r.failed, r.warned), (0, 1), r.checks)


if __name__ == "__main__":
    unittest.main()
