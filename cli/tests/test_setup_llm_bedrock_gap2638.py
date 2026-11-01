"""GAP-2638: setup llm --provider bedrock takes a short model name and a region."""

from __future__ import annotations

import os
import unittest
from unittest import mock

import click
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.commands.cmd_doctor import _DoctorResult

HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


class SetupLLMBedrockModelRegionTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.helpers import cleanup_app, make_app_context

        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.addCleanup(cleanup_app, self.app, self.db_path, self.tmp_dir)
        env = {k: v for k, v in os.environ.items() if k not in ("AWS_REGION", "AWS_DEFAULT_REGION")}
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _configure(self, **kw) -> None:
        cmd_setup._configure_llm_non_interactive(self.app.cfg, str(self.tmp_dir), provider="bedrock", **kw)

    def test_short_name_becomes_full_id_and_region_is_saved(self) -> None:
        self._configure(model="haiku-4.5", bedrock_auth_mode="instance_role")
        llm = self.app.cfg.llm
        self.assertEqual(llm.model, HAIKU)
        self.assertEqual(llm.bedrock.region, "us-east-1")
        self.assertEqual(llm.bedrock.auth_mode, "instance_role")

    def test_region_comes_from_aws_region(self) -> None:
        with mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            self._configure(model=HAIKU, bedrock_auth_mode="instance_role")
        self.assertEqual(self.app.cfg.llm.bedrock.region, "us-west-2")

    def test_explicit_region_and_prefixed_id_are_kept(self) -> None:
        self._configure(model="bedrock/" + HAIKU, bedrock_region="eu-west-1")
        self.assertEqual(self.app.cfg.llm.model, "bedrock/" + HAIKU)
        self.assertEqual(self.app.cfg.llm.bedrock.region, "eu-west-1")

    def test_unknown_short_name_is_refused(self) -> None:
        with self.assertRaises(click.UsageError) as err:
            self._configure(model="sonnet-latest")
        self.assertIn("not an Amazon Bedrock model id", str(err.exception))

    def test_deployment_alias_and_arn_are_accepted(self) -> None:
        self._configure(model="judge", bedrock_deployment_aliases=(f"judge={HAIKU}",))
        self.assertEqual(self.app.cfg.llm.model, "judge")
        arn = "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/abc"
        self._configure(model=arn)
        self.assertEqual(self.app.cfg.llm.model, arn)

    def test_bound_instance_is_left_to_the_instance(self) -> None:
        self._configure(model="m", instance_name="acme-bedrock-prod")
        self.assertEqual(self.app.cfg.llm.model, "m")
        self.assertIsNone(self.app.cfg.llm.bedrock)

    def test_other_providers_untouched(self) -> None:
        cmd_setup._configure_llm_non_interactive(self.app.cfg, str(self.tmp_dir), provider="anthropic", model="haiku-4.5")
        self.assertEqual(self.app.cfg.llm.model, "haiku-4.5")
        self.assertIsNone(self.app.cfg.llm.bedrock)

    def test_doctor_region_passes_after_setup(self) -> None:
        self._configure(model="haiku-4.5", bedrock_auth_mode="instance_role")
        self.app.cfg.guardrail.enabled = True
        r = _DoctorResult()
        cmd_doctor._check_regional_provider_config(self.app.cfg, r)
        self.assertEqual(r.failed, 0)
