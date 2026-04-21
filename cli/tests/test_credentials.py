# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the central credentials registry.

Focus: verify the *semantics* of the classification pipeline —
predicates return the right ``Requirement`` for each config shape, the
effective env-name override takes precedence over canonical names, and
``resolve`` walks the ``env → .env → unset`` ladder correctly.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import credentials as C
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    JudgeConfig,
    LLMConfig,
    OpenShellConfig,
    ScannersConfig,
    SkillScannerConfig,
    SplunkConfig,
)


def _make_cfg(data_dir: str, **overrides) -> Config:
    """Minimal, construction-only ``Config`` for predicate tests."""
    kwargs = dict(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    kwargs.update(overrides)
    return Config(**kwargs)


class RequirementPredicateTests(unittest.TestCase):
    """Each predicate should correctly respond to whether its feature is on."""

    def test_openclaw_token_always_required(self):
        cfg = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._openclaw_gateway_token(cfg), C.Requirement.REQUIRED)

    def test_judge_key_not_used_when_guardrail_disabled(self):
        cfg = _make_cfg("/tmp/dc-test", guardrail=GuardrailConfig(enabled=False))
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_not_used_when_default_key_covers_it(self):
        """With no per-component llm.api_key_env override, JUDGE_API_KEY
        is NOT_USED because the top-level DEFENSECLAW_LLM_KEY covers it."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(enabled=True),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_required_with_custom_override(self):
        """When judge.llm.api_key_env points at a non-default env var,
        that env var is REQUIRED."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(api_key_env="MY_JUDGE_KEY"),
                ),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.REQUIRED)

    def test_judge_key_not_used_for_local_provider(self):
        """Local providers (ollama/vllm) don't need a key."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(model="ollama/llama3.1", api_key_env="MY_JUDGE_KEY"),
                ),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_not_used_when_guardrail_on_but_judge_off(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(enabled=False),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_cisco_key_required_only_for_remote_and_both(self):
        for mode, expected in (
            ("local",  C.Requirement.NOT_USED),
            ("remote", C.Requirement.REQUIRED),
            ("both",   C.Requirement.REQUIRED),
        ):
            with self.subTest(mode=mode):
                cfg = _make_cfg(
                    "/tmp/dc-test",
                    guardrail=GuardrailConfig(enabled=True, scanner_mode=mode),
                )
                self.assertEqual(C._cisco_ai_defense_key(cfg), expected)

    def test_virustotal_respects_use_virustotal_flag(self):
        off = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._virustotal_key(off), C.Requirement.NOT_USED)
        on = _make_cfg(
            "/tmp/dc-test",
            scanners=ScannersConfig(
                skill_scanner=SkillScannerConfig(use_virustotal=True),
            ),
        )
        self.assertEqual(C._virustotal_key(on), C.Requirement.REQUIRED)

    def test_splunk_required_when_enabled(self):
        off = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._splunk_token(off), C.Requirement.NOT_USED)
        on = _make_cfg("/tmp/dc-test", splunk=SplunkConfig(enabled=True))
        self.assertEqual(C._splunk_token(on), C.Requirement.REQUIRED)

    def test_defenseclaw_llm_key_not_used_when_nothing_uses_llm(self):
        cfg = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.NOT_USED)

    def test_defenseclaw_llm_key_required_when_guardrail_on(self):
        cfg = _make_cfg("/tmp/dc-test", guardrail=GuardrailConfig(enabled=True))
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)

    def test_defenseclaw_llm_key_optional_with_local_guardrail(self):
        """Local provider needs no key, but the knob is still surfaced."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                llm=LLMConfig(model="ollama/llama3.1"),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.OPTIONAL)

    def test_defenseclaw_llm_key_required_when_skill_scanner_llm_on(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            scanners=ScannersConfig(
                skill_scanner=SkillScannerConfig(use_llm=True),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)


class EffectiveEnvNameTests(unittest.TestCase):
    """``effective_env_name`` must win over the canonical name when set."""

    def test_judge_env_override_applied(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(api_key_env="MY_JUDGE"),
                ),
            ),
        )
        judge_spec = C.lookup("JUDGE_API_KEY")
        self.assertIsNotNone(judge_spec)
        self.assertEqual(judge_spec.resolve_env_name(cfg), "MY_JUDGE")

    def test_canonical_name_used_when_override_empty(self):
        cfg = _make_cfg("/tmp/dc-test")
        spec = C.lookup("SPLUNK_ACCESS_TOKEN")
        self.assertIsNotNone(spec)
        resolved = spec.resolve_env_name(cfg)
        self.assertIn(resolved, ("SPLUNK_ACCESS_TOKEN", ""))


class ResolveTests(unittest.TestCase):
    """Resolution walks env → .env → unset."""

    def test_env_beats_dotenv(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=from_dotenv\n")
            with patch.dict(os.environ, {"EXAMPLE_KEY": "from_env"}, clear=False):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "from_env")
                self.assertEqual(res.source, "env")
                self.assertTrue(res.is_set)

    def test_dotenv_used_when_env_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                # Values may be quoted; parser must strip them.
                fh.write('EXAMPLE_KEY="from_dotenv"\n')
            env = {k: v for k, v in os.environ.items() if k != "EXAMPLE_KEY"}
            with patch.dict(os.environ, env, clear=True):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "from_dotenv")
                self.assertEqual(res.source, "dotenv")

    def test_unset_when_neither_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "EXAMPLE_KEY"}
            with patch.dict(os.environ, env, clear=True):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertFalse(res.is_set)
                self.assertEqual(res.source, "unset")


class MaskTests(unittest.TestCase):
    def test_short_secrets_fully_masked(self):
        self.assertEqual(C.mask(""), "")
        self.assertEqual(C.mask("abc"), "****")
        self.assertEqual(C.mask("abcdefgh"), "****")

    def test_long_secrets_reveal_edges(self):
        self.assertEqual(C.mask("abcdefghij"), "abcd…ghij")


class ClassifyTests(unittest.TestCase):
    """Integration: classify() produces a CredentialStatus per entry."""

    def test_classify_returns_entry_per_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_cfg(tmp)
            statuses = C.classify(cfg)
            self.assertEqual(len(statuses), len(C.CREDENTIALS))
            # Order is stable — registry order drives UX order.
            for i, status in enumerate(statuses):
                self.assertIs(status.spec, C.CREDENTIALS[i])

    def test_missing_required_identifies_unset_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_cfg(
                tmp,
                guardrail=GuardrailConfig(
                    enabled=True,
                    scanner_mode="remote",  # triggers CISCO_AI_DEFENSE_API_KEY
                ),
            )
            env = {k: v for k, v in os.environ.items()
                   if k not in ("OPENCLAW_GATEWAY_TOKEN", "CISCO_AI_DEFENSE_API_KEY")}
            with patch.dict(os.environ, env, clear=True):
                missing = {s.spec.env_name for s in C.missing_required(cfg)}
                self.assertIn("OPENCLAW_GATEWAY_TOKEN", missing)
                self.assertIn("CISCO_AI_DEFENSE_API_KEY", missing)


if __name__ == "__main__":
    unittest.main()
