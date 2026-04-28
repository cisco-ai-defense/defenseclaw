"""Tests for the LLM-as-a-Judge guardrail configuration.

The judge logic has been migrated to Go (internal/gateway/llm_judge.go).
Python-side tests now only cover CLI config parsing for JudgeConfig.
Go-side judge tests are in internal/gateway/gateway_test.go.
"""

import os
import sys
import unittest

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    ),
)


# ===================================================================
# CLI config parsing
# ===================================================================


class TestCLIFlagParsing(unittest.TestCase):
    def test_judge_config_defaults(self):
        from defenseclaw.config import JudgeConfig

        cfg = JudgeConfig()
        self.assertFalse(cfg.enabled)
        self.assertTrue(cfg.injection)
        self.assertTrue(cfg.pii)
        self.assertTrue(cfg.pii_prompt)
        self.assertTrue(cfg.pii_completion)
        self.assertEqual(cfg.timeout, 30.0)
        self.assertEqual(cfg.model, "")
        self.assertEqual(cfg.api_key_env, "")
        self.assertEqual(cfg.api_base, "")

    def test_judge_config_from_dict(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {
                "enabled": True, "injection": True, "pii": False,
                "model": "claude-haiku-4-5-20251001", "timeout": 20,
            },
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertTrue(gc.judge.enabled)
        self.assertFalse(gc.judge.pii)
        self.assertEqual(gc.judge.model, "claude-haiku-4-5-20251001")
        self.assertEqual(gc.judge.timeout, 20)

    def test_judge_config_absent(self):
        from defenseclaw.config import _merge_guardrail

        gc = _merge_guardrail({"enabled": True}, "/tmp/test")
        self.assertFalse(gc.judge.enabled)
        self.assertTrue(gc.judge.injection)
        self.assertTrue(gc.judge.pii)

    def test_guardrail_config_no_legacy_fields(self):
        """Ensure legacy guardrail_dir and litellm_config fields are absent."""
        from defenseclaw.config import GuardrailConfig

        gc = GuardrailConfig()
        self.assertFalse(hasattr(gc, "guardrail_dir"))
        self.assertFalse(hasattr(gc, "litellm_config"))

    def test_judge_pii_prompt_completion_flags(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {
                "enabled": True,
                "pii": True,
                "pii_prompt": False,
                "pii_completion": True,
            },
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertFalse(gc.judge.pii_prompt)
        self.assertTrue(gc.judge.pii_completion)

    def test_judge_tool_injection_default(self):
        from defenseclaw.config import JudgeConfig

        cfg = JudgeConfig()
        self.assertTrue(cfg.tool_injection)

    def test_judge_tool_injection_from_dict(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {
                "enabled": True,
                "tool_injection": False,
            },
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertFalse(gc.judge.tool_injection)

    def test_judge_tool_injection_absent_defaults_true(self):
        from defenseclaw.config import _merge_guardrail

        gc = _merge_guardrail({"enabled": True, "judge": {"enabled": True}}, "/tmp/test")
        self.assertTrue(gc.judge.tool_injection)

    def test_judge_exfil_default_true(self):
        # The exfil judge is the dedicated "are you trying to read or
        # exfiltrate sensitive files / credentials / secrets?" classifier.
        # Default-on so polite-tone /etc/passwd-shaped prompts cannot
        # silently slip past a fresh install.
        from defenseclaw.config import JudgeConfig

        cfg = JudgeConfig()
        self.assertTrue(cfg.exfil)

    def test_judge_exfil_from_dict(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {"enabled": True, "exfil": False},
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertFalse(gc.judge.exfil)

    def test_judge_exfil_absent_defaults_true(self):
        from defenseclaw.config import _merge_guardrail

        gc = _merge_guardrail({"enabled": True, "judge": {"enabled": True}}, "/tmp/test")
        self.assertTrue(gc.judge.exfil)

    def test_judge_exfil_yaml_roundtrip(self):
        """exfil flag survives load → asdict → reload."""
        from dataclasses import asdict
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {"enabled": True, "exfil": False},
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        d = asdict(gc)
        gc2 = _merge_guardrail(d, "/tmp/test")
        self.assertFalse(gc2.judge.exfil)

    def test_judge_fallbacks_roundtrip(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "judge": {
                "enabled": True,
                "fallbacks": ["openai/gpt-4o-mini", "anthropic/claude-haiku-4-5-20251001"],
                "adjudication_timeout": 3.5,
            },
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertEqual(gc.judge.fallbacks, ["openai/gpt-4o-mini", "anthropic/claude-haiku-4-5-20251001"])
        self.assertEqual(gc.judge.adjudication_timeout, 3.5)

    def test_judge_fallbacks_default_empty(self):
        from defenseclaw.config import _merge_guardrail

        gc = _merge_guardrail({"enabled": True, "judge": {"enabled": True}}, "/tmp/test")
        self.assertEqual(gc.judge.fallbacks, [])
        self.assertEqual(gc.judge.adjudication_timeout, 5.0)

    def test_guardrail_detection_strategy_roundtrip(self):
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "detection_strategy": "judge_first",
            "detection_strategy_prompt": "regex_judge",
            "detection_strategy_completion": "regex_only",
            "detection_strategy_tool_call": "",
            "judge_sweep": True,
            "rule_pack_dir": "/opt/defenseclaw/policies/strict",
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        self.assertEqual(gc.detection_strategy, "judge_first")
        self.assertEqual(gc.detection_strategy_prompt, "regex_judge")
        self.assertEqual(gc.detection_strategy_completion, "regex_only")
        self.assertEqual(gc.detection_strategy_tool_call, "")
        self.assertTrue(gc.judge_sweep)
        self.assertEqual(gc.rule_pack_dir, "/opt/defenseclaw/policies/strict")

    def test_guardrail_detection_strategy_defaults(self):
        from defenseclaw.config import _merge_guardrail

        gc = _merge_guardrail({"enabled": True}, "/tmp/test")
        # Default strategy is regex_judge so the judge triages ambiguous
        # regex matches when enabled; per-direction overrides stay empty.
        self.assertEqual(gc.detection_strategy, "regex_judge")
        self.assertEqual(gc.detection_strategy_prompt, "")
        # judge_sweep defaults to True as of the multi-provider-adapters
        # PR — see cli/defenseclaw/config.py and docs/GUARDRAIL.md for
        # the reasoning (semantic-only evasions dominate the regex-only
        # false-negative rate). Operators opt out explicitly.
        self.assertTrue(gc.judge_sweep)
        self.assertEqual(gc.rule_pack_dir, "")

    def test_guardrail_full_yaml_roundtrip(self):
        """All guardrail + judge fields survive load→asdict→reload cycle."""
        from dataclasses import asdict
        from defenseclaw.config import _merge_guardrail

        raw = {
            "enabled": True,
            "mode": "action",
            "scanner_mode": "local",
            "host": "10.0.0.1",
            "port": 5000,
            "model": "bedrock/anthropic.claude-3-haiku",
            "model_name": "claude-haiku",
            "api_key_env": "BEDROCK_KEY",
            "block_message": "Blocked by policy",
            "detection_strategy": "regex_judge",
            "detection_strategy_prompt": "judge_first",
            "judge_sweep": True,
            "rule_pack_dir": "/etc/defenseclaw/policies/strict",
            "judge": {
                "enabled": True,
                "injection": True,
                "pii": True,
                "pii_prompt": False,
                "pii_completion": True,
                "tool_injection": False,
                "model": "openai/gpt-4o",
                "timeout": 15.0,
                "fallbacks": ["anthropic/claude-sonnet-4-20250514"],
                "adjudication_timeout": 2.0,
            },
        }
        gc = _merge_guardrail(raw, "/tmp/test")
        d = asdict(gc)
        gc2 = _merge_guardrail(d, "/tmp/test")

        self.assertEqual(gc2.detection_strategy, "regex_judge")
        self.assertEqual(gc2.detection_strategy_prompt, "judge_first")
        self.assertTrue(gc2.judge_sweep)
        self.assertEqual(gc2.rule_pack_dir, "/etc/defenseclaw/policies/strict")
        self.assertFalse(gc2.judge.pii_prompt)
        self.assertFalse(gc2.judge.tool_injection)
        self.assertEqual(gc2.judge.fallbacks, ["anthropic/claude-sonnet-4-20250514"])
        self.assertEqual(gc2.judge.adjudication_timeout, 2.0)
        self.assertEqual(gc2.judge.timeout, 15.0)


if __name__ == "__main__":
    unittest.main()
