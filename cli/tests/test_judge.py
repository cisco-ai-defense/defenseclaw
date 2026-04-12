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


if __name__ == "__main__":
    unittest.main()
