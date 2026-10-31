"""#1395: guardrail.judge.max_parallel round trip and judge fallback summaries."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import defenseclaw.config as config_mod  # noqa: E402
from defenseclaw.commands.cmd_status import judge_fallback_summary  # noqa: E402
from defenseclaw.config import _merge_guardrail, default_config  # noqa: E402


class TestJudgeMaxParallelConfig(unittest.TestCase):
    def _save_and_reload(self, cfg):
        cfg.save()
        with patch.dict(os.environ, {"DEFENSECLAW_HOME": cfg.data_dir}):
            return config_mod.load()

    def test_default_is_no_limit_and_stays_out_of_the_file(self):
        cfg = default_config()
        cfg.data_dir = tempfile.mkdtemp()
        self.assertEqual(cfg.guardrail.judge.max_parallel, 0)
        cfg.save()
        with open(os.path.join(cfg.data_dir, "config.yaml")) as f:
            # Rollback-safe: a config that never set it does not name it
            # (releases before 1.0.6 refuse the key).
            self.assertNotIn("max_parallel", f.read())

    def test_set_then_clear_round_trips(self):
        cfg = default_config()
        cfg.data_dir = tempfile.mkdtemp()
        cfg.guardrail.judge.max_parallel = 2
        loaded = self._save_and_reload(cfg)
        self.assertEqual(loaded.guardrail.judge.max_parallel, 2)
        loaded.guardrail.judge.max_parallel = 0
        reloaded = self._save_and_reload(loaded)
        self.assertEqual(reloaded.guardrail.judge.max_parallel, 0)
        with open(os.path.join(loaded.data_dir, "config.yaml")) as f:
            self.assertNotIn("max_parallel", f.read())

    def test_merge_reads_an_int(self):
        gc = _merge_guardrail({"judge": {"enabled": True, "max_parallel": 3}}, "/tmp/test")
        self.assertEqual(gc.judge.max_parallel, 3)
        gc = _merge_guardrail({"judge": {"enabled": True}}, "/tmp/test")
        self.assertEqual(gc.judge.max_parallel, 0)


class TestJudgeFallbackSummary(unittest.TestCase):
    def test_no_fallbacks_says_nothing(self):
        self.assertEqual(judge_fallback_summary({}), "")
        self.assertEqual(judge_fallback_summary({"judge_fallbacks": 0}), "")

    def test_names_count_connectors_and_last(self):
        text = judge_fallback_summary(
            {
                "judge_fallbacks": 3,
                "judge_fallbacks_by_connector": {"codex": 1, "claudecode": 2},
                "judge_last_fallback": "timeout (claudecode)",
            }
        )
        self.assertIn("3 hook check(s)", text)
        self.assertIn("claudecode 2, codex 1", text)
        self.assertIn("last: timeout (claudecode)", text)


if __name__ == "__main__":
    unittest.main()
