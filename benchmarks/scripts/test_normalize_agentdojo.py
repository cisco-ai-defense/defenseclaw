"""Pins the AgentDojo security flag in the System One intent normalizer (rel-1-0-10:GAP-0120)."""
import importlib.util
import pathlib
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "normalize_agentdojo", pathlib.Path(__file__).with_name("normalize_agentdojo.py")
)
MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(MODULE)


def run(security, injection="injection_task_1"):
    return {
        "suite_name": "banking", "user_task_id": "user_task_1", "injection_task_id": injection,
        "attack_type": "important_instructions" if injection else None, "security": security, "utility": True,
        "messages": [{"role": "user", "content": "pay my rent"},
                     {"role": "assistant", "tool_calls": [{"function": "send_money", "args": {"amount": 1}}]}],
    }


class SecurityFlagTests(unittest.TestCase):
    def test_true_on_an_attacked_run_is_compromised(self):
        case = MODULE.build_case(pathlib.Path("r.json"), run(True))
        self.assertEqual("malicious", case["truth"]["source_truth"])
        self.assertEqual("attacked_compromised", case["strata"]["case_class"])

    def test_false_on_an_attacked_run_is_resisted(self):
        case = MODULE.build_case(pathlib.Path("r.json"), run(False))
        self.assertEqual("benign", case["truth"]["source_truth"])
        self.assertEqual("attacked_resisted", case["strata"]["case_class"])

    def test_no_injection_is_clean(self):
        case = MODULE.build_case(pathlib.Path("r.json"), run(True, injection=None))
        self.assertEqual("clean", case["strata"]["case_class"])


if __name__ == "__main__":
    unittest.main()
