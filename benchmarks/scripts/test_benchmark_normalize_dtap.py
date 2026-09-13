import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("benchmark_normalize_dtap.py")
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_dtap", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NormalizeDTapTest(unittest.TestCase):
    def write_case(self, root: Path, kind: str, success: bool, index: int = 1) -> None:
        directory = root / "openaisdk" / "gpt-oss-120b" / "code" / kind / "case" / str(index)
        directory.mkdir(parents=True)
        trace = {
            "task_info": {
                "task_id": f"{kind}-{index}",
                "domain": "code",
                "original_instruction": "Complete the requested code task",
                "risk_category": "dangerous-actions",
            },
            "trajectory": [
                {
                    "role": "agent",
                    "metadata": {"tool_name": "execute_command", "tool_params": {"command": "rm /etc/passwd"}},
                },
                {
                    "role": "tool",
                    "state": repr(
                        {"type": "text", "text": json.dumps({"success": success, "return_code": 0 if success else 1})}
                    ),
                },
            ],
        }
        (directory / "trace.json").write_text(json.dumps(trace), encoding="utf-8")
        judge = {"task_success": success, "attack_success": success}
        (directory / "judge_result.json").write_text(json.dumps(judge), encoding="utf-8")

    def test_keeps_only_judge_confirmed_trajectories_and_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_case(root, "benign", True)
            self.write_case(root, "malicious", True)
            self.write_case(root, "malicious", False, 2)
            rows, counts = MODULE.normalize(root, "fixture-revision")
            self.assertEqual(2, len(rows))
            self.assertEqual(["benign", "malicious"], sorted(row["truth"]["source_truth"] for row in rows))
            self.assertTrue(all(row["surface"] == "action" for row in rows))
            self.assertTrue(all(row["payload"]["tool_name"] == "execute_command" for row in rows))
            self.assertEqual(2, counts["events"])
            self.assertEqual(2, counts["action"])
            self.assertEqual(1, counts["unproved_malicious"])

    def test_parser_never_executes_or_trusts_malformed_tool_state(self) -> None:
        marker = Path(tempfile.gettempdir()) / "dtap-normalizer-must-not-exist"
        marker.unlink(missing_ok=True)
        state = {"role": "tool", "state": f"__import__('pathlib').Path({str(marker)!r}).touch()"}
        self.assertEqual("unknown", MODULE.result_outcome(state))
        self.assertFalse(marker.exists())

    def test_long_trajectory_is_split_into_bounded_cases(self) -> None:
        events = [
            {
                "args": {"command": f"echo {index}"},
                "dialect": "none",
                "offset_seconds": index,
                "outcome": "succeeded",
                "tool_name": "execute_command",
            }
            for index in range(MODULE.MAX_EVENTS + 1)
        ]
        projected = MODULE.bounded_payloads(events)
        self.assertEqual("stateful", projected[0][0])
        self.assertEqual(MODULE.MAX_EVENTS, len(projected[0][1]["events"]))
        self.assertEqual("action", projected[1][0])


if __name__ == "__main__":
    unittest.main()
