# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Fixed harness failure evidence tests; no process or PE executes."""

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location("axis_parent_death", Path(__file__).with_name("run_parent_death.py"))
assert _SPEC is not None and _SPEC.loader is not None
parent_death = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(parent_death)


class EarlyHarnessFailureTests(unittest.TestCase):
    def exercise_failure(self, creates_case):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            case = root / "parent-death-early-exit"
            verification = root / "verification.json"
            verification.write_text(json.dumps({"payload": str(root / "payload")}))
            args = types.SimpleNamespace(
                case_root=case,
                verification=verification,
                harness=root / "not-executed-harness.exe",
                probe=root / "not-executed-probe.exe",
                probe_sha256="a" * 64,
            )
            process = mock.Mock(pid=123, returncode=7)
            process.poll.return_value = 7

            def launch(*_args, **_kwargs):
                if creates_case:
                    case.mkdir()
                return process

            with (
                mock.patch.object(parent_death.subprocess, "Popen", side_effect=launch) as popen,
                mock.patch.object(parent_death, "owned_processes") as inspect,
                mock.patch("builtins.print"),
            ):
                self.assertFalse(parent_death.run(args))
            popen.assert_called_once()
            inspect.assert_not_called()
            process.kill.assert_not_called()
            process.wait.assert_not_called()
            original = case / "parent-death-result.json"
            fallback = root / (case.name + "-parent-death-result.json")
            result_path = original if creates_case else fallback
            self.assertFalse((fallback if creates_case else original).exists())
            result = json.loads(result_path.read_text())
            self.assertFalse(result["passed"])
            self.assertEqual(result["harness_exit_code"], 7)
            self.assertIsNone(result["readiness"])
            self.assertEqual(result["error"], "contained descendant readiness was not observed")
            self.assertTrue((root / (case.name + "-controller-stdout.txt")).is_file())
            self.assertTrue((root / (case.name + "-controller-stderr.txt")).is_file())

    def test_exit_before_case_creation_keeps_failure_beside_controller_logs(self):
        self.exercise_failure(creates_case=False)

    def test_existing_case_retains_original_result_location(self):
        self.exercise_failure(creates_case=True)


if __name__ == "__main__":
    unittest.main()
