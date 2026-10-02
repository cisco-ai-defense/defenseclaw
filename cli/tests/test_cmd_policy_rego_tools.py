"""GAP-1091: policy validate/test fall back to defenseclaw-gateway without opa."""

import os
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_policy import _rego_dir

from tests.test_cmd_policy import PolicyCommandTestBase

GATEWAY = "/opt/fake/defenseclaw-gateway"


class TestPolicyRegoToolsWithoutOPA(PolicyCommandTestBase):
    def _run(self, args):
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="PASS: 1/1\n", stderr="")

        with (
            patch("shutil.which", return_value=None),
            patch("defenseclaw.gateway.resolve_gateway_binary", return_value=GATEWAY),
            patch("defenseclaw.commands.cmd_policy.subprocess.run", side_effect=fake_run),
        ):
            result = self.invoke(args)
        return result, calls

    def test_validate_uses_gateway_when_opa_missing(self):
        rd = _rego_dir()
        result, calls = self._run(["validate", "--rego-dir", rd])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(calls, [[GATEWAY, "policy", "validate", "--rego-dir", rd]])
        self.assertIn("defenseclaw-gateway", result.output)
        self.assertNotIn("brew install opa", result.output)

    def test_test_uses_gateway_when_opa_missing(self):
        rd = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rd, ignore_errors=True)
        with open(os.path.join(rd, "policy_test.rego"), "w") as f:
            f.write("package defenseclaw_test\n")
        result, calls = self._run(["test", "--rego-dir", rd, "-v"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(calls, [[GATEWAY, "policy", "test", "--rego-dir", rd, "-v"]])
        self.assertIn("All Rego tests passed.", result.output)

    def test_test_without_test_files_has_nothing_to_run(self):
        # Installed policy directories ship no *_test.rego (GAP-1091).
        rd = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rd, ignore_errors=True)
        with open(os.path.join(rd, "guardrail.rego"), "w") as f:
            f.write("package defenseclaw.guardrail\n")
        result, calls = self._run(["test", "--rego-dir", rd])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(calls, [])
        self.assertIn("nothing to run", result.output)

    def test_validate_fails_closed_without_any_checker(self):
        with (
            patch("shutil.which", return_value=None),
            patch("defenseclaw.gateway.resolve_gateway_binary", return_value=None),
        ):
            result = self.invoke(["validate", "--rego-dir", _rego_dir()])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("no Rego checker found", result.output)
