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
    def _run(self, args, opa=None):
        calls = []

        def fake_run(cmd, **_kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="PASS: 1/1\n", stderr="")

        with (
            patch("shutil.which", return_value=opa),
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

    def test_validate_prefers_gateway_over_opa(self):
        # The gateway loader refuses a module reading data.config, which
        # opa check accepts: its verdict is the one that holds.
        rd = _rego_dir()
        result, calls = self._run(["validate", "--rego-dir", rd], opa="/usr/bin/opa")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(calls, [[GATEWAY, "policy", "validate", "--rego-dir", rd]])

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
        # GAP-1392: the modules are still compiled before "nothing to run".
        self.assertEqual(calls, [[GATEWAY, "policy", "validate", "--rego-dir", rd]])
        self.assertIn("nothing to run", result.output)

    def test_test_without_test_files_fails_when_modules_do_not_compile(self):
        # GAP-1392: a broken policy dir with no tests must not pass.
        rd = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, rd, ignore_errors=True)
        with open(os.path.join(rd, "guardrail.rego"), "w") as f:
            f.write("package defenseclaw.guardrail\nallow_broken if { input.x ==\n")

        def failing_run(cmd, **_kwargs):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="rego_parse_error\n")

        with (
            patch("shutil.which", return_value=None),
            patch("defenseclaw.gateway.resolve_gateway_binary", return_value=GATEWAY),
            patch("defenseclaw.commands.cmd_policy.subprocess.run", side_effect=failing_run),
        ):
            result = self.invoke(["test", "--rego-dir", rd])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("rego_parse_error", result.output)
        self.assertNotIn("nothing to run", result.output)

    def test_test_defaults_to_the_user_policy_dir(self):
        # GAP-1459: without --rego-dir, test the policies the gateway loads
        # (<policy_dir>/rego), not the bundled copy inside the package.
        user_rego = os.path.join(self.app.cfg.policy_dir, "rego")
        os.makedirs(user_rego, exist_ok=True)
        with open(os.path.join(user_rego, "guardrail.rego"), "w") as f:
            f.write("package defenseclaw.guardrail\n")
        result, _calls = self._run(["test"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(user_rego, result.output)
        self.assertNotIn("site-packages", result.output)

    def test_delete_help_has_no_internal_tags(self):
        result = self.invoke(["delete", "--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("(N1)", result.output)
        self.assertNotIn("data.json", result.output)

    def test_validate_fails_closed_without_any_checker(self):
        with (
            patch("shutil.which", return_value=None),
            patch("defenseclaw.gateway.resolve_gateway_binary", return_value=None),
        ):
            result = self.invoke(["validate", "--rego-dir", _rego_dir()])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("no Rego checker found", result.output)
