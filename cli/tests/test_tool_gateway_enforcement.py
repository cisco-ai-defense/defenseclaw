# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1879: tool block/allow/unblock say whether the running gateway enforces the change."""

from __future__ import annotations

import itertools
import os
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_tool import tool

from tests.helpers import cleanup_app, make_app_context


class _Client:
    """A gateway whose applied digest moves to the new one after `lag` health calls."""

    def __init__(self, digests):
        self.digests = list(digests)
        self.closed = False

    def health(self):
        digest = self.digests.pop(0) if len(self.digests) > 1 else self.digests[0]
        return {"policy": {"effective_digest": digest}}

    def close(self):
        self.closed = True


class TestToolGatewayEnforcement(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def run_with(self, client, args, digest="sha256:new"):
        with (
            unittest.mock.patch("defenseclaw.gateway.OrchestratorClient", return_value=client),
            unittest.mock.patch("defenseclaw.gateway.foreign_loopback_listener", return_value=""),
            unittest.mock.patch("defenseclaw.gateway.local_policy_digest", return_value={"effective_digest": digest}),
            unittest.mock.patch("time.sleep"),
        ):
            return self.runner.invoke(tool, args, obj=self.app, catch_exceptions=False)

    def test_block_waits_until_the_gateway_applies_it(self):
        client = _Client(["sha256:old", "sha256:old", "sha256:new"])
        result = self.run_with(client, ["block", "bash", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("The running gateway enforces it now", result.output)
        self.assertTrue(client.closed)

    def test_unblock_and_allow_say_so_too(self):
        self.run_with(_Client(["sha256:new"]), ["block", "bash", "--connector", "codex"])
        for args in (["unblock", "bash", "--connector", "codex"], ["allow", "bash", "--connector", "codex"]):
            result = self.run_with(_Client(["sha256:new"]), args)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("The running gateway enforces it now", result.output)

    def test_a_gateway_that_does_not_apply_it_in_time_is_pending(self):
        clock = itertools.count(0.0, 1.0)
        with unittest.mock.patch("time.monotonic", side_effect=lambda: next(clock)):
            result = self.run_with(_Client(["sha256:old"]), ["block", "bash", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Pending: the running gateway has not applied it yet", result.output)

    def test_no_gateway_says_nothing(self):
        class Down(_Client):
            def health(self):
                raise ConnectionError("refused")

        result = self.run_with(Down(["x"]), ["block", "bash", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("running gateway", result.output)


if __name__ == "__main__":
    unittest.main()
