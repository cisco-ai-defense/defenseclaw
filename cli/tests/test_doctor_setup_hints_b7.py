# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Doctor hints for a refused private upstream (GAP-1703) and an agent
executable setup could not verify (GAP-1711)."""

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from defenseclaw import agent_selection
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult

HOST = "bedrock-runtime.us-east-1.amazonaws.com"


class DoctorSetupHintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data_dir = self.tmp.name

    def _run(self, check, cfg) -> _DoctorResult:
        r = _DoctorResult()
        with mock.patch.object(cmd_doctor, "_json_mode", True):
            check(cfg, r)
        return r

    def test_refused_private_upstream_warns_until_allowed(self) -> None:
        with open(os.path.join(self.data_dir, "gateway.log"), "w", encoding="utf-8") as fh:
            fh.write(
                f"[guardrail] refused private upstream: host={HOST} ip=10.0.2.169; "
                f"allow it with: defenseclaw guardrail allow-private-upstream {HOST}\n"
            )
        guardrail = SimpleNamespace(enabled=True, allow_private_upstreams=[])
        cfg = SimpleNamespace(data_dir=self.data_dir, guardrail=guardrail)

        r = self._run(cmd_doctor._check_private_upstream_refusals, cfg)
        self.assertEqual(r.warned, 1, r.checks)
        self.assertIn("10.0.2.169", r.checks[0]["detail"])
        self.assertIn(f"defenseclaw guardrail allow-private-upstream {HOST}", str(r.checks[0]))

        guardrail.allow_private_upstreams = ["10.0.2.169"]
        self.assertEqual(self._run(cmd_doctor._check_private_upstream_refusals, cfg).checks, [])

    def test_unverified_executable_is_reported_until_setup_verifies_it(self) -> None:
        agent_selection.record_unverified_setup_agents(
            self.data_dir, {"claudecode": "version probe timed out"}, ["codex"]
        )
        cfg = SimpleNamespace(data_dir=self.data_dir)
        detail, step = cmd_doctor._unverified_executable_note(cfg, "claudecode")
        self.assertIn("version probe timed out", detail)
        self.assertEqual(step, "run 'defenseclaw setup claude-code' once the executable starts normally")
        self.assertEqual(cmd_doctor._unverified_executable_note(cfg, "codex"), ("", ""))

        agent_selection.record_unverified_setup_agents(self.data_dir, {}, ["claudecode"])
        self.assertEqual(cmd_doctor._unverified_executable_note(cfg, "claudecode"), ("", ""))
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, agent_selection.UNVERIFIED_FILENAME)))


if __name__ == "__main__":
    unittest.main()
