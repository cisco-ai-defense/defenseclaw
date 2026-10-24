# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0461: the doctor Rule pack row states each connector's real prompt capability.

The detection-only warning said "prompts still block" for every connector,
also for OpenCode, whose user prompts reach the model. The wording now comes
from the hook contract manifest (the same data the docs capability matrix is
checked against), one class per test.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defenseclaw.commands.cmd_doctor import (
    _check_connector_inventory,
    _DoctorResult,
    _prompt_block_capability,
)
from defenseclaw.connector_contracts import HOOK_CONTRACT_MANIFEST
from defenseclaw.rulepack_validation import RulePackValidationResult

# Every connector the manifest knows, by the class its prompt hook falls in.
PROMPT_BLOCKING = ("claudecode", "codex", "cursor", "devin",  )
PROXY = ("openclaw", "zeptoclaw")
NO_PROMPT_HOOK = ("opencode", "copilot", "hermes", "amp", "antigravity")
# Block events resolved per request from the hook surface (no versioned
# contract): Kiro IDE vetoes a prompt, neither kiro-cli engine does.
SURFACE_DEPENDENT = ("kiro",)


def _cfg() -> MagicMock:
    cfg = MagicMock()
    cfg.skill_dirs.return_value = []
    cfg.plugin_dirs.return_value = []
    cfg.mcp_servers.return_value = []
    cfg.data_dir = "/tmp/dc-doctor-prompt-capability"
    cfg.guardrail.effective_mode.return_value = "action"
    cfg.guardrail.effective_rule_pack_dir.return_value = "/tmp/wv102-pack"
    cfg.guardrail.effective_rule_pack.return_value = ""
    cfg.guardrail.detection_strategy = "regex_only"
    cfg.guardrail.judge.enabled = False
    cfg.guardrail.judge.hook_connectors = []
    return cfg


def _detection_only_pack() -> RulePackValidationResult:
    return RulePackValidationResult(
        wire_version=1,
        kind="validation",
        valid=True,
        summary={
            "rule_count": 245,
            "enabled_rule_count": 241,
            "stale_rule_count": 0,
            "alert_only_rule_count": 1,
            "digest": "a" * 64,
            "files_digest": "",
        },
    )


@patch("defenseclaw.commands.cmd_doctor.rulepack_validation.validate_rule_pack")
class TestRulePackPromptCapability(unittest.TestCase):
    def _row(self, validate, connector: str) -> dict:
        validate.return_value = _detection_only_pack()
        r = _DoctorResult()
        _check_connector_inventory(_cfg(), connector, r)
        row = next(c for c in r.checks if c["label"] == "Rule pack")
        self.assertEqual(row["status"], "warn")
        self.assertIn("detection-only for tool calls", row["detail"])
        return row

    def test_classes_cover_every_manifest_connector(self, _validate):
        known = set(HOOK_CONTRACT_MANIFEST["connectors"])
        self.assertEqual(known, set(PROMPT_BLOCKING) | set(PROXY) | set(NO_PROMPT_HOOK) | set(SURFACE_DEPENDENT))

    def test_prompt_hook_connectors_say_prompts_still_block(self, validate):
        for connector in PROMPT_BLOCKING:
            with self.subTest(connector=connector):
                self.assertEqual(_prompt_block_capability(connector), "blocks")
                row = self._row(validate, connector)
                self.assertIn("prompts still block", row["detail"])
                self.assertNotIn("no hook that can block a prompt", row["detail"])

    def test_proxy_connectors_say_prompts_still_block(self, validate):
        for connector in PROXY:
            with self.subTest(connector=connector):
                self.assertEqual(_prompt_block_capability(connector), "blocks")
                self.assertIn("prompts still block", self._row(validate, connector)["detail"])

    def test_connectors_without_a_prompt_hook_say_prompts_reach_the_model(self, validate):
        # The wave run (WV-A-06a): OpenCode answered a prompt that matched a
        # CRITICAL prompt-only rule, while its tool-call marker was blocked.
        for connector in NO_PROMPT_HOOK:
            with self.subTest(connector=connector):
                self.assertEqual(_prompt_block_capability(connector), "no-hook")
                detail = self._row(validate, connector)["detail"]
                self.assertNotIn("prompts still block", detail)
                self.assertIn("has no hook that can block a prompt", detail)
                self.assertIn("they reach the model, and only tool calls are blocked", detail)
        self.assertIn("OpenCode has no hook", self._row(validate, "opencode")["detail"])

    def test_surface_dependent_connector_names_the_clients(self, validate):
        # The DELTA-1 verifier: Kiro still said "prompts still block", from
        # the v3 surface's block events, although kiro-cli 2.24.1 --v3 sends a
        # blocked prompt to the model and the unmarked 2.x surface blocks tool
        # calls only.
        for connector in SURFACE_DEPENDENT:
            with self.subTest(connector=connector):
                self.assertEqual(_prompt_block_capability(connector), "surface")
                detail = self._row(validate, connector)["detail"]
                self.assertNotIn("never blocked; prompts still block)", detail)
                self.assertNotIn("no hook that can block a prompt", detail)
        self.assertIn(
            "(a match is recorded, never blocked; prompts still block only in Kiro IDE; "
            "kiro-cli sends every prompt to the model and blocks tool calls only)",
            self._row(validate, "kiro")["detail"],
        )

    def test_unknown_connector_makes_no_prompt_claim(self, validate):
        self.assertEqual(_prompt_block_capability("not-a-connector"), "unknown")
        detail = self._row(validate, "not-a-connector")["detail"]
        self.assertNotIn("prompts still block", detail)
        self.assertNotIn("no hook that can block a prompt", detail)
        self.assertIn("(a match is recorded, never blocked)", detail)


if __name__ == "__main__":
    unittest.main()
