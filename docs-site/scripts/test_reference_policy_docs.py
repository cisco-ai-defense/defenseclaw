# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Regression checks for policy-related reference claims."""

import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs/reference"


class ReferencePolicyDocsTest(unittest.TestCase):
    def test_fail_modes_distinguish_managed_refusals_from_user_outages(self):
        text = (DOCS / "configuration/fail-modes.mdx").read_text()
        behavior = text.split("## Effective behavior", 1)[1].split("### Stop", 1)[0]
        self.assertIn("Managed standalone `open`", behavior)
        rows = [line for line in behavior.splitlines() if line.startswith("| ")]
        for label in ("Gateway 5xx", "Connector authentication missing",
                      "Gateway returns 4xx", "Hook input over"):
            row = next(line for line in rows if line.startswith("| " + label))
            self.assertIn("Block", row.split("|")[3])
        # A cut-off error answer and a 429 the gateway cannot answer in time
        # are error statuses, not outages (W6 review loop 1).
        for label in ("Gateway 5xx", "Gateway returns 4xx"):
            row = next(line for line in rows if line.startswith("| " + label))
            self.assertIn("cut off", row.split("|")[1])
        row = next(line for line in rows if line.startswith("| Gateway returns 4xx"))
        self.assertIn("429", row.split("|")[1])


    def test_amp_is_excluded_from_persisted_fail_open_reporting(self):
        text = (DOCS / "configuration/fail-modes.mdx").read_text()
        reporting = text.split("## Reporting and diagnosis", 1)[1]
        self.assertNotIn("A call that ran fail-open is never silent", reporting)
        self.assertIn("Amp", reporting)
        self.assertIn("does not write", reporting)
        self.assertIn("guardrail-degraded", reporting)


    def test_zero_consensus_uses_sdk_default_without_disabling_llm(self):
        text = (DOCS / "configuration/index.mdx").read_text()
        row = next(line for line in text.splitlines()
                   if line.startswith("| `scanners.skill_scanner.llm_consensus_runs` |"))
        self.assertIn("`0` leaves the SDK default", row)
        self.assertIn("`use_llm: false` disables LLM analysis", row)


    def test_secure_client_status_and_digest_exceptions_are_explicit(self):
        text = (DOCS / "commands/cli.mdx").read_text()
        status = next(line for line in text.splitlines()
                      if line.startswith("| `defenseclaw status` |"))
        digest = next(line for line in text.splitlines()
                      if line.startswith("| `defenseclaw-gateway policy digest"))
        self.assertIn("Secure Client", status)
        self.assertIn("neither the Policy line", status)
        self.assertIn("nor the `policy` object", status)
        self.assertIn("Secure Client", digest)
        self.assertIn("unknown-command error", digest)
        section = text.split("### Policy generation and digest", 1)[1].split("## ", 1)[0]
        self.assertIn("Not available on Secure Client", section)


    def test_remote_skill_scan_uses_gateway_timeout(self):
        text = (DOCS / "configuration/index.mdx").read_text()
        row = next(line for line in text.splitlines()
                   if line.startswith("| `scanners.skill_scanner.timeouts.scan_s` |"))
        self.assertIn("`defenseclaw skill scan --remote`", row)
        self.assertIn("`defenseclaw skill scan` without `--remote`", row)


    def test_effective_config_is_file_resolution_not_live_gateway(self):
        text = (DOCS / "commands/cli.mdx").read_text()
        row = next(line for line in text.splitlines()
                   if line.startswith("| `defenseclaw config get KEY"))
        section = text.split("`--effective` resolves", 1)[1].split("### Managed devices", 1)[0]
        self.assertIn("current `config.yaml`", row)
        self.assertIn("does not query the running gateway", section)
        self.assertIn("rejected reload", section)
        self.assertIn("`defenseclaw status`", section)


    def test_edited_generated_hook_can_run_before_repair(self):
        text = (DOCS / "configuration/source-of-truth.mdx").read_text()
        section = text.split("## What is derived", 1)[1].split("## What is evidence", 1)[0]
        self.assertIn("next hook event", section)
        self.assertIn("before repair", section)
        self.assertNotIn("editing one changes nothing", section)


    def test_managed_guardrail_refusal_uses_exit_three(self):
        text = (DOCS / "commands/cli.mdx").read_text()
        section = text.split("### Managed devices and exit code 3", 1)[1].split("## Registries", 1)[0]
        self.assertIn("`guardrail ...` writers", section)
        self.assertIn("exit `3`", section)
        self.assertIn("change config.yaml in the admin config", section)
        self.assertNotIn("with exit `1`", section)


if __name__ == "__main__":
    unittest.main()
