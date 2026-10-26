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

"""Regression check for the documented enterprise policy alert path."""

import unittest
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "content/docs/enterprise/operations.mdx"


class PolicyAlertDocsTest(unittest.TestCase):
    def test_verify_policy_warnings_have_explicit_alert_path(self):
        alerts = DOC.read_text().split("### What to alert on", 1)[1].split(
            "## Effective policy digest", 1
        )[0]
        self.assertIn("policy_reload_rejected", alerts)
        self.assertIn("policy_not_applied", alerts)
        self.assertRegex(alerts, r"policy_not_applied[^\n]*changing actions")
        self.assertRegex(alerts, r"policy warnings[^\n]*verify[^\n]*exit code")
        self.assertNotIn("verify` reports each as an error", alerts)


if __name__ == "__main__":
    unittest.main()
