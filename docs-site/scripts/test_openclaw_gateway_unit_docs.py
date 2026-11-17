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

"""The separate-user OpenClaw page documents a gateway unit that reaches active.

A slow gateway start ended `defenseclaw-gateway start` with exit 1, systemd
failed the Type=forking unit and Restart=on-failure looped
(rel-1-0-10:GAP-1160). The command now exits 0 under systemd
(internal/cli/daemon_start_messages.go); the page says so, gives the unit a
start timeout above the readiness wait, and names the SELinux label a binary
under a home folder needs.
"""

import re
import unittest
from pathlib import Path

SITE = Path(__file__).resolve().parents[1]
PAGE = SITE / "content/docs/connectors/openclaw.mdx"


class OpenClawGatewayUnitDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = PAGE.read_text()
        match = re.search(
            r"# /etc/systemd/system/defenseclaw-gateway\.service\n(.*?)\n```", cls.page, re.S
        )
        assert match, "the defenseclaw-gateway unit block is missing"
        cls.unit = match.group(1)

    def test_unit_keeps_the_daemonizing_start(self):
        self.assertIn("Type=forking", self.unit)
        self.assertRegex(self.unit, r"(?m)^ExecStart=\S*defenseclaw-gateway start$")

    def test_unit_waits_longer_than_the_readiness_wait(self):
        found = re.search(r"(?m)^TimeoutStartSec=(\d+)$", self.unit)
        self.assertTrue(found, "the unit sets no TimeoutStartSec")
        self.assertGreaterEqual(int(found.group(1)), 120)

    def test_page_says_a_slow_start_exits_zero_under_systemd(self):
        self.assertIn("`STILL STARTING`", self.page)
        self.assertIn("Started by systemd it exits 0", self.page)
        self.assertIn("run from a terminal the same command exits 1", self.page)

    def test_page_names_the_selinux_label_for_a_home_folder_binary(self):
        for text in ("SELinux", "`status=203/EXEC`", "`bin_t`", "semanage fcontext -a -t bin_t", "restorecon"):
            with self.subTest(text=text):
                self.assertIn(text, self.page)


if __name__ == "__main__":
    unittest.main()
