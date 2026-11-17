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

"""The Codex page says what the update pin does not cover (rel-1-0-10:GAP-0253).

check_for_update_on_startup = false stops Codex's update check; the app-server
daemon under ~/.codex/packages/app-server-daemon/releases is outside it.
DefenseClaw neither pins nor reports that release, so the page names the limit
and the restart that clears a stale daemon.
"""

import unittest
from pathlib import Path

SITE = Path(__file__).resolve().parents[1]
PAGE = SITE / "content/docs/connectors/codex.mdx"


class CodexAppServerPinDocsTest(unittest.TestCase):
    def test_row_names_the_limit_of_the_update_pin(self):
        page = PAGE.read_text()
        row = next(
            line for line in page.splitlines() if line.startswith("| Codex runs a newer app-server release")
        )
        for text in (
            "`check_for_update_on_startup = false`",
            "does not cover the Codex app-server daemon",
            "~/.codex/packages/app-server-daemon/releases",
            "DefenseClaw does not pin or report the daemon's release",
            "known limit",
            "`codex app-server daemon restart`",
            "401 Bearer Token has expired",
        ):
            with self.subTest(text=text):
                self.assertIn(text, row)


if __name__ == "__main__":
    unittest.main()
