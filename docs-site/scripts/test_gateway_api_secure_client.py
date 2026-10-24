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

"""Keep Secure Client route availability aligned with the gateway API reference."""

import unittest
from pathlib import Path


class SecureClientAPIDocsTest(unittest.TestCase):
    def test_identity_and_ide_routes_are_documented_as_absent(self):
        text = (Path(__file__).resolve().parents[1] / "content/docs/reference/apis/gateway-api.mdx").read_text()
        for route in ("/api/v1/agents/identities", "/api/v1/ai-usage/ide-plugins"):
            row = next(line for line in text.splitlines() if line.startswith("| `GET` | `" + route + "` |"))
            self.assertIn("404", row, route)
            self.assertIn("Secure Client", row, route)


if __name__ == "__main__":
    unittest.main()
