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

"""Regression check for the documented manual 0.8.x rollback."""

import unittest
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "content/docs/reference/migrate-v9.mdx"


class ManualRollbackDocsTest(unittest.TestCase):
    def test_restores_saved_v8_rego_modules(self):
        rollback = DOC.read_text().split("## Going back to 0.8.x", 1)[1]
        self.assertIn("for module in admission guardrail skill_actions; do", rollback)
        self.assertIn('mv "$module.rego.migrated-v9" "$module.rego"', rollback)

    def test_restores_legacy_provider_overlay(self):
        rollback = DOC.read_text().split("## Going back to 0.8.x", 1)[1]
        self.assertIn("custom-providers.json.migrated-v9", rollback)
        self.assertIn("mv custom-providers.json.migrated-v9 custom-providers.json", rollback)

    def test_legacy_windows_setup_rollback_is_documented(self):
        migration = DOC.read_text().split("## Going back to 0.8.x", 1)[1]
        upgrade = (DOC.parents[1] / "get-started/upgrade.mdx").read_text()
        for guidance in (migration, upgrade):
            self.assertIn("0.8.7-0.8.10", guidance)
            self.assertIn("defenseclaw uninstall", guidance)
            self.assertIn("DefenseClawSetup-x64.exe", guidance)


if __name__ == "__main__":
    unittest.main()
