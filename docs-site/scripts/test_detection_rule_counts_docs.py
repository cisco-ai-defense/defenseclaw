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

"""The rule counts on the deterministic-detection page match the shipped packs.

The counts are derived from the YAML under policies/guardrail, so a rule added
to or removed from a pack fails here until the page is updated
(rel-1-0-10:GAP-0357).
"""

import re
import unittest
from pathlib import Path

SITE = Path(__file__).resolve().parents[1]
REPO = SITE.parent
PAGE = SITE / "content/docs/policies/deterministic-detection.mdx"
PACKS = REPO / "policies/guardrail"
USE_CASES = REPO / "policies/guardrail-use-cases"

# The page names each rule file by the family it reports.
FAMILY_OF_FILE = {
    "commands.yaml": "command",
    "sensitive-paths.yaml": "sensitive-path",
    "secrets.yaml": "secret",
    "trust-exploit.yaml": "trust-exploit",
    "c2.yaml": "c2",
    "enterprise-data.yaml": "enterprise-data",
    "cognitive.yaml": "cognitive-file",
}


def rules_of(path):
    """Return [(id, enabled)] for a rule file, without a YAML dependency."""
    rules = []
    for line in path.read_text().splitlines():
        found = re.match(r"^  - id:\s*(\S+)\s*$", line)
        if found:
            rules.append([found.group(1), True])
        elif re.match(r"^    enabled:\s*false\s*$", line):
            rules[-1][1] = False
    return rules


def pack_counts(pack):
    declared = enabled = 0
    families = {}
    for path in sorted((PACKS / pack / "rules").glob("*.yaml")):
        rules = rules_of(path)
        declared += len(rules)
        on = sum(1 for _, enabled_rule in rules if enabled_rule)
        enabled += on
        if rules:
            families[FAMILY_OF_FILE[path.name]] = on
    return declared, enabled, families


class DetectionRuleCountsDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = PAGE.read_text()
        cls.default = pack_counts("default")

    def test_headline_and_family_total_match_the_default_pack(self):
        _, enabled, families = self.default
        self.assertEqual(sum(families.values()), enabled)
        self.assertIn(f"catalog contains {enabled} local rules across seven families", self.page)
        self.assertIn(f"The {enabled} enabled balanced/default rules are generated from", self.page)

    def test_profile_table_matches_each_pack(self):
        for pack, label in (("default", "Balanced/default"), ("permissive", "Permissive"), ("strict", "Strict")):
            with self.subTest(pack=pack):
                declared, enabled, _ = pack_counts(pack)
                row = next(line for line in self.page.splitlines() if line.startswith(f"| {label} | "))
                cells = [c.strip() for c in row.strip("|").split("|")]
                self.assertEqual(cells[1:3], [str(declared), str(enabled)])

    def test_family_table_matches_the_default_pack(self):
        _, _, families = self.default
        for family, count in families.items():
            with self.subTest(family=family):
                row = next(line for line in self.page.splitlines() if line.startswith(f"| `{family}` | "))
                self.assertEqual(row.split("|")[2].strip(), str(count))

    def test_high_assurance_pack_rows_match_the_use_case_packs(self):
        row = next(line for line in self.page.splitlines() if line.startswith("| `privacy-high-assurance` | "))
        count = len(rules_of(USE_CASES / "privacy-high-assurance/rules/enterprise-data.yaml"))
        self.assertRegex(row.split("|")[3], rf"^\s*{count} structured PII rules")

    def test_email_severity_paragraph_is_present(self):
        # The paragraph s7/gap172 wrote; merge 6d0398e51f dropped it once (GAP-0357).
        self.assertIn("Email addresses are scored by how many there are.", self.page)
        self.assertIn("PII-EMAIL-LIST", self.page)
        self.assertIn("PII-EMAIL-FIELD", self.page)


if __name__ == "__main__":
    unittest.main()
