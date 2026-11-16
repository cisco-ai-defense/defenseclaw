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

"""The skill scanner reads its rule packs with libyaml (rel-1-0-6 GAP-0113)."""

import tempfile
import unittest
from pathlib import Path

import yaml
from defenseclaw.scanner import _skill_judge_compat as compat
from skill_scanner.core import rule_registry


@unittest.skipUnless(hasattr(yaml, "CSafeLoader"), "PyYAML is built without libyaml")
class RulePackYamlTest(unittest.TestCase):
    def setUp(self):
        original = rule_registry._DuplicateKeySafeLoader
        self.addCleanup(setattr, rule_registry, "_DuplicateKeySafeLoader", original)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def _load(self, text: str):
        path = Path(self.dir.name) / "pack.yaml"
        path.write_text(text, encoding="utf-8")
        return rule_registry._load_strict_yaml(path)

    def test_rule_packs_load_through_libyaml_with_the_same_result(self):
        text = "signatures:\n  - id: R1\n    patterns: ['a+', 'b']\n    flag: yes\n    n: 3\n"
        before = self._load(text)
        self.assertTrue(compat.use_libyaml_for_rule_packs())
        self.assertTrue(issubclass(rule_registry._DuplicateKeySafeLoader, yaml.CSafeLoader))
        self.assertEqual(self._load(text), before)

    def test_a_duplicate_key_is_still_refused(self):
        self.assertTrue(compat.use_libyaml_for_rule_packs())
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            self._load("id: R1\nid: R2\n")

    def test_install_is_idempotent(self):
        self.assertTrue(compat.use_libyaml_for_rule_packs())
        loader = rule_registry._DuplicateKeySafeLoader
        self.assertTrue(compat.use_libyaml_for_rule_packs())
        self.assertIs(rule_registry._DuplicateKeySafeLoader, loader)

    def test_a_scanner_without_the_loader_is_left_as_shipped(self):
        saved = rule_registry._construct_unique_mapping
        del rule_registry._construct_unique_mapping
        self.addCleanup(setattr, rule_registry, "_construct_unique_mapping", saved)
        loader = rule_registry._DuplicateKeySafeLoader
        self.assertFalse(compat.use_libyaml_for_rule_packs())
        self.assertIs(rule_registry._DuplicateKeySafeLoader, loader)
