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

"""RV-SYNC3 F2 (GAP-0734): a substrate.git.https_rewrite "to" ends in "/"."""

import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defenseclaw.config import _merge_substrate_git  # noqa: E402

_SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json"


def _find(node, key):
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for v in node.values():
            found = _find(v, key)
            if found is not None:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _find(v, key)
            if found is not None:
                return found
    return None


class TestGitRewriteToEndsInSlash(unittest.TestCase):
    def test_schema_pattern(self):
        to = _find(json.loads(_SCHEMA.read_text()), "https_rewrite")["items"]["properties"]["to"]
        pat = re.compile(to["pattern"])
        for ok in ("https://ghe.example/", "https://ghe.example/scm/", "https://ghe.example:8443/"):
            self.assertTrue(pat.search(ok), ok)
        for bad in ("https://ghe.example", "https://ghe.example/scm", "https://u@ghe.example/"):
            self.assertIsNone(pat.search(bad), bad)

    def test_mirror_drops_a_to_without_slash(self):
        g = _merge_substrate_git(
            {
                "https_rewrite": [
                    {"from": "git@a.example:", "to": "https://a.example"},
                    {"from": "git@b.example:", "to": "https://b.example/"},
                ]
            }
        )
        self.assertEqual(g.https_rewrite, [{"from": "git@b.example:", "to": "https://b.example/"}])


if __name__ == "__main__":
    unittest.main()
