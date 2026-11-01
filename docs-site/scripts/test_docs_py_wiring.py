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

"""The docs-site Python page checks run in the docs CI job (GAP-0011)."""

import json
import re
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SITE = SCRIPTS.parent
WORKFLOW = SITE.parent / ".github/workflows/docs-site.yml"


class DocsPythonChecksAreWiredTest(unittest.TestCase):
    def test_npm_script_and_ci_step_run_them(self):
        scripts = json.loads((SITE / "package.json").read_text())["scripts"]
        self.assertEqual(scripts.get("test:docs-py"), "python3 -m unittest discover -s scripts -p 'test_*.py'")
        self.assertRegex(WORKFLOW.read_text(), r"\n        run: npm run test:docs-py\n")

    def test_every_file_is_a_unittest_case(self):
        # `unittest discover` skips module-level pytest functions, so a file
        # written that way would guard nothing in CI.
        for path in sorted(SCRIPTS.glob("test_*.py")):
            with self.subTest(file=path.name):
                text = path.read_text()
                self.assertRegex(text, r"(?m)^class \w+\(unittest\.TestCase\):")
                self.assertIsNone(re.search(r"(?m)^def test_", text))


if __name__ == "__main__":
    unittest.main()
