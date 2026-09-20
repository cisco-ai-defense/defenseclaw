#!/usr/bin/env python3
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


import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_dependency_lock.py"
SCANNER_URL = (
    "https://files.pythonhosted.org/packages/aa/bb/"
    "cisco_ai_skill_scanner-2.0.4-py3-none-any.whl"
    "#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


class DependencyLockValidatorTests(unittest.TestCase):
    def validate(self, lock: str, source_url: str = SCANNER_URL) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pyproject = root / "pyproject.toml"
            lock_path = root / "requirements.lock"
            pyproject.write_text(
                '[project]\nname = "fixture"\nversion = "1.0.0"\n'
                f'dependencies = ["cisco-ai-skill-scanner @ {source_url}"]\n',
                encoding="utf-8",
            )
            lock_path.write_text(lock, encoding="utf-8")
            return subprocess.run(
                ["python3", str(VALIDATOR), str(pyproject), str(lock_path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )

    def test_accepts_authenticated_hash_bound_pythonhosted_reference(self) -> None:
        result = self.validate(
            f"cisco-ai-skill-scanner @ {SCANNER_URL} \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "click==8.3.3 \\\n"
            "    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_rejects_changed_direct_reference(self) -> None:
        changed = SCANNER_URL.replace("/aa/bb/", "/cc/dd/")
        result = self.validate(
            f"cisco-ai-skill-scanner @ {changed} \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unauthenticated direct reference", result.stdout)

    def test_rejects_local_paths(self) -> None:
        result = self.validate(
            "cisco-ai-skill-scanner @ file:///tmp/scanner.whl \\\n"
            "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unauthenticated direct reference", result.stdout)

    def test_rejects_missing_distribution_hash(self) -> None:
        result = self.validate(f"cisco-ai-skill-scanner @ {SCANNER_URL}\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no SHA-256 hash", result.stdout)


if __name__ == "__main__":
    unittest.main()
