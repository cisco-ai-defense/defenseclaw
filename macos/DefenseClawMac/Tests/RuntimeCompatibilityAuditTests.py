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


import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / ".codex"
    / "skills"
    / "defenseclaw-runtime-compat"
    / "scripts"
    / "audit_compatibility.py"
)
SPEC = importlib.util.spec_from_file_location("audit_compatibility", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class RuntimeCompatibilityAuditTests(unittest.TestCase):
    def test_protected_wheel_decode_is_not_a_legacy_assignment(self) -> None:
        source = 'DECODED_WHEEL="$RUNTIME_DIR/defenseclaw-${RUNTIME_VERSION}-py3-none-any.whl"\n'
        value = '"$RUNTIME_DIR/defenseclaw-${RUNTIME_VERSION}-py3-none-any.whl"'

        self.assertFalse(AUDIT.has_shell_assignment(source, "WHEEL", value))

    def test_legacy_wheel_assignment_is_detected(self) -> None:
        source = '  export WHEEL = "$RUNTIME_DIR/defenseclaw-${RUNTIME_VERSION}-py3-none-any.whl" # old\n'
        value = '"$RUNTIME_DIR/defenseclaw-${RUNTIME_VERSION}-py3-none-any.whl"'

        self.assertTrue(AUDIT.has_shell_assignment(source, "WHEEL", value))

    def test_version_skew_uses_installed_package_requirements(self) -> None:
        self.assertEqual(AUDIT.dependency_probe_mode("0.8.10", "0.8.6"), "installed")
        self.assertEqual(AUDIT.dependency_probe_mode("0.8.10", "0.8.10"), "upstream")


if __name__ == "__main__":
    unittest.main()
