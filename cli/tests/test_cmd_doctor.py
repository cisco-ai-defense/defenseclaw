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

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import _DoctorResult, _check_guardrail_proxy
from defenseclaw.config import Config, GuardrailConfig, GatewayConfig, OpenShellConfig


class DoctorGuardrailTests(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_doctor._emit")
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_empty_guardrail_model_is_warning_not_failure(self, _mock_probe, mock_emit):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="", port=4000),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 1)
        self.assertEqual(result.passed, 1)
        mock_emit.assert_any_call(
            "warn",
            "Guardrail proxy",
            "guardrail.model is empty — relying on fetch-interceptor routing",
        )


if __name__ == "__main__":
    unittest.main()
