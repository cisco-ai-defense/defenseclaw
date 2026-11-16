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

"""GAP-0592: doctor names OpenClaw's device approval step.

The gateway no longer writes OpenClaw's pairing state. When OpenClaw refuses
its device, the gateway keeps retrying and publishes the operator step on the
gateway subsystem of /health; doctor must show it as the row's next step.
"""

import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import _check_sidecar, _DoctorResult
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig

_HINT = (
    "OpenClaw has not approved the DefenseClaw device abc (client gateway-client). "
    "Run 'openclaw devices list', then 'openclaw devices approve <requestId>' for its pending request. "
    "DefenseClaw keeps retrying and connects once it is approved"
)


def _cfg() -> Config:
    cfg = Config(
        data_dir="/tmp/defenseclaw",
        audit_db="/tmp/defenseclaw/audit.db",
        quarantine_dir="/tmp/defenseclaw/quarantine",
        plugin_dir="/tmp/defenseclaw/plugins",
        policy_dir="/tmp/defenseclaw/policies",
        guardrail=GuardrailConfig(enabled=True, connector="openclaw"),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    cfg.claw.mode = "openclaw"
    return cfg


class DoctorOpenClawPairingHintTests(unittest.TestCase):
    def setUp(self):
        from defenseclaw.commands import cmd_doctor

        trusted = patch.object(
            cmd_doctor,
            "_trusted_gateway_listener",
            return_value=cmd_doctor._GatewayTrust("trusted", "verified fixture gateway", 4321),
        )
        trusted.start()
        self.addCleanup(trusted.stop)

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_gateway_row_names_the_openclaw_approval_step(self, mock_probe):
        mock_probe.return_value = (
            200,
            json.dumps(
                {
                    "gateway": {
                        "state": "reconnecting",
                        "last_error": "gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)",
                        "details": {"reason": "openclaw_operator_action_required", "hint": _HINT},
                    },
                    "watcher": {"state": "running"},
                    "guardrail": {"state": "running", "details": {"mode": "observe"}},
                    "api": {"state": "running"},
                    "telemetry": {"state": "running"},
                }
            ),
        )
        result = _DoctorResult()
        _check_sidecar(_cfg(), result)
        rows = [c for c in result.checks if c.get("label", "").strip().endswith("gateway")]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["status"], "fail")
        self.assertIn("reconnecting", rows[0]["detail"])
        self.assertIn("NOT_PAIRED", rows[0]["detail"])
        self.assertEqual(rows[0]["remediation"], _HINT)

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_plain_reconnecting_row_is_unchanged(self, mock_probe):
        mock_probe.return_value = (
            200,
            json.dumps(
                {
                    "gateway": {"state": "reconnecting"},
                    "watcher": {"state": "running"},
                    "guardrail": {"state": "running", "details": {"mode": "observe"}},
                    "api": {"state": "running"},
                    "telemetry": {"state": "running"},
                }
            ),
        )
        result = _DoctorResult()
        _check_sidecar(_cfg(), result)
        rows = [c for c in result.checks if c.get("label", "").strip().endswith("gateway")]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["status"], "fail")
        self.assertEqual(rows[0]["detail"], "reconnecting")


if __name__ == "__main__":
    unittest.main()
