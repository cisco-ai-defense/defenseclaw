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

import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _DoctorResult,
    _parse_hec_response,
    _probe_splunk_hec,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_destination(name="splunk-audit", index=None):
    """Minimal Destination-like object for probe tests."""
    return SimpleNamespace(
        name=name,
        kind="splunk_hec",
        preset_id="splunk-hec",
        endpoint="http://splunk.example.com:8088/services/collector/event",
        index=index,
    )


def _make_cfg():
    return SimpleNamespace(data_dir="/tmp/defenseclaw-test")


def _hec_body(code: int, text: str) -> str:
    return json.dumps({"text": text, "code": code})


def _checks_with_status(result: _DoctorResult, status: str):
    return [c for c in result.checks if c["status"] == status]


# ---------------------------------------------------------------------------
# _parse_hec_response unit tests
# ---------------------------------------------------------------------------

class ParseHECResponseTests(unittest.TestCase):

    def test_success_code_zero(self):
        hec_code, msg = _parse_hec_response('{"text":"Success","code":0}')
        self.assertEqual(hec_code, 0)
        self.assertIn("success", msg.lower())

    def test_invalid_token_code_four(self):
        hec_code, msg = _parse_hec_response('{"text":"Invalid token","code":4}')
        self.assertEqual(hec_code, 4)
        self.assertIn("invalid token", msg.lower())

    def test_incorrect_index_code_seven(self):
        hec_code, msg = _parse_hec_response('{"text":"Incorrect index","code":7}')
        self.assertEqual(hec_code, 7)
        self.assertIn("index", msg.lower())

    def test_server_busy_code_nine(self):
        hec_code, msg = _parse_hec_response('{"text":"Server is busy","code":9}')
        self.assertEqual(hec_code, 9)
        self.assertIn("busy", msg.lower())

    def test_queues_full_code_eighteen(self):
        hec_code, msg = _parse_hec_response('{"text":"HEC is unhealthy, queues are full","code":18}')
        self.assertEqual(hec_code, 18)
        self.assertIn("queue", msg.lower())

    def test_non_json_body_returns_none_code(self):
        hec_code, msg = _parse_hec_response("<html>Bad Gateway</html>")
        self.assertIsNone(hec_code)
        self.assertIn("Bad Gateway", msg)

    def test_empty_body(self):
        hec_code, msg = _parse_hec_response("")
        self.assertIsNone(hec_code)

    def test_unknown_hec_code_falls_back_to_text(self):
        hec_code, msg = _parse_hec_response('{"text":"Something new","code":99}')
        self.assertEqual(hec_code, 99)
        self.assertIn("Something new", msg)


# ---------------------------------------------------------------------------
# _probe_splunk_hec integration tests
# ---------------------------------------------------------------------------

class ProbeSplunkHECTests(unittest.TestCase):

    def _run_probe(self, http_code, body, index=None):
        """Helper: run _probe_splunk_hec with a mocked _http_probe and
        _resolve_audit_sink_endpoint_and_token, returning the result."""
        d = _make_destination(index=index)
        cfg = _make_cfg()
        result = _DoctorResult()
        with patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(http_code, body),
        ), patch(
            "defenseclaw.commands.cmd_doctor._resolve_audit_sink_endpoint_and_token",
            return_value=(d.endpoint, "test-token"),
        ), patch(
            "defenseclaw.commands.cmd_doctor._check_splunk_token_posture",
        ):
            _probe_splunk_hec(cfg, d, result)
        return result

    # --- success paths ---

    def test_200_success_emits_pass(self):
        result = self._run_probe(200, _hec_body(0, "Success"))
        self.assertEqual(len(_checks_with_status(result, "pass")), 1)
        self.assertEqual(len(_checks_with_status(result, "fail")), 0)

    def test_200_hec_healthy_code_17_emits_pass(self):
        result = self._run_probe(200, _hec_body(17, "HEC is healthy"))
        self.assertEqual(len(_checks_with_status(result, "pass")), 1)

    def test_200_unexpected_hec_code_emits_warn(self):
        result = self._run_probe(200, _hec_body(9, "Server is busy"))
        self.assertEqual(len(_checks_with_status(result, "warn")), 1)

    # --- auth failure paths ---

    def test_403_disabled_token_code_1_mentions_disabled(self):
        result = self._run_probe(403, _hec_body(1, "Token disabled"))
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("disabled", fails[0]["detail"].lower())

    def test_403_invalid_token_code_4_mentions_token_env(self):
        result = self._run_probe(403, _hec_body(4, "Invalid token"))
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("token_env", fails[0]["detail"])

    def test_401_generic_auth_failure(self):
        result = self._run_probe(401, _hec_body(3, "Invalid authorization"))
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("authorization", fails[0]["detail"].lower())

    # --- bad request paths ---

    def test_400_incorrect_index_code_7_mentions_index(self):
        result = self._run_probe(400, _hec_body(7, "Incorrect index"), index="my-index")
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("index", fails[0]["detail"].lower())
        # Should include the configured index name in the message
        self.assertIn("my-index", fails[0]["detail"])

    def test_400_other_bad_request(self):
        result = self._run_probe(400, _hec_body(6, "Invalid data format"))
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("bad request", fails[0]["detail"].lower())

    # --- server busy / unavailable paths ---

    def test_503_queues_full_code_18(self):
        result = self._run_probe(503, _hec_body(18, "HEC is unhealthy, queues are full"))
        warns = _checks_with_status(result, "warn")
        self.assertEqual(len(warns), 1)
        self.assertIn("queue", warns[0]["detail"].lower())

    def test_503_server_busy_code_9(self):
        result = self._run_probe(503, _hec_body(9, "Server is busy"))
        warns = _checks_with_status(result, "warn")
        self.assertEqual(len(warns), 1)
        self.assertIn("busy", warns[0]["detail"].lower())

    def test_503_generic_unavailable(self):
        result = self._run_probe(503, "<html>Service Unavailable</html>")
        warns = _checks_with_status(result, "warn")
        self.assertEqual(len(warns), 1)
        self.assertIn("unavailable", warns[0]["detail"].lower())

    # --- network / TLS failure paths ---

    def test_network_failure_code_0_emits_warn(self):
        result = self._run_probe(0, "Connection refused")
        warns = _checks_with_status(result, "warn")
        self.assertEqual(len(warns), 1)
        self.assertIn("unreachable", warns[0]["detail"].lower())

    def test_tls_error_detected_from_body(self):
        result = self._run_probe(0, "SSL: certificate verify failed")
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("tls", fails[0]["detail"].lower())

    def test_certificate_keyword_triggers_tls_fail(self):
        result = self._run_probe(0, "certificate signed by unknown authority")
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("tls", fails[0]["detail"].lower())

    # --- missing config ---

    def test_missing_endpoint_emits_fail(self):
        d = _make_destination()
        cfg = _make_cfg()
        result = _DoctorResult()
        with patch(
            "defenseclaw.commands.cmd_doctor._resolve_audit_sink_endpoint_and_token",
            return_value=("", ""),
        ):
            _probe_splunk_hec(cfg, d, result)
        fails = _checks_with_status(result, "fail")
        self.assertEqual(len(fails), 1)
        self.assertIn("token_env", fails[0]["detail"])


# ---------------------------------------------------------------------------
# _check_splunk_token_posture tests
# ---------------------------------------------------------------------------

class CheckSplunkTokenPostureTests(unittest.TestCase):

    def _run_posture_check(self, sink_yaml):
        from defenseclaw.commands.cmd_doctor import _check_splunk_token_posture
        d = _make_destination()
        cfg = _make_cfg()
        result = _DoctorResult()
        doc = {"audit_sinks": [sink_yaml]}
        with patch(
            "defenseclaw.commands.cmd_doctor._load_yaml" if False else
            "defenseclaw.observability.writer._load_yaml",
            return_value=doc,
        ), patch(
            "defenseclaw.observability.writer.CONFIG_FILE_NAME",
            "config.yaml",
        ):
            _check_splunk_token_posture(cfg, d, "test-label", result)
        return result

    def test_inline_token_without_token_env_emits_warn(self):
        from defenseclaw.commands.cmd_doctor import _check_splunk_token_posture, _DoctorResult
        d = _make_destination()
        cfg = _make_cfg()
        result = _DoctorResult()
        doc = {"audit_sinks": [{"name": d.name, "splunk_hec": {"token": "abc123"}}]}
        with patch("defenseclaw.observability.writer._load_yaml", return_value=doc), \
             patch("defenseclaw.observability.writer.CONFIG_FILE_NAME", "config.yaml"):
            _check_splunk_token_posture(cfg, d, "test-label", result)
        warns = [c for c in result.checks if c["status"] == "warn"]
        self.assertEqual(len(warns), 1)
        self.assertIn("token_env", warns[0]["detail"])

    def test_token_env_set_emits_no_warn(self):
        from defenseclaw.commands.cmd_doctor import _check_splunk_token_posture, _DoctorResult
        d = _make_destination()
        cfg = _make_cfg()
        result = _DoctorResult()
        doc = {"audit_sinks": [{"name": d.name, "splunk_hec": {"token_env": "SPLUNK_TOKEN"}}]}
        with patch("defenseclaw.observability.writer._load_yaml", return_value=doc), \
             patch("defenseclaw.observability.writer.CONFIG_FILE_NAME", "config.yaml"):
            _check_splunk_token_posture(cfg, d, "test-label", result)
        self.assertEqual(len(result.checks), 0)

    def test_load_failure_does_not_crash(self):
        from defenseclaw.commands.cmd_doctor import _check_splunk_token_posture, _DoctorResult
        d = _make_destination()
        cfg = _make_cfg()
        result = _DoctorResult()
        with patch("defenseclaw.observability.writer._load_yaml", side_effect=Exception("boom")):
            # Should not raise
            _check_splunk_token_posture(cfg, d, "test-label", result)
        self.assertEqual(len(result.checks), 0)


if __name__ == "__main__":
    unittest.main()
