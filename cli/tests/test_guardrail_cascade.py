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

"""guardrail.cascade in the Python mirror, the explain command and doctor."""

import os
import sys
import unittest
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import cascade  # noqa: E402
from defenseclaw import config as config_module  # noqa: E402
from defenseclaw.commands import cmd_doctor, cmd_guardrail  # noqa: E402

RAW = {
    "enabled": True,
    "cascade": {"unknown": "block", "judge": {"max_action": "alert", "block_needs_system_one": False}},
    "connectors": {"codex": {"mode": "action", "cascade": {"system_one": {"on_unsure": "alert"}}}},
    "profiles": {
        "contractors": {
            "block_at": "HIGH",
            "cascade": {"unknown": "confirm"},
            "connectors": {"codex": {"cascade": {"lanes": {"effects": "shadow"}}}},
        }
    },
}


class TestCascadeMirror(unittest.TestCase):
    def test_every_scope_round_trips_as_written(self):
        gc = config_module._merge_guardrail(RAW, "/tmp/x")
        self.assertEqual(gc.cascade["unknown"], "block")
        self.assertIs(gc.cascade["judge"]["block_needs_system_one"], False)
        self.assertEqual(gc.connectors["codex"].cascade, {"system_one": {"on_unsure": "alert"}})
        self.assertEqual(gc.profiles["contractors"].cascade, {"unknown": "confirm"})
        self.assertEqual(gc.profiles["contractors"].connectors["codex"].cascade, {"lanes": {"effects": "shadow"}})
        cfg = config_module.default_config()
        cfg.guardrail = gc
        out = config_module._config_to_dict(cfg)["guardrail"]
        self.assertEqual(out["cascade"], RAW["cascade"])  # an explicit false survives
        self.assertEqual(out["connectors"]["codex"]["cascade"], RAW["connectors"]["codex"]["cascade"])
        self.assertEqual(out["profiles"]["contractors"]["cascade"], {"unknown": "confirm"})
        self.assertEqual(out["profiles"]["contractors"]["connectors"]["codex"]["cascade"], {"lanes": {"effects": "shadow"}})
        self.assertTrue(cascade.configured(cfg))

    def test_unset_cascade_is_not_written(self):
        gc = config_module._merge_guardrail({"enabled": True, "connectors": {"codex": {"mode": "action"}}}, "/tmp/x")
        cfg = config_module.default_config()
        cfg.guardrail = gc
        out = config_module._config_to_dict(cfg)["guardrail"]
        self.assertNotIn("cascade", out)
        self.assertNotIn("cascade", out["connectors"]["codex"])
        self.assertFalse(cascade.configured(cfg))


VIEW = {
    "connector": "",
    "valid": True,
    "rules": {"tier": "default"},
    "unknown": {"setting": "pack", "action": "alert"},
    "judge": {"runs": "escalation", "max_action": "block"},
    "system_one": {"runs": "off"},
    "policy": {"active": False},
    "critical_floor": "alert",
}


class TestCascadeDoctor(unittest.TestCase):
    def _run(self, payload, error=""):
        cfg = config_module.default_config()
        cfg.guardrail = config_module._merge_guardrail(RAW, "/tmp/x")
        rows = []
        with (
            patch.object(cascade, "gateway_explain", return_value=(payload, error)),
            patch.object(cmd_doctor, "_emit", side_effect=lambda status, name, detail, **kw: rows.append((status, name, detail))),
        ):
            cmd_doctor._check_guardrail_cascade(cfg, cmd_doctor._DoctorResult())
        return rows

    def test_invalid_cascade_fails_and_names_the_fallback(self):
        invalid = dict(VIEW, valid=False, invalid={
            "error": "guardrail.cascade.unknown: \"allow\" ...", "fallback": "pack_defaults",
            "weaker": ["unknown block is not in effect"],
        })
        rows = self._run({"cascade": invalid})
        self.assertEqual(rows[0][0], "fail")
        self.assertIn("the rule pack defaults", rows[0][2])
        self.assertIn("WEAKER", rows[0][2])

    def test_loosening_settings_warn(self):
        view = dict(VIEW, critical_floor="log", policy={"active": True, "lowest": "allow"})
        rows = self._run({"cascade": view})
        self.assertEqual(rows[0][0], "warn")
        self.assertIn("critical_floor is log", rows[0][2])
        self.assertIn("may silence", rows[0][2])

    def test_valid_passes(self):
        rows = self._run({"cascade": VIEW})
        self.assertEqual(rows[0][0], "pass")

    def test_silent_when_unset(self):
        cfg = config_module.default_config()
        rows = []
        with patch.object(cmd_doctor, "_emit", side_effect=lambda *a, **kw: rows.append(a)):
            cmd_doctor._check_guardrail_cascade(cfg, cmd_doctor._DoctorResult())
        self.assertEqual(rows, [])


class TestCascadeExplainCommand(unittest.TestCase):
    def test_explain_passes_the_scope_to_the_gateway(self):
        calls = []

        def fake(connector="", profile="", input_path="", *, as_json=True, timeout=30.0):
            calls.append((connector, profile, input_path, as_json))
            return ({"cascade": VIEW}, "") if as_json else ("Guardrail cascade for codex\n", "")

        with patch.object(cascade, "gateway_explain", side_effect=fake):
            result = CliRunner().invoke(cmd_guardrail.guardrail, ["cascade", "explain", "--connector", "codex", "--json"])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn('"critical_floor": "alert"', result.output)
            text = CliRunner().invoke(cmd_guardrail.guardrail, ["cascade", "explain", "--connector", "codex", "--profile", "p"])
            self.assertEqual(text.exit_code, 0, text.output)
            self.assertIn("Guardrail cascade for codex", text.output)
        self.assertEqual(calls, [("codex", "", "", True), ("codex", "p", "", False)])

    def test_explain_reports_a_missing_gateway(self):
        with patch.object(cascade, "gateway_explain", return_value=(None, "defenseclaw-gateway is not installed")):
            result = CliRunner().invoke(cmd_guardrail.guardrail, ["cascade", "explain"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not installed", result.output)


if __name__ == "__main__":
    unittest.main()
