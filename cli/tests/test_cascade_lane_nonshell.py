# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""guardrail.cascade.lanes.nonshell in the CLI (GAP-0472).

One cascade type: ``GuardrailConfig.cascade`` keeps guardrail.cascade as
written (the gateway validates it and reads the lane through its registry,
internal/config/cascade_lanes.go). A config without the key keeps it absent
(the gateway reads that as on); a value is kept as written, so a spelling the
gateway refuses (it takes exact values) is refused there with the key named;
a CLI save writes on and off as strings, never as the YAML 1.1 booleans the
gateway refuses.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import _merge_cascade, load, parse_config_yaml  # noqa: E402


def _write(tmpdir: str, lane: str | None) -> str:
    path = os.path.join(tmpdir, "config.yaml")
    text = f"config_version: 8\ndata_dir: {tmpdir}\nenvironment: linux\nguardrail:\n  mode: observe\n"
    if lane is not None:
        text += f"  cascade:\n    lanes:\n      nonshell: {lane}\n"
    text += "observability: {}\n"
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(text)
    return path


def _load_save(tmpdir: str, mutate=None):
    with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmpdir}, clear=False):
        os.environ.pop("DEFENSECLAW_CONFIG", None)
        cfg = load()
        if mutate is not None:
            mutate(cfg)
        cfg.guardrail.block_message = "changed"  # an unrelated edit forces a write
        cfg.save()
        return cfg


class TestCascadeLaneNonShell(unittest.TestCase):
    def test_parse_keeps_lane_values_as_strings(self):
        for raw, want in (("on", "on"), ("OFF", "OFF"), ("Shadow", "Shadow"), ("off", "off"), ("' On '", " On ")):
            doc = parse_config_yaml(f"config_version: 8\nguardrail:\n  cascade:\n    lanes:\n      nonshell: {raw}\n")
            self.assertIsInstance(doc["guardrail"]["cascade"]["lanes"]["nonshell"], str, raw)
            self.assertEqual(_merge_cascade(doc["guardrail"]["cascade"])["lanes"]["nonshell"], want, raw)

    def test_absent_key_stays_absent_and_is_on_for_the_gateway(self):
        self.assertNotIn("nonshell", _merge_cascade(None).get("lanes") or {})
        self.assertNotIn("nonshell", _merge_cascade({"lanes": {"effects": "shadow"}}).get("lanes") or {})
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write(tmpdir, None)
            cfg = _load_save(tmpdir)
            self.assertNotIn("nonshell", cfg.guardrail.cascade.get("lanes") or {})
            with open(path, encoding="utf-8") as stream:
                persisted = yaml.safe_load(stream)
            lanes = ((persisted.get("guardrail") or {}).get("cascade") or {}).get("lanes") or {}
            self.assertNotIn("nonshell", lanes)

    def test_save_keeps_on_and_off_as_strings(self):
        for start, value in (("Shadow", "on"), ("on", "off"), (None, "off"), (None, "on"), ("OFF", "shadow")):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = _write(tmpdir, start)

                def set_lane(cfg, value=value):
                    cfg.guardrail.cascade.setdefault("lanes", {})["nonshell"] = value

                _load_save(tmpdir, set_lane)
                with open(path, encoding="utf-8") as stream:
                    text = stream.read()
                # yaml.safe_load is YAML 1.1: an unquoted on/off would read as a bool.
                got = yaml.safe_load(text)["guardrail"]["cascade"]["lanes"]["nonshell"]
                self.assertIsInstance(got, str, text)
                self.assertEqual(got, value)

    def test_unrelated_save_keeps_a_written_value(self):
        # Exact values only: another spelling is refused by the gateway, so no save
        # starts from one.
        for start, want in (("on", "on"), ("off", "off"), ("shadow", "shadow")):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = _write(tmpdir, start)
                _load_save(tmpdir)
                with open(path, encoding="utf-8") as stream:
                    doc = parse_config_yaml(stream.read())
                got = doc["guardrail"]["cascade"]["lanes"]["nonshell"]
                self.assertIsInstance(got, str)
                self.assertEqual(got.strip().lower(), want)

    def test_a_refused_value_is_kept_for_the_gateway_to_refuse(self):
        self.assertEqual(_merge_cascade({"lanes": {"nonshell": ""}})["lanes"]["nonshell"], "")
        self.assertEqual(_merge_cascade({"lanes": {"nonshell": "Enabled"}})["lanes"]["nonshell"], "Enabled")


if __name__ == "__main__":
    unittest.main()
