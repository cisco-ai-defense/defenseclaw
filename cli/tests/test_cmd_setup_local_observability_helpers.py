#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for canonical-v8 local-observability CLI helpers.

Native Docker ownership, port, and process contracts live beside the
``LocalStackController`` implementation in ``test_local_observability_controller``.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup_local_observability import (
    _apply_local_otlp_config,
)
from defenseclaw.commands.redaction_status import redaction_status_hint

ROOT = Path(__file__).resolve().parents[2]
LOCAL_BRIDGE = ROOT / "bundles/local_observability_stack/bin/openclaw-observability-bridge"


class TestBridgeReadinessContract(unittest.TestCase):
    def test_up_waits_for_every_query_and_ingest_service(self):
        text = LOCAL_BRIDGE.read_text(encoding="utf-8")
        for marker in (
            'collector_ok="false"',
            "http://127.0.0.1:13133/",
            "http://127.0.0.1:3000/api/health",
            "http://127.0.0.1:9090/-/ready",
            "http://127.0.0.1:3200/ready",
            "http://127.0.0.1:3100/ready",
        ):
            self.assertIn(marker, text)


class TestV8LocalDestinationWriter(unittest.TestCase):
    def test_local_stack_uses_one_unified_v8_destination(self):
        app = SimpleNamespace(cfg=SimpleNamespace(data_dir="/tmp/defenseclaw-v8"))
        with (
            patch(
                "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
                return_value=object(),
            ),
            patch(
                "defenseclaw.commands.cmd_setup_observability._add_v8_destination",
                return_value=(SimpleNamespace(changed=True), []),
            ) as add,
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._reload_cfg_from_data_dir",
            ) as reload_cfg,
        ):
            result = _apply_local_otlp_config(
                app,
                endpoint="127.0.0.1:4317",
                protocol="grpc",
                signals=("traces", "metrics", "logs"),
                service_name="defenseclaw",
            )

        self.assertIsNone(result)
        args, kwargs = add.call_args
        self.assertEqual(args[0], "/tmp/defenseclaw-v8")
        self.assertEqual(args[1].id, "local-otlp")
        self.assertEqual(args[2]["endpoint"], "127.0.0.1:4317")
        self.assertEqual(kwargs["name"], "local-observability")
        self.assertEqual(kwargs["signals"], ("traces", "metrics", "logs"))
        self.assertIsNone(kwargs["target"])
        self.assertEqual(len(kwargs["extra_mutations"]), 1)
        self.assertEqual(
            kwargs["extra_mutations"][0].path,
            ("observability", "resource", "attributes", "service.name"),
        )
        reload_cfg.assert_called_once_with(app)

    def test_v8_redaction_summary_uses_route_policy(self):
        cfg = SimpleNamespace(_source_config_version=8)
        status, label, command = redaction_status_hint(cfg)
        self.assertEqual(status, "PER DESTINATION (defaults are unredacted)")
        self.assertIn("route redaction", label)
        self.assertIn("config show --effective", command)


if __name__ == "__main__":
    unittest.main()
