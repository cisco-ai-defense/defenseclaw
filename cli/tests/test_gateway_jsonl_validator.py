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

"""Regression tests for scripts/assert-gateway-jsonl.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "assert-gateway-jsonl.py"


class GatewayJSONLValidatorTests(unittest.TestCase):
    def test_accepts_llm_and_tool_telemetry_event_types(self) -> None:
        """The live validator must stay in lockstep with the v7.1 schema."""
        events = [
            {
                "ts": "2026-04-29T22:09:45Z",
                "event_type": "llm_prompt",
                "severity": "INFO",
                "schema_version": 7,
                "request_id": "123e4567-e89b-42d3-a456-426614174000",
                "llm_prompt": {"prompt_id": "prompt-1"},
            },
            {
                "ts": "2026-04-29T22:09:45Z",
                "event_type": "llm_response",
                "severity": "INFO",
                "schema_version": 7,
                "request_id": "123e4567-e89b-42d3-a456-426614174001",
                "llm_response": {"response_id": "response-1"},
            },
            {
                "ts": "2026-04-29T22:09:45Z",
                "event_type": "tool_invocation",
                "severity": "INFO",
                "schema_version": 7,
                "request_id": "123e4567-e89b-42d3-a456-426614174002",
                "tool_invocation": {"phase": "call", "tool": "search"},
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            jsonl = Path(tmp) / "gateway.jsonl"
            jsonl.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )

            res = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--min-events",
                    "3",
                    "--require-uuid-request-id",
                    "--require-type",
                    "llm_prompt",
                    "--require-type",
                    "llm_response",
                    "--require-type",
                    "tool_invocation",
                    str(jsonl),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(
            res.returncode,
            0,
            f"validator should accept v7.1 LLM/tool events\n"
            f"stdout={res.stdout}\nstderr={res.stderr}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
