# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

VALIDATOR = Path(__file__).resolve().parents[2] / "scripts" / "assert-observability-v8-jsonl.py"


def _record(event_name: str, request_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "bucket_catalog_version": 1,
        "timestamp": "2026-07-10T12:00:00Z",
        "record_id": f"record-{event_name}",
        "bucket": "guardrail.evaluation",
        "signal": "logs",
        "event_name": event_name,
        "source": "gateway",
        "severity": "HIGH",
        "mandatory": True,
        "correlation": {"request_id": request_id},
        "provenance": {
            "producer": "defenseclaw",
            "binary_version": "8.0.0",
            "registry_schema_version": 8,
            "config_generation": 1,
        },
        "field_classes": {},
        "body": {"result": "safe"},
        "redaction_profile": "strict",
    }


def test_accepts_canonical_v8_records_and_nested_correlation(tmp_path: Path) -> None:
    request_id = "123e4567-e89b-42d3-a456-426614174000"
    path = tmp_path / "events.jsonl"
    path.write_text(
        "".join(
            json.dumps(_record(event_name, request_id)) + "\n"
            for event_name in (
                "guardrail.evaluation.completed",
                "guardrail.judge.completed",
            )
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(path),
            "--min-records",
            "2",
            "--require-uuid-request-id",
            "--require-event-name",
            "guardrail.evaluation.completed",
            "--require-event-name",
            "guardrail.judge.completed",
            "--require-shared-guardrail-request-id",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "2 canonical v8 record(s)" in result.stdout


def test_rejects_retired_gateway_event_envelope(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(
            {
                "ts": "2026-07-10T12:00:00Z",
                "event_type": "verdict",
                "severity": "HIGH",
                "verdict": {"stage": "prompt", "action": "block"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(path), "--min-records", "1"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "missing canonical fields" in result.stderr
