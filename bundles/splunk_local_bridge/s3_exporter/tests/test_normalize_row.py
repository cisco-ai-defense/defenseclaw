import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_splunk_to_s3 as exporter


def _row(raw: str = '{"message":"ok"}') -> dict:
    return {
        "_time": "1770000000.123",
        "_indextime": "1770000001",
        "index": "defenseclaw_local",
        "source": "defenseclaw",
        "sourcetype": "defenseclaw:json",
        "run_id": "run-1",
        "session_id": "session-1",
        "trace_id": "trace-1",
        "request_id": "request-1",
        "agent_name": "codex",
        "agent_type": "codex",
        "tool_name": "shell",
        "destination_app": "terminal",
        "action": "invoke",
        "policy_id": "policy-1",
        "decision": "allow",
        "severity": "INFO",
        "_raw": raw,
    }


def test_normalize_row_with_json_raw(monkeypatch):
    monkeypatch.setenv("TENANT_ID", "tenant-a")
    monkeypatch.setenv("WORKSPACE_ID", "workspace-a")
    monkeypatch.setenv("DEPLOYMENT_ENVIRONMENT", "local")

    normalized = exporter.normalize_row(_row(), "2026-05-06T12:00:00Z")

    assert normalized["schema_version"] == "defenseclaw.splunk_s3.raw_event.v0.1"
    assert normalized["tenant_id"] == "tenant-a"
    assert normalized["workspace_id"] == "workspace-a"
    assert normalized["event"] == {"message": "ok"}
    assert normalized["raw"] == '{"message":"ok"}'
    assert normalized["correlation"]["run_id"] == "run-1"
    assert normalized["correlation"]["request_id"] == "request-1"
    assert normalized["correlation"]["action"] == "invoke"
    assert normalized["splunk"]["index"] == "defenseclaw_local"


def test_invalid_json_raw_keeps_raw_and_null_event():
    normalized = exporter.normalize_row(_row("not json"), "2026-05-06T12:00:00Z")

    assert normalized["event"] is None
    assert normalized["raw"] == "not json"


def test_duplicate_multivalue_fields_are_collapsed():
    row = _row()
    row["run_id"] = ["run-1", "run-1"]
    row["action"] = ["invoke", "invoke"]
    row["_raw"] = ['{"message":"ok"}', '{"message":"ok"}']

    normalized = exporter.normalize_row(row, "2026-05-06T12:00:00Z")

    assert normalized["correlation"]["run_id"] == "run-1"
    assert normalized["correlation"]["action"] == "invoke"
    assert normalized["raw"] == '{"message":"ok"}'
    assert normalized["event"] == {"message": "ok"}


def test_export_event_id_is_deterministic():
    first = exporter.normalize_row(_row(json.dumps({"x": 1})), "2026-05-06T12:00:00Z")
    second = exporter.normalize_row(_row(json.dumps({"x": 1})), "2026-05-06T12:00:01Z")

    assert first["export_event_id"] == second["export_event_id"]
