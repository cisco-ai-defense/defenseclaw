from __future__ import annotations

import importlib.util
import sys
import urllib.error
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "import_agent_control_buckets.py"
_SPEC = importlib.util.spec_from_file_location("import_agent_control_buckets", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
bucket_import = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bucket_import
_SPEC.loader.exec_module(bucket_import)


def test_load_buckets_imports_every_bundled_regex_family() -> None:
    rules_dir = _ROOT / "policies" / "guardrail" / "default" / "rules"

    buckets = bucket_import.load_buckets(rules_dir)

    by_name = {bucket.name: bucket for bucket in buckets}
    assert set(by_name) == {
        "c2",
        "cognitive",
        "commands",
        "enterprise-data",
        "local-data-exfiltration",
        "local-data-privacy",
        "local-prompt-injection",
        "local-secrets",
        "secrets",
        "sensitive-paths",
        "trust-exploit",
    }
    # Six enterprise-data patterns are intentionally disabled in the source
    # pack, so the importer preserves the 185-rule active set.
    assert sum(len(bucket.rules) for bucket in buckets) == 185
    assert len(by_name["local-prompt-injection"].rules) == 25
    assert all(rule["pattern"].startswith("(?i)") for rule in by_name["local-prompt-injection"].rules)
    assert {rule["severity"] for rule in by_name["local-prompt-injection"].rules} == {"CRITICAL"}
    rule_ids = [rule["id"] for bucket in buckets for rule in bucket.rules]
    assert len(rule_ids) == len(set(rule_ids))


def test_rule_pack_control_is_sdk_metadata_and_preserves_bucket_toggle() -> None:
    bucket = bucket_import.Bucket(
        name="prompt-injection",
        rules=[
            {
                "id": "TEST-1",
                "pattern": "(?i)ignore previous",
                "title": "Prompt injection",
                "severity": "HIGH",
                "confidence": 0.95,
                "tags": ["test"],
            }
        ],
    )

    control = bucket_import.rule_pack_control(bucket, enabled=False)

    assert control["enabled"] is False
    assert control["execution"] == "sdk"
    assert control["scope"] == {}
    assert control["action"] == {"decision": "observe"}
    evaluator = control["condition"]["evaluator"]
    assert evaluator["name"] == "defenseclaw.rule_pack"
    assert evaluator["config"]["rule_pack"]["rules"] == bucket.rules


def test_api_rejects_insecure_non_loopback_server_urls() -> None:
    with pytest.raises(ValueError, match="must use HTTPS"):
        bucket_import.AgentControlAPI("http://agent-control.example.test", "secret", "X-API-Key")
    bucket_import.AgentControlAPI("http://127.0.0.1:8000", None, "X-API-Key")
    bucket_import.AgentControlAPI("https://agent-control.example.test", "secret", "X-API-Key")


def test_find_control_follows_cursor_pagination() -> None:
    api = bucket_import.AgentControlAPI("https://agent-control.example.test", None, "X-API-Key")
    paths: list[str] = []

    def request(method: str, path: str, payload: object = None) -> object:
        paths.append(path)
        if len(paths) == 1:
            return {"controls": [], "pagination": {"has_more": True, "next_cursor": "41"}}
        return {
            "controls": [{"id": 42, "name": "defenseclaw-local-prompt-injection"}],
            "pagination": {"has_more": False, "next_cursor": None},
        }

    api.request = request  # type: ignore[method-assign]
    assert api.find_control("defenseclaw-local-prompt-injection") == 42
    assert "cursor=41" in paths[1]


def test_load_buckets_reports_missing_required_rule_fields(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yaml").write_text(
        "version: 1\ncategory: test\nrules:\n  - id: BROKEN\n    pattern: test\n",
        encoding="utf-8",
    )
    (rules_dir / "local-patterns.yaml").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="BROKEN.*missing fields"):
        bucket_import.load_buckets(rules_dir)


def test_api_wraps_transport_errors() -> None:
    api = bucket_import.AgentControlAPI("https://agent-control.example.test", None, "X-API-Key")

    class FailingOpener:
        def open(self, request: object, timeout: int) -> object:
            raise urllib.error.URLError("offline")

    api._opener = FailingOpener()
    with pytest.raises(RuntimeError, match="GET /api/v1/controls transport failed"):
        api.request("GET", "/api/v1/controls")
