from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "bundles/local_observability_stack/grafana/dashboards/defenseclaw-blocked-events.json"
PACKAGED = ROOT / "cli/defenseclaw/_data/local_observability_stack/grafana/dashboards/defenseclaw-blocked-events.json"


def _dashboard() -> dict:
    return json.loads(DASHBOARD.read_text(encoding="utf-8"))


def _panel(document: dict, title: str) -> dict:
    return next(panel for panel in document["panels"] if panel.get("title") == title)


def test_blocked_event_dashboard_has_truthful_investigation_surfaces() -> None:
    dashboard = _dashboard()
    assert dashboard["uid"] == "defenseclaw-blocked-events"
    assert dashboard["time"] == {"from": "now-24h", "to": "now"}
    titles = {panel["title"] for panel in dashboard["panels"]}
    assert {
        "Enforced blocks", "Would-block decisions", "Blocked prompt hooks",
        "Blocked tool hooks", "Similar block signatures",
        "Blocked event records — rules, reason, agent, and correlation",
        "Projected blocked tool calls", "Prompt-surface decisions",
    } <= titles

    detail = _panel(dashboard, "Blocked event records — rules, reason, agent, and correlation")["targets"][0]["expr"]
    assert 'event_name="hook_decision"' in detail
    assert "body_defenseclaw_guardrail_enforced" in detail
    assert "body_defenseclaw_guardrail_would_block" in detail
    assert "defenseclaw.guardrail.rule_ids" in detail
    assert "(?P<rule_ids>" in detail
    for field in ("body_defenseclaw_guardrail_reason", "body_defenseclaw_evaluation_id", "body_defenseclaw_operation_id", "correlation_trace_id"):
        assert field in detail

    similar = _panel(dashboard, "Similar block signatures")
    assert "semantic or AI-generated similarity" in similar["description"]
    assert "primary_rule" in similar["targets"][0]["expr"]
    assert "(?P<primary_rule>" in similar["targets"][0]["expr"]


def test_blocked_tool_context_preserves_projection_boundary() -> None:
    panel = _panel(_dashboard(), "Projected blocked tool calls")
    assert "already projected" in panel["description"]
    assert "never reverses redaction" in panel["description"]
    query = panel["targets"][0]["expr"]
    assert 'event_name="tool.invocation.blocked"' in query
    assert "body_gen_ai_tool_call_arguments" in query
    assert "body_defenseclaw_content_input_state" in query


def test_packaged_dashboard_matches_source() -> None:
    assert PACKAGED.read_bytes() == DASHBOARD.read_bytes()
