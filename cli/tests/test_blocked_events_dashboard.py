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
        "Recent blocked events", "Rules and what they mean", "Rule family guide",
    } <= titles

    detail = _panel(dashboard, "Recent blocked events")["targets"][0]["expr"]
    assert 'event_name="hook_decision"' in detail
    assert "body_defenseclaw_guardrail_enforced" in detail
    assert "body_defenseclaw_guardrail_would_block" in detail
    assert "defenseclaw.guardrail.rule_ids" in detail
    assert "(?P<rule_ids>" in detail
    assert "body_defenseclaw_guardrail_reason" in detail
    for identifier in ("body_defenseclaw_evaluation_id", "body_defenseclaw_operation_id", "correlation_trace_id"):
        assert identifier not in detail

    similar = _panel(dashboard, "Similar block signatures")
    assert "semantic or AI-generated similarity" in similar["description"]
    assert "primary_rule" in similar["targets"][0]["expr"]
    assert "(?P<primary_rule>" in similar["targets"][0]["expr"]


def test_rule_explanation_uses_canonical_post_redaction_decisions() -> None:
    panel = _panel(_dashboard(), "Rules and what they mean")
    assert "post-redaction" in panel["description"]
    query = panel["targets"][0]["expr"]
    assert 'event_name="hook_decision"' in query
    assert ".rule_ids" in query
    assert "body_defenseclaw_guardrail_reason" in query


def test_rule_guide_and_investigation_explain_limits_and_identifiers() -> None:
    dashboard = _dashboard()
    guide = _panel(dashboard, "Rule family guide")["options"]["content"]
    for family in ("CMD-", "PATH-", "COG-", "SEC-", "C2-", "ENT-", "TRUST-"):
        assert family in guide
    assert "does **not** record" in guide
    assert "does not guess" in guide

    workflow = _panel(dashboard, "How to investigate")["options"]["content"]
    assert "evaluation ID" in workflow
    assert "operation ID" in workflow
    assert "trace ID" in workflow


def test_who_was_blocked_row_answers_who_where_which_policy_which_rule() -> None:
    # GAP-1028: one row per enforced decision with the user, the machine, the
    # connector, the guardrail profile, the directory group that selected it,
    # the rule IDs, the action and the time; counts per machine, profile and
    # rule; boxes for machine, profile and rule.
    dashboard = _dashboard()
    boxes = {variable["name"]: variable for variable in dashboard["templating"]["list"]}
    assert boxes["machine"]["query"] == {
        "label": "host_name",
        "refId": "LokiVariableQueryEditor-VariableQuery",
        "stream": '{service_name="defenseclaw"}',
        "type": 1,
    }
    assert boxes["profile"]["type"] == "textbox" and boxes["profile"]["query"] == ".*"
    assert boxes["rule_id"]["label"] == "Rule"

    table = _panel(dashboard, "Enforced decisions: who, where, under which policy, by which rule")
    assert table["type"] == "table"
    expr = table["targets"][0]["expr"]
    for needle in (
        'event_name="hook_decision"',
        'body_defenseclaw_guardrail_enforced="true"',
        'host_name=~"$machine"',
        'profile=~"$profile"',
        '|~ "$rule_id"',
        "body_defenseclaw_guardrail_profile_matched_group",
        "body_defenseclaw_guardrail_effective_action",
        "defenseclaw.guardrail.rule_ids",
        "body_defenseclaw_user_name",
    ):
        assert needle in expr, needle
    assert "would_block" not in expr
    organize = next(t for t in table["transformations"] if t["id"] == "organize")["options"]
    assert list(organize["indexByName"]) == ["Time", "user", "machine", "connector", "profile", "group", "rule", "action"]
    assert [organize["renameByName"][key] for key in organize["indexByName"]] == [
        "Time", "User", "Machine", "Connector", "Profile", "Directory group", "Rule IDs", "Action",
    ]

    for title, label in (
        ("Enforced blocks by machine", "machine"),
        ("Enforced blocks by guardrail profile", "profile"),
        ("Enforced blocks by primary rule", "rule"),
    ):
        count = _panel(dashboard, title)["targets"][0]["expr"]
        assert f"sum by ({label})" in count and 'body_defenseclaw_guardrail_enforced="true"' in count, title
        assert 'host_name=~"$machine"' in count and 'profile=~"$profile"' in count, title


def test_every_loki_panel_on_the_board_follows_the_machine_box() -> None:
    for panel in _dashboard()["panels"]:
        for target in panel.get("targets", []):
            if (target.get("datasource") or panel.get("datasource") or {}).get("type") == "loki":
                assert 'host_name=~"$machine"' in target["expr"], panel["title"]


def test_packaged_dashboard_matches_source() -> None:
    assert PACKAGED.read_bytes() == DASHBOARD.read_bytes()
