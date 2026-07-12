"""Durable contract checks for the bundled Grafana dashboard catalog."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = ROOT / "bundles/local_observability_stack/grafana/dashboards"


def _load_audit_module() -> ModuleType:
    path = ROOT / "scripts/check_grafana_dashboards.py"
    spec = importlib.util.spec_from_file_location("check_grafana_dashboards", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _dashboard(name: str) -> dict:
    return json.loads((DASHBOARD_DIR / name).read_text(encoding="utf-8"))


def _panel(dashboard: dict, title: str) -> dict:
    return next(panel for panel in dashboard["panels"] if panel.get("title") == title)


def test_grafana_dashboard_catalog_contract() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_grafana_dashboards.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_grafana_dashboard_catalog_requires_generated_mirror() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_grafana_dashboards.py"),
            "--require-packaged",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_prometheus_label_inventory_includes_unchanged_canonical_v8_fields() -> None:
    audit = _load_audit_module()
    labels = audit.compatibility_errors.__globals__["prometheus_label_inputs"]()

    assert {
        "defenseclaw_agent_phase_from",
        "defenseclaw_agent_phase_to",
        "http_route",
    } <= labels


def test_tempo_dependency_inventory_does_not_parse_quoted_family_values_as_attributes() -> None:
    audit = _load_audit_module()
    dependencies = audit.compatibility_errors.__globals__["_tempo_dependencies"](
        '{ span.defenseclaw.span.family = "span.approval.resolve" }',
    )

    assert dependencies == {"defenseclaw.span.family"}


def test_local_rules_describe_v8_schema_and_destination_ownership() -> None:
    relative_paths = (
        Path("prometheus/rules/alerts.yml"),
        Path("prometheus/rules/recording.yml"),
    )
    roots = (
        ROOT / "bundles/local_observability_stack",
        ROOT / "cli/defenseclaw/_data/local_observability_stack",
    )

    for root in roots:
        text = "\n".join((root / relative).read_text(encoding="utf-8") for relative in relative_paths)
        assert "gateway.jsonl" not in text
        assert "gatewaylog.Writer" not in text
        assert "RecordSinkBatch" not in text
        assert "internal/telemetry/metrics.go::RecordSinkFailure" not in text
        assert "(legacy" not in text
        assert "Audit sink" not in text


def test_local_dashboards_and_rules_use_active_v8_event_sources() -> None:
    roots = (
        ROOT / "bundles/local_observability_stack",
        ROOT / "cli/defenseclaw/_data/local_observability_stack",
    )
    retired_inputs = (
        "defenseclaw_gateway_events_emitted_total",
        "defenseclaw_gateway_verdicts_total",
        "defenseclaw_slo_tui_refresh_milliseconds",
        "slo:defenseclaw_tui_refresh:ratio_5m",
        'job=\\"ai-governance/defenseclaw\\"',
    )
    for root in roots:
        query_assets = sorted((root / "grafana/dashboards").glob("*.json")) + sorted(
            (root / "prometheus/rules").glob("*.yml"),
        )
        text = "\n".join(path.read_text(encoding="utf-8") for path in query_assets)
        for retired in retired_inputs:
            assert retired not in text

    overview = _dashboard("defenseclaw-overview.json")
    event_flow = _panel(overview, "Canonical events / sec by type")
    model_tool_flow = _panel(overview, "LLM events by type")
    freshness = _panel(overview, "Exporter freshness")
    assert event_flow["datasource"]["type"] == "loki"
    assert "event_name" in event_flow["targets"][0]["expr"]
    assert '| json | __error__=""' in event_flow["targets"][0]["expr"]
    assert model_tool_flow["datasource"]["type"] == "loki"
    assert "model[.].*|tool[.]invocation[.].*" in model_tool_flow["targets"][0]["expr"]
    assert "{job=" not in freshness["targets"][0]["expr"]

    policy = _panel(_dashboard("defenseclaw-policy-decisions.json"), "Policy reloads / sec by status")
    assert "defenseclaw_policy_reloads_total" in policy["targets"][0]["expr"]
    assert "policy_status" in policy["targets"][0]["expr"]

    scanners = _dashboard("defenseclaw-scanners.json")
    variables = {item["name"]: item for item in scanners["templating"]["list"]}
    assert "defenseclaw_scan_count_total" in variables["scanner"]["definition"]
    assert "defenseclaw_scan_count_total" in variables["target_type"]["definition"]

    recording_rules = (roots[0] / "prometheus/rules/recording.yml").read_text(encoding="utf-8")
    assert "defenseclaw_guardrail_evaluations_total" in recording_rules
    assert "guardrail_action_taken" in recording_rules
    assert "guardrail_connector" in recording_rules
    assert "guardrail_scanner" in recording_rules
    alert_rules = (roots[0] / "prometheus/rules/alerts.yml").read_text(encoding="utf-8")
    block_alert = alert_rules.split("- alert: DefenseClawBlockRateSpike", maxsplit=1)[1].split(
        "- alert:", maxsplit=1
    )[0]
    assert "expr: service:defenseclaw_guardrail_block_ratio:5m > 0.25" in block_alert
    assert "rate(defenseclaw_guardrail_evaluations_total" not in block_alert


def test_security_dashboard_exposes_generated_ai_defense_metrics() -> None:
    dashboard = _dashboard("defenseclaw-security.json")
    attempts = _panel(dashboard, "AI Defense attempts / min")
    errors = _panel(dashboard, "AI Defense errors by code")
    latency = _panel(dashboard, "AI Defense latency by outcome")

    assert "defenseclaw_cisco_inspect_latency_milliseconds_count" in attempts["targets"][0]["expr"]
    assert "defenseclaw_cisco_errors_total" in errors["targets"][0]["expr"]
    assert {target["refId"] for target in latency["targets"]} == {"P50", "P95", "P99"}
    assert all(
        "defenseclaw_cisco_inspect_latency_milliseconds_bucket" in target["expr"] and "outcome" in target["expr"]
        for target in latency["targets"]
    )
    global_panels = (
        "AI Defense attempts / min",
        "AI Defense errors (1h)",
        "AI Defense completion rate (1h)",
        "AI Defense latency p95 (5m)",
        "AI Defense latency by outcome",
        "AI Defense errors by code",
    )
    for title in global_panels:
        panel = _panel(dashboard, title)
        assert "process-global" in panel["description"]
        assert "Connector selection does not apply" in panel["description"]
        assert all("connector=" not in target["expr"] for target in panel["targets"])


def test_security_and_policy_log_queries_preserve_connector_scope() -> None:
    security = _panel(_dashboard("defenseclaw-security.json"), "Recent guardrail events")
    security_targets = {target["refId"]: target["expr"] for target in security["targets"]}
    assert '| connector=~"$connector"' in security_targets["B"]

    policy = _panel(_dashboard("defenseclaw-policy-decisions.json"), "Recent OPA + egress events")
    policy_targets = {target["refId"]: target["expr"] for target in policy["targets"]}
    assert set(policy_targets) == {"A", "B", "C"}
    assert 'event_name=~"guardrail[.]evaluation[.](completed|failed)"' in policy_targets["B"]
    assert '| connector=~"$connector"' in policy_targets["B"]
    assert 'event_name=~"policy[.](updated|reload[.]rejected)"' in policy_targets["C"]
    assert "connector=" not in policy_targets["C"]
    assert "process-global control-plane records without a connector" in policy["description"]


def test_traffic_dashboard_exposes_generated_stream_metrics() -> None:
    dashboard = _dashboard("defenseclaw-traffic.json")
    transitions = _panel(dashboard, "Stream transitions by outcome")
    duration = _panel(dashboard, "Stream duration by outcome")
    byte_volume = _panel(dashboard, "Stream bytes by outcome")

    assert "defenseclaw_stream_lifecycle_total" in transitions["targets"][0]["expr"]
    assert {target["refId"] for target in duration["targets"]} == {"P50", "P95"}
    assert all("defenseclaw_stream_duration_ms_milliseconds_bucket" in target["expr"] for target in duration["targets"])
    assert all("defenseclaw_stream_bytes_sent_bucket" in target["expr"] for target in byte_volume["targets"])


def test_runtime_dashboard_exposes_generated_watcher_health_metrics() -> None:
    dashboard = _dashboard("defenseclaw-runtime.json")
    errors = _panel(dashboard, "Watcher errors/hour")
    recoveries = _panel(dashboard, "Runtime recoveries/hour")
    heals = _panel(dashboard, "Hook self-heals/hour by connector")

    assert "defenseclaw_watcher_errors_total" in errors["targets"][0]["expr"]
    assert "defenseclaw_watcher_restarts_total" in recoveries["targets"][0]["expr"]
    assert "gateway reconnects" in recoveries["description"]
    assert "watchdog-observed sidecar" in recoveries["description"]
    assert "defenseclaw_watcher_events_total" in heals["targets"][0]["expr"]
    assert 'event_type="hook-heal"' in heals["targets"][0]["expr"]
    assert "connector, target_type" in heals["targets"][0]["expr"]


def test_hitl_dashboard_exposes_canonical_correlated_approval_records() -> None:
    dashboard = _dashboard("defenseclaw-hitl.json")
    stream = _panel(
        dashboard,
        "Approval requests and resolutions — ID, result, agent, and trace",
    )

    assert stream["datasource"]["uid"] == "defenseclaw-loki"
    expression = stream["targets"][0]["expr"]
    assert 'event_name=~"approval[.](requested|resolved)"' in expression
    for field in (
        ".body_defenseclaw_approval_id",
        ".body_defenseclaw_approval_result",
        ".body_defenseclaw_approval_actor_type",
        ".body_gen_ai_agent_id",
        ".correlation_trace_id",
    ):
        assert field in expression
    assert "trace_id={{.correlation_trace_id}}" in expression


def test_correlated_log_lines_match_the_loki_tempo_derived_field() -> None:
    checked: list[str] = []
    for path in sorted(DASHBOARD_DIR.glob("*.json")):
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []):
                expression = str(target.get("expr", ""))
                if "line_format" not in expression or ".correlation_trace_id" not in expression:
                    continue
                checked.append(f"{path.name}: {panel.get('title')}")
                assert "trace_id={{.correlation_trace_id}}" in expression
                assert "trace={{.correlation_trace_id}}" not in expression

    assert checked


def test_agent360_aggregates_model_and_tool_work_with_clickable_totals() -> None:
    panel = _panel(
        _dashboard("defenseclaw-agent-360.json"),
        "Lifecycle DAG — prompt → agents → work → outcomes",
    )
    expressions = {target["refId"]: target["expr"] for target in panel["targets"]}
    edge_expressions = [
        expression
        for ref_id, expression in expressions.items()
        if ref_id.startswith("edges")
    ]
    node_expressions = [
        expression
        for ref_id, expression in expressions.items()
        if ref_id.startswith("nodes")
    ]
    assert len(edge_expressions) == 8
    assert len(node_expressions) == 10
    for expression in (" or ".join(edge_expressions), " or ".join(node_expressions)):
        assert "body_gen_ai_provider_name" in expression
        assert "body_gen_ai_response_model" in expression
        assert "agent_model_summary" in expression or "model_summary" in expression
        assert "tool_family=" in expression
        for family in (
            "Skills",
            "MCP",
            "Bash",
            "File edits",
            "Collaboration",
            "Web / browser",
            "Visual",
            "Task control",
        ):
            assert family in expression
        assert "body_gen_ai_tool_call_id}}`" not in expression

    edge_expression = " or ".join(edge_expressions)
    node_expression = " or ".join(node_expressions)
    prompt_expressions = (
        expressions["edgesConversationPrompts"],
        expressions["nodesConversationPrompts"],
    )
    for expression in prompt_expressions:
        assert 'defenseclaw_event_name=~`hook_decision|model.request`' in expression
        assert '(event_name="hook_decision" and source="connector"' in expression
        assert '(connector!="codex" and event_name="model.request")' in expression
        assert 'body_defenseclaw_agent_depth="0"' in expression
        assert "prompts:{{.body_gen_ai_agent_id}}" in expression
        assert expression.startswith("max by (")
        assert expression.count("count by") == 2
        assert "prompt_observation" in expression
        assert "prompt_key" in expression
        assert expression.index(".body_defenseclaw_turn_id") < expression.index(".body_defenseclaw_model_request_id")
        assert expression.index(".body_defenseclaw_model_request_id") < expression.index(".body_defenseclaw_request_id")
        assert expression.index(".body_defenseclaw_request_id") < expression.index(".body_defenseclaw_operation_id")
        assert expression.index(".body_defenseclaw_operation_id") < expression.index(".record_id")
        assert "detail__event_name=`prompt submission`" in expression
        assert "detail__hook_event" not in expression
        assert "detail__count_meaning" in expression
        assert "detail__correlation_note" in expression
    assert "prompt_submissions_to_root" in edge_expression
    assert "Prompt inputs" in node_expression

    for ref_id in ("edgesModelSummary", "nodesModelSummary"):
        expression = expressions[ref_id]
        assert expression.startswith("max by (")
        assert "sum by (" in expression
        assert "observation_source" in expression
        assert "largest source total" in expression

    for ref_id in ("edgesToolSummary", "nodesToolSummary"):
        assert (
            'body_gen_ai_tool_name!~"(?i)collaboration[._]*send[._]*message"'
            in expressions[ref_id]
        )
        assert "excluding send_message requests represented by message nodes" in expressions[ref_id]
    for ref_id in ("edgesMessages", "nodesMessages"):
        message_expression = expressions[ref_id]
        assert "message_target_group" in message_expression
        assert 'hasPrefix "/root/" .body_gen_ai_tool_call_arguments_target' in message_expression
        assert "/root and /root/* (grouped)" in message_expression
        assert "non-root targets remain exact" in message_expression
    assert "Messages to root" in expressions["nodesMessages"]

    root_anchor = expressions["nodesRootAnchor"]
    assert 'event_name="session_start"' in root_anchor
    assert 'id=`agent:{{.body_gen_ai_agent_id}}`' in root_anchor
    assert 'detail__node_type=`root_agent_anchor`' in root_anchor
    assert "matching 24-hour session anchor" in root_anchor
    assert "unless on (id)" in root_anchor
    assert 'label_format id=`agent:{{.body_gen_ai_agent_id}}` [$__range]' in root_anchor

    spawn_parent_anchor = expressions["nodesSpawnParent"]
    assert 'event_name="subagent_start"' in spawn_parent_anchor
    assert 'id=`agent:{{.body_defenseclaw_agent_parent_id}}`' in spawn_parent_anchor
    assert 'detail__node_type=`spawn_parent_anchor`' in spawn_parent_anchor
    assert 'body_defenseclaw_agent_parent_id!=""' in spawn_parent_anchor
    assert "Parent endpoint recovered from 24-hour canonical subagent_start facts" in spawn_parent_anchor
    assert "[24h]" in spawn_parent_anchor
    assert "[$__range]" in spawn_parent_anchor
    assert "and on (graph_child_id)" in spawn_parent_anchor
    assert "unless on (id)" in spawn_parent_anchor
    assert 'label_format id=`agent:{{.body_gen_ai_agent_id}}` [$__range]' in spawn_parent_anchor

    agent_nodes = expressions["nodesAgent"]
    assert agent_nodes.startswith("((topk by (id) (1,")
    assert agent_nodes.count("topk by (id) (1,") == 2
    assert 'defenseclaw_event_name=~`session_start|subagent_start`' in agent_nodes
    assert "Canonical 24-hour session_start or subagent_start identity" in agent_nodes
    assert "and on (id)" in agent_nodes
    assert "unless on (id)" in agent_nodes

    # Session start is a lifecycle anchor, not fabricated prompt content. The
    # grouped prompt counter includes the first and every later submission.
    assert "edge:session:{{.body_gen_ai_agent_id}}" in edge_expression
    assert "session_starts_root" in edge_expression
    assert "id=`session:{{.body_gen_ai_agent_id}}`" in node_expression
    assert "detail__node_type=`session_start`" in node_expression
    assert "initial_prompt" not in node_expression
    for expression in (edge_expression, node_expression):
        assert 'event_name="model.request"' in expression
        assert 'event_name="tool.invocation.requested"' in expression
        assert 'event_name="approval.requested"' in expression
        assert "collaboration[._]*send[._]*message" in expression
        assert "body_gen_ai_tool_call_arguments_target" in expression
        assert "session_failed" not in expression
        assert "subagent_failed" not in expression

    precedence = (
        'contains "skill"',
        'hasPrefix "mcp"',
        'eq (lower .body_gen_ai_tool_name) "bash"',
        'eq (lower .body_gen_ai_tool_name) "apply_patch"',
        'hasPrefix "collaboration"',
        'hasPrefix "web"',
        'contains "image"',
        'eq (lower .body_gen_ai_tool_name) "update_plan"',
    )
    assert list(map(edge_expression.index, precedence)) == sorted(
        map(edge_expression.index, precedence),
    )

    assert any(
        "detail__total" in json.dumps(transformation, sort_keys=True)
        for transformation in panel["transformations"]
    )
    calculated_totals = [
        transformation
        for transformation in panel["transformations"]
        if transformation["id"] == "calculateField"
    ]
    assert len(calculated_totals) == 18
    assert all(
        transformation["options"]["alias"] == "detail__total"
        and transformation["options"]["unary"]["fieldName"]
        == f'Value #{transformation["filter"]["options"]}'
        for transformation in calculated_totals
    )
    assert not any(
        transformation["id"] == "renameByRegex"
        for transformation in panel["transformations"]
    )

    overrides = {
        override["matcher"]["options"]: override["properties"]
        for override in panel["fieldConfig"]["overrides"]
        if override.get("matcher", {}).get("id") == "byName"
    }
    for display_only_field in ("detail__trace_id", "detail__target_agent_id"):
        properties = overrides[display_only_field]
        assert any(property_["id"] == "displayName" for property_ in properties)
        assert all(property_["id"] != "links" for property_ in properties)

    serialized_panel = json.dumps(panel, sort_keys=True)
    assert "Open exact Tempo trace" not in serialized_panel
    assert "Open resolved target agent" not in serialized_panel
    id_links = next(
        property_["value"]
        for property_ in overrides["id"]
        if property_["id"] == "links"
    )
    assert any(link["title"] == "Find related Tempo traces" for link in id_links)


@pytest.mark.parametrize(
    ("reported", "expected"),
    (
        ("skill_mcp_shell", "Skills"),
        ("mcp_shell", "MCP"),
        ("run_shell_command", "Bash"),
        ("apply_patch", "File edits"),
        ("collaboration.send_message", "Collaboration"),
        ("web_browser", "Web / browser"),
        ("image_gen", "Visual"),
        ("update_plan", "Task control"),
        ("read_file", "read_file"),
    ),
)
def test_golden_gate_tool_family_matches_authored_precedence(
    reported: str,
    expected: str,
) -> None:
    audit = _load_audit_module()

    assert audit._golden_tool_family(reported) == expected
    assert _golden_tool_family(reported) == expected


def test_source_audit_allows_missing_generated_mirror(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = _load_audit_module()
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing")

    _dashboards, source_errors = audit.static_audit()
    _dashboards, ci_errors = audit.static_audit(require_packaged=True)

    assert not any("packaged Grafana dashboard directory is missing" in error for error in source_errors)
    assert any("packaged Grafana dashboard directory is missing" in error for error in ci_errors)


def test_static_audit_checks_variable_datasources_and_over_time_stats(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = _load_audit_module()
    dashboard = {
        "uid": "audit-fixture",
        "title": "Audit fixture",
        "description": "Exercises non-panel datasource and PromQL checks.",
        "templating": {
            "list": [
                {
                    "datasource": {
                        "type": "prometheus",
                        "uid": "wrong-prometheus",
                    },
                },
            ],
        },
        "panels": [
            {
                "type": "stat",
                "title": "Range stat",
                "datasource": {
                    "type": "prometheus",
                    "uid": "defenseclaw-prometheus",
                },
                "targets": [
                    {
                        "expr": "sum(sum_over_time(example_total[5m]))",
                        "refId": "A",
                    },
                ],
            },
            {
                "type": "timeseries",
                "title": "Grouped naked zero fallback",
                "datasource": {
                    "type": "prometheus",
                    "uid": "defenseclaw-prometheus",
                },
                "targets": [
                    {
                        "expr": "sum by (reason) (rate(example_total[5m])) or    vector(0)",
                        "refId": "A",
                    },
                ],
            },
            {
                "type": "table",
                "title": "Unsupported structured Tempo target",
                "datasource": {
                    "type": "tempo",
                    "uid": "defenseclaw-tempo",
                },
                "targets": [{"queryType": "traceqlSearch", "filters": []}],
            },
            {
                "type": "logs",
                "title": "Retired flat Loki field",
                "datasource": {
                    "type": "loki",
                    "uid": "defenseclaw-loki",
                },
                "targets": [
                    {
                        "expr": ('{service_name="defenseclaw"} | defenseclaw_gateway_event_type="llm_response"'),
                        "refId": "A",
                    },
                ],
            },
            {
                "type": "logs",
                "title": "Unparsed canonical Loki field",
                "datasource": {
                    "type": "loki",
                    "uid": "defenseclaw-loki",
                },
                "targets": [
                    {
                        "expr": '{service_name="defenseclaw"} | event_name="model.response"',
                        "refId": "A",
                    },
                ],
            },
        ],
    }
    (tmp_path / "fixture.json").write_text(json.dumps(dashboard), encoding="utf-8")
    monkeypatch.setattr(audit, "SOURCE_DIR", tmp_path)
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing")

    _dashboards, errors = audit.static_audit()

    assert any("prometheus must use 'defenseclaw-prometheus'" in error for error in errors)
    assert any("range-aggregate stat targets must be instant" in error for error in errors)
    assert any("grouped zero fallbacks must use `or on() vector(0)`" in error for error in errors)
    assert any("traceqlSearch targets must provide" in error for error in errors)
    assert any("uses retired flat v7 fields: defenseclaw_gateway_event_type" in error for error in errors)
    assert any("canonical v8 log fields require `| json`" in error for error in errors)


def test_live_inventory_distinguishes_data_zero_empty_and_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    dashboard = {
        "uid": "inventory-fixture",
        "title": "Inventory fixture",
        "description": "Exercises live panel result classification.",
        "panels": [
            {
                "type": "timeseries",
                "title": "Has data",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "fixture_data_total", "refId": "A"}],
            },
            {
                "type": "timeseries",
                "title": "Healthy zero",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "fixture_zero_total", "refId": "A"}],
            },
            {
                "type": "logs",
                "title": "No matching event",
                "datasource": {"type": "loki", "uid": "defenseclaw-loki"},
                "targets": [{"expr": '{service_name="defenseclaw"}', "refId": "A"}],
            },
            {
                "type": "traces",
                "title": "Selected waterfall",
                "datasource": {"type": "tempo", "uid": "defenseclaw-tempo"},
                "targets": [{"query": "$trace", "refId": "A"}],
            },
            {
                "type": "text",
                "title": "Instructions",
                "options": {"content": "Choose a trace."},
            },
        ],
    }

    def fake_request(
        url: str,
        params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        assert params is not None
        assert timeout_seconds == audit.DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS
        if "127.0.0.1:9090" in url:
            value = "2" if "fixture_data_total" in params["query"] else "0"
            return {
                "status": "success",
                "data": {"result": [{"metric": {}, "values": [[1, value]]}]},
            }
        if "127.0.0.1:3100" in url:
            return {"status": "success", "data": {"resultType": "streams", "result": []}}
        raise AssertionError(f"unexpected request: {url}")

    monkeypatch.setattr(audit, "request_json", fake_request)
    inventory, errors = audit.live_inventory([(Path("fixture.json"), dashboard)])

    assert errors == []
    assert inventory[0]["status_counts"] == {
        "data": 1,
        "zero": 1,
        "empty": 1,
        "interactive": 1,
        "static": 1,
        "error": 0,
    }
    assert {panel["title"]: panel["status"] for panel in inventory[0]["panels"]} == {
        "Has data": "data",
        "Healthy zero": "zero",
        "No matching event": "empty",
        "Selected waterfall": "interactive",
        "Instructions": "static",
    }


def test_static_audit_rejects_dashboard_semantic_contract_regressions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = _load_audit_module()
    dashboard = {
        "uid": "semantic-fixture",
        "title": "Semantic fixture",
        "description": "Exercises v8 dashboard semantic checks.",
        "templating": {
            "list": [
                {
                    "name": "connector",
                    "type": "custom",
                    "query": "codex,opencode",
                    "options": [
                        {"text": "All", "value": "$__all"},
                        {"text": "codex", "value": "codex"},
                    ],
                },
                {"name": "agent", "definition": "label_values(example, gen_ai_agent_id)"},
                {"name": "scope_label", "query": "gen_ai_agent_id"},
            ],
        },
        "panels": [
            {
                "type": "logs",
                "title": "Wrong connector identity",
                "datasource": {"type": "loki", "uid": "defenseclaw-loki"},
                "targets": [
                    {
                        "expr": (
                            '{service_name="defenseclaw"} | json | __error__="" '
                            f'| body_gen_ai_agent_name=~"{variable}"'
                        ),
                    }
                    for variable in ("$connector", "${connector:regex}", "${connector:pipe}")
                ],
            },
            {
                "type": "stat",
                "title": "Active agents",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "count(max_over_time(defenseclaw_agent_last_seen_seconds[5m]))", "instant": True}],
            },
            {
                "type": "timeseries",
                "title": "Estimated cost by model",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "rate(gen_ai_client_token_usage_sum[5m]) * 1.25e-06"}],
            },
            {
                "type": "timeseries",
                "title": "Estimated cost from provider",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "max(defenseclaw_agent_reported_cost_USD)"}],
            },
            {
                "type": "timeseries",
                "title": "Hook events / sec",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "rate(defenseclaw_connector_hook_outcome_total[5m])"}],
            },
            {
                "type": "stat",
                "title": "Active discovery signals",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "max(max_over_time(defenseclaw_ai_discovery_active_signals[1h]))", "instant": True}],
            },
            {
                "type": "stat",
                "title": "Optional tokens",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "sum(increase(defenseclaw_agent_token_usage_total[1h])) or vector(0)", "instant": True}],
            },
            {
                "type": "traces",
                "title": "Selected trace",
                "description": "Trace waterfall.",
                "datasource": {"type": "tempo", "uid": "defenseclaw-tempo"},
                "targets": [{"queryType": "traceql", "query": "$trace"}],
            },
        ],
    }
    (tmp_path / "fixture.json").write_text(json.dumps(dashboard), encoding="utf-8")
    monkeypatch.setattr(audit, "SOURCE_DIR", tmp_path)
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing")

    _dashboards, errors = audit.static_audit()

    connector_identity_errors = [
        error
        for error in errors
        if error.startswith("semantic-fixture/Wrong connector identity:")
        and "not gen_ai_agent_name" in error
    ]
    assert len(connector_identity_errors) == 3
    assert any("active last-seen queries must compare" in error for error in errors)
    assert any("upstream-reported cost" in error for error in errors)
    assert not any(
        error.startswith("semantic-fixture/Estimated cost from provider:")
        and "hard-coded prices" in error
        for error in errors
    )
    assert any("invocation-volume panels" in error for error in errors)
    assert any("latest-value discovery gauges" in error for error in errors)
    assert any("optional token/cost absence" in error for error in errors)
    assert any("blank trace selection" in error for error in errors)
    assert any("scope_label must be defined before" in error for error in errors)
    assert any("agent variable must enumerate" in error for error in errors)
    assert any("persisted options must match" in error for error in errors)


def test_operator_units_and_legends_match_query_outputs() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    tool_panel = _panel(activity, "Terminal tool outcomes by tool name (range)")
    tool_target = tool_panel["targets"][0]
    assert "sum by (tool_name)" in tool_target["expr"]
    assert tool_target["legendFormat"] == "{{tool_name}}"

    connector = _dashboard("defenseclaw-connector-detail.json")
    token_panel = _panel(connector, "Reported tokens / min")
    assert token_panel["fieldConfig"]["defaults"]["unit"] == "suffix: tokens/min"

    token_rate_panels = (
        (activity, "Tokens / sec by type", "suffix: tokens/sec"),
        (connector, "Tokens / sec by direction x model", "suffix: tokens/sec"),
        (
            _dashboard("defenseclaw-connectors.json"),
            "Reported agent tokens / min",
            "suffix: tokens/min",
        ),
        (
            _dashboard("defenseclaw-connectors.json"),
            "Tokens / sec by connector x direction",
            "suffix: tokens/sec",
        ),
        (
            _dashboard("defenseclaw-traffic.json"),
            "Tokens / sec by direction x model",
            "suffix: tokens/sec",
        ),
    )
    for dashboard, title, expected_unit in token_rate_panels:
        assert _panel(dashboard, title)["fieldConfig"]["defaults"]["unit"] == expected_unit


def test_latest_ai_discovery_gauges_choose_newest_current_logical_series() -> None:
    now = 1_000
    physical_samples = [
        {"source": "host", "privacy_mode": "standard", "instance": "old", "ts": 800, "value": 9},
        {"source": "host", "privacy_mode": "standard", "instance": "new", "ts": 995, "value": 2},
        {"source": "workspace", "privacy_mode": "standard", "instance": "new", "ts": 990, "value": 3},
    ]
    current = [sample for sample in physical_samples if sample["ts"] >= now - 300]
    newest = {
        (sample["source"], sample["privacy_mode"]): max(
            candidate["ts"]
            for candidate in current
            if (candidate["source"], candidate["privacy_mode"])
            == (sample["source"], sample["privacy_mode"])
        )
        for sample in current
    }
    assert sum(
        sample["value"]
        for sample in current
        if sample["ts"] == newest[(sample["source"], sample["privacy_mode"])]
    ) == 5

    discovery = _dashboard("defenseclaw-ai-discovery.json")
    identity = _dashboard("defenseclaw-agent-identity.json")
    for panel in (
        _panel(discovery, "Active AI signals"),
        _panel(discovery, "Active signals by source"),
        _panel(identity, "AI discovery active signals"),
    ):
        expression = panel["targets"][0]["expr"]
        assert "timestamp(defenseclaw_ai_discovery_active_signals" in expression
        assert "max by (source, privacy_mode) (timestamp(" in expression
        assert "== on (source, privacy_mode) group_left" in expression
        assert "time() - 300" in expression
        assert "sum(last_over_time(" not in expression
        assert "max(last_over_time(" not in expression


def test_low_risk_dashboard_labels_match_their_queries() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    assert _panel(activity, "Canonical events (selected root session tree)")
    assert not any(
        panel.get("title") == "Hook events (selected root session tree)"
        for panel in activity["panels"]
    )

    policy = _dashboard("defenseclaw-policy-decisions.json")
    live_hosts = _panel(policy, "URL references by host (live)")["targets"][0]["expr"]
    assert 'host!~"localhost|127\\\\..*"' in live_hosts

    identity = _dashboard("defenseclaw-agent-identity.json")
    for title in (
        "Distinct agent.id observed (Loki, by gen_ai.agent.name)",
        "Header-presence rate (Loki) — events with gen_ai.agent.id set",
    ):
        assert _panel(identity, title)["targets"][0]["legendFormat"] == "{{agent_name}}"
    discovery_runs = _panel(identity, "Discovery runs ($__range)")
    discovery_runs_expr = discovery_runs["targets"][0]["expr"]
    assert discovery_runs["datasource"]["type"] == "loki"
    assert "$__range" in discovery_runs_expr
    assert "count_over_time" in discovery_runs_expr
    assert "agent[.]discovery[.](completed|rejected)" in discovery_runs_expr
    assert "increase(" not in discovery_runs_expr
    assert "two counter samples" in discovery_runs["description"]
    assert discovery_runs["fieldConfig"]["defaults"]["unit"] == "short"
    vendors = _panel(identity, "Top vendors / products ($__range)")
    assert "$__range" in vendors["targets"][0]["expr"]
    assert vendors["transformations"][0]["options"]["renameByName"]["Value"] == "signals/$__range"


def test_live_inventory_does_not_report_non_finite_samples_as_zero() -> None:
    audit = _load_audit_module()

    assert audit._numeric_result_status([]) == "empty"
    assert audit._numeric_result_status([{"values": [[1, "NaN"], [2, "+Inf"]]}]) == "empty"
    assert audit._numeric_result_status([{"values": [[1, "0"]]}]) == "zero"


def test_tempo_readiness_retries_before_succeeding(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _load_audit_module()
    calls = 0

    class ReadyResponse:
        status = 200

        def __enter__(self) -> ReadyResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_urlopen(_url: str, *, timeout: int) -> ReadyResponse:
        nonlocal calls
        assert timeout == 10
        calls += 1
        if calls < 3:
            raise OSError("Tempo is starting")
        return ReadyResponse()

    monkeypatch.setattr(audit.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(audit.time, "sleep", lambda _seconds: None)

    assert audit.tempo_readiness_error() is None
    assert calls == 3


def test_live_inventory_checks_tempo_before_search(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _load_audit_module()
    call_order: list[str] = []
    dashboard = {
        "uid": "tempo-fixture",
        "title": "Tempo fixture",
        "description": "Exercises readiness-gated TraceQL search.",
        "panels": [
            {
                "type": "table",
                "title": "Recent traces",
                "datasource": {"type": "tempo", "uid": "defenseclaw-tempo"},
                "targets": [
                    {
                        "queryType": "traceqlSearch",
                        "filters": [
                            {
                                "tag": "service.name",
                                "scope": "resource",
                                "operator": "=",
                                "value": ["defenseclaw"],
                            },
                            {
                                "tag": "name",
                                "scope": "span",
                                "operator": "=",
                                "value": ["defenseclaw.ai.discovery"],
                            },
                        ],
                    },
                ],
            },
        ],
    }

    def fake_readiness() -> None:
        call_order.append("ready")
        return None

    def fake_request(
        _url: str,
        params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        assert params is not None
        assert timeout_seconds == audit.DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS
        assert params["q"] == ('{ resource.service.name = "defenseclaw" && name = "defenseclaw.ai.discovery" }')
        call_order.append("search")
        return {"traces": [{"traceID": "1"}]}

    monkeypatch.setattr(audit, "tempo_readiness_error", fake_readiness)
    monkeypatch.setattr(audit, "request_json", fake_request)

    inventory, errors = audit.live_inventory([(Path("fixture.json"), dashboard)])

    assert errors == []
    assert call_order == ["ready", "search"]
    assert inventory[0]["panels"][0]["status"] == "data"


def test_live_inventory_caps_each_query_by_shared_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    observed_timeouts: list[float] = []
    dashboard = {
        "uid": "deadline-fixture",
        "title": "Deadline fixture",
        "panels": [
            {
                "type": "stat",
                "title": "Bounded query",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [{"expr": "fixture_total", "instant": True}],
            },
        ],
    }

    def fake_request(
        _url: str,
        _params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        observed_timeouts.append(timeout_seconds)
        return {"status": "success", "data": {"result": []}}

    monkeypatch.setattr(audit.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(audit, "request_json", fake_request)

    inventory, errors = audit.live_inventory(
        [(Path("fixture.json"), dashboard)],
        deadline=112.5,
        query_timeout_seconds=60,
    )

    assert errors == []
    assert inventory[0]["status_counts"]["empty"] == 1
    assert observed_timeouts == [12.5]


def test_live_inventory_reports_genuine_backend_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    dashboard = {
        "uid": "timeout-fixture",
        "title": "Timeout fixture",
        "panels": [
            {
                "type": "logs",
                "title": "Hung backend",
                "datasource": {"type": "loki", "uid": "defenseclaw-loki"},
                "targets": [{"expr": '{service_name="defenseclaw"}'}],
            },
        ],
    }

    def fake_request(
        _url: str,
        _params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        assert timeout_seconds == 7
        raise audit.AuditError("timed out")

    monkeypatch.setattr(audit, "request_json", fake_request)

    inventory, errors = audit.live_inventory(
        [(Path("fixture.json"), dashboard)],
        query_timeout_seconds=7,
    )

    assert inventory[0]["status_counts"]["error"] == 1
    assert errors == ["timeout-fixture/Hung backend: timed out"]


_GOLDEN_AGENTS = (
    {"role": "root", "parent": "", "depth": 0},
    {"role": "direct", "parent": "root", "depth": 1},
    {"role": "nested", "parent": "direct", "depth": 2},
    {"role": "leaf", "parent": "nested", "depth": 3},
)
_GOLDEN_PHASE_CODES = {
    "session": 1,
    "planning": 2,
    "model": 3,
    "tool": 4,
    "approval": 5,
    "waiting": 6,
    "responding": 7,
    "completed": 9,
}
_GOLDEN_LIFECYCLE_EVENTS = {
    "session_start",
    "session_end",
    "subagent_start",
    "subagent_stop",
    "turn_start",
    "turn_end",
    "tool_start",
    "tool_end",
    "event",
}


def _golden_tool_family(tool_name: str) -> str:
    normalized = tool_name.strip().lower()
    if "skill" in normalized:
        return "Skills"
    if normalized.startswith("mcp"):
        return "MCP"
    if (
        normalized in {"bash", "shell", "exec_command", "run_shell_command"}
        or "shell" in normalized
        or "terminal" in normalized
    ):
        return "Bash"
    if normalized == "apply_patch":
        return "File edits"
    if normalized.startswith("collaboration"):
        return "Collaboration"
    if normalized.startswith("web") or "browser" in normalized:
        return "Web / browser"
    if "image" in normalized or "visual" in normalized:
        return "Visual"
    if normalized in {"update_plan", "get_goal", "update_goal"}:
        return "Task control"
    return tool_name.strip()


def _golden_agent(stamp: str, role: str, *, bad_leaf_depth: bool = False) -> dict[str, object]:
    agent = next(item for item in _GOLDEN_AGENTS if item["role"] == role)
    depth = int(agent["depth"])
    if role == "leaf" and bad_leaf_depth:
        depth = 2
    parent = str(agent["parent"])
    return {
        "role": role,
        "agent_id": f"golden-agent-{role}-{stamp}",
        "session_id": f"golden-session-{role}-{stamp}",
        "parent_id": f"golden-agent-{parent}-{stamp}" if parent else "",
        "parent_session_id": f"golden-session-{parent}-{stamp}" if parent else "",
        "root_id": f"golden-agent-root-{stamp}",
        "root_session_id": f"golden-session-root-{stamp}",
        "lifecycle_id": f"golden-lifecycle-{role}-{stamp}",
        "execution_id": f"golden-execution-{role}-{stamp}",
        "depth": depth,
    }


def _golden_log_record(
    stamp: str,
    role: str,
    event_name: str,
    *,
    order: int,
    lifecycle_event: str,
    lifecycle_state: str,
    lifecycle_outcome: str,
    phase: str,
    previous_phase: str,
    sequence: int,
    trace_id: str = "aa" * 16,
    bad_leaf_depth: bool = False,
) -> dict[str, object]:
    agent = _golden_agent(stamp, role, bad_leaf_depth=bad_leaf_depth)
    agent_id = str(agent["agent_id"])
    body: dict[str, object] = {
        "gen_ai.agent.id": agent_id,
        "gen_ai.agent.name": f"golden-{role}",
        "gen_ai.conversation.id": agent["session_id"],
        "defenseclaw.agent.type": role,
        "defenseclaw.agent.root.id": agent["root_id"],
        "defenseclaw.agent.lineage.provenance": "reported",
        "defenseclaw.session.root.id": agent["root_session_id"],
        "defenseclaw.agent.lifecycle.id": agent["lifecycle_id"],
        "defenseclaw.agent.execution.id": agent["execution_id"],
        "defenseclaw.agent.depth": agent["depth"],
        "defenseclaw.agent.lifecycle.event": lifecycle_event,
        "defenseclaw.agent.lifecycle.state": lifecycle_state,
        "defenseclaw.agent.phase": phase,
        "defenseclaw.agent.phase.code": _GOLDEN_PHASE_CODES[phase],
        "defenseclaw.agent.sequence": sequence,
        "defenseclaw.operation.id": f"golden-operation-{role}-{stamp}",
    }
    if agent["parent_id"]:
        body["defenseclaw.agent.parent.id"] = agent["parent_id"]
        body["defenseclaw.session.parent.id"] = agent["parent_session_id"]
    if previous_phase:
        body["defenseclaw.agent.phase.previous"] = previous_phase
    if event_name == "model.request":
        marker = "initial prompt" if role == "root" else "model request"
        body["gen_ai.input.messages"] = f"local-observability golden {marker} {stamp}"
        body["defenseclaw.model.request.id"] = f"golden-prompt-{role}-{stamp}"
        body["gen_ai.provider.name"] = "openai"
        body["gen_ai.request.model"] = "gpt-5"
    elif event_name == "model.response":
        body["gen_ai.output.messages"] = f"local-observability golden model response {stamp}"
        body["defenseclaw.model.response.id"] = f"golden-response-{role}-{stamp}"
        body["gen_ai.provider.name"] = "openai"
        body["gen_ai.request.model"] = "gpt-5"
        body["gen_ai.response.model"] = "gpt-5"
    elif event_name == "tool.invocation.requested":
        body["gen_ai.tool.name"] = "read_file" if role == "root" else "shell"
        body["gen_ai.tool.call.id"] = (
            f"golden-tool-root-{stamp}" if role == "root" else f"golden-tool-{stamp}"
        )
        body["gen_ai.tool.call.arguments"] = {"marker": "local-observability-golden"}
    elif event_name == "tool.invocation.completed":
        body["gen_ai.tool.name"] = "read_file" if role == "root" else "shell"
        body["gen_ai.tool.call.id"] = (
            f"golden-tool-root-{stamp}" if role == "root" else f"golden-tool-{stamp}"
        )
        body["gen_ai.tool.call.result"] = {"marker": "local-observability-golden"}
    elif event_name == "event":
        body["defenseclaw.operation.id"] = f"golden-update-{stamp}"
    elif event_name == "hook_decision":
        body["defenseclaw.hook.event"] = "UserPromptSubmit"
        body["defenseclaw.hook.result"] = "ok"
        body["defenseclaw.guardrail.effective_action"] = "allow"
        body["defenseclaw.guardrail.raw_action"] = "allow"
        body["defenseclaw.guardrail.reason"] = (
            f"local-observability golden prompt accepted {stamp}"
        )
        body["defenseclaw.security.severity"] = "INFO"
        body["defenseclaw.guardrail.mode"] = "enforce"
        body["defenseclaw.guardrail.would_block"] = False
        body["defenseclaw.guardrail.enforced"] = False
        body["defenseclaw.connector.step_idx"] = 1
        body["defenseclaw.guardrail.latency_ms"] = 1
    elif event_name.startswith("approval."):
        # The approval belongs to the same Codex leaf/tool execution and must
        # remain selectable under the root-scoped Agent360 and Activity views.
        body.pop("defenseclaw.agent.lifecycle.event", None)
        body.pop("defenseclaw.agent.lifecycle.state", None)
        body.pop("defenseclaw.operation.id", None)
        body["defenseclaw.approval.id"] = f"golden-approval-{stamp}"
        body["defenseclaw.approval.command"] = "printf local-observability-golden-approval"
        if event_name == "approval.resolved":
            body["defenseclaw.approval.result"] = "approved"
            body["defenseclaw.approval.actor_type"] = "automatic"
    connector = "codex"
    correlation = {
        "agent_id": agent_id,
        "connector_id": connector,
        "request_id": f"golden-request-{stamp}",
        "run_id": f"golden-run-{stamp}",
        "session_id": agent["session_id"],
        "turn_id": f"golden-turn-{stamp}",
    }
    if trace_id:
        correlation["trace_id"] = trace_id
    record: dict[str, object] = {
        "record_id": f"golden-record-{order}-{stamp}",
        "timestamp": f"2026-07-07T00:00:{order:02d}Z",
        "event_name": event_name,
        "body": body,
        "correlation": correlation,
        "projection": {"state": "raw", "redaction_profile": "none"},
    }
    if lifecycle_outcome:
        record["outcome"] = lifecycle_outcome
    return record


def _golden_span(
    stamp: str,
    *,
    role: str,
    family: str,
    span_id: str,
    parent_span_id: str = "",
    lifecycle_event: str = "",
    lifecycle_state: str = "",
    phase: str = "",
    sequence: int = 0,
    trace_id: str = "aa" * 16,
    bad_leaf_depth: bool = False,
) -> dict[str, object]:
    agent = _golden_agent(stamp, role, bad_leaf_depth=bad_leaf_depth)
    agent_id = str(agent["agent_id"])
    attributes = {
        "defenseclaw.span.family": family,
        "gen_ai.agent.id": agent_id,
        "gen_ai.conversation.id": agent["session_id"],
        "defenseclaw.agent.root.id": agent["root_id"],
        "defenseclaw.session.root.id": agent["root_session_id"],
        "defenseclaw.agent.lifecycle.id": agent["lifecycle_id"],
        "defenseclaw.agent.execution.id": agent["execution_id"],
        "defenseclaw.agent.depth": str(agent["depth"]),
        "defenseclaw.run.id": f"golden-run-{stamp}",
        "defenseclaw.request.id": f"golden-request-{stamp}",
        "defenseclaw.turn.id": f"golden-turn-{stamp}",
    }
    if agent["parent_id"]:
        attributes["defenseclaw.agent.parent.id"] = agent["parent_id"]
        attributes["defenseclaw.session.parent.id"] = agent["parent_session_id"]
    if lifecycle_event:
        attributes["defenseclaw.agent.lifecycle.event"] = lifecycle_event
    if lifecycle_state:
        attributes["defenseclaw.agent.lifecycle.state"] = lifecycle_state
    if phase:
        attributes["defenseclaw.agent.phase"] = phase
        attributes["defenseclaw.agent.phase.code"] = str(_GOLDEN_PHASE_CODES[phase])
    if sequence:
        attributes["defenseclaw.agent.sequence"] = str(sequence)
    if family == "span.approval.resolve":
        attributes["defenseclaw.approval.id"] = f"golden-approval-{stamp}"
        attributes["defenseclaw.approval.result"] = "approved"
    span: dict[str, object] = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": "exec.approval" if family == "span.approval.resolve" else f"{family} {role}",
        "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attributes.items()],
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    return span


def _golden_backend_responses(
    stamp: str,
    *,
    broken_nested_parent: bool = False,
    omit_approval: bool = False,
    omit_turn_end: bool = False,
    omit_initial_prompt: bool = False,
    omit_conversation_prompt: bool = False,
    omit_conversation_prompt_edge: bool = False,
    corrupt_conversation_prompt_edge_details: bool = False,
    bad_leaf_depth: bool = False,
    regress_terminal_sequence: bool = False,
    omit_terminal_transition: bool = False,
    omit_model_edge: bool = False,
    omit_tool_edge: bool = False,
    omit_root_model_edge: bool = False,
    omit_root_tool_edge: bool = False,
    omit_authored_phase_edge: bool = False,
    reverse_approval_chronology: bool = False,
    approval_before_tool_request: bool = False,
    approval_after_tool_completion: bool = False,
    parent_terminal_span: bool = False,
    missing_terminal_span_id: bool = False,
    mismatched_terminal_wire_trace_id: bool = False,
    approval_outside_tool_span: bool = False,
    drop_generic_event_parent_lineage: bool = False,
    drift_last_seen_identity: bool = False,
    drift_lifecycle_identity: bool = False,
    leading_zero_main_trace_id: bool = False,
    strip_search_leading_zero: bool = False,
    duplicate_topology_node: bool = False,
    duplicate_topology_node_across_frames: bool = False,
    duplicate_topology_edge: bool = False,
    dangling_topology_edge: bool = False,
    cyclic_topology_edge: bool = False,
    observed_requests: list[tuple[str, str]] | None = None,
):
    main_trace_id = "0a" + ("aa" * 15) if leading_zero_main_trace_id else "aa" * 16
    span_ids = {
        "root": "11" * 8,
        "direct": "22" * 8,
        "nested": "33" * 8,
        "leaf": "44" * 8,
        "root_model": "55" * 8,
        "root_tool": "66" * 8,
        "model": "77" * 8,
        "tool": "88" * 8,
        "approval": "99" * 8,
        "direct_turn": "aa" * 8,
        "root_turn": "bb" * 8,
    }
    spans = [
        _golden_span(
            stamp,
            role="root",
            family="span.agent.invoke",
            span_id=span_ids["root"],
            lifecycle_event="session_start",
            lifecycle_state="active",
            phase="model",
        ),
        _golden_span(
            stamp,
            role="root",
            family="span.model.chat",
            span_id=span_ids["root_model"],
            parent_span_id=span_ids["root"],
            lifecycle_event="turn_start",
            lifecycle_state="active",
            phase="model",
        ),
        _golden_span(
            stamp,
            role="root",
            family="span.tool.execute",
            span_id=span_ids["root_tool"],
            parent_span_id=span_ids["root"],
            lifecycle_event="tool_end",
            lifecycle_state="active",
            phase="tool",
        ),
        _golden_span(
            stamp,
            role="direct",
            family="span.agent.invoke",
            span_id=span_ids["direct"],
            parent_span_id=span_ids["root"],
            lifecycle_event="subagent_start",
            lifecycle_state="active",
            phase="model",
        ),
        _golden_span(
            stamp,
            role="nested",
            family="span.agent.invoke",
            span_id=span_ids["nested"],
            parent_span_id=span_ids["root"] if broken_nested_parent else span_ids["direct"],
            lifecycle_event="subagent_start",
            lifecycle_state="active",
            phase="model",
        ),
        _golden_span(
            stamp,
            role="leaf",
            family="span.agent.invoke",
            span_id=span_ids["leaf"],
            parent_span_id=span_ids["nested"],
            lifecycle_event="subagent_start",
            lifecycle_state="active",
            phase="model",
            bad_leaf_depth=bad_leaf_depth,
        ),
        _golden_span(
            stamp,
            role="direct",
            family="span.agent.transition",
            span_id=span_ids["direct_turn"],
            parent_span_id=span_ids["model"],
            lifecycle_event="turn_end",
            lifecycle_state="completed",
            phase="model",
            sequence=3,
        ),
        _golden_span(
            stamp,
            role="root",
            family="span.agent.transition",
            span_id=span_ids["root_turn"],
            parent_span_id=span_ids["root"],
            lifecycle_event="turn_end",
            lifecycle_state="completed",
            phase="responding",
            sequence=5,
        ),
        _golden_span(
            stamp,
            role="direct",
            family="span.model.chat",
            span_id=span_ids["model"],
            parent_span_id=span_ids["direct"],
            lifecycle_event="turn_end",
            lifecycle_state="completed",
            phase="model",
        ),
        _golden_span(
            stamp,
            role="leaf",
            family="span.tool.execute",
            span_id=span_ids["tool"],
            parent_span_id=span_ids["leaf"],
            lifecycle_event="tool_end",
            lifecycle_state="active",
            phase="tool",
            bad_leaf_depth=bad_leaf_depth,
        ),
    ]
    if not omit_approval:
        spans.append(
            _golden_span(
                stamp,
                role="leaf",
                family="span.approval.resolve",
                span_id=span_ids["approval"],
                parent_span_id=span_ids["tool"],
                phase="approval",
                sequence=4,
                bad_leaf_depth=bad_leaf_depth,
            )
        )
    span_times = {
        span_ids["root"]: (100, 10_000),
        span_ids["direct"]: (200, 9_000),
        span_ids["nested"]: (300, 8_000),
        span_ids["leaf"]: (400, 7_000),
        span_ids["root_model"]: (500, 1_000),
        span_ids["root_tool"]: (600, 1_800),
        span_ids["model"]: (700, 2_200),
        span_ids["tool"]: (2_300, 5_000),
        span_ids["direct_turn"]: (2_200, 2_200),
        span_ids["root_turn"]: (9_000, 9_000),
        span_ids["approval"]: (
            (5_001, 6_000) if approval_outside_tool_span else (3_000, 4_000)
        ),
    }
    for span in spans:
        span["traceId"] = main_trace_id
        started_at, finished_at = span_times[str(span["spanId"])]
        span["startTimeUnixNano"] = str(started_at)
        span["endTimeUnixNano"] = str(finished_at)
    record_specs = [
        ("root", "session_start", "session_start", "active", "attempted", "session", "", 1),
        ("root", "turn_start", "turn_start", "active", "attempted", "planning", "session", 2),
        ("root", "hook_decision", "turn_start", "active", "allowed", "planning", "session", 2),
        ("root", "model.request", "turn_start", "active", "attempted", "model", "planning", 2),
        ("root", "model.response", "turn_start", "active", "attempted", "model", "planning", 2),
        ("root", "tool_start", "tool_start", "active", "attempted", "tool", "planning", 3),
        ("root", "tool.invocation.requested", "tool_start", "active", "attempted", "tool", "planning", 3),
        ("root", "tool.invocation.completed", "tool_end", "active", "completed", "planning", "tool", 4),
        ("root", "tool_end", "tool_end", "active", "completed", "planning", "tool", 4),
        ("direct", "subagent_start", "subagent_start", "active", "attempted", "planning", "session", 1),
        ("direct", "turn_start", "turn_start", "active", "attempted", "planning", "session", 2),
        ("nested", "subagent_start", "subagent_start", "active", "attempted", "planning", "session", 1),
        ("nested", "event", "event", "observed", "", "waiting", "planning", 2),
        ("leaf", "subagent_start", "subagent_start", "active", "attempted", "planning", "session", 1),
        ("direct", "model.request", "turn_end", "completed", "completed", "model", "planning", 3),
        ("direct", "model.response", "turn_end", "completed", "completed", "model", "planning", 3),
        ("direct", "turn_end", "turn_end", "completed", "completed", "model", "planning", 3),
        ("leaf", "tool_start", "tool_start", "active", "attempted", "tool", "planning", 2),
        ("leaf", "tool.invocation.requested", "tool_start", "active", "attempted", "tool", "planning", 2),
        ("leaf", "tool.invocation.completed", "tool_end", "active", "completed", "tool", "tool", 5),
        ("leaf", "tool_end", "tool_end", "active", "completed", "tool", "tool", 5),
        (
            "leaf",
            "subagent_stop",
            "subagent_stop",
            "completed",
            "completed",
            "completed",
            "tool",
            2 if regress_terminal_sequence else 6,
        ),
        ("nested", "subagent_stop", "subagent_stop", "completed", "completed", "completed", "waiting", 3),
        ("direct", "subagent_stop", "subagent_stop", "completed", "completed", "completed", "model", 4),
        ("root", "turn_end", "turn_end", "completed", "completed", "responding", "planning", 5),
        ("root", "session_end", "session_end", "completed", "completed", "completed", "responding", 6),
    ]
    if omit_initial_prompt:
        record_specs = [
            spec
            for spec in record_specs
            if not (spec[0] == "root" and spec[1] in {"turn_start", "model.request"})
        ]
    if omit_conversation_prompt:
        record_specs = [spec for spec in record_specs if spec[1] != "hook_decision"]
    if omit_turn_end:
        record_specs = [spec for spec in record_specs if spec[1] != "turn_end"]
    records = [
        _golden_log_record(
            stamp,
            role,
            event_name,
            order=order,
            lifecycle_event=lifecycle_event,
            lifecycle_state=lifecycle_state,
            lifecycle_outcome=lifecycle_outcome,
            phase=phase,
            previous_phase=previous_phase,
            sequence=sequence,
            trace_id="" if event_name in {"session_end", "subagent_stop"} else main_trace_id,
            bad_leaf_depth=bad_leaf_depth,
        )
        for order, (
            role,
            event_name,
            lifecycle_event,
            lifecycle_state,
            lifecycle_outcome,
            phase,
            previous_phase,
            sequence,
        ) in enumerate(record_specs, 1)
    ]
    if omit_turn_end:
        records = [record for record in records if record["event_name"] != "turn_end"]
    if not omit_approval:
        approval_events = ["approval.requested", "approval.resolved"]
        if reverse_approval_chronology:
            approval_events.reverse()
        leaf_request_index = next(
            index
            for index, record in enumerate(records)
            if record["event_name"] == "tool.invocation.requested"
            and record["body"]["gen_ai.agent.id"] == f"golden-agent-leaf-{stamp}"
        )
        leaf_completed_index = next(
            index
            for index, record in enumerate(records)
            if record["event_name"] == "tool.invocation.completed"
            and record["body"]["gen_ai.agent.id"] == f"golden-agent-leaf-{stamp}"
        )
        approval_insert_at = leaf_request_index + 1
        if approval_before_tool_request:
            approval_insert_at = leaf_request_index
        elif approval_after_tool_completion:
            approval_insert_at = leaf_completed_index + 1
        records[approval_insert_at:approval_insert_at] = [
            _golden_log_record(
                stamp,
                "leaf",
                event_name,
                order=15 + offset,
                lifecycle_event="tool_end",
                lifecycle_state="active",
                lifecycle_outcome="completed",
                phase="approval",
                previous_phase="tool",
                sequence=3 + offset,
                trace_id=main_trace_id,
                bad_leaf_depth=bad_leaf_depth,
            )
            for offset, event_name in enumerate(approval_events)
        ]
    for order, record in enumerate(records, 1):
        record["record_id"] = f"golden-record-{order}-{stamp}"
        record["timestamp"] = f"2026-07-07T00:00:{order:02d}Z"
        if drop_generic_event_parent_lineage and record["event_name"] == "event":
            record["body"].pop("defenseclaw.agent.parent.id", None)

    terminal_spans: dict[str, list[dict[str, object]]] = {}
    if not omit_terminal_transition:
        for index, role in enumerate(("leaf", "nested", "direct", "root"), 8):
            terminal_event = "session_end" if role == "root" else "subagent_stop"
            terminal_trace_id = f"{index:02x}" * 16
            terminal_spans[terminal_trace_id] = [
                _golden_span(
                    stamp,
                    role=role,
                    family="span.agent.transition",
                    span_id="" if missing_terminal_span_id and role == "leaf" else f"{index + 16:02x}" * 8,
                    parent_span_id="ff" * 8 if parent_terminal_span and role == "leaf" else "",
                    lifecycle_event=terminal_event,
                    lifecycle_state="completed",
                    phase="completed",
                    trace_id=(
                        "ee" * 16
                        if mismatched_terminal_wire_trace_id and role == "leaf"
                        else terminal_trace_id
                    ),
                    bad_leaf_depth=bad_leaf_depth,
                )
            ]

    lifecycle_records = [
        record for record in records if record["event_name"] in _GOLDEN_LIFECYCLE_EVENTS
    ]
    last_seen = [
        {
            "metric": {
                "connector": "codex",
                "gen_ai_agent_id": agent["agent_id"],
                "defenseclaw_agent_root_id": agent["root_id"],
                "defenseclaw_agent_parent_id": agent["parent_id"] or "none",
                "defenseclaw_session_root_id": agent["root_session_id"],
                "defenseclaw_agent_lifecycle_id": agent["lifecycle_id"],
                "defenseclaw_agent_execution_id": agent["execution_id"],
            },
            "value": [1, "1"],
        }
        for item in _GOLDEN_AGENTS
        for agent in [_golden_agent(stamp, str(item["role"]), bad_leaf_depth=bad_leaf_depth)]
    ]
    if drift_last_seen_identity:
        drifted_last_seen = copy.deepcopy(last_seen[0])
        drifted_last_seen["metric"]["defenseclaw_agent_execution_id"] = "golden-execution-drifted"
        last_seen.append(drifted_last_seen)
    lifecycle_transitions = [
        {
            "metric": {
                "connector": "codex",
                "gen_ai_agent_id": record["body"]["gen_ai.agent.id"],
                "defenseclaw_agent_root_id": record["body"]["defenseclaw.agent.root.id"],
                "defenseclaw_agent_parent_id": record["body"].get("defenseclaw.agent.parent.id", "none"),
                "defenseclaw_session_root_id": record["body"]["defenseclaw.session.root.id"],
                "defenseclaw_agent_lifecycle_id": record["body"]["defenseclaw.agent.lifecycle.id"],
                "defenseclaw_agent_execution_id": record["body"]["defenseclaw.agent.execution.id"],
                "defenseclaw_agent_depth": str(record["body"]["defenseclaw.agent.depth"]),
                "defenseclaw_agent_lifecycle_event": record["event_name"],
                "defenseclaw_agent_lifecycle_state": record["body"]["defenseclaw.agent.lifecycle.state"],
            },
            "value": [1, "1"],
        }
        for record in lifecycle_records
    ]
    if drift_lifecycle_identity:
        drifted_lifecycle = copy.deepcopy(lifecycle_transitions[0])
        drifted_lifecycle["metric"]["gen_ai_agent_id"] = f"golden-agent-rogue-{stamp}"
        lifecycle_transitions.append(drifted_lifecycle)
    transitions = [
        {
            "metric": {
                "connector": "codex",
                "gen_ai_agent_id": record["body"]["gen_ai.agent.id"],
                "defenseclaw_agent_root_id": record["body"]["defenseclaw.agent.root.id"],
                "defenseclaw_agent_execution_id": record["body"]["defenseclaw.agent.execution.id"],
                "defenseclaw_agent_phase_from": record["body"]["defenseclaw.agent.phase.previous"],
                "defenseclaw_agent_phase_to": record["body"]["defenseclaw.agent.phase"],
            },
            "value": [1, "1"],
        }
        for record in lifecycle_records
        if record["body"].get("defenseclaw.agent.phase.previous")
        and record["body"]["defenseclaw.agent.phase.previous"]
        != record["body"]["defenseclaw.agent.phase"]
    ]
    authored_transitions = transitions
    if omit_authored_phase_edge and transitions:
        omitted_metric = transitions[0]["metric"]
        omitted_edge = (
            omitted_metric["defenseclaw_agent_phase_from"],
            omitted_metric["defenseclaw_agent_phase_to"],
        )
        authored_transitions = [
            series
            for series in transitions
            if (
                series["metric"]["defenseclaw_agent_phase_from"],
                series["metric"]["defenseclaw_agent_phase_to"],
            )
            != omitted_edge
        ]
    topology_edges = [
        {
            "metric": {
                "source": f"agent:{agent['parent_id']}",
                "target": f"agent:{agent['agent_id']}",
                "id": f"edge:spawn:{agent['parent_id']}:{agent['agent_id']}",
                "detail__lineage_provenance": "reported",
            },
            "value": [1, "1"],
        }
        for item in _GOLDEN_AGENTS
        for agent in [_golden_agent(stamp, str(item["role"]), bad_leaf_depth=bad_leaf_depth)]
        if agent["parent_id"]
    ]
    root_agent = _golden_agent(stamp, "root")
    topology_edges.append(
        {
            "metric": {
                "source": f"session:{root_agent['agent_id']}",
                "target": f"agent:{root_agent['agent_id']}",
                "id": f"edge:session:{root_agent['agent_id']}",
            },
            "value": [1, "1"],
        }
    )
    for record in records:
        body = record.get("body", {})
        if not isinstance(body, dict):
            continue
        event_name = str(record.get("event_name") or "")
        agent_id = str(body.get("gen_ai.agent.id") or "")
        operation_id = str(body.get("defenseclaw.operation.id") or "")
        execution_id = str(body.get("defenseclaw.agent.execution.id") or "")
        provider = str(body.get("gen_ai.provider.name") or "")
        model_name = str(body.get("gen_ai.response.model") or body.get("gen_ai.request.model") or "")
        if (
            event_name == "model.request"
            and body.get("defenseclaw.agent.depth") == 0
            and not omit_conversation_prompt_edge
        ):
            topology_edges.append(
                {
                    "metric": {
                        "source": f"prompts:{agent_id}",
                        "target": f"agent:{agent_id}",
                        "id": f"edge:prompts:{agent_id}",
                        "detail__edge_kind": (
                            "wrong_prompt_edge"
                            if corrupt_conversation_prompt_edge_details
                            else "prompt_submissions_to_root"
                        ),
                        "detail__agent_id": agent_id,
                        "detail__root_agent_id": str(body["defenseclaw.agent.root.id"]),
                        "detail__event_name": "prompt submission",
                        "detail__connector": "codex",
                    },
                    "value": [1, "1"],
                }
            )
        if (
            event_name == "model.request"
            and provider
            and model_name
            and not omit_model_edge
            and not (omit_root_model_edge and agent_id == f"golden-agent-root-{stamp}")
        ):
            topology_edges.append(
                {
                    "metric": {
                        "source": f"agent:{agent_id}",
                        "target": f"model:{agent_id}:{provider}:{model_name}",
                        "id": f"edge:model:{agent_id}:{provider}:{model_name}",
                    },
                    "value": [1, "1"],
                }
            )
        tool_family = _golden_tool_family(str(body.get("gen_ai.tool.name") or ""))
        if (
            event_name == "tool.invocation.requested"
            and tool_family
            and not omit_tool_edge
            and not (omit_root_tool_edge and agent_id == f"golden-agent-root-{stamp}")
        ):
            topology_edges.append(
                {
                    "metric": {
                        "source": f"agent:{agent_id}",
                        "target": f"tool:{agent_id}:{tool_family}",
                        "id": f"edge:tool:{agent_id}:{tool_family}",
                    },
                    "value": [1, "1"],
                }
            )
        approval_id = str(body.get("defenseclaw.approval.id") or "")
        if event_name == "approval.requested" and approval_id and not omit_approval:
            topology_edges.append(
                {
                    "metric": {
                        "source": f"agent:{agent_id}",
                        "target": f"approval:{agent_id}:{approval_id}",
                        "id": f"edge:approval:{agent_id}:{approval_id}",
                    },
                    "value": [1, "1"],
                }
            )
        if event_name in {"session_end", "subagent_stop", "turn_end"} and execution_id:
            outcome_suffix = execution_id
            if event_name == "turn_end":
                outcome_suffix = (
                    f"turns:{body.get('defenseclaw.agent.lifecycle.state', '')}:"
                    f"{record.get('outcome', '')}"
                )
            topology_edges.append(
                {
                    "metric": {
                        "source": f"agent:{agent_id}",
                        "target": f"outcome:{agent_id}:{outcome_suffix}",
                        "id": f"edge:outcome:{agent_id}:{outcome_suffix}",
                    },
                    "value": [1, "1"],
                }
            )

    # LogQL aggregations return one series per grouped edge/node identity.
    topology_edges = list(
        {
            str(series["metric"]["id"]): series
            for series in topology_edges
        }.values()
    )
    topology_nodes = [
        {"metric": {"id": node_id}, "value": [1, "1"]}
        for node_id in sorted(
            {
                str(series["metric"][endpoint])
                for series in topology_edges
                for endpoint in ("source", "target")
            }
        )
    ]
    # All golden agents have graph-eligible activity in the selected range, so
    # the 24-hour endpoint anchors must suppress themselves instead of emitting
    # a second row with the same Node Graph ID.
    root_anchor_nodes: list[dict[str, object]] = []
    spawn_parent_anchor_nodes: list[dict[str, object]] = []
    if duplicate_topology_node_across_frames:
        root_anchor_nodes.append(
            {
                "metric": {"id": f"agent:golden-agent-root-{stamp}"},
                "value": [1, "1"],
            },
        )
    if duplicate_topology_node:
        topology_nodes.append(copy.deepcopy(topology_nodes[0]))
    if duplicate_topology_edge:
        spawn_edge = next(
            series
            for series in topology_edges
            if str(series["metric"]["id"]).startswith("edge:spawn:")
        )
        topology_edges.append(copy.deepcopy(spawn_edge))
    if dangling_topology_edge:
        topology_edges.append(
            {
                "metric": {
                    "source": f"agent:golden-agent-root-{stamp}",
                    "target": "agent:missing-golden-agent",
                    "id": f"edge:spawn:dangling:{stamp}",
                },
                "value": [1, "1"],
            }
        )
    if cyclic_topology_edge:
        topology_edges.append(
            {
                "metric": {
                    "source": f"agent:golden-agent-leaf-{stamp}",
                    "target": f"agent:golden-agent-root-{stamp}",
                    "id": f"edge:spawn:cycle:{stamp}",
                },
                "value": [1, "1"],
            }
        )

    spans_by_trace: dict[str, list[dict[str, object]]] = {
        main_trace_id: spans,
        **terminal_spans,
    }

    def fake_request(
        url: str,
        params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        assert timeout_seconds == 7
        if observed_requests is not None:
            observed_requests.append((url, str((params or {}).get("query", (params or {}).get("q", "")))))
        if url == "http://127.0.0.1:3100/loki/api/v1/query":
            assert params is not None
            query = params["query"]
            edge_prefix_by_query_marker = {
                "session_starts_root": "edge:session:",
                "parent_agent_to_subagent": "edge:spawn:",
                "prompt_submissions_to_root": "edge:prompts:",
                "agent_model_summary": "edge:model:",
                "agent_tool_summary": "edge:tool:",
                "agent_approval": "edge:approval:",
                "agent_sends_message": "edge:message:",
                "detail__edge_kind=`agent_outcomes`": "edge:outcome:",
            }
            edge_prefix = next(
                (
                    prefix
                    for marker, prefix in edge_prefix_by_query_marker.items()
                    if marker in query
                ),
                None,
            )
            if edge_prefix is not None:
                result = [
                    series
                    for series in topology_edges
                    if str(series.get("metric", {}).get("id", "")).startswith(edge_prefix)
                ]
            elif "detail__node_type=`root_agent_anchor`" in query:
                result = root_anchor_nodes
            elif "detail__node_type=`spawn_parent_anchor`" in query:
                result = spawn_parent_anchor_nodes
            else:
                node_prefix_by_query_marker = {
                    "detail__node_type=`session_start`": "session:",
                    "detail__node_type=`agent`": "agent:",
                    "detail__node_type=`prompt_summary`": "prompts:",
                    "detail__node_type=`model_summary`": "model:",
                    "detail__node_type=`tool_summary`": "tool:",
                    "detail__node_type=`approval_request`": "approval:",
                    "detail__node_type=`agent_messages`": "message:",
                    "Session/subagent terminal observation": "outcome:",
                }
                node_prefix = next(
                    (
                        prefix
                        for marker, prefix in node_prefix_by_query_marker.items()
                        if marker in query
                    ),
                    None,
                )
                assert node_prefix is not None, query
                result = [
                    series
                    for series in topology_nodes
                    if str(series.get("metric", {}).get("id", "")).startswith(node_prefix)
                ]
            return {"status": "success", "data": {"result": result}}
        if url.endswith("/api/v1/query"):
            assert params is not None
            query = params["query"]
            if "count(count by (gen_ai_agent_id)" in query:
                result = [{"metric": {}, "value": [1, str(len(_GOLDEN_AGENTS) - 1)]}]
            elif '"source"' in query and "defenseclaw_agent_parent_id" in query:
                result = topology_edges
            elif "lifecycle_transitions" in query:
                result = lifecycle_transitions
            elif "phase_transitions" in query:
                result = (
                    authored_transitions
                    if omit_authored_phase_edge and '"direction"' in query
                    else transitions
                )
            else:
                result = last_seen
            return {"status": "success", "data": {"result": result}}
        if "loki/api/v1/query_range" in url:
            return {
                "status": "success",
                "data": {
                    "result": [
                        {"values": [[str(index), json.dumps(record)] for index, record in enumerate(records)]},
                    ],
                },
            }
        if url.endswith("/api/search"):
            return {
                "traces": [
                    {
                        "traceID": (
                            trace_id.lstrip("0")
                            if strip_search_leading_zero
                            else trace_id
                        ),
                    }
                    for trace_id in spans_by_trace
                ],
            }
        if "/api/traces/" in url:
            trace_id = url.rsplit("/", 1)[-1].zfill(32)
            return {"batches": [{"scopeSpans": [{"spans": spans_by_trace.get(trace_id, [])}]}]}
        raise AssertionError(f"unexpected request: {url}")

    return fake_request


def test_live_golden_accepts_one_coherent_native_run(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(audit, "request_json", _golden_backend_responses(stamp))

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    assert report["stamp"] == stamp
    assert report["last_seen_series"] == 4
    assert report["log_records"] == 28
    assert report["trace_spans"] == 15
    assert report["trace_id"] == "aa" * 16
    assert report["model_agent_count"] == 2
    assert report["tool_agent_count"] == 2
    assert report["agent360_topology_edges"] == 16
    assert report["agent360_phase_edges"] == 10


def test_live_golden_queries_prometheus_history_over_configured_lookback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    observed_requests: list[tuple[str, str]] = []
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, observed_requests=observed_requests),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    prometheus_queries = [
        query
        for url, query in observed_requests
        if url.endswith("/api/v1/query")
    ]
    for metric in (
        "defenseclaw_agent_last_seen_seconds",
        "defenseclaw_agent_lifecycle_transitions_total",
        "defenseclaw_agent_phase_transitions_total",
    ):
        discovery_queries = [
            query
            for query in prometheus_queries
            if metric in query and "golden-agent-[a-z]" in query
        ]
        assert discovery_queries, metric
        assert discovery_queries[0].startswith(f"max_over_time({metric}")
        assert discovery_queries[0].endswith("[600s])")


def test_live_golden_scopes_tempo_search_to_selected_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    backend = _golden_backend_responses(stamp)
    observed_queries: list[str] = []

    def crowded_tempo(
        url: str,
        params: dict[str, str] | None = None,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        if url.endswith("/api/search"):
            query = str((params or {}).get("q", ""))
            observed_queries.append(query)
            if stamp not in query:
                return {
                    "traces": [
                        {"traceID": f"{index:032x}"}
                        for index in range(1, 101)
                    ],
                }
        return backend(url, params, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(audit, "request_json", crowded_tempo)

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    assert report["trace_spans"] == 15
    assert observed_queries
    assert all(stamp in query for query in observed_queries)


def test_live_golden_accepts_tempo_search_ids_without_leading_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, strip_search_leading_zero=True),
    )

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    assert report["trace_spans"] == 15


def test_live_golden_normalizes_authored_operation_search_trace_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(
            stamp,
            strip_search_leading_zero=True,
            leading_zero_main_trace_id=True,
        ),
    )

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    assert report["trace_id"] == "0a" + ("aa" * 15)


def test_live_golden_proves_generic_depth_three_agent_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(audit, "request_json", _golden_backend_responses(stamp))

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    assert report["agent_count"] == 4
    assert report["max_depth"] == 3
    assert report["terminal_events"] == 4


@pytest.mark.parametrize(
    ("mutation", "message_fragment"),
    (
        ("drift_last_seen_identity", "last_seen identity drifted"),
        ("drift_lifecycle_identity", "unknown golden agent"),
    ),
)
def test_live_golden_rejects_every_positive_metric_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message_fragment: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any(message_fragment in error for error in errors), errors


def test_live_golden_executes_authored_agent360_target_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    observed_requests: list[tuple[str, str]] = []
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, observed_requests=observed_requests),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert errors == []
    queries = [query for _url, query in observed_requests]
    assert any("count(count by (gen_ai_agent_id)" in query for query in queries)
    assert any(
        "count_over_time" in query
        and "label_format" in query
        and "body_defenseclaw_agent_parent_id" in query
        for query in queries
    )
    assert any('"direction"' in query and "defenseclaw_agent_phase_transitions_total" in query for query in queries)
    topology_queries = [
        query
        for url, query in observed_requests
        if url == "http://127.0.0.1:3100/loki/api/v1/query"
    ]
    assert len(topology_queries) == 18
    assert any(
        'event_name="session_start"' in query
        and 'detail__node_type=`root_agent_anchor`' in query
        and 'id=`agent:{{.body_gen_ai_agent_id}}`' in query
        and "unless on (id)" in query
        and "[10m]" in query
        for query in topology_queries
    )
    assert any(
        'event_name="subagent_start"' in query
        and 'detail__node_type=`spawn_parent_anchor`' in query
        and 'id=`agent:{{.body_defenseclaw_agent_parent_id}}`' in query
        and "[24h]" in query
        and "[10m]" in query
        and "and on (graph_child_id)" in query
        and "unless on (id)" in query
        for query in topology_queries
    )
    assert any(
        'detail__node_type=`agent`' in query
        and query.startswith("((topk by (id) (1,")
        and "Canonical 24-hour session_start or subagent_start identity" in query
        and "unless on (id)" in query
        for query in topology_queries
    )
    assert any(
        'event_name="model.request"' in query
        and "body_gen_ai_provider_name" in query
        and "body_gen_ai_response_model" in query
        and "agent_model_summary" in query
        for query in topology_queries
    )
    assert any(
        'event_name="tool.invocation.requested"' in query
        and "tool_family=" in query
        and "agent_tool_summary" in query
        for query in topology_queries
    )
    assert any(
        'defenseclaw_event_name=~`hook_decision|model.request`' in query
        and '(event_name="hook_decision" and source="connector"' in query
        and '(connector!="codex" and event_name="model.request")' in query
        and 'body_defenseclaw_agent_depth="0"' in query
        and query.startswith("max by (")
        and query.count("count by") == 2
        and "prompt_observation" in query
        and "prompt_key" in query
        and "prompts:{{.body_gen_ai_agent_id}}" in query
        and "prompt_submissions_to_root" in query
        for query in queries
    )
    assert any("span.defenseclaw.agent.root.id" in query for query in queries)
    assert any(
        "approval[.](requested|resolved)" in query
        and f'|= "golden-agent-root-{stamp}" | json' in query
        for query in queries
    )
    assert any(
        f'|~ "golden-session-root-{stamp}" | json' in query
        and "body_defenseclaw_session_root_id" in query
        for query in queries
    )


@pytest.mark.parametrize(
    ("mutation", "expected_edge"),
    (
        ("omit_model_edge", "golden-agent-direct"),
        ("omit_tool_edge", "golden-agent-leaf"),
        ("omit_root_model_edge", "golden-agent-root"),
        ("omit_root_tool_edge", "golden-agent-root"),
    ),
)
def test_live_golden_rejects_missing_model_or_tool_topology_edge(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_edge: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("topology" in error.lower() and expected_edge in error for error in errors), errors


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        ("duplicate_topology_node", "blank or duplicate node IDs"),
        ("duplicate_topology_node_across_frames", "blank or duplicate node IDs"),
        ("duplicate_topology_edge", "blank or duplicate edge IDs"),
        ("dangling_topology_edge", "dangling edge endpoints"),
        ("cyclic_topology_edge", "directed cycle"),
    ),
)
def test_live_golden_rejects_invalid_topology_integrity(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_error: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any(expected_error in error for error in errors), errors


def test_live_golden_rejects_missing_root_conversation_prompt_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, omit_conversation_prompt=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("conversation prompt decisions=0" in error for error in errors), errors


def test_live_golden_rejects_missing_conversation_prompt_topology_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, omit_conversation_prompt_edge=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    expected = f"prompts:golden-agent-root-{stamp} -> agent:golden-agent-root-{stamp}"
    assert any("topology" in error.lower() and expected in error for error in errors), errors


def test_live_golden_rejects_conversation_prompt_edge_without_click_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(
            stamp,
            corrupt_conversation_prompt_edge_details=True,
        ),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("clickable identity/details" in error for error in errors), errors


def test_live_golden_rejects_missing_authored_directed_phase_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, omit_authored_phase_edge=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("authored directed phase edge" in error for error in errors), errors


def test_live_golden_rejects_generic_event_without_canonical_parent_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, drop_generic_event_parent_lineage=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("nested-owned generic lifecycle observation" in error for error in errors), errors


def test_live_golden_rejects_reversed_approval_chronology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, reverse_approval_chronology=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("approval.requested" in error and "precedes approval.resolved" in error for error in errors)


@pytest.mark.parametrize(
    "mutation",
    ("approval_before_tool_request", "approval_after_tool_completion"),
)
def test_live_golden_rejects_approval_outside_tool_causal_interval(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("tool/approval causal order" in error for error in errors), errors


@pytest.mark.parametrize(
    ("mutation", "message_fragment"),
    (
        ("parent_terminal_span", "request-bounded root"),
        ("missing_terminal_span_id", "span id"),
        ("mismatched_terminal_wire_trace_id", "wire trace id"),
    ),
)
def test_live_golden_rejects_invalid_terminal_span_identity(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message_fragment: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any(message_fragment in error.lower() for error in errors), errors


def test_live_golden_rejects_approval_span_outside_parent_tool_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, approval_outside_tool_span=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("approval span falls outside its parent tool span" in error for error in errors), errors


def test_live_golden_rejects_disconnected_w3c_agent_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, broken_nested_parent=True),
    )

    report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert report["trace_id"] == ""
    assert any("W3C" in error and "topology" in error for error in errors)


def test_live_golden_rejects_missing_canonical_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, omit_approval=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("missing" in error and "approval.requested" in error for error in errors)
    assert any("tool-child approval" in error for error in errors)


def test_live_golden_rejects_missing_turn_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, omit_turn_end=True),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any("missing" in error and "turn_end" in error for error in errors)


@pytest.mark.parametrize(
    ("mutation", "message_fragment"),
    (
        ("omit_initial_prompt", "initial prompt"),
        ("bad_leaf_depth", "depth"),
        ("regress_terminal_sequence", "sequence"),
        ("omit_terminal_transition", "terminal transition"),
    ),
)
def test_live_golden_rejects_correlation_contract_regressions(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message_fragment: str,
) -> None:
    audit = _load_audit_module()
    stamp = "1783400000000000000"
    monkeypatch.setattr(audit.time, "time", lambda: 1783400001.0)
    monkeypatch.setattr(
        audit,
        "request_json",
        _golden_backend_responses(stamp, **{mutation: True}),
    )

    _report, errors = audit._live_golden_once(range_seconds=600, query_timeout_seconds=7)

    assert any(message_fragment in error.lower() for error in errors), errors


def test_live_golden_retry_preserves_the_last_semantic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _load_audit_module()
    clock = iter((100.0, 100.0, 101.5, 102.0))
    monkeypatch.setattr(audit.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(audit.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        audit,
        "_live_golden_once",
        lambda **_kwargs: ({"stamp": "1"}, ["Prometheus is missing native Agent360 data"]),
    )

    report, errors = audit.live_golden_audit(deadline=102.0, query_timeout_seconds=60)

    assert report == {"stamp": "1"}
    assert errors == ["Prometheus is missing native Agent360 data"]


def test_tempo_target_query_uses_operator_correct_multi_value_join() -> None:
    audit = _load_audit_module()

    positive = audit.tempo_target_query(
        {
            "queryType": "traceqlSearch",
            "filters": [
                {
                    "tag": "service.name",
                    "scope": "resource",
                    "operator": "=",
                    "value": ["gateway", "worker"],
                },
            ],
        },
    )
    negative = audit.tempo_target_query(
        {
            "queryType": "traceqlSearch",
            "filters": [
                {
                    "tag": "name",
                    "scope": "span",
                    "operator": "!=",
                    "value": ["health", "ready"],
                },
            ],
        },
    )

    assert positive == ('{ (resource.service.name = "gateway" || resource.service.name = "worker") }')
    assert negative == '{ (name != "health" && name != "ready") }'


@pytest.mark.parametrize("query", [{}, [], "   "])
def test_tempo_target_query_rejects_invalid_raw_queries(query: object) -> None:
    audit = _load_audit_module()

    with pytest.raises(audit.AuditError):
        audit.tempo_target_query({"query": query})


def test_prometheus_rate_interval_matches_default_otel_push_cadence() -> None:
    audit = _load_audit_module()

    assert (
        audit.prometheus_time_interval_seconds(audit.SOURCE_DATASOURCES) >= audit.DEFAULT_METRIC_EXPORT_INTERVAL_SECONDS
    )


def test_static_audit_rejects_short_rate_windows_and_mislabelled_series(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    audit = _load_audit_module()
    dashboard_dir = tmp_path / "dashboards"
    dashboard_dir.mkdir()
    dashboard = {
        "uid": "rate-contract-fixture",
        "title": "Rate contract fixture",
        "description": "Exercises cadence, legend, and percentile validation.",
        "panels": [
            {
                "type": "timeseries",
                "title": "Wrong legend",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [
                    {
                        "expr": 'sum by (action) (rate(example_total{severity="HIGH"}[5m]))',
                        "legendFormat": "{{severity}}",
                        "refId": "A",
                    },
                ],
            },
            {
                "type": "timeseries",
                "title": "Wrong percentile",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [
                    {
                        "expr": ("histogram_quantile(0.95, sum by (le) (rate(example_bucket[5m])))"),
                        "legendFormat": "p50",
                        "refId": "p50",
                    },
                ],
            },
            {
                "type": "timeseries",
                "title": "Unknown metric label",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [
                    {
                        "expr": ('rate(defenseclaw_connector_hook_outcome_total{connector="codex", result="ok"}[5m])'),
                        "refId": "A",
                    },
                ],
            },
            {
                "type": "timeseries",
                "title": "Unknown histogram bucket",
                "datasource": {"type": "prometheus", "uid": "defenseclaw-prometheus"},
                "targets": [
                    {
                        "expr": ('rate(defenseclaw_connector_hook_latency_milliseconds_bucket{le="2500.0"}[5m])'),
                        "refId": "A",
                    },
                ],
            },
        ],
    }
    (dashboard_dir / "fixture.json").write_text(json.dumps(dashboard), encoding="utf-8")
    datasource = tmp_path / "datasources.yml"
    datasource.write_text("jsonData:\n  timeInterval: 15s\n", encoding="utf-8")

    monkeypatch.setattr(audit, "SOURCE_DIR", dashboard_dir)
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing-dashboards")
    monkeypatch.setattr(audit, "SOURCE_DATASOURCES", datasource)
    monkeypatch.setattr(audit, "PACKAGED_DATASOURCES", tmp_path / "missing-datasources.yml")

    _dashboards, errors = audit.static_audit()

    assert any("must be at least the default 60s" in error for error in errors)
    assert any("legend references labels absent from the query: severity" in error for error in errors)
    assert any("is labelled [50] but queries p95" in error for error in errors)
    assert any("filters on unknown labels: result" in error for error in errors)
    assert any("uses unknown exact le value '2500.0'" in error for error in errors)


def test_connector_dashboard_queries_the_metric_named_by_each_panel() -> None:
    dashboard = _dashboard("defenseclaw-connectors.json")
    expected_fragments = {
        "Records / sec by source x signal": (
            "defenseclaw_otel_ingest_records_total",
            "sum by (source, signal)",
        ),
        "Bytes / sec by source x signal": (
            "defenseclaw_otel_ingest_bytes_total",
            "sum by (source, signal)",
        ),
        "Tokens / sec by connector x direction": (
            "defenseclaw_agent_token_usage_total",
            "sum by (connector, kind)",
        ),
        "LLM operation duration p95 by connector": (
            "defenseclaw_agent_span_duration_milliseconds_bucket",
            "sum by (le, connector)",
            "gen_ai_operation_name",
        ),
        "Evaluations / sec by hook event": (
            "defenseclaw_inspect_evaluations_total",
            "sum by (hook_event)",
            "label_replace",
        ),
        "Codex notify by type + status (5m)": ("defenseclaw_codex_notify_total",),
        "Quietest connectors (silence sec)": ("defenseclaw_otel_ingest_last_seen_ts_seconds",),
        "Hook latency p95 by event type": (
            "defenseclaw_connector_hook_latency_milliseconds_bucket",
            "sum by (le, event_type)",
        ),
    }
    for title, fragments in expected_fragments.items():
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert all(fragment in expression for fragment in fragments), title


def test_token_counter_queries_preserve_a_new_series_first_sample() -> None:
    audit = _load_audit_module()
    token_counters = (
        "defenseclaw_agent_token_usage_total",
        "gen_ai_client_token_usage_sum",
    )
    checked: list[tuple[str, str]] = []

    for dashboard_path in sorted(DASHBOARD_DIR.glob("*.json")):
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
        for panel in audit.panels(dashboard):
            for target in panel.get("targets", []):
                expression = str(target.get("expr", ""))
                metric = next((name for name in token_counters if name in expression), None)
                if metric is None:
                    continue
                checked.append((dashboard_path.name, str(panel.get("title", ""))))
                assert f"rate({metric}" not in expression
                assert "increase(" in expression
                assert expression.count(f"last_over_time({metric}") >= 2
                assert " * 0" in expression
                assert " unless " in expression
                assert " offset " in expression
                if "$__rate_interval" in expression:
                    assert "/ ($__rate_interval_ms / 1000)" in expression

    assert len(checked) == 18


def test_dashboard_queries_preserve_v8_identity_and_absence_semantics() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    queried_panels = [
        panel
        for panel in activity["panels"]
        if panel.get("type") not in {"row", "text"} and panel.get("targets")
    ]
    assert all(
        "$connector" in " ".join(str(target.get("expr", "")) for target in panel["targets"])
        for panel in queried_panels
    )
    assert "defenseclaw_connector_hook_invocations_total" in _panel(activity, "Tool calls")["targets"][0]["expr"]
    for title in (
        "Hook events / sec by event type",
        "Hook events / sec by connector",
        "Hook events by event type",
        "Events by connector",
    ):
        expression = _panel(activity, title)["targets"][0]["expr"]
        assert "defenseclaw_connector_hook_invocations_total" in expression
        assert "defenseclaw_connector_hook_outcome_total" not in expression

    cost = _panel(activity, "Reported cumulative cost by model")
    cost_query = cost["targets"][0]["expr"]
    assert "defenseclaw_agent_reported_cost_USD" in cost_query
    assert "gen_ai_client_token_usage" not in cost_query
    assert "vector(0)" not in cost_query


def test_agent_dashboards_use_canonical_terminal_failure_vocabulary() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    model_terminal = _panel(activity, "LLM responses and failures (live)")
    model_query = model_terminal["targets"][0]["expr"]
    assert 'event_name=~"model[.](response|call[.]failed)"' in model_query
    assert "model.failed" not in model_query

    for title in (
        "Terminal tool outcomes by tool name (range)",
        "Terminal tool outcomes by category (range)",
    ):
        panel = _panel(activity, title)
        expression = panel["targets"][0]["expr"]
        assert "tool[.]invocation[.](completed|failed|blocked)" in expression
        assert "completed, failed, and blocked" in panel["description"].lower()

    agent360 = _panel(
        _dashboard("defenseclaw-agent-360.json"),
        "Lifecycle DAG — prompt → agents → work → outcomes",
    )
    topology_queries = " ".join(target["expr"] for target in agent360["targets"])
    assert r"model\.(request|response|call\.failed)" in topology_queries
    assert r"model\.(request|response|failed)" not in topology_queries
    assert "model.failed" not in topology_queries


def test_activity_session_tree_drilldown_uses_canonical_root_identity() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    variables = {item["name"]: item for item in activity["templating"]["list"]}
    session = variables["session"]
    assert session["label"] == "Root session"
    assert "defenseclaw_agent_last_seen_seconds" in session["definition"]
    assert 'connector=~"$connector"' in session["definition"]
    assert "defenseclaw_session_root_id" in session["definition"]
    assert "gen_ai_client_token_usage_count" not in session["definition"]

    token_panel = _panel(activity, "Reported tokens for selected session tree")
    token_query = token_panel["targets"][0]["expr"]
    assert "defenseclaw_agent_token_usage_total" in token_query
    assert "gen_ai_client_token_usage_sum" not in token_query
    assert 'defenseclaw_session_root_id=~"$session"' in token_query
    assert "and on (gen_ai_agent_id, defenseclaw_agent_lifecycle_id, defenseclaw_agent_execution_id)" in token_query
    rename = token_panel["transformations"][0]["options"]["renameByName"]
    assert rename["kind"] == "direction"

    for title in (
        "Canonical events (selected root session tree)",
        "Shadow blocks (root session tree)",
        "Ordered session-tree lifecycle and work timeline",
    ):
        panel = _panel(activity, title)
        query = panel["targets"][0]["expr"]
        assert '|~ "$session" | json' in query
        assert '|= "$session"' not in query
        assert "select" in panel["description"].lower()
        assert 'body_defenseclaw_session_root_id=~"$session"' in query
        assert 'body_gen_ai_conversation_id=~"$session"' in query
        assert 'body_defenseclaw_session_parent_id=~"$session"' in query

    timeline = _panel(activity, "Ordered session-tree lifecycle and work timeline")
    assert timeline["options"]["sortOrder"] == "Ascending"
    timeline_query = timeline["targets"][0]["expr"]
    for field in (
        ".body_defenseclaw_agent_sequence",
        ".event_name",
        ".body_gen_ai_agent_id",
        ".body_gen_ai_agent_name",
        ".body_defenseclaw_agent_type",
        ".body_defenseclaw_agent_root_id",
        ".body_defenseclaw_agent_parent_id",
        ".body_defenseclaw_agent_depth",
        ".body_defenseclaw_agent_lineage_provenance",
        ".body_gen_ai_conversation_id",
        ".body_defenseclaw_session_root_id",
        ".body_defenseclaw_session_parent_id",
        ".body_defenseclaw_agent_phase_previous",
        ".body_defenseclaw_agent_phase",
        ".body_defenseclaw_agent_lifecycle_id",
        ".body_defenseclaw_agent_lifecycle_event",
        ".body_defenseclaw_agent_lifecycle_state",
        ".body_defenseclaw_agent_execution_id",
        ".body_defenseclaw_request_id",
        ".body_defenseclaw_turn_id",
        ".body_defenseclaw_run_id",
        ".body_defenseclaw_operation_id",
        ".body_gen_ai_provider_name",
        ".body_gen_ai_request_model",
        ".body_gen_ai_response_model",
        ".body_defenseclaw_model_request_id",
        ".body_defenseclaw_model_response_id",
        ".body_gen_ai_tool_name",
        ".body_gen_ai_tool_call_id",
        ".body_defenseclaw_tool_status",
        ".body_defenseclaw_tool_exit_code",
        ".body_defenseclaw_approval_id",
        ".body_defenseclaw_approval_result",
        ".outcome",
        ".correlation_trace_id",
        ".correlation_span_id",
    ):
        assert field in timeline_query

    tool_categories = _panel(activity, "Terminal tool outcomes by category (range)")
    assert len(tool_categories["targets"]) == 1
    category_query = tool_categories["targets"][0]["expr"]
    assert "sum by (tool_family)" in category_query
    for family in (
        "Skills",
        "MCP",
        "Bash",
        "File edits",
        "Collaboration",
        "Web / browser",
        "Visual",
        "Task control",
    ):
        assert family in category_query

    tool_detail = _panel(activity, "Projected tool command details (live)")
    detail_query = tool_detail["targets"][0]["expr"]
    assert "requested|started|completed|failed|blocked" in detail_query
    assert ".body_gen_ai_tool_call_arguments" in detail_query
    assert ".body_gen_ai_tool_call_result" in detail_query
    assert ".body_defenseclaw_tool_status" in detail_query
    assert ".body_defenseclaw_tool_exit_code" in detail_query
    assert ".correlation_span_id" in detail_query
    assert "printf" not in detail_query

    tokens_by_agent = _panel(activity, "Reported tokens by agent, model & direction")
    tokens_query = tokens_by_agent["targets"][0]["expr"]
    assert "connector, gen_ai_agent_id" in tokens_query
    assert "defenseclaw_agent_root_id" in tokens_query
    for column, scope in (
        ("Agent ID", "gen_ai_agent_id"),
        ("Root Agent", "defenseclaw_agent_root_id"),
    ):
        override = next(
            item
            for item in tokens_by_agent["fieldConfig"]["overrides"]
            if item["matcher"].get("options") == column
        )
        link = next(
            prop["value"][0]
            for prop in override["properties"]
            if prop["id"] == "links"
        )
        assert "defenseclaw-agent-360" in link["url"]
        assert f"var-scope_label={scope}" in link["url"]
        assert "from=${__from}&to=${__to}" in link["url"]

    assert _panel(activity, "Session-tree lifecycle drilldown — root to terminal")["gridPos"]["y"] == 115
    assert token_panel["gridPos"]["y"] == 116
    assert timeline["gridPos"]["y"] == 124

    truthful_titles = {
        "Hook event volume by type and connector",
        "Hook events / sec by event type",
        "Hook events by event type",
        "Shadow blocks by hook event type",
        "Tools — names, categories, and projected details",
        "Projected URL references and host summaries",
    }
    activity_title_list = [panel.get("title") for panel in activity["panels"]]
    assert truthful_titles <= set(activity_title_list)
    assert len(activity_title_list) == len(set(activity_title_list))


def test_activity_root_session_all_value_and_timeline_are_truthful() -> None:
    activity = _dashboard("defenseclaw-activity.json")
    session = next(
        item for item in activity["templating"]["list"] if item["name"] == "session"
    )
    assert session["includeAll"] is True
    assert session["allValue"] == ".+"

    timeline = _panel(activity, "Ordered session-tree lifecycle and work timeline")
    expression = timeline["targets"][0]["expr"]
    for field in (
        ".body_defenseclaw_session_source",
        ".body_defenseclaw_session_resumed",
        ".body_defenseclaw_agent_execution_id",
        ".body_defenseclaw_operation_id",
        ".body_defenseclaw_approval_id",
        ".body_defenseclaw_approval_result",
        ".body_defenseclaw_approval_actor_type",
        ".body_defenseclaw_guardrail_effective_action",
        ".body_defenseclaw_guardrail_raw_action",
        ".body_defenseclaw_guardrail_enforced",
        ".body_defenseclaw_guardrail_would_block",
    ):
        assert field in expression

    description = timeline["description"].lower()
    assert "all root sessions" in description
    assert "approval" in description


def test_identity_observed_agents_claims_only_available_fields_and_keeps_time_range() -> None:
    identity = _dashboard("defenseclaw-agent-identity.json")
    panel = _panel(identity, "Observed agents — click Agent ID for Agent360")

    assert "current lifecycle state" not in panel["description"].lower()
    rename = panel["transformations"][1]["options"]["renameByName"]
    assert "defenseclaw_agent_lifecycle_state" not in rename
    assert "defenseclaw_agent_depth" not in rename
    assert "State" not in rename.values()
    assert "Depth" not in rename.values()

    for column in ("Agent ID", "Root Agent"):
        override = next(
            item
            for item in panel["fieldConfig"]["overrides"]
            if item["matcher"].get("options") == column
        )
        link = next(
            prop["value"][0]
            for prop in override["properties"]
            if prop["id"] == "links"
        )
        assert "from=${__from}&to=${__to}" in link["url"]


def test_dashboard_queries_preserve_v8_identity_across_other_dashboards() -> None:
    connectors = _dashboard("defenseclaw-connectors.json")
    connector_text = json.dumps(connectors)
    assert 'gen_ai_agent_name=~\\"$connector' not in connector_text
    assert 'body_gen_ai_agent_name=~\\"$connector' not in connector_text

    identity = _dashboard("defenseclaw-agent-identity.json")
    active_identity = _panel(identity, "Active agent.id (5m)")["targets"][0]["expr"]
    assert "time() - 300" in active_identity
    assert "timestamp(defenseclaw_ai_discovery_active_signals" in _panel(
        identity, "AI discovery active signals"
    )["targets"][0]["expr"]
    assert "> 0" in _panel(identity, "Components observed")["targets"][0]["expr"]

    discovery = _dashboard("defenseclaw-ai-discovery.json")
    for title in (
        "Signals by category",
        "Signals by state",
        "Top vendor / product (selected range)",
        "Signals by detector (selected range)",
    ):
        expression = _panel(discovery, title)["targets"][0]["expr"]
        assert "increase(defenseclaw_ai_discovery_signals_total" in expression
        assert "max_over_time" not in expression

    findings_stream = _panel(_dashboard("defenseclaw-findings.json"), "Finding event stream")
    finding_query = findings_stream["targets"][0]["expr"]
    for variable in ("$connector", "$scanner", "$rule_id", "$severity"):
        assert variable in finding_query


def test_identity_dashboard_queries_identity_and_discovery_instruments() -> None:
    dashboard = _dashboard("defenseclaw-agent-identity.json")
    expected_metrics = {
        "Discovery runs by source × cache_hit × result": "defenseclaw_agent_discovery_runs_total",
        "Components observed": "defenseclaw_ai_components_installs",
        "OTLP records by connector (source)": "defenseclaw_otel_ingest_records_total",
        "Per-connector install state (latest)": "defenseclaw_agent_discovery_installed_ratio",
        "Identity confidence distribution": "defenseclaw_ai_confidence_identity_score_bucket",
        "Presence confidence distribution": "defenseclaw_ai_confidence_presence_score_bucket",
    }
    for title, metric in expected_metrics.items():
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert metric in expression, title

    duration_targets = _panel(dashboard, "Discovery duration p50/p95")["targets"]
    assert "histogram_quantile(0.50" in duration_targets[0]["expr"]
    assert "histogram_quantile(0.95" in duration_targets[1]["expr"]
    assert all(
        "defenseclaw_agent_discovery_duration_milliseconds_bucket" in target["expr"] for target in duration_targets
    )

    distinct_ids = _panel(dashboard, "Distinct agent.id observed (Loki, by gen_ai.agent.name)")
    header_rate = _panel(
        dashboard,
        "Header-presence rate (Loki) — events with gen_ai.agent.id set",
    )
    assert "gen_ai_agent_id" in distinct_ids["targets"][0]["expr"]
    assert "gen_ai_agent_id" in header_rate["targets"][0]["expr"]


def test_security_dashboard_uses_inspection_metrics_for_inspection_panels() -> None:
    dashboard = _dashboard("defenseclaw-security.json")
    for title in (
        "Inspect latency p95 (5m)",
        "Inspect latency p50/p95/p99 by hook event",
    ):
        assert all(
            "defenseclaw_inspect_latency_milliseconds_bucket" in target["expr"]
            for target in _panel(dashboard, title)["targets"]
        )

    for title in (
        "Non-allow evaluations by hook event",
        "Evaluations / sec by connector",
    ):
        assert "defenseclaw_inspect_evaluations_total" in _panel(dashboard, title)["targets"][0]["expr"]


def test_hitl_dashboard_scopes_chat_and_exec_approval_metrics() -> None:
    dashboard = _dashboard("defenseclaw-hitl.json")

    chat_status = _panel(dashboard, "Chat HILT status mix over time")["targets"][0]["expr"]
    chat_ratio = _panel(dashboard, "Chat HILT approval-vs-denial rate (1h rolling)")["targets"][0]["expr"]
    assert "defenseclaw_approval_lifecycle_total" in chat_status
    assert 'surface="chat"' in chat_status
    assert 'connector=~"$connector"' in chat_status
    assert "result" in chat_status
    assert "defenseclaw_approval_lifecycle_total" in chat_ratio
    assert 'surface="chat"' in chat_ratio

    for title in (
        "Exec approvals approved (1h)",
        "Exec approvals denied (1h)",
        "Exec approvals pending (1h)",
        "Auto-approval ratio (1h)",
        "Dangerous-command share (1h)",
        "Denial rate (dangerous exec, 1h)",
        "Exec approval result mix over time",
        "Exec approvals by automatic vs manual",
    ):
        expressions = [target["expr"] for target in _panel(dashboard, title)["targets"]]
        assert all("defenseclaw_approval_count_total" in expression for expression in expressions)


def test_cross_dashboard_semantic_regressions() -> None:
    overview = _dashboard("defenseclaw-overview.json")
    slo = _panel(overview, "Hook latency SLO < 2.5s (5m)")["targets"][0]["expr"]
    assert 'le="2500"' in slo
    assert 'le="2500.0"' not in slo
    llm_stream = _panel(overview, "LLM prompt/response/tool event stream")["targets"][0]["expr"]
    assert "model[.].*" in llm_stream
    assert "tool[.]invocation[.].*" in llm_stream
    assert "defenseclaw_gateway_event_type" not in llm_stream
    overview_active = _panel(overview, "Active connectors (5m)")["targets"][0]["expr"]
    assert "sum by (connector) (label_replace" in overview_active

    connectors = _dashboard("defenseclaw-connectors.json")
    connector_active = _panel(connectors, "Active connectors (5m)")["targets"][0]["expr"]
    assert "sum by (connector) (label_replace" in connector_active

    detail = _dashboard("defenseclaw-connector-detail.json")
    would_block = _panel(detail, "Would-block / min (observe shadow blocks)")["targets"][0]["expr"]
    assert 'would_block="true"' in would_block
    assert "* 60" in would_block
    assert _panel(detail, "OTLP silence (s)")["targets"][0]["expr"] == (
        'time() - max(defenseclaw_otel_ingest_last_seen_ts_seconds{source="$connector"})'
    )

    policy = _dashboard("defenseclaw-policy-decisions.json")
    schema_violations = _panel(policy, "Schema violations by event_type × code")["targets"][0]
    assert "defenseclaw_schema_violations_total" in schema_violations["expr"]
    assert schema_violations["legendFormat"] == "{{event_type}} · {{code}}"

    findings = _dashboard("defenseclaw-findings.json")
    assert (
        "max_over_time((timestamp(increase("
        in _panel(
            findings,
            "Last-seen per rule_id (24h)",
        )["targets"][0]["expr"]
    )
    assert (
        "min_over_time((timestamp(increase("
        in _panel(
            findings,
            "First-seen per rule_id (24h)",
        )["targets"][0]["expr"]
    )
    verdict_panel = _panel(findings, "Verdicts in selected connector/severity window")
    assert verdict_panel["transformations"][0]["options"]["renameByName"]["Value"] == ("verdicts/range")


def test_runtime_fd_history_excludes_unavailable_sentinel() -> None:
    runtime = _dashboard("defenseclaw-runtime.json")
    current = _panel(runtime, "Open FDs")
    history = _panel(runtime, "File descriptors")

    assert current["fieldConfig"]["defaults"]["mappings"][0]["options"]["-1"]["text"] == ("Not supported")
    assert history["targets"][0]["expr"] == "max(defenseclaw_runtime_fd_in_use >= 0)"
    assert "-1" in history["description"]
