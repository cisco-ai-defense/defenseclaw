"""Contract tests for the dynamic Agent Directory -> Agent360 experience."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARDS = ROOT / "bundles" / "local_observability_stack" / "grafana" / "dashboards"
AGENT360 = DASHBOARDS / "defenseclaw-agent-360.json"
CLI_AGENT360 = (
    ROOT
    / "cli"
    / "defenseclaw"
    / "_data"
    / "local_observability_stack"
    / "grafana"
    / "dashboards"
    / "defenseclaw-agent-360.json"
)
IDENTITY = DASHBOARDS / "defenseclaw-agent-identity.json"
COLLECTOR = ROOT / "bundles" / "local_observability_stack" / "otel-collector" / "config.yaml"
PROMETHEUS = ROOT / "bundles" / "local_observability_stack" / "prometheus" / "prometheus.yml"
COMPOSE = ROOT / "bundles" / "local_observability_stack" / "docker-compose.yml"
DATASOURCES = (
    ROOT
    / "bundles"
    / "local_observability_stack"
    / "grafana"
    / "provisioning"
    / "datasources"
    / "datasources.yml"
)


def _dashboard(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _panel_by_title(dashboard: dict, title: str) -> dict:
    for panel in dashboard["panels"]:
        if panel.get("title") == title:
            return panel
    raise AssertionError(f"missing panel {title!r}")


def test_agent360_has_dynamic_directory_and_required_drilldown_surfaces() -> None:
    dashboard = _dashboard(AGENT360)
    assert dashboard["uid"] == "defenseclaw-agent-360"

    variables = {item["name"]: item for item in dashboard["templating"]["list"]}
    assert {"connector", "agent", "scope_label", "lifecycle", "execution", "trace"} <= variables.keys()
    assert "defenseclaw_agent_last_seen_seconds" in variables["agent"]["definition"]

    panel_types = {panel["type"] for panel in dashboard["panels"]}
    assert {"table", "stat", "gauge", "state-timeline", "timeseries", "logs", "traces", "nodeGraph"} <= panel_types

    serialized = json.dumps(dashboard)
    for datasource_uid in ("defenseclaw-prometheus", "defenseclaw-loki", "defenseclaw-tempo"):
        assert datasource_uid in serialized
    for correlation_field in (
        "defenseclaw_agent_root_id",
        "defenseclaw_agent_lifecycle_id",
        "defenseclaw_agent_execution_id",
    ):
        assert correlation_field in serialized
    assert "defenseclaw_agent_token_usage_total" in serialized
    assert "defenseclaw_agent_reported_cost_USD" in serialized
    # Application metrics have exactly one local transport (remote write), so
    # dashboard authors do not need transport-label de-duplication boilerplate.
    assert "max without (job, instance, service, exported_job)" not in serialized


def test_agent360_cli_packaged_dashboard_matches_bundle_source() -> None:
    assert _dashboard(CLI_AGENT360) == _dashboard(AGENT360)


def test_agent360_terminal_success_excludes_observed_non_terminal_events() -> None:
    dashboard = _dashboard(AGENT360)
    panel = _panel_by_title(dashboard, "Terminal success")
    expr = panel["targets"][0]["expr"]
    assert 'defenseclaw_agent_lifecycle_state="completed"' in expr
    assert 'defenseclaw_agent_lifecycle_state=~"completed|failed|interrupted"' in expr
    assert "completed|observed" not in expr


def test_agent360_trace_selection_drives_waterfall_and_topology() -> None:
    dashboard = _dashboard(AGENT360)
    recent = _panel_by_title(dashboard, "Recent traces — click a Trace ID")
    assert "with (most_recent=true)" in recent["targets"][0]["query"]
    links = recent["fieldConfig"]["defaults"]["links"]
    assert any(
        link["title"] == "Select trace in Agent360"
        and "var-trace=${__data.fields.traceID}" in link["url"]
        and link["targetBlank"] is False
        for link in links
    )
    assert any("queryType%22:%22traceId" in link["url"] for link in links)

    waterfall = _panel_by_title(dashboard, "Selected trace waterfall")
    assert waterfall["targets"] == [
        {"queryType": "traceql", "query": "$trace", "refId": "A"}
    ]

    topology = _panel_by_title(dashboard, "Agent, subagent, model, and tool graph")
    assert topology["datasource"]["uid"] == "defenseclaw-prometheus"
    edge_query = topology["targets"][0]["expr"]
    for edge_field in ('"id"', '"source"', '"target"'):
        assert edge_field in edge_query
    assert "gen_ai_tool_name" in edge_query
    assert "gen_ai_request_model" in edge_query
    assert "defenseclaw_agent_parent_id" in edge_query
    assert [step["id"] for step in topology["transformations"]] == [
        "labelsToFields",
        "merge",
        "organize",
    ]


def test_agent360_presents_human_readable_usage_lifecycle_and_logs() -> None:
    dashboard = _dashboard(AGENT360)

    directory = _panel_by_title(dashboard, "Agent Directory — click an Agent ID to drill down")
    assert directory["targets"][0]["expr"].startswith("1000 * ")
    assert directory["options"]["sortBy"][0]["displayName"] == "Last Seen"
    assert any(
        override["matcher"].get("options") == "Last Seen"
        and any(prop.get("value") == "dateTimeFromNow" for prop in override["properties"])
        for override in directory["fieldConfig"]["overrides"]
    )

    last_seen = _panel_by_title(dashboard, "Last seen")
    assert last_seen["options"]["textMode"] == "value"
    assert last_seen["options"]["graphMode"] == "none"

    model_calls_expr = _panel_by_title(dashboard, "Model calls")["targets"][0]["expr"]
    assert "gen_ai_operation_name" in model_calls_expr
    # Spanmetrics does not carry the connector dimension. Stable agent/root
    # identity is the cross-signal selector for this panel.
    assert "connector=" not in model_calls_expr
    for title in ("Input tokens", "Output tokens"):
        assert _panel_by_title(dashboard, title)["options"]["colorMode"] == "none"

    executions = _panel_by_title(dashboard, "Executions and current lifecycle state")
    assert executions["targets"][0]["expr"].startswith("1000 * ")
    assert any(
        override["matcher"].get("options") == "Last Seen"
        for override in executions["fieldConfig"]["overrides"]
    )

    for title in (
        "LLM turns — prompts, responses, model, usage",
        "Tools and website/network interactions",
        "Errors, blocks, approvals, and guardrail decisions",
        "Raw correlated event stream",
    ):
        expr = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert "| json | line_format" in expr


def test_agent360_uses_canonical_gateway_event_types() -> None:
    dashboard = _dashboard(AGENT360)
    decisions = _panel_by_title(
        dashboard, "Errors, blocks, approvals, and guardrail decisions"
    )["targets"][0]["expr"]
    assert 'defenseclaw_gateway_event_type=~"error|verdict|judge|scan_finding"' in decisions
    for nonexistent in ("runtime_error", "approval|", "guardrail|"):
        assert nonexistent not in decisions

    network = _panel_by_title(
        dashboard, "Tools and website/network interactions"
    )["targets"][0]["expr"]
    assert 'defenseclaw_gateway_event_type=~"tool_invocation|egress"' in network
    assert "network_egress" not in network


def test_agent360_exposes_model_tool_cost_and_reliability_analytics() -> None:
    dashboard = _dashboard(AGENT360)
    expected = {
        "Model calls by provider and model": ("gen_ai_provider_name", "gen_ai_request_model"),
        "Model p95 latency by provider and model": ("histogram_quantile", "gen_ai_request_model"),
        "Top tools by calls": ("gen_ai_tool_name",),
        "Tool p95 latency": ("gen_ai_tool_name", "histogram_quantile"),
        "Top websites and destinations": ("defenseclaw_destination_app",),
        "Reported tokens by model": ("defenseclaw_agent_token_usage_total", "gen_ai_request_model"),
        "Reported cost over time": ("defenseclaw_agent_reported_cost_USD",),
        "Reported cost by model": ("defenseclaw_agent_reported_cost_USD", "gen_ai_request_model"),
        "Lifecycle funnel": ("defenseclaw_agent_lifecycle_event",),
        "Span error rate": ('status_code="STATUS_CODE_ERROR"',),
        "Agent span latency heatmap": ("_bucket", "sum by (le)"),
        "Active agents over time": ("gen_ai_agent_id",),
    }
    for title, fragments in expected.items():
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert all(fragment in expression for fragment in fragments), title

    topology = _panel_by_title(dashboard, "Agent, subagent, model, and tool graph")
    assert "Persistent cross-trace topology" in topology["description"]


def test_agent_directory_links_to_reusable_agent360_dashboard() -> None:
    identity = json.dumps(_dashboard(IDENTITY))
    assert "Runtime Agent Directory" in identity
    assert "/d/defenseclaw-agent-360/agent360" in identity
    assert "${__value.raw}" in identity


def test_collector_derives_agent_span_metrics_and_fans_them_to_prometheus() -> None:
    config = COLLECTOR.read_text(encoding="utf-8")
    assert "spanmetrics/agent360:" in config
    assert "defenseclaw.agent.root.id" in config
    assert "gen_ai.tool.name" in config
    assert "exporters: [otlp/tempo, spanmetrics/agent360, debug]" in config
    assert "receivers: [otlp, spanmetrics/agent360]" in config
    assert "exporters: [prometheusremotewrite/prometheus, debug]" in config
    assert "endpoint: 0.0.0.0:8889" not in config

    prometheus = PROMETHEUS.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")
    assert "otel-collector-export" not in prometheus
    assert "otel-collector:8889" not in prometheus
    assert ":8889:8889" not in compose


def test_loki_json_trace_ids_link_to_tempo() -> None:
    config = DATASOURCES.read_text(encoding="utf-8")
    assert '"trace_id"\\s*:\\s*"' in config
    assert "datasourceUid: defenseclaw-tempo" in config
