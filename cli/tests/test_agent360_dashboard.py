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
    assert panel["datasource"]["uid"] == "defenseclaw-loki"
    assert 'agent_lifecycle_state="completed"' in expr
    assert 'agent_lifecycle_state=~"completed|failed|interrupted"' in expr
    assert "completed|observed" not in expr


def test_agent360_durable_counts_use_loki_event_history() -> None:
    dashboard = _dashboard(AGENT360)
    expected_filters = {
        "Turns": 'agent_lifecycle_event="turn_end"',
        "Model calls": 'defenseclaw_gateway_event_type="llm_response"',
        "Tool calls": 'tool_invocation_phase="result"',
    }
    for title, fragment in expected_filters.items():
        panel = _panel_by_title(dashboard, title)
        assert panel["datasource"]["uid"] == "defenseclaw-loki"
        assert "count_over_time" in panel["targets"][0]["expr"]
        assert fragment in panel["targets"][0]["expr"]
        assert 'connector=~"$connector"' in panel["targets"][0]["expr"]

    funnel = _panel_by_title(dashboard, "Lifecycle funnel")
    assert funnel["datasource"]["uid"] == "defenseclaw-loki"
    assert "count_over_time" in funnel["targets"][0]["expr"]


def test_agent360_trace_selection_drives_waterfall_and_topology() -> None:
    dashboard = _dashboard(AGENT360)
    recent = _panel_by_title(
        dashboard, "Operation and enforcement traces — click a Trace ID"
    )
    assert "with (most_recent=true)" in recent["targets"][0]["query"]
    assert "tool_end|turn_end|session_end|subagent_stop" in recent["targets"][0]["query"]
    assert "span.gen_ai.operation.name" in recent["targets"][0]["query"]
    assert "span.defenseclaw.raw_action" in recent["targets"][0]["query"]
    assert "span.defenseclaw.decision" in recent["targets"][0]["query"]
    trace_override = next(
        override
        for override in recent["fieldConfig"]["overrides"]
        if override["matcher"].get("options") == "Trace ID"
    )
    links = next(
        prop["value"]
        for prop in trace_override["properties"]
        if prop["id"] == "links"
    )
    assert links == [
        {
            "title": "${__value.text}",
            "url": "/d/defenseclaw-agent-360/agent360?orgId=1&${connector:queryparam}&${agent:queryparam}&${scope_label:queryparam}&${lifecycle:queryparam}&${execution:queryparam}&var-trace=${__value.raw}&from=${__from}&to=${__to}",
            "targetBlank": False,
        }
    ]
    cell_options = next(
        prop["value"]
        for prop in trace_override["properties"]
        if prop["id"] == "custom.cellOptions"
    )
    assert cell_options == {"type": "data-links"}

    waterfall = _panel_by_title(
        dashboard, "Selected trace waterfall — choose a Trace ID on the left"
    )
    assert waterfall["targets"] == [
        {"queryType": "traceql", "query": "$trace", "refId": "A"}
    ]

    topology = _panel_by_title(
        dashboard, "Aggregate dependency map — agents, subagents, models, and tools"
    )
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


def test_agent360_has_continuous_phase_timeline_and_directed_flow() -> None:
    dashboard = _dashboard(AGENT360)
    timeline = _panel_by_title(dashboard, "Execution phase timeline")
    assert timeline["datasource"]["uid"] == "defenseclaw-prometheus"
    assert "defenseclaw_agent_phase_current_ratio" in timeline["targets"][0]["expr"]
    mappings = timeline["fieldConfig"]["defaults"]["mappings"][0]["options"]
    assert mappings["2"]["text"] == "Planning"
    assert mappings["3"]["text"] == "Model"
    assert mappings["4"]["text"] == "Tool"
    assert mappings["9"]["text"] == "Completed"

    sequence = _panel_by_title(
        dashboard, "Ordered execution sequence — every hook transition"
    )
    assert sequence["options"]["sortOrder"] == "Ascending"
    assert ".agent_sequence" in sequence["targets"][0]["expr"]
    assert ".agent_previous_phase" in sequence["targets"][0]["expr"]
    assert ".agent_phase" in sequence["targets"][0]["expr"]

    flow = _panel_by_title(dashboard, "Execution phase network")
    assert flow["type"] == "nodeGraph"
    edge_query = flow["targets"][0]["expr"]
    assert "defenseclaw_agent_phase_transitions_total" in edge_query
    for edge_field in ('"id"', '"source"', '"target"'):
        assert edge_field in edge_query
    assert "defenseclaw_agent_phase_from" in edge_query
    assert "defenseclaw_agent_phase_to" in edge_query

    directed_edges = _panel_by_title(
        dashboard, "Directed phase edges (source → target)"
    )
    assert '"direction", " → "' in directed_edges["targets"][0]["expr"]
    rename = directed_edges["transformations"][1]["options"]["renameByName"]
    assert rename["defenseclaw_agent_phase_from"] == "From"
    assert rename["defenseclaw_agent_phase_to"] == "To"
    assert rename["direction"] == "Direction"

    for title in ("Average observed phase duration", "Slowest operation classes (p95)"):
        assert _panel_by_title(dashboard, title)["datasource"]["uid"] == "defenseclaw-prometheus"


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
    agent_id_override = next(
        override
        for override in directory["fieldConfig"]["overrides"]
        if override["matcher"].get("options") == "Agent ID"
    )
    assert any(
        prop.get("id") == "custom.cellOptions"
        and prop.get("value") == {"type": "data-links"}
        for prop in agent_id_override["properties"]
    )
    root_id_override = next(
        override
        for override in directory["fieldConfig"]["overrides"]
        if override["matcher"].get("options") == "Root Agent"
    )
    assert any(
        prop.get("id") == "custom.cellOptions"
        and prop.get("value") == {"type": "data-links"}
        for prop in root_id_override["properties"]
    )

    last_seen = _panel_by_title(dashboard, "Last seen")
    assert last_seen["options"]["textMode"] == "value"
    assert last_seen["options"]["graphMode"] == "none"

    model_calls = _panel_by_title(dashboard, "Model calls")
    assert model_calls["datasource"]["uid"] == "defenseclaw-loki"
    assert 'defenseclaw_gateway_event_type="llm_response"' in model_calls["targets"][0]["expr"]
    for title in ("Input tokens", "Output tokens"):
        assert _panel_by_title(dashboard, title)["options"]["colorMode"] == "none"

    executions = _panel_by_title(dashboard, "Executions and last activity")
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
        assert "| json" in expr
        assert '| connector=~"$connector"' in expr
        assert "| line_format" in expr


def test_agent360_uses_canonical_gateway_event_types() -> None:
    dashboard = _dashboard(AGENT360)
    decisions = _panel_by_title(
        dashboard, "Errors, blocks, approvals, and guardrail decisions"
    )["targets"][0]["expr"]
    assert 'defenseclaw_gateway_event_type=~"error|verdict|judge|scan_finding|hook_decision"' in decisions
    assert ".hook_decision_enforced" in decisions
    assert ".hook_decision_would_block" in decisions
    for nonexistent in ("runtime_error", "approval|", "guardrail|"):
        assert nonexistent not in decisions

    network = _panel_by_title(
        dashboard, "Tools and website/network interactions"
    )["targets"][0]["expr"]
    assert 'defenseclaw_gateway_event_type=~"tool_invocation|egress"' in network
    assert "network_egress" not in network


def test_agent360_correlates_hook_decisions_to_recovery_paths() -> None:
    dashboard = _dashboard(AGENT360)

    for title, field in (
        ("Enforced hook blocks", "hook_decision_enforced"),
        ("Observe-mode would-blocks", "hook_decision_would_block"),
    ):
        panel = _panel_by_title(dashboard, title)
        assert panel["datasource"]["uid"] == "defenseclaw-loki"
        expr = panel["targets"][0]["expr"]
        assert 'defenseclaw_gateway_event_type="hook_decision"' in expr
        assert field in expr
        assert "defenseclaw_agent_lifecycle_id=~\"$lifecycle\"" in expr
        assert "defenseclaw_agent_execution_id=~\"$execution\"" in expr

    outcomes = _panel_by_title(dashboard, "Hook action outcomes over time")
    assert outcomes["type"] == "timeseries"
    assert {target["legendFormat"] for target in outcomes["targets"]} == {
        "enforced block", "would block", "alert or approval"
    }

    recovery = _panel_by_title(dashboard, "Decision → recovery path")
    assert recovery["options"]["sortOrder"] == "Ascending"
    expr = recovery["targets"][0]["expr"]
    for event_type in (
        "hook_decision",
        "tool_invocation",
        "llm_prompt",
        "llm_response",
        "lifecycle",
    ):
        assert event_type in expr
    for field in (
        ".hook_decision_event",
        ".hook_decision_action",
        ".hook_decision_enforced",
        ".hook_decision_would_block",
        ".trace_id",
    ):
        assert field in expr


def test_agent360_exposes_model_tool_cost_and_reliability_analytics() -> None:
    dashboard = _dashboard(AGENT360)
    expected = {
        "Model calls by provider and model": ("count_over_time", "provider", "model"),
        "Execution-lifetime model p95 (active in range)": ("histogram_quantile", "gen_ai_request_model"),
        "Top tools by calls": ("count_over_time", "tool_name"),
        "Execution-lifetime tool p95 (active in range)": ("gen_ai_tool_name", "histogram_quantile"),
        "Top websites and destinations": ("count_over_time", "destination"),
        "Reported tokens by model": ("defenseclaw_agent_token_usage_total", "gen_ai_request_model"),
        "Reported cost over time": ("defenseclaw_agent_reported_cost_USD",),
        "Reported cost by model": ("defenseclaw_agent_reported_cost_USD", "gen_ai_request_model"),
        "Lifecycle funnel": ("count_over_time", "agent_lifecycle_event"),
        "Span error rate": ('status_code="STATUS_CODE_ERROR"',),
        "Agent span latency heatmap": ("_bucket", "sum by (le)"),
        "Active agents over time": ("gen_ai_agent_id",),
    }
    for title, fragments in expected.items():
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert all(fragment in expression for fragment in fragments), title

    topology = _panel_by_title(
        dashboard, "Aggregate dependency map — agents, subagents, models, and tools"
    )
    assert "structural topology" in topology["description"]

    for title in (
        "Execution-lifetime model p95 (active in range)",
        "Execution-lifetime tool p95 (active in range)",
    ):
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert "max_over_time(defenseclaw_agent_last_seen_seconds" in expression
        assert "time() - $__range_s" in expression


def test_agent_directory_links_to_reusable_agent360_dashboard() -> None:
    identity = json.dumps(_dashboard(IDENTITY))
    assert "Runtime Agent Directory" in identity
    assert "/d/defenseclaw-agent-360/agent360" in identity
    assert "${__value.raw}" in identity
    assert "var-scope_label=gen_ai_agent_id" in identity
    assert '"type": "data-links"' in identity


def test_agent360_span_metrics_are_connector_scoped() -> None:
    dashboard = _dashboard(AGENT360)
    seen = 0
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            expression = target.get("expr", "")
            if "defenseclaw_agent_span_" not in expression:
                continue
            seen += 1
            # New series carry connector directly. The empty-label branch keeps
            # pre-upgrade spanmetrics visible; the adjacent execution-ID join is
            # still filtered by the selected connector.
            assert expression.count('connector=~"(${connector:regex}|^$)"') == (
                expression.count("defenseclaw_agent_span_")
            ), panel["title"]
    assert seen > 0


def test_collector_derives_agent_span_metrics_and_fans_them_to_prometheus() -> None:
    config = COLLECTOR.read_text(encoding="utf-8")
    assert "spanmetrics/agent360:" in config
    assert "defenseclaw.agent.root.id" in config
    assert "defenseclaw.agent.phase" in config
    assert "defenseclaw.agent.phase.code" in config
    assert "- name: connector" in config
    assert "gen_ai.tool.name" in config
    assert "exporters: [otlp/tempo, spanmetrics/agent360, debug]" in config
    assert "receivers: [otlp, spanmetrics/agent360]" in config
    assert "exporters: [prometheusremotewrite/prometheus, debug]" in config
    assert "deltatocumulative:" in config
    assert "processors: [resource, deltatocumulative, batch]" in config
    assert "endpoint: 0.0.0.0:8889" not in config
    assert "readers:" in config
    assert "without_type_suffix: true" in config
    assert "without_units: true" in config
    assert "address: 0.0.0.0:8888" not in config

    prometheus = PROMETHEUS.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")
    assert "otel/opentelemetry-collector-contrib:0.153.0" in compose
    assert "otel-collector-export" not in prometheus
    assert "otel-collector:8889" not in prometheus
    assert ":8889:8889" not in compose


def test_loki_json_trace_ids_link_to_tempo() -> None:
    config = DATASOURCES.read_text(encoding="utf-8")
    assert '"trace_id"\\s*:\\s*"' in config
    assert "datasourceUid: defenseclaw-tempo" in config
