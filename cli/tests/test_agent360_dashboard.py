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
    assert variables["agent"]["datasource"]["uid"] == "defenseclaw-loki"
    assert '{service_name="defenseclaw"}' in variables["agent"]["definition"]
    assert "body_$scope_label" in variables["agent"]["definition"]
    assert "$scope_label" in variables["agent"]["definition"]
    assert variables["lifecycle"]["datasource"]["uid"] == "defenseclaw-loki"
    assert variables["execution"]["datasource"]["uid"] == "defenseclaw-loki"
    assert variables["lifecycle"]["label"] == "Lifecycle (drilldown)"
    assert variables["execution"]["label"] == "Execution (drilldown)"
    variable_order = [item["name"] for item in dashboard["templating"]["list"]]
    assert variable_order.index("scope_label") < variable_order.index("agent")

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
    assert "body_gen_ai_usage_input_tokens" in serialized
    assert "body_gen_ai_usage_output_tokens" in serialized
    assert "body_defenseclaw_agent_reported_cost_usd" in serialized
    # Application metrics have exactly one local transport (remote write), so
    # dashboard authors do not need transport-label de-duplication boilerplate.
    assert "max without (job, instance, service, exported_job)" not in serialized


def test_agent360_cli_packaged_dashboard_matches_bundle_source() -> None:
    assert _dashboard(CLI_AGENT360) == _dashboard(AGENT360)


def test_agent360_terminal_success_excludes_observed_non_terminal_events() -> None:
    dashboard = _dashboard(AGENT360)
    panel = _panel_by_title(dashboard, "Terminal event success rate")
    expr = panel["targets"][0]["expr"]
    assert panel["datasource"]["uid"] == "defenseclaw-loki"
    assert 'agent_lifecycle_state="completed"' in expr
    assert 'agent_lifecycle_state=~"completed|failed|interrupted"' in expr
    assert "completed|observed" not in expr
    numerator, _denominator = expr.split(" / ", maxsplit=1)
    assert numerator.startswith("100 * (sum(")
    assert numerator.endswith("or vector(0))")


def test_agent360_durable_counts_use_loki_event_history() -> None:
    dashboard = _dashboard(AGENT360)
    expected_filters = {
        "Turns": 'event_name="turn_end"',
        "Model calls": 'event_name="model.response"',
        "Tool calls": 'event_name="tool.invocation.completed"',
    }
    for title, fragment in expected_filters.items():
        panel = _panel_by_title(dashboard, title)
        assert panel["datasource"]["uid"] == "defenseclaw-loki"
        assert "count_over_time" in panel["targets"][0]["expr"]
        assert fragment in panel["targets"][0]["expr"]
        assert 'connector=~"$connector"' in panel["targets"][0]["expr"]
        assert '| json | __error__=""' in panel["targets"][0]["expr"]
        assert 'body_$scope_label=~"$agent"' in panel["targets"][0]["expr"]
        assert "count(sum by (logical_event_id)" in panel["targets"][0]["expr"]
        assert 'correlation_logical_event_id' in panel["targets"][0]["expr"]
        assert 'logical_event_id!=""' not in panel["targets"][0]["expr"]
        for fallback in (
            "logical:{{.correlation_logical_event_id}}",
            "semantic:{{.correlation_semantic_event_id}}",
            "record:{{.record_id}}",
        ):
            assert fallback in panel["targets"][0]["expr"]

    funnel = _panel_by_title(dashboard, "Lifecycle event totals")
    assert funnel["datasource"]["uid"] == "defenseclaw-loki"
    assert "count_over_time" in funnel["targets"][0]["expr"]


def test_agent360_separates_logical_summaries_from_raw_correlation_evidence() -> None:
    dashboard = _dashboard(AGENT360)

    logical = _panel_by_title(dashboard, "Logical events")
    raw = _panel_by_title(dashboard, "Raw observations")
    warnings = _panel_by_title(dashboard, "Relationship warnings observed")
    relationships = _panel_by_title(
        dashboard, "Relationship evidence and conflict chronology"
    )

    assert logical["datasource"]["uid"] == "defenseclaw-loki"
    assert "count(sum by (logical_event_id)" in logical["targets"][0]["expr"]
    assert "correlation_logical_event_id" in logical["targets"][0]["expr"]
    assert 'logical_event_id!=""' not in logical["targets"][0]["expr"]
    assert "semantic:{{.correlation_semantic_event_id}}" in logical["targets"][0]["expr"]
    assert "record:{{.record_id}}" in logical["targets"][0]["expr"]
    assert "exact hook, proxy, and native-otlp mirrors count once" in logical[
        "description"
    ].lower()
    assert "no canonical observation is omitted" in logical["description"].lower()

    assert raw["datasource"]["uid"] == "defenseclaw-loki"
    assert raw["targets"][0]["expr"].startswith("sum(count_over_time(")
    assert "logical_event_id" not in raw["targets"][0]["expr"]
    assert "every canonical loki record" in raw["description"].lower()

    warning_expr = warnings["targets"][0]["expr"]
    assert 'event_name="correlation.relationship.changed"' in warning_expr
    assert 'unresolved|conflicted|rejected' in warning_expr
    assert "transition count" in warnings["description"].lower()
    assert "conflicts api" in warnings["description"].lower()

    assert relationships["type"] == "logs"
    assert relationships["options"]["sortOrder"] == "Ascending"
    assert relationships["options"]["dedupStrategy"] == "none"
    relationship_expr = relationships["targets"][0]["expr"]
    assert 'event_name="correlation.relationship.changed"' in relationship_expr
    for field in (
        "body_defenseclaw_correlation_relationship_type",
        "body_defenseclaw_correlation_relationship_source_kind",
        "body_defenseclaw_correlation_relationship_source_id",
        "body_defenseclaw_correlation_relationship_target_kind",
        "body_defenseclaw_correlation_relationship_target_id",
        "body_defenseclaw_correlation_relationship_method",
        "body_defenseclaw_correlation_relationship_status",
        "body_defenseclaw_correlation_relationship_rule_id",
        "body_defenseclaw_correlation_relationship_rule_version",
        "body_defenseclaw_correlation_relationship_confidence",
        "body_defenseclaw_correlation_relationship_evidence_count",
        "correlation_semantic_event_id",
        "correlation_logical_event_id",
        "correlation_connector_instance_id",
        "correlation_trace_id",
        "correlation_span_id",
    ):
        assert field in relationship_expr
    assert "never substitutes trace parentage for agent lineage" in relationships[
        "description"
    ].lower()
    assert "cumulative durable evidence count" in relationships["description"].lower()

    topology = _panel_by_title(
        dashboard, "Lifecycle DAG — prompt → agents → work → outcomes"
    )
    topology_queries = " ".join(
        target.get("expr", "") for target in topology["targets"]
    )
    for forbidden_parentage in ("parent_span_id", "parentSpanID", "traceparent"):
        assert forbidden_parentage not in topology_queries

    ordered = _panel_by_title(
        dashboard, "Ordered lifecycle and work sequence — root to terminal"
    )
    ordered_expr = ordered["targets"][0]["expr"]
    assert "semantic={{.correlation_semantic_event_id}}" in ordered_expr
    assert "logical={{.correlation_logical_event_id}}" in ordered_expr
    assert "connector_instance={{.correlation_connector_instance_id}}" in ordered_expr
    assert ordered["options"]["sortOrder"] == "Ascending"

    raw_stream = _panel_by_title(dashboard, "Raw correlated event stream")
    assert raw_stream["options"]["dedupStrategy"] == "none"
    assert "no raw observation is collapsed" in raw_stream["description"].lower()

    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            datasource = target.get("datasource", panel.get("datasource", {})).get(
                "type"
            )
            if datasource != "prometheus":
                continue
            expression = target.get("expr", "")
            for forbidden_metric_label in (
                "$scope_label",
                "gen_ai_agent_id",
                "gen_ai_agent_name",
                "defenseclaw_agent_root_id",
                "defenseclaw_agent_parent_id",
                "defenseclaw_agent_lifecycle_id",
                "defenseclaw_agent_execution_id",
                "defenseclaw_session_root_id",
                "semantic_event_id",
                "logical_event_id",
                "request_id",
                "turn_id",
                "tool_invocation_id",
                "correlation_relationship_id",
            ):
                assert forbidden_metric_label not in expression


def test_agent360_trace_selection_drives_waterfall_and_topology() -> None:
    dashboard = _dashboard(AGENT360)
    recent = _panel_by_title(
        dashboard, "Operation and enforcement traces — click a Trace ID"
    )
    assert "with (most_recent=true)" in recent["targets"][0]["query"]
    query = recent["targets"][0]["query"]
    for filter_fragment in (
        'span.defenseclaw.connector.source =~ "${connector:regex}"',
        'span.defenseclaw.agent.lifecycle.id =~ "$lifecycle"',
        'span.defenseclaw.agent.execution.id =~ "$execution"',
    ):
        assert filter_fragment in query
    assert "span.defenseclaw.guardrail.raw_action" in query
    assert "span.defenseclaw.guardrail.effective_action" in query
    assert "span.defenseclaw.guardrail.decision" in query
    assert 'span.defenseclaw.span.family =~ "span.agent.invoke|span.agent.transition|' in query
    assert "span.workflow.run" in query
    assert "session_start|session_end|subagent_start|subagent_stop|turn_start|turn_end" in query
    assert "span.gen_ai.operation.name" in query
    assert 'name = "exec.approval"' in query
    assert "span.defenseclaw.raw_action" not in query
    assert "span.defenseclaw.decision" not in query
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
        dashboard, "Selected trace waterfall — selection required"
    )
    assert waterfall["targets"] == [
        {"queryType": "traceql", "query": "$trace", "refId": "A"}
    ]
    assert "expected initial state" in waterfall["description"].lower()
    assert "until you click a trace id" in waterfall["description"].lower()

    topology = _panel_by_title(
        dashboard, "Lifecycle DAG — prompt → agents → work → outcomes"
    )
    assert topology["datasource"]["uid"] == "defenseclaw-loki"
    expected_target_refs = [
        "edgesSessionStart",
        "edgesSpawn",
        "edgesConversationPrompts",
        "edgesModelSummary",
        "edgesToolSummary",
        "edgesApproval",
        "edgesMessages",
        "edgesOutcome",
        "nodesSessionStart",
        "nodesRootAnchor",
        "nodesSpawnParent",
        "nodesAgent",
        "nodesConversationPrompts",
        "nodesModelSummary",
        "nodesToolSummary",
        "nodesApproval",
        "nodesMessages",
        "nodesOutcome",
    ]
    assert [target["refId"] for target in topology["targets"]] == expected_target_refs
    edge_queries = [
        target["expr"]
        for target in topology["targets"]
        if target["refId"].startswith("edges")
    ]
    node_queries = [
        target["expr"]
        for target in topology["targets"]
        if target["refId"].startswith("nodes")
    ]
    targets_by_ref = {target["refId"]: target["expr"] for target in topology["targets"]}
    prompt_queries = (
        targets_by_ref["edgesConversationPrompts"],
        targets_by_ref["nodesConversationPrompts"],
    )
    assert len(edge_queries) == 8
    assert len(node_queries) == 10
    edge_query = " or ".join(edge_queries)
    node_query = " or ".join(node_queries)
    for edge_field in ("id=", "source=", "target="):
        assert edge_field in edge_query
    for node_field in ("id=", "title=", "subtitle=", "color="):
        assert node_field in node_query
    assert "body_gen_ai_tool_name" in edge_query
    assert "body_gen_ai_request_model" in node_query
    assert "body_defenseclaw_agent_parent_id" in edge_query
    assert "session:" in edge_query
    assert "prompts:" in edge_query
    assert "outcome:" in edge_query
    assert "approval:" in edge_query
    assert (
        "model:{{.body_gen_ai_agent_id}}:{{.body_gen_ai_provider_name}}:"
        in edge_query
    )
    assert (
        "model:{{.body_gen_ai_agent_id}}:{{.body_gen_ai_provider_name}}:"
        in node_query
    )
    assert "tool:{{.body_gen_ai_agent_id}}:{{.tool_family}}" in edge_query
    assert "tool:{{.body_gen_ai_agent_id}}:{{.tool_family}}" in node_query
    for key_field in ("body_gen_ai_agent_id", "body_defenseclaw_agent_execution_id"):
        assert key_field in edge_query
    for query in (*edge_queries, *node_queries):
        assert "count_over_time(" in query
        assert "label_format" in query
        assert '|= "$agent" | json | __error__=""' in query
        assert 'body_$scope_label=~"$agent"' in query
        assert "defenseclaw_event_name=" in query
    assert 'defenseclaw_agent_lifecycle_id=~"$lifecycle"' not in edge_query
    assert 'defenseclaw_agent_execution_id=~"$execution"' not in edge_query
    serialized_topology = json.dumps(topology)
    for detail_field in (
        "detail__node_type",
        "detail__agent_id",
        "detail__root_agent_id",
        "detail__parent_agent_id",
        "detail__lifecycle_id",
        "detail__execution_id",
        "detail__state",
        "detail__outcome",
        "detail__model",
        "detail__provider",
        "detail__tool",
        "detail__tool_family",
        "detail__operation_id",
        "detail__trace_id",
        "detail__lineage_provenance",
        "detail__target_task",
        "detail__target_agent_id",
        "detail__delivery_status",
        "detail__event_name",
        "detail__count_meaning",
        "detail__correlation_note",
        "detail__total",
    ):
        assert detail_field in serialized_topology
    assert "from=${__from}&to=${__to}" in serialized_topology
    assert 'var-agent=${__data.fields[\\"detail__agent_id\\"]}' in serialized_topology
    assert 'var-trace=${__value.raw}' not in serialized_topology
    assert "Open exact Tempo trace" not in serialized_topology
    assert "Open resolved target agent" not in serialized_topology
    transformations = topology["transformations"]
    node_refs = [ref_id for ref_id in expected_target_refs if ref_id.startswith("nodes")]
    edge_refs = [ref_id for ref_id in expected_target_refs if ref_id.startswith("edges")]
    assert [
        (transform["filter"]["options"], transform["id"])
        for transform in transformations
    ] == [
        ("/^nodes/", "labelsToFields"),
        *((ref_id, "calculateField") for ref_id in node_refs),
        ("/^nodes/", "merge"),
        ("/^edges/", "labelsToFields"),
        *((ref_id, "calculateField") for ref_id in edge_refs),
        ("/^edges/", "merge"),
    ]
    calculated_totals = {
        transform["filter"]["options"]: transform["options"]
        for transform in transformations
        if transform["id"] == "calculateField"
    }
    assert calculated_totals == {
        ref_id: {
            "alias": "detail__total",
            "mode": "unary",
            "replaceFields": False,
            "timeSeries": False,
            "unary": {"fieldName": f"Value #{ref_id}", "operator": "abs"},
        }
        for ref_id in (*node_refs, *edge_refs)
    }
    assert not any(
        transform["id"] == "renameByRegex" for transform in transformations
    )
    # Endpoint anchors intentionally omit per-event trace IDs so one stable
    # agent row cannot split by child/session trace. Exact traces remain on the
    # session/spawn edges and in the linked trace/raw panels.
    assert all("detail__trace_id" in query for query in edge_queries)
    assert all(
        "detail__trace_id" in targets_by_ref[ref_id]
        for ref_id in node_refs
        if ref_id not in {"nodesRootAnchor", "nodesSpawnParent"}
    )
    assert all(
        'var-trace=${__value.raw}' not in link["url"] or link["url"].endswith("viewPanel=panel-23")
        for override in topology["fieldConfig"]["overrides"]
        for prop in override["properties"]
        if prop["id"] == "links"
        for link in prop["value"]
    )
    assert "repeated model calls collapse" in topology["description"].lower()
    assert "normalized families" in topology["description"].lower()
    assert "total in range" in topology["description"].lower()
    assert "{{.body_gen_ai_agent_name}}" in node_query
    assert "{{.body_defenseclaw_agent_type}} • depth {{.body_defenseclaw_agent_depth}}" in node_query
    assert "Lifecycle update" not in node_query
    assert "agent_emits_update" not in edge_query
    assert 'event_name="event"' not in edge_query
    assert "detail__edge_kind=`parent_agent_to_subagent`" in edge_query
    assert "detail__lineage_provenance" in edge_query
    assert edge_query.count("[24h]") == 2
    assert node_query.count("[24h]") == 5
    assert edge_query.count('body_defenseclaw_session_resumed!="true"') == 1
    assert node_query.count('body_defenseclaw_session_resumed!="true"') == 4
    assert "session-start and durable lineage anchors are recovered from the last 24 hours" in topology["description"].lower()
    assert "durable relationship records alone establish parentage" in topology["description"].lower()
    assert "raw subagent parent fields and trace parentage never create graph lineage" in topology["description"].lower()
    assert "one node per agent" in topology["description"].lower()
    assert "deliberately not presented as prompt content" in topology["description"].lower()
    assert "counts canonical depth-zero prompt submissions" in topology["description"].lower()
    assert "codex uses connector-source userpromptsubmit facts" in topology["description"].lower()
    assert "native otlp model.request mirrors" in topology["description"].lower()
    assert "model-call totals first sum within each observation source" in topology["description"].lower()
    assert "turn id, model request id, request id, operation id, then occurrence id" in topology["description"].lower()
    assert "structural topology" not in topology["description"].lower()
    assert "directed acyclic" in topology["description"].lower()
    assert "dashboard applies no redaction" in topology["description"].lower()
    assert "central redaction and projection boundary upstream" in topology["description"].lower()

    # Session lifecycle and submitted prompt/model-request facts are distinct.
    assert 'event_name="session_start"' in edge_query
    assert "id=`edge:session:{{.body_gen_ai_agent_id}}`" in edge_query
    assert "source=`session:{{.body_gen_ai_agent_id}}`" in edge_query
    assert "detail__edge_kind=`session_starts_root`" in edge_query
    assert 'event_name="session_start"' in node_query
    assert "id=`session:{{.body_gen_ai_agent_id}}`" in node_query
    assert "title=`Session start`" in node_query
    root_anchor = targets_by_ref["nodesRootAnchor"]
    assert "id=`agent:{{.body_gen_ai_agent_id}}`" in root_anchor
    assert "detail__node_type=`root_agent_anchor`" in root_anchor
    assert "detail__trace_id" not in root_anchor
    assert "unless on (id)" in root_anchor
    assert 'label_format id=`agent:{{.body_gen_ai_agent_id}}` [$__range]' in root_anchor
    spawn_parent = targets_by_ref["nodesSpawnParent"]
    assert "id=`agent:{{.graph_parent_id}}`" in spawn_parent
    assert "detail__node_type=`spawn_parent_anchor`" in spawn_parent
    assert "graph_child_id" in spawn_parent
    assert "and on (connector, graph_child_id)" in spawn_parent
    assert "detail__trace_id" not in spawn_parent
    assert "unless on (connector, id)" in spawn_parent
    assert 'label_format id=`agent:{{.body_gen_ai_agent_id}}` [$__range]' in spawn_parent
    assert 'event_name="correlation.relationship.changed"' in spawn_parent
    assert 'body_defenseclaw_correlation_relationship_source_kind="agent"' in spawn_parent
    assert 'body_defenseclaw_correlation_relationship_target_kind="agent"' in spawn_parent
    assert 'body_defenseclaw_correlation_relationship_type=~"parent_of|delegated_by"' in spawn_parent
    assert "body_defenseclaw_agent_parent_id" not in spawn_parent
    spawn_edge = targets_by_ref["edgesSpawn"]
    assert "graph_child_id" in spawn_edge
    assert "and on (connector, graph_child_id)" in spawn_edge
    assert "[24h]" in spawn_edge
    assert 'event_name="correlation.relationship.changed"' in spawn_edge
    assert 'body_defenseclaw_correlation_relationship_status="active"' in spawn_edge
    assert 'body_defenseclaw_correlation_relationship_source_kind="agent"' in spawn_edge
    assert 'body_defenseclaw_correlation_relationship_target_kind="agent"' in spawn_edge
    assert 'body_defenseclaw_correlation_relationship_type=~"parent_of|delegated_by"' in spawn_edge
    assert 'source=`agent:{{.graph_parent_id}}`' in spawn_edge
    assert 'target=`agent:{{.graph_child_id}}`' in spawn_edge
    assert "paired inverse orientations count once" in spawn_edge
    assert "raw subagent parent fields never create this edge" in spawn_edge
    assert "body_defenseclaw_agent_parent_id" not in spawn_edge
    agent_nodes = targets_by_ref["nodesAgent"]
    assert agent_nodes.startswith("((topk by (id) (1,")
    assert 'defenseclaw_event_name=~`session_start|subagent_start`' in agent_nodes
    assert '((event_name="subagent_start") or (event_name="session_start"' in agent_nodes
    assert "Canonical 24-hour session_start or subagent_start identity" in agent_nodes
    assert "and on (id)" in agent_nodes
    assert "unless on (id)" in agent_nodes
    assert agent_nodes.count("topk by (id) (1,") == 2
    assert agent_nodes.count("[24h]") == 2
    # Grouped work nodes aggregate by their semantic ID and stable work labels,
    # not historical owner title/type/depth metadata. The canonical agent node
    # carries that identity detail; retaining it in this aggregation can split
    # one Bash family into duplicate visual nodes after lineage repair.
    tool_nodes = targets_by_ref["nodesToolSummary"]
    tool_grouping = tool_nodes.split(") (count_over_time(", maxsplit=1)[0]
    for unstable_owner_label in (
        "detail__agent_name",
        "detail__agent_type",
        "detail__agent_depth",
        "detail__parent_agent_id",
    ):
        assert unstable_owner_label not in tool_grouping
    assert "detail__agent_id" in tool_grouping
    assert "detail__root_agent_id" in tool_grouping
    assert "initial_prompt" not in node_query
    for query in prompt_queries:
        assert 'defenseclaw_event_name=~`hook_decision|model.request`' in query
        assert '(event_name="hook_decision" and source="connector"' in query
        assert 'body_defenseclaw_hook_event=~"(?i)^(' in query
        assert '(connector!="codex" and event_name="model.request")' in query
        assert 'body_defenseclaw_agent_depth="0"' in query
        assert query.startswith("max by (")
        assert query.count("count by") == 2
        assert "prompt_observation" in query
        assert "prompt_key" in query
        assert query.index(".body_defenseclaw_turn_id") < query.index(".body_defenseclaw_model_request_id")
        assert query.index(".body_defenseclaw_model_request_id") < query.index(".body_defenseclaw_request_id")
        assert query.index(".body_defenseclaw_request_id") < query.index(".body_defenseclaw_operation_id")
        assert query.index(".body_defenseclaw_operation_id") < query.index(".record_id")
        assert "detail__event_name=`prompt submission`" in query
        assert "detail__hook_event" not in query
    assert "id=`edge:prompts:{{.body_gen_ai_agent_id}}`" in edge_query
    assert "source=`prompts:{{.body_gen_ai_agent_id}}`" in edge_query
    assert "detail__edge_kind=`prompt_submissions_to_root`" in edge_query
    assert "id=`prompts:{{.body_gen_ai_agent_id}}`" in node_query
    assert "title=`Prompt inputs`" in node_query
    assert "detail__node_type=`prompt_summary`" in node_query

    for ref_id in ("edgesModelSummary", "nodesModelSummary"):
        query = targets_by_ref[ref_id]
        assert query.startswith("max by (")
        assert "sum by (" in query
        assert "observation_source" in query
        assert "label_format observation_source=" in query
        assert "Source-deduplicated model requests" in query
        assert "largest source total" in query

    # Request records remain visible without a terminal counterpart. Totals are
    # request counts and do not claim the work is still pending.
    for query in (edge_query, node_query):
        assert 'event_name="model.request"' in query
        assert 'event_name="tool.invocation.requested"' in query
        assert 'event_name="approval.requested"' in query

    # Real collaboration messages group by sender + exact reported task. Only
    # /root and /root/* collapse per sender; arbitrary non-root task paths stay
    # exact and never create a fabricated agent-to-agent edge.
    for query in (edge_query, node_query):
        assert "collaboration[._]*send[._]*message" in query
        assert "body_gen_ai_tool_call_arguments_target" in query
        assert 'eq .body_gen_ai_tool_call_arguments_target "/root"' in query
        assert 'hasPrefix "/root/" .body_gen_ai_tool_call_arguments_target' in query
        assert "message_target_group" in query
        assert "/root and /root/* (grouped)" in query
        assert "detail__target_task" in query
        assert "detail__target_agent_id" in query
    assert "detail__edge_kind=`agent_sends_message`" in edge_query
    assert "target=`message:{{.body_gen_ai_agent_id}}:{{.message_target_group}}`" in edge_query
    for ref_id in ("edgesToolSummary", "nodesToolSummary"):
        assert (
            'body_gen_ai_tool_name!~"(?i)collaboration[._]*send[._]*message"'
            in targets_by_ref[ref_id]
        )
    assert "Messages to root" in node_query
    assert "exact root task paths" in topology["description"].lower()

    # Root turn completion is visible even while its long-lived session remains
    # active; nonexistent session_failed/subagent_failed names are forbidden.
    for query in (edge_query, node_query):
        assert "session_end|subagent_stop|turn_end" in query
        assert "session_failed" not in query
        assert "subagent_failed" not in query
        assert "Turn outcomes" in query or "turn_end" in query


def test_agent360_has_continuous_phase_timeline_and_directed_flow() -> None:
    dashboard = _dashboard(AGENT360)
    timeline = _panel_by_title(dashboard, "Execution phase timeline")
    assert timeline["datasource"]["uid"] == "defenseclaw-loki"
    assert "last_over_time" in timeline["targets"][0]["expr"]
    assert "unwrap body_defenseclaw_agent_phase_code" in timeline["targets"][0]["expr"]
    mappings = timeline["fieldConfig"]["defaults"]["mappings"][0]["options"]
    assert mappings["2"]["text"] == "Planning"
    assert mappings["3"]["text"] == "Model"
    assert mappings["4"]["text"] == "Tool"
    assert mappings["9"]["text"] == "Completed"
    timeline_query = timeline["targets"][0]["expr"]
    assert 'body_defenseclaw_agent_lifecycle_id=~"$lifecycle"' in timeline_query
    assert 'body_defenseclaw_agent_execution_id=~"$execution"' in timeline_query

    sequence = _panel_by_title(
        dashboard, "Ordered lifecycle and work sequence — root to terminal"
    )
    assert sequence["options"]["sortOrder"] == "Ascending"
    sequence_query = sequence["targets"][0]["expr"]
    assert "| event_name=" not in sequence_query
    assert "every retained v8 event is included" in sequence["description"].lower()
    for field in (
        ".body_defenseclaw_agent_sequence",
        ".body_gen_ai_agent_id",
        ".body_gen_ai_agent_name",
        ".body_defenseclaw_agent_type",
        ".body_defenseclaw_agent_instance_id",
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
        ".body_defenseclaw_session_source",
        ".body_defenseclaw_session_resumed",
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
        ".body_gen_ai_tool_type",
        ".body_gen_ai_tool_call_id",
        ".body_defenseclaw_tool_provider",
        ".body_defenseclaw_tool_status",
        ".body_defenseclaw_tool_exit_code",
        ".body_defenseclaw_approval_id",
        ".body_defenseclaw_approval_result",
        ".body_defenseclaw_approval_actor_type",
        ".outcome",
        ".correlation_trace_id",
        ".correlation_span_id",
    ):
        assert field in sequence_query
    assert "trace_id={{.correlation_trace_id}}" in sequence_query
    assert "· trace={{.correlation_trace_id}}" not in sequence_query

    flow = _panel_by_title(dashboard, "Connector phase network")
    assert flow["type"] == "nodeGraph"
    edge_query = flow["targets"][0]["expr"]
    assert "defenseclaw_agent_phase_transitions_total" in edge_query
    assert "increase(defenseclaw_agent_phase_transitions_total" in edge_query
    assert "max_over_time(defenseclaw_agent_phase_transitions_total" not in edge_query
    assert "defenseclaw_agent_last_seen_seconds" not in edge_query
    transition_selector = edge_query.split(
        "defenseclaw_agent_phase_transitions_total", 1
    )[1].split("}", 1)[0]
    assert "defenseclaw_agent_lifecycle_id" not in transition_selector
    assert "defenseclaw_agent_lifecycle_id" not in edge_query
    assert "defenseclaw_agent_execution_id" not in edge_query
    for edge_field in ('"id"', '"source"', '"target"'):
        assert edge_field in edge_query
    assert "defenseclaw_agent_phase_from" in edge_query
    assert "defenseclaw_agent_phase_to" in edge_query

    directed_edges = _panel_by_title(
        dashboard, "Connector directed phase edges (source → target)"
    )
    directed_expr = directed_edges["targets"][0]["expr"]
    assert '"direction", " → "' in directed_expr
    assert "increase(defenseclaw_agent_phase_transitions_total" in directed_expr
    assert "max_over_time(defenseclaw_agent_phase_transitions_total" not in directed_expr
    assert "defenseclaw_agent_last_seen_seconds" not in directed_expr
    transition_selector = directed_expr.split(
        "defenseclaw_agent_phase_transitions_total", 1
    )[1].split("}", 1)[0]
    assert "defenseclaw_agent_lifecycle_id" not in transition_selector
    assert "defenseclaw_agent_lifecycle_id" not in directed_expr
    assert "defenseclaw_agent_execution_id" not in directed_expr
    rename = directed_edges["transformations"][1]["options"]["renameByName"]
    assert rename["defenseclaw_agent_phase_from"] == "From"
    assert rename["defenseclaw_agent_phase_to"] == "To"
    assert rename["direction"] == "Direction"

    for title in (
        "Connector average observed phase duration",
        "Connector slowest operation classes (p95)",
    ):
        assert _panel_by_title(dashboard, title)["datasource"]["uid"] == "defenseclaw-prometheus"


def test_agent360_presents_human_readable_usage_lifecycle_and_logs() -> None:
    dashboard = _dashboard(AGENT360)

    directory = _panel_by_title(dashboard, "Agent Directory — click an Agent ID to drill down")
    assert directory["datasource"]["uid"] == "defenseclaw-loki"
    assert directory["targets"][0]["expr"].startswith("sum by (")
    assert directory["options"]["sortBy"][0]["displayName"] == "Observations"
    assert not any(
        override["matcher"].get("options") == "Last Seen"
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

    observations = _panel_by_title(dashboard, "Observations in range")
    assert observations["datasource"]["uid"] == "defenseclaw-loki"
    assert observations["options"]["textMode"] == "value"
    assert observations["options"]["graphMode"] == "none"

    model_calls = _panel_by_title(dashboard, "Model calls")
    assert model_calls["datasource"]["uid"] == "defenseclaw-loki"
    assert 'event_name="model.response"' in model_calls["targets"][0]["expr"]
    for title in ("Input tokens", "Output tokens"):
        panel = _panel_by_title(dashboard, title)
        assert panel["options"]["colorMode"] == "none"
        assert panel["datasource"]["uid"] == "defenseclaw-loki"
        assert "logical_event_id" in panel["targets"][0]["expr"]

    executions = _panel_by_title(dashboard, "Executions and observations")
    assert executions["datasource"]["uid"] == "defenseclaw-loki"
    assert executions["targets"][0]["expr"].startswith("sum by (")
    assert "count_over_time" in executions["targets"][0]["expr"]
    assert not any(
        override["matcher"].get("options") == "Last Seen"
        for override in executions["fieldConfig"]["overrides"]
    )
    execution_override = next(
        override
        for override in executions["fieldConfig"]["overrides"]
        if override["matcher"].get("options") == "Execution"
    )
    execution_link = next(
        prop["value"][0]
        for prop in execution_override["properties"]
        if prop["id"] == "links"
    )
    assert "var-lifecycle=${__data.fields.Lifecycle}" in execution_link["url"]
    assert "var-execution=${__value.raw}" in execution_link["url"]
    assert "from=${__from}&to=${__to}" in execution_link["url"]

    for column in ("Agent ID", "Root Agent"):
        override = next(
            item
            for item in directory["fieldConfig"]["overrides"]
            if item["matcher"].get("options") == column
        )
        link = next(
            prop["value"][0]
            for prop in override["properties"]
            if prop["id"] == "links"
        )
        assert "from=${__from}&to=${__to}" in link["url"]

    for title in (
        "LLM turns — prompts, responses, model, usage",
        "Tools and website/network interactions",
        "Errors, blocks, approvals, and guardrail decisions",
    ):
        expr = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert "| json" in expr
        assert '| connector=~"$connector"' in expr
        assert "| line_format" in expr
        assert "printf" not in expr

    llm = _panel_by_title(
        dashboard, "LLM turns — prompts, responses, model, usage"
    )["targets"][0]["expr"]
    assert 'body_gen_ai_input_messages="body[\\"gen_ai.input.messages\\"]"' in llm
    assert 'body_gen_ai_output_messages="body[\\"gen_ai.output.messages\\"]"' in llm
    assert ".body_gen_ai_output_messages" in llm
    tools = _panel_by_title(
        dashboard, "Tools and website/network interactions"
    )["targets"][0]["expr"]
    assert ".body_gen_ai_tool_call_arguments" in tools
    assert ".body_gen_ai_tool_call_result" in tools

    raw_events = _panel_by_title(dashboard, "Raw correlated event stream")
    raw_expr = raw_events["targets"][0]["expr"]
    assert "| json" in raw_expr
    assert '| connector=~"$connector"' in raw_expr
    assert "| line_format" not in raw_expr
    assert "| label_format" not in raw_expr
    assert "unformatted canonical otel json" in raw_events["description"].lower()
    assert "dashboard applies no additional hiding or field projection" in raw_events[
        "description"
    ].lower()
    assert "central redaction boundary" in raw_events["description"].lower()


def test_agent360_uses_canonical_v8_log_families() -> None:
    dashboard = _dashboard(AGENT360)
    decisions = _panel_by_title(
        dashboard, "Errors, blocks, approvals, and guardrail decisions"
    )["targets"][0]["expr"]
    assert 'event_name=~"approval[.](requested|resolved)|hook_decision|guardrail[.]' in decisions
    assert "approval[.](requested|resolved)" in decisions
    assert ".body_defenseclaw_approval_id" in decisions
    assert ".body_defenseclaw_approval_result" in decisions
    assert "finding[.](observed|correlated)" in decisions
    assert ".body_defenseclaw_guardrail_enforced" in decisions
    assert ".body_defenseclaw_guardrail_would_block" in decisions
    assert "defenseclaw_gateway_event_type" not in decisions

    network = _panel_by_title(
        dashboard, "Tools and website/network interactions"
    )["targets"][0]["expr"]
    assert 'event_name=~"tool[.]invocation[.]' in network
    assert "egress[.](requested|allowed|blocked|completed|failed)" in network
    assert ".body_defenseclaw_network_target_ref" in network


def test_agent360_agent_scoped_loki_queries_prefilter_before_json_parsing() -> None:
    dashboard = _dashboard(AGENT360)
    checked: list[str] = []

    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            expression = target.get("expr", "")
            datasource = target.get("datasource", panel.get("datasource", {})).get("type")
            if datasource != "loki" or 'body_$scope_label=~"$agent"' not in expression:
                continue
            checked.append(panel["title"])
            assert '|= "$agent" | json' in expression, panel["title"]

    assert checked


def test_agent360_topology_groups_model_and_normalized_tool_families_per_agent() -> None:
    dashboard = _dashboard(AGENT360)
    topology = _panel_by_title(
        dashboard,
        "Lifecycle DAG — prompt → agents → work → outcomes",
    )
    expressions = {
        target["refId"]: target["expr"] for target in topology["targets"]
    }

    for expression in expressions.values():
        assert "defenseclaw_agent_span_calls_total" not in expression
        assert "body_gen_ai_tool_call_id" not in expression
        assert "defenseclaw_event_name=" in expression

    edges = " or ".join(
        expression
        for ref_id, expression in expressions.items()
        if ref_id.startswith("edges")
    )
    nodes = " or ".join(
        expression
        for ref_id, expression in expressions.items()
        if ref_id.startswith("nodes")
    )
    for expression in (edges, nodes):
        assert 'event_name="model.request"' in expression
        assert 'event_name="tool.invocation.requested"' in expression
        assert "{{if .body_gen_ai_response_model}}" in expression
        assert "{{else}}{{.body_gen_ai_request_model}}{{end}}" in expression
        assert "{{.body_gen_ai_provider_name}}" in expression
        assert "tool_family=`{{if contains" in expression
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

    assert "detail__edge_kind=`agent_model_summary`" in edges
    assert "detail__edge_kind=`agent_tool_summary`" in edges
    assert "id=`edge:tool:{{.body_gen_ai_agent_id}}:{{.tool_family}}`" in edges
    assert "source=`agent:{{.body_gen_ai_agent_id}}`" in edges
    assert "target=`tool:{{.body_gen_ai_agent_id}}:{{.tool_family}}`" in edges
    assert "detail__node_type=`model_summary`" in nodes
    assert "detail__node_type=`tool_summary`" in nodes
    assert "id=`tool:{{.body_gen_ai_agent_id}}:{{.tool_family}}`" in nodes
    assert "detail__count_meaning" in edges
    assert "detail__count_meaning" in nodes


def test_agent360_enables_layered_node_graph_layout() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    assert "GF_FEATURE_TOGGLES_ENABLE=traceqlEditor,nodeGraphDotLayout" in compose


def test_agent360_correlates_hook_decisions_to_recovery_paths() -> None:
    dashboard = _dashboard(AGENT360)

    for title, field in (
        ("Enforced hook blocks", "body_defenseclaw_guardrail_enforced"),
        ("Observe-mode would-blocks", "body_defenseclaw_guardrail_would_block"),
    ):
        panel = _panel_by_title(dashboard, title)
        assert panel["datasource"]["uid"] == "defenseclaw-loki"
        expr = panel["targets"][0]["expr"]
        assert 'event_name="hook_decision"' in expr
        assert field in expr
        assert "body_defenseclaw_agent_lifecycle_id=~\"$lifecycle\"" in expr
        assert "body_defenseclaw_agent_execution_id=~\"$execution\"" in expr

    outcomes = _panel_by_title(dashboard, "Hook action outcomes over time")
    assert outcomes["type"] == "timeseries"
    assert {target["legendFormat"] for target in outcomes["targets"]} == {
        "enforced block",
        "would block",
        "alert or confirmation decision",
        "approval {{approval_result}}",
    }
    approval_target = next(
        target
        for target in outcomes["targets"]
        if target["legendFormat"] == "approval {{approval_result}}"
    )
    assert 'event_name="approval.resolved"' in approval_target["expr"]
    assert "body_defenseclaw_approval_result" in approval_target["expr"]

    recovery = _panel_by_title(dashboard, "Decision → recovery path")
    assert recovery["options"]["sortOrder"] == "Ascending"
    expr = recovery["targets"][0]["expr"]
    for event_type in (
        "hook_decision",
        "tool[.]invocation",
        "model[.]",
        "turn_(start|end)",
        "approval[.](requested|resolved)",
    ):
        assert event_type in expr
    for field in (
        ".body_defenseclaw_hook_event",
        ".body_defenseclaw_guardrail_effective_action",
        ".body_defenseclaw_guardrail_enforced",
        ".body_defenseclaw_guardrail_would_block",
        ".body_defenseclaw_approval_id",
        ".body_defenseclaw_approval_result",
        ".correlation_trace_id",
    ):
        assert field in expr


def test_agent360_exposes_model_tool_cost_and_reliability_analytics() -> None:
    dashboard = _dashboard(AGENT360)
    expected = {
        "Model calls by provider and model": ("count_over_time", "provider", "model"),
        "Connector-wide model p95 (selected range)": ("histogram_quantile", "gen_ai_request_model"),
        "Top tools by calls": ("count_over_time", "tool_name"),
        "Connector-wide tool p95 (selected range)": ("gen_ai_tool_name", "histogram_quantile"),
        "Top websites and destinations": ("count_over_time", "destination"),
        "Reported tokens by model": ("body_gen_ai_usage_input_tokens", "logical_event_id"),
        "Reported cost over time": ("body_defenseclaw_agent_reported_cost_usd",),
        "Reported cost by model": ("body_defenseclaw_agent_reported_cost_usd", "model"),
        "Lifecycle event totals": ("count_over_time", "agent_lifecycle_event"),
        "Connector span error rate": ('status_code="STATUS_CODE_ERROR"',),
        "Connector span latency heatmap": ("_bucket", "sum by (le)"),
        "Active agents over time": ("gen_ai_agent_id", "count_over_time"),
    }
    for title, fragments in expected.items():
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert all(fragment in expression for fragment in fragments), title
    for title in ("Reported cost", "Reported cost over time", "Reported cost by model"):
        panel = _panel_by_title(dashboard, title)
        assert panel["fieldConfig"]["defaults"]["noValue"] == "Not reported"
        assert "infer" in panel["description"].lower()
    assert "time() - 300" not in _panel_by_title(
        dashboard, "Active agents over time"
    )["targets"][0]["expr"]
    assert "sum by (connector, gen_ai_agent_id)" in _panel_by_title(
        dashboard, "Active agents over time"
    )["targets"][0]["expr"]

    topology = _panel_by_title(
        dashboard, "Lifecycle DAG — prompt → agents → work → outcomes"
    )
    assert "directed acyclic" in topology["description"].lower()

    for title in (
        "Connector average observed phase duration",
        "Connector slowest operation classes (p95)",
        "Connector phase network",
        "Connector directed phase edges (source → target)",
    ):
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert "defenseclaw_agent_lifecycle_id" not in expression
        assert "defenseclaw_agent_execution_id" not in expression

    assert _panel_by_title(dashboard, "Descendants in selected root tree")

    for title in (
        "Connector-wide model p95 (selected range)",
        "Connector-wide tool p95 (selected range)",
    ):
        expression = _panel_by_title(dashboard, title)["targets"][0]["expr"]
        assert "increase(defenseclaw_agent_span_duration_milliseconds_bucket" in expression
        assert "defenseclaw_agent_last_seen_seconds" not in expression


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
    assert "defenseclaw.agent.phase" in config
    assert "defenseclaw.agent.phase.code" in config
    assert "- name: connector" in config
    assert "gen_ai.tool.name" in config
    for forbidden_dimension in (
        "gen_ai.agent.id",
        "gen_ai.agent.name",
        "defenseclaw.agent.root.id",
        "defenseclaw.agent.parent.id",
        "defenseclaw.agent.lifecycle.id",
        "defenseclaw.agent.execution.id",
    ):
        assert f"- name: {forbidden_dimension}" not in config
    assert "filter/agent360-canary:" in config
    assert 'span.attributes["defenseclaw.telemetry.canary"] == true' in config
    assert "exporters: [otlp/tempo, forward/agent360, debug]" in config
    assert "receivers: [forward/agent360]" in config
    assert "exporters: [spanmetrics/agent360]" in config
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
