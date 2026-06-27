"""Contract tests for the dynamic Agent Directory -> Agent360 experience."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARDS = ROOT / "bundles" / "local_observability_stack" / "grafana" / "dashboards"
AGENT360 = DASHBOARDS / "defenseclaw-agent-360.json"
IDENTITY = DASHBOARDS / "defenseclaw-agent-identity.json"
COLLECTOR = ROOT / "bundles" / "local_observability_stack" / "otel-collector" / "config.yaml"
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
    # Both local metric transports can coexist during upgrades. Aggregates
    # collapse transport-only label copies so values are never double-counted.
    assert serialized.count("max without (job, instance, service, exported_job)") >= 8


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


def test_loki_json_trace_ids_link_to_tempo() -> None:
    config = DATASOURCES.read_text(encoding="utf-8")
    assert '"trace_id"\\s*:\\s*"' in config
    assert "datasourceUid: defenseclaw-tempo" in config
