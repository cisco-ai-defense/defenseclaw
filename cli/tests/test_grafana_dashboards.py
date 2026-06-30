"""Durable contract checks for the bundled Grafana dashboard catalog."""

from __future__ import annotations

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

    def fake_request(url: str, params: dict[str, str] | None = None) -> dict[str, object]:
        assert params is not None
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

    def fake_request(_url: str, params: dict[str, str] | None = None) -> dict[str, object]:
        assert params is not None
        assert params["q"] == (
            '{ resource.service.name = "defenseclaw" '
            '&& name = "defenseclaw.ai.discovery" }'
        )
        call_order.append("search")
        return {"traces": [{"traceID": "1"}]}

    monkeypatch.setattr(audit, "tempo_readiness_error", fake_readiness)
    monkeypatch.setattr(audit, "request_json", fake_request)

    inventory, errors = audit.live_inventory([(Path("fixture.json"), dashboard)])

    assert errors == []
    assert call_order == ["ready", "search"]
    assert inventory[0]["panels"][0]["status"] == "data"


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

    assert positive == (
        '{ (resource.service.name = "gateway" || resource.service.name = "worker") }'
    )
    assert negative == '{ (name != "health" && name != "ready") }'


@pytest.mark.parametrize("query", [{}, [], "   "])
def test_tempo_target_query_rejects_invalid_raw_queries(query: object) -> None:
    audit = _load_audit_module()

    with pytest.raises(audit.AuditError):
        audit.tempo_target_query({"query": query})


def test_prometheus_rate_interval_matches_default_otel_push_cadence() -> None:
    audit = _load_audit_module()

    assert (
        audit.prometheus_time_interval_seconds(audit.SOURCE_DATASOURCES)
        >= audit.DEFAULT_METRIC_EXPORT_INTERVAL_SECONDS
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
                        "expr": "sum by (action) (rate(example_total{severity=\"HIGH\"}[5m]))",
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
                        "expr": (
                            "histogram_quantile(0.95, "
                            "sum by (le) (rate(example_bucket[5m])))"
                        ),
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
                        "expr": (
                            "rate(defenseclaw_connector_hook_outcome_total"
                            '{connector="codex", result="ok"}[5m])'
                        ),
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
                        "expr": (
                            "rate(defenseclaw_connector_hook_latency_milliseconds_bucket"
                            '{le="2500.0"}[5m])'
                        ),
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
            "gen_ai_client_token_usage_sum",
            "sum by (gen_ai_agent_name, gen_ai_token_type)",
        ),
        "LLM operation duration p95 by connector": (
            "gen_ai_client_operation_duration_seconds_bucket",
            "sum by (le, gen_ai_agent_name)",
        ),
        "Evaluations / sec by hook event": (
            "defenseclaw_inspect_evaluations_total",
            "sum by (hook_event)",
            "label_replace",
        ),
        "Codex notify by type + status (5m)": ("defenseclaw_codex_notify_total",),
        "Quietest connectors (silence sec)": (
            "defenseclaw_otel_ingest_last_seen_ts_seconds",
        ),
        "Hook latency p95 by event type": (
            "defenseclaw_connector_hook_latency_milliseconds_bucket",
            "sum by (le, event_type)",
        ),
    }
    for title, fragments in expected_fragments.items():
        expression = _panel(dashboard, title)["targets"][0]["expr"]
        assert all(fragment in expression for fragment in fragments), title


def test_identity_dashboard_queries_identity_and_discovery_instruments() -> None:
    dashboard = _dashboard("defenseclaw-agent-identity.json")
    expected_metrics = {
        "Discovery runs (range)": "defenseclaw_agent_discovery_runs_total",
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
        "defenseclaw_agent_discovery_duration_milliseconds_bucket" in target["expr"]
        for target in duration_targets
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
        assert "defenseclaw_inspect_evaluations_total" in _panel(dashboard, title)["targets"][0][
            "expr"
        ]


def test_hitl_dashboard_uses_dedicated_chat_and_exec_approval_metrics() -> None:
    dashboard = _dashboard("defenseclaw-hitl.json")

    chat_status = _panel(dashboard, "Chat HILT status mix over time")["targets"][0]["expr"]
    chat_ratio = _panel(dashboard, "Chat HILT approval-vs-denial rate (1h rolling)")[
        "targets"
    ][0]["expr"]
    assert "defenseclaw_guardrail_evaluations_total" in chat_status
    assert "guardrail_scanner=\"openclaw:hilt\"" in chat_status
    assert "guardrail_action_taken" in chat_status
    assert "defenseclaw_guardrail_evaluations_total" in chat_ratio

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
    assert "llm_response" in llm_stream
    assert "scan_finding" not in llm_stream
    overview_active = _panel(overview, "Active connectors (5m)")["targets"][0]["expr"]
    assert "sum by (connector) (label_replace" in overview_active

    connectors = _dashboard("defenseclaw-connectors.json")
    connector_active = _panel(connectors, "Active connectors (5m)")["targets"][0]["expr"]
    assert "sum by (connector) (label_replace" in connector_active

    detail = _dashboard("defenseclaw-connector-detail.json")
    would_block = _panel(detail, "Would-block / min (observe shadow blocks)")["targets"][0][
        "expr"
    ]
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
    assert "max_over_time((timestamp(increase(" in _panel(
        findings,
        "Last-seen per rule_id (24h)",
    )["targets"][0]["expr"]
    assert "min_over_time((timestamp(increase(" in _panel(
        findings,
        "First-seen per rule_id (24h)",
    )["targets"][0]["expr"]
    verdict_panel = _panel(findings, "Verdicts in selected connector/severity window")
    assert verdict_panel["transformations"][0]["options"]["renameByName"]["Value"] == (
        "verdicts/range"
    )
