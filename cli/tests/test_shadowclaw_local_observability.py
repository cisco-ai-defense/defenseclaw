"""Contracts for the bundled ShadowClaw local-observability integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import check_shadowclaw_otel_integration as integration
from scripts import local_observability_v1 as compat

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "bundles/local_observability_stack"
DASHBOARD_PATH = BUNDLE / "grafana/dashboards/shadowclaw-shadow-ai.json"


def _dashboards() -> list[tuple[Path, dict]]:
    dashboard_dir = BUNDLE / "grafana/dashboards"
    return [(path, json.loads(path.read_text(encoding="utf-8"))) for path in sorted(dashboard_dir.glob("*.json"))]


def _panels(value: dict):
    for panel in value.get("panels", []):
        yield panel
        yield from _panels(panel)


def _resource_values(collector: dict, supplied: dict[str, str]) -> dict[str, str]:
    result = dict(supplied)
    for item in collector["processors"]["resource"]["attributes"]:
        assert item["action"] == "insert"
        if item["key"] in result:
            continue
        source = item.get("from_attribute")
        if source is not None:
            if source in result:
                result[item["key"]] = result[source]
            continue
        result[item["key"]] = item["value"]
    return result


def test_shadowclaw_dashboard_is_attributed_and_redistributable() -> None:
    dashboard = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))
    license_text = (BUNDLE / "SHADOWCLAW_LICENSE.md").read_text(encoding="utf-8")
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

    assert dashboard["__comment_product"] == "ShadowClaw -- Universal Shadow AI Detector"
    assert "Mike Storm" in dashboard["__comment_author"]
    assert "SHADOWCLAW_LICENSE.md" in dashboard["__comment_attribution"]
    assert "BSD 3-Clause License with Attribution Requirement" in license_text
    assert "Copyright (c) 2026 Mike Storm" in license_text
    assert "SHADOWCLAW_LICENSE.md" in notice


def test_shadowclaw_dashboard_uses_the_provisioned_loki_datasource() -> None:
    dashboard = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))
    serialized = json.dumps(dashboard)
    targets = [target for panel in _panels(dashboard) for target in panel.get("targets", [])]

    assert len(targets) >= 40
    assert "${DS_LOKI}" not in serialized
    assert all(target.get("datasource") == {"type": "loki", "uid": "defenseclaw-loki"} for target in targets)

    finding_queries = [
        target["expr"]
        for target in targets
        if 'service_name="shadowclaw"' in target.get("expr", "") and integration.EVENT_NAME in target.get("expr", "")
    ]
    assert len(finding_queries) >= 10
    for query in finding_queries:
        assert query.index("shadowclaw_event_name") < query.index("| json")
        assert '__error__=""' in query


def test_external_dashboard_does_not_expand_the_native_v8_query_contract() -> None:
    dashboards = _dashboards()
    native = compat.defenseclaw_dashboards(dashboards)
    native_uids = {dashboard["uid"] for _, dashboard in native}

    assert native_uids == compat.NATIVE_DASHBOARD_UIDS
    assert compat.EXTERNAL_DASHBOARD_UIDS == {"shadowclaw-shadow-ai"}
    assert compat.EXTERNAL_DASHBOARD_UIDS.isdisjoint(native_uids)

    expected = compat.build_inventory(native)
    actual, errors = compat.compatibility_errors(dashboards, require_packaged=False)
    assert errors == []
    assert actual == expected

    without_shadowclaw = [item for item in dashboards if item[1].get("uid") != "shadowclaw-shadow-ai"]
    _inventory, errors = compat.compatibility_errors(
        without_shadowclaw,
        require_packaged=False,
    )
    assert any("shadowclaw-shadow-ai" in error and "missing" in error for error in errors)


def test_collector_preserves_shadowclaw_service_identity() -> None:
    paths = [
        BUNDLE / "otel-collector/config.yaml",
        compat.PACKAGED / "otel-collector/config.yaml",
    ]
    for path in paths:
        collector = yaml.safe_load(path.read_text(encoding="utf-8"))
        shadowclaw = _resource_values(
            collector,
            {
                "service.name": "shadowclaw",
                "service.namespace": "shadowclaw",
            },
        )
        assert shadowclaw["service.name"] == "shadowclaw"
        assert shadowclaw["service.namespace"] == "shadowclaw"

        defenseclaw = _resource_values(collector, {"service.name": "defenseclaw"})
        assert defenseclaw["service.namespace"] == "defenseclaw"


def test_synthetic_payload_matches_the_shadowclaw_otlp_shape() -> None:
    payload = integration.build_payload("marker-123", timestamp_ns=123456789)
    resource_log = payload["resourceLogs"][0]
    resources = {item["key"]: next(iter(item["value"].values())) for item in resource_log["resource"]["attributes"]}
    record = resource_log["scopeLogs"][0]["logRecords"][0]
    attributes = {item["key"]: next(iter(item["value"].values())) for item in record["attributes"]}
    body = json.loads(record["body"]["stringValue"])

    assert resources["service.name"] == "shadowclaw"
    assert resources["service.namespace"] == "shadowclaw"
    assert resources["shadowclaw.author"] == "Mike Storm"
    assert resources["shadowclaw.attribution.intact"] is True
    assert attributes["shadowclaw.event_name"] == integration.EVENT_NAME
    assert attributes["process.pid"] == "4242"
    assert body["event_name"] == integration.EVENT_NAME
    assert body["integration_marker"] == "marker-123"
    assert body["synthetic"] is True


def test_loki_verification_requires_namespace_metadata_and_marker() -> None:
    marker = "marker-123"
    query = integration.loki_query(marker)
    assert 'service_namespace="shadowclaw"' in query
    assert 'service_name="shadowclaw"' in query
    assert f'shadowclaw_event_name="{integration.EVENT_NAME}"' in query

    record = {
        "event_name": integration.EVENT_NAME,
        "integration_marker": marker,
        "synthetic": True,
    }
    streams = [
        {
            "stream": {
                "service_namespace": "shadowclaw",
                "service_name": "shadowclaw",
            },
            "values": [["123", json.dumps(record)]],
        },
    ]
    assert integration.matching_record(streams, marker) == record

    streams[0]["stream"]["service_namespace"] = "defenseclaw"
    assert integration.matching_record(streams, marker) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:4318",
        "ftp://127.0.0.1:4318",
    ],
)
def test_integration_check_refuses_nonlocal_or_unsupported_urls(url: str) -> None:
    with pytest.raises(integration.IntegrationError):
        integration.otlp_logs_url(url)
