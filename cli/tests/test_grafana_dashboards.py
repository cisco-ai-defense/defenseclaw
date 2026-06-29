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


def _load_audit_module() -> ModuleType:
    path = ROOT / "scripts/check_grafana_dashboards.py"
    spec = importlib.util.spec_from_file_location("check_grafana_dashboards", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        ],
    }
    (tmp_path / "fixture.json").write_text(json.dumps(dashboard), encoding="utf-8")
    monkeypatch.setattr(audit, "SOURCE_DIR", tmp_path)
    monkeypatch.setattr(audit, "PACKAGED_DIR", tmp_path / "missing")

    _dashboards, errors = audit.static_audit()

    assert any("prometheus must use 'defenseclaw-prometheus'" in error for error in errors)
    assert any("range-aggregate stat targets must be instant" in error for error in errors)
    assert any("grouped zero fallbacks must use `or on() vector(0)`" in error for error in errors)


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
        "error": 0,
    }
    assert {panel["title"]: panel["status"] for panel in inventory[0]["panels"]} == {
        "Has data": "data",
        "Healthy zero": "zero",
        "No matching event": "empty",
        "Selected waterfall": "interactive",
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
                "targets": [{"query": '{ resource.service.name = "defenseclaw" }'}],
            },
        ],
    }

    def fake_readiness() -> None:
        call_order.append("ready")
        return None

    def fake_request(_url: str, _params: dict[str, str] | None = None) -> dict[str, object]:
        call_order.append("search")
        return {"traces": [{"traceID": "1"}]}

    monkeypatch.setattr(audit, "tempo_readiness_error", fake_readiness)
    monkeypatch.setattr(audit, "request_json", fake_request)

    inventory, errors = audit.live_inventory([(Path("fixture.json"), dashboard)])

    assert errors == []
    assert call_order == ["ready", "search"]
    assert inventory[0]["panels"][0]["status"] == "data"
