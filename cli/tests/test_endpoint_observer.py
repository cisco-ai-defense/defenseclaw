from __future__ import annotations

import json

import pytest
from defenseclaw import endpoint_observer as observer


def test_parse_ps_line_preserves_process_identity_and_usage() -> None:
    process = observer._parse_ps_line(
        "4242 41 alice 2048 12.5 Tue Sep  3 10:11:12 2026 /Applications/Agent.app/Contents/MacOS/agent"
    )

    assert process is not None
    assert process.pid == 4242
    assert process.ppid == 41
    assert process.user == "alice"
    assert process.rss_kb == 2048
    assert process.cpu_percent == 12.5
    assert process.start_time == "Tue Sep 3 10:11:12 2026"
    assert process.executable.endswith("/agent")


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://127.0.0.1:4318",
        "http://example.com:4318",
        "http://127.0.0.1:4318/v1/logs",
    ],
)
def test_exporter_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError):
        observer.OtlpExporter(endpoint)


class _FakeExporter:
    successes = 3
    failures = 1
    last_error = "collector unavailable"

    def __init__(self) -> None:
        self.log_records: list[dict] = []
        self.metric_records: list[dict] = []

    def logs(self, records: list[dict]) -> bool:
        self.log_records.extend(records)
        return True

    def metrics(self, metrics: list[dict]) -> bool:
        self.metric_records.extend(metrics)
        return True


def test_observe_once_reports_partial_coverage_and_resource_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    processes = [
        observer.ProcessObservation(1, 0, "root", 100, 2.0, "start-1", "/bin/one"),
        observer.ProcessObservation(2, 1, "root", 200, 1.0, "start-2", "/bin/two"),
        observer.ProcessObservation(3, 1, "root", 300, 0.5, "start-3", "/bin/three"),
    ]
    monkeypatch.setattr(observer, "sample_processes", lambda: (processes, ""))
    monkeypatch.setattr(observer, "_resource_metrics", lambda: (1.25, 4096.0))
    exporter = _FakeExporter()

    status = observer.observe_once(exporter, report_limit=2)

    assert status["processes_observed"] == 3
    assert status["processes_reported"] == 2
    assert status["coverage"] == pytest.approx(2 / 3, abs=0.0001)
    assert status["coverage_status"] == "partial"
    assert len(exporter.log_records) == 3
    assert len(exporter.metric_records) == 8

    bodies = [json.loads(item["body"]["stringValue"]) for item in exporter.log_records]
    assert bodies[0]["event_name"] == observer.EVENT_STATUS
    assert all(body["observation_only"] for body in bodies)
    assert bodies[1]["process"]["start_time"] == "start-1"
    assert bodies[1]["process"]["executable_identity"] == "/bin/one"
    assert all(
        item["attributes"][0]["key"] == "shadowclaw.event_name"
        for item in exporter.log_records
    )
    resource = observer._resource_attributes()
    assert resource["service.name"] == observer.SERVICE_NAME
    assert resource["service.namespace"] == observer.SERVICE_NAMESPACE
    assert resource["shadowclaw.mode"] == "observation-only"
