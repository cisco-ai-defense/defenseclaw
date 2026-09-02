#!/usr/bin/env python3
"""Verify ShadowClaw log ingestion through the local observability stack."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

DEFAULT_OTLP_ENDPOINT = "http://127.0.0.1:4318"
DEFAULT_LOKI_URL = "http://127.0.0.1:3100"
EVENT_NAME = "shadowclaw.finding.recorded"


class IntegrationError(RuntimeError):
    pass


def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def _attributes(values: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": _any_value(value)} for key, value in values.items()]


def build_payload(marker: str, *, timestamp_ns: int | None = None) -> dict[str, Any]:
    stamp = str(timestamp_ns if timestamp_ns is not None else time.time_ns())
    body = {
        "event_name": EVENT_NAME,
        "summary": "Synthetic Phase 1 integration finding",
        "finding_id": marker,
        "risk_score": 72,
        "severity": "high",
        "process_name": "defenseclaw-phase1-test",
        "pid": 4242,
        "user": "integration-test",
        "exe_path": "/usr/bin/false",
        "provider": "openai",
        "provider_name": "OpenAI",
        "endpoint": "api.openai.com",
        "category": "catalog",
        "attribution_source": "synthetic",
        "confidence": 1.0,
        "sanctioned": False,
        "providers": "openai",
        "endpoints": "api.openai.com",
        "signals": "agent_kill_chain,network_egress",
        "cpu_percent": 80.0,
        "rss_mb": 512.0,
        "egress_count": 1,
        "integration_marker": marker,
        "synthetic": True,
    }
    record_attributes = {
        "shadowclaw.finding_id": marker,
        "shadowclaw.risk_score": 72,
        "shadowclaw.severity": "high",
        "shadowclaw.event_name": EVENT_NAME,
        "shadowclaw.integration.synthetic": True,
        "process.pid": 4242,
        "process.executable.name": "defenseclaw-phase1-test",
        "process.executable.path": "/usr/bin/false",
    }
    resource_attributes = {
        "service.name": "shadowclaw",
        "service.namespace": "shadowclaw",
        "service.version": "phase1-test",
        "deployment.environment.name": "local-test",
        "host.name": "defenseclaw-phase1-test",
        "os.type": "synthetic",
        "shadowclaw.product": "ShadowClaw",
        "shadowclaw.author": "Mike Storm",
        "shadowclaw.author.title": "Distinguished Engineer",
        "shadowclaw.author.credential": "CCIE Security 13847",
        "shadowclaw.author.attribution": ("Mike Storm, Distinguished Engineer, CCIE Security 13847"),
        "shadowclaw.copyright": "Copyright (c) 2026 Mike Storm. All rights reserved.",
        "shadowclaw.attribution.intact": True,
    }
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": _attributes(resource_attributes)},
                "scopeLogs": [
                    {
                        "scope": {"name": "shadowclaw", "version": "phase1-test"},
                        "logRecords": [
                            {
                                "timeUnixNano": stamp,
                                "observedTimeUnixNano": stamp,
                                "severityNumber": 17,
                                "severityText": "HIGH",
                                "body": {
                                    "stringValue": json.dumps(body, separators=(",", ":")),
                                },
                                "attributes": _attributes(record_attributes),
                            },
                        ],
                    },
                ],
            },
        ],
    }


def _loopback_url(value: str, *, name: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise IntegrationError(f"{name} must use http or https")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise IntegrationError(f"{name} must use a loopback host")
    return value.rstrip("/")


def otlp_logs_url(endpoint: str) -> str:
    base = _loopback_url(endpoint, name="OTLP endpoint")
    if base.endswith("/v1/logs"):
        return base
    return f"{base}/v1/logs"


def post_payload(endpoint: str, payload: dict[str, Any], *, timeout_seconds: float) -> None:
    request = urllib.request.Request(
        otlp_logs_url(endpoint),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if response.status < 200 or response.status >= 300:
                raise IntegrationError(f"Collector returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise IntegrationError(f"Collector returned HTTP {exc.code}: {body[:300]}") from exc
    except OSError as exc:
        raise IntegrationError(f"Collector request failed: {exc}") from exc


def loki_query(marker: str) -> str:
    encoded_marker = json.dumps(marker)
    return (
        '{service_namespace="shadowclaw", service_name="shadowclaw"} '
        f'| shadowclaw_event_name="{EVENT_NAME}" |= {encoded_marker}'
    )


def _query_loki(loki_url: str, marker: str, *, timeout_seconds: float) -> list[dict[str, Any]]:
    now_ns = time.time_ns()
    params = urllib.parse.urlencode(
        {
            "query": loki_query(marker),
            "start": str(now_ns - 120_000_000_000),
            "end": str(now_ns + 1_000_000_000),
            "direction": "backward",
            "limit": "20",
        },
    )
    url = f"{_loopback_url(loki_url, name='Loki URL')}/loki/api/v1/query_range?{params}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise IntegrationError(f"Loki returned HTTP {exc.code}: {body[:300]}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"Loki query failed: {exc}") from exc
    if result.get("status") != "success":
        raise IntegrationError(f"Loki query failed: {result}")
    return result.get("data", {}).get("result", [])


def matching_record(streams: list[dict[str, Any]], marker: str) -> dict[str, Any] | None:
    for stream in streams:
        labels = stream.get("stream", {})
        if labels.get("service_namespace") != "shadowclaw":
            continue
        if labels.get("service_name") != "shadowclaw":
            continue
        for value in stream.get("values", []):
            if not isinstance(value, list) or len(value) < 2:
                continue
            try:
                body = json.loads(value[1])
            except (TypeError, json.JSONDecodeError):
                continue
            if body.get("integration_marker") != marker:
                continue
            if body.get("event_name") != EVENT_NAME or body.get("synthetic") is not True:
                continue
            return body
    return None


def wait_for_record(
    loki_url: str,
    marker: str,
    *,
    wait_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_seconds
    last_error: IntegrationError | None = None
    while True:
        try:
            if record := matching_record(
                _query_loki(loki_url, marker, timeout_seconds=timeout_seconds),
                marker,
            ):
                return record
            last_error = None
        except IntegrationError as exc:
            last_error = exc
        if time.monotonic() >= deadline:
            detail = f": {last_error}" if last_error is not None else ""
            raise IntegrationError(f"ShadowClaw record did not reach Loki within {wait_seconds:g}s{detail}")
        time.sleep(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--otlp-endpoint", default=DEFAULT_OTLP_ENDPOINT)
    parser.add_argument("--loki-url", default=DEFAULT_LOKI_URL)
    parser.add_argument("--wait-seconds", type=float, default=60)
    parser.add_argument("--request-timeout-seconds", type=float, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    marker = f"shadowclaw-phase1-{uuid.uuid4().hex}"
    try:
        post_payload(
            args.otlp_endpoint,
            build_payload(marker),
            timeout_seconds=args.request_timeout_seconds,
        )
        wait_for_record(
            args.loki_url,
            marker,
            wait_seconds=args.wait_seconds,
            timeout_seconds=args.request_timeout_seconds,
        )
    except IntegrationError as exc:
        print(f"ShadowClaw OTLP integration check failed: {exc}")
        return 1
    print("ShadowClaw OTLP integration check passed: namespace and finding metadata preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
