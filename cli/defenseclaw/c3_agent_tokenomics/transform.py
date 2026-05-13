# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

TOKEN_TYPE_ALIASES = {
    "prompt": "input",
    "input": "input",
    "input_tokens": "input",
    "completion": "output",
    "output": "output",
    "output_tokens": "output",
    "cache": "cached",
    "cached": "cached",
    "cache_read": "cached",
    "cacheRead": "cached",
    "reasoning": "reasoning",
    "reasoning_tokens": "reasoning",
    "tool": "tool",
    "tool_tokens": "tool",
}

KNOWN_TOKEN_TYPES = ("input", "output", "cached", "reasoning", "tool")


@dataclass(frozen=True)
class MetricPoint:
    timestamp: str
    tokens: float
    token_type: str
    agent_name: str
    model: str
    service_name: str = "unknown"
    provider: str = "unknown"
    connector: str = "unknown"
    environment: str = "unknown"
    tenant_id: str = "unknown"
    workspace_id: str = "unknown"
    session_id: str | None = None
    trace_id: str | None = None
    request_count: int = 0


def _coalesce(row: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return default


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_token_type(value: Any) -> str:
    token_type = str(value or "unknown")
    return TOKEN_TYPE_ALIASES.get(token_type, token_type)


def metric_point_from_row(row: Mapping[str, Any]) -> MetricPoint:
    """Normalize SignalFlow/O11y rows into a stable Cisco Cloud Control DTO input.

    The production adapter should convert raw SignalFlow messages to this small
    shape before aggregation. Missing optional dimensions are normalized to
    ``unknown`` instead of failing the Cisco Cloud Control endpoint.
    """
    token_type = normalize_token_type(
        _coalesce(
            row,
            "token_type",
            "gen_ai.token.type",
            "gen_ai_token_type",
            "token.type",
            "type",
            default="unknown",
        )
    )
    tokens = _coalesce(row, "tokens", "value", "sum", "metric_value", default=0)

    return MetricPoint(
        timestamp=str(_coalesce(row, "timestamp", "ts", default="")),
        tokens=_to_float(tokens),
        token_type=token_type,
        agent_name=str(_coalesce(row, "agent_name", "gen_ai.agent.name", "gen_ai_agent_name", default="unknown")),
        model=str(_coalesce(row, "model", "gen_ai.request.model", "gen_ai_request_model", default="unknown")),
        service_name=str(_coalesce(row, "service_name", "service.name", default="unknown")),
        provider=str(_coalesce(row, "provider", "gen_ai.provider.name", default="unknown")),
        connector=str(_coalesce(row, "connector", "source_system", "discovery_source", default="unknown")),
        environment=str(
            _coalesce(row, "environment", "deployment.environment", "deployment_environment", default="unknown")
        ),
        tenant_id=str(_coalesce(row, "tenant_id", default="unknown")),
        workspace_id=str(_coalesce(row, "workspace_id", default="unknown")),
        session_id=_coalesce(row, "session_id", "gen_ai.conversation.id", default=None),
        trace_id=_coalesce(row, "trace_id", "trace.id", default=None),
        request_count=_to_int(_coalesce(row, "request_count", "requests", default=0)),
    )


def _request_key(point: MetricPoint) -> str:
    if point.session_id:
        return f"session:{point.session_id}:{point.agent_name}"
    if point.trace_id:
        return f"trace:{point.trace_id}:{point.agent_name}"
    return f"agent:{point.agent_name}:{point.model}:{point.timestamp}"


def _sum_by(points: Iterable[MetricPoint], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    totals: MutableMapping[tuple[Any, ...], dict[str, Any]] = {}
    for point in points:
        key = tuple(getattr(point, k) for k in keys)
        if key not in totals:
            totals[key] = {k: getattr(point, k) for k in keys}
            totals[key]["tokens"] = 0.0
            totals[key]["_requests_by_key"] = {}
            totals[key]["_session_ids"] = set()
            totals[key]["_trace_ids"] = set()
        bucket = totals[key]
        bucket["tokens"] += point.tokens
        reqs = bucket["_requests_by_key"]
        req_key = _request_key(point)
        reqs[req_key] = max(reqs.get(req_key, 0), point.request_count)
        if point.session_id:
            bucket["_session_ids"].add(point.session_id)
        if point.trace_id:
            bucket["_trace_ids"].add(point.trace_id)

    rows = []
    for value in totals.values():
        requests_by_key = value.pop("_requests_by_key")
        session_ids = value.pop("_session_ids")
        trace_ids = value.pop("_trace_ids")
        value["requests"] = sum(requests_by_key.values())
        value["sessions"] = len(session_ids)
        value["session_ids"] = sorted(session_ids)
        value["trace_ids"] = sorted(trace_ids)
        value["tokens"] = round(value["tokens"], 2)
        rows.append(value)
    return sorted(rows, key=lambda r: r["tokens"], reverse=True)




def _sum_agents(points: Iterable[MetricPoint]) -> list[dict[str, Any]]:
    totals: MutableMapping[tuple[Any, ...], dict[str, Any]] = {}
    for point in points:
        key = (point.agent_name, point.service_name)
        if key not in totals:
            totals[key] = {
                "agent_name": point.agent_name,
                "service_name": point.service_name,
                "_connectors": set(),
                "tokens": 0.0,
                "_requests_by_key": {},
                "_session_ids": set(),
                "_trace_ids": set(),
            }
        bucket = totals[key]
        bucket["tokens"] += point.tokens
        if point.connector:
            bucket["_connectors"].add(point.connector)
        reqs = bucket["_requests_by_key"]
        req_key = _request_key(point)
        reqs[req_key] = max(reqs.get(req_key, 0), point.request_count)
        if point.session_id:
            bucket["_session_ids"].add(point.session_id)
        if point.trace_id:
            bucket["_trace_ids"].add(point.trace_id)

    rows = []
    for value in totals.values():
        connectors = sorted(value.pop("_connectors"))
        requests_by_key = value.pop("_requests_by_key")
        session_ids = value.pop("_session_ids")
        trace_ids = value.pop("_trace_ids")
        value["connector"] = (
            connectors[0] if len(connectors) == 1 else ",".join(connectors) if connectors else "unknown"
        )
        value["requests"] = sum(requests_by_key.values())
        value["sessions"] = len(session_ids)
        value["session_ids"] = sorted(session_ids)
        value["trace_ids"] = sorted(trace_ids)
        value["tokens"] = round(value["tokens"], 2)
        rows.append(value)
    return sorted(rows, key=lambda r: r["tokens"], reverse=True)


def _recommendations(
    summary: Mapping[str, Any],
    top_agents: list[dict[str, Any]],
    top_models: list[dict[str, Any]],
) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    total = float(summary.get("total_tokens", 0) or 0)
    reasoning = float(summary.get("reasoning_tokens", 0) or 0)
    cached = float(summary.get("cached_tokens", 0) or 0)

    if top_agents:
        agent = top_agents[0]
        recs.append(
            {
                "title": f"Review top token consumer: {agent.get('agent_name', 'unknown')}",
                "why": f"This agent accounts for {agent.get('tokens', 0)} tokens in the selected window.",
                "action": (
                    "Open the related O11y Agent detail view and inspect trace/session outliers "
                    "before applying budget caps."
                ),
            }
        )
    if total and reasoning / total > 0.2:
        recs.append(
            {
                "title": "Reasoning token pressure detected",
                "why": "Reasoning tokens exceed 20% of total token usage.",
                "action": "Consider routing simple tasks to a cheaper model tier or reducing reasoning-heavy prompts.",
            }
        )
    if total and cached / total < 0.1:
        recs.append(
            {
                "title": "Low cache utilization",
                "why": "Cached tokens are below 10% of total usage.",
                "action": (
                    "Evaluate prompt prefix reuse, semantic caching, or model gateway caching "
                    "for repeated workflows."
                ),
            }
        )
    if top_models:
        recs.append(
            {
                "title": f"Validate model mix: {top_models[0].get('model', 'unknown')}",
                "why": "The top model dominates the current token burn.",
                "action": "Confirm whether high-volume workflows can use a smaller model without quality loss.",
            }
        )
    return recs[:4]


def _deep_links(realm: str | None = None) -> dict[str, str]:
    realm = realm or os.environ.get("O11Y_REALM") or "<realm>"
    return {
        "o11y_agents": f"https://app.{realm}.signalfx.com/#/apm/agents",
        "trace_analyzer": f"https://app.{realm}.signalfx.com/#/apm/traces",
    }


def build_summary(
    rows: Iterable[Mapping[str, Any]],
    tenant_id: str | None = None,
    workspace_id: str | None = None,
    realm: str | None = None,
) -> dict[str, Any]:
    points = [metric_point_from_row(row) for row in rows]
    if tenant_id:
        points = [p for p in points if p.tenant_id in (tenant_id, "unknown")]
    if workspace_id:
        points = [p for p in points if p.workspace_id in (workspace_id, "unknown")]

    token_totals = {token_type: 0.0 for token_type in KNOWN_TOKEN_TYPES}
    request_counts_by_key: MutableMapping[str, int] = {}
    sessions = set()
    trace_ids = set()
    for point in points:
        token_totals[point.token_type] = token_totals.get(point.token_type, 0.0) + point.tokens
        req_key = _request_key(point)
        request_counts_by_key[req_key] = max(request_counts_by_key.get(req_key, 0), point.request_count)
        if point.session_id:
            sessions.add(point.session_id)
        if point.trace_id:
            trace_ids.add(point.trace_id)
    total_requests = sum(request_counts_by_key.values())

    total_tokens = sum(token_totals.values())
    summary = {
        "total_tokens": round(total_tokens, 2),
        "input_tokens": round(token_totals.get("input", 0.0), 2),
        "output_tokens": round(token_totals.get("output", 0.0), 2),
        "cached_tokens": round(token_totals.get("cached", 0.0), 2),
        "reasoning_tokens": round(token_totals.get("reasoning", 0.0), 2),
        "tool_tokens": round(token_totals.get("tool", 0.0), 2),
        "request_count": total_requests,
        "session_count": len(sessions),
        "trace_count": len(trace_ids),
        "active_agents": len({p.agent_name for p in points if p.agent_name != "unknown"}),
    }

    top_agents = _sum_agents(points)[:10]
    top_models = _sum_by(points, ("model", "provider"))[:10]

    mix_keys = [*KNOWN_TOKEN_TYPES, *sorted(k for k in token_totals if k not in KNOWN_TOKEN_TYPES)]
    token_mix = [
        {
            "token_type": key,
            "tokens": round(token_totals[key], 2),
            "percentage": round((token_totals[key] / total_tokens) * 100, 2) if total_tokens else 0,
        }
        for key in mix_keys
        if token_totals.get(key, 0) > 0
    ]

    return {
        "schema_version": "c3.agent_tokenomics.v0.1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "splunk_o11y_signalflow",
        "tenant_id": tenant_id or (points[0].tenant_id if points else "unknown"),
        "workspace_id": workspace_id or (points[0].workspace_id if points else "unknown"),
        "summary": summary,
        "top_agents": top_agents,
        "top_models": top_models,
        "token_mix": token_mix,
        "recommendations": _recommendations(summary, top_agents, top_models),
        "deep_links": _deep_links(realm),
    }


def points_as_dicts(points: Iterable[MetricPoint]) -> list[dict[str, Any]]:
    return [asdict(point) for point in points]
