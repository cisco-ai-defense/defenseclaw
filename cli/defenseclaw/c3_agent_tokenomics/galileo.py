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

import copy
from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

CONTROL_DECISIONS = {"allow", "deny", "warn", "steer", "log", "human_review"}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clean_str(value: Any, default: str = "") -> str:
    if value in (None, ""):
        return default
    return str(value)


def _normalize_decision(value: Any) -> str:
    raw = str(value or "log").strip().lower().replace("-", "_")
    aliases = {
        "block": "deny",
        "blocked": "deny",
        "review": "human_review",
        "human-review": "human_review",
        "observe": "log",
        "audit": "log",
    }
    decision = aliases.get(raw, raw)
    return decision if decision in CONTROL_DECISIONS else "log"


def _normalize_severity(value: Any) -> str:
    sev = str(value or "INFO").strip().upper()
    return sev if sev in SEVERITY_ORDER else "INFO"


def _max_severity(values: list[str]) -> str:
    if not values:
        return "INFO"
    return max(values, key=lambda v: SEVERITY_ORDER.get(v, 0))


def _index_o11y_agents(summary: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]]]:
    by_trace: dict[str, str] = {}
    by_session: dict[str, str] = {}
    by_agent: dict[str, dict[str, Any]] = {}
    for row in _as_list(summary.get("top_agents")):
        agent = _clean_str(row.get("agent_name"), "unknown")
        by_agent[agent] = row
        for trace_id in _as_list(row.get("trace_ids")):
            by_trace[_clean_str(trace_id)] = agent
        for session_id in _as_list(row.get("session_ids")):
            by_session[_clean_str(session_id)] = agent
    return by_trace, by_session, by_agent


def _match_trace_to_agent(
    trace: Mapping[str, Any],
    by_trace: Mapping[str, str],
    by_session: Mapping[str, str],
    by_agent: Mapping[str, dict[str, Any]],
) -> tuple[str, str]:
    trace_id = _clean_str(trace.get("trace_id"))
    session_id = _clean_str(trace.get("session_id"))
    agent_name = _clean_str(trace.get("agent_name"), "(unknown)")
    if trace_id and trace_id in by_trace:
        return by_trace[trace_id], "trace_id"
    if session_id and session_id in by_session:
        return by_session[session_id], "session_id"
    if agent_name in by_agent:
        return agent_name, "agent_name"
    return agent_name, "agent_name_unmatched"


def _token_pressure(agent_name: str, by_agent: Mapping[str, dict[str, Any]], total_tokens: float) -> dict[str, Any]:
    ranked = sorted(by_agent.values(), key=lambda row: float(row.get("tokens", 0) or 0), reverse=True)
    row = by_agent.get(agent_name, {})
    tokens = float(row.get("tokens", 0) or 0)
    rank = next((idx + 1 for idx, item in enumerate(ranked) if item.get("agent_name") == agent_name), None)
    return {
        "tokens": round(tokens, 2),
        "percentage_of_total": round((tokens / total_tokens) * 100, 2) if total_tokens else 0,
        "rank": rank,
    }


def _add_reason(counter: Counter[str], value: Any) -> None:
    reason = _clean_str(value).strip()
    if reason:
        counter[reason] += 1


def _empty_agent_summary(agent_name: str) -> dict[str, Any]:
    return {
        "agent_name": agent_name,
        "trace_ids": set(),
        "session_ids": set(),
        "runtime_control_events": 0,
        "allows": 0,
        "denies": 0,
        "warns": 0,
        "steers": 0,
        "logs": 0,
        "human_reviews": 0,
        "eval_count": 0,
        "failed_evals": 0,
        "severities": [],
        "reasons": Counter(),
        "deep_links": set(),
        "join_keys": Counter(),
    }


def _public_agent_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "agent_name": item["agent_name"],
        "trace_ids": sorted(item["trace_ids"]),
        "session_ids": sorted(item["session_ids"]),
        "runtime_control_events": item["runtime_control_events"],
        "allows": item["allows"],
        "denies": item["denies"],
        "warns": item["warns"],
        "steers": item["steers"],
        "logs": item["logs"],
        "human_reviews": item["human_reviews"],
        "eval_count": item["eval_count"],
        "failed_evals": item["failed_evals"],
        "max_severity": _max_severity(item["severities"]),
        "top_reasons": [reason for reason, _ in item["reasons"].most_common(3)],
        "deep_links": sorted(item["deep_links"]),
        "join_keys": dict(item["join_keys"]),
    }


def summarize_galileo(
    galileo_payload: Mapping[str, Any],
    o11y_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize Galileo trace/eval/control data for the Cisco Cloud Control response.

    ``o11y_summary`` is optional. When supplied, join reliability follows the
    required order: trace_id, then session_id, then agent_name.
    """
    o11y_summary = o11y_summary or {}
    by_trace, by_session, by_agent = _index_o11y_agents(o11y_summary)
    total_tokens = float(o11y_summary.get("summary", {}).get("total_tokens", 0) or 0)

    agents: dict[str, dict[str, Any]] = defaultdict(lambda: _empty_agent_summary("(unknown)"))
    evidence: list[dict[str, Any]] = []

    traces = _as_list(galileo_payload.get("traces"))
    for trace in traces:
        if not isinstance(trace, Mapping):
            continue
        matched_agent, join_key = _match_trace_to_agent(trace, by_trace, by_session, by_agent)
        if matched_agent not in agents or agents[matched_agent]["agent_name"] == "(unknown)":
            agents[matched_agent] = _empty_agent_summary(matched_agent)
        item = agents[matched_agent]
        item["join_keys"][join_key] += 1

        trace_id = _clean_str(trace.get("trace_id"))
        session_id = _clean_str(trace.get("session_id"))
        deep_link = _clean_str(trace.get("deep_link"))
        if trace_id:
            item["trace_ids"].add(trace_id)
        if session_id:
            item["session_ids"].add(session_id)
        if deep_link:
            item["deep_links"].add(deep_link)

        for ev in _as_list(trace.get("evals")):
            if not isinstance(ev, Mapping):
                continue
            severity = _normalize_severity(ev.get("severity"))
            item["eval_count"] += 1
            item["severities"].append(severity)
            if ev.get("passed") is False:
                item["failed_evals"] += 1
                _add_reason(item["reasons"], ev.get("explanation") or ev.get("name"))

        for ctrl in _as_list(trace.get("controls")):
            if not isinstance(ctrl, Mapping):
                continue
            decision = _normalize_decision(ctrl.get("decision"))
            severity = _normalize_severity(ctrl.get("severity"))
            item["runtime_control_events"] += 1
            item["severities"].append(severity)
            if decision == "allow":
                item["allows"] += 1
            elif decision == "deny":
                item["denies"] += 1
            elif decision == "warn":
                item["warns"] += 1
            elif decision == "steer":
                item["steers"] += 1
            elif decision == "human_review":
                item["human_reviews"] += 1
            else:
                item["logs"] += 1
            _add_reason(item["reasons"], ctrl.get("reason"))
            evidence.append(
                {
                    "agent_name": matched_agent,
                    "decision": decision,
                    "severity": severity,
                    "reason": _clean_str(ctrl.get("reason")),
                    "target": _clean_str(ctrl.get("target"), "unknown"),
                    "action": _clean_str(ctrl.get("action"), "unknown"),
                    "control_id": _clean_str(ctrl.get("control_id")),
                    "policy_id": _clean_str(ctrl.get("policy_id")),
                    "evidence_ref": _clean_str(ctrl.get("evidence_ref")),
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "deep_link": deep_link,
                    "join_key": join_key,
                    "token_pressure": _token_pressure(matched_agent, by_agent, total_tokens),
                }
            )

    public_agents = {agent: _public_agent_summary(item) for agent, item in agents.items()}
    return {
        "project": galileo_payload.get("project"),
        "project_id": galileo_payload.get("project_id"),
        "log_stream": galileo_payload.get("log_stream"),
        "log_stream_id": galileo_payload.get("log_stream_id"),
        "trace_count": len(traces),
        "agents_with_runtime_controls": len(public_agents),
        "runtime_control_events": sum(x["runtime_control_events"] for x in public_agents.values()),
        "allows": sum(x["allows"] for x in public_agents.values()),
        "denies": sum(x["denies"] for x in public_agents.values()),
        "warns": sum(x["warns"] for x in public_agents.values()),
        "steers": sum(x["steers"] for x in public_agents.values()),
        "logs": sum(x["logs"] for x in public_agents.values()),
        "human_reviews": sum(x["human_reviews"] for x in public_agents.values()),
        "failed_evals": sum(x["failed_evals"] for x in public_agents.values()),
        "agent_summaries": public_agents,
        "evidence": evidence,
    }


def _runtime_cards(g: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "title": "Runtime Controls",
            "value": g.get("runtime_control_events", 0),
            "subtitle": "Galileo Agent Control decisions in the selected window",
        },
        {
            "title": "Blocked Unsafe Actions",
            "value": g.get("denies", 0),
            "subtitle": "Deny decisions returned before action execution",
        },
        {
            "title": "Human Reviews",
            "value": g.get("human_reviews", 0),
            "subtitle": "Actions escalated for approval or review",
        },
        {
            "title": "Failed Runtime Evals",
            "value": g.get("failed_evals", 0),
            "subtitle": "Galileo evals that did not pass",
        },
    ]


def _runtime_recommendations(g: Mapping[str, Any]) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    if g.get("denies", 0):
        recs.append(
            {
                "title": "Runtime controls blocked unsafe agent activity",
                "why": "Galileo Agent Control returned deny decisions for one or more runtime actions.",
                "action": (
                    "Review the Runtime Governance Evidence table and open the Galileo trace link "
                    "for policy tuning context."
                ),
            }
        )
    if g.get("human_reviews", 0):
        recs.append(
            {
                "title": "Human review path exercised",
                "why": "Sensitive or high-risk runtime activity required a human-review decision.",
                "action": (
                    "Use Cisco Cloud Control to show the executive escalation path while preserving "
                    "Galileo evidence for investigators."
                ),
            }
        )
    if g.get("failed_evals", 0):
        recs.append(
            {
                "title": "Failed runtime evals need follow-up",
                "why": "Galileo evals identified safety, quality, or mission-drift concerns in the selected window.",
                "action": (
                    "Open the Galileo trace summaries next to token-pressure context before changing "
                    "model routing or quotas."
                ),
            }
        )
    return recs


def merge_galileo_enrichment(o11y_summary: Mapping[str, Any], galileo_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return the Cisco Cloud Control DTO with optional Galileo enrichment attached."""
    out = copy.deepcopy(dict(o11y_summary))
    g = summarize_galileo(galileo_payload, out)
    agent_summaries = g["agent_summaries"]

    seen_agents: set[str] = set()
    for row in out.get("top_agents", []):
        agent_name = _clean_str(row.get("agent_name"), "unknown")
        seen_agents.add(agent_name)
        row["galileo"] = agent_summaries.get(agent_name)

    for agent_name, runtime in agent_summaries.items():
        if agent_name in seen_agents:
            continue
        out.setdefault("top_agents", []).append(
            {
                "agent_name": agent_name,
                "service_name": "unknown",
                "connector": "galileo",
                "tokens": 0,
                "requests": 0,
                "sessions": len(runtime.get("session_ids", [])),
                "session_ids": runtime.get("session_ids", []),
                "trace_ids": runtime.get("trace_ids", []),
                "runtime_only": True,
                "galileo": runtime,
            }
        )

    out["schema_version"] = "c3.agent_tokenomics.v0.2"
    out["source"] = "splunk_o11y_signalflow+galileo"
    out["galileo"] = {key: value for key, value in g.items() if key != "evidence"}
    out["runtime_governance_cards"] = _runtime_cards(g)
    out["runtime_governance_evidence"] = g["evidence"]
    out.setdefault("recommendations", []).extend(_runtime_recommendations(g))
    out.setdefault("deep_links", {})["galileo_project"] = "https://app.galileo.ai/"
    out["executive_banner"] = (
        "O11y identifies token and cost pressure; Galileo evaluates agent behavior and applies runtime controls; "
        "Cisco Cloud Control brings the governance view together."
    )
    return out
