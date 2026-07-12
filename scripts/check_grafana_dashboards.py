#!/usr/bin/env python3
"""Validate the bundled Grafana dashboard contract.

The static pass is suitable for CI.  ``--live`` additionally asks the local
Prometheus, Loki, Tempo, and Grafana APIs to parse every retained query.  A
query may legitimately return no rows (for example, no approval was denied),
but it must be syntactically valid and target a configured datasource.
``--live-golden`` is the explicit release gate for data emitted by
``TestLocalObservabilityGoldenProducerScenario``; ordinary CI never contacts
the local stack.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
try:
    from local_observability_v1 import compatibility_errors
except ModuleNotFoundError:  # Imported as scripts.check_grafana_dashboards in tests.
    sys.path.insert(0, str(SCRIPT_DIR))
    from local_observability_v1 import compatibility_errors

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "bundles/local_observability_stack/grafana/dashboards"
PACKAGED_DIR = ROOT / "cli/defenseclaw/_data/local_observability_stack/grafana/dashboards"
SOURCE_DATASOURCES = ROOT / "bundles/local_observability_stack/grafana/provisioning/datasources/datasources.yml"
PACKAGED_DATASOURCES = (
    ROOT / "cli/defenseclaw/_data/local_observability_stack/grafana/provisioning/datasources/datasources.yml"
)
DEFAULT_METRIC_EXPORT_INTERVAL_SECONDS = 60

# Prometheus label contracts for the security-sensitive metrics most likely to
# produce plausible-looking zeroes when a dashboard filters on a nonexistent
# label. Resource labels are shared across all application metrics and remain
# legal selectors in addition to the instrument-specific labels below.
COMMON_PROMETHEUS_RESOURCE_LABELS = {
    "deployment_environment",
    "host_arch",
    "host_name",
    "job",
    "os_type",
    "otel_scope_name",
    "service_name",
    "service_namespace",
    "service_version",
}
PROMETHEUS_METRIC_LABELS = {
    "defenseclaw_approval_count_total": {"result", "auto", "dangerous"},
    "defenseclaw_approval_lifecycle_total": {"connector", "result", "surface"},
    "defenseclaw_cisco_errors_total": {"code"},
    "defenseclaw_cisco_inspect_latency_milliseconds_bucket": {"le", "outcome"},
    "defenseclaw_cisco_inspect_latency_milliseconds_count": {"outcome"},
    "defenseclaw_connector_hook_outcome_total": {
        "action",
        "connector",
        "event_type",
        "severity",
        "would_block",
    },
    "defenseclaw_guardrail_evaluations_total": {
        "guardrail_action_taken",
        "guardrail_connector",
        "guardrail_scanner",
    },
    "defenseclaw_schema_violations_total": {"code", "event_type"},
    "defenseclaw_stream_bytes_sent_bucket": {"le", "outcome"},
    "defenseclaw_stream_duration_ms_milliseconds_bucket": {"le", "outcome"},
    "defenseclaw_stream_lifecycle_total": {"outcome", "transition"},
}
PROMETHEUS_EXACT_LABEL_VALUES = {
    ("defenseclaw_approval_lifecycle_total", "surface"): {"chat", "exec", "native"},
    ("defenseclaw_approval_lifecycle_total", "result"): {
        "approved",
        "cancelled",
        "delivery_failed",
        "denied",
        "expired",
        "pending",
        "unavailable",
    },
    ("defenseclaw_connector_hook_latency_milliseconds_bucket", "le"): {
        "1",
        "2",
        "5",
        "10",
        "25",
        "50",
        "100",
        "250",
        "500",
        "1000",
        "2500",
        "5000",
        "10000",
        "+Inf",
    },
}

# Canonical v8 OTLP logs keep routing fields in the envelope and schema-owned
# family fields under ``body``. Loki's JSON parser exposes these as
# ``event_name``, ``body_<normalized_attribute>``, and
# ``correlation_<normalized_key>``. The pre-v8 gateway exporter instead
# promoted a parallel flat vocabulary; retaining those filters makes a panel
# look healthy while it silently returns no canonical records.
LEGACY_FLAT_LOKI_FIELDS = {
    "defenseclaw_gateway_event_type",
    "defenseclaw_hook_action",
    "defenseclaw_hook_event",
    "defenseclaw_hook_raw_action",
    "defenseclaw_hook_reason",
    "defenseclaw_hook_would_block",
    "hook_decision_action",
    "hook_decision_enforced",
    "hook_decision_event",
    "hook_decision_raw_action",
    "hook_decision_reason",
    "hook_decision_would_block",
    "scan_finding_rule_id",
    "scan_finding_scanner",
    "scan_finding_severity",
    "scan_finding_target",
    "tool_invocation_phase",
    "tool_invocation_tool_input",
    "tool_invocation_tool_output",
}
CANONICAL_JSON_LOKI_FIELD_RE = re.compile(
    r"\b(?:event_name|body_[A-Za-z0-9_]+|correlation_[A-Za-z0-9_]+)\b",
)

DATASOURCES = {
    "prometheus": "defenseclaw-prometheus",
    "loki": "defenseclaw-loki",
    "tempo": "defenseclaw-tempo",
}

VARIABLES = {
    "$__range_s": "300",
    "$__rate_interval": "5m",
    "$__rate_interval_ms": "300000",
    "$__interval": "5m",
    "$__range": "5m",
    "$scope_label": "gen_ai_agent_id",
    "$connector": "codex",
    "$agent": ".*",
    "$lifecycle": ".*",
    "$execution": ".*",
    "$session": ".*",
    "$user": ".*",
    "$vendor": ".*",
    "$category": ".*",
    "$state": ".*",
    "$source": ".*",
    "$scanner": ".*",
    "$severity": ".*",
    "$rule_id": ".*",
    "$target_type": ".*",
    "$stage": ".*",
    "$action": ".*",
    "$egress_branch": ".*",
    "${connector:regex}": "codex",
    "${connector:pipe}": "codex",
    "${agent:regex}": ".*",
    "${lifecycle:regex}": ".*",
    "${execution:regex}": ".*",
}

INVENTORY_VARIABLES = {
    **VARIABLES,
    "$__range_s": "172800",
    "$__range": "48h",
    "$agent": ".*",
}


class AuditError(RuntimeError):
    pass


DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS = 60.0
GOLDEN_AGENT_ID_RE = re.compile(r"^golden-agent-([a-z][a-z0-9-]*)-([0-9]+)$")
GOLDEN_REQUIRED_APPROVAL_EVENTS = {"approval.requested", "approval.resolved"}
GOLDEN_LIFECYCLE_EVENTS = {
    "session_start",
    "session_end",
    "subagent_start",
    "subagent_stop",
    "turn_start",
    "turn_end",
    "tool_start",
    "tool_end",
    "event",
}
GOLDEN_TERMINAL_EVENTS = {"session_end", "subagent_stop"}
GOLDEN_PHASE_CODES = {
    "session": 1,
    "planning": 2,
    "model": 3,
    "tool": 4,
    "approval": 5,
    "waiting": 6,
    "responding": 7,
    "maintenance": 8,
    "completed": 9,
    "failed": 10,
    "interrupted": 11,
    "observed": 12,
}
GOLDEN_INITIAL_PROMPT_MARKER = "local-observability golden initial prompt"
AGENT360_DESCENDANTS_PANEL = "Descendants in selected root tree"
AGENT360_TOPOLOGY_PANEL = "Lifecycle DAG — prompt → agents → work → outcomes"
AGENT360_TRACE_PANEL = "Operation and enforcement traces — click a Trace ID"
AGENT360_APPROVAL_PANEL = "Errors, blocks, approvals, and guardrail decisions"
AGENT360_CHRONOLOGY_PANEL = "Ordered lifecycle and work sequence — root to terminal"
AGENT360_PHASE_EDGES_PANEL = "Directed phase edges (source → target)"
ACTIVITY_CHRONOLOGY_PANEL = "Ordered session-tree lifecycle and work timeline"


@dataclass(frozen=True)
class GoldenAgent:
    agent_id: str
    session_id: str
    root_id: str
    parent_id: str
    root_session_id: str
    parent_session_id: str
    lifecycle_id: str
    execution_id: str
    depth: int


def load_dashboards(path: Path) -> list[tuple[Path, dict[str, Any]]]:
    dashboards: list[tuple[Path, dict[str, Any]]] = []
    for dashboard_path in sorted(path.glob("*.json")):
        dashboards.append((dashboard_path, json.loads(dashboard_path.read_text(encoding="utf-8"))))
    return dashboards


def prometheus_time_interval_seconds(path: Path) -> float:
    """Read Grafana's advertised Prometheus sample interval without a YAML dependency."""

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuditError(f"cannot read Grafana datasource config {path}: {exc}") from exc
    match = re.search(r"^\s*timeInterval:\s*([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)\s*$", text, re.MULTILINE)
    if match is None:
        raise AuditError(f"{path}: Prometheus jsonData.timeInterval is required")
    value = float(match.group(1))
    multiplier = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]
    return value * multiplier


def panels(dashboard: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for panel in dashboard.get("panels", []):
        yield panel
        yield from panels(panel)


def dashboard_links(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "url" and isinstance(child, str) and child.startswith("/d/"):
                yield child
            else:
                yield from dashboard_links(child)
    elif isinstance(value, list):
        for child in value:
            yield from dashboard_links(child)


def target_datasource(panel: dict[str, Any], target: dict[str, Any]) -> str | None:
    value = target.get("datasource") or panel.get("datasource") or {}
    return value.get("type")


def tempo_target_query(target: dict[str, Any]) -> str | None:
    """Return executable TraceQL for raw and structured Grafana Tempo targets."""

    raw_query = target.get("query")
    if raw_query is not None:
        if not isinstance(raw_query, str):
            raise AuditError("Tempo raw queries must be strings")
        raw_query = raw_query.strip()
        if not raw_query:
            raise AuditError("Tempo raw queries must not be blank")
        return raw_query
    if target.get("queryType") != "traceqlSearch":
        raise AuditError(
            f"unsupported Tempo target queryType {target.get('queryType')!r}; "
            "expected a raw query or traceqlSearch filters",
        )

    filters = target.get("filters")
    if not isinstance(filters, list) or not filters:
        raise AuditError("traceqlSearch targets must provide a raw query or structured filters")

    conditions: list[str] = []
    for item in filters:
        if not isinstance(item, dict):
            raise AuditError("TraceQL filter entries must be objects")
        tag = item.get("tag")
        scope = item.get("scope")
        operator = item.get("operator")
        values = item.get("value")
        if not isinstance(tag, str) or not tag:
            raise AuditError("TraceQL filters require a tag")
        if operator not in {"=", "!=", "=~", "!~"}:
            raise AuditError(f"unsupported TraceQL filter operator {operator!r}")
        if not isinstance(values, list) or not values:
            raise AuditError(f"TraceQL filter {tag!r} requires at least one value")

        if scope == "resource":
            attribute = tag if tag.startswith("resource.") else f"resource.{tag}"
        elif scope == "span":
            if tag == "name":
                attribute = "name"
            else:
                attribute = tag if tag.startswith("span.") else f"span.{tag}"
        else:
            raise AuditError(f"unsupported TraceQL filter scope {scope!r}")

        comparisons = [f"{attribute} {operator} {json.dumps(value)}" for value in values]
        joiner = " && " if operator in {"!=", "!~"} else " || "
        condition = comparisons[0] if len(comparisons) == 1 else f"({joiner.join(comparisons)})"
        conditions.append(condition)
    return f"{{ {' && '.join(conditions)} }}"


def interpolate(query: str, variables: dict[str, str] | None = None) -> str:
    replacements = VARIABLES if variables is None else variables
    for variable, value in sorted(replacements.items(), key=lambda item: -len(item[0])):
        query = query.replace(variable, value)
    query = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[^}]*)?\}", ".*", query)
    return re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", ".*", query)


def static_audit(
    *,
    require_packaged: bool = False,
) -> tuple[list[tuple[Path, dict[str, Any]]], list[str]]:
    dashboards = load_dashboards(SOURCE_DIR)
    errors: list[str] = []
    if not dashboards:
        return dashboards, [f"no dashboards found under {SOURCE_DIR}"]

    try:
        datasource_interval = prometheus_time_interval_seconds(SOURCE_DATASOURCES)
        if datasource_interval < DEFAULT_METRIC_EXPORT_INTERVAL_SECONDS:
            errors.append(
                "Grafana Prometheus timeInterval must be at least the default "
                f"{DEFAULT_METRIC_EXPORT_INTERVAL_SECONDS}s OTel metric export interval; "
                f"got {datasource_interval:g}s",
            )
    except AuditError as exc:
        errors.append(str(exc))

    for path, dashboard in dashboards:
        if not dashboard.get("uid"):
            errors.append(f"{path.name}: dashboard UID is required")
        if not dashboard.get("title"):
            errors.append(f"{path.name}: dashboard title is required")
    uids = [dashboard.get("uid") for _, dashboard in dashboards if dashboard.get("uid")]
    titles = [dashboard.get("title") for _, dashboard in dashboards if dashboard.get("title")]
    if len(set(uids)) != len(uids):
        errors.append("dashboard UIDs must be unique")
    if len(set(titles)) != len(titles):
        errors.append("dashboard titles must be unique")
    known_uids = set(uids)

    if "defenseclaw-reliability" in known_uids:
        errors.append("the retired Reliability board must stay consolidated into Runtime")

    for path, dashboard in dashboards:
        uid = dashboard.get("uid") or path.name
        if not dashboard.get("description"):
            errors.append(f"{uid}: dashboard description is required")
        serialized = json.dumps(dashboard)
        if "Speculative — pending instrumentation" in serialized:
            errors.append(f"{uid}: speculative/uninstrumented panels are not shippable")
        if "EMITTED-NOWHERE" in serialized:
            errors.append(f"{uid}: panel references explicitly orphaned instrumentation")

        top_level = dashboard.get("panels", [])
        for index, panel in enumerate(top_level):
            if panel.get("type") != "row" or panel.get("panels"):
                continue
            following = top_level[index + 1] if index + 1 < len(top_level) else None
            if following is None or following.get("type") == "row":
                errors.append(f"{uid}: empty row {panel.get('title')!r}")

        for section in ("templating", "annotations"):
            for item in dashboard.get(section, {}).get("list", []):
                datasource = item.get("datasource")
                if datasource is None:
                    continue
                if not isinstance(datasource, dict):
                    errors.append(f"{uid}/{section}: datasource must be an object")
                    continue
                datasource_type = datasource.get("type")
                datasource_uid = datasource.get("uid")
                if datasource_type == "grafana" and datasource_uid == "-- Grafana --":
                    continue
                if datasource_type not in DATASOURCES:
                    errors.append(
                        f"{uid}/{section}: unsupported datasource {datasource_type!r}",
                    )
                    continue
                if datasource_uid != DATASOURCES[datasource_type]:
                    errors.append(
                        f"{uid}/{section}: {datasource_type} must use {DATASOURCES[datasource_type]!r}",
                    )

        for panel in panels(dashboard):
            title = panel.get("title")
            kind = panel.get("type")
            if not title:
                errors.append(f"{uid}: every panel and row needs a title")
            if kind not in {"row", "text"} and not panel.get("targets"):
                errors.append(f"{uid}/{title}: panel has no query target")
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                if datasource not in DATASOURCES:
                    errors.append(f"{uid}/{title}: unsupported datasource {datasource!r}")
                    continue
                configured = (target.get("datasource") or panel.get("datasource") or {}).get("uid")
                if configured != DATASOURCES[datasource]:
                    errors.append(f"{uid}/{title}: {datasource} must use {DATASOURCES[datasource]!r}")

                expression = target.get("expr", "")
                legend = target.get("legendFormat", "")
                if re.search(
                    r'\b(?:body_)?gen_ai_agent_name\s*(?:=~|!~|=|!=)\s*'
                    r'"\$(?:connector|\{connector:(?:regex|pipe)\})"',
                    expression,
                ):
                    errors.append(
                        f"{uid}/{title}: connector filters must use canonical connector/source identity, "
                        "not gen_ai_agent_name",
                    )
                if (
                    datasource == "prometheus"
                    and "defenseclaw_agent_last_seen_seconds" in expression
                    and "active" in str(title).lower()
                    and "time()" not in expression
                ):
                    errors.append(
                        f"{uid}/{title}: active last-seen queries must compare the gauge value to time()",
                    )
                if (
                    datasource == "prometheus"
                    and "gen_ai_client_token_usage" in expression
                    and re.search(r"\*\s*(?:\d+(?:\.\d+)?e-\d+|0\.\d{5,})", expression)
                ):
                    errors.append(
                        f"{uid}/{title}: dashboards must use upstream-reported cost, not hard-coded prices",
                    )
                invocation_volume_title = any(
                    token in str(title).lower()
                    for token in ("hook events", "events by", "tool calls")
                )
                if (
                    datasource == "prometheus"
                    and invocation_volume_title
                    and "defenseclaw_connector_hook_outcome_total" in expression
                    and not any(
                        token in str(title).lower()
                        for token in ("shadow", "outcome", "decision")
                    )
                ):
                    errors.append(
                        f"{uid}/{title}: invocation-volume panels must use "
                        "defenseclaw_connector_hook_invocations_total",
                    )
                if (
                    datasource == "prometheus"
                    and "defenseclaw_ai_discovery_active_signals" in expression
                    and (
                        "last_over_time" in expression
                        or "timestamp(defenseclaw_ai_discovery_active_signals" not in expression
                        or "max by (source, privacy_mode) (timestamp(" not in expression
                        or "== on (source, privacy_mode) group_left" not in expression
                        or "time() - 300" not in expression
                    )
                ):
                    errors.append(
                        f"{uid}/{title}: latest-value discovery gauges must select the newest current "
                        "service-instance sample per (source, privacy_mode) before aggregation",
                    )
                if (
                    datasource == "prometheus"
                    and "defenseclaw_ai_discovery_signals_total" in expression
                    and "max_over_time" in expression
                ):
                    errors.append(
                        f"{uid}/{title}: selected-range discovery counters must use increase",
                    )
                if (
                    datasource == "prometheus"
                    and "vector(0)" in expression
                    and re.search(
                        r"(?:defenseclaw_agent_token_usage_total|gen_ai_client_token_usage_|"
                        r"defenseclaw_agent_reported_cost_USD)",
                        expression,
                    )
                ):
                    errors.append(
                        f"{uid}/{title}: optional token/cost absence must not be fabricated as zero",
                    )
                first_sample_token_counters = (
                    "defenseclaw_agent_token_usage_total",
                    "gen_ai_client_token_usage_sum",
                )
                for token_counter in first_sample_token_counters:
                    if datasource != "prometheus" or token_counter not in expression:
                        continue
                    if re.search(rf"\brate\(\s*{re.escape(token_counter)}\b", expression):
                        errors.append(
                            f"{uid}/{title}: token rates must divide the first-sample-aware delta, "
                            f"not call rate({token_counter}) directly",
                        )
                    if "increase(" in expression and not all(
                        marker in expression
                        for marker in ("last_over_time(", " unless ", " offset ")
                    ):
                        errors.append(
                            f"{uid}/{title}: {token_counter} deltas must preserve a new series' "
                            "initial cumulative sample with last_over_time/unless/offset",
                        )
                    if "$__rate_interval" in expression and "$__rate_interval_ms" not in expression:
                        errors.append(
                            f"{uid}/{title}: first-sample-aware token rates must divide by "
                            "$__rate_interval_ms / 1000",
                        )
                if datasource == "loki" and expression:
                    if (
                        'body_$scope_label=~"$agent"' in expression
                        and '|= "$agent" | json' not in expression
                    ):
                        errors.append(
                            f"{uid}/{title}: agent-scoped Loki queries must prefilter the literal "
                            'agent ID before JSON parsing with `|= "$agent" | json`',
                        )
                    legacy_fields = {
                        field for field in LEGACY_FLAT_LOKI_FIELDS if re.search(rf"\b{re.escape(field)}\b", expression)
                    }
                    if legacy_fields:
                        errors.append(
                            f"{uid}/{title}: Loki query uses retired flat v7 fields: "
                            f"{', '.join(sorted(legacy_fields))}",
                        )
                    if CANONICAL_JSON_LOKI_FIELD_RE.search(expression) and "| json" not in expression:
                        errors.append(
                            f"{uid}/{title}: canonical v8 log fields require `| json` before filtering",
                        )
                if datasource == "prometheus" and expression:
                    for metric_name, selector in re.findall(
                        r"\b([A-Za-z_:][A-Za-z0-9_:]*)\s*\{([^{}]*)\}",
                        expression,
                    ):
                        selector_pairs = re.findall(
                            r"([A-Za-z_][A-Za-z0-9_]*)\s*(=~|!~|=|!=)\s*\"([^\"]*)\"",
                            selector,
                        )
                        if metric_name in PROMETHEUS_METRIC_LABELS:
                            allowed_labels = PROMETHEUS_METRIC_LABELS[metric_name] | COMMON_PROMETHEUS_RESOURCE_LABELS
                            unknown_labels = {label for label, _operator, _value in selector_pairs} - allowed_labels
                            if unknown_labels:
                                errors.append(
                                    f"{uid}/{title}: {metric_name} filters on unknown labels: "
                                    f"{', '.join(sorted(unknown_labels))}",
                                )
                        for label, operator, value in selector_pairs:
                            allowed_values = PROMETHEUS_EXACT_LABEL_VALUES.get(
                                (metric_name, label),
                            )
                            if allowed_values is None or operator != "=":
                                continue
                            if value not in allowed_values:
                                errors.append(
                                    f"{uid}/{title}: {metric_name} uses unknown exact {label} value {value!r}",
                                )
                if datasource == "prometheus" and expression and legend:
                    legend_labels = set(
                        re.findall(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}", legend),
                    )
                    grouped_labels: set[str] = set()
                    for group in re.findall(r"\bby\s*\(([^)]*)\)", expression):
                        grouped_labels.update(label.strip() for label in group.split(","))
                    removed_labels: set[str] = set()
                    for group in re.findall(r"\bwithout\s*\(([^)]*)\)", expression):
                        removed_labels.update(label.strip() for label in group.split(","))
                    selector_labels = set(
                        re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|=|!=)", expression),
                    )
                    if grouped_labels:
                        # A `by(...)` aggregation drops every source label that is
                        # not named in the grouping, even when that label appears
                        # in a selector. Treat only grouped labels as available.
                        missing_legend_labels = legend_labels - grouped_labels
                    elif removed_labels:
                        # `without(...)` preserves an open-ended set of source
                        # labels, so the only labels we can prove absent are the
                        # labels explicitly removed by the aggregation.
                        missing_legend_labels = legend_labels & removed_labels
                    else:
                        missing_legend_labels = legend_labels - selector_labels
                    if missing_legend_labels:
                        errors.append(
                            f"{uid}/{title}: legend references labels absent from the query: "
                            f"{', '.join(sorted(missing_legend_labels))}",
                        )

                quantile = re.search(r"histogram_quantile\(\s*(0(?:\.\d+)?|1(?:\.0+)?)", expression)
                percentile_labels = {
                    int(value)
                    for value in re.findall(
                        r"\bp(\d{1,3})\b",
                        f"{target.get('refId', '')} {legend}".lower(),
                    )
                }
                if quantile and percentile_labels:
                    actual_percentile = round(float(quantile.group(1)) * 100)
                    if percentile_labels != {actual_percentile}:
                        errors.append(
                            f"{uid}/{title}: target {target.get('refId', '?')} is labelled "
                            f"{sorted(percentile_labels)} but queries p{actual_percentile}",
                        )
                if datasource == "tempo":
                    try:
                        tempo_target_query(target)
                    except AuditError as exc:
                        errors.append(f"{uid}/{title}: {exc}")
                    if str(target.get("query", "")).strip() == "$trace":
                        description = str(panel.get("description", "")).lower()
                        if "expected" not in description or "until" not in description:
                            errors.append(
                                f"{uid}/{title}: blank trace selection must document its expected empty state",
                            )
                if datasource == "loki" and "| json" in expression and '__error__=""' not in expression:
                    errors.append(f"{uid}/{title}: JSON parsing must discard malformed log lines")
                range_function = re.search(
                    r"\b(?:increase|i?rate|i?delta|changes|resets|deriv|predict_linear|holt_winters|[A-Za-z_][A-Za-z0-9_]*_over_time)\(",
                    expression,
                )
                if datasource == "prometheus" and kind == "stat" and range_function and not target.get("instant"):
                    errors.append(f"{uid}/{title}: range-aggregate stat targets must be instant queries")
                if (
                    datasource == "prometheus"
                    and re.search(r"gen_ai_client_token_usage_(?:sum|count)", expression)
                    and not range_function
                ):
                    errors.append(f"{uid}/{title}: historical token panels must use a range function")
                if (
                    datasource == "prometheus"
                    and re.match(
                        r"^\s*(?:sum|avg|max|min|count)\s+by\s*\([^)]*\)",
                        expression,
                    )
                    and re.search(r"\bor\s+vector\(0\)", expression)
                ):
                    errors.append(
                        f"{uid}/{title}: grouped zero fallbacks must use `or on() vector(0)` "
                        "to avoid an unlabeled series",
                    )

        variables = dashboard.get("templating", {}).get("list", [])
        for variable in variables:
            if variable.get("type") != "custom" or not variable.get("options"):
                continue
            query_values = [
                item.rsplit(" : ", 1)[-1].strip()
                for item in str(variable.get("query", "")).split(",")
                if item.strip()
            ]
            option_values = [
                str(option.get("value", "")).strip()
                for option in variable.get("options", [])
                if str(option.get("value", "")).strip() not in {"", "$__all"}
            ]
            if query_values != option_values:
                errors.append(
                    f"{uid}: custom variable {variable.get('name', '<unnamed>')} persisted options "
                    "must match its query values",
                )
        variable_positions = {
            item.get("name"): index
            for index, item in enumerate(variables)
            if item.get("name")
        }
        if "scope_label" in variable_positions and "agent" in variable_positions:
            if variable_positions["scope_label"] > variable_positions["agent"]:
                errors.append(f"{uid}: scope_label must be defined before the dependent agent variable")
            agent_variable = variables[variable_positions["agent"]]
            if "$scope_label" not in json.dumps(agent_variable):
                errors.append(f"{uid}: the agent variable must enumerate the selected scope_label")

        for link in dashboard_links(dashboard):
            match = re.match(r"/d/([^/?]+)", link)
            if match and match.group(1) not in known_uids:
                errors.append(f"{uid}: dashboard link targets missing UID {match.group(1)!r}")

    if require_packaged and not PACKAGED_DIR.is_dir():
        errors.append(f"CLI packaged Grafana dashboard directory is missing: {PACKAGED_DIR}")
    elif PACKAGED_DIR.is_dir():
        packaged = load_dashboards(PACKAGED_DIR)
        source_by_name = {path.name: dashboard for path, dashboard in dashboards}
        packaged_by_name = {path.name: dashboard for path, dashboard in packaged}
        if source_by_name != packaged_by_name:
            errors.append("CLI packaged Grafana dashboards do not match bundle sources")

    if require_packaged and not PACKAGED_DATASOURCES.is_file():
        errors.append(f"CLI packaged Grafana datasource config is missing: {PACKAGED_DATASOURCES}")
    elif SOURCE_DATASOURCES.is_file() and PACKAGED_DATASOURCES.is_file():
        if SOURCE_DATASOURCES.read_bytes() != PACKAGED_DATASOURCES.read_bytes():
            errors.append("CLI packaged Grafana datasource config does not match bundle source")

    _compatibility_inventory, compatibility_audit_errors = compatibility_errors(
        dashboards,
        require_packaged=require_packaged,
    )
    errors.extend(compatibility_audit_errors)

    return dashboards, errors


def request_json(
    url: str,
    params: dict[str, str] | None = None,
    *,
    timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise AuditError(f"{url}: HTTP {exc.code}: {body[:400]}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"{url}: {exc}") from exc


def live_query_timeout_seconds(
    *,
    deadline: float | None,
    configured_seconds: float,
) -> float:
    """Bound one backend request by both its configured and global budgets."""

    if configured_seconds <= 0:
        raise AuditError("live query timeout must be greater than zero")
    if deadline is None:
        return configured_seconds
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AuditError("live dashboard audit exceeded its global deadline")
    return min(configured_seconds, remaining)


def _numeric_result_status(result: Any) -> str:
    """Classify a Prometheus or metric-LogQL result without inventing data."""

    if not result:
        return "empty"
    values: list[Any] = []
    for series in result:
        if not isinstance(series, dict):
            continue
        if "value" in series:
            values.append(series["value"][-1])
        values.extend(value[-1] for value in series.get("values", []))
    saw_finite_value = False
    for raw_value in values:
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(value):
            continue
        saw_finite_value = True
        if value != 0:
            return "data"
    return "zero" if saw_finite_value else "empty"


def _inventory_variables(range_seconds: int) -> dict[str, str]:
    variables = dict(INVENTORY_VARIABLES)
    variables["$__range_s"] = str(range_seconds)
    variables["$__range"] = f"{max(1, range_seconds // 3600)}h"
    return variables


def tempo_readiness_error(*, attempts: int = 9, retry_delay_seconds: float = 2) -> str | None:
    """Wait through Tempo's 15-second single-binary ingester startup delay."""

    tempo_error: OSError | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen("http://127.0.0.1:3200/ready", timeout=10) as response:
                if response.status == 200:
                    return None
                tempo_error = OSError(f"HTTP {response.status}")
        except OSError as exc:
            tempo_error = exc
        if attempt < attempts - 1:
            time.sleep(retry_delay_seconds)
    return f"Tempo readiness failed after {attempts} attempts: {tempo_error}"


def _readiness_endpoint_error(name: str, url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            if 200 <= response.status < 300:
                return None
            return f"{name} readiness returned HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return f"{name} readiness returned HTTP {exc.code}"
    except OSError as exc:
        return f"{name} readiness failed: {exc}"


def backend_readiness_errors() -> list[str]:
    """Fail fast before compiling hundreds of queries against an unready stack."""

    errors: list[str] = []
    try:
        grafana = request_json("http://127.0.0.1:3000/api/health")
        if grafana.get("database") != "ok":
            errors.append("Grafana database health is not ok")
    except AuditError as exc:
        errors.append(f"Grafana health failed: {exc}")
    for name, url in (
        ("Prometheus", "http://127.0.0.1:9090/-/ready"),
        ("Loki", "http://127.0.0.1:3100/ready"),
        ("Collector", "http://127.0.0.1:13133/"),
    ):
        if error := _readiness_endpoint_error(name, url):
            errors.append(error)
    if error := tempo_readiness_error():
        errors.append(error)
    return errors


def live_inventory(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    range_seconds: int = 48 * 60 * 60,
    deadline: float | None = None,
    query_timeout_seconds: float = DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Measure whether every retained panel can render against the local stack.

    Empty and zero are intentionally different: ``zero`` proves a signal is
    instrumented but no matching event occurred, while ``empty`` means the
    selected deployment/range has no matching series or event.  Trace
    waterfalls that require a user-selected trace are reported as
    ``interactive`` instead of being mislabeled as broken, and text panels are
    ``static`` because they intentionally have no datasource.
    """

    errors: list[str] = []
    inventory: list[dict[str, Any]] = []
    now_seconds = time.time()
    start_seconds = now_seconds - range_seconds
    now_ns = int(now_seconds * 1_000_000_000)
    start_ns = int(start_seconds * 1_000_000_000)
    variables = _inventory_variables(range_seconds)
    # A long inventory range still needs a fine enough step to catch sparse
    # counters that were exported for only a few minutes before an instance
    # restarted. Fifteen-minute steps can skip those windows entirely and
    # misclassify a working historical panel as empty.
    step_seconds = max(60, min(300, range_seconds // 200))
    has_tempo_search = any(
        (query := tempo_target_query(target))
        and not any(variable in query for variable in ("$trace", "$agent", "$scope_label"))
        for _, dashboard in dashboards
        for panel in panels(dashboard)
        for target in panel.get("targets", [])
        if target_datasource(panel, target) == "tempo"
    )
    tempo_error = tempo_readiness_error() if has_tempo_search else None

    for _, dashboard in dashboards:
        if deadline is not None and time.monotonic() >= deadline:
            errors.append("live dashboard audit exceeded its global deadline")
            return inventory, errors
        panel_results: list[dict[str, Any]] = []
        for panel in panels(dashboard):
            if deadline is not None and time.monotonic() >= deadline:
                errors.append("live dashboard audit exceeded its global deadline")
                return inventory, errors
            if panel.get("type") == "row":
                continue
            if panel.get("type") == "text":
                panel_results.append(
                    {
                        "title": panel.get("title", "untitled"),
                        "type": "text",
                        "status": "static",
                    },
                )
                continue
            target_statuses: list[str] = []
            target_errors: list[str] = []
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                expression = target.get("expr", "")
                trace_query = tempo_target_query(target) if datasource == "tempo" else None
                try:
                    if datasource == "prometheus" and expression:
                        params = {"query": interpolate(expression, variables)}
                        if target.get("instant"):
                            params["time"] = str(now_seconds)
                            endpoint = "http://127.0.0.1:9090/api/v1/query"
                        else:
                            params.update(
                                {
                                    "start": str(start_seconds),
                                    "end": str(now_seconds),
                                    "step": str(step_seconds),
                                },
                            )
                            endpoint = "http://127.0.0.1:9090/api/v1/query_range"
                        result = request_json(
                            endpoint,
                            params,
                            timeout_seconds=live_query_timeout_seconds(
                                deadline=deadline,
                                configured_seconds=query_timeout_seconds,
                            ),
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                        target_statuses.append(
                            _numeric_result_status(result.get("data", {}).get("result")),
                        )
                    elif datasource == "loki" and expression:
                        params = {
                            "query": interpolate(expression, variables),
                            "limit": "10",
                        }
                        if target.get("instant") or target.get("queryType") == "instant":
                            params["time"] = str(now_ns)
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query"
                        else:
                            params.update(
                                {
                                    "start": str(start_ns),
                                    "end": str(now_ns),
                                    "step": str(step_seconds),
                                    "direction": "backward",
                                },
                            )
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query_range"
                        result = request_json(
                            endpoint,
                            params,
                            timeout_seconds=live_query_timeout_seconds(
                                deadline=deadline,
                                configured_seconds=query_timeout_seconds,
                            ),
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                        data = result.get("data", {})
                        rows = data.get("result", [])
                        if data.get("resultType") == "streams":
                            target_statuses.append("data" if rows else "empty")
                        else:
                            target_statuses.append(_numeric_result_status(rows))
                    elif datasource == "tempo" and trace_query:
                        if any(variable in trace_query for variable in ("$trace", "$agent", "$scope_label")):
                            target_statuses.append("interactive")
                        else:
                            if tempo_error is not None:
                                raise AuditError(tempo_error)
                            result = request_json(
                                "http://127.0.0.1:3200/api/search",
                                {
                                    "q": interpolate(trace_query, variables),
                                    "limit": "10",
                                    "start": str(int(start_seconds)),
                                    "end": str(int(now_seconds)),
                                },
                                timeout_seconds=live_query_timeout_seconds(
                                    deadline=deadline,
                                    configured_seconds=query_timeout_seconds,
                                ),
                            )
                            target_statuses.append("data" if result.get("traces") else "empty")
                except AuditError as exc:
                    target_errors.append(str(exc))

            if not target_statuses and not target_errors:
                continue
            if target_errors:
                status = "error"
            elif "data" in target_statuses:
                status = "data"
            elif "zero" in target_statuses:
                status = "zero"
            elif set(target_statuses) == {"interactive"}:
                status = "interactive"
            else:
                status = "empty"
            panel_result = {
                "title": panel.get("title", "untitled"),
                "type": panel.get("type", "unknown"),
                "status": status,
            }
            if target_errors:
                panel_result["errors"] = target_errors
                errors.extend(f"{dashboard['uid']}/{panel_result['title']}: {error}" for error in target_errors)
            panel_results.append(panel_result)

        status_counts = {
            status: sum(result["status"] == status for result in panel_results)
            for status in ("data", "zero", "empty", "interactive", "static", "error")
        }
        inventory.append(
            {
                "uid": dashboard["uid"],
                "title": dashboard["title"],
                "description": dashboard.get("description", ""),
                "panels": panel_results,
                "status_counts": status_counts,
            },
        )
    return inventory, errors


def print_inventory(inventory: list[dict[str, Any]], *, range_seconds: int) -> None:
    hours = range_seconds / 3600
    print(f"Live Grafana inventory ({hours:g}h, representative connector=codex, all agents)")
    print(
        "| Dashboard | Panels | Data | Zero | Empty | Interactive | Static | Errors | Empty panels |",
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for dashboard in inventory:
        counts = dashboard["status_counts"]
        empty_titles = [result["title"] for result in dashboard["panels"] if result["status"] == "empty"]
        print(
            f"| {dashboard['title']} (`{dashboard['uid']}`) "
            f"| {len(dashboard['panels'])} | {counts['data']} | {counts['zero']} "
            f"| {counts['empty']} | {counts['interactive']} | {counts['static']} "
            f"| {counts['error']} "
            f"| {', '.join(empty_titles) or 'None'} |",
        )


def live_audit(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    deadline: float | None = None,
    query_timeout_seconds: float = DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS,
) -> list[str]:
    errors: list[str] = []
    try:
        health = request_json("http://127.0.0.1:3000/api/health")
    except AuditError as exc:
        return [f"Grafana health failed: {exc}"]
    if health.get("database") != "ok":
        errors.append("Grafana database health is not ok")

    tempo_error = tempo_readiness_error()
    if tempo_error is not None:
        errors.append(tempo_error)

    now_ns = int(time.time() * 1_000_000_000)
    start_ns = now_ns - 300 * 1_000_000_000

    for _, dashboard in dashboards:
        if deadline is not None and time.monotonic() >= deadline:
            return errors + ["live dashboard audit exceeded its global deadline"]
        uid = dashboard["uid"]
        for panel in panels(dashboard):
            if deadline is not None and time.monotonic() >= deadline:
                return errors + ["live dashboard audit exceeded its global deadline"]
            title = panel.get("title", "untitled")
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                expression = target.get("expr", "")
                try:
                    if datasource == "prometheus" and expression:
                        result = request_json(
                            "http://127.0.0.1:9090/api/v1/query",
                            {"query": interpolate(expression)},
                            timeout_seconds=live_query_timeout_seconds(
                                deadline=deadline,
                                configured_seconds=query_timeout_seconds,
                            ),
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                    elif datasource == "loki" and expression:
                        query = interpolate(expression).replace("[1h]", "[5m]").replace("[24h]", "[5m]")
                        if panel.get("type") == "logs":
                            params = {
                                "query": query,
                                "start": str(start_ns),
                                "end": str(now_ns),
                                "limit": "1",
                                "direction": "backward",
                            }
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query_range"
                        else:
                            params = {"query": query, "time": str(now_ns), "limit": "1"}
                            endpoint = "http://127.0.0.1:3100/loki/api/v1/query"
                        result = request_json(
                            endpoint,
                            params,
                            timeout_seconds=live_query_timeout_seconds(
                                deadline=deadline,
                                configured_seconds=query_timeout_seconds,
                            ),
                        )
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                    elif datasource == "tempo" and tempo_error is None:
                        query = tempo_target_query(target)
                        if query and query != "$trace":
                            request_json(
                                "http://127.0.0.1:3200/api/search",
                                {"q": interpolate(query), "limit": "1"},
                                timeout_seconds=live_query_timeout_seconds(
                                    deadline=deadline,
                                    configured_seconds=query_timeout_seconds,
                                ),
                            )
                except AuditError as exc:
                    errors.append(f"{uid}/{title}: {exc}")

    return errors


def _golden_agent_role_stamp(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    match = GOLDEN_AGENT_ID_RE.fullmatch(value)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _golden_tool_family(value: Any) -> str:
    reported = str(value or "").strip()
    normalized = reported.lower()
    if "skill" in normalized:
        return "Skills"
    if normalized.startswith("mcp"):
        return "MCP"
    if (
        normalized in {"bash", "shell", "exec_command", "run_shell_command"}
        or "shell" in normalized
        or "terminal" in normalized
    ):
        return "Bash"
    if normalized == "apply_patch":
        return "File edits"
    if normalized.startswith("collaboration"):
        return "Collaboration"
    if normalized.startswith("web") or "browser" in normalized:
        return "Web / browser"
    if "image" in normalized or "visual" in normalized:
        return "Visual"
    if normalized in {"update_plan", "get_goal", "update_goal"}:
        return "Task control"
    return reported


def _prometheus_vector(
    query: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    response = request_json(
        "http://127.0.0.1:9090/api/v1/query",
        {"query": query},
        timeout_seconds=timeout_seconds,
    )
    data = response.get("data", {})
    result = data.get("result", []) if isinstance(data, dict) else []
    if response.get("status") != "success" or not isinstance(result, list):
        raise AuditError(f"Prometheus golden query failed: {response}")
    return [series for series in result if isinstance(series, dict)]


def _loki_vector(
    query: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    response = request_json(
        "http://127.0.0.1:3100/loki/api/v1/query",
        {"query": query},
        timeout_seconds=timeout_seconds,
    )
    data = response.get("data", {})
    result = data.get("result", []) if isinstance(data, dict) else []
    if response.get("status") != "success" or not isinstance(result, list):
        raise AuditError(f"Loki golden instant query failed: {response}")
    return [series for series in result if isinstance(series, dict)]


def _positive_prometheus_series(series: dict[str, Any]) -> bool:
    value = series.get("value")
    if not isinstance(value, list) or len(value) < 2:
        return False
    try:
        number = float(value[-1])
    except (TypeError, ValueError):
        return False
    return math.isfinite(number) and number > 0


def _loki_golden_records(
    *,
    start_ns: int,
    end_ns: int,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    response = request_json(
        "http://127.0.0.1:3100/loki/api/v1/query_range",
        {
            "query": (
                '{service_name="defenseclaw"} | json | __error__="" '
                '| body_gen_ai_agent_id=~"golden-agent-[a-z][a-z0-9-]*-[0-9]+"'
            ),
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": "1000",
            "direction": "backward",
        },
        timeout_seconds=timeout_seconds,
    )
    data = response.get("data", {})
    streams = data.get("result", []) if isinstance(data, dict) else []
    if response.get("status") != "success" or not isinstance(streams, list):
        raise AuditError(f"Loki golden query failed: {response}")
    records: list[dict[str, Any]] = []
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        for value in stream.get("values", []):
            if not isinstance(value, list) or len(value) < 2 or not isinstance(value[1], str):
                continue
            try:
                record = json.loads(value[1])
            except json.JSONDecodeError as exc:
                raise AuditError(f"Loki returned malformed canonical JSON: {exc}") from exc
            if isinstance(record, dict):
                records.append(record)
    return records


def _loki_query_lines(
    query: str,
    *,
    start_ns: int,
    end_ns: int,
    timeout_seconds: float,
) -> list[tuple[int, str]]:
    response = request_json(
        "http://127.0.0.1:3100/loki/api/v1/query_range",
        {
            "query": query,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": "1000",
            "direction": "forward",
        },
        timeout_seconds=timeout_seconds,
    )
    data = response.get("data", {})
    streams = data.get("result", []) if isinstance(data, dict) else []
    if response.get("status") != "success" or not isinstance(streams, list):
        raise AuditError(f"Loki authored golden query failed: {response}")
    lines: list[tuple[int, str]] = []
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        for value in stream.get("values", []):
            if not isinstance(value, list) or len(value) < 2 or not isinstance(value[1], str):
                continue
            try:
                timestamp_ns = int(value[0])
            except (TypeError, ValueError):
                continue
            lines.append((timestamp_ns, value[1]))
    return sorted(lines)


def _otel_scalar(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    return None


def _otel_attributes(items: Any) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    if not isinstance(items, list):
        return attributes
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            continue
        attributes[item["key"]] = _otel_scalar(item.get("value"))
    return attributes


def _normalize_otel_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in {16, 32}:
        return value.lower()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return ""
    if len(decoded) not in {8, 16}:
        return ""
    return decoded.hex()


def _normalize_tempo_search_trace_id(value: Any) -> str:
    """Canonicalize Tempo search IDs that omit leading zero nibbles."""

    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,32}", value):
        return ""
    normalized = value.lower().zfill(32)
    if normalized == "0" * 32:
        return ""
    return normalized


def _otel_unix_nano(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value > 0 else 0
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value)
        return parsed if parsed > 0 else 0
    return 0


def _tempo_trace_spans(
    trace_id: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    response = request_json(
        f"http://127.0.0.1:3200/api/traces/{trace_id}",
        timeout_seconds=timeout_seconds,
    )
    spans: list[dict[str, Any]] = []
    for batch in response.get("batches", []):
        if not isinstance(batch, dict):
            continue
        for scope in batch.get("scopeSpans", []):
            if not isinstance(scope, dict):
                continue
            for span in scope.get("spans", []):
                if not isinstance(span, dict):
                    continue
                wire_trace_id = _normalize_otel_id(span.get("traceId"))
                spans.append(
                    {
                        "trace_id": trace_id.lower(),
                        "wire_trace_id": wire_trace_id,
                        "span_id": _normalize_otel_id(span.get("spanId")),
                        "parent_span_id": _normalize_otel_id(span.get("parentSpanId")),
                        "name": span.get("name", ""),
                        "start_time_unix_nano": _otel_unix_nano(span.get("startTimeUnixNano")),
                        "end_time_unix_nano": _otel_unix_nano(span.get("endTimeUnixNano")),
                        "attributes": _otel_attributes(span.get("attributes")),
                    },
                )
    return spans


def _golden_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    return None


def _golden_records_for_stamp(records: list[dict[str, Any]], stamp: str) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for record in records:
        body = record.get("body", {})
        if not isinstance(body, dict):
            continue
        identity = _golden_agent_role_stamp(body.get("gen_ai.agent.id"))
        if identity is not None and identity[1] == stamp:
            selected.append(record)
    return selected


def _golden_agent_identities(
    records: list[dict[str, Any]],
    stamp: str,
) -> tuple[dict[str, GoldenAgent], list[str]]:
    agents: dict[str, GoldenAgent] = {}
    errors: list[str] = []
    for record in _golden_records_for_stamp(records, stamp):
        event_name = record.get("event_name")
        body = record.get("body", {})
        if event_name not in GOLDEN_LIFECYCLE_EVENTS or not isinstance(body, dict):
            continue
        agent_id = body.get("gen_ai.agent.id")
        depth = _golden_int(body.get("defenseclaw.agent.depth"))
        values = {
            "agent_id": agent_id,
            "session_id": body.get("gen_ai.conversation.id"),
            "root_id": body.get("defenseclaw.agent.root.id"),
            "root_session_id": body.get("defenseclaw.session.root.id"),
            "lifecycle_id": body.get("defenseclaw.agent.lifecycle.id"),
            "execution_id": body.get("defenseclaw.agent.execution.id"),
        }
        if depth is None or any(not isinstance(value, str) or not value for value in values.values()):
            errors.append(f"Loki {agent_id or '?'} {event_name} has incomplete canonical identity/depth")
            continue
        candidate = GoldenAgent(
            agent_id=str(agent_id),
            session_id=str(values["session_id"]),
            root_id=str(values["root_id"]),
            parent_id=str(body.get("defenseclaw.agent.parent.id") or ""),
            root_session_id=str(values["root_session_id"]),
            parent_session_id=str(body.get("defenseclaw.session.parent.id") or ""),
            lifecycle_id=str(values["lifecycle_id"]),
            execution_id=str(values["execution_id"]),
            depth=depth,
        )
        previous = agents.get(candidate.agent_id)
        if previous is not None and previous != candidate:
            errors.append(f"Loki {candidate.agent_id} has conflicting lineage/session/lifecycle/execution/depth")
        else:
            agents[candidate.agent_id] = candidate

    roots = [agent for agent in agents.values() if not agent.parent_id]
    if len(roots) != 1:
        errors.append(f"Loki golden tree has {len(roots)} roots, want exactly one")
        return agents, errors
    root = roots[0]
    if root.depth != 0 or root.root_id != root.agent_id or root.root_session_id != root.session_id:
        errors.append("Loki golden root has incorrect root/session/depth identity")
    for agent in agents.values():
        if agent.root_id != root.agent_id or agent.root_session_id != root.session_id:
            errors.append(f"Loki {agent.agent_id} lost canonical root identity")
        if not agent.parent_id:
            if agent.parent_session_id:
                errors.append(f"Loki root {agent.agent_id} fabricated a parent session")
            continue
        parent = agents.get(agent.parent_id)
        if parent is None:
            errors.append(f"Loki {agent.agent_id} references missing parent {agent.parent_id}")
            continue
        if agent.parent_session_id != parent.session_id:
            errors.append(f"Loki {agent.agent_id} has incorrect parent session identity")
        if agent.depth != parent.depth + 1:
            errors.append(
                f"Loki {agent.agent_id} depth={agent.depth}, want parent depth {parent.depth} + 1",
            )
    max_depth = max((agent.depth for agent in agents.values()), default=-1)
    if max_depth < 3:
        errors.append(f"Loki golden tree max depth={max_depth}, want at least depth 3")
    return agents, errors


def _golden_identity_problems(record: dict[str, Any], agent: GoldenAgent, stamp: str) -> list[str]:
    body = record.get("body", {})
    correlation = record.get("correlation", {})
    projection = record.get("projection", {})
    if not isinstance(body, dict):
        return ["body"]
    expected_body: dict[str, Any] = {
        "gen_ai.agent.id": agent.agent_id,
        "gen_ai.conversation.id": agent.session_id,
        "defenseclaw.agent.root.id": agent.root_id,
        "defenseclaw.session.root.id": agent.root_session_id,
        "defenseclaw.agent.lifecycle.id": agent.lifecycle_id,
        "defenseclaw.agent.execution.id": agent.execution_id,
        "defenseclaw.agent.depth": agent.depth,
    }
    if agent.parent_id:
        expected_body["defenseclaw.agent.parent.id"] = agent.parent_id
        expected_body["defenseclaw.session.parent.id"] = agent.parent_session_id
    problems: list[str] = []
    for key, expected in expected_body.items():
        actual = body.get(key)
        if key == "defenseclaw.agent.depth":
            actual = _golden_int(actual)
        if actual != expected:
            problems.append(key)
    if not agent.parent_id and (
        body.get("defenseclaw.agent.parent.id") or body.get("defenseclaw.session.parent.id")
    ):
        problems.append("root parent identity")
    expected_correlation = {
        "run_id": f"golden-run-{stamp}",
        "request_id": f"golden-request-{stamp}",
        "turn_id": f"golden-turn-{stamp}",
        "agent_id": agent.agent_id,
        "session_id": agent.session_id,
        "connector_id": "codex",
    }
    if not isinstance(correlation, dict) or any(
        correlation.get(key) != value for key, value in expected_correlation.items()
    ):
        problems.append("correlation")
    if (
        not isinstance(projection, dict)
        or projection.get("state") != "raw"
        or projection.get("redaction_profile") != "none"
    ):
        problems.append("raw projection")
    phase = body.get("defenseclaw.agent.phase")
    phase_code = _golden_int(body.get("defenseclaw.agent.phase.code"))
    if phase not in GOLDEN_PHASE_CODES or phase_code != GOLDEN_PHASE_CODES[phase]:
        problems.append("phase/code")
    return problems


def _golden_log_errors(
    records: list[dict[str, Any]],
    stamp: str,
    agents: dict[str, GoldenAgent],
) -> tuple[list[str], set[str], set[str], str, list[dict[str, Any]]]:
    errors: list[str] = []
    selected_records = _golden_records_for_stamp(records, stamp)
    selected: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in selected_records:
        body = record.get("body", {})
        event_name = record.get("event_name")
        if not isinstance(body, dict) or not isinstance(event_name, str):
            continue
        agent_id = str(body.get("gen_ai.agent.id") or "")
        selected.setdefault((agent_id, event_name), []).append(record)

    roots = [agent for agent in agents.values() if not agent.parent_id]
    root = roots[0] if len(roots) == 1 else None
    model_agents = {
        agent_id for agent_id, event_name in selected if event_name == "model.response"
    }
    tool_agents = {
        agent_id for agent_id, event_name in selected if event_name == "tool.invocation.completed"
    }
    approval_agents = {
        agent_id for agent_id, event_name in selected if event_name == "approval.resolved"
    }
    conversation_prompt_records = [
        record
        for record in selected_records
        if record.get("event_name") == "hook_decision"
        and isinstance(record.get("body"), dict)
        and record["body"].get("defenseclaw.hook.event") == "UserPromptSubmit"
    ]
    approval_tool_agent_id = next(iter(approval_agents)) if len(approval_agents) == 1 else ""
    if not approval_agents and tool_agents:
        deepest_tool_depth = max(
            (agents[agent_id].depth for agent_id in tool_agents if agent_id in agents),
            default=-1,
        )
        deepest_tool_agents = {
            agent_id
            for agent_id in tool_agents
            if agent_id in agents and agents[agent_id].depth == deepest_tool_depth
        }
        if len(deepest_tool_agents) == 1:
            approval_tool_agent_id = next(iter(deepest_tool_agents))
    if len(model_agents) != 2:
        errors.append(f"Loki golden run has {len(model_agents)} model agents, want exactly two")
    if len(tool_agents) != 2:
        errors.append(f"Loki golden run has {len(tool_agents)} tool agents, want exactly two")
    if len(approval_agents) != 1:
        errors.append(
            f"Loki golden run has {len(approval_agents)} approval-bearing agents, want exactly one",
        )
    if approval_tool_agent_id and approval_tool_agent_id not in tool_agents:
        errors.append("Loki golden approval agent has no completed tool invocation")
    if root is not None:
        if root.agent_id not in model_agents:
            errors.append("Loki golden root has no completed model operation")
        if root.agent_id not in tool_agents:
            errors.append("Loki golden root has no completed tool operation")
        if len(conversation_prompt_records) != 1:
            errors.append(
                "Loki golden root conversation prompt decisions="
                f"{len(conversation_prompt_records)}, want exactly one UserPromptSubmit",
            )
        else:
            prompt_record = conversation_prompt_records[0]
            prompt_body = prompt_record["body"]
            prompt_agent_id = str(prompt_body.get("gen_ai.agent.id") or "")
            if (
                prompt_agent_id != root.agent_id
                or _golden_int(prompt_body.get("defenseclaw.agent.depth")) != 0
                or prompt_body.get("defenseclaw.agent.parent.id")
                or prompt_body.get("defenseclaw.session.parent.id")
                or prompt_body.get("defenseclaw.hook.result") != "ok"
                or prompt_body.get("defenseclaw.guardrail.effective_action") != "allow"
                or prompt_body.get("defenseclaw.guardrail.raw_action") != "allow"
                or prompt_body.get("defenseclaw.guardrail.mode") != "enforce"
                or prompt_record.get("outcome") != "allowed"
            ):
                errors.append(
                    "Loki golden UserPromptSubmit decision is not a truthful allowed depth-zero root prompt",
                )
        non_root_non_leaf_agents = {
            agent.parent_id
            for agent in agents.values()
            if agent.parent_id and agent.parent_id != root.agent_id
        }
        if not non_root_non_leaf_agents.intersection(model_agents | tool_agents):
            errors.append("Loki golden tree has no non-leaf subagent with model or tool work")

    required: dict[str, set[str]] = {}
    if root is not None:
        required[root.agent_id] = {"session_start", "turn_start", "model.request", "session_end"}
    for agent in agents.values():
        if agent.parent_id:
            required.setdefault(agent.agent_id, set()).update({"subagent_start", "subagent_stop"})
    for model_agent_id in model_agents:
        required.setdefault(model_agent_id, set()).update(
            {"turn_start", "turn_end", "model.request", "model.response"},
        )
    for tool_agent_id in tool_agents:
        required.setdefault(tool_agent_id, set()).update(
            {"tool_start", "tool_end", "tool.invocation.requested", "tool.invocation.completed"},
        )
    generic_records = [record for record in selected_records if record.get("event_name") == "event"]
    if len(generic_records) != 1:
        errors.append(
            f"Loki golden run has {len(generic_records)} correlated generic lifecycle observations, want exactly one",
        )
    else:
        generic_body = generic_records[0].get("body", {})
        generic_agent_id = str(generic_body.get("gen_ai.agent.id") or "")
        generic_agent = agents.get(generic_agent_id)
        if (
            generic_agent is None
            or not generic_agent.parent_id
            or generic_body.get("defenseclaw.agent.parent.id") != generic_agent.parent_id
            or not str(generic_body.get("defenseclaw.operation.id") or "")
        ):
            errors.append(
                "Loki nested-owned generic lifecycle observation is missing canonical parent lineage "
                "or operation identity",
            )
    for agent_id, event_names in sorted(required.items()):
        for event_name in sorted(event_names):
            count = len(selected.get((agent_id, event_name), []))
            if count == 0:
                label = "root initial prompt/turn" if root and agent_id == root.agent_id and event_name in {
                    "turn_start",
                    "model.request",
                } else event_name
                errors.append(f"Loki is missing {agent_id} {label} for golden run {stamp}")
            elif count != 1:
                errors.append(f"Loki {agent_id} {event_name} occurrences={count}, want exactly one")

    record_ids = [record.get("record_id") for record in selected_records]
    if any(not isinstance(record_id, str) or not record_id for record_id in record_ids):
        errors.append(f"Loki golden run {stamp} contains a record without a stable occurrence ID")
    if len(record_ids) != len(set(record_ids)):
        errors.append(f"Loki golden run {stamp} contains duplicate occurrence IDs")

    for record in selected_records:
        event_name = str(record.get("event_name") or "")
        if event_name in GOLDEN_REQUIRED_APPROVAL_EVENTS:
            continue
        body = record.get("body", {})
        agent_id = str(body.get("gen_ai.agent.id") or "") if isinstance(body, dict) else ""
        agent = agents.get(agent_id)
        if agent is None:
            errors.append(f"Loki {event_name} references unknown golden agent {agent_id or '?'}")
            continue
        problems = _golden_identity_problems(record, agent, stamp)
        serialized_body = json.dumps(body, sort_keys=True)
        if event_name.startswith(("model.", "tool.invocation.")) and not any(
            marker in serialized_body
            for marker in ("local-observability golden", "local-observability-golden")
        ):
            problems.append("unredacted golden content")
        if event_name in {"model.response", "model.call.failed"} and (
            not str(body.get("gen_ai.provider.name") or "")
            or not str(body.get("gen_ai.response.model") or body.get("gen_ai.request.model") or "")
        ):
            problems.append("model summary identity")
        if event_name in {
            "tool.invocation.completed",
            "tool.invocation.failed",
            "tool.invocation.blocked",
        } and not str(body.get("gen_ai.tool.name") or ""):
            problems.append("tool summary identity")
        if problems:
            errors.append(
                f"Loki {agent_id} {event_name} violates {', '.join(sorted(set(problems)))}",
            )

    if root is not None:
        prompt_candidates = selected.get((root.agent_id, "model.request"), [])
        if len(prompt_candidates) == 1 and GOLDEN_INITIAL_PROMPT_MARKER not in json.dumps(
            prompt_candidates[0].get("body", {}),
            sort_keys=True,
        ):
            errors.append(f"Loki root initial prompt marker is missing for golden run {stamp}")

    lifecycle_by_agent: dict[str, list[dict[str, Any]]] = {}
    terminal_records: list[dict[str, Any]] = []
    for record in selected_records:
        event_name = record.get("event_name")
        body = record.get("body", {})
        if event_name not in GOLDEN_LIFECYCLE_EVENTS or not isinstance(body, dict):
            continue
        agent_id = str(body.get("gen_ai.agent.id") or "")
        lifecycle_by_agent.setdefault(agent_id, []).append(record)
        if event_name in GOLDEN_TERMINAL_EVENTS:
            terminal_records.append(record)
        state = body.get("defenseclaw.agent.lifecycle.state")
        outcome = record.get("outcome")
        if event_name in {"session_end", "subagent_stop", "turn_end"} and (
            state != "completed" or outcome != "completed"
        ):
            errors.append(f"Loki {agent_id} {event_name} has incorrect terminal state/outcome")
        if event_name == "tool_end" and (state != "active" or outcome != "completed"):
            errors.append(f"Loki {agent_id} tool_end has incorrect state/outcome")
        if event_name == "event" and (state != "observed" or outcome not in {None, ""}):
            errors.append(
                f"Loki {agent_id} generic lifecycle observation has incorrect observed state/outcome",
            )

    ordered = sorted(selected_records, key=lambda record: str(record.get("timestamp") or ""))
    if any(not isinstance(record.get("timestamp"), str) or not record.get("timestamp") for record in ordered):
        errors.append(f"Loki golden run {stamp} contains a record without source ordering time")
    positions: dict[tuple[str, str], int] = {}
    for index, record in enumerate(ordered):
        body = record.get("body", {})
        if isinstance(body, dict):
            positions.setdefault(
                (str(body.get("gen_ai.agent.id") or ""), str(record.get("event_name") or "")),
                index,
            )
    for agent_id, agent_records in lifecycle_by_agent.items():
        agent_records.sort(key=lambda record: str(record.get("timestamp") or ""))
        sequences = [
            _golden_int(record.get("body", {}).get("defenseclaw.agent.sequence"))
            for record in agent_records
        ]
        if any(sequence is None for sequence in sequences) or any(
            right <= left
            for left, right in zip(sequences, sequences[1:])
            if left is not None and right is not None
        ):
            errors.append(f"Loki {agent_id} lifecycle sequence is not strictly monotonic: {sequences}")

    if root is not None:
        prompt_position = positions.get((root.agent_id, "model.request"))
        turn_position = positions.get((root.agent_id, "turn_start"))
        conversation_prompt_position = positions.get((root.agent_id, "hook_decision"))
        if (
            turn_position is not None
            and conversation_prompt_position is not None
            and prompt_position is not None
            and not turn_position < conversation_prompt_position < prompt_position
        ):
            errors.append(
                "Loki root UserPromptSubmit decision must follow turn_start and precede the initial model prompt",
            )
        for agent in agents.values():
            if not agent.parent_id:
                continue
            child_start = positions.get((agent.agent_id, "subagent_start"))
            if prompt_position is not None and child_start is not None and prompt_position >= child_start:
                errors.append(f"Loki root initial prompt does not precede delegation to {agent.agent_id}")
            if turn_position is not None and child_start is not None and turn_position >= child_start:
                errors.append(f"Loki root turn_start does not precede delegation to {agent.agent_id}")
            parent = agents.get(agent.parent_id)
            if parent is None:
                continue
            parent_start_event = "session_start" if not parent.parent_id else "subagent_start"
            parent_terminal_event = "session_end" if not parent.parent_id else "subagent_stop"
            parent_start = positions.get((parent.agent_id, parent_start_event))
            child_stop = positions.get((agent.agent_id, "subagent_stop"))
            parent_stop = positions.get((parent.agent_id, parent_terminal_event))
            if parent_start is not None and child_start is not None and parent_start >= child_start:
                errors.append(f"Loki parent {parent.agent_id} starts after child {agent.agent_id}")
            if child_stop is not None and parent_stop is not None and child_stop >= parent_stop:
                errors.append(f"Loki child {agent.agent_id} terminates after parent {parent.agent_id}")
    for model_agent_id in sorted(model_agents):
        model_positions = [
            positions.get((model_agent_id, event))
            for event in ("model.request", "model.response", "turn_end")
        ]
        if all(position is not None for position in model_positions) and model_positions != sorted(model_positions):
            errors.append(f"Loki {model_agent_id} model request/response/terminal ordering is invalid")
    for tool_agent_id in sorted(tool_agents):
        tool_events = ["tool_start", "tool.invocation.requested"]
        if tool_agent_id == approval_tool_agent_id:
            tool_events.extend(["approval.requested", "approval.resolved"])
        tool_events.extend(["tool.invocation.completed", "tool_end"])
        tool_positions = [
            positions.get((tool_agent_id, event))
            for event in tool_events
        ]
        if all(position is not None for position in tool_positions) and any(
            right <= left
            for left, right in zip(tool_positions, tool_positions[1:])
            if left is not None and right is not None
        ):
            errors.append(
                f"Loki {tool_agent_id} tool/approval causal order is invalid; want "
                + " < ".join(tool_events),
            )
    return errors, model_agents, tool_agents, approval_tool_agent_id, terminal_records


def _golden_approval_log_errors(
    records: list[dict[str, Any]],
    stamp: str,
    tool_agent: GoldenAgent | None,
) -> list[str]:
    """Require one raw canonical request/resolution pair inside the tool trace."""

    if tool_agent is None:
        return [f"Loki cannot associate golden approvals with a tool agent for run {stamp}"]
    errors: list[str] = []
    approval_id = f"golden-approval-{stamp}"
    expected_correlation = {
        "run_id": f"golden-run-{stamp}",
        "request_id": f"golden-request-{stamp}",
        "session_id": tool_agent.session_id,
        "turn_id": f"golden-turn-{stamp}",
        "agent_id": tool_agent.agent_id,
        "connector_id": "codex",
    }
    selected: dict[str, list[dict[str, Any]]] = {}
    for record in _golden_records_for_stamp(records, stamp):
        body = record.get("body", {})
        if not isinstance(body, dict) or body.get("gen_ai.agent.id") != tool_agent.agent_id:
            continue
        event_name = record.get("event_name")
        if event_name in GOLDEN_REQUIRED_APPROVAL_EVENTS:
            selected.setdefault(str(event_name), []).append(record)
    for event_name in sorted(GOLDEN_REQUIRED_APPROVAL_EVENTS):
        candidates = selected.get(event_name, [])
        if len(candidates) != 1:
            errors.append(
                f"Loki is missing {tool_agent.agent_id} {event_name}"
                if not candidates
                else f"Loki {tool_agent.agent_id} {event_name} occurrences={len(candidates)}, want one",
            )
            continue
        record = candidates[0]
        body = record.get("body", {})
        correlation = record.get("correlation", {})
        projection = record.get("projection", {})
        problems = _golden_identity_problems(record, tool_agent, stamp)
        if body.get("defenseclaw.approval.id") != approval_id:
            problems.append("approval identity")
        if event_name == "approval.resolved" and body.get("defenseclaw.approval.result") != "approved":
            problems.append("approval result")
        if not isinstance(correlation, dict) or any(
            correlation.get(key) != value for key, value in expected_correlation.items()
        ):
            problems.append("correlation")
        if not isinstance(correlation, dict) or not re.fullmatch(
            r"[0-9a-f]{32}",
            str(correlation.get("trace_id", "")),
        ):
            problems.append("W3C trace correlation")
        if (
            not isinstance(projection, dict)
            or projection.get("state") != "raw"
            or projection.get("redaction_profile") != "none"
        ):
            problems.append("raw projection")
        if "local-observability-golden-approval" not in json.dumps(body, sort_keys=True):
            problems.append("unredacted approval content")
        if problems:
            errors.append(
                f"Loki {tool_agent.agent_id} {event_name} violates {', '.join(sorted(set(problems)))}",
            )
    requested = selected.get("approval.requested", [])
    resolved = selected.get("approval.resolved", [])
    if len(requested) == 1 and len(resolved) == 1:
        requested_sequence = _golden_int(requested[0].get("body", {}).get("defenseclaw.agent.sequence"))
        resolved_sequence = _golden_int(resolved[0].get("body", {}).get("defenseclaw.agent.sequence"))
        requested_timestamp = str(requested[0].get("timestamp") or "")
        resolved_timestamp = str(resolved[0].get("timestamp") or "")
        if (
            requested_sequence is None
            or resolved_sequence is None
            or requested_sequence >= resolved_sequence
            or not requested_timestamp
            or requested_timestamp >= resolved_timestamp
        ):
            errors.append("Loki approval.requested must precede approval.resolved by timestamp and sequence")
    return errors


def _prometheus_parent_matches(metric: dict[str, Any], parent_id: str) -> bool:
    value = metric.get("defenseclaw_agent_parent_id")
    return value == parent_id if parent_id else value in {None, "", "none"}


def _golden_metric_errors(
    last_seen: list[dict[str, Any]],
    lifecycle_transitions: list[dict[str, Any]],
    phase_transitions: list[dict[str, Any]],
    records: list[dict[str, Any]],
    stamp: str,
    agents: dict[str, GoldenAgent],
) -> list[str]:
    errors: list[str] = []
    observed_last_seen: set[str] = set()
    for series in last_seen:
        metric = series.get("metric", {})
        if not isinstance(metric, dict) or not _positive_prometheus_series(series):
            continue
        identity = _golden_agent_role_stamp(metric.get("gen_ai_agent_id"))
        if identity is None or identity[1] != stamp:
            continue
        agent_id = str(metric.get("gen_ai_agent_id") or "")
        agent = agents.get(agent_id)
        if agent is None:
            errors.append(f"Prometheus last_seen references unknown golden agent {agent_id}")
            continue
        if (
            metric.get("connector") != "codex"
            or metric.get("defenseclaw_agent_root_id") != agent.root_id
            or metric.get("defenseclaw_session_root_id") != agent.root_session_id
            or metric.get("defenseclaw_agent_lifecycle_id") != agent.lifecycle_id
            or metric.get("defenseclaw_agent_execution_id") != agent.execution_id
            or not _prometheus_parent_matches(metric, agent.parent_id)
        ):
            errors.append(f"Prometheus last_seen identity drifted for {agent.agent_id}")
            continue
        observed_last_seen.add(agent.agent_id)
    for agent in agents.values():
        if agent.agent_id not in observed_last_seen:
            errors.append(f"Prometheus is missing canonical Agent360 last_seen identity for {agent.agent_id}")

    expected_lifecycle: set[tuple[str, str, str]] = set()
    expected_phases: set[tuple[str, str, str]] = set()
    for record in _golden_records_for_stamp(records, stamp):
        event_name = record.get("event_name")
        body = record.get("body", {})
        if event_name not in GOLDEN_LIFECYCLE_EVENTS or not isinstance(body, dict):
            continue
        agent_id = str(body.get("gen_ai.agent.id") or "")
        expected_lifecycle.add(
            (agent_id, str(event_name), str(body.get("defenseclaw.agent.lifecycle.state") or "")),
        )
        previous = str(body.get("defenseclaw.agent.phase.previous") or "")
        phase = str(body.get("defenseclaw.agent.phase") or "")
        if previous and phase and previous != phase:
            expected_phases.add((agent_id, previous, phase))

    observed_lifecycle: set[tuple[str, str, str]] = set()
    for series in lifecycle_transitions:
        metric = series.get("metric", {})
        if not isinstance(metric, dict) or not _positive_prometheus_series(series):
            continue
        agent = agents.get(str(metric.get("gen_ai_agent_id") or ""))
        if agent is None:
            identity = _golden_agent_role_stamp(metric.get("gen_ai_agent_id"))
            if identity is not None and identity[1] == stamp:
                errors.append(
                    "Prometheus lifecycle transition references unknown golden agent "
                    f"{metric.get('gen_ai_agent_id')}",
                )
            continue
        if (
            metric.get("connector") != "codex"
            or metric.get("defenseclaw_agent_root_id") != agent.root_id
            or metric.get("defenseclaw_session_root_id") != agent.root_session_id
            or metric.get("defenseclaw_agent_lifecycle_id") != agent.lifecycle_id
            or metric.get("defenseclaw_agent_execution_id") != agent.execution_id
            or _golden_int(metric.get("defenseclaw_agent_depth")) != agent.depth
            or not _prometheus_parent_matches(metric, agent.parent_id)
        ):
            errors.append(f"Prometheus lifecycle identity drifted for {agent.agent_id}")
            continue
        observed_lifecycle.add(
            (
                agent.agent_id,
                str(metric.get("defenseclaw_agent_lifecycle_event") or ""),
                str(metric.get("defenseclaw_agent_lifecycle_state") or ""),
            ),
        )
    for agent_id, event_name, state in sorted(expected_lifecycle - observed_lifecycle):
        errors.append(f"Prometheus is missing lifecycle transition {agent_id}: {event_name}/{state}")

    observed_phases = {
        (
            str(series.get("metric", {}).get("gen_ai_agent_id") or ""),
            str(series.get("metric", {}).get("defenseclaw_agent_phase_from") or ""),
            str(series.get("metric", {}).get("defenseclaw_agent_phase_to") or ""),
        )
        for series in phase_transitions
        if isinstance(series.get("metric"), dict)
        and series["metric"].get("connector") == "codex"
        and _positive_prometheus_series(series)
    }
    for agent_id, phase_from, phase_to in sorted(expected_phases - observed_phases):
        errors.append(f"Prometheus is missing native phase transition {agent_id}: {phase_from} -> {phase_to}")
    return errors


def _golden_topology(
    spans: list[dict[str, Any]],
    stamp: str,
    agents: dict[str, GoldenAgent],
    model_agent_ids: set[str],
    tool_agent_ids: set[str],
    approval_tool_agent_id: str,
) -> tuple[str, list[dict[str, Any]]] | None:
    roots = [agent for agent in agents.values() if not agent.parent_id]
    if (
        len(roots) != 1
        or not model_agent_ids
        or not tool_agent_ids
        or approval_tool_agent_id not in tool_agent_ids
    ):
        return None
    by_trace: dict[str, list[dict[str, Any]]] = {}
    for span in spans:
        by_trace.setdefault(span["trace_id"], []).append(span)
    for trace_id, trace_spans in by_trace.items():
        invocations: dict[str, dict[str, Any]] = {}
        for agent_id in agents:
            candidates = [
                span
                for span in trace_spans
                if span["attributes"].get("defenseclaw.span.family") == "span.agent.invoke"
                and span["attributes"].get("gen_ai.agent.id") == agent_id
            ]
            if len(candidates) != 1:
                break
            invocations[agent_id] = candidates[0]
        if len(invocations) != len(agents):
            continue
        valid_tree = True
        for agent in agents.values():
            span = invocations[agent.agent_id]
            if not agent.parent_id:
                valid_tree = not span["parent_span_id"]
            else:
                valid_tree = span["parent_span_id"] == invocations[agent.parent_id]["span_id"]
            if not valid_tree:
                break
        if not valid_tree:
            continue
        models = {
            agent_id: [
                span
                for span in trace_spans
                if span["attributes"].get("defenseclaw.span.family") == "span.model.chat"
                and span["attributes"].get("gen_ai.agent.id") == agent_id
                and span["parent_span_id"] == invocations[agent_id]["span_id"]
            ]
            for agent_id in model_agent_ids
        }
        tools = {
            agent_id: [
                span
                for span in trace_spans
                if span["attributes"].get("defenseclaw.span.family") == "span.tool.execute"
                and span["attributes"].get("gen_ai.agent.id") == agent_id
                and span["parent_span_id"] == invocations[agent_id]["span_id"]
            ]
            for agent_id in tool_agent_ids
        }
        if any(len(candidates) != 1 for candidates in [*models.values(), *tools.values()]):
            continue
        turn_transitions = {
            agent_id: [
                span
                for span in trace_spans
                if span["attributes"].get("defenseclaw.span.family") == "span.agent.transition"
                and span["attributes"].get("defenseclaw.agent.lifecycle.event") == "turn_end"
                and span["attributes"].get("gen_ai.agent.id") == agent_id
            ]
            for agent_id in model_agent_ids
        }
        if any(len(candidates) != 1 for candidates in turn_transitions.values()):
            continue
        approval_tool = tools[approval_tool_agent_id][0]
        approvals = [
            span
            for span in trace_spans
            if span["attributes"].get("defenseclaw.span.family") == "span.approval.resolve"
            and span["attributes"].get("gen_ai.agent.id") == approval_tool_agent_id
            and span["attributes"].get("defenseclaw.approval.id") == f"golden-approval-{stamp}"
            and span["parent_span_id"] == approval_tool["span_id"]
        ]
        if len(approvals) == 1:
            ordered_agents = sorted(agents.values(), key=lambda agent: agent.depth)
            return trace_id, [
                *(invocations[agent.agent_id] for agent in ordered_agents),
                *(models[agent_id][0] for agent_id in sorted(models)),
                *(tools[agent_id][0] for agent_id in sorted(tools)),
                *(turn_transitions[agent_id][0] for agent_id in sorted(turn_transitions)),
                approvals[0],
            ]
    return None


def _golden_trace_errors(
    spans: list[dict[str, Any]],
    stamp: str,
    agents: dict[str, GoldenAgent],
    model_agent_ids: set[str],
    tool_agent_ids: set[str],
    approval_tool_agent_id: str,
) -> tuple[list[str], str]:
    topology = _golden_topology(
        spans,
        stamp,
        agents,
        model_agent_ids,
        tool_agent_ids,
        approval_tool_agent_id,
    )
    if topology is None:
        summaries: list[str] = []
        for trace_id in sorted({span["trace_id"] for span in spans}):
            names = sorted(
                f"{span['attributes'].get('defenseclaw.span.family', '?')}:"
                f"{span['attributes'].get('gen_ai.agent.id', '?')}"
                for span in spans
                if span["trace_id"] == trace_id
                and (_golden_agent_role_stamp(span["attributes"].get("gen_ai.agent.id")) or ("", ""))[1]
                == stamp
            )
            if names:
                summaries.append(f"{trace_id}=[{', '.join(names)}]")
        observed = "; ".join(summaries) or "no matching golden spans"
        return [
            f"Tempo is missing one W3C agent topology containing {len(agents)} correlated agents, "
            f"{len(model_agent_ids)} model children, {len(tool_agent_ids)} tool children, "
            f"{len(model_agent_ids)} turn-end transitions, and one tool-child approval; observed {observed}",
        ], ""

    trace_id, selected = topology
    errors: list[str] = []
    span_ids = {span["span_id"] for span in selected}
    if "" in span_ids or len(span_ids) != len(selected):
        errors.append("Tempo golden topology contains missing or duplicate W3C span IDs")
    spans_by_id = {span["span_id"]: span for span in selected if span["span_id"]}
    for span in selected:
        started_at = span["start_time_unix_nano"]
        finished_at = span["end_time_unix_nano"]
        if started_at <= 0 or finished_at < started_at:
            errors.append(f"Tempo span {span['name']} has invalid temporal bounds")
            continue
        parent = spans_by_id.get(span["parent_span_id"])
        if parent is None:
            continue
        if (
            started_at < parent["start_time_unix_nano"]
            or finished_at > parent["end_time_unix_nano"]
        ):
            if span["attributes"].get("defenseclaw.span.family") == "span.approval.resolve":
                errors.append("Tempo golden approval span falls outside its parent tool span")
            else:
                errors.append(f"Tempo span {span['name']} falls outside its parent span")
    for span in selected:
        attributes = span["attributes"]
        agent_id = str(attributes.get("gen_ai.agent.id") or "")
        family = attributes.get("defenseclaw.span.family")
        if family == "span.approval.resolve":
            tool_agent = agents.get(approval_tool_agent_id)
            expected = {
                "defenseclaw.run.id": f"golden-run-{stamp}",
                "gen_ai.conversation.id": tool_agent.session_id if tool_agent else "",
                "gen_ai.agent.id": tool_agent.agent_id if tool_agent else "",
                "defenseclaw.agent.root.id": tool_agent.root_id if tool_agent else "",
                "defenseclaw.session.root.id": tool_agent.root_session_id if tool_agent else "",
                "defenseclaw.agent.lifecycle.id": tool_agent.lifecycle_id if tool_agent else "",
                "defenseclaw.agent.execution.id": tool_agent.execution_id if tool_agent else "",
                "defenseclaw.agent.phase": "approval",
                "defenseclaw.agent.sequence": 4,
                "defenseclaw.approval.id": f"golden-approval-{stamp}",
                "defenseclaw.approval.result": "approved",
            }
            if tool_agent and tool_agent.parent_id:
                expected["defenseclaw.agent.parent.id"] = tool_agent.parent_id
                expected["defenseclaw.session.parent.id"] = tool_agent.parent_session_id
            if tool_agent and _golden_int(attributes.get("defenseclaw.agent.depth")) != tool_agent.depth:
                errors.append("Tempo golden approval span has incorrect agent depth")
            if span["name"] != "exec.approval":
                errors.append("Tempo golden approval span has incorrect canonical name")
        else:
            agent = agents.get(agent_id)
            if agent is None:
                errors.append(f"Tempo span {span['name']} references unknown agent {agent_id}")
                continue
            expected = {
                "gen_ai.conversation.id": agent.session_id,
                "defenseclaw.agent.root.id": agent.root_id,
                "defenseclaw.session.root.id": agent.root_session_id,
                "defenseclaw.agent.lifecycle.id": agent.lifecycle_id,
                "defenseclaw.agent.execution.id": agent.execution_id,
                "defenseclaw.run.id": f"golden-run-{stamp}",
                "defenseclaw.request.id": f"golden-request-{stamp}",
                "defenseclaw.turn.id": f"golden-turn-{stamp}",
            }
            if _golden_int(attributes.get("defenseclaw.agent.depth")) != agent.depth:
                errors.append(f"Tempo span {span['name']} has incorrect agent depth")
            if agent.parent_id:
                expected["defenseclaw.agent.parent.id"] = agent.parent_id
                expected["defenseclaw.session.parent.id"] = agent.parent_session_id
            elif attributes.get("defenseclaw.agent.parent.id") or attributes.get(
                "defenseclaw.session.parent.id",
            ):
                errors.append(f"Tempo root span {span['name']} fabricated parent identity")
        if any(
            (_golden_int(attributes.get(key)) if isinstance(value, int) else attributes.get(key)) != value
            for key, value in expected.items()
        ):
            errors.append(f"Tempo span {span['name']} has incomplete golden correlation")
        if span["wire_trace_id"] != trace_id:
            errors.append(f"Tempo span {span['name']} carries a mismatched W3C trace ID")

    terminal_span_ids: list[str] = []
    for agent in agents.values():
        terminal_event = "session_end" if not agent.parent_id else "subagent_stop"
        candidates = [
            span
            for span in spans
            if span["attributes"].get("defenseclaw.span.family") == "span.agent.transition"
            and span["attributes"].get("gen_ai.agent.id") == agent.agent_id
            and span["attributes"].get("defenseclaw.agent.lifecycle.event") == terminal_event
        ]
        if len(candidates) != 1:
            errors.append(
                f"Tempo terminal transition count for {agent.agent_id}/{terminal_event} is "
                f"{len(candidates)}, want exactly one",
            )
            continue
        span = candidates[0]
        attributes = span["attributes"]
        expected = {
            "gen_ai.conversation.id": agent.session_id,
            "defenseclaw.agent.root.id": agent.root_id,
            "defenseclaw.session.root.id": agent.root_session_id,
            "defenseclaw.agent.lifecycle.id": agent.lifecycle_id,
            "defenseclaw.agent.execution.id": agent.execution_id,
            "defenseclaw.agent.lifecycle.state": "completed",
        }
        if agent.parent_id:
            expected["defenseclaw.agent.parent.id"] = agent.parent_id
            expected["defenseclaw.session.parent.id"] = agent.parent_session_id
        elif attributes.get("defenseclaw.agent.parent.id") or attributes.get(
            "defenseclaw.session.parent.id",
        ):
            errors.append(f"Tempo terminal root {agent.agent_id} fabricated canonical parent identity")
        if any(attributes.get(key) != value for key, value in expected.items()) or (
            _golden_int(attributes.get("defenseclaw.agent.depth")) != agent.depth
        ):
            errors.append(
                f"Tempo terminal transition has incomplete canonical IDs for {agent.agent_id}/{terminal_event}",
            )
        if not span["span_id"]:
            errors.append(f"Tempo terminal transition {agent.agent_id}/{terminal_event} has a missing span ID")
        else:
            terminal_span_ids.append(span["span_id"])
        if span["parent_span_id"]:
            errors.append(
                f"Tempo terminal transition {agent.agent_id}/{terminal_event} is not a request-bounded root",
            )
        if span["wire_trace_id"] != span["trace_id"]:
            errors.append(
                f"Tempo terminal transition {agent.agent_id}/{terminal_event} has a mismatched wire trace ID",
            )
    if len(terminal_span_ids) != len(set(terminal_span_ids)):
        errors.append("Tempo terminal transitions contain duplicate span IDs")
    return errors, trace_id


def _golden_cross_signal_trace_errors(
    records: list[dict[str, Any]],
    stamp: str,
    trace_id: str,
) -> list[str]:
    errors: list[str] = []
    for record in _golden_records_for_stamp(records, stamp):
        event_name = str(record.get("event_name") or "")
        if event_name in GOLDEN_TERMINAL_EVENTS:
            # Independent hook deliveries are truthful request-bounded roots.
            # Their stable identity join is validated above; do not fabricate
            # a parent just to make every lifecycle record share one trace.
            continue
        correlation = record.get("correlation", {})
        if not isinstance(correlation, dict) or correlation.get("trace_id") != trace_id:
            errors.append(f"Loki {event_name} does not correlate to the golden operation trace")
    return errors


def _dashboard_targets(uid: str, title: str) -> list[dict[str, Any]]:
    for _, dashboard in load_dashboards(SOURCE_DIR):
        if dashboard.get("uid") != uid:
            continue
        for panel in panels(dashboard):
            if panel.get("title") == title and panel.get("targets"):
                return panel["targets"]
    raise AuditError(f"Golden gate cannot find {uid}/{title!r} target")


def _dashboard_target(uid: str, title: str) -> dict[str, Any]:
    return _dashboard_targets(uid, title)[0]


def _agent360_target(title: str) -> dict[str, Any]:
    return _dashboard_target("defenseclaw-agent-360", title)


def _agent360_targets(title: str) -> list[dict[str, Any]]:
    return _dashboard_targets("defenseclaw-agent-360", title)


def _approval_chronology_errors(
    lines: list[tuple[int, str]],
    *,
    label: str,
) -> list[str]:
    positions = {
        event_name: [timestamp_ns for timestamp_ns, line in lines if event_name in line]
        for event_name in sorted(GOLDEN_REQUIRED_APPROVAL_EVENTS)
    }
    errors: list[str] = []
    for event_name, timestamps in positions.items():
        if len(timestamps) != 1:
            errors.append(f"{label} returned {len(timestamps)} {event_name} rows, want exactly one")
    requested = positions["approval.requested"]
    resolved = positions["approval.resolved"]
    if len(requested) == 1 and len(resolved) == 1 and requested[0] >= resolved[0]:
        errors.append(f"{label} must show approval.requested precedes approval.resolved")
    return errors


def _golden_agent360_errors(
    agents: dict[str, GoldenAgent],
    trace_id: str,
    records: list[dict[str, Any]],
    stamp: str,
    phase_transitions: list[dict[str, Any]],
    *,
    range_seconds: int,
    now_seconds: float,
    query_timeout_seconds: float,
) -> tuple[dict[str, int], list[str]]:
    roots = [agent for agent in agents.values() if not agent.parent_id]
    if len(roots) != 1:
        return {}, ["Agent360 golden gate cannot select a unique root"]
    root = roots[0]
    variables = {
        **VARIABLES,
        "$connector": "codex",
        "${connector:regex}": "codex",
        "$scope_label": "defenseclaw_agent_root_id",
        "$agent": root.agent_id,
        "$lifecycle": ".*",
        "$execution": ".*",
        "$session": root.root_session_id,
        "$user": ".*",
        "$trace": trace_id,
        "$__range_s": str(range_seconds),
        "$__range": f"{max(1, range_seconds // 60)}m",
    }
    errors: list[str] = []
    descendants_query = interpolate(
        str(_agent360_target(AGENT360_DESCENDANTS_PANEL).get("expr", "")),
        variables,
    )
    descendants = _prometheus_vector(descendants_query, timeout_seconds=query_timeout_seconds)
    descendant_values = [
        float(series["value"][-1])
        for series in descendants
        if isinstance(series.get("value"), list) and len(series["value"]) >= 2
    ]
    expected_descendants = len(agents) - 1
    if not descendant_values or max(descendant_values) != expected_descendants:
        errors.append(
            f"Agent360 Descendants returned {descendant_values or 'no data'}, want {expected_descendants}",
        )

    topology_targets = _agent360_targets(AGENT360_TOPOLOGY_PANEL)
    edge_targets = [
        target for target in topology_targets if str(target.get("refId", "")).startswith("edges")
    ]
    node_targets = [
        target for target in topology_targets if str(target.get("refId", "")).startswith("nodes")
    ]
    anchor_node_refs = {"nodesRootAnchor", "nodesSpawnParent"}
    if len(edge_targets) != 8 or len(node_targets) != 10:
        errors.append(
            "Agent360 topology must retain exactly 8 edge and 10 node query components; "
            f"got edges={len(edge_targets)}, nodes={len(node_targets)}",
        )
    missing_anchor_refs = sorted(
        anchor_node_refs
        - {str(target.get("refId", "")) for target in node_targets}
    )
    if missing_anchor_refs:
        errors.append(
            f"Agent360 topology is missing endpoint-anchor node queries: {missing_anchor_refs}",
        )
    topology_results = {
        str(target.get("refId", "")): _loki_vector(
            interpolate(str(target.get("expr", "")), variables),
            timeout_seconds=query_timeout_seconds,
        )
        for target in topology_targets
    }
    topology_edges = [
        series
        for target in edge_targets
        for series in topology_results.get(str(target.get("refId", "")), [])
        if isinstance(series.get("metric"), dict) and _positive_prometheus_series(series)
    ]
    topology_node_rows = [
        (str(target.get("refId", "")), series)
        for target in node_targets
        for series in topology_results.get(str(target.get("refId", "")), [])
        if isinstance(series.get("metric"), dict) and _positive_prometheus_series(series)
    ]
    topology_nodes = [series for _ref_id, series in topology_node_rows]
    observed_edges = {
        (
            str(series["metric"].get("source") or ""),
            str(series["metric"].get("target") or ""),
        )
        for series in topology_edges
    }
    observed_nodes = {
        str(series["metric"].get("id") or "")
        for series in topology_nodes
    }
    expected_edges = {
        *(
            (f"agent:{agent.parent_id}", f"agent:{agent.agent_id}")
            for agent in agents.values()
            if agent.parent_id
        ),
        (f"session:{root.agent_id}", f"agent:{root.agent_id}"),
    }
    selected_records = _golden_records_for_stamp(records, stamp)
    for record in selected_records:
        event_name = str(record.get("event_name") or "")
        body = record.get("body", {})
        if not isinstance(body, dict):
            continue
        agent_id = str(body.get("gen_ai.agent.id") or "")
        agent = agents.get(agent_id)
        if agent is None:
            continue
        provider = str(body.get("gen_ai.provider.name") or "")
        model = str(body.get("gen_ai.response.model") or body.get("gen_ai.request.model") or "")
        if event_name == "model.request" and _golden_int(
            body.get("defenseclaw.agent.depth"),
        ) == 0:
            expected_edges.add(
                (f"prompts:{agent.agent_id}", f"agent:{agent.agent_id}"),
            )
        if event_name == "model.request" and provider and model:
            expected_edges.add(
                (
                    f"agent:{agent.agent_id}",
                    f"model:{agent.agent_id}:{provider}:{model}",
                ),
            )
        tool_family = _golden_tool_family(body.get("gen_ai.tool.name"))
        if event_name == "tool.invocation.requested" and tool_family:
            expected_edges.add(
                (f"agent:{agent.agent_id}", f"tool:{agent.agent_id}:{tool_family}"),
            )
        approval_id = str(body.get("defenseclaw.approval.id") or "")
        if event_name == "approval.requested" and approval_id:
            expected_edges.add(
                (f"agent:{agent.agent_id}", f"approval:{agent.agent_id}:{approval_id}"),
            )
        tool_name = str(body.get("gen_ai.tool.name") or "")
        arguments = body.get("gen_ai.tool.call.arguments")
        target_task = str(arguments.get("target") or "") if isinstance(arguments, dict) else ""
        if (
            event_name == "tool.invocation.requested"
            and re.fullmatch(r"collaboration[._]*send[._]*message", tool_name, re.IGNORECASE)
            and target_task
        ):
            expected_edges.add(
                (
                    f"agent:{agent.agent_id}",
                    f"message:{agent.agent_id}:{target_task}",
                ),
            )
        if event_name in {"session_end", "subagent_stop", "turn_end"}:
            outcome_suffix = agent.execution_id
            if event_name == "turn_end":
                outcome_suffix = (
                    "turns:"
                    f"{body.get('defenseclaw.agent.lifecycle.state', '')}:"
                    f"{record.get('outcome', '')}"
                )
            expected_edges.add(
                (
                    f"agent:{agent.agent_id}",
                    f"outcome:{agent.agent_id}:{outcome_suffix}",
                ),
            )
    for source, target in sorted(expected_edges - observed_edges):
        errors.append(f"Agent360 topology is missing golden edge {source} -> {target}")

    expected_nodes = {
        *(f"agent:{agent.agent_id}" for agent in agents.values()),
        *(endpoint for edge in expected_edges for endpoint in edge),
    }
    for node_id in sorted(expected_nodes - observed_nodes):
        errors.append(f"Agent360 topology is missing golden node {node_id}")

    # Grafana's Node Graph does not coalesce duplicate IDs across query frames;
    # it can render the anchor and rich row as separate visual nodes. Endpoint
    # anchors therefore suppress themselves whenever the same exact agent ID
    # has graph-eligible activity in range. Reject every blank or repeated ID,
    # including an otherwise tempting anchor/rich-row cross-frame duplicate.
    node_id_refs: dict[str, list[str]] = {}
    for ref_id, series in topology_node_rows:
        node_id = str(series["metric"].get("id") or "")
        node_id_refs.setdefault(node_id, []).append(ref_id)
    invalid_nodes = sorted(
        node_id
        for node_id, ref_ids in node_id_refs.items()
        if not node_id or len(ref_ids) > 1
    )
    if invalid_nodes:
        errors.append(f"Agent360 topology has blank or duplicate node IDs: {invalid_nodes}")

    edge_id_counts: dict[str, int] = {}
    for series in topology_edges:
        metric = series["metric"]
        edge_id = str(metric.get("id") or "")
        source = str(metric.get("source") or "")
        target = str(metric.get("target") or "")
        edge_id_counts[edge_id] = edge_id_counts.get(edge_id, 0) + 1
        if not source or not target:
            errors.append(f"Agent360 topology edge {edge_id or '<blank>'} has a blank endpoint")
    duplicate_edges = sorted(
        edge_id for edge_id, count in edge_id_counts.items() if not edge_id or count != 1
    )
    if duplicate_edges:
        errors.append(f"Agent360 topology has blank or duplicate edge IDs: {duplicate_edges}")

    dangling = sorted(
        (source, target)
        for source, target in observed_edges
        if source not in observed_nodes or target not in observed_nodes
    )
    if dangling:
        errors.append(f"Agent360 topology has dangling edge endpoints: {dangling}")

    # Kahn's algorithm proves the authored Node Graph frame remains a DAG. A
    # message to /root is represented as an event node with resolved target
    # identity in details, rather than a back-edge that would create a cycle.
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in observed_nodes if node_id}
    indegree = {node_id: 0 for node_id in adjacency}
    for source, target in observed_edges:
        if source not in adjacency or target not in adjacency or target in adjacency[source]:
            continue
        adjacency[source].add(target)
        indegree[target] += 1
    ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
    visited = 0
    while ready:
        node_id = ready.pop(0)
        visited += 1
        for target in sorted(adjacency[node_id]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if visited != len(adjacency):
        errors.append("Agent360 topology contains a directed cycle")

    prompt_source = f"prompts:{root.agent_id}"
    prompt_target = f"agent:{root.agent_id}"
    prompt_edges = [
        series
        for series in topology_edges
        if isinstance(series.get("metric"), dict)
        and series["metric"].get("source") == prompt_source
        and series["metric"].get("target") == prompt_target
        and _positive_prometheus_series(series)
    ]
    if len(prompt_edges) == 1:
        prompt_metric = prompt_edges[0]["metric"]
        expected_prompt_details = {
            "id": f"edge:prompts:{root.agent_id}",
            "detail__edge_kind": "prompt_submissions_to_root",
            "detail__agent_id": root.agent_id,
            "detail__root_agent_id": root.agent_id,
            "detail__event_name": "prompt submission",
            "detail__connector": "codex",
        }
        if any(
            prompt_metric.get(key) != value
            for key, value in expected_prompt_details.items()
        ) or float(prompt_edges[0]["value"][-1]) != 1:
            errors.append(
                "Agent360 conversation prompt edge lost its clickable identity/details or exact count",
            )
    elif prompt_edges:
        errors.append(
            f"Agent360 conversation prompt edge rows={len(prompt_edges)}, want exactly one grouped edge",
        )

    expected_phase_edges = {
        (
            str(series.get("metric", {}).get("defenseclaw_agent_phase_from") or ""),
            str(series.get("metric", {}).get("defenseclaw_agent_phase_to") or ""),
        )
        for series in phase_transitions
        if isinstance(series.get("metric"), dict)
        and str(series["metric"].get("gen_ai_agent_id") or "") in agents
        and _positive_prometheus_series(series)
    }
    phase_query = interpolate(
        str(_agent360_target(AGENT360_PHASE_EDGES_PANEL).get("expr", "")),
        variables,
    )
    authored_phase_edges = _prometheus_vector(
        phase_query,
        timeout_seconds=query_timeout_seconds,
    )
    observed_phase_edges = {
        (
            str(series.get("metric", {}).get("defenseclaw_agent_phase_from") or ""),
            str(series.get("metric", {}).get("defenseclaw_agent_phase_to") or ""),
        )
        for series in authored_phase_edges
        if isinstance(series.get("metric"), dict) and _positive_prometheus_series(series)
    }
    for phase_from, phase_to in sorted(expected_phase_edges - observed_phase_edges):
        errors.append(
            "Agent360 authored directed phase edge is missing golden transition "
            f"{phase_from} -> {phase_to}",
        )

    start_ns = int((now_seconds - range_seconds) * 1_000_000_000)
    end_ns = int(now_seconds * 1_000_000_000)
    authored_loki = (
        (
            "Agent360 approval target",
            _agent360_target(AGENT360_APPROVAL_PANEL),
            variables,
        ),
        (
            "Agent360 chronology target",
            _agent360_target(AGENT360_CHRONOLOGY_PANEL),
            variables,
        ),
        (
            "Activity chronology target",
            _dashboard_target("defenseclaw-activity", ACTIVITY_CHRONOLOGY_PANEL),
            {**variables, "$agent": ".*"},
        ),
    )
    authored_rows = 0
    for label, target, target_variables in authored_loki:
        query = interpolate(str(target.get("expr", "")), target_variables)
        lines = _loki_query_lines(
            query,
            start_ns=start_ns,
            end_ns=end_ns,
            timeout_seconds=query_timeout_seconds,
        )
        authored_rows += len(lines)
        errors.extend(_approval_chronology_errors(lines, label=label))

    trace_target = _agent360_target(AGENT360_TRACE_PANEL)
    trace_query = interpolate(tempo_target_query(trace_target) or "", variables)
    trace_search = request_json(
        "http://127.0.0.1:3200/api/search",
        {
            "q": trace_query,
            "limit": "100",
            "start": str(int(now_seconds - range_seconds)),
            "end": str(int(now_seconds)),
        },
        timeout_seconds=query_timeout_seconds,
    )
    trace_ids = {
        normalized
        for item in trace_search.get("traces", [])
        if isinstance(item, dict)
        for normalized in [_normalize_tempo_search_trace_id(item.get("traceID"))]
        if normalized
    }
    if trace_id not in trace_ids:
        errors.append("Agent360 authored operation-trace target does not return the golden operation trace")
    return {
        "descendants": expected_descendants,
        "topology_edges": len(observed_edges),
        "phase_edges": len(observed_phase_edges),
        "authored_loki_rows": authored_rows,
    }, errors


def _live_golden_once(
    *,
    range_seconds: int = 15 * 60,
    query_timeout_seconds: float = DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], list[str]]:
    """Verify one coherent native-producer run across Prometheus, Loki, and Tempo."""

    now_seconds = time.time()
    prometheus_lookback = f"{max(1, int(range_seconds))}s"
    last_seen = _prometheus_vector(
        'max_over_time(defenseclaw_agent_last_seen_seconds{'
        'gen_ai_agent_id=~"golden-agent-[a-z][a-z0-9-]*-[0-9]+"}'
        f'[{prometheus_lookback}])',
        timeout_seconds=query_timeout_seconds,
    )
    lifecycle_transitions = _prometheus_vector(
        'max_over_time(defenseclaw_agent_lifecycle_transitions_total{'
        'gen_ai_agent_id=~"golden-agent-[a-z][a-z0-9-]*-[0-9]+"}'
        f'[{prometheus_lookback}])',
        timeout_seconds=query_timeout_seconds,
    )
    transitions = _prometheus_vector(
        'max_over_time(defenseclaw_agent_phase_transitions_total{'
        'gen_ai_agent_id=~"golden-agent-[a-z][a-z0-9-]*-[0-9]+"}'
        f'[{prometheus_lookback}])',
        timeout_seconds=query_timeout_seconds,
    )
    records = _loki_golden_records(
        start_ns=int((now_seconds - range_seconds) * 1_000_000_000),
        end_ns=int(now_seconds * 1_000_000_000),
        timeout_seconds=query_timeout_seconds,
    )
    stamps: set[str] = set()
    for series in [*last_seen, *lifecycle_transitions, *transitions]:
        identity = _golden_agent_role_stamp(series.get("metric", {}).get("gen_ai_agent_id"))
        if identity is not None:
            stamps.add(identity[1])
    for record in records:
        identity = _golden_agent_role_stamp(record.get("body", {}).get("gen_ai.agent.id"))
        if identity is not None:
            stamps.add(identity[1])
    if not stamps:
        return {}, ["no local-observability golden producer run was found in Prometheus or Loki"]
    stamp = max(stamps, key=int)

    # Scope Tempo discovery to the one run already selected from Prometheus
    # and Loki. A broad lookback eventually contains more than Tempo's search
    # limit and can silently omit some request-bounded terminal traces even
    # though those traces are present and queryable by exact agent identity.
    search = request_json(
        "http://127.0.0.1:3200/api/search",
        {
            "q": (
                '{ span.gen_ai.agent.id =~ "golden-agent-[a-z][a-z0-9-]*-'
                f'{stamp}" }}'
            ),
            "limit": "100",
            "start": str(int(now_seconds - range_seconds)),
            "end": str(int(now_seconds)),
        },
        timeout_seconds=query_timeout_seconds,
    )
    trace_ids = {
        normalized
        for trace in search.get("traces", [])
        if isinstance(trace, dict)
        for normalized in [_normalize_tempo_search_trace_id(trace.get("traceID"))]
        if normalized
    }
    spans = [
        span
        for trace_id in sorted(trace_ids)
        for span in _tempo_trace_spans(trace_id, timeout_seconds=query_timeout_seconds)
    ]

    agents, identity_errors = _golden_agent_identities(records, stamp)
    (
        log_errors,
        model_agent_ids,
        tool_agent_ids,
        approval_tool_agent_id,
        terminal_records,
    ) = _golden_log_errors(
        records,
        stamp,
        agents,
    )
    errors = [*identity_errors, *log_errors]
    errors.extend(
        _golden_approval_log_errors(records, stamp, agents.get(approval_tool_agent_id)),
    )
    errors.extend(
        _golden_metric_errors(
            last_seen,
            lifecycle_transitions,
            transitions,
            records,
            stamp,
            agents,
        ),
    )
    trace_errors, trace_id = _golden_trace_errors(
        spans,
        stamp,
        agents,
        model_agent_ids,
        tool_agent_ids,
        approval_tool_agent_id,
    )
    errors.extend(trace_errors)
    if trace_id:
        errors.extend(_golden_cross_signal_trace_errors(records, stamp, trace_id))
    agent360_report: dict[str, int] = {}
    if trace_id and agents:
        agent360_report, agent360_errors = _golden_agent360_errors(
            agents,
            trace_id,
            records,
            stamp,
            transitions,
            range_seconds=range_seconds,
            now_seconds=now_seconds,
            query_timeout_seconds=query_timeout_seconds,
        )
        errors.extend(agent360_errors)
    matching_records = [
        record
        for record in records
        if (_golden_agent_role_stamp(record.get("body", {}).get("gen_ai.agent.id")) or ("", ""))[1] == stamp
    ]
    matching_spans = [
        span
        for span in spans
        if (_golden_agent_role_stamp(span["attributes"].get("gen_ai.agent.id")) or ("", ""))[1] == stamp
    ]
    matching_last_seen = [
        series
        for series in last_seen
        if (_golden_agent_role_stamp(series.get("metric", {}).get("gen_ai_agent_id")) or ("", ""))[1] == stamp
    ]
    matching_transitions = [
        series
        for series in transitions
        if (_golden_agent_role_stamp(series.get("metric", {}).get("gen_ai_agent_id")) or ("", ""))[1] == stamp
    ]
    matching_lifecycle_transitions = [
        series
        for series in lifecycle_transitions
        if (_golden_agent_role_stamp(series.get("metric", {}).get("gen_ai_agent_id")) or ("", ""))[1]
        == stamp
    ]
    return {
        "stamp": stamp,
        "agent_count": len(agents),
        "max_depth": max((agent.depth for agent in agents.values()), default=-1),
        "terminal_events": len(terminal_records),
        "model_agent_count": len(model_agent_ids),
        "tool_agent_count": len(tool_agent_ids),
        "last_seen_series": len(matching_last_seen),
        "lifecycle_transition_series": len(matching_lifecycle_transitions),
        "phase_transition_series": len(matching_transitions),
        "log_records": len(matching_records),
        "trace_spans": len(matching_spans),
        "trace_id": trace_id,
        "agent360_descendants": agent360_report.get("descendants", 0),
        "agent360_topology_edges": agent360_report.get("topology_edges", 0),
        "agent360_phase_edges": agent360_report.get("phase_edges", 0),
        "agent360_authored_loki_rows": agent360_report.get("authored_loki_rows", 0),
    }, errors


def live_golden_audit(
    *,
    range_seconds: int = 15 * 60,
    deadline: float | None = None,
    query_timeout_seconds: float = DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS,
    retry_delay_seconds: float = 2.0,
) -> tuple[dict[str, Any], list[str]]:
    """Retry the explicit live golden gate while backends finish ingesting."""

    report: dict[str, Any] = {}
    errors: list[str] = []
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return report, errors or ["live golden audit exceeded its ingestion deadline"]
        try:
            report, errors = _live_golden_once(
                range_seconds=range_seconds,
                query_timeout_seconds=live_query_timeout_seconds(
                    deadline=deadline,
                    configured_seconds=query_timeout_seconds,
                ),
            )
        except AuditError as exc:
            errors = [str(exc)]
        if not errors:
            return report, []
        if deadline is None:
            return report, errors
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return report, errors
        time.sleep(min(retry_delay_seconds, remaining))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compile every query against the local stack")
    parser.add_argument(
        "--live-golden",
        action="store_true",
        help="require one coherent native golden-producer run across Prometheus, Loki, and Tempo",
    )
    parser.add_argument(
        "--require-packaged",
        action="store_true",
        help="fail if the generated CLI dashboard mirror is absent",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="report data/zero/empty/interactive/error panels against the local stack",
    )
    parser.add_argument(
        "--inventory-hours",
        type=int,
        default=48,
        help="lookback used by --inventory (default: 48 hours)",
    )
    parser.add_argument(
        "--live-timeout-seconds",
        type=int,
        default=300,
        help="global deadline shared by live compilation and inventory (default: 300)",
    )
    parser.add_argument(
        "--live-query-timeout-seconds",
        type=int,
        default=int(DEFAULT_LIVE_QUERY_TIMEOUT_SECONDS),
        help="maximum wait for one backend query, capped by the shared live deadline (default: 60)",
    )
    parser.add_argument(
        "--golden-lookback-minutes",
        type=int,
        default=15,
        help="lookback used by --live-golden (default: 15 minutes)",
    )
    parser.add_argument(
        "--golden-wait-seconds",
        type=int,
        default=30,
        help="maximum wait for golden data to finish ingesting (default: 30 seconds)",
    )
    args = parser.parse_args()

    if args.inventory_hours <= 0:
        parser.error("--inventory-hours must be greater than zero")
    if args.live_timeout_seconds <= 0:
        parser.error("--live-timeout-seconds must be greater than zero")
    if args.live_query_timeout_seconds <= 0:
        parser.error("--live-query-timeout-seconds must be greater than zero")
    if args.golden_lookback_minutes <= 0:
        parser.error("--golden-lookback-minutes must be greater than zero")
    if args.golden_wait_seconds <= 0:
        parser.error("--golden-wait-seconds must be greater than zero")

    dashboards, errors = static_audit(require_packaged=args.require_packaged)
    live_deadline = time.monotonic() + args.live_timeout_seconds
    if (args.live or args.inventory or args.live_golden) and not errors:
        errors.extend(backend_readiness_errors())
    if args.live and not errors:
        errors.extend(
            live_audit(
                dashboards,
                deadline=live_deadline,
                query_timeout_seconds=args.live_query_timeout_seconds,
            ),
        )
    inventory: list[dict[str, Any]] = []
    if args.inventory and not errors:
        inventory, inventory_errors = live_inventory(
            dashboards,
            range_seconds=args.inventory_hours * 60 * 60,
            deadline=live_deadline,
            query_timeout_seconds=args.live_query_timeout_seconds,
        )
        errors.extend(inventory_errors)
    golden_report: dict[str, Any] = {}
    if args.live_golden and not errors:
        golden_report, golden_errors = live_golden_audit(
            range_seconds=args.golden_lookback_minutes * 60,
            deadline=min(live_deadline, time.monotonic() + args.golden_wait_seconds),
            query_timeout_seconds=args.live_query_timeout_seconds,
        )
        errors.extend(golden_errors)

    if args.inventory and inventory:
        print_inventory(inventory, range_seconds=args.inventory_hours * 60 * 60)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.live_golden:
        print(
            "Live golden producer verified: "
            f"run={golden_report['stamp']}, trace={golden_report['trace_id']}, "
            f"last_seen={golden_report['last_seen_series']}, "
            f"phase_transitions={golden_report['phase_transition_series']}, "
            f"logs={golden_report['log_records']}, spans={golden_report['trace_spans']}",
        )
    print(
        f"Grafana audit passed: {len(dashboards)} dashboards, "
        f"{sum(1 for _, dashboard in dashboards for panel in panels(dashboard) if panel.get('type') != 'row')} panels"
        + (", live queries compiled" if args.live else "")
        + (", live data inventoried" if args.inventory else "")
        + (", live golden producer verified" if args.live_golden else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
