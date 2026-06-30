#!/usr/bin/env python3
"""Validate the bundled Grafana dashboard contract.

The static pass is suitable for CI.  ``--live`` additionally asks the local
Prometheus, Loki, Tempo, and Grafana APIs to parse every retained query.  A
query may legitimately return no rows (for example, no approval was denied),
but it must be syntactically valid and target a configured datasource.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "bundles/local_observability_stack/grafana/dashboards"
PACKAGED_DIR = ROOT / "cli/defenseclaw/_data/local_observability_stack/grafana/dashboards"
SOURCE_DATASOURCES = (
    ROOT / "bundles/local_observability_stack/grafana/provisioning/datasources/datasources.yml"
)
PACKAGED_DATASOURCES = (
    ROOT
    / "cli/defenseclaw/_data/local_observability_stack/grafana/provisioning/datasources/datasources.yml"
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
}
PROMETHEUS_EXACT_LABEL_VALUES = {
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

DATASOURCES = {
    "prometheus": "defenseclaw-prometheus",
    "loki": "defenseclaw-loki",
    "tempo": "defenseclaw-tempo",
}

VARIABLES = {
    "$__range_s": "300",
    "$__rate_interval": "5m",
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
        yield from panel.get("panels", [])


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
                            allowed_labels = (
                                PROMETHEUS_METRIC_LABELS[metric_name]
                                | COMMON_PROMETHEUS_RESOURCE_LABELS
                            )
                            unknown_labels = {
                                label for label, _operator, _value in selector_pairs
                            } - allowed_labels
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
                                    f"{uid}/{title}: {metric_name} uses unknown exact "
                                    f"{label} value {value!r}",
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

    return dashboards, errors


def request_json(url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise AuditError(f"{url}: HTTP {exc.code}: {body[:400]}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"{url}: {exc}") from exc


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


def live_inventory(
    dashboards: list[tuple[Path, dict[str, Any]]],
    *,
    range_seconds: int = 48 * 60 * 60,
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
        panel_results: list[dict[str, Any]] = []
        for panel in panels(dashboard):
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
                        result = request_json(endpoint, params)
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
                errors.extend(
                    f"{dashboard['uid']}/{panel_result['title']}: {error}" for error in target_errors
                )
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
        empty_titles = [
            result["title"] for result in dashboard["panels"] if result["status"] == "empty"
        ]
        print(
            f"| {dashboard['title']} (`{dashboard['uid']}`) "
            f"| {len(dashboard['panels'])} | {counts['data']} | {counts['zero']} "
            f"| {counts['empty']} | {counts['interactive']} | {counts['static']} "
            f"| {counts['error']} "
            f"| {', '.join(empty_titles) or 'None'} |",
        )


def live_audit(dashboards: list[tuple[Path, dict[str, Any]]]) -> list[str]:
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
        uid = dashboard["uid"]
        for panel in panels(dashboard):
            title = panel.get("title", "untitled")
            for target in panel.get("targets", []):
                datasource = target_datasource(panel, target)
                expression = target.get("expr", "")
                try:
                    if datasource == "prometheus" and expression:
                        result = request_json(
                            "http://127.0.0.1:9090/api/v1/query",
                            {"query": interpolate(expression)},
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
                        result = request_json(endpoint, params)
                        if result.get("status") != "success":
                            raise AuditError(str(result))
                    elif datasource == "tempo" and tempo_error is None:
                        query = tempo_target_query(target)
                        if query and query != "$trace":
                            request_json(
                                "http://127.0.0.1:3200/api/search",
                                {"q": interpolate(query), "limit": "1"},
                            )
                except AuditError as exc:
                    errors.append(f"{uid}/{title}: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="also compile every query against the local stack")
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
    args = parser.parse_args()

    if args.inventory_hours <= 0:
        parser.error("--inventory-hours must be greater than zero")

    dashboards, errors = static_audit(require_packaged=args.require_packaged)
    if args.live and not errors:
        errors.extend(live_audit(dashboards))
    inventory: list[dict[str, Any]] = []
    if args.inventory and not errors:
        inventory, inventory_errors = live_inventory(
            dashboards,
            range_seconds=args.inventory_hours * 60 * 60,
        )
        errors.extend(inventory_errors)

    if args.inventory and inventory:
        print_inventory(inventory, range_seconds=args.inventory_hours * 60 * 60)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"Grafana audit passed: {len(dashboards)} dashboards, "
        f"{sum(1 for _, dashboard in dashboards for panel in panels(dashboard) if panel.get('type') != 'row')} panels"
        + (", live queries compiled" if args.live else "")
        + (", live data inventoried" if args.inventory else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
